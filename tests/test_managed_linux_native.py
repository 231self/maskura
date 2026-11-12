"""Source/construction regressions only: never compile, execute C or probe this host.

The guards' --self-test builders and real positive/negative kernel controls must
still run on the authorized native Linux CI runner. These tests are not receipts.
"""
import ast
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
NATIVE = ROOT / "scripts" / "managed_release_linux"
KERNEL = (NATIVE / "kernel_guard.c").read_text()
PRODUCT = (NATIVE / "product_guard.c").read_text()
NOTES = (NATIVE / "NATIVE.md").read_text()


def function(source, name):
    """Extract a top-level C function; do not load any native code."""
    match = re.search(r"^(?:static )?[^\n]*\b" + re.escape(name) + r"\(", source, re.M)
    if not match:
        raise AssertionError(f"missing function {name}")
    end = re.search(r"^}[ \t]*$", source[match.start():], re.M)
    if not end:
        raise AssertionError(f"missing function end {name}")
    return source[match.start():match.start() + end.end()]


def without_comments(source):
    return re.sub(r"/\*.*?\*/", "", source, flags=re.S)


def offset_value(expression, count, j=0):
    """Interpret only integer branch arithmetic extracted from the C builder."""
    def visit(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name) and node.id in {"count", "j"}:
            return {"count": count, "j": j}[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
            left, right = visit(node.left), visit(node.right)
            return left + right if isinstance(node.op, ast.Add) else left - right
        raise AssertionError("not bounded branch arithmetic")
    return visit(ast.parse(expression, mode="eval").body)


class KernelGuardSourceTests(unittest.TestCase):
    def test_platform_and_dependency_boundary(self):
        self.assertIn("!defined(__linux__) || !defined(__x86_64__)", KERNEL)
        self.assertIn("syscall(SYS_bpf, cmd, attr, sizeof(*attr))", KERNEL)
        self.assertNotRegex(KERNEL, r"#include\s*[<\"](?:bpf/|libbpf)")
        self.assertNotRegex(KERNEL, r"\bbpf_map_|\bBPF_MAP_CREATE\b|\bBPF_CALL\b")

    def test_four_exact_hooks_in_closed_order(self):
        block = re.search(r"hooks\[HOOKS\] = \{([^}]+)}", KERNEL).group(1)
        self.assertEqual(re.findall(r"BPF_CGROUP_\w+", block), [
            "BPF_CGROUP_INET4_BIND", "BPF_CGROUP_INET4_CONNECT",
            "BPF_CGROUP_INET6_BIND", "BPF_CGROUP_INET6_CONNECT",
        ])
        self.assertIn("HOOKS = 4", KERNEL)
        self.assertIn("j < 2, ports, count", function(KERNEL, "main"))

    def test_owned_descriptor_not_path(self):
        main = function(KERNEL, "main")
        for required in ("number < 3", "geteuid() != 0", "O_DIRECTORY", "O_NOFOLLOW",
                         "fstat(cgroup, &st)", "S_ISDIR(st.st_mode)",
                         "fstatfs(cgroup, &fs)", "CGROUP2_SUPER_MAGIC"):
            self.assertIn(required, main)
        self.assertNotRegex(KERNEL, r"\b(?:open|openat|fopen|opendir)\s*\(")

    def test_port_parser_limits_and_no_wildcard(self):
        parser = function(KERNEL, "parse_ports")
        self.assertIn("MAX_PORTS = 16", KERNEL)
        for required in ("*count = 0", "*s == '\\0'", "65535", "port < 1024",
                         "port == 5432", "port == 54322", "*count == MAX_PORTS",
                         "ports[at] == port", "ports[at] < port", "memmove("):
            self.assertIn(required, parser)
        self.assertNotIn("strtok", parser)
        native_tests = function(KERNEL, "self_test")
        for malformed in ('"1024,"', '",1024"', '"1024,,1025"', '"1024,1024"',
                          '"-1"', '" 1024"', '"1e4"', '"65536"'):
            self.assertIn(malformed, native_tests)

    def test_original_monotonic_deadline_only(self):
        parser = function(KERNEL, "parse_deadline")
        for required in ("digits > 12", "fraction > 9", "!isfinite(d)",
                         "d <= now", "d > now + 3600.0"):
            self.assertIn(required, parser)
        self.assertIn("CLOCK_MONOTONIC", function(KERNEL, "monotonic_now"))
        waiter = function(KERNEL, "wait_stop")
        self.assertIn("now >= deadline", waiter)
        self.assertNotIn("deadline =", waiter)
        self.assertNotIn("CLOCK_REALTIME", KERNEL)

    def test_immutable_program_and_endianness(self):
        builder = function(KERNEL, "build_program")
        for required in ("offsetof(struct bpf_sock_addr, user_ip4)",
                         "offsetof(struct bpf_sock_addr, user_port)",
                         "htonl(INADDR_LOOPBACK)", "htons(ports[j])"):
            self.assertIn(required, builder)
        self.assertEqual(builder.count("if (ipv4 && count)"), 2)
        self.assertNotRegex(builder, r"BPF_(?:ST|STX|CALL|MAP|LD_IMM)")
        load = function(KERNEL, "load_program")
        for required in ("BPF_PROG_TYPE_CGROUP_SOCK_ADDR", "a.expected_attach_type = hook",
                         "BPF_OBJ_GET_INFO_BY_FD", "!info.id", "info.type !="):
            self.assertIn(required, load)
        self.assertNotRegex(load, r"\.log_(?:buf|level|size)\s*=")

    def test_all_builder_forward_jump_targets(self):
        builder = function(KERNEL, "build_program")
        ip_expression = re.search(r"\(short\)\(([^)]+)\), \(int\)htonl", builder).group(1)
        port_expression = re.search(r"\(short\)\(([^)]+)\), \(int\)htons", builder).group(1)
        for count in range(1, 17):
            with self.subTest(count=count):
                # ip(0), jne(1), port(2), count JEQs, deny/exit, allow/exit.
                deny, allow, length = count + 3, count + 5, count + 7
                self.assertLessEqual(length, 32)
                self.assertEqual(1 + 1 + offset_value(ip_expression, count), deny)
                for j in range(count):
                    offset = offset_value(port_expression, count, j)
                    self.assertGreater(offset, 0)
                    self.assertEqual(3 + j + 1 + offset, allow)

    def test_effective_and_direct_readback_require_exact_id(self):
        query = function(KERNEL, "query_exact")
        for required in ("ids[64]", "BPF_F_QUERY_EFFECTIVE", "BPF_PROG_QUERY",
                         "a.query.attach_flags != 0", "a.query.prog_cnt == 0",
                         "a.query.prog_cnt == 1 && ids[0] == id"):
            self.assertIn(required, query)
        self.assertIn("return -1", query)
        waiter = function(KERNEL, "wait_stop")
        self.assertIn("hooks[j], ids[j], 0", waiter)
        self.assertIn("hooks[j], ids[j], 1", waiter)

    def test_attach_exclusive_detach_only_retained_fds(self):
        attachment = function(KERNEL, "attachment")
        self.assertIn("a.attach_bpf_fd = (uint32_t)fd", attachment)
        self.assertNotRegex(attachment, r"\.attach_flags\s*=")
        main = function(KERNEL, "main")
        self.assertIn("attachment(BPF_PROG_DETACH, cgroup, hooks[j], fds[j])", main)
        self.assertIn("if (attached[j])", main)
        self.assertIn("hooks[j], 0, 0", main)
        self.assertIn("hooks[j], 0, 1", main)
        self.assertIn("if (fds[j] >= 0 && close(fds[j])) detached = 0", main)
        self.assertIn("!ok || !detached || !was_ready", main)

    def test_all_four_read_back_before_ready(self):
        main = function(KERNEL, "main")
        marker = main.index("Read back ALL hooks")
        self.assertLess(marker, main.index("ready(ids, &st, ports, count)"))
        block = main[marker:main.index("int was_ready")]
        self.assertIn("ids[k] == ids[j]", block)
        self.assertIn("hooks[j], ids[j], 0", block)
        self.assertIn("hooks[j], ids[j], 1", block)

    def test_bounded_exact_stop_protocol(self):
        waiter = function(KERNEL, "wait_stop")
        for required in ("char command[6]", 'memcmp(command, "STOP\\n", 5)',
                         'memcmp(command, "STOP\\n", used)', "used == 0 ? 0 : -1",
                         "POLLERR | POLLNVAL", "if (ms > 250) ms = 250",
                         "query_exact("):
            self.assertIn(required, waiter)
        self.assertIn("O_NONBLOCK", function(KERNEL, "main"))
        handler = re.search(r"static void on_signal\([^\n]+", KERNEL).group(0)
        self.assertEqual(handler, "static void on_signal(int signum) { (void)signum; interrupted = 1; }")
        for signal in ("SIGTERM", "SIGINT", "SIGHUP", "SIGPIPE"):
            self.assertIn(signal, function(KERNEL, "main"))

    def test_closed_kernel_status_schema(self):
        ready = function(KERNEL, "ready")
        fields = set(re.findall(r'\\"(\w+)\\":', ready))
        self.assertEqual(fields, {"schema", "kind", "ready", "program_ids",
                                  "cgroup_device", "cgroup_inode", "allowed_ports"})
        self.assertIn('\\"stopped\\":true,\\"detached\\":true', KERNEL)
        codes = set(re.findall(r'fail\("([a-z_]+)"\)', KERNEL))
        self.assertEqual(codes, {"arguments", "authority", "cgroup_identity", "control_channel",
                                 "signals", "self_test"})
        self.assertIn('detached ? "policy_failed" : "cleanup_uncertain"', KERNEL)


class ProductGuardSourceTests(unittest.TestCase):
    def setUp(self):
        self.builder = function(PRODUCT, "build_filter")
        self.main = function(PRODUCT, "main")
        self.allowed = re.findall(r"ALLOW\((\w+)\);", self.builder)

    def test_native_arch_and_x32_gate_precede_dispatch(self):
        self.assertIn("!defined(__linux__) || !defined(__x86_64__)", PRODUCT)
        order = [self.builder.index(token) for token in (
            "AUDIT_ARCH_X86_64", "SECCOMP_RET_KILL_PROCESS", "0x40000000U", "__NR_clone3",
            "network_policy(b, profile)", "#define ALLOW",
        )]
        self.assertEqual(order, sorted(order))

    def test_default_denial_and_unique_explicit_allowlist(self):
        self.assertGreater(len(self.allowed), 100)
        self.assertEqual(len(self.allowed), len(set(self.allowed)))
        self.assertIn("#define DENIED (SECCOMP_RET_ERRNO | EPERM)", PRODUCT)
        self.assertRegex(self.builder, r"#undef ALLOW\s+stmt\(b, BPF_RET \| BPF_K, DENIED\)")
        self.assertIn("MAX_FILTER = 512", PRODUCT)
        self.assertIn("b->failed || b->count > MAX_FILTER", self.builder)

    def test_privileged_and_alternative_network_syscalls_absent(self):
        forbidden = {"ptrace", "process_vm_readv", "process_vm_writev", "bpf", "setns", "unshare",
                     "mount", "umount2", "pivot_root", "chroot", "fsopen", "fsmount", "open_tree",
                     "move_mount", "io_uring_setup", "io_uring_enter", "io_uring_register",
                     "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "setgroups",
                     "capset", "setfsuid", "setfsgid", "iopl", "ioperm", "keyctl", "add_key",
                     "request_key", "reboot", "kexec_load", "init_module", "finit_module",
                     "delete_module", "perf_event_open", "userfaultfd", "open_by_handle_at",
                     "name_to_handle_at", "pidfd_getfd", "pidfd_open", "seccomp"}
        self.assertFalse(forbidden.intersection(self.allowed))
        self.assertTrue({"execve", "fork", "vfork", "kill", "tgkill", "mmap", "mprotect",
                         "memfd_create", "getrandom", "rseq", "membarrier"}.issubset(self.allowed))

    def test_special_syscalls_cannot_be_unconditionally_allowed(self):
        special = {"socket", "socketpair", "clone", "clone3", "ioctl", "prctl", "close_range"}
        self.assertFalse(special.intersection(self.allowed))
        self.assertIn("SECCOMP_RET_ERRNO | ENOSYS", PRODUCT)
        self.assertRegex(self.builder, r"__NR_clone3, 0, 1\);\s+stmt\(b, BPF_RET \| BPF_K, UNSUPPORTED\)")

    def test_socket_rules_only_tcp4_or_unix(self):
        policy = function(PRODUCT, "socket_policy")
        for required in ("{ AF_UNIX, AF_INET }", "pair ? 1 : 2", "ARG_HI(0)", "ARG_HI(1)",
                         "ARG_HI(2)", "SOCK_CLOEXEC | SOCK_NONBLOCK", "SOCK_STREAM",
                         "SOCK_DGRAM", "SOCK_SEQPACKET", "{ 0, 6 }"):
            self.assertIn(required, policy)
        for forbidden in ("AF_INET6", "AF_PACKET", "AF_NETLINK", "SOCK_RAW", "IPPROTO_UDP"):
            self.assertNotIn(forbidden, policy)
        self.assertIn("require_eq(b, ARG_LO(2), 0)", policy)

    def test_clone_is_positive_flag_mask_and_no_newtime(self):
        flags = re.search(r"clone_allowed = ([^;]+);", self.builder).group(1)
        actual = set(re.findall(r"CLONE_\w+", flags))
        self.assertEqual(actual, {"CLONE_VM", "CLONE_FS", "CLONE_FILES", "CLONE_SIGHAND",
                                  "CLONE_THREAD", "CLONE_SYSVSEM", "CLONE_SETTLS",
                                  "CLONE_PARENT_SETTID", "CLONE_CHILD_CLEARTID",
                                  "CLONE_CHILD_SETTID", "CLONE_VFORK"})
        self.assertIn("require_mask(b, ARG_LO(0), ~clone_allowed)", self.builder)
        self.assertIn("require_mask(b, ARG_LO(0), CLONE_NEWTIME)", self.builder)

    def test_ioctl_prctl_and_close_range_are_narrow(self):
        ioctls = re.search(r"ioctls\[\] = \{([^}]+)}", self.builder).group(1)
        self.assertEqual(set(re.findall(r"\w+", ioctls)),
                          {"FIONBIO", "FIONREAD", "FIOCLEX", "TCGETS", "TIOCGWINSZ", "TIOCGPGRP"})
        names = re.search(r"names\[\] = \{([^}]+)}", self.builder).group(1)
        self.assertEqual(set(re.findall(r"\w+", names)), {"PR_SET_NAME", "PR_GET_NAME"})
        self.assertIn("close_flags[] = { 0, 4 }", self.builder)
        for argument in (0, 1, 2):
            self.assertIn(f"require_eq(b, ARG_HI({argument}), 0)", PRODUCT)

    def test_special_blocks_have_bounded_forward_skip(self):
        end = function(PRODUCT, "special_end")
        self.assertIn("length > 255", end)
        self.assertIn("b->code[at].jf = (unsigned char)length", end)
        one_of = function(PRODUCT, "require_one_of")
        self.assertIn("count > 254", one_of)
        self.assertIn("(unsigned char)(count - j)", one_of)
        for count in range(1, 255):
            # One LD; count comparisons; one denial; success is the following insn.
            for j in range(count):
                self.assertEqual(1 + j + 1 + count - j, count + 2)

    def test_only_trusted_root_direct_child_of_init(self):
        for required in ("getuid() != 0", "geteuid() != 0", "getppid() != 1", "getpid() == 1"):
            self.assertIn(required, self.main)
        self.assertLess(self.main.index('fail("authority")'), self.main.index("setgroups(0, NULL)"))

    def test_fixed_nonroot_identity_and_bounded_absolute_exec(self):
        parser = function(PRODUCT, "parse_cli")
        for required in ('strcmp(argv[at], "--uid")', 'strcmp(argv[at], "--gid")',
                         'strcmp(argv[at + 1], "20001")', "argv[*executable][0] != '/'",
                         "MAX_ARGS + 8", "MAX_ARG_BYTES - bytes", "argc - at - 1 > MAX_ARGS",
                         "strnlen(argv[j], MAX_ARG_BYTES + 1)"):
            self.assertIn(required, parser)
        self.assertIn("execv(argv[executable], &argv[executable])", self.main)
        self.assertNotRegex(PRODUCT, r"\b(?:system|popen|execvp|execlp|execle|execveat)\s*\(")
        self.assertNotIn("/bin/sh", PRODUCT)

    def test_profile_cli_default_compatibility_and_unknown_fail_closed(self):
        parser = function(PRODUCT, "parse_cli")
        self.assertIn("*profile = PROFILE_PRODUCT", parser)
        self.assertIn('strcmp(argv[at], "--profile")', parser)
        self.assertRegex(parser, r'if \(strcmp\(argv\[at \+ 1\], "product"\) == 0\) \*profile = PROFILE_PRODUCT;\s+'
                                r'else if \(strcmp\(argv\[at \+ 1\], "coordinator"\) == 0\) \*profile = PROFILE_COORDINATOR;\s+'
                                r'else return -1;')
        self.assertIn("if (seen & bit) return -1", parser)
        self.assertIn("(seen & 3) != 3", parser)
        self.assertIn('strcmp(argv[at], "--") != 0', parser)
        self.assertIn("if (at + 1 >= argc) return -1", parser)
        self.assertIn("parse_cli(argc, argv, &profile, &executable)", self.main)
        self.assertIn("build_filter(&filter, profile)", self.main)
        self.assertIn("profile != PROFILE_PRODUCT && profile != PROFILE_COORDINATOR", self.builder)

    def test_coordinator_has_no_network_syscall_permissions(self):
        network = function(PRODUCT, "network_policy")
        self.assertIn("if (profile != PROFILE_PRODUCT) return;", network)
        self.assertLess(network.index("if (profile != PROFILE_PRODUCT) return;"),
                        network.index("socket_policy("))
        names = set(re.findall(r"ALLOW\((\w+)\);", network)) | {"socket", "socketpair"}
        self.assertEqual(names, {"socket", "socketpair", "connect", "bind", "listen", "accept",
                                 "accept4", "getsockname", "getpeername", "shutdown", "sendto",
                                 "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
                                 "setsockopt", "getsockopt"})
        self.assertFalse(names.intersection(self.allowed))
        self.assertNotIn("socket_policy(", self.builder)
        self.assertEqual(PRODUCT.count("socket_policy(b,"), 2)
        test = function(PRODUCT, "self_test")
        denied = re.search(r"const int network\[\] = \{([^}]+)}", test).group(1)
        self.assertEqual(set(re.findall(r"__NR_(\w+)", denied)), names)
        self.assertIn("evaluate(&coordinator, &d) != DENIED", test)
        self.assertIn("evaluate(&coordinator, &d) != SECCOMP_RET_ALLOW", test)

    def test_coordinator_entrypoint_still_drops_credentials_before_python_exec(self):
        self.assertIn("profile == PROFILE_PRODUCT && (getppid() != 1 || getpid() == 1)", self.main)
        self.assertIn("profile == PROFILE_COORDINATOR && getpid() != 1 && getppid() != 1", self.main)
        transitions = self.main[self.main.index("struct builder filter"):]
        self.assertNotIn("if (profile", transitions)
        self.assertIn("setgroups(0, NULL)", transitions)
        self.assertIn("setgid(20001)", transitions)
        self.assertIn("setuid(20001)", transitions)
        self.assertIn("SYS_close_range", transitions)
        self.assertLess(transitions.index("PR_SET_SECCOMP"), transitions.index("execv("))

    def test_native_profile_self_tests_cover_default_explicit_and_rejection(self):
        native = function(PRODUCT, "self_test")
        for required in ("parse_cli(7, defaults", "profile != PROFILE_PRODUCT", "executable != 6",
                         "parse_cli(9, explicit", "profile != PROFILE_COORDINATOR", "executable != 8",
                         'explicit[2] = "product"', 'explicit[2] = "unknown"', 'explicit[2] = ""',
                         "parse_cli(11, duplicate", "build_filter(&coordinator, (enum profile)99)"):
            self.assertIn(required, native)

    def test_credential_drop_verify_seccomp_exec_order(self):
        tokens = ["setrlimit(RLIMIT_CORE", "setgroups(0, NULL)", "setgid(20001)", "setuid(20001)",
                  "getresuid(", "getresgid(", "empty_capabilities()", "PR_SET_NO_NEW_PRIVS",
                  "SYS_close_range", "PR_SET_SECCOMP", "execv("]
        positions = [self.main.index(token) for token in tokens]
        self.assertEqual(positions, sorted(positions))
        self.assertIn(".rlim_cur = 0, .rlim_max = 0", self.main)
        for identity in ("ruid", "euid", "suid", "rgid", "egid", "sgid"):
            self.assertIn(f"{identity} != 20001", self.main)
        self.assertIn("getgroups(0, NULL) != 0", self.main)

    def test_capability_drop_readback_and_no_false_bounding_claim(self):
        capabilities = function(PRODUCT, "empty_capabilities")
        for required in ("memset(data, 0", "SYS_capset", "PR_CAP_AMBIENT_CLEAR_ALL", "SYS_capget",
                         ".effective", ".permitted", ".inheritable", "PR_CAP_AMBIENT_IS_SET"):
            self.assertIn(required, capabilities)
        self.assertNotIn("PR_CAPBSET_DROP", PRODUCT)
        self.assertNotIn("CAP_SETPCAP", PRODUCT)
        self.assertIn("bounding set is **not** claimed empty", NOTES)

    def test_no_descriptor_fallback_or_credential_retention(self):
        self.assertIn("syscall(SYS_close_range, 3U, UINT_MAX, 0U)", self.main)
        self.assertNotRegex(without_comments(self.main), r"/proc|RLIMIT_NOFILE|PR_SET_KEEPCAPS")
        self.assertIn("PR_GET_NO_NEW_PRIVS", self.main)
        self.assertIn("if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) return fail", self.main)

    def test_closed_product_error_schema(self):
        failure = function(PRODUCT, "fail")
        self.assertEqual(set(re.findall(r'\\"(\w+)\\":', failure)), {"schema", "kind", "ok", "code"})
        codes = set(re.findall(r'fail\("([a-z_]+)"\)', PRODUCT))
        self.assertEqual(codes, {"arguments", "authority", "policy_build", "credentials",
                                 "no_new_privileges", "descriptors", "seccomp", "exec", "self_test"})


class NativeContractTests(unittest.TestCase):
    def test_no_native_side_effect_imports_in_this_test(self):
        tree = ast.parse(pathlib.Path(__file__).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        self.assertEqual(imported, {"ast", "pathlib", "re", "unittest"})

    def test_native_self_tests_do_not_install_policies(self):
        for source in (KERNEL, PRODUCT):
            test = function(source, "self_test")
            self.assertNotRegex(test, r"\b(?:syscall|prctl|bpf_call|attachment|load_program|execv)\s*\(")
            main = function(source, "main")
            self.assertLess(main.index('"--self-test"'), main.index("geteuid()"))
        self.assertIn("interpret(program", function(KERNEL, "self_test"))
        self.assertIn("evaluate(&b", function(PRODUCT, "self_test"))

    def test_errors_never_disclose_raw_diagnostics(self):
        for source in (KERNEL, PRODUCT):
            with self.subTest(source="kernel" if source is KERNEL else "product"):
                self.assertNotRegex(source, r"\b(?:perror|strerror|fprintf|dprintf|system|popen)\s*\(")
                failure = without_comments(function(source, "fail"))
                self.assertNotRegex(failure, r"argv|errno|environ|STDERR_FILENO|%[diux]")

    def test_notes_freeze_build_events_failure_and_evidence(self):
        for required in ("-std=c11 -O2 -Wall -Wextra -Werror", "--cgroup-fd", "--ports",
                         "--deadline", "--uid 20001 --gid 20001 --", "STOP", "EPERM", "ENOSYS",
                         "cleanup_uncertain", "PR_SET_NAME", "native execution is unverified"):
            self.assertIn(required, NOTES)
        self.assertIn("not kernel enforcement evidence", NOTES)
        self.assertIn("--profile product|coordinator", NOTES)
        self.assertIn("coordinator's seccomp is installed before Python exec", NOTES)


if __name__ == "__main__":
    unittest.main()
