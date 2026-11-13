/* Pinned init/entrypoint invokes this fixed-command credential/seccomp boundary. */
#define _GNU_SOURCE
#if !defined(__linux__) || !defined(__x86_64__)
#error "native Linux AMD64 required"
#endif
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <termios.h>
#include <unistd.h>

enum { MAX_FILTER = 512, MAX_ARGS = 128, MAX_ARG_BYTES = 65536 };
enum profile { PROFILE_PRODUCT, PROFILE_COORDINATOR };
#define DENIED (SECCOMP_RET_ERRNO | EPERM)
#define UNSUPPORTED (SECCOMP_RET_ERRNO | ENOSYS)
#define ARG_LO(n) ((unsigned int)offsetof(struct seccomp_data, args[n]))
#define ARG_HI(n) (ARG_LO(n) + 4U)
struct builder { struct sock_filter code[MAX_FILTER]; size_t count; int failed; };
static void stmt(struct builder *b, unsigned short code, uint32_t k) {
    if (b->count == MAX_FILTER) { b->failed = 1; return; }
    b->code[b->count++] = (struct sock_filter)BPF_STMT(code, k);
}
static void jump(struct builder *b, unsigned short code, uint32_t k,
                  unsigned char yes, unsigned char no) {
    if (b->count == MAX_FILTER) { b->failed = 1; return; }
    b->code[b->count++] = (struct sock_filter)BPF_JUMP(code, k, yes, no);
}
static void require_eq(struct builder *b, unsigned int offset, uint32_t value) {
    stmt(b, BPF_LD | BPF_W | BPF_ABS, offset);
    jump(b, BPF_JMP | BPF_JEQ | BPF_K, value, 1, 0);
    stmt(b, BPF_RET | BPF_K, DENIED);
}
static void require_mask(struct builder *b, unsigned int offset, uint32_t forbidden) {
    stmt(b, BPF_LD | BPF_W | BPF_ABS, offset);
    jump(b, BPF_JMP | BPF_JSET | BPF_K, forbidden, 0, 1);
    stmt(b, BPF_RET | BPF_K, DENIED);
}
static void require_one_of(struct builder *b, unsigned int offset,
                           const uint32_t *values, size_t count) {
    stmt(b, BPF_LD | BPF_W | BPF_ABS, offset);
    if (count > 254) { b->failed = 1; return; }
    for (size_t j = 0; j < count; ++j)
        jump(b, BPF_JMP | BPF_JEQ | BPF_K, values[j], (unsigned char)(count - j), 0);
    stmt(b, BPF_RET | BPF_K, DENIED);
}
static size_t special_begin(struct builder *b, unsigned int nr) {
    size_t at = b->count;
    jump(b, BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 0);
    return at;
}
static void special_end(struct builder *b, size_t at) {
    stmt(b, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    size_t length = b->count - at - 1;
    if (length > 255 || at >= MAX_FILTER) { b->failed = 1; return; }
    b->code[at].jf = (unsigned char)length;
    /* Each argument block destroys A; nonmatching dispatch preserves syscall A. */
}
static void socket_policy(struct builder *b, unsigned int nr, int pair) {
    size_t at = special_begin(b, nr);
    require_eq(b, ARG_HI(0), 0);
    require_eq(b, ARG_HI(1), 0);
    require_eq(b, ARG_HI(2), 0);
    uint32_t families[] = { AF_UNIX, AF_INET };
    require_one_of(b, ARG_LO(0), families, pair ? 1 : 2);
    require_mask(b, ARG_LO(1), ~(uint32_t)(SOCK_CLOEXEC | SOCK_NONBLOCK | 0xf));
    stmt(b, BPF_LD | BPF_W | BPF_ABS, ARG_LO(0));
    /* Unix sockets: stream/dgram/seqpacket, protocol zero only. */
    size_t is_inet = b->count;
    jump(b, BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 0, 0);
    require_eq(b, ARG_LO(2), 0);
    stmt(b, BPF_LD | BPF_W | BPF_ABS, ARG_LO(1));
    stmt(b, BPF_ALU | BPF_AND | BPF_K, 0xf);
    jump(b, BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 3, 0);
    jump(b, BPF_JMP | BPF_JEQ | BPF_K, SOCK_DGRAM, 2, 0);
    jump(b, BPF_JMP | BPF_JEQ | BPF_K, SOCK_SEQPACKET, 1, 0);
    stmt(b, BPF_RET | BPF_K, DENIED);
    stmt(b, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    if (b->count - is_inet - 1 > 255) b->failed = 1;
    else b->code[is_inet].jt = (unsigned char)(b->count - is_inet - 1);
    /* IPv4 must be TCP stream, not UDP/raw or another protocol. */
    uint32_t protocols[] = { 0, 6 }; /* IPPROTO_TCP */
    require_one_of(b, ARG_LO(2), protocols, 2);
    stmt(b, BPF_LD | BPF_W | BPF_ABS, ARG_LO(1));
    stmt(b, BPF_ALU | BPF_AND | BPF_K, ~(uint32_t)(SOCK_CLOEXEC | SOCK_NONBLOCK));
    jump(b, BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 1, 0);
    stmt(b, BPF_RET | BPF_K, DENIED);
    special_end(b, at);
}
static void network_policy(struct builder *b, enum profile profile) {
    /* The JSON-stdio coordinator gets NONE of the product network permissions. */
    if (profile != PROFILE_PRODUCT) return;
    socket_policy(b, __NR_socket, 0);
    socket_policy(b, __NR_socketpair, 1);
#define ALLOW(name) do { \
    jump(b, BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1); \
    stmt(b, BPF_RET | BPF_K, SECCOMP_RET_ALLOW); \
} while (0)
    ALLOW(bind); ALLOW(connect); ALLOW(listen); ALLOW(accept); ALLOW(accept4);
    ALLOW(getsockname); ALLOW(getpeername); ALLOW(shutdown);
    ALLOW(sendto); ALLOW(recvfrom); ALLOW(sendmsg); ALLOW(recvmsg);
    ALLOW(sendmmsg); ALLOW(recvmmsg); ALLOW(setsockopt); ALLOW(getsockopt);
#undef ALLOW
}
static int build_filter(struct builder *b, enum profile profile) {
    memset(b, 0, sizeof(*b));
    if (profile != PROFILE_PRODUCT && profile != PROFILE_COORDINATOR) return -1;
    stmt(b, BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    jump(b, BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    stmt(b, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    stmt(b, BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    jump(b, BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1); /* reject x32 ABI */
    stmt(b, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    jump(b, BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1);
    stmt(b, BPF_RET | BPF_K, UNSUPPORTED); /* glibc's documented clone fallback */
    network_policy(b, profile);
    size_t at = special_begin(b, __NR_clone);
    require_eq(b, ARG_HI(0), 0);
    /* Positive flag mask: excludes NEW*, PTRACE, UNTRACED, PARENT, IO and unknown. */
    const uint32_t clone_allowed = 0xffU | CLONE_VM | CLONE_FS | CLONE_FILES |
        CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
        CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | CLONE_VFORK;
    require_mask(b, ARG_LO(0), ~clone_allowed);
    /* CLONE_NEWTIME shares the legacy CSIGNAL byte; reject that bit explicitly. */
    require_mask(b, ARG_LO(0), CLONE_NEWTIME);
    special_end(b, at);
    at = special_begin(b, __NR_ioctl);
    require_eq(b, ARG_HI(1), 0);
    /* FIOCLEX only sets close-on-exec (CPython's fopen launcher); never FIONCLEX. */
    const uint32_t ioctls[] = { FIONBIO, FIONREAD, FIOCLEX, TCGETS, TIOCGWINSZ, TIOCGPGRP };
    require_one_of(b, ARG_LO(1), ioctls, sizeof(ioctls) / sizeof(ioctls[0]));
    special_end(b, at);
    at = special_begin(b, __NR_prctl);
    require_eq(b, ARG_HI(0), 0);
    const uint32_t names[] = { PR_SET_NAME, PR_GET_NAME };
    require_one_of(b, ARG_LO(0), names, sizeof(names) / sizeof(names[0]));
    special_end(b, at);
    at = special_begin(b, __NR_close_range);
    require_eq(b, ARG_HI(2), 0);
    const uint32_t close_flags[] = { 0, 4 }; /* zero or CLOSE_RANGE_CLOEXEC only */
    require_one_of(b, ARG_LO(2), close_flags, 2);
    special_end(b, at);
    /* Ordinary userspace only. No catch-all, privileged prctl, capabilities, namespaces,
       ptrace, process_vm, bpf, io_uring, keyring, perf, mount or kernel control. */
#define ALLOW(name) do { \
    jump(b, BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1); \
    stmt(b, BPF_RET | BPF_K, SECCOMP_RET_ALLOW); \
} while (0)
    ALLOW(read); ALLOW(write); ALLOW(readv); ALLOW(writev);
    ALLOW(pread64); ALLOW(pwrite64); ALLOW(preadv); ALLOW(pwritev);
    ALLOW(close); ALLOW(lseek); ALLOW(dup); ALLOW(dup2); ALLOW(dup3);
    ALLOW(fcntl); ALLOW(pipe); ALLOW(pipe2);
    ALLOW(open); ALLOW(openat); ALLOW(creat); ALLOW(access); ALLOW(faccessat);
    ALLOW(faccessat2); ALLOW(stat); ALLOW(lstat); ALLOW(fstat); ALLOW(newfstatat);
    ALLOW(statx); ALLOW(statfs); ALLOW(fstatfs); ALLOW(getdents); ALLOW(getdents64);
    ALLOW(readlink); ALLOW(readlinkat); ALLOW(getcwd); ALLOW(chdir); ALLOW(fchdir);
    ALLOW(mkdir); ALLOW(mkdirat); ALLOW(rmdir); ALLOW(unlink); ALLOW(unlinkat);
    ALLOW(rename); ALLOW(renameat); ALLOW(renameat2); ALLOW(link); ALLOW(linkat);
    ALLOW(symlink); ALLOW(symlinkat); ALLOW(chmod); ALLOW(fchmod); ALLOW(fchmodat);
    ALLOW(umask); ALLOW(truncate); ALLOW(ftruncate); ALLOW(fallocate);
    ALLOW(fsync); ALLOW(fdatasync); ALLOW(flock); ALLOW(utime); ALLOW(utimes);
    ALLOW(utimensat); ALLOW(futimesat); ALLOW(copy_file_range); ALLOW(sendfile);
    ALLOW(memfd_create); ALLOW(fadvise64);
    ALLOW(mmap); ALLOW(mprotect); ALLOW(munmap); ALLOW(mremap); ALLOW(madvise);
    ALLOW(brk); ALLOW(msync); ALLOW(mincore);
    ALLOW(rt_sigaction); ALLOW(rt_sigprocmask); ALLOW(rt_sigreturn);
    ALLOW(rt_sigsuspend); ALLOW(rt_sigtimedwait); ALLOW(sigaltstack);
    ALLOW(kill); ALLOW(tkill); ALLOW(tgkill); /* Private PID namespace only. */
    ALLOW(fork); ALLOW(vfork); ALLOW(execve); ALLOW(wait4); ALLOW(waitid);
    ALLOW(exit); ALLOW(exit_group); ALLOW(set_tid_address); ALLOW(set_robust_list);
    ALLOW(get_robust_list); ALLOW(futex); ALLOW(rseq); ALLOW(membarrier);
    ALLOW(arch_prctl); ALLOW(sched_yield); ALLOW(sched_getaffinity);
    ALLOW(sched_getparam); ALLOW(sched_getscheduler); ALLOW(sched_get_priority_max);
    ALLOW(sched_get_priority_min); ALLOW(sched_rr_get_interval);
    ALLOW(clock_gettime); ALLOW(clock_getres); ALLOW(clock_nanosleep);
    ALLOW(nanosleep); ALLOW(gettimeofday); ALLOW(time); ALLOW(times);
    ALLOW(getpid); ALLOW(getppid); ALLOW(gettid); ALLOW(getpgrp); ALLOW(getpgid);
    ALLOW(getsid); ALLOW(setpgid); ALLOW(setsid); ALLOW(getuid); ALLOW(geteuid);
    ALLOW(getgid); ALLOW(getegid); ALLOW(getresuid); ALLOW(getresgid); ALLOW(getgroups);
    ALLOW(getrlimit); ALLOW(getrusage); ALLOW(prlimit64); ALLOW(sysinfo); ALLOW(uname);
    ALLOW(getrandom); ALLOW(getcpu); ALLOW(restart_syscall);
    ALLOW(poll); ALLOW(ppoll); ALLOW(select); ALLOW(pselect6);
    ALLOW(epoll_create); ALLOW(epoll_create1); ALLOW(epoll_ctl); ALLOW(epoll_wait);
    ALLOW(epoll_pwait); ALLOW(epoll_pwait2); ALLOW(eventfd); ALLOW(eventfd2);
    ALLOW(timerfd_create); ALLOW(timerfd_settime); ALLOW(timerfd_gettime);
    ALLOW(setitimer); ALLOW(getitimer); ALLOW(alarm);
#undef ALLOW
    stmt(b, BPF_RET | BPF_K, DENIED);
    return b->failed || b->count > MAX_FILTER ? -1 : 0;
}
static int parse_cli(int argc, char **argv, enum profile *profile, int *executable) {
    if (argc < 7 || argc > MAX_ARGS + 8) return -1;
    *profile = PROFILE_PRODUCT; /* Existing init argv keeps its product policy. */
    unsigned seen = 0;
    int at = 1;
    while (at < argc && strcmp(argv[at], "--") != 0) {
        if (at + 1 >= argc) return -1;
        unsigned bit;
        if (strcmp(argv[at], "--uid") == 0) {
            bit = 1;
            if (strcmp(argv[at + 1], "20001") != 0) return -1;
        } else if (strcmp(argv[at], "--gid") == 0) {
            bit = 2;
            if (strcmp(argv[at + 1], "20001") != 0) return -1;
        } else if (strcmp(argv[at], "--profile") == 0) {
            bit = 4;
            if (strcmp(argv[at + 1], "product") == 0) *profile = PROFILE_PRODUCT;
            else if (strcmp(argv[at + 1], "coordinator") == 0) *profile = PROFILE_COORDINATOR;
            else return -1;
        } else return -1;
        if (seen & bit) return -1; /* Even identical duplicate options fail. */
        seen |= bit;
        at += 2;
    }
    if ((seen & 3) != 3 || at >= argc || argc - at - 1 < 1 || argc - at - 1 > MAX_ARGS)
        return -1;
    *executable = at + 1;
    if (argv[*executable][0] != '/') return -1;
    size_t bytes = 0;
    for (int j = *executable; j < argc; ++j) {
        size_t n = strnlen(argv[j], MAX_ARG_BYTES + 1);
        if (n >= MAX_ARG_BYTES || n + 1 > MAX_ARG_BYTES - bytes) return -1;
        bytes += n + 1;
    }
    return 0;
}
static int fail(const char *code) {
    /* Fixed codes only; never errno, argv, environment, paths or verifier data. */
    char message[128];
    int n = snprintf(message, sizeof(message),
        "{\"schema\":1,\"kind\":\"product-guard\",\"ok\":false,\"code\":\"%s\"}\n", code);
    if (n > 0 && (size_t)n < sizeof(message)) {
        ssize_t ignored = write(STDOUT_FILENO, message, (size_t)n);
        (void)ignored;
    }
    return 1;
}
static int empty_capabilities(void) {
    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof(data));
    if (syscall(SYS_capset, &header, data) ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) return -1;
    if (syscall(SYS_capget, &header, data)) return -1;
    for (size_t j = 0; j < 2; ++j)
        if (data[j].effective || data[j].permitted || data[j].inheritable) return -1;
    for (int cap = 0; cap <= CAP_LAST_CAP; ++cap)
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0) return -1;
    return 0;
}
/* Construction-only interpreter; does NOT install a policy or prove enforcement. */
static uint32_t evaluate(const struct builder *b, const struct seccomp_data *d) {
    uint32_t a = 0;
    const unsigned char *bytes = (const unsigned char *)d;
    for (size_t pc = 0, steps = 0; pc < b->count && steps++ < MAX_FILTER; ++pc) {
        const struct sock_filter *i = &b->code[pc];
        if (i->code == (BPF_LD | BPF_W | BPF_ABS)) {
            if (i->k > sizeof(*d) - sizeof(a) || i->k % 4) return 0;
            memcpy(&a, bytes + i->k, sizeof(a));
        } else if (i->code == (BPF_JMP | BPF_JEQ | BPF_K)) pc += a == i->k ? i->jt : i->jf;
        else if (i->code == (BPF_JMP | BPF_JSET | BPF_K)) pc += (a & i->k) ? i->jt : i->jf;
        else if (i->code == (BPF_ALU | BPF_AND | BPF_K)) a &= i->k;
        else if (i->code == (BPF_RET | BPF_K)) return i->k;
        else return 0;
    }
    return 0;
}
static int self_test(void) {
    struct builder b;
    if (build_filter(&b, PROFILE_PRODUCT)) return fail("self_test");
    struct seccomp_data d;
    memset(&d, 0, sizeof(d));
    d.arch = AUDIT_ARCH_X86_64;
    const int denied[] = { __NR_ptrace, __NR_process_vm_readv, __NR_process_vm_writev,
        __NR_bpf, __NR_setns, __NR_unshare, __NR_mount, __NR_umount2, __NR_io_uring_setup,
        __NR_io_uring_enter, __NR_io_uring_register, __NR_setuid, __NR_setgid, __NR_capset,
        __NR_reboot, __NR_kexec_load, __NR_init_module, __NR_finit_module, __NR_perf_event_open,
        __NR_open_by_handle_at, __NR_userfaultfd, __NR_keyctl, 999999 };
    for (size_t j = 0; j < sizeof(denied) / sizeof(denied[0]); ++j) {
        d.nr = denied[j];
        if (evaluate(&b, &d) != DENIED) return fail("self_test");
    }
    d.nr = __NR_clone3;
    if (evaluate(&b, &d) != UNSUPPORTED) return fail("self_test");
    d.nr = __NR_read;
    if (evaluate(&b, &d) != SECCOMP_RET_ALLOW) return fail("self_test");
    d.arch = AUDIT_ARCH_I386;
    if (evaluate(&b, &d) != SECCOMP_RET_KILL_PROCESS) return fail("self_test");
    d.arch = AUDIT_ARCH_X86_64;
    d.nr = __NR_read | 0x40000000U;
    if (evaluate(&b, &d) != SECCOMP_RET_KILL_PROCESS) return fail("self_test");
    for (size_t j = 0; j < b.count; ++j) {
        const struct sock_filter *i = &b.code[j];
        if ((i->code == (BPF_JMP | BPF_JEQ | BPF_K) ||
             i->code == (BPF_JMP | BPF_JSET | BPF_K)) &&
            (j + 1 + i->jt >= b.count || j + 1 + i->jf >= b.count)) return fail("self_test");
    }
    for (int nr = 0; nr < 2; ++nr) {
        d.nr = nr ? __NR_socketpair : __NR_socket;
        for (unsigned family = 0; family <= 46; ++family) {
            for (unsigned type = 0; type <= 15; ++type) {
                for (unsigned proto = 0; proto <= 17; ++proto) {
                    d.args[0] = family; d.args[1] = type | SOCK_CLOEXEC | SOCK_NONBLOCK;
                    d.args[2] = proto;
                    int allowed = (family == AF_UNIX && proto == 0 &&
                        (type == SOCK_STREAM || type == SOCK_DGRAM || type == SOCK_SEQPACKET)) ||
                        (!nr && family == AF_INET && type == SOCK_STREAM && (proto == 0 || proto == 6));
                    if (evaluate(&b, &d) != (allowed ? SECCOMP_RET_ALLOW : DENIED)) return fail("self_test");
                }
            }
        }
    }
    memset(d.args, 0, sizeof(d.args));
    d.nr = __NR_socket;
    d.args[0] = AF_INET; d.args[1] = SOCK_STREAM;
    for (unsigned arg = 0; arg < 3; ++arg) {
        d.args[arg] |= UINT64_C(1) << 32;
        if (evaluate(&b, &d) != DENIED) return fail("self_test");
        d.args[arg] &= UINT32_MAX;
    }
    d.args[1] |= 0x100;
    if (evaluate(&b, &d) != DENIED) return fail("self_test");
    memset(d.args, 0, sizeof(d.args));
    d.nr = __NR_clone;
    for (unsigned bit = 0; bit < 64; ++bit) {
        d.args[0] = UINT64_C(1) << bit;
        int allowed = bit < 7 || bit == 8 || bit == 9 || bit == 10 || bit == 11 ||
            bit == 14 || bit == 16 || bit == 18 || bit == 19 || bit == 20 || bit == 21 || bit == 24;
        if (evaluate(&b, &d) != (allowed ? SECCOMP_RET_ALLOW : DENIED)) return fail("self_test");
    }
    memset(d.args, 0, sizeof(d.args));
    d.nr = __NR_ioctl;
    for (unsigned request = 0; request < 65536; ++request) {
        d.args[1] = request;
        int allowed = request == FIONBIO || request == FIONREAD || request == FIOCLEX || request == TCGETS ||
                      request == TIOCGWINSZ || request == TIOCGPGRP;
        if (evaluate(&b, &d) != (allowed ? SECCOMP_RET_ALLOW : DENIED)) return fail("self_test");
    }
    d.args[1] = (UINT64_C(1) << 32) | FIONBIO;
    if (evaluate(&b, &d) != DENIED) return fail("self_test");
    d.args[1] = FIONCLEX; /* Clearing close-on-exec is not the launcher exception. */
    if (evaluate(&b, &d) != DENIED) return fail("self_test");
    memset(d.args, 0, sizeof(d.args));
    d.nr = __NR_prctl;
    for (unsigned option = 0; option < 100; ++option) {
        d.args[0] = option;
        int allowed = option == PR_SET_NAME || option == PR_GET_NAME;
        if (evaluate(&b, &d) != (allowed ? SECCOMP_RET_ALLOW : DENIED)) return fail("self_test");
    }
    memset(d.args, 0, sizeof(d.args));
    d.nr = __NR_close_range;
    for (unsigned flags = 0; flags < 16; ++flags) {
        d.args[2] = flags;
        if (evaluate(&b, &d) != ((flags == 0 || flags == 4) ? SECCOMP_RET_ALLOW : DENIED))
            return fail("self_test");
    }
    struct builder coordinator;
    if (build_filter(&coordinator, PROFILE_COORDINATOR)) return fail("self_test");
    memset(&d, 0, sizeof(d));
    d.arch = AUDIT_ARCH_X86_64;
    const int network[] = { __NR_socket, __NR_socketpair, __NR_connect, __NR_bind,
        __NR_listen, __NR_accept, __NR_accept4, __NR_getsockname, __NR_getpeername,
        __NR_shutdown, __NR_sendto, __NR_recvfrom, __NR_sendmsg, __NR_recvmsg,
        __NR_sendmmsg, __NR_recvmmsg, __NR_setsockopt, __NR_getsockopt };
    for (size_t j = 0; j < sizeof(network) / sizeof(network[0]); ++j) {
        d.nr = network[j];
        if (evaluate(&coordinator, &d) != DENIED) return fail("self_test");
        d.args[0] = AF_INET; d.args[1] = SOCK_STREAM; d.args[2] = 6;
        if (evaluate(&coordinator, &d) != DENIED) return fail("self_test");
        memset(d.args, 0, sizeof(d.args));
    }
    const int stdio[] = { __NR_read, __NR_write, __NR_close, __NR_poll, __NR_ppoll,
        __NR_epoll_wait, __NR_execve, __NR_openat, __NR_mmap, __NR_getpid, __NR_exit_group };
    for (size_t j = 0; j < sizeof(stdio) / sizeof(stdio[0]); ++j) {
        d.nr = stdio[j];
        if (evaluate(&coordinator, &d) != SECCOMP_RET_ALLOW) return fail("self_test");
    }
    if (build_filter(&coordinator, (enum profile)99) == 0) return fail("self_test");
    enum profile profile;
    int executable;
    char *defaults[] = { "guard", "--uid", "20001", "--gid", "20001", "--", "/fixed" };
    char *explicit[] = { "guard", "--profile", "coordinator", "--uid", "20001", "--gid", "20001", "--", "/fixed" };
    if (parse_cli(7, defaults, &profile, &executable) || profile != PROFILE_PRODUCT || executable != 6 ||
        parse_cli(9, explicit, &profile, &executable) || profile != PROFILE_COORDINATOR || executable != 8)
        return fail("self_test");
    explicit[2] = "product";
    if (parse_cli(9, explicit, &profile, &executable) || profile != PROFILE_PRODUCT) return fail("self_test");
    explicit[2] = "unknown";
    if (parse_cli(9, explicit, &profile, &executable) == 0) return fail("self_test");
    explicit[2] = "";
    if (parse_cli(9, explicit, &profile, &executable) == 0) return fail("self_test");
    char *duplicate[] = { "guard", "--uid", "20001", "--gid", "20001", "--profile", "product",
                          "--profile", "coordinator", "--", "/fixed" };
    if (parse_cli(11, duplicate, &profile, &executable) == 0) return fail("self_test");
    char *reordered[] = { "guard", "--gid", "20001", "--uid", "20001", "--profile", "coordinator",
                          "--", "/fixed", "--profile", "product" };
    if (parse_cli(11, reordered, &profile, &executable) ||
        profile != PROFILE_COORDINATOR || executable != 8) return fail("self_test");
    reordered[5] = "--unknown";
    if (parse_cli(11, reordered, &profile, &executable) == 0) return fail("self_test");
    static const char ok[] = "{\"schema\":1,\"kind\":\"product-guard-self-test\",\"ok\":true}\n";
    return write(STDOUT_FILENO, ok, sizeof(ok) - 1) == (ssize_t)(sizeof(ok) - 1) ? 0 : 1;
}
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return self_test();
    enum profile profile;
    int executable;
    if (parse_cli(argc, argv, &profile, &executable)) return fail("arguments");
    /* Admission pins image/UID/namespaces. Coordinator may be the entrypoint;
       a product must remain a child of its separate trusted PID-1 supervisor. */
    if (getuid() != 0 || geteuid() != 0 ||
        (profile == PROFILE_PRODUCT && (getppid() != 1 || getpid() == 1)) ||
        (profile == PROFILE_COORDINATOR && getpid() != 1 && getppid() != 1))
        return fail("authority");
    struct builder filter;
    if (build_filter(&filter, profile)) return fail("policy_build");
    struct rlimit core = { .rlim_cur = 0, .rlim_max = 0 };
    if (setrlimit(RLIMIT_CORE, &core) || setgroups(0, NULL) || setgid(20001) || setuid(20001))
        return fail("credentials");
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    if (getresuid(&ruid, &euid, &suid) || getresgid(&rgid, &egid, &sgid) ||
        ruid != 20001 || euid != 20001 || suid != 20001 ||
        rgid != 20001 || egid != 20001 || sgid != 20001 || getgroups(0, NULL) != 0 ||
        empty_capabilities()) return fail("credentials");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        return fail("no_new_privileges");
    /* Required native runner facility. No racy /proc or guessed-RLIMIT fallback. */
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U)) return fail("descriptors");
    struct sock_fprog program = { .len = (unsigned short)filter.count, .filter = filter.code };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) return fail("seccomp");
    execv(argv[executable], &argv[executable]);
    return fail("exec");
}
