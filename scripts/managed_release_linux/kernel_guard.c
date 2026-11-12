/* Linux AMD64 only. No libbpf, maps, verifier output, paths or shell commands. */
#define _GNU_SOURCE
#if !defined(__linux__) || !defined(__x86_64__)
#error "native Linux AMD64 required"
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/magic.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

enum { MAX_PORTS = 16, MAX_INSNS = 32, HOOKS = 4 };
static const enum bpf_attach_type hooks[HOOKS] = {
    BPF_CGROUP_INET4_BIND, BPF_CGROUP_INET4_CONNECT,
    BPF_CGROUP_INET6_BIND, BPF_CGROUP_INET6_CONNECT
};
static volatile sig_atomic_t interrupted;
static void on_signal(int signum) { (void)signum; interrupted = 1; }

static int bpf_call(enum bpf_cmd cmd, union bpf_attr *attr) {
    return (int)syscall(SYS_bpf, cmd, attr, sizeof(*attr));
}
static double monotonic_now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return -1;
    return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0;
}
static int decimal(const char *s, unsigned long max, unsigned long *out) {
    unsigned long n = 0;
    if (*s == '\0') return -1;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9') return -1;
        unsigned digit = (unsigned)(*s - '0');
        if (digit > max || n > (max - digit) / 10)
            return -1;
        n = n * 10 + digit;
        if (n > max) return -1;
    }
    *out = n;
    return 0;
}
static int parse_ports(const char *s, uint16_t ports[MAX_PORTS], size_t *count) {
    *count = 0;
    if (*s == '\0') return 0; /* Empty means deny all, never a wildcard. */
    while (*s) {
        char word[6];
        size_t n = 0;
        unsigned long port;
        while (*s && *s != ',') {
            if (n == sizeof(word) - 1) return -1;
            word[n++] = *s++;
        }
        word[n] = '\0';
        if (decimal(word, 65535, &port) || port < 1024 ||
            port == 5432 || port == 54322 || *count == MAX_PORTS) return -1;
        size_t at = 0;
        while (at < *count && ports[at] < port) ++at;
        if (at < *count && ports[at] == port) return -1;
        memmove(&ports[at + 1], &ports[at], (*count - at) * sizeof(*ports));
        ports[at] = (uint16_t)port;
        ++*count;
        if (*s == ',' && *++s == '\0') return -1;
    }
    return 0;
}
static int parse_deadline(const char *s, double now, double *deadline) {
    size_t digits = 0, fraction = 0;
    const char *p = s;
    while (*p >= '0' && *p <= '9') { ++digits; ++p; }
    if (!digits || digits > 12) return -1;
    if (*p == '.') {
        ++p;
        while (*p >= '0' && *p <= '9') { ++fraction; ++p; }
        if (!fraction || fraction > 9) return -1;
    }
    if (*p) return -1;
    char *end;
    errno = 0;
    double d = strtod(s, &end);
    if (errno || *end || !isfinite(d) || now < 0 || d <= now || d > now + 3600.0)
        return -1;
    *deadline = d;
    return 0;
}
static struct bpf_insn insn(unsigned char code, unsigned char dst,
                            unsigned char src, short off, int imm) {
    struct bpf_insn i = { .code = code, .dst_reg = dst, .src_reg = src,
                          .off = off, .imm = imm };
    return i;
}
/* Only forward branches, no helpers, maps, memory writes or mutable state. */
static size_t build_program(struct bpf_insn out[MAX_INSNS], int ipv4,
                            const uint16_t *ports, size_t count) {
    size_t n = 0;
    if (ipv4 && count) {
        out[n++] = insn(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_0, BPF_REG_1,
                        offsetof(struct bpf_sock_addr, user_ip4), 0);
        out[n++] = insn(BPF_JMP | BPF_JNE | BPF_K, BPF_REG_0, 0,
                        (short)(count + 1), (int)htonl(INADDR_LOOPBACK));
        out[n++] = insn(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_0, BPF_REG_1,
                        offsetof(struct bpf_sock_addr, user_port), 0);
        for (size_t j = 0; j < count; ++j)
            out[n++] = insn(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0,
                            (short)(count - j + 1), (int)htons(ports[j]));
    }
    out[n++] = insn(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0);
    out[n++] = insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
    if (ipv4 && count) {
        out[n++] = insn(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 1);
        out[n++] = insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
    }
    return n;
}
static int load_program(enum bpf_attach_type hook, int ipv4,
                        const uint16_t *ports, size_t count, uint32_t *id) {
    struct bpf_insn program[MAX_INSNS];
    size_t n = build_program(program, ipv4, ports, count);
    static const char license[] = "GPL";
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.prog_type = BPF_PROG_TYPE_CGROUP_SOCK_ADDR;
    a.expected_attach_type = hook;
    a.insn_cnt = (uint32_t)n;
    a.insns = (uint64_t)(uintptr_t)program;
    a.license = (uint64_t)(uintptr_t)license;
    /* Deliberately no verifier log buffer. */
    int fd = bpf_call(BPF_PROG_LOAD, &a);
    if (fd < 0) return -1;
    struct bpf_prog_info info;
    memset(&info, 0, sizeof(info));
    memset(&a, 0, sizeof(a));
    a.info.bpf_fd = (uint32_t)fd;
    a.info.info_len = sizeof(info);
    a.info.info = (uint64_t)(uintptr_t)&info;
    if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &a) < 0 || !info.id ||
        info.type != BPF_PROG_TYPE_CGROUP_SOCK_ADDR) { close(fd); return -1; }
    *id = info.id;
    return fd;
}
/* A bounded list: overflow/unsupported queries are uncertainty, never absence. */
static int query_exact(int cgroup, enum bpf_attach_type hook, uint32_t id,
                       int effective) {
    uint32_t ids[64] = {0};
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.query.target_fd = (uint32_t)cgroup;
    a.query.attach_type = hook;
    a.query.query_flags = effective ? BPF_F_QUERY_EFFECTIVE : 0;
    a.query.prog_ids = (uint64_t)(uintptr_t)ids;
    a.query.prog_cnt = 64;
    if (bpf_call(BPF_PROG_QUERY, &a) < 0 || a.query.attach_flags != 0) return -1;
    if (!id) return a.query.prog_cnt == 0 ? 0 : -1;
    return a.query.prog_cnt == 1 && ids[0] == id ? 0 : -1;
}
static int attachment(int cmd, int cgroup, enum bpf_attach_type hook, int fd) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.target_fd = (uint32_t)cgroup;
    a.attach_bpf_fd = (uint32_t)fd;
    a.attach_type = hook;
    /* Exclusive attachment: no ALLOW_OVERRIDE, ALLOW_MULTI or REPLACE. */
    return bpf_call((enum bpf_cmd)cmd, &a);
}
static int emit(const char *s) {
    size_t n = strlen(s);
    ssize_t written;
    do { written = write(STDOUT_FILENO, s, n); } while (written < 0 && errno == EINTR);
    return written == (ssize_t)n ? 0 : -1;
}
static int fail(const char *code) {
    char message[160];
    int n = snprintf(message, sizeof(message),
        "{\"schema\":1,\"kind\":\"kernel-policy\",\"ready\":false,\"code\":\"%s\"}\n", code);
    if (n > 0 && (size_t)n < sizeof(message)) (void)emit(message);
    return 1;
}
static int ready(const uint32_t ids[HOOKS], const struct stat *st,
                  const uint16_t *ports, size_t count) {
    char message[768];
    int n = snprintf(message, sizeof(message),
        "{\"schema\":1,\"kind\":\"kernel-policy\",\"ready\":true,"
        "\"program_ids\":[%u,%u,%u,%u],\"cgroup_device\":%llu,\"cgroup_inode\":%llu,"
        "\"allowed_ports\":[", ids[0], ids[1], ids[2], ids[3],
        (unsigned long long)st->st_dev, (unsigned long long)st->st_ino);
    if (n < 0 || (size_t)n >= sizeof(message)) return -1;
    size_t at = (size_t)n;
    for (size_t j = 0; j < count; ++j) {
        n = snprintf(message + at, sizeof(message) - at, "%s%u", j ? "," : "", ports[j]);
        if (n < 0 || (size_t)n >= sizeof(message) - at) return -1;
        at += (size_t)n;
    }
    if (sizeof(message) - at < 4) return -1;
    memcpy(message + at, "]}\n", 4);
    return emit(message);
}
static int wait_stop(double deadline, int cgroup, const uint32_t ids[HOOKS]) {
    char command[6];
    size_t used = 0;
    while (!interrupted) {
        double now = monotonic_now();
        if (now < 0) return -1;
        if (now >= deadline) return 0;
        /* Recheck retained ownership during the wait; changes are never hidden. */
        for (int j = 0; j < HOOKS; ++j)
            if (query_exact(cgroup, hooks[j], ids[j], 0) ||
                query_exact(cgroup, hooks[j], ids[j], 1)) return -1;
        int ms = (int)((deadline - now) * 1000.0);
        if (ms > 250) ms = 250;
        if (ms < 1) ms = 1;
        struct pollfd p = { .fd = STDIN_FILENO, .events = POLLIN };
        int rc = poll(&p, 1, ms);
        if (rc < 0) { if (errno == EINTR) continue; return -1; }
        if (!rc) continue;
        if (p.revents & (POLLERR | POLLNVAL)) return -1;
        ssize_t n = read(STDIN_FILENO, command + used, sizeof(command) - used);
        if (n < 0) { if (errno == EINTR || errno == EAGAIN) continue; return -1; }
        if (!n) return used == 0 ? 0 : -1;
        used += (size_t)n;
        if (used == 5 && memcmp(command, "STOP\n", 5) == 0) return 0;
        if (used >= 5 || memcmp(command, "STOP\n", used) != 0) return -1;
    }
    return 0;
}
/* A deliberately tiny interpreter for builder-only --self-test (not BPF evidence). */
static int interpret(const struct bpf_insn *p, size_t n, uint32_t ip, uint32_t port) {
    uint32_t r0 = 0;
    for (size_t pc = 0, steps = 0; pc < n && steps++ < MAX_INSNS; ++pc) {
        const struct bpf_insn *i = &p[pc];
        if (i->code == (BPF_LDX | BPF_MEM | BPF_W)) {
            if (i->off == (short)offsetof(struct bpf_sock_addr, user_ip4)) r0 = ip;
            else if (i->off == (short)offsetof(struct bpf_sock_addr, user_port)) r0 = port;
            else return -1;
        } else if (i->code == (BPF_JMP | BPF_JNE | BPF_K)) {
            if (r0 != (uint32_t)i->imm) pc += (size_t)i->off;
        } else if (i->code == (BPF_JMP | BPF_JEQ | BPF_K)) {
            if (r0 == (uint32_t)i->imm) pc += (size_t)i->off;
        } else if (i->code == (BPF_ALU64 | BPF_MOV | BPF_K)) r0 = (uint32_t)i->imm;
        else if (i->code == (BPF_JMP | BPF_EXIT)) return (int)r0;
        else return -1;
    }
    return -1;
}
static int self_test(void) {
    uint16_t ports[MAX_PORTS];
    size_t count;
    double deadline;
    const char *bad[] = {",", "1024,", ",1024", "1024,,1025", "5432", "54322",
                         "0", "1023", "65536", "-1", " 1024", "1024,1024", "1e4"};
    for (size_t j = 0; j < sizeof(bad) / sizeof(bad[0]); ++j)
        if (parse_ports(bad[j], ports, &count) == 0) return fail("self_test");
    const char *bad_deadlines[] = { "", "nan", "inf", "100", "99.9", "3700.000000001",
        "3701", "1e3", "+1000", "-1000", " 1000", "1000 ", ".5", "1000.",
        "1000.0000000001", "999999999999999999999999999999" };
    for (size_t j = 0; j < sizeof(bad_deadlines) / sizeof(bad_deadlines[0]); ++j)
        if (parse_deadline(bad_deadlines[j], 100, &deadline) == 0) return fail("self_test");
    if (parse_deadline("3600.25", 100, &deadline) || deadline != 3600.25 ||
        parse_deadline("3700", 100, &deadline) || deadline != 3700)
        return fail("self_test");
    if (parse_ports("65535,1024,15432", ports, &count) || count != 3 ||
        ports[0] != 1024 || ports[1] != 15432 || ports[2] != 65535) return fail("self_test");
    if (parse_ports("1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,65535",
                    ports, &count) || count != MAX_PORTS ||
        parse_ports("1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040",
                    ports, &count) == 0) return fail("self_test");
    /* The overflow parser may have written a prefix; restore the accepted set. */
    for (size_t j = 0; j < MAX_PORTS; ++j) ports[j] = (uint16_t)(1024 + j);
    ports[MAX_PORTS - 1] = 65535;
    count = MAX_PORTS;
    for (int ipv4 = 0; ipv4 <= 1; ++ipv4) {
        for (size_t c = 0; c <= count; ++c) {
            struct bpf_insn program[MAX_INSNS];
            size_t n = build_program(program, ipv4, ports, c);
            for (size_t j = 0; j < n; ++j)
                if ((program[j].code == (BPF_JMP | BPF_JEQ | BPF_K) ||
                     program[j].code == (BPF_JMP | BPF_JNE | BPF_K)) &&
                    (program[j].off < 0 || j + 1 + (size_t)program[j].off >= n))
                    return fail("self_test");
            for (unsigned port = 0; port <= 65535; ++port) {
                int allowed = 0;
                for (size_t j = 0; j < c; ++j) if (port == ports[j]) allowed = ipv4;
                if (interpret(program, n, htonl(INADDR_LOOPBACK), htons((uint16_t)port)) != allowed ||
                    interpret(program, n, htonl(0x7f000002), htons((uint16_t)port)) != 0 ||
                    interpret(program, n, htonl(0x08080808), htons((uint16_t)port)) != 0)
                    return fail("self_test");
            }
        }
    }
    return emit("{\"schema\":1,\"kind\":\"kernel-policy-self-test\",\"ok\":true}\n") ? 1 : 0;
}
int main(int argc, char **argv) {
    /* Avoid a blocked output pipe defeating the original deadline. */
    int flags = fcntl(STDOUT_FILENO, F_GETFL);
    if (flags < 0 || fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) < 0) return 1;
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return self_test();
    if (argc != 7 || strcmp(argv[1], "--cgroup-fd") || strcmp(argv[3], "--ports") ||
        strcmp(argv[5], "--deadline")) return fail("arguments");
    unsigned long number;
    uint16_t ports[MAX_PORTS];
    size_t count;
    double deadline;
    if (decimal(argv[2], INT_MAX, &number) || number < 3 ||
        parse_ports(argv[4], ports, &count) ||
        parse_deadline(argv[6], monotonic_now(), &deadline)) return fail("arguments");
    if (geteuid() != 0) return fail("authority");
    int cgroup = (int)number;
    struct stat st;
    struct statfs fs;
    flags = fcntl(cgroup, F_GETFL);
    if (flags < 0 || !(flags & O_DIRECTORY) || !(flags & O_NOFOLLOW) ||
        fstat(cgroup, &st) || !S_ISDIR(st.st_mode) || fstatfs(cgroup, &fs) ||
        (unsigned long)fs.f_type != (unsigned long)CGROUP2_SUPER_MAGIC)
        return fail("cgroup_identity");
    flags = fcntl(STDIN_FILENO, F_GETFL);
    if (flags < 0 || fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) < 0)
        return fail("control_channel");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) || sigaction(SIGINT, &sa, NULL) ||
        sigaction(SIGHUP, &sa, NULL)) return fail("signals");
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL)) return fail("signals");
    int fds[HOOKS] = {-1, -1, -1, -1};
    int attached[HOOKS] = {0};
    uint32_t ids[HOOKS] = {0};
    int ok = 1;
    for (int j = 0; j < HOOKS; ++j) {
        double now = monotonic_now();
        if (interrupted || now < 0 || now >= deadline ||
            query_exact(cgroup, hooks[j], 0, 0) || query_exact(cgroup, hooks[j], 0, 1)) {
            ok = 0; break;
        }
        fds[j] = load_program(hooks[j], j < 2, ports, count, &ids[j]);
        if (fds[j] < 0) { ok = 0; break; }
        if (attachment(BPF_PROG_ATTACH, cgroup, hooks[j], fds[j]) < 0) { ok = 0; break; }
        attached[j] = 1;
        if (query_exact(cgroup, hooks[j], ids[j], 0) || query_exact(cgroup, hooks[j], ids[j], 1)) {
            ok = 0; break;
        }
    }
    /* Read back ALL hooks together before publishing READY. */
    for (int j = 0; ok && j < HOOKS; ++j) {
        if (query_exact(cgroup, hooks[j], ids[j], 0) || query_exact(cgroup, hooks[j], ids[j], 1)) ok = 0;
        for (int k = 0; k < j; ++k) if (ids[k] == ids[j]) ok = 0;
    }
    int was_ready = 0;
    double now = monotonic_now();
    if (ok && !interrupted && now >= 0 && now < deadline) {
        if (ready(ids, &st, ports, count)) ok = 0;
        else { was_ready = 1; if (wait_stop(deadline, cgroup, ids)) ok = 0; }
    } else ok = 0;
    int detached = 1;
    for (int j = HOOKS - 1; j >= 0; --j) {
        if (attached[j]) {
            /* Never detach by hook alone or use a caller-supplied program ID. */
            if (attachment(BPF_PROG_DETACH, cgroup, hooks[j], fds[j]) < 0 ||
                query_exact(cgroup, hooks[j], 0, 0) || query_exact(cgroup, hooks[j], 0, 1))
                detached = 0;
        }
        if (fds[j] >= 0 && close(fds[j])) detached = 0;
    }
    if (close(cgroup)) detached = 0;
    if (!ok || !detached || !was_ready) return fail(detached ? "policy_failed" : "cleanup_uncertain");
    return emit("{\"schema\":1,\"kind\":\"kernel-policy\",\"stopped\":true,\"detached\":true}\n") ? 1 : 0;
}
