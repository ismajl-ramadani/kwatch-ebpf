//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// ARM64/x86 are little-endian; network byte order is big-endian.
// __builtin_bswap* are compiler builtins — no extra header needed.
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

#define AF_INET 2

// CO-RE stubs — lets the BPF verifier resolve task_struct field offsets
// at load time via BTF, so this works across kernel versions.
struct task_struct {
    int tgid;
    struct task_struct *real_parent;
} __attribute__((preserve_access_index));

static __always_inline __u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, real_parent, tgid);
}

// Minimal inline sockaddr_in — avoids pulling in <linux/in.h>.
struct sockaddr4 {
    __u16 sa_family;
    __u16 sin_port;  // network byte order (big-endian)
    __u32 sin_addr;  // network byte order
    __u8  _pad[8];
};

char __license[] SEC("license") = "Dual MIT/GPL";

// accept/accept4 entry — we only need the sockaddr pointer
struct accept_enter_ctx {
    __u64            common;
    __s32            __syscall_nr;
    __u32            _pad;
    __u64            fd;
    struct sockaddr4 *upeer_sockaddr; // empty buffer; kernel fills it on exit
    __u32            *upeer_addrlen;
};

// accept/accept4 exit — ret is the new fd (or negative errno)
struct accept_exit_ctx {
    __u64 common;
    __s32 __syscall_nr;
    __u32 _pad;
    __s64 ret;
};

// connect(fd, *sockaddr, addrlen) tracepoint layout
struct connect_ctx {
    __u64            common;
    __s32            __syscall_nr;
    __u32            _pad;
    __u64            fd;
    struct sockaddr4 *uservaddr;
    __u64            addrlen;
};

struct openat_ctx {
    __u64        common;
    __s32        __syscall_nr;
    __u32        _pad;
    __u64        dfd;
    const char  *filename;
    __u64        flags;
    __u64        mode;
};

struct execve_ctx {
    __u64        common; 
    __u32        __syscall_nr;
    __u32        _pad;
    const char  *filename;
    const char *const *argv;
    const char *const *envp;
};

struct event {
    __u32 pid;
    __u32 ppid;          // parent PID — grabbed in-kernel, no /proc race
    __u32 uid;
    __u32 gid;
    __u32 type;          // 0 = exec, 1 = exit
    __u32 _pad;          // alignment for duration_ns
    __u64 duration_ns;   // lifetime (exit events only)
    __u64 cgroup_id;     // maps to container/pod when running under cgroups v2
    __u8  comm[16];
    __u8  filename[256];
    __u8  args[512]; // argv[1..8], fixed 64-byte slots, null-terminated (exec only)
    __u32 dst_ip;    // IPv4, host byte order (connect events only)
    __u16 dst_port;  // host byte order
    __u16 af;        // address family (AF_INET=2)
};

// Tracks execve start time per PID so exit can compute lifetime.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);  // pid
    __type(value, __u64);  // ktime_ns at execve
} start_times SEC(".maps");

// Saves the sockaddr pointer from accept/accept4 entry so the exit
// handler can read the client address after the kernel fills it in.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);  // pid
    __type(value, __u64);  // userspace address of sockaddr buffer
} pending_accept SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16mb buffer
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct execve_ctx *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; // failed to reserve space, drop the event
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->ppid = get_ppid();

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = (uid_gid >> 32) & 0xFFFFFFFF;

    e->type = 0; // exec
    e->duration_ns = 0;
    e->cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), ctx->filename);

    // Walk argv[1..8], skipping argv[0] (duplicates filename).
    // Fixed 64-byte slots let the BPF verifier prove array bounds statically.
    // __builtin_memset zeroes unused slots so Go can stop at the first empty one.
    __builtin_memset(e->args, 0, sizeof(e->args));
    #pragma unroll
    for (int i = 1; i <= 8; i++) {
        const char *argp = NULL;
        if (bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]) < 0 || !argp)
            break;
        bpf_probe_read_user_str(&e->args[(i - 1) * 64], 64, argp);
    }

    // record birth time so the exit handler can compute lifetime
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_times, &e->pid, &ts, BPF_ANY);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct connect_ctx *ctx) {
    // Read the sockaddr struct from userspace memory.
    // bpf_probe_read_user is safe even if the pointer is bad — returns an error code.
    struct sockaddr4 sa = {};
    if (bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr) < 0)
        return 0;

    // Skip everything that isn't a plain IPv4 connection.
    if (sa.sa_family != AF_INET)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->ppid = get_ppid();

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = (uid_gid >> 32) & 0xFFFFFFFF;

    e->type = 2; // connect
    e->duration_ns = 0;
    e->cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->filename[0] = '\0';

    // Convert from network byte order (big-endian) to host byte order
    // so Go can read the values directly as uint32/uint16.
    e->dst_ip   = bpf_ntohl(sa.sin_addr);
    e->dst_port = bpf_ntohs(sa.sin_port);
    e->af       = sa.sa_family;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Shared enter logic — just stash the sockaddr pointer.
static __always_inline void save_accept_addr(struct sockaddr4 *upeer) {
    if (!upeer) return; // caller passed NULL — doesn't want peer addr
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 addr = (__u64)(long)upeer;
    bpf_map_update_elem(&pending_accept, &pid, &addr, BPF_ANY);
}

// Shared exit logic — read the now-filled sockaddr and emit the event.
static __always_inline int emit_accept(__s64 ret) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u64 *addrp = bpf_map_lookup_elem(&pending_accept, &pid);
    bpf_map_delete_elem(&pending_accept, &pid); // always clean up

    if (!addrp || ret < 0)  // accept failed, or entry was never recorded
        return 0;

    struct sockaddr4 sa = {};
    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)(long)*addrp) < 0)
        return 0;

    if (sa.sa_family != AF_INET)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = get_ppid();

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = (uid_gid >> 32) & 0xFFFFFFFF;

    e->type = 3; // accept
    e->duration_ns = 0;
    e->cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->filename[0] = '\0';

    e->dst_ip   = bpf_ntohl(sa.sin_addr);
    e->dst_port = bpf_ntohs(sa.sin_port);
    e->af       = sa.sa_family;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept_enter(struct accept_enter_ctx *ctx) {
    save_accept_addr(ctx->upeer_sockaddr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_accept_exit(struct accept_exit_ctx *ctx) {
    return emit_accept(ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4_enter(struct accept_enter_ctx *ctx) {
    save_accept_addr(ctx->upeer_sockaddr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_accept4_exit(struct accept_exit_ctx *ctx) {
    return emit_accept(ctx->ret);
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Only emit if we saw the execve — processes we didn't trace get ignored.
    __u64 *start_ns = bpf_map_lookup_elem(&start_times, &pid);
    if (!start_ns)
        return 0;

    __u64 duration_ns = bpf_ktime_get_ns() - *start_ns;
    bpf_map_delete_elem(&start_times, &pid);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->ppid = get_ppid();

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = (uid_gid >> 32) & 0xFFFFFFFF;

    e->type = 1; // exit
    e->duration_ns = duration_ns;
    e->cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct openat_ctx *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = get_ppid();

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = (uid_gid >> 32) & 0xFFFFFFFF;

    e->type = 4; // open
    e->duration_ns = 0;
    e->cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), ctx->filename);

    e->args[0] = '\0';
    e->dst_ip = 0; e->dst_port = 0; e->af = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}