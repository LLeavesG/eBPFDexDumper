#ifndef __BPF_HEADER__
#define __BPF_HEADER__


#include <vmlinux.h>
#include <bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_ARGS_NUM 16
#define MAX_PERCPU_BUFSIZE  (1 << 14)     // This value is actually set by the kernel as an upper bound

struct config_t{
	uid_t uid;
	pid_t pid;
};

struct dex_event_data_t {
    u64 begin;
    u32 pid;
    u32 size;
};

struct method_event_data_t {
    u64 begin;
    u32 pid;
    u32 size;

    u64 thread;
    u64 art_method_ptr;

    u32 method_index;
    u32 codeitem_size;
};

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
    u32 offset;
} buf_t;



// Events submission for dex file dumps using ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Events submission for method execution traces using ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} method_events SEC(".maps");

// Config map
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct config_t);
} config_map SEC(".maps");

// dexFileCache map
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u32);
} dexFileCache_map SEC(".maps");

// methodCodeCache map to track which methods have had their bytecode read
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, u64);
    __type(value, u32);
} methodCodeCache_map SEC(".maps");


// Percpu global buffer variables

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, buf_t);
} bufs_m SEC(".maps");


#define INVALID_UID_PID ((uid_t)-1)

struct pt_regs;
#define PT_REGS_ARM64 const volatile struct user_pt_regs
#define PT_REGS_PARM1(x) (((PT_REGS_ARM64 *)(x))->regs[0])
#define PT_REGS_PARM2(x) (((PT_REGS_ARM64 *)(x))->regs[1])
#define PT_REGS_PARM3(x) (((PT_REGS_ARM64 *)(x))->regs[2])
#define PT_REGS_PARM4(x) (((PT_REGS_ARM64 *)(x))->regs[3])
#define PT_REGS_PARM5(x) (((PT_REGS_ARM64 *)(x))->regs[4])
#define PT_REGS_PARM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#define PT_REGS_PARM7(x) (((PT_REGS_ARM64 *)(x))->regs[6])
#define PT_REGS_PARMX(x, n) (((PT_REGS_ARM64 *)(x))->regs[n])

#define PT_REGS_RET(x) (((PT_REGS_ARM64 *)(x))->regs[30])
/* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_FP(x) (((PT_REGS_ARM64 *)(x))->regs[29])
#define PT_REGS_RC(x) (((PT_REGS_ARM64 *)(x))->regs[0])
#define PT_REGS_SP(x) (((PT_REGS_ARM64 *)(x))->sp)
#define PT_REGS_IP(x) (((PT_REGS_ARM64 *)(x))->pc)

#define PT_REGS_PARM1_CORE(x) BPF_CORE_READ((PT_REGS_ARM64 *)(x), regs[0])
#define PT_REGS_PARM2_CORE(x) BPF_CORE_READ((PT_REGS_ARM64 *)(x), regs[1])
#define PT_REGS_PARM3_CORE(x) BPF_CORE_READ((PT_REGS_ARM64 *)(x), regs[2])
#define PT_REGS_PARM4_CORE(x) BPF_CORE_READ((PT_REGS_ARM64 *)(x), regs[3])
#define PT_REGS_PARM5_CORE(x) BPF_CORE_READ((PT_REGS_ARM64 *)(x), regs[4])
#define PT_REGS_RET_CORE(x) BPF_CORE_READ((PT_REGS_ARM64 *)(x), regs[30])
#define PT_REGS_FP_CORE(x) BPF_CORE_READ((PT_REGS_ARM64 *)(x), regs[29])
#define PT_REGS_RC_CORE(x) BPF_CORE_READ((PT_REGS_ARM64 *)(x), regs[0])
#define PT_REGS_SP_CORE(x) BPF_CORE_READ((PT_REGS_ARM64 *)(x), sp)
#define PT_REGS_IP_CORE(x) BPF_CORE_READ((PT_REGS_ARM64 *)(x), pc)


#endif