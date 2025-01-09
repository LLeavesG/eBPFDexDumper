//go:build ignore
#include "header.h"

const struct config_ *unused_config_t __attribute__((unused));
const struct event_data_t *unused_event_data_t __attribute__((unused));

static int config_loaded = 0;
static bool filter_enable = false;
static uid_t targ_uid = INVALID_UID_PID;
static pid_t targ_pid = INVALID_UID_PID;

static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID_PID;
}

static __always_inline
bool trace_allowed(u32 pid, u32 uid)
{   
    if ( targ_uid == INVALID_UID_PID){
        // load config
        struct config_t *conf = bpf_map_lookup_elem(&config_map, &config_loaded);
        if (conf){
            targ_uid = conf->uid;
            targ_pid = conf->pid;
        }
    }

	if (valid_uid(targ_uid)) {
		if (targ_uid != uid) {
			return false;
		}
	}
    return true;
}

SEC("uprobe/libart_execute")
int uprobe_libart_execute(struct pt_regs *ctx)
{

    u32 pid = bpf_get_current_pid_tgid();
    if (!trace_allowed(0, bpf_get_current_uid_gid())){
        return 0;
    }

    struct event_data_t evt = {};
    __builtin_memset(&evt, 0, sizeof(evt)); 
    unsigned char *shadow_frame_ptr = (unsigned char *)PT_REGS_PARM3(ctx);

    unsigned char *art_method_ptr = 0;
    bpf_probe_read_user(&art_method_ptr, sizeof(u64), shadow_frame_ptr + 8);
    // bpf_printk("art_method_ptr: %llx", art_method_ptr);

    unsigned char *declaring_class_ptr = 0;
    bpf_probe_read_user(&declaring_class_ptr, sizeof(u32), art_method_ptr);
    // bpf_printk("declaring_class_ptr: %llx", declaring_class_ptr);

    unsigned char *dex_cache_ptr = 0;
    bpf_probe_read_user(&dex_cache_ptr, sizeof(u64), declaring_class_ptr + 0x10);
    // bpf_printk("dex_cache_ptr: %llx", dex_cache_ptr);

    unsigned char *dex_file_ptr = 0;
    bpf_probe_read_user(&dex_file_ptr, sizeof(u64), dex_cache_ptr + 0x10);
    // bpf_printk("dex_file_ptr: %llx", dex_file_ptr);
    
    u64 begin = 0;
    u32 size = 0;
    u8 ch = 0;
    bpf_probe_read_user(&begin, sizeof(u64), dex_file_ptr + 0x8);
    bpf_probe_read_user(&size, sizeof(u32), dex_file_ptr + 0x10);

    if(begin != 0 && size != 0) {
        // bpf_printk("begin: %llx size: %x", begin, size);
        if (size < 0){
            return 0;
        }

        u32 exist = 1;
        u32 *value = bpf_map_lookup_elem(&dexFileCache_map, &begin);

        if (value != 0 && *value == 1){
            // bpf_printk("exist begin %x, size: %x exist %d", begin, size, *value);
            return 0;
        }
        
        evt.begin = begin;
        evt.pid = pid;
        evt.size = size;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_map_update_elem(&dexFileCache_map, &begin, &exist, BPF_ANY);
    }

    return 0;
}

SEC("uprobe/libart_executeNterpImpl")
int uprobe_libart_executeNterpImpl(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (!trace_allowed(0, bpf_get_current_uid_gid())){
        return 0;
    }

    struct event_data_t evt = {};
    __builtin_memset(&evt, 0, sizeof(evt)); 
    unsigned char *art_method_ptr = (unsigned char *)PT_REGS_PARM1(ctx);

    unsigned char *declaring_class_ptr = 0;
    bpf_probe_read_user(&declaring_class_ptr, sizeof(u32), art_method_ptr);
    
    unsigned char *dex_cache_ptr = 0;
    bpf_probe_read_user(&dex_cache_ptr, sizeof(u64), declaring_class_ptr + 0x10);

    unsigned char *dex_file_ptr = 0;
    bpf_probe_read_user(&dex_file_ptr, sizeof(u64), dex_cache_ptr + 0x10);
    
    u64 begin = 0;
    u32 size = 0;
    u8 ch = 0;
    bpf_probe_read_user(&begin, sizeof(u64), dex_file_ptr + 0x8);
    bpf_probe_read_user(&size, sizeof(u32), dex_file_ptr + 0x10);

    if(begin != 0 && size != 0) {
        // bpf_printk("begin: %llx size: %x", begin, size);
        if (size < 0){
            return 0;
        }

        u32 exist = 1;
        u32 *value = bpf_map_lookup_elem(&dexFileCache_map, &begin);

        if (value != 0 && *value == 1){
            // bpf_printk("exist begin %x, size: %x exist %d", begin, size, *value);
            return 0;
        }
        
        evt.begin = begin;
        evt.pid = pid;
        evt.size = size;

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_map_update_elem(&dexFileCache_map, &begin, &exist, BPF_ANY);
    }
    return 0;
}

// VerifyClass
SEC("uprobe/libart_verifyClass")
int uprobe_libart_verifyClass(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (!trace_allowed(0, bpf_get_current_uid_gid())){
        return 0;
    }

    struct event_data_t evt = {};
    __builtin_memset(&evt, 0, sizeof(evt)); 
    unsigned char *dex_file_ptr = (unsigned char *)PT_REGS_PARM3(ctx);
    
    u64 begin = 0;
    u32 size = 0;
    u8 ch = 0;
    bpf_probe_read_user(&begin, sizeof(u64), dex_file_ptr + 0x8);
    bpf_probe_read_user(&size, sizeof(u32), dex_file_ptr + 0x10);

    if(begin != 0 && size != 0) {
        // bpf_printk("begin: %llx size: %x", begin, size);
        if (size < 0){
            return 0;
        }

        u32 exist = 1;
        u32 *value = bpf_map_lookup_elem(&dexFileCache_map, &begin);

        if (value != 0 && *value == 1){
            // bpf_printk("exist begin %x, size: %x exist %d", begin, size, *value);
            return 0;
        }
        
        evt.begin = begin;
        evt.pid = pid;
        evt.size = size;

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_map_update_elem(&dexFileCache_map, &begin, &exist, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";