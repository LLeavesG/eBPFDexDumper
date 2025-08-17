//go:build ignore
#include "header.h"

const struct config_t *unused_config_t __attribute__((unused));
const struct dex_event_data_t *unused_dex_event_data_t __attribute__((unused));
const struct method_event_data_t *unused_method_event_data_t __attribute__((unused));

static int config_loaded = 0;
static bool filter_enable = false;
static uid_t targ_uid = INVALID_UID_PID;
static pid_t targ_pid = INVALID_UID_PID;

static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID_PID;
}

static __always_inline bool filter_art(u64 artmethod) {
    // check if high 32 bits are zero
    return (artmethod & 0xFFFFFFFF00000000) == 0;
}

static __always_inline
bool trace_allowed(u32 pid, u32 uid)
{   
    if ( targ_uid == INVALID_UID_PID){
        // load config
        struct config_t *conf = (struct config_t *)bpf_map_lookup_elem(&config_map, &config_loaded);
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

    struct dex_event_data_t evt = {};
    __builtin_memset(&evt, 0, sizeof(evt)); 
    unsigned char *shadow_frame_ptr = (unsigned char *)PT_REGS_PARM3(ctx);

    u64 art_method_ptr = 0;
    bpf_probe_read_user(&art_method_ptr, sizeof(u64), shadow_frame_ptr + 8);
    // bpf_printk("art_method_ptr: %llx", art_method_ptr);
    if (filter_art(art_method_ptr)) return 0;

    u32 dex_method_index = 0;
    bpf_probe_read_user(&dex_method_index, sizeof(u32), (void *)(art_method_ptr + 0x08));

    unsigned char *declaring_class_ptr = 0;
    bpf_probe_read_user(&declaring_class_ptr, sizeof(u32), (void *)art_method_ptr);
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
        u32 *value = (u32 *)bpf_map_lookup_elem(&dexFileCache_map, &begin);

        if (value != 0 && *value == 1){
            // bpf_printk("exist begin %x, size: %x exist %d", begin, size, *value);
            return 0;
        }
        
        struct dex_event_data_t *evt_ptr = (struct dex_event_data_t *)bpf_ringbuf_reserve(&events, sizeof(struct dex_event_data_t), 0);
        if (evt_ptr) {
            evt_ptr->begin = begin;
            evt_ptr->pid = pid;
            evt_ptr->size = size;
            bpf_ringbuf_submit(evt_ptr, 0);
        }
        bpf_map_update_elem(&dexFileCache_map, &begin, &exist, BPF_ANY);

        struct method_event_data_t *method_evt = (struct method_event_data_t *)bpf_ringbuf_reserve(&method_events, sizeof(struct method_event_data_t), 0);
        if (method_evt) {
            method_evt->begin = begin;
            method_evt->pid = pid;
            method_evt->size = size;
            method_evt->art_method_ptr = art_method_ptr;
            method_evt->method_index = dex_method_index;
            bpf_ringbuf_submit(method_evt, 0);
        }
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

    u64 art_method_ptr = (u64)PT_REGS_PARM1(ctx);
    bpf_printk("ArtMethod ptr: %llx", art_method_ptr);
    if (filter_art(art_method_ptr)) return 0;

    // 读取ArtMethod中的dex_method_index (偏移量0x08)
    u32 dex_method_index = 0;
    bpf_probe_read_user(&dex_method_index, sizeof(u32), (void *)(art_method_ptr + 0x08));

    unsigned char *declaring_class_ptr = 0;
    bpf_probe_read_user(&declaring_class_ptr, sizeof(u32), (void *)art_method_ptr);
    
    unsigned char *dex_cache_ptr = 0;
    bpf_probe_read_user(&dex_cache_ptr, sizeof(u64), declaring_class_ptr + 0x10);

    unsigned char *dex_file_ptr = 0;
    bpf_probe_read_user(&dex_file_ptr, sizeof(u64), dex_cache_ptr + 0x10);
    
    u64 begin = 0;
    u32 size = 0;
    bpf_probe_read_user(&begin, sizeof(u64), dex_file_ptr + 0x8);
    bpf_probe_read_user(&size, sizeof(u32), dex_file_ptr + 0x10);

    if(begin != 0 && size != 0) {
        if (size < 0){
            return 0;
        }

        // 首先检查并处理Dex文件缓存
        u32 exist = 1;
        u32 *value = (u32 *)bpf_map_lookup_elem(&dexFileCache_map, &begin);

        if (value == 0 || *value != 1){
            // Dex文件未缓存，发送Dex文件事件
            struct dex_event_data_t *dex_evt = (struct dex_event_data_t *)bpf_ringbuf_reserve(&events, sizeof(struct dex_event_data_t), 0);
            if (dex_evt) {
                dex_evt->begin = begin;
                dex_evt->pid = pid;
                dex_evt->size = size;
                bpf_ringbuf_submit(dex_evt, 0);
            }
            bpf_map_update_elem(&dexFileCache_map, &begin, &exist, BPF_ANY);
        }

        // 发送方法执行事件使用ringbuf
        struct method_event_data_t *method_evt = (struct method_event_data_t *)bpf_ringbuf_reserve(&method_events, sizeof(struct method_event_data_t), 0);
        if (method_evt) {
            method_evt->begin = begin;
            method_evt->pid = pid;
            method_evt->size = size;
            method_evt->art_method_ptr = art_method_ptr;
            method_evt->method_index = dex_method_index;
            bpf_ringbuf_submit(method_evt, 0);
        }
    }
    return 0;
}

// NterpOpInvoke
SEC("uprobe/libart_nterpOpInvoke")
int uprobe_libart_nterpOpInvoke(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (!trace_allowed(0, bpf_get_current_uid_gid())){
        return 0;
    }

    u64 art_method_ptr = (u64)PT_REGS_PARM1(ctx);
    if (filter_art(art_method_ptr)) return 0;

    u32 dex_method_index = 0;
    bpf_probe_read_user(&dex_method_index, sizeof(u32), (void *)(art_method_ptr + 0x08));

    unsigned char *declaring_class_ptr = 0;
    bpf_probe_read_user(&declaring_class_ptr, sizeof(u32), (void *)art_method_ptr);
    
    unsigned char *dex_cache_ptr = 0;
    bpf_probe_read_user(&dex_cache_ptr, sizeof(u64), declaring_class_ptr + 0x10);

    unsigned char *dex_file_ptr = 0;
    bpf_probe_read_user(&dex_file_ptr, sizeof(u64), dex_cache_ptr + 0x10);
    
    u64 begin = 0;
    u32 size = 0;
    bpf_probe_read_user(&begin, sizeof(u64), dex_file_ptr + 0x8);
    bpf_probe_read_user(&size, sizeof(u32), dex_file_ptr + 0x10);

    if(begin != 0 && size != 0) {
        if (size < 0){
            return 0;
        }

        u32 exist = 1;
        u32 *value = (u32 *)bpf_map_lookup_elem(&dexFileCache_map, &begin);

        if (value == 0 || *value != 1){
            struct dex_event_data_t *dex_evt = (struct dex_event_data_t *)bpf_ringbuf_reserve(&events, sizeof(struct dex_event_data_t), 0);
            if (dex_evt) {
                dex_evt->begin = begin;
                dex_evt->pid = pid;
                dex_evt->size = size;
                bpf_ringbuf_submit(dex_evt, 0);
            }
            bpf_map_update_elem(&dexFileCache_map, &begin, &exist, BPF_ANY);
        }

        struct method_event_data_t *method_evt = (struct method_event_data_t *)bpf_ringbuf_reserve(&method_events, sizeof(struct method_event_data_t), 0);
        if (method_evt) {
            method_evt->begin = begin;
            method_evt->pid = pid;
            method_evt->size = size;
            method_evt->art_method_ptr = art_method_ptr;
            method_evt->method_index = dex_method_index;
            bpf_ringbuf_submit(method_evt, 0);
        }
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

    struct dex_event_data_t evt = {};
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
        u32 *value = (u32 *)bpf_map_lookup_elem(&dexFileCache_map, &begin);

        if (value != 0 && *value == 1){
            // bpf_printk("exist begin %x, size: %x exist %d", begin, size, *value);
            return 0;
        }

        struct dex_event_data_t *evt_ptr = (struct dex_event_data_t *)bpf_ringbuf_reserve(&events, sizeof(struct dex_event_data_t), 0);
        if (evt_ptr) {
            evt_ptr->begin = begin;
            evt_ptr->pid = pid;
            evt_ptr->size = size;
            bpf_ringbuf_submit(evt_ptr, 0);
        }
        bpf_map_update_elem(&dexFileCache_map, &begin, &exist, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";