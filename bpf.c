//go:build ignore
#include "header.h"

const struct config_t *unused_config_t __attribute__((unused));
const struct dex_event_data_t *unused_dex_event_data_t __attribute__((unused));
const struct method_event_data_t *unused_method_event_data_t __attribute__((unused));
const buf_t *unused_buf_t __attribute__((unused));
const struct dex_chunk_event_t *unused_dex_chunk_event_t __attribute__((unused));

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
u32 read_method_bytecode(u64 art_method_ptr, u32 *codeitem_size) {
    *codeitem_size = 0;
    
    // Check if this method's bytecode has already been read
    u32 *cached = (u32 *)bpf_map_lookup_elem(&methodCodeCache_map, &art_method_ptr);
    if (cached && *cached == 1) {
        return 0; // Already read, don't read again
    }
    
    // Get the CodeItem pointer from ArtMethod
    u64 code_item_ptr = 0;
    if (bpf_probe_read_user(&code_item_ptr, sizeof(u64), (void *)(art_method_ptr + 0x10)) != 0) {
        return 0;
    }
    
    // clear the lowest bit
    code_item_ptr = code_item_ptr & -1;
    if (code_item_ptr == 0) {
        return 0; // No bytecode (native method or abstract)
    }
    
    // Read CodeItem header to get insns_size_in_code_units
    u32 insns_size = 0;
    if (bpf_probe_read_user(&insns_size, sizeof(u32), (void *)(code_item_ptr + 0x0c)) != 0) {
        return 0;
    }
    
    if (insns_size == 0 || insns_size > 0x10000) { // Sanity check
        return 0;
    }
    
    *codeitem_size = insns_size * 2; // Convert to bytes
    
    // Get per-CPU buffer
    u32 zero = 0;
    buf_t *buf = (buf_t *)bpf_map_lookup_elem(&bufs_m, &zero);
    if (!buf) {
        return 0;
    }
    
    // Read bytecode into buffer
    u32 bytes_to_read = *codeitem_size;
    if (bytes_to_read > MAX_PERCPU_BUFSIZE - sizeof(struct method_event_data_t)) {
        bytes_to_read = MAX_PERCPU_BUFSIZE - sizeof(struct method_event_data_t);
        *codeitem_size = bytes_to_read;
    }
    
    asm volatile("if %[size] < %[max] goto +1;\n"
    "%[size] = %[max];\n"
    :
    : [size] "r"(bytes_to_read), [max] "i"(MAX_PERCPU_BUFSIZE - sizeof(struct method_event_data_t)));

    if (bpf_probe_read_user(buf->buf + sizeof(struct method_event_data_t), bytes_to_read, 
                            (void *)(code_item_ptr + 0x10)) != 0) {
        *codeitem_size = 0;
        return 0;
    }
    
    // Mark this method as read
    u32 read_flag = 1;
    bpf_map_update_elem(&methodCodeCache_map, &art_method_ptr, &read_flag, BPF_ANY);
    
    return 1;
}

static __always_inline
void submit_method_event_with_bytecode(u64 begin, u32 pid, u32 size, u64 art_method_ptr, 
                                       u32 method_index, u32 codeitem_size) {
    if (codeitem_size > 0) {
        // Submit with bytecode using variable-length ringbuf
        u32 zero = 0;
        buf_t *buf = (buf_t *)bpf_map_lookup_elem(&bufs_m, &zero);
        if (!buf) {
            return;
        }
        
        struct method_event_data_t *method_evt = (struct method_event_data_t *)buf->buf;
        method_evt->begin = begin;
        method_evt->pid = pid;
        method_evt->size = size;
        method_evt->art_method_ptr = art_method_ptr;
        method_evt->method_index = method_index;
        method_evt->codeitem_size = codeitem_size;
        
        u32 total_size = sizeof(struct method_event_data_t) + codeitem_size;
        asm volatile("if %[size] < %[max] goto +1;\n"
        "%[size] = %[max];\n"
        :
        : [size] "r"(total_size), [max] "i"(MAX_PERCPU_BUFSIZE));
        bpf_ringbuf_output(&method_events, buf->buf, total_size, 0);
    } else {
        // Submit without bytecode using fixed-size structure
        struct method_event_data_t *method_evt = (struct method_event_data_t *)bpf_ringbuf_reserve(&method_events, sizeof(struct method_event_data_t), 0);
        if (method_evt) {
            method_evt->begin = begin;
            method_evt->pid = pid;
            method_evt->size = size;
            method_evt->art_method_ptr = art_method_ptr;
            method_evt->method_index = method_index;
            method_evt->codeitem_size = 0;
            bpf_ringbuf_submit(method_evt, 0);
        }
    }
}

// Max chunks per invocation to control runtime
#define MAX_CHUNKS_PER_CALL 64

static __always_inline void submit_dex_chunks_partial(u64 begin, u32 pid, u32 size) {
    if (size == 0) return;

    // load current progress
    u32 *pnext = (u32 *)bpf_map_lookup_elem(&dexProgress_map, &begin);
    u32 next_off = 0;
    if (pnext) {
        next_off = *pnext;
        if (next_off >= size) {
            return; // completed
        }
    }

    // compute max payload per record
    const u32 hdr_sz = sizeof(struct dex_chunk_event_t);
    const u32 max_payload = MAX_PERCPU_BUFSIZE - hdr_sz;

    #pragma unroll
    for (int i = 0; i < MAX_CHUNKS_PER_CALL; i++) {
        if (next_off >= size) {
            break;
        }

        u32 remain = size > next_off ? size - next_off : 0;
        if (remain == 0) {
            break;
        }
        u32 payload = remain;
        if (payload > max_payload) {
            payload = max_payload;
        }
        // ensure non-negative and 32-bit clean for helper
        payload &= 0x7fffffff;

        // Reserve fixed-size space in ringbuf (use constant size for verifier)
        struct dex_chunk_event_t *evt = (struct dex_chunk_event_t *)bpf_ringbuf_reserve(&dex_chunks, MAX_PERCPU_BUFSIZE, 0);
        if (!evt) {
            // Failed to reserve, stop processing
            break;
        }

        // Fill the event header
        evt->begin = begin;
        evt->pid = pid;
        evt->size = size;
        evt->offset = next_off;
        evt->data_len = payload;

        // read user memory into buffer after header
        u32 read_size = payload;
        asm volatile("if %[size] < %[max] goto +1;\n"
                     "%[size] = %[max];\n"
                     : [size] "+r"(read_size)
                     : [max] "i"(max_payload));
        if (bpf_probe_read_user((void *)((char *)evt + sizeof(*evt)), read_size, (void *)(begin + next_off)) != 0) {
            // On failure, discard the reserved space and stop
            bpf_ringbuf_discard(evt, 0);
            break;
        }

        // Submit the filled event
        bpf_ringbuf_submit(evt, 0);

        next_off += payload;
    }

    // store progress
    bpf_map_update_elem(&dexProgress_map, &begin, &next_off, BPF_ANY);
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

        u32 codeitem_size = 0;
        read_method_bytecode(art_method_ptr, &codeitem_size);
        submit_method_event_with_bytecode(begin, pid, size, art_method_ptr, dex_method_index, codeitem_size);

        // submit dex chunks progressively via ringbuf
        submit_dex_chunks_partial(begin, pid, size);
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
        u32 codeitem_size = 0;
        read_method_bytecode(art_method_ptr, &codeitem_size);
        submit_method_event_with_bytecode(begin, pid, size, art_method_ptr, dex_method_index, codeitem_size);

        // submit dex chunks progressively via ringbuf
        submit_dex_chunks_partial(begin, pid, size);
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

        u32 codeitem_size = 0;
        read_method_bytecode(art_method_ptr, &codeitem_size);
        submit_method_event_with_bytecode(begin, pid, size, art_method_ptr, dex_method_index, codeitem_size);

        // submit dex chunks progressively via ringbuf
        submit_dex_chunks_partial(begin, pid, size);
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

        // submit dex chunks progressively via ringbuf
        submit_dex_chunks_partial(begin, pid, size);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
