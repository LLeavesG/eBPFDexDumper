typedef int __kernel_pid_t;

typedef unsigned int __kernel_uid32_t;

typedef __u64 binder_uintptr_t;

typedef __u64 binder_size_t;

struct binder_transaction_data {
	union {
		__u32 handle;
		binder_uintptr_t ptr;
	} target;
	binder_uintptr_t cookie;
	__u32 code;
	__u32 flags;
	__kernel_pid_t sender_pid;
	__kernel_uid32_t sender_euid;
	binder_size_t data_size;
	binder_size_t offsets_size;
	union {
		struct {
			binder_uintptr_t buffer;
			binder_uintptr_t offsets;
		} ptr;
		__u8 buf[8];
	} data;
};
