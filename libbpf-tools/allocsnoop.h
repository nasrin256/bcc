// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __ALLOCSNOOP_H
#define __ALLOCSNOOP_H

#define RING_BUF_MAX_SIZE	(1 << 23) /* 8MB */
#define ERR_RING_BUF_MAX_SIZE	(16)

enum allocsnoop_err_types {
	E_RB_ALLOC,
	E_RB_DEALLOC,
	E_MAXTYPE,
};

struct allocsnoop_err_info {
	__u32 type;
	__u32 err;
};

struct alloc_info {
	__u64 timestamp_ns;
	__u64 addr;
	__u64 size;
	__u32 stack_id;
	__u64 pid;
};

struct dealloc_info {
	__u64 timestamp_ns;
	__u64 addr;
	__u64 pid;
};

#endif /* __ALLOCSNOOP_H */
