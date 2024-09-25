// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __ALLOCSNOOP_H
#define __ALLOCSNOOP_H

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
