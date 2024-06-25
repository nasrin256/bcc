// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240
#define MAX_CPU_NR	128
#define RAW_ALLOCS_MAX_ENTRIES 100

struct raw_alloc_info {
	__u64 timestamp_ns;
	__u64 addr;
	__u64 size;
	__u32 stack_id;
	__u64 pid;
};

struct raw_dealloc_info {
	__u64 timestamp_ns;
	__u64 addr;
	__u64 pid;
};

struct alloc_info {
	__u64 size;
	__u64 timestamp_ns;
	int stack_id;
};

union combined_alloc_info {
	struct {
		__u64 total_size : 40;
		__u64 number_of_allocs : 24;
	};
	__u64 bits;
};

#endif /* __MEMLEAK_H */
