/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __UNWIND_HELPERS_H
#define __UNWIND_HELPERS_H

#include <bpf/bpf.h>
#include <libunwind-ptrace.h>
#include "unwind_types.h"

enum log_level {
	DEBUG,
	INFO,
	WARN,
	ERROR,
};

struct unw_info {
	unw_addr_space_t as;
	void *context;
	struct unw_data data;
};

int unw_init(struct unw_info *u, pid_t pid, size_t user_stack_size);
void unw_deinit(struct unw_info *u);
int post_unwind(struct unw_info *u, int sample_fd, int ustack_fd, int ustack_id,
		unsigned long *ip, size_t nr_ip);
void set_log_level(enum log_level level);
#endif /* __UNWIND_HELPERS_H */
