/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright 2023 LG Electronics Inc. */
#ifndef __UNWIND_HELPERS_H
#define __UNWIND_HELPERS_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <libunwind-ptrace.h>
#include "unwind_types.h"

/*
 * UNWIND_INIT(obj, user_stack_size, unwind_max_entries)
 *
 * @obj: bpf_object
 * @user_stack_size: max size to store each user stack
 * @unwind_max_entries: max entries to store user stacks
 */
#define UNWIND_INIT(obj, user_stack_size, unwind_max_entries) 		\
({									\
	obj->rodata->post_unwind = true; 				\
	obj->rodata->sample_ustack_size = user_stack_size; 		\
	obj->rodata->sample_max_entries = unwind_max_entries;	 	\
	unwind_map__set(obj->obj, user_stack_size, unwind_max_entries);	\
})

int unwind_map__set(struct bpf_object *obj, size_t sample_ustack_size, size_t max_entries);

/*
 * unwind_map_lookup_elem
 *
 * allows to lookup BPF map value corresponding to provided key.
 *
 * @brief **bpf_map__lookup_elem()** allows to lookup BPF map value
 * corresponding to provided key.
 * @ustack_id: user stack id to lookup and unwind
 * @pid: process id of @key
 * @value: pointer to memory in which unwounded value will be stored
 * @count: number of value data memory
 *
 * This function returns id of dumped user stack and registers for current context
 * 	Perform a lookup in *map* for an entry associated to *key*.
 */
int unwind_map_lookup_elem(const int *ustack_id, pid_t pid,
			   unsigned long *value, size_t count);

#endif /* __UNWIND_HELPERS_H */
