/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __UNWIND_BPF_H
#define __UNWIND_BPF_H

#include "unwind_types.h"
#include "maps.bpf.h"

/*
 * Post mortem Dwarf CFI based unwinding on top of regs and stack dumps.
 *
 * Lots of this code have been borrowed or heavily inspired from parts of
 * the libunwind and perf codes.
 */

/*
 * This macro can be defined to change the default before including this helper.
 * This value is used to set the resource size.$
 *
 * #define SAMPLE_USTACK_SIZE	128  Stack storage size to store per user stack
 * #define SAMPLE_MAX_ENTRIES	1024 Maximum number of entries of user stack and regs
 */
#if !defined(SAMPLE_USTACK_SIZE)
#define SAMPLE_USTACK_SIZE		128
#endif

#if !defined(SAMPLE_MAX_ENTRIES)
#define SAMPLE_MAX_ENTRIES		1024
#endif

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#ifdef bpf_dbg_printk
#error bpf_dbg_printk cannot be redefinded.
#endif

#define DEBUG
#ifdef DEBUG
#define bpf_dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define bpf_dbg_printk(fmt, ...) ;
#endif

#define PT_REGS_r10_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), r10)

/*
 * map to store user regs and stack
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__type(value, struct sample_data);
	__uint(max_entries, SAMPLE_MAX_ENTRIES);
} samples SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__uint(value_size, SAMPLE_USTACK_SIZE);
	__uint(max_entries, SAMPLE_MAX_ENTRIES);
} ustacks SEC(".maps");

/*
 * get_user_stackid - get user stack and user regs id for @ctx
 * @ctx: context to get user stack and user regs
 * @stack_storage_size: maximun buffer size to save user stack
 *
 * This function returns id of dumped user stack and registers for the context
 */
static int get_user_stackid(struct pt_regs *ctx, const volatile unsigned long stack_storage_size)
{
	u64 sp;
	u64 pc;
	int ret;
	u32 stack_len;
	struct sample_data *sample;
	struct task_struct *task;
	struct mm_struct *mm;
	static const struct sample_data szero;
	static const char zero[MAX_USTACK_SIZE] = {0, };
	__u64* ustack;
	static __u32 id = 0;

	task = bpf_get_current_task_btf();
	mm = BPF_CORE_READ(task, mm);
	ctx = (struct pt_regs *)bpf_task_pt_regs(task);

	if (id >= SAMPLE_MAX_ENTRIES)
		return -1;

	__sync_fetch_and_add(&id, 1);

	sample = bpf_map_lookup_or_try_init(&samples, &id, &szero);
	if (!sample) {
		bpf_printk("sample is null\n");
		goto cleanup;
	}

	/* dump user regs */
	pc = PT_REGS_IP_CORE(ctx);
	sp = PT_REGS_SP_CORE(ctx);
	bpf_probe_read(&sample->user_regs, sizeof(struct pt_regs), ctx);
	bpf_dbg_printk("id: %d, sp: %lx, pc: %lx\n", id, sp, pc);

	/* dump user stack */
	if (!mm) {
		bpf_printk("ustack is null\n");
		goto cleanup;
	}

	ustack = bpf_map_lookup_or_try_init(&ustacks, &id, &zero);
	if (!ustack) {
		bpf_printk("ustack is null\n");
		goto cleanup;
	}

	/* stack length to read */
	stack_len = BPF_CORE_READ(mm, start_stack) - sp;
	stack_len = MIN(stack_len, stack_storage_size);
	bpf_dbg_printk("stack_len: %d\n", stack_len);

	ret = bpf_probe_read_user(ustack, stack_len, (void*)sp);
	if (ret != 0)
		bpf_printk("failed to read stack: %d\n", ret);
	else
		sample->user_stack.size = stack_len;

#ifdef DEBUG_PRINT_STACK
	if (ret == 0) {
		bpf_printk("stack data:\n");
		for (int i = 0; i < 10; i++)
			bpf_printk("%x ", ustack[i]);
		bpf_printk("\n");
	}
#endif

	return id;

cleanup:
	__sync_fetch_and_add(&id, -1);
	return -1;
}

#endif /* __UNWIND_BPF_H */
