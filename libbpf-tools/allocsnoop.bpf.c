// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 LG Electronics Inc.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "maps.bpf.h"
#include "allocsnoop.h"
#include "core_fixes.bpf.h"

const volatile size_t min_size = 0;
const volatile size_t max_size = -1;
const volatile size_t page_size = 4096;
const volatile __u64 sample_rate = 1;
const volatile bool trace_all = false;
const volatile __u64 stack_flags = 0;
const volatile bool wa_missing_free = false;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RING_BUF_MAX_SIZE);
} rb_alloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RING_BUF_MAX_SIZE);
} rb_dealloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, ERR_RING_BUF_MAX_SIZE);
} rb_err SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 10240);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stack_traces SEC(".maps");

static int gen_alloc_enter(size_t size)
{
	if (size < min_size || size > max_size)
		return 0;

	if (sample_rate > 1) {
		if (bpf_ktime_get_ns() % sample_rate != 0)
			return 0;
	}

	const u32 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);

	if (trace_all)
		bpf_printk("alloc entered, size = %lu\n", size);

	return 0;
}

static int gen_alloc_exit2(void *ctx, u64 address)
{
	const u32 tid = bpf_get_current_pid_tgid();
	struct alloc_info info;
	int ret;

	const u64* size = bpf_map_lookup_elem(&sizes, &tid);
	if (!size)
		return 0; // missed alloc entry

	__builtin_memset(&info, 0, sizeof(info));

	info.size = *size;
	bpf_map_delete_elem(&sizes, &tid);

	if (address != 0) {
		info.timestamp_ns = bpf_ktime_get_ns();

		info.addr = address;

		info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);

		info.pid = bpf_get_current_pid_tgid() >> 32;

		ret = bpf_ringbuf_output(&rb_alloc, &info, sizeof(info), 0);
		if (ret < 0) {
			struct allocsnoop_err_info e_info;
			e_info.type = E_RB_ALLOC;
			e_info.err = ret;

			ret = bpf_ringbuf_output(&rb_err, &e_info, sizeof(e_info), 0);
			if (ret < 0)
				bpf_printk("rb_err: failed to output\n");
		}
	}

	if (trace_all) {
		bpf_printk("alloc exited, size = %lu, result = %lx\n",
			   info.size, address);
	}

	return 0;
}

static int gen_alloc_exit(struct pt_regs *ctx)
{
	return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static int gen_free_enter(void *ctx, const void *address)
{
	const u64 addr = (u64)address;
	struct dealloc_info info;
	int ret;

	if (trace_all)
		bpf_printk("free entered, address = %lx\n", address);

	__builtin_memset(&info, 0, sizeof(info));

	if (addr != 0) {
		info.timestamp_ns = bpf_ktime_get_ns();

		info.addr = addr;

		info.pid = bpf_get_current_pid_tgid() >> 32;

		ret = bpf_ringbuf_output(&rb_dealloc, &info, sizeof(info), 0);
		if (ret < 0) {
			struct allocsnoop_err_info e_info;
			e_info.type = E_RB_DEALLOC;
			e_info.err = ret;

			ret = bpf_ringbuf_output(&rb_err, &e_info, sizeof(e_info), 0);
			if (ret < 0)
				bpf_printk("rb_err: failed to output\n");
		}
	}

	return 0;
}

SEC("uprobe")
int BPF_UPROBE(malloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(malloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(free_enter, void *address)
{
	return gen_free_enter(ctx, address);
}

SEC("uprobe")
int BPF_UPROBE(calloc_enter, size_t nmemb, size_t size)
{
	return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_URETPROBE(calloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(realloc_enter, void *ptr, size_t size)
{
	gen_free_enter(ctx, ptr);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(realloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(mmap_enter, void *address, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(mmap_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(munmap_enter, void *address)
{
	return gen_free_enter(ctx, address);
}

SEC("uprobe")
int BPF_UPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size)
{
	const u64 memptr64 = (u64)(size_t)memptr;
	const u32 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&memptrs, &tid, &memptr64, BPF_ANY);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(posix_memalign_exit)
{
	u64 *memptr64;
	void *addr;
	const u32 tid = bpf_get_current_pid_tgid();

	memptr64 = bpf_map_lookup_elem(&memptrs, &tid);
	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &tid);

	if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
		return 0;

	const u64 addr64 = (u64)(size_t)addr;

	return gen_alloc_exit2(ctx, addr64);
}

SEC("uprobe")
int BPF_UPROBE(aligned_alloc_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(aligned_alloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(valloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(valloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(memalign_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(memalign_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(pvalloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(pvalloc_exit)
{
	return gen_alloc_exit(ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
