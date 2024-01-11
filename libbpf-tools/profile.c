// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2022 LG Electronics
//
// Based on profile(8) from BCC by Brendan Gregg and others.
// 28-Dec-2021   Eunseon Lee   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "profile.h"
#include "profile.skel.h"
#include "trace_helpers.h"

/* This structure combines key_t and count which should be sorted together */
struct key_ext_t {
	struct key_t k;
	__u64 v;
};

static struct env {
	pid_t pid;
	pid_t tid;
	bool user_stacks_only;
	bool kernel_stacks_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	int duration;
	bool verbose;
	bool freq;
	int sample_freq;
	bool delimiter;
	bool include_idle;
	bool folded;
	int cpu;
} env = {
	.pid = -1,
	.tid = -1,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.duration = 99999999,
	.freq = 1,
	.sample_freq = 49,
	.cpu = -1,
};

/*
 * -EFAULT in get_stackid normally means the stack-trace is not available,
 * Such as getting kernel stack trace in userspace code
 */
#define STACK_ID_EFAULT(stack_id)	(stack_id == -EFAULT)

#define STACK_ID_ERR(stack_id)		((stack_id < 0) && !STACK_ID_EFAULT(stack_id))

#define NEED_DELIMITER(delimiter, ustack_id, kstack_id) \
	(delimiter && ustack_id >= 0 && kstack_id >= 0)

const char *argp_program_version = "profile 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Profile CPU usage by sampling stack traces at a timed interval.\n"
"\n"
"USAGE: profile [OPTIONS...] [duration]\n"
"EXAMPLES:\n"
"    profile             # profile stack traces at 49 Hertz until Ctrl-C\n"
"    profile -F 99       # profile stack traces at 99 Hertz\n"
"    profile -c 1000000  # profile stack traces every 1 in a million events\n"
"    profile 5           # profile at 49 Hertz for 5 seconds only\n"
"    profile -f          # output in folded format for flame graphs\n"
"    profile -p 185      # only profile process with PID 185\n"
"    profile -L 185      # only profile thread with TID 185\n"
"    profile -U          # only show user space stacks (no kernel)\n"
"    profile -K          # only show kernel space stacks (no user)\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "profile process with this PID only" },
	{ "tid", 'L', "TID", 0, "profile thread with this TID only" },
	{ "user-stacks-only", 'U', NULL, 0,
	  "show stacks from user space only (no kernel space stacks)" },
	{ "kernel-stacks-only", 'K', NULL, 0,
	  "show stacks from kernel space only (no user space stacks)" },
	{ "frequency", 'F', "FREQUENCY", 0, "sample frequency, Hertz" },
	{ "delimited", 'd', NULL, 0, "insert delimiter between kernel/user stacks" },
	{ "include-idle ", 'I', NULL, 0, "include CPU idle stacks" },
	{ "folded", 'f', NULL, 0, "output folded format, one line per stack (for flame graphs)" },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)" },
	{ "cpu", 'C', "CPU", 0, "cpu number to run profile on" },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'L':
		errno = 0;
		env.tid = strtol(arg, NULL, 10);
		if (errno || env.tid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'U':
		env.user_stacks_only = true;
		break;
	case 'K':
		env.kernel_stacks_only = true;
		break;
	case 'F':
		errno = 0;
		env.sample_freq = strtol(arg, NULL, 10);
		if (errno || env.sample_freq <= 0) {
			fprintf(stderr, "invalid FREQUENCY: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		env.delimiter = true;
		break;
	case 'I':
		env.include_idle = true;
		break;
	case 'f':
		env.folded = true;
		break;
	case 'C':
		errno = 0;
		env.cpu = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid CPU: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration (in s): %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				      struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = env.freq,
		.sample_freq = env.sample_freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		if (env.cpu != -1 && env.cpu != i)
			continue;

		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			fprintf(stderr, "failed to attach perf event on cpu: "
				"%d\n", i);
			links[i] = NULL;
			close(fd);
			return -1;
		}
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
}

static int cmp_counts(const void *dx, const void *dy)
{
	__u64 x = ((struct key_ext_t *) dx)->v;
	__u64 y = ((struct key_ext_t *) dy)->v;
	return x > y ? -1 : !(x == y);
}

static bool batch_map_ops = true; /* hope for the best */

static bool read_batch_counts_map(int fd, struct key_ext_t *items, __u32 *count)
{
	void *in = NULL, *out;
	__u32 i, n, n_read = 0;
	int err = 0;
	__u32 vals[*count];
	struct key_t keys[*count];

	while (n_read < *count && !err) {
		n = *count - n_read;
		err = bpf_map_lookup_batch(fd, &in, &out, keys + n_read,
					   vals + n_read, &n, NULL);
		if (err && errno != ENOENT) {
			/* we want to propagate EINVAL upper, so that
			 * the batch_map_ops flag is set to false */
			if (errno != EINVAL)
				fprintf(stderr, "bpf_map_lookup_batch: %s\n",
					strerror(-err));
			return false;
		}
		n_read += n;
		in = out;
	}

	for (i = 0; i < n_read; i++) {
		items[i].k.pid = keys[i].pid;
		items[i].k.user_stack_id = keys[i].user_stack_id;
		items[i].k.kern_stack_id = keys[i].kern_stack_id;
		memcpy(items[i].k.name, keys[i].name, TASK_COMM_LEN);
		items[i].v = vals[i];
	}

	*count = n_read;
	return true;
}

static bool read_counts_map(int fd, struct key_ext_t *items, __u32 *count)
{
	struct key_t empty = {};
	struct key_t *lookup_key = &empty;
	int i = 0;
	int err;

	if (batch_map_ops) {
		bool ok = read_batch_counts_map(fd, items, count);
		if (!ok && errno == EINVAL) {
			/* fall back to a racy variant */
			batch_map_ops = false;
		} else {
			return ok;
		}
	}

	if (!items || !count || !*count)
		return true;

	while (!bpf_map_get_next_key(fd, lookup_key, &items[i].k)) {

		err = bpf_map_lookup_elem(fd, &items[i].k, &items[i].v);
		if (err < 0) {
			fprintf(stderr, "failed to lookup counts: %d\n", err);
			return false;
		}
		if (items[i].v == 0)
			continue;

		lookup_key = &items[i].k;
		i++;
	}

	*count = i;
	return true;
}

static void print_user_stacktrace(unsigned long *ip,
				  struct syms_cache *syms_cache,
				  pid_t pid)
{
	int i;
	const struct sym *sym;
	const struct syms *syms = syms_cache__get_syms(syms_cache, pid);

	if (!syms) {
		fprintf(stderr, "failed to get syms\n");
		return;
	}

	for (i = 0; ip[i] && i < env.perf_max_stack_depth; i++) {
		sym = syms__map_addr(syms, ip[i]);
		printf("    %s\n", sym ? sym->name : "[unknown]");
	}
}

static void print_user_stacktrace_folded(unsigned long *ip,
					 struct syms_cache *syms_cache,
					 pid_t pid)
{
	int i;
	const struct sym *sym;
	const struct syms *syms = syms_cache__get_syms(syms_cache, pid);

	if (!syms)
		return;

	for (i = env.perf_max_stack_depth - 1; i >= 0; i--) {
		if (ip[i] == 0)
			continue;

		sym = syms__map_addr(syms, ip[i]);
		printf(";%s", sym ? sym->name : "[unknown]");
	}
}

static void print_kernel_stacktrace(unsigned long *ip, struct ksyms *ksyms)
{
	int i;
	const struct ksym *ksym;

	for (i = 0; ip[i] && i < env.perf_max_stack_depth; i++) {
		ksym = ksyms__map_addr(ksyms, ip[i]);
		printf("    %s\n", ksym ? ksym->name : "unknown");
	}
}

static void print_kernel_stacktrace_folded(unsigned long *ip, struct ksyms *ksyms)
{
	int i;
	const struct ksym *ksym;

	for (i = env.perf_max_stack_depth - 1; i >= 0; i--) {
		if (ip[i] == 0)
			continue;

		ksym = ksyms__map_addr(ksyms, ip[i]);
		printf(";%s", ksym ? ksym->name : "[unknown]");
	}
}

enum syms_type {
	SYMS_CACHE,
	KSYMS,
	BLAZESYM,
};

/* it */
struct iterator {
	bool reverse;
	int cur_idx;
	unsigned long *ip;
	enum syms_type syms_type;
	void *syms;
	void *sym;
};

int _begin(struct iterator *it, bool reverse, unsigned long *ip, enum syms_type type, void *syms) {
	int i;

	it->reverse = reverse;
	it->ip = ip;
	it->syms_type = type;
	it->syms = syms;

	if (!it->reverse) {
		it->cur_idx = 0;
	} else {
		for (i = env.perf_max_stack_depth - 1; ip[i] == 0; i--)
			;
		it->cur_idx = i;
	}
}

int begin(struct iterator *it, unsigned long *ip, enum syms_type type, void *syms) {
	_begin(it, false, ip, type, syms);
}

int begin_reverse(struct iterator *it, unsigned long *ip, enum syms_type type, void *syms) {
	_begin(it, true, ip, type, syms);
}

int next(struct iterator *it) {

	if (it->syms_type == KSYMS) {
		struct ksyms *ksyms = it->syms;
		it->sym = (void*)ksyms__map_addr(ksyms, it->ip[it->cur_idx]);
	} else if (it->syms_type == SYMS_CACHE) {
		struct syms *syms = it->syms;
		it->sym = (void*)syms__map_addr(syms, it->ip[it->cur_idx]);
	}

	if (it->reverse)
		it->cur_idx--;
	else
		it->cur_idx++;
}

int end(struct iterator *it) {
	if (it->reverse)
		return it->cur_idx < 0;
	else
		return (it->cur_idx >= env.perf_max_stack_depth) || (it->ip[it->cur_idx] == 0);
}

static void print_count(struct key_t *event, __u64 count, int sfd,
			struct ksyms *ksyms, struct syms_cache *syms_cache)
{
	unsigned long *ip;
	struct iterator it;
	//const struct ksym *ksym;
	struct ksym *ksym;
	struct sym *sym;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return;
	}

	/* kernel stack */
	if (!env.user_stacks_only && !STACK_ID_EFAULT(event->kern_stack_id)) {
		if (bpf_map_lookup_elem(sfd, &event->kern_stack_id, ip) != 0)
			printf("    [Missed Kernel Stack]\n");
		else {
			for (begin(&it, ip, KSYMS, ksyms); !end(&it); next(&it)) {
				ksym = it.sym;
				printf("    %s\n", ksym ? ksym->name : "unknown");
			}
		}
	}

	/* user stack */
	if (!env.kernel_stacks_only && !STACK_ID_EFAULT(event->user_stack_id)) {
		if (NEED_DELIMITER(env.delimiter, event->user_stack_id, event->kern_stack_id))
			printf("    --\n");

		if (bpf_map_lookup_elem(sfd, &event->user_stack_id, ip) != 0)
			printf("    [Missed User Stack]\n");
		else {
			const struct syms *syms = syms_cache__get_syms(syms_cache, event->pid);

			if (!syms) {
				fprintf(stderr, "failed to get syms\n");
				return;
			}

			for (begin_reverse(&it, ip, SYMS_CACHE, syms); !end(&it); next(&it)) {
				sym = it.sym;
				printf("    %s\n", sym ? sym->name : "[unknown]");
			}
		}
	}

	printf("    %-16s %s (%d)\n", "-", event->name, event->pid);
	printf("        %lld\n\n", count);

	free(ip);
}

static void print_count_folded(struct key_t *event, __u64 count, int sfd,
			       struct ksyms *ksyms, struct syms_cache *syms_cache)
{
	unsigned long *ip;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return;
	}

	printf("%s", event->name);

	/* user stack */
	if (!env.kernel_stacks_only && !STACK_ID_EFAULT(event->user_stack_id)) {
		if (bpf_map_lookup_elem(sfd, &event->user_stack_id, ip) != 0)
			printf(";[Missed User Stack]");
		else {
			print_user_stacktrace_folded(ip, syms_cache, event->pid);
#if 0
			struct sym_iterator it;
			begin(it, true, ip, syms);

			for (it, it, next(it, sym))
				printf("format", sym.name, sym.offset);
#endif
		}
	}

	/* kernel stack */
	if (!env.user_stacks_only && !STACK_ID_EFAULT(event->kern_stack_id)) {
		if (NEED_DELIMITER(env.delimiter, event->user_stack_id, event->kern_stack_id))
			printf(";-");

		if (bpf_map_lookup_elem(sfd, &event->kern_stack_id, ip) != 0)
			printf(";[Missed Kernel Stack]");
		else {
			print_kernel_stacktrace_folded(ip, ksyms);
#if 0
			struct sym_iterator it;
			begin(it, true, ip, syms);

			for (it, it, next(it, sym))
				printf("format", sym.name, sym.offset);
#endif
		}
	}

	printf(" %lld\n", count);

	free(ip);
}

static void print_counts(struct ksyms *ksyms, struct syms_cache *syms_cache,
			 struct profile_bpf *obj)
{
	int i, cfd, sfd;
	struct key_t *event;
	__u64 count;
	__u32 nr_count = MAX_ENTRIES;
	bool has_collision = false;
	unsigned int missing_stacks = 0;
	struct key_ext_t counts[MAX_ENTRIES];

	cfd = bpf_map__fd(obj->maps.counts);
	sfd = bpf_map__fd(obj->maps.stackmap);

	if (!read_counts_map(cfd, counts, &nr_count))
		return;

	qsort(counts, nr_count, sizeof(counts[0]), cmp_counts);

	for (i = 0; i < nr_count; i++) {
		event = &counts[i].k;
		count = counts[i].v;

		/* hash collision (-EEXIST) suggests that the map size may be too small */
		if (!env.user_stacks_only && STACK_ID_ERR(event->kern_stack_id)) {
			missing_stacks += 1;
			has_collision |= (event->kern_stack_id == -EEXIST);
		}
		if (!env.kernel_stacks_only && STACK_ID_ERR(event->user_stack_id)) {
			missing_stacks += 1;
			has_collision |= (event->user_stack_id == -EEXIST);
		}

		if (env.folded) {
			/* print folded stack output */
			print_count_folded(event, count, sfd, ksyms, syms_cache);
		} else {
			/* print default multi-line stack output */
			print_count(event, count, sfd, ksyms, syms_cache);
		}
	}

	if (missing_stacks > 0) {
		fprintf(stderr, "WARNING: %d stack traces could not be displayed.%s\n",
			missing_stacks, has_collision ?
			" Consider increasing --stack-storage-size.":"");
	}
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct syms_cache *syms_cache = NULL;
	struct ksyms *ksyms = NULL;
	struct bpf_link *links[MAX_CPU_NR] = {};
	struct profile_bpf *obj;
	int err, i;
	char* stack_context = "user + kernel";
	char thread_context[64];
	char sample_context[64];

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.user_stacks_only && env.kernel_stacks_only) {
		fprintf(stderr, "user_stacks_only and kernel_stacks_only cannot be used together.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		printf("failed to get # of possible cpus: '%s'!\n",
		       strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		fprintf(stderr, "the number of cpu cores is too big, please "
			"increase MAX_CPU_NR's value and recompile");
		return 1;
	}

	obj = profile_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_pid = env.pid;
	obj->rodata->targ_tid = env.tid;
	obj->rodata->user_stacks_only = env.user_stacks_only;
	obj->rodata->kernel_stacks_only = env.kernel_stacks_only;
	obj->rodata->include_idle = env.include_idle;

	bpf_map__set_value_size(obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = profile_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		goto cleanup;
	}
	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}
	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}

	err = open_and_attach_perf_event(env.freq, obj->progs.do_perf_event, links);
	if (err)
		goto cleanup;

	signal(SIGINT, sig_handler);

	if (env.pid != -1)
		snprintf(thread_context, sizeof(thread_context), "PID %d", env.pid);
	else if (env.tid != -1)
		snprintf(thread_context, sizeof(thread_context), "TID %d", env.tid);
	else
		snprintf(thread_context, sizeof(thread_context), "all threads");

	snprintf(sample_context, sizeof(sample_context), "%d Hertz", env.sample_freq);

	if (env.user_stacks_only)
		stack_context = "user";
	else if (env.kernel_stacks_only)
		stack_context = "kernel";

	if (!env.folded) {
		printf("Sampling at %s of %s by %s stack", sample_context, thread_context, stack_context);
		if (env.cpu != -1)
			printf(" on CPU#%d", env.cpu);
		if (env.duration < 99999999)
			printf(" for %d secs.\n", env.duration);
		else
			printf("... Hit Ctrl-C to end.\n");
	}

	/*
	 * We'll get sleep interrupted when someone presses Ctrl-C.
	 * (which will be "handled" with noop by sig_handler)
	 */
	sleep(env.duration);

	print_counts(ksyms, syms_cache, obj);

cleanup:
	if (env.cpu != -1)
		bpf_link__destroy(links[env.cpu]);
	else {
		for (i = 0; i < nr_cpus; i++)
			bpf_link__destroy(links[i]);
	}
	profile_bpf__destroy(obj);
	syms_cache__free(syms_cache);
	ksyms__free(ksyms);
	return err != 0;
}
