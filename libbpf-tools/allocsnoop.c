// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 LG Electronics Inc.

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "allocsnoop.h"
#include "allocsnoop.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

#include "bpftool/src/json_writer.h"

static struct env {
	int interval;
	int nr_intervals;
	pid_t pid;
	bool trace_all;
	bool show_allocs;
	int min_age_ns;
	uint64_t sample_rate;
	int top_stacks;
	size_t min_size;
	size_t max_size;
	char object[32];

	bool wa_missing_free;
	bool percpu;
	int perf_max_stack_depth;
	int stack_map_max_entries;
	long page_size;
	bool kernel_trace;
	bool verbose;
	char symbols_prefix[16];
} env = {
	.interval = 5, // posarg 1
	.nr_intervals = -1, // posarg 2
	.pid = -1, // -p --pid
	.trace_all = false, // -t --trace
	.show_allocs = false, // -a --show-allocs
	.min_age_ns = 500, // -o --older (arg * 1e6)
	.wa_missing_free = false, // --wa-missing-free
	.sample_rate = 1, // -s --sample-rate
	.top_stacks = 10, // -T --top
	.min_size = 0, // -z --min-size
	.max_size = -1, // -Z --max-size
	.object = {0}, // -O --obj
	.percpu = false, // --percpu
	.perf_max_stack_depth = 127,
	.stack_map_max_entries = 10240,
	.page_size = 1,
	.kernel_trace = false,
	.verbose = false,
	.symbols_prefix = {0},
};

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
	do { \
		char sym[32]; \
		sprintf(sym, "%s%s", env.symbols_prefix, #sym_name); \
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, \
				.func_name = sym, \
				.retprobe = is_retprobe); \
		skel->links.prog_name = bpf_program__attach_uprobe_opts( \
				skel->progs.prog_name, \
				env.pid, \
				env.object, \
				0, \
				&uprobe_opts); \
	} while (false)

#define __CHECK_PROGRAM(skel, prog_name) \
	do { \
		if (!skel->links.prog_name) { \
			perror("no program attached for " #prog_name); \
			return -errno; \
		} \
	} while (false)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
	do { \
		__ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe); \
		__CHECK_PROGRAM(skel, prog_name); \
	} while (false)

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

#define FILENAME_ALLOCS		"./allocsnoop_allocs.out"
#define FILENAME_DEALLOCS	"./allocsnoop_frees.out"
#define FILENAME_STACKTRACES	"./allocsnoop_stacktraces.out"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	10000
#define warn(...) fprintf(stderr, __VA_ARGS__)

static void sig_handler(int signo);

static long argp_parse_long(int key, const char *arg, struct argp_state *state);
static error_t argp_parse_arg(int key, char *arg, struct argp_state *state);

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);

#ifdef KERNEL_ALLOC
static bool has_kernel_node_tracepoints();
static void disable_kernel_node_tracepoints(struct allocsnoop_bpf *skel);
static void disable_kernel_percpu_tracepoints(struct allocsnoop_bpf *skel);
static void disable_kernel_tracepoints(struct allocsnoop_bpf *skel);
#endif

static int attach_uprobes(struct allocsnoop_bpf *skel);

const char *argp_program_version = "allocsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_args_doc[] =
"Trace outstanding memory allocations\n"
"\n"
"USAGE: allocsnoop [-h] [-c COMMAND] [-p PID] [-t] [-n] [-a] [-o AGE_MS] [-C] [-F] [-s SAMPLE_RATE] [-T TOP_STACKS] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJECT] [-P] [INTERVAL] [INTERVALS]\n"
"\n"
"EXAMPLES:\n"
"./allocsnoop -p $(pidof allocs)\n"
"        Trace allocations and display a summary of 'leaked' (outstanding)\n"
"        allocations every 5 seconds\n"
"./allocsnoop -p $(pidof allocs) -t\n"
"        Trace allocations and display each individual allocator function call\n"
"./allocsnoop -ap $(pidof allocs) 10\n"
"        Trace allocations and display allocated addresses, sizes, and stacks\n"
"        every 10 seconds for outstanding allocations\n"
"./allocsnoop -c './allocs'\n"
"        Run the specified command and trace its allocations\n"
"./allocsnoop\n"
"        Trace allocations in kernel mode and display a summary of outstanding\n"
"        allocations every 5 seconds\n"
"./allocsnoop -o 60000\n"
"        Trace allocations in kernel mode and display a summary of outstanding\n"
"        allocations that are at least one minute (60 seconds) old\n"
"./allocsnoop -s 5\n"
"        Trace roughly every 5th allocation, to reduce overhead\n"
"./allocsnoop -p $(pidof allocs) -S je_\n"
"        Trace task who sue jemalloc\n"
"";

static const struct argp_option argp_options[] = {
	// name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
	{"pid", 'p', "PID", 0, "process ID to trace. if not specified, trace kernel allocs", 0 },
	{"trace", 't', 0, 0, "print trace messages for each alloc/free call", 0 },
	{"show-allocs", 'a', 0, 0, "show allocation addresses and sizes as well as call stacks", 0 },
	{"older", 'o', "AGE_MS", 0, "prune allocations younger than this age in milliseconds", 0 },
	{"command", 'c', "COMMAND", 0, "execute and trace the specified command", 0 },
	{"combined-only", 'C', 0, 0, "show combined allocation statistics only", 0 },
	{"wa-missing-free", 'F', 0, 0, "workaround to alleviate misjudgments when free is missing", 0 },
	{"sample-rate", 's', "SAMPLE_RATE", 0, "sample every N-th allocation to decrease the overhead", 0 },
	{"top", 'T', "TOP_STACKS", 0, "display only this many top allocating stacks (by size)", 0 },
	{"min-size", 'z', "MIN_SIZE", 0, "capture only allocations larger than this size", 0 },
	{"max-size", 'Z', "MAX_SIZE", 0, "capture only allocations smaller than this size", 0 },
	{"obj", 'O', "OBJECT", 0, "attach to allocator functions in the specified object", 0 },
	{"percpu", 'P', NULL, 0, "trace percpu allocations", 0 },
	{"symbols-prefix", 'S', "SYMBOLS_PREFIX", 0, "memory allocator symbols prefix", 0 },
	{"verbose", 'v', NULL, 0, "verbose debug output", 0 },
	{},
};

static volatile sig_atomic_t exiting;
static volatile sig_atomic_t child_exited;

static struct sigaction sig_action = {
	.sa_handler = sig_handler
};

struct syms_cache *syms_cache;
struct ksyms *ksyms;

static uint64_t *stack;

static struct allocation *allocs;

static const char default_object[] = "libc.so.6";

/* Structure to synchronize kernel time with real time */
struct time_sync {
    struct timespec monotonic_time;
    struct timespec real_time;
};

static void sync_time(struct time_sync *sync);

struct time_sync g_sync;
static volatile sig_atomic_t exiting = 0;

json_writer_t *json_wtr_alloc;
json_writer_t *json_wtr_dealloc;
json_writer_t *json_wtr_stacktrace;

static void handle_alloc_event(void *ctx, int cpu, void *data, __u32 data_size);
static void handle_dealloc_event(void *ctx, int cpu, void *data, __u32 data_size);

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int init_outfile(FILE **f, char *fname, json_writer_t **json_wtr);
static int deinit_outfile(FILE *f, json_writer_t *json_wtr);

int main(int argc, char *argv[])
{
	int ret = 0;
	struct allocsnoop_bpf *skel = NULL;
	struct perf_buffer *alloc_pb = NULL;
	struct perf_buffer *dealloc_pb = NULL;
	FILE *f_alloc = NULL;
	FILE *f_dealloc = NULL;
	FILE *f_stacktrace = NULL;
	int err;

	static const struct argp argp = {
		.options = argp_options,
		.parser = argp_parse_arg,
		.doc = argp_args_doc,
	};

	sync_time(&g_sync);

	/* parse command line args to env settings */
	if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
		fprintf(stderr, "failed to parse args\n");

		goto cleanup;
	}

	/* install signal handler */
	if (sigaction(SIGINT, &sig_action, NULL) || sigaction(SIGCHLD, &sig_action, NULL)) {
		perror("failed to set up signal handling");
		ret = -errno;

		goto cleanup;
	}

	/* post-processing and validation of env settings */
	if (env.min_size > env.max_size) {
		fprintf(stderr, "min size (-z) can't be greater than max_size (-Z)\n");
		return 1;
	}

	if (!strlen(env.object)) {
		printf("using default object: %s\n", default_object);
		strncpy(env.object, default_object, sizeof(env.object) - 1);
	}

	env.page_size = sysconf(_SC_PAGE_SIZE);
	printf("using page size: %ld\n", env.page_size);

	// allocate space for storing a stack trace
	stack = calloc(env.perf_max_stack_depth, sizeof(*stack));
	if (!stack) {
		fprintf(stderr, "failed to allocate stack array\n");
		ret = -ENOMEM;

		goto cleanup;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = allocsnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		ret = 1;

		goto cleanup;
	}

	skel->rodata->trace_all = env.trace_all;
	skel->rodata->stack_flags = env.kernel_trace ? 0 : BPF_F_USER_STACK;
	skel->rodata->min_size = env.min_size;
	skel->rodata->max_size = env.max_size;
	skel->rodata->page_size = env.page_size;
	skel->rodata->sample_rate = env.sample_rate;
	skel->rodata->wa_missing_free = env.wa_missing_free;

	bpf_map__set_value_size(skel->maps.stack_traces,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(skel->maps.stack_traces, env.stack_map_max_entries);

#ifdef KERNEL_ALLOC
	// disable kernel tracepoints based on settings or availability
	if (env.kernel_trace) {
		if (!has_kernel_node_tracepoints())
			disable_kernel_node_tracepoints(skel);

		if (!env.percpu)
			disable_kernel_percpu_tracepoints(skel);
	} else {
		disable_kernel_tracepoints(skel);
	}
#endif

	ret = allocsnoop_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "failed to load bpf object\n");

		goto cleanup;
	}

	// if userspace oriented, attach upbrobes
	if (!env.kernel_trace) {
		ret = attach_uprobes(skel);
		if (ret) {
			fprintf(stderr, "failed to attach uprobes\n");

			goto cleanup;
		}
	}

	ret = allocsnoop_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "failed to attach bpf program(s)\n");

		goto cleanup;
	}

#if 0
	// if running a specific userspace program,
	// notify the child process that it can exec its program
	if (strlen(env.command)) {
		ret = event_notify(child_exec_event_fd, 1);
		if (ret) {
			fprintf(stderr, "failed to notify child to perform exec\n");

			goto cleanup;
		}
	}
#endif

	if (env.kernel_trace) {
		ksyms = ksyms__load();
		if (!ksyms) {
			fprintf(stderr, "Failed to load ksyms\n");
			ret = -ENOMEM;

			goto cleanup;
		}
	} else {
		syms_cache = syms_cache__new(0);
		if (!syms_cache) {
			fprintf(stderr, "Failed to create syms_cache\n");
			ret = -ENOMEM;

			goto cleanup;
		}
	}

	init_outfile(&f_alloc, FILENAME_ALLOCS, &json_wtr_alloc);
	init_outfile(&f_dealloc, FILENAME_DEALLOCS, &json_wtr_dealloc);
	init_outfile(&f_stacktrace, FILENAME_STACKTRACES, &json_wtr_stacktrace);

	alloc_pb = perf_buffer__new(bpf_map__fd(skel->maps.alloc_events), PERF_BUFFER_PAGES,
				    handle_alloc_event, handle_lost_events, skel, NULL);
	if (!alloc_pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	dealloc_pb = perf_buffer__new(bpf_map__fd(skel->maps.dealloc_events), PERF_BUFFER_PAGES,
				      handle_dealloc_event, handle_lost_events, NULL, NULL);
	if (!dealloc_pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("Tracing memory allocs...  Hit Ctrl-C to end\n");

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (!exiting) {
		sleep(env.interval);

		err = perf_buffer__poll(alloc_pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}

		err = perf_buffer__poll(dealloc_pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	if (syms_cache)
		syms_cache__free(syms_cache);
	if (ksyms)
		ksyms__free(ksyms);

	allocsnoop_bpf__destroy(skel);

	free(allocs);
	free(stack);
	perf_buffer__free(alloc_pb);
	perf_buffer__free(dealloc_pb);
	deinit_outfile(f_alloc, json_wtr_alloc);
	deinit_outfile(f_dealloc, json_wtr_dealloc);
	deinit_outfile(f_stacktrace, json_wtr_stacktrace);

	printf("done\n");
	return ret;
}

long argp_parse_long(int key, const char *arg, struct argp_state *state)
{
	errno = 0;
	const long temp = strtol(arg, NULL, 10);
	if (errno || temp <= 0) {
		fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
		argp_usage(state);
	}

	return temp;
}

error_t argp_parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args = 0;

	switch (key) {
	case 'p':
		env.pid = atoi(arg);
		break;
	case 't':
		env.trace_all = true;
		break;
	case 'a':
		env.show_allocs = true;
		break;
	case 'o':
		env.min_age_ns = 1e6 * atoi(arg);
		break;
#if 0
	case 'c':
		strncpy(env.command, arg, sizeof(env.command) - 1);
		break;
	case 'C':
		env.combined_only = true;
		break;
#endif
	case 'F':
		env.wa_missing_free = true;
		break;
	case 's':
		env.sample_rate = argp_parse_long(key, arg, state);
		break;
	case 'S':
		strncpy(env.symbols_prefix, arg, sizeof(env.symbols_prefix) - 1);
		break;
	case 'T':
		env.top_stacks = atoi(arg);
		break;
	case 'z':
		env.min_size = argp_parse_long(key, arg, state);
		break;
	case 'Z':
		env.max_size = argp_parse_long(key, arg, state);
		break;
	case 'O':
		strncpy(env.object, arg, sizeof(env.object) - 1);
		break;
	case 'P':
		env.percpu = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		pos_args++;

		if (pos_args == 1) {
			env.interval = argp_parse_long(key, arg, state);
		}
		else if (pos_args == 2) {
			env.nr_intervals = argp_parse_long(key, arg, state);
		} else {
			fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}

		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

void sig_handler(int signo)
{
	if (signo == SIGCHLD)
		child_exited = 1;

	exiting = 1;
}

static void sync_time(struct time_sync *sync)
{
	clock_gettime(CLOCK_MONOTONIC, &sync->monotonic_time);
	clock_gettime(CLOCK_REALTIME, &sync->real_time);
}

/* Convert kernel time to real time in nanoseconds */
static uint64_t convert_to_realtime_ns(uint64_t kernel_ns, struct time_sync *sync) {
	uint64_t elapsed_ns;
	uint64_t real_time_ns;

	elapsed_ns = kernel_ns -
		(sync->monotonic_time.tv_sec * 1000000000 + sync->monotonic_time.tv_nsec);
	real_time_ns = elapsed_ns +
		(sync->real_time.tv_sec * 1000000000 + sync->real_time.tv_nsec);

	return real_time_ns;
}

static time_t get_unix_ts(unsigned long kernel_ns)
{
	return convert_to_realtime_ns(kernel_ns, &g_sync);
}

static void json_init(FILE *f, json_writer_t **json_wtr)
{
	*json_wtr = jsonw_new(f);
	if (!*json_wtr) {
		printf("failed to create JSON writer");
		return;
	}
	jsonw_pretty(*json_wtr, true);
	jsonw_start_array(*json_wtr);
}

static void json_deinit(FILE *f, json_writer_t *json_wtr)
{
	jsonw_end_array(json_wtr);
	jsonw_destroy(&json_wtr);
	fclose(f);
}

static void json_add_alloc(struct alloc_info *ra)
{
	json_writer_t *w = json_wtr_alloc;
	jsonw_start_object(w);
	jsonw_uint_field(w, "time", get_unix_ts(ra->timestamp_ns));
	jsonw_uint_field(w, "addr", ra->addr);
	jsonw_uint_field(w, "size", ra->size);
	jsonw_uint_field(w, "stackid", ra->stack_id);
	jsonw_uint_field(w, "pid", ra->pid);
	jsonw_end_object(w);
}

static void json_add_dealloc(struct dealloc_info *ra)
{
	json_writer_t *w = json_wtr_dealloc;
	jsonw_start_object(w);
	jsonw_uint_field(w, "time", get_unix_ts(ra->timestamp_ns));
	jsonw_uint_field(w, "addr", ra->addr);
	jsonw_uint_field(w, "pid", ra->pid);
	jsonw_end_object(w);
}

void print_stack(json_writer_t *w, pid_t pid)
{
	const struct syms *syms = syms_cache__get_syms(syms_cache, pid);
	if (!syms) {
		fprintf(stderr, "Failed to get syms\n");
		return;
	}

	for (size_t i = 0; i < env.perf_max_stack_depth; ++i) {
		const uint64_t addr = stack[i];

		if (addr == 0)
			break;

		const struct sym *sym = syms__map_addr(syms, addr);

		jsonw_string(w, sym ? sym->name : "[unknown]");
	}
}

static void json_add_stacktrace(int stack_id, u64 *ip, pid_t pid)
{
	json_writer_t *w = json_wtr_stacktrace;
	jsonw_start_object(w);

	jsonw_uint_field(w, "stackid", stack_id);
	jsonw_uint_field(w, "stackid_tag", stack_id);

	jsonw_name(w, "callchain");
	jsonw_start_array(w);

	//
	print_stack(w, pid);

	jsonw_end_array(w);

	jsonw_end_object(w);
}

static void handle_stacktrace(void *ctx, int stack_id, pid_t pid)
{
	struct allocsnoop_bpf *skel = ctx;
	const int stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);

	if (bpf_map_lookup_elem(stack_traces_fd, &stack_id, stack)) {
		if (errno == ENOENT)
			return;

		fprintf(stderr, "failed to lookup stack trace: %s", strerror(errno));
		return;
	}

	json_add_stacktrace(stack_id, stack, pid);
}

static void handle_alloc_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	struct alloc_info *alloc = data;

	if (env.verbose)
		fprintf(stdout, "CPU: %d, [%#llx] addr = %#llx, size = %llx, "
			"stackid: %x, pid: %llx\n", cpu, alloc->timestamp_ns,
			alloc->addr, alloc->size, alloc->stack_id, alloc->pid);

	json_add_alloc(alloc);

	handle_stacktrace(ctx, alloc->stack_id, alloc->pid);
}

static void handle_dealloc_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	struct dealloc_info *dealloc = data;

	if (env.verbose)
		fprintf(stdout, "CPU: %d, [%#llx] addr = %#llx, pid: %llx\n",
			cpu, dealloc->timestamp_ns, dealloc->addr, dealloc->pid);

	json_add_dealloc(dealloc);
}

static int init_outfile(FILE **f, char *fname, json_writer_t **json_wtr)
{
	*f = fopen(fname, "w");
	json_init(*f, json_wtr);

	return 0;
}

static int deinit_outfile(FILE *f, json_writer_t *json_wtr)
{
	json_deinit(f, json_wtr);

	return 0;
}

#ifdef KERNEL_ALLOC
bool has_kernel_node_tracepoints()
{
	return tracepoint_exists("kmem", "kmalloc_node") &&
		tracepoint_exists("kmem", "kmem_cache_alloc_node");
}

void disable_kernel_node_tracepoints(struct allocsnoop_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.allocsnoop__kmalloc_node, false);
	bpf_program__set_autoload(skel->progs.allocsnoop__kmem_cache_alloc_node, false);
}

void disable_kernel_percpu_tracepoints(struct allocsnoop_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.allocsnoop__percpu_alloc_percpu, false);
	bpf_program__set_autoload(skel->progs.allocsnoop__percpu_free_percpu, false);
}

void disable_kernel_tracepoints(struct allocsnoop_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.allocsnoop__kmalloc, false);
	bpf_program__set_autoload(skel->progs.allocsnoop__kmalloc_node, false);
	bpf_program__set_autoload(skel->progs.allocsnoop__kfree, false);
	bpf_program__set_autoload(skel->progs.allocsnoop__kmem_cache_alloc, false);
	bpf_program__set_autoload(skel->progs.allocsnoop__kmem_cache_alloc_node, false);
	bpf_program__set_autoload(skel->progs.allocsnoop__kmem_cache_free, false);
	bpf_program__set_autoload(skel->progs.allocsnoop__mm_page_alloc, false);
	bpf_program__set_autoload(skel->progs.allocsnoop__mm_page_free, false);
	bpf_program__set_autoload(skel->progs.allocsnoop__percpu_alloc_percpu, false);
	bpf_program__set_autoload(skel->progs.allocsnoop__percpu_free_percpu, false);
}
#endif

int attach_uprobes(struct allocsnoop_bpf *skel)
{
	ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);

	ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);

	ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);

	/* third party allocator like jemallloc not support mmap, so remove the check. */
	if (strlen(env.symbols_prefix)) {
		ATTACH_UPROBE(skel, mmap, mmap_enter);
		ATTACH_URETPROBE(skel, mmap, mmap_exit);
	} else {
		ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
		ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);
	}

	ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);

	ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);

	ATTACH_UPROBE_CHECKED(skel, free, free_enter);
	if (strlen(env.symbols_prefix))
		ATTACH_UPROBE(skel, munmap, munmap_enter);
	else
		ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);

	// the following probes are intentinally allowed to fail attachment

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, valloc, valloc_enter);
	ATTACH_URETPROBE(skel, valloc, valloc_exit);

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
	ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);

	// added in C11
	ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
	ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);


	return 0;
}
