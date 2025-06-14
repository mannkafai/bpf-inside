// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Facebook */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "data_breakpoint.skel.h"
#include "data_breakpoint.h"
#include "blazesym.h"

/*
 * This function is from libbpf, but it is not a public API and can only be
 * used for demonstration. We can use this here because we statically link
 * against the libbpf built from submodule during build.
 */
extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
							unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

static struct blaze_symbolizer *symbolizer;

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info)
{
    // If we have an input address  we have a new symbol.
    if (input_addr != 0) {
      printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
			if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
				printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
				printf(" %s:%u\n", code_info->file, code_info->line);
      } else {
				printf("\n");
      }
    } else {
      printf("%16s  %s", "", name);
			if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
				printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
				printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
      } else {
				printf("[inlined]\n");
      }
    }
}

static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
  const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_syms *syms;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
		};
		syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};
		syms = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}

	if (syms == NULL) {
		printf("  failed to symbolize addresses: %s\n", blaze_err_str(blaze_err_last()));
		return;
	}

	for (i = 0; i < stack_sz; i++) {
		if (!syms || syms->cnt <= i || syms->syms[i].name == NULL) {
			printf("%016llx: <no-symbol>\n", stack[i]);
			continue;
		}

    sym = &syms->syms[i];
    print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

    for (j = 0; j < sym->inlined_cnt; j++) {
      inlined = &sym->inlined[j];
      print_frame(sym->name, 0, 0, 0, &inlined->code_info);
    }
	}

	blaze_syms_free(syms);
}

/* Receive events from the ring buffer. */
static int event_handler(void *_ctx, void *data, size_t size)
{
	struct stacktrace_event *event = data;

	if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
		return 1;

	printf("Time:%ld, COMM: %s (pid=%d) @ CPU %d\n", time(NULL), event->comm, event->pid, event->cpu_id);

	if (event->kstack_sz > 0)
	{
		printf("Kernel:\n");
		show_stack_trace(event->kstack, event->kstack_sz / sizeof(__u64), 0);
	}
	else
	{
		printf("No Kernel Stack\n");
	}

	if (event->ustack_sz > 0)
	{
		printf("Userspace:\n");
		show_stack_trace(event->ustack, event->ustack_sz / sizeof(__u64), event->pid);
	}
	else
	{
		printf("No Userspace Stack\n");
	}

	printf("\n");
	return 0;
}

static void show_help(const char *progname)
{
	printf("Usage: %s [-a <address>] [-l <len>] [-t <type>] [-h]\n", progname);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static char *hw_type[] = {"EMPTY", "R", "W", "RW", "X"};

int main(int argc, char *const argv[])
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	int pid = -1, cpu, bp_len = 1, bp_type = HW_BREAKPOINT_W;
	uint64_t bp_addr = 0;
	struct data_breakpoint_bpf *skel = NULL;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;
	struct ring_buffer *ring_buf = NULL;
	int num_cpus, num_online_cpus;
	int *pefds = NULL, pefd;
	int argp, i, err = 0;
	bool *online_mask = NULL;

	while ((argp = getopt(argc, argv, "ha:l:t:")) != -1)
	{
		switch (argp)
		{
		case 'a':
			bp_addr = strtoul(optarg, NULL, 16);
			break;
		case 'l':
			bp_len = atoi(optarg);
			break;
		case 't':
			bp_type = atoi(optarg);
			break;
		case 'h':
		default:
			show_help(argv[0]);
			return 1;
		}
	}
	if ((bp_len < 1 || bp_len > 8) || (bp_type < 0 || bp_type > 4))
	{
		show_help(argv[0]);
		return 1;
	}
	printf("addr:%#lX, len:%d, type:%s\n", bp_addr, bp_len, hw_type[bp_type]);

	err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
	if (err)
	{
		fprintf(stderr, "Fail to get online CPU numbers: %d\n", err);
		goto cleanup;
	}

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0)
	{
		fprintf(stderr, "Fail to get the number of processors\n");
		err = -1;
		goto cleanup;
	}
	libbpf_set_print(libbpf_print_fn);

	skel = data_breakpoint_bpf__open_and_load();
	if (!skel)
	{
		fprintf(stderr, "Fail to open and load BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	symbolizer = blaze_symbolizer_new();
	if (!symbolizer)
	{
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto cleanup;
	}

	/* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);
	if (!ring_buf)
	{
		err = -1;
		goto cleanup;
	}

	pefds = malloc(num_cpus * sizeof(int));
	for (i = 0; i < num_cpus; i++)
	{
		pefds[i] = -1;
	}

	links = calloc(num_cpus, sizeof(struct bpf_link *));
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_BREAKPOINT;
	attr.size = sizeof(attr);
	attr.pinned = 1;
	attr.sample_period = 1;
	attr.bp_addr = bp_addr;
	attr.bp_len = bp_len;
	attr.bp_type = bp_type;

	for (cpu = 0; cpu < num_cpus; cpu++)
	{
		/* skip offline/not present CPUs */
		if (cpu >= num_online_cpus || !online_mask[cpu])
			continue;

		/* Set up performance monitoring on a CPU/Core */
		pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0)
		{
			fprintf(stderr, "Fail to set up performance monitor on a CPU/Core,%m\n");
			err = -1;
			goto cleanup;
		}
		pefds[cpu] = pefd;

		/* Attach a BPF program on a CPU */
		links[cpu] = bpf_program__attach_perf_event(skel->progs.profile, pefd);
		if (!links[cpu])
		{
			err = -1;
			goto cleanup;
		}
	}

	/* Wait and receive stack traces */
	while (ring_buffer__poll(ring_buf, -1) >= 0)
	{
	}

cleanup:
	if (links)
	{
		for (cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(links[cpu]);
		free(links);
	}
	if (pefds)
	{
		for (i = 0; i < num_cpus; i++)
		{
			if (pefds[i] >= 0)
				close(pefds[i]);
		}
		free(pefds);
	}
	ring_buffer__free(ring_buf);
	data_breakpoint_bpf__destroy(skel);
	blaze_symbolizer_free(symbolizer);
	free(online_mask);
	return -err;
}
