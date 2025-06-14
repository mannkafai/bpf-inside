// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "runqlen.h"

/**
 * commit 736c55a02c47 ("sched/fair: Rename cfs_rq.nr_running into nr_queued")
 * renamed cfs_rq::nr_running to cfs_rq::nr_queued.
 *
 * References:
 *   [0]: https://github.com/torvalds/linux/commit/736c55a02c47
 */
struct cfs_rq___pre_v614 {
	unsigned int		nr_running;
};

static __always_inline __u8 cfs_rq_get_nr_running_or_nr_queued(void *cfs_rq)
{
	if (bpf_core_field_exists(struct cfs_rq___pre_v614, nr_running))
		return BPF_CORE_READ((struct cfs_rq___pre_v614 *)cfs_rq, nr_running);

	return BPF_CORE_READ((struct cfs_rq *)cfs_rq, nr_queued);
}

const volatile bool targ_per_cpu = false;
const volatile bool targ_host = false;

struct hist hists[MAX_CPU_NR] = {};

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
	struct task_struct *task;
	struct hist *hist;
	u64 slot, cpu = 0;

	task = (void*)bpf_get_current_task();
	if (targ_host)
		slot = BPF_CORE_READ(task, se.cfs_rq, rq, nr_running);
	else
		slot = cfs_rq_get_nr_running_or_nr_queued(BPF_CORE_READ(task, se.cfs_rq));
	/*
	 * Calculate run queue length by subtracting the currently running task,
	 * if present. len 0 == idle, len 1 == one running task.
	 */
	if (slot > 0)
		slot--;
	if (targ_per_cpu) {
		cpu = bpf_get_smp_processor_id();
		/*
		 * When the program is started, the user space will immediately
		 * exit when it detects this situation, here just to pass the
		 * verifier's check.
		 */
		if (cpu >= MAX_CPU_NR)
			return 0;
	}
	hist = &hists[cpu];
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	if (targ_per_cpu)
		hist->slots[slot]++;
	else
		__sync_fetch_and_add(&hist->slots[slot], 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
