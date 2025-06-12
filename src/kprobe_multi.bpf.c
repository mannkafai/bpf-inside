// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe.multi/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	pid_t pid;
	const char *filename;
	pid = bpf_get_current_pid_tgid() >> 32;
	filename = BPF_CORE_READ(name, name);
	bpf_printk("KPROBE.MULTI ENTRY pid = %d, filename = %s\n", pid, filename);
	return 0;
}

SEC("kretprobe.multi/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE.MULTI EXIT: pid = %d, ret = %ld\n", pid, ret);
	return 0;
}

SEC("kprobe.session/do_unlinkat")
int BPF_KPROBE(session_unlinkat, int dfd, struct filename *name)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	const char *filename = BPF_CORE_READ(name, name);
	bool is_return = bpf_session_is_return();
	bpf_printk("KPROBE.SESSION %s pid = %d, filename = %s\n", is_return ? "EXIT" : "ENTRY",  pid, filename);
	return 0;
}