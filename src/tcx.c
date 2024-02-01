// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include "tcx.skel.h"

#define LO_IFINDEX 3

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_tcx_opts, optl);
	struct tcx_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = tcx_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	skel->links.tc_ingress = bpf_program__attach_tcx(skel->progs.tc_ingress, LO_IFINDEX, &optl);
	if ((err = libbpf_get_error(skel->links.tc_ingress)) != 0)
	{
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	tcx_bpf__destroy(skel);
	return -err;
}
