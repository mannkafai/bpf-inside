// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include "xdp.skel.h"

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
	DECLARE_LIBBPF_OPTS(bpf_xdp_attach_opts, xdp_opts);
	struct xdp_bpf *skel;
	int prog_fd;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = xdp_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	prog_fd = bpf_program__fd(skel->progs.xdp_pass);
	err = bpf_xdp_attach(LO_IFINDEX, prog_fd, 0, &xdp_opts);
	if (err) {
		fprintf(stderr, "Failed to attach xdp: %d\n", err);
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

	err = bpf_xdp_detach(LO_IFINDEX, 0, &xdp_opts);
	if (err) {
		fprintf(stderr, "Failed to detach xdp: %d\n", err);
		goto cleanup;
	}

cleanup:
	xdp_bpf__destroy(skel);
	return -err;
}
