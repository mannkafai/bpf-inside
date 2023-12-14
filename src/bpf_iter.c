// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpf_iter.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void do_dummy_read_opts(struct bpf_program *prog, struct bpf_iter_attach_opts *opts)
{
    char buf[256] = {};
    int iter_fd, len;
    struct bpf_link *link;

    link = bpf_program__attach_iter(prog, opts);
    if (link == NULL)
    {
        fprintf(stderr, "failed to attach_iter,%m\n");
        return;
    }
    iter_fd = bpf_iter_create(bpf_link__fd(link));
    if (iter_fd < 0)
    {
        fprintf(stderr, "failed to create_iter,%m\n");
        goto free_link;
    }
    /* not check contents, but ensure read() ends without error */
    while ((len = read(iter_fd, buf, sizeof(buf) - 1)) > 0)
    {
        buf[len] = 0;
        fprintf(stderr, "%s", buf);
    }
    printf("\n");

    close(iter_fd);

free_link:
    bpf_link__destroy(link);
}

static void do_dummy_read(struct bpf_program *prog)
{
    do_dummy_read_opts(prog, NULL);
}

int main(int argc, char **argv)
{
    struct bpf_iter_bpf *skel;
    LIBBPF_OPTS(bpf_iter_attach_opts, opts);
    union bpf_iter_link_info linfo;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open load and verify BPF application */
    skel = bpf_iter_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    printf("PID %d\n", getpid());

    memset(&linfo, 0, sizeof(linfo));
    linfo.task.tid = getpid();
    opts.link_info = &linfo;
    opts.link_info_len = sizeof(linfo);
    do_dummy_read_opts(skel->progs.dump_task_stack, &opts);
    // do_dummy_read(skel->progs.dump_task_stack);
    // do_dummy_read(skel->links.get_task_user_stacks);
    do_dummy_read(skel->progs.dump_bpf_map);

cleanup:
    bpf_iter_bpf__destroy(skel);
    return -err;
}
