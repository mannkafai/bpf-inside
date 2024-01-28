// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe_multi.skel.h"

#define ASSERT_EQ(actual, expected, name) ({                      \
	typeof(actual) ___act = (actual);                             \
	typeof(expected) ___exp = (expected);                         \
	bool ___ok = ___act == ___exp;                                \
	if (!___ok)                                                   \
		printf("unexpected %s: actual %lld != expected %lld\n",   \
			   (name), (long long)(___act), (long long)(___exp)); \
	___ok;                                                        \
})

#define ASSERT_OK_PTR(ptr, name) ({        \
	const void *___res = (ptr);            \
	int ___err = libbpf_get_error(___res); \
	bool ___ok = ___err == 0;              \
	if (!___ok)                            \
		printf("%s\n", name);              \
	___ok;                                 \
})

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

struct child
{
	int go[2];
	int pid;
};

static char test_data[] = "test_data";
void uprobe_multi_func_1(void)
{
	asm volatile("");
}

void uprobe_multi_func_2(void)
{
	asm volatile("");
}

void uprobe_multi_func_3(void)
{
	asm volatile("");
}

static void uprobe_multi_test_run(struct uprobe_multi_bpf *skel, struct child *child)
{
	skel->bss->uprobe_multi_func_1_addr = (__u64)uprobe_multi_func_1;
	skel->bss->uprobe_multi_func_2_addr = (__u64)uprobe_multi_func_2;
	skel->bss->uprobe_multi_func_3_addr = (__u64)uprobe_multi_func_3;

	skel->bss->user_ptr = test_data;

	/*
	 * Disable pid check in bpf program if we are pid filter test,
	 * because the probe should be executed only by child->pid
	 * passed at the probe attach.
	 */
	skel->bss->pid = child ? 0 : getpid();

	/* trigger all probes */
	uprobe_multi_func_1();
	uprobe_multi_func_2();
	uprobe_multi_func_3();

	/*
	 * There are 2 entry and 2 exit probe called for each uprobe_multi_func_[123]
	 * function and each slepable probe (6) increments uprobe_multi_sleep_result.
	 */
	ASSERT_EQ(skel->bss->uprobe_multi_func_1_result, 2, "uprobe_multi_func_1_result");
	ASSERT_EQ(skel->bss->uprobe_multi_func_2_result, 2, "uprobe_multi_func_2_result");
	ASSERT_EQ(skel->bss->uprobe_multi_func_3_result, 2, "uprobe_multi_func_3_result");

	ASSERT_EQ(skel->bss->uretprobe_multi_func_1_result, 2, "uretprobe_multi_func_1_result");
	ASSERT_EQ(skel->bss->uretprobe_multi_func_2_result, 2, "uretprobe_multi_func_2_result");
	ASSERT_EQ(skel->bss->uretprobe_multi_func_3_result, 2, "uretprobe_multi_func_3_result");

	ASSERT_EQ(skel->bss->uprobe_multi_sleep_result, 6, "uprobe_multi_sleep_result");
}

static void
test_attach_api(const char *binary, const char *pattern, struct bpf_uprobe_multi_opts *opts,
				struct child *child)
{
	pid_t pid = child ? child->pid : -1;
	struct uprobe_multi_bpf *skel = NULL;

	skel = uprobe_multi_bpf__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi_bpf__open_and_load"))
		goto cleanup;

	opts->retprobe = false;
	skel->links.uprobe = bpf_program__attach_uprobe_multi(skel->progs.uprobe, pid,
														  binary, pattern, opts);
	if (!ASSERT_OK_PTR(skel->links.uprobe, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	opts->retprobe = true;
	skel->links.uretprobe = bpf_program__attach_uprobe_multi(skel->progs.uretprobe, pid,
															 binary, pattern, opts);
	if (!ASSERT_OK_PTR(skel->links.uretprobe, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	opts->retprobe = false;
	skel->links.uprobe_sleep = bpf_program__attach_uprobe_multi(skel->progs.uprobe_sleep, pid,
																binary, pattern, opts);
	if (!ASSERT_OK_PTR(skel->links.uprobe_sleep, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	opts->retprobe = true;
	skel->links.uretprobe_sleep = bpf_program__attach_uprobe_multi(skel->progs.uretprobe_sleep,
																   pid, binary, pattern, opts);
	if (!ASSERT_OK_PTR(skel->links.uretprobe_sleep, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	opts->retprobe = false;
	skel->links.uprobe_extra = bpf_program__attach_uprobe_multi(skel->progs.uprobe_extra, -1,
																binary, pattern, opts);
	if (!ASSERT_OK_PTR(skel->links.uprobe_extra, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	uprobe_multi_test_run(skel, child);

cleanup:
	uprobe_multi_bpf__destroy(skel);
}

int main(int argc, char **argv)
{
	libbpf_set_print(libbpf_print_fn);
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts);
	const char *syms[3] = {
		"uprobe_multi_func_1",
		"uprobe_multi_func_2",
		"uprobe_multi_func_3",
	};

	opts.syms = syms;
	opts.cnt = ARRAY_SIZE(syms);
	test_attach_api("/proc/self/exe", NULL, &opts, NULL);
	return 0;
}
