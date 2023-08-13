#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

SEC("ksyscall/unlinkat")
int BPF_KSYSCALL(unlinkat_entry, int fd, const char *pathname, int flag)
{
	char comm[TASK_COMM_LEN];
	__u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
	
	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk( "PID %d (%s) unlinkat syscall called with fd[%d], pathname[%s] and flag[%d].",
		caller_pid, comm, fd, pathname, flag);
	return 0;
}

SEC("kretsyscall/unlinkat")
int BPF_KRETPROBE(unlinkat_return, int ret)
{
	char comm[TASK_COMM_LEN];
	__u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("PID %d (%s) unlinkat syscall return called  with ret[%d].", caller_pid, comm, ret);
	return 0;
}

char _license[] SEC("license") = "GPL";
