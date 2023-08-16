#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

const __u32 blockme = 0x01010101; // 1.1.1.1

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    // Satisfying "cannot override a denial" rule
    if (ret != 0)
        return ret;

    // Only IPv4 in this example
    if (address->sa_family != AF_INET)
        return 0;

    // Cast the address to an IPv4 socket address
    struct sockaddr_in *addr = (struct sockaddr_in *)address;

    // Where do you want to go?
    __u32 dest = addr->sin_addr.s_addr;
    bpf_printk("lsm: found connect to %08x", dest);

    if (dest == blockme)
    {
        bpf_printk("lsm: blocking %08x", dest);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/sk_free_security")
void BPF_PROG(sk_free_security, struct socket *sock)
{
    // do nothing
}
