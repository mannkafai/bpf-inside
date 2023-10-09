#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "iptables_test.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, uint32_t);
    __type(value, struct stats);
} cookie_stats SEC(".maps");

SEC("socket")
int iptables_accepted(struct __sk_buff *skb)
{
    uint32_t cookie = bpf_get_socket_cookie(skb);
    struct stats *rst = bpf_map_lookup_elem(&cookie_stats, &cookie);
    if (rst == NULL)
    {
        struct stats stat;
        stat.uid = bpf_get_socket_uid(skb);
        stat._res = 0;
        stat.packets = 1;
        stat.bytes = skb->len;
        bpf_map_update_elem(&cookie_stats, &cookie, &stat, BPF_ANY);
    }
    else
    {
        rst->uid = bpf_get_socket_uid(skb);
        rst->packets += 1;
        rst->bytes += skb->len;
    }
    return 0;
}
