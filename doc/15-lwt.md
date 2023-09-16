# LWT的内核实现

## 0 前言

在前面几篇文章中，我们分析网络数据包在L2的处理过程(XDP、taps、classify), 接下来进入内核协议栈中进行L3处理，L3在确定输入/输出路由后进行后续处理。今天我们借助`test_lwt_bpf`示例程序分析使用BPF建立轻量级隧道的实现过程。

## 1 简介

轻量级隧道（Lightweight Tunnel）是一种用于在网络中传输数据的技术，在不同的网络之间创建一个虚拟的通道，使得数据可以在这个通道上安全、可靠的传输。轻量级隧道适用于多种应用场景，可以用于连接不同地理位置的局域网（LAN）或广域网（WAN），使得远程办公和远程访问变得更加方便和安全，或者用于在云计算环境中连接不同的数据中心或虚拟机，实现跨网络的互联。

## 2 `test_lwt_bpf`示例程序

### 2.1 BPF程序

BPF程序源码参见[test_lwt_bpf.c](../src/test_lwt_bpf.c)，主要内容如下：

```C
SEC("test_ctx")
int do_test_ctx(struct __sk_buff *skb)
{
    skb->cb[0] = CB_MAGIC;
    printk("len %d hash %d protocol %d", skb->len, skb->hash, skb->protocol);
    printk("cb %d ingress_ifindex %d ifindex %d", skb->cb[0], skb->ingress_ifindex, skb->ifindex);
    return BPF_OK;
}
...
```

该程序包含多个BPF程序，使用自定义的前缀，参数为`__sk_buff`类型。

### 2.3 用户程序

和之前的用户程序不同，`test_lwt_bpf`程序通过脚本测试的，[test_lwt_bpf.sh](../src/test_lwt_bpf.sh)主要内容如下：

#### 1 附加BPF程序

```bash
# 创建测试需要的网络环境
function setup_one_veth {
	ip netns add $1
	ip link add $2 type veth peer name $3
	ip link set dev $2 up
	ip addr add $4/24 dev $2
	ip link set $3 netns $1
	ip netns exec $1 ip link set dev $3 up
	ip netns exec $1 ip addr add $5/24 dev $3
	if [ "$6" ]; then
		ip netns exec $1 ip addr add $6/32 dev $3
	fi
}
# 附加测试程序
function install_test {
	cleanup_routes
	cp /dev/null ${TRACE_ROOT}/trace

	OPTS="encap bpf headroom 14 $1 obj $BPF_PROG section $2 $VERBOSE"

	if [ "$1" == "in" ];  then
		ip route add table local local ${IP_LOCAL}/32 $OPTS dev lo
	else
		ip route add ${IPVETH1}/32 $OPTS dev $VETH0
	fi
}
# ctx_xmit测试程序
function test_ctx_xmit {
	test_start "test_ctx on lwt xmit"
	install_test xmit test_ctx
	ping -c 3 $IPVETH1 || {
		failure "test_ctx xmit: packets are dropped"
	}
	match_trace "$(get_trace)" "
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 0 ifindex $DST_IFINDEX
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 0 ifindex $DST_IFINDEX
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 0 ifindex $DST_IFINDEX" || exit 1
	remove_prog xmit
}
```

#### 2 读取数据过程

BPF程序通过 `bpf_printk` 输出到 `/sys/kernel/debug/tracing/trace_pipe` 文件中。`test_lwt_bpf.sh` 脚本通过`get_trace`函数读取该文件内容后，`match_trace` 函数比较测试结果。

### 2.3 编译运行

在命令终端中运行`test_lwt_bpf.sh`脚本文件，如下：

```bash
$ sudo ./test_lwt_bpf.sh 
+ setup_one_veth lwt_ns1 tst_lwt1a tst_lwt1b 192.168.254.1 192.168.254.2 192.168.254.3
+ ip netns add lwt_ns1
...
----------------------------------------------------------------
Starting test: test_ctx on lwt xmit
----------------------------------------------------------------
+ install_test xmit test_ctx
...
+ ip route add 192.168.254.2/32 encap bpf headroom 14 xmit obj test_lwt_bpf.o section test_ctx dev tst_lwt1a
+ ping -c 3 192.168.254.2
PING 192.168.254.2 (192.168.254.2) 56(84) bytes of data.
64 bytes from 192.168.254.2: icmp_seq=1 ttl=64 time=0.067 ms
64 bytes from 192.168.254.2: icmp_seq=2 ttl=64 time=0.096 ms
64 bytes from 192.168.254.2: icmp_seq=3 ttl=64 time=0.074 ms

--- 192.168.254.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2042ms
rtt min/avg/max/mdev = 0.067/0.079/0.096/0.012 ms
++ get_trace
++ set +x
+ match_trace 'bpf_trace_printk: len 84 hash 0 protocol 8
bpf_trace_printk: cb 1234 ingress_ifindex 0 ifindex 84
...
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 0 ifindex 84'
...
+ remove_prog xmit
+ ip route del 192.168.254.2/32 dev tst_lwt1a
...
```

## 3 附加BPF的过程

`test_lwt_bpf.bpf.c`文件中BPF程序的SEC名称为自定义名称。在libbpf中的有关`lwt`的前缀如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("lwt_in", LWT_IN, 0, SEC_NONE),
    SEC_DEF("lwt_out", LWT_OUT, 0, SEC_NONE),
    SEC_DEF("lwt_xmit", LWT_XMIT, 0, SEC_NONE),
    SEC_DEF("lwt_seg6local", LWT_SEG6LOCAL, 0, SEC_NONE),
    ...
};
```

`lwt` 前缀不支持自动附加，需要通过手动方式附加。`test_lwt_bpf.sh`通过`ip`命令添加路由信息，在路由信息中设置路由隧道封装，如下：

```bash
ip route add 192.168.254.2/32 encap bpf headroom 14 xmit obj test_lwt_bpf.o section test_ctx dev tst_lwt1a
```

在测试完成后，通过`ip`命令删除路由信息，如下：

```bash
ip route del 192.168.254.2/32 dev tst_lwt1a
```

## 4 内核实现--ipv4

### 4.1 ipv4添加路由

#### (1) `netlink`接口

`ip route add` 命令向Linux内核中添加一条路由信息，对应 `PF_INET:RTM_NEWROUTE` 类型的netlink接口，在内核中处理如下：

```C
// file: net/ipv4/fib_frontend.c
void __init ip_fib_init(void)
{
    ...
    rtnl_register(PF_INET, RTM_NEWROUTE, inet_rtm_newroute, NULL, 0);
    rtnl_register(PF_INET, RTM_DELROUTE, inet_rtm_delroute, NULL, 0);
    rtnl_register(PF_INET, RTM_GETROUTE, NULL, inet_dump_fib, 0);
}
```

在`fs_initcall(inet_init)`阶段初始化ipv4网络协议栈过程中进行初始化，如下：

```C
// file: net/ipv4/af_inet.c
static int __init inet_init(void)
    --> ip_init();
        --> ip_rt_init();
            --> ip_fib_init();
```

`inet_rtm_newroute` 函数解析netlink请求信息后，添加到路由表中，如下：

```C
// file: net/ipv4/fib_frontend.c
static int inet_rtm_newroute(struct sk_buff *skb, struct nlmsghdr *nlh, struct netlink_ext_ack *extack)
{
    struct net *net = sock_net(skb->sk);
    struct fib_config cfg;
    struct fib_table *tb;
    int err;

    // 解析netlink请求，转换为`fib_config`配置信息, 解析`RTA_ENCAP`和`RTA_ENCAP_TYPE`字段信息
    err = rtm_to_fib_config(net, skb, nlh, &cfg, extack);
    if (err < 0) goto errout;

    // 获取ipv4路由表，默认为`RT_TABLE_MAIN`
    tb = fib_new_table(net, cfg.fc_table);
    if (!tb) { ... }

    // 向路由表中插入路由配置
    err = fib_table_insert(net, tb, &cfg, extack);
    // 本地路由时，设置自定义路由规则
    if (!err && cfg.fc_type == RTN_LOCAL)
        net->ipv4.fib_has_custom_local_routes = true;
errout:
    return err;
}
```

#### (2) 获取路由表

`fib_new_table` 函数获取路由表配置信息，如下：

```C
// file: net/ipv4/fib_trie.c
struct fib_table *fib_new_table(struct net *net, u32 id)
{
    struct fib_table *tb, *alias = NULL;
    unsigned int h;

    // 默认主路由表(MAIN)
    if (id == 0) id = RT_TABLE_MAIN;
    // 从`ipv4.fib_table_hash`中获取对应id的路由
    tb = fib_get_table(net, id);
    if (tb) return tb;

    // 本地路由(LOCAL)时，转换为主路由(MAIN)
    if (id == RT_TABLE_LOCAL && !net->ipv4.fib_has_custom_rules)
        alias = fib_new_table(net, RT_TABLE_MAIN);

    // 创建新的路由表
    tb = fib_trie_table(id, alias);
    if (!tb) return NULL;

    // 主路由和默认路由设置
    switch (id) {
    case RT_TABLE_MAIN: rcu_assign_pointer(net->ipv4.fib_main, tb); break;
    case RT_TABLE_DEFAULT: rcu_assign_pointer(net->ipv4.fib_default, tb); break;
    default: break; }

    // 添加到`ipv4.fib_table_hash`中
    h = id & (FIB_TABLE_HASHSZ - 1);
    hlist_add_head_rcu(&tb->tb_hlist, &net->ipv4.fib_table_hash[h]);
    return tb;
}
```

#### (3) 添加路由信息

`fib_table_insert` 函数创建路由信息后，更新到路由表中。路由表以目标地址(dst)作为key的基树(trie)实现，存在路由相同路由时进行替换，不存在时添加。我们不关心具体路由表的实现细节，只关注创建路由部分，如下：

```C
// file: net/ipv4/fib_trie.c
int fib_table_insert(struct net *net, struct fib_table *tb, struct fib_config *cfg, struct netlink_ext_ack *extack)
{
    struct trie *t = (struct trie *)tb->tb_data;
    struct fib_alias *fa, *new_fa;
    struct key_vector *l, *tp;
    u16 nlflags = NLM_F_EXCL;
    struct fib_info *fi;
    u8 plen = cfg->fc_dst_len;
    u8 slen = KEYLENGTH - plen;
    dscp_t dscp;
    u32 key;
    int err;

    // 目标地址作为key
    key = ntohl(cfg->fc_dst);
    // 验证key长度是否正确
    if (!fib_valid_key_len(key, plen, extack)) return -EINVAL;

    // 创建路由信息
    fi = fib_create_info(cfg, extack);
    if (IS_ERR(fi)) { ... }

    // 获取dst对应的节点和匹配的前缀的路由别名
    dscp = cfg->fc_dscp;
    l = fib_find_node(t, &tp, key);
    fa = l ? fib_find_alias(&l->leaf, slen, dscp, fi->fib_priority, tb->tb_id, false) : NULL;

    // fa存在，表示具有相同[前缀,dscp,优先级]的fib别名，存在精确匹配的路由时进行替换
    if (fa && fa->fa_dscp == dscp && fa->fa_info->fib_priority == fi->fib_priority) { ... }

    err = -ENOENT;
    // 路由不存在时，必须设置`NLM_F_CREATE`标记
    if (!(cfg->fc_nlflags & NLM_F_CREATE)) goto out;
    nlflags |= NLM_F_CREATE;
    err = -ENOBUFS;

    // 创建和设置路由别名(fa)
    new_fa = kmem_cache_alloc(fn_alias_kmem, GFP_KERNEL);
    if (!new_fa) goto out;
    new_fa->fa_info = fi;
    new_fa->fa_dscp = dscp;
    new_fa->fa_type = cfg->fc_type;
    new_fa->fa_state = 0;
    new_fa->fa_slen = slen;
    new_fa->tb_id = tb->tb_id;
    new_fa->fa_default = -1;
    new_fa->offload = 0;
    new_fa->trap = 0;
    new_fa->offload_failed = 0;

    // 插入新的路由到列表中
    err = fib_insert_alias(t, tp, l, new_fa, fa, key);
    if (err) goto out_free_new_fa;
    // 确定路由信息插入成功
    l = l ? l : fib_find_node(t, &tp, key);
    if (WARN_ON_ONCE(!l)) { ...  }

    // 路由更新成功后，通知路由变化
    if (fib_find_alias(&l->leaf, new_fa->fa_slen, 0, 0, tb->tb_id, true) == new_fa) {
        enum fib_event_type fib_event;
        fib_event = FIB_EVENT_ENTRY_REPLACE;
        // 路由更新通知链
        err = call_fib_entry_notifiers(net, fib_event, key, plen, new_fa, extack);
        if (err) goto out_remove_new_fa;
    }
    if (!plen) tb->tb_num_default++;
    // 刷新路由缓存
    rt_cache_flush(cfg->fc_nlinfo.nl_net);
    // netlink通知路由变化
    rtmsg_fib(RTM_NEWROUTE, htonl(key), new_fa, plen, new_fa->tb_id, &cfg->fc_nlinfo, nlflags);
succeeded:
    return 0;
    ....
}
```

`fib_create_info` 函数根据配置创建新的路由信息，如下：

```C
// file: net/ipv4/fib_semantics.c
struct fib_info *fib_create_info(struct fib_config *cfg, struct netlink_ext_ack *extack)
{
    int err;
    struct fib_info *fi = NULL;
    struct nexthop *nh = NULL;
    struct fib_info *ofi;
    int nhs = 1;
    struct net *net = cfg->fc_nlinfo.nl_net;

    if (cfg->fc_type > RTN_MAX) goto err_inval;
    // scope和flags检查 
    if (fib_props[cfg->fc_type].scope > cfg->fc_scope) { ... }
    if (cfg->fc_flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN)) { ... }

    // 下一跳路由获取
    if (cfg->fc_nh_id) {
        if (!cfg->fc_mx) {
            // 没有指标信息，只有下一跳(nexthop)时，直接获取
            fi = fib_find_info_nh(net, cfg);
            if (fi) { refcount_inc(&fi->fib_treeref); return fi; }
        }
        // 获取下一跳(nexthop)路由信息
        nh = nexthop_find_by_id(net, cfg->fc_nh_id);
        if (!nh) { ... }
        nhs = 0;
    }
#ifdef CONFIG_IP_ROUTE_MULTIPATH
    if (cfg->fc_mp) {
        // 多路径路由存在时，获取nexthop数量
        nhs = fib_count_nexthops(cfg->fc_mp, cfg->fc_mp_len, extack);
        if (nhs == 0) goto err_inval;
    }
#endif

    err = -ENOBUFS;
    // 路由信息空间不足时，扩展内存空间
    if (READ_ONCE(fib_info_cnt) >= fib_info_hash_size) { ... }
    // 创建路由信息
    fi = kzalloc(struct_size(fi, fib_nh, nhs), GFP_KERNEL);
    if (!fi) goto failure;
    // 初始化路由指标信息，如：MTU、RTT、HOPLIMIT等信息。指标信息不存在时，使用默认指标信息
    fi->fib_metrics = ip_fib_metrics_init(fi->fib_net, cfg->fc_mx, cfg->fc_mx_len, extack);
    if (IS_ERR(fi->fib_metrics)) { ... }
    // 路由信息设置
    fi->fib_net = net;
    fi->fib_protocol = cfg->fc_protocol;
    fi->fib_scope = cfg->fc_scope;
    fi->fib_flags = cfg->fc_flags;
    fi->fib_priority = cfg->fc_priority;
    fi->fib_prefsrc = cfg->fc_prefsrc;
    fi->fib_type = cfg->fc_type;
    fi->fib_tb_id = cfg->fc_table;
    fi->fib_nhs = nhs;

    if (nh) {
        // nexthop存在时，检查并设置nexthop
        if (!nexthop_get(nh)) { err = -EINVAL; } 
        else { err = 0; fi->nh = nh; }
    } else {
        // 设置nexthop的父路由
        change_nexthops(fi) {
            nexthop_nh->nh_parent = fi;
        } endfor_nexthops(fi)
        if (cfg->fc_mp)
            // 多路径路由初始化
            err = fib_get_nhs(fi, cfg->fc_mp, cfg->fc_mp_len, cfg, extack);
        else
            // 下一跳路由初始化
            err = fib_nh_init(net, fi->fib_nh, cfg, 1, extack);
    }
    if (err != 0) goto failure;

    // 路由类型检查
    if (fib_props[cfg->fc_type].error) {
        // 网关、设备、多路径路由不能指定路由类型
        if (cfg->fc_gw_family || cfg->fc_oif || cfg->fc_mp) { goto err_inval; }
        goto link_it;
    } else {
        switch (cfg->fc_type) {
        case RTN_UNICAST: case RTN_LOCAL: case RTN_BROADCAST:
        case RTN_ANYCAST: case RTN_MULTICAST: break;
        default:
            // 其他类型无效
            goto err_inval;
        }
    }
    // 路由范围(scope)检查
    if (cfg->fc_scope > RT_SCOPE_HOST) { goto err_inval; }

    if (fi->nh) {
        // nexthop检查，检查scope范围
        err = fib_check_nexthop(fi->nh, cfg->fc_scope, extack);
        if (err) goto failure;
    } else if (cfg->fc_scope == RT_SCOPE_HOST) {
        // 主机范围内路由设置
        struct fib_nh *nh = fi->fib_nh;
        // 本地地址和网关地址无效
        if (nhs != 1) { goto err_inval; }
        if (nh->fib_nh_gw_family) { goto err_inval; }
        // 下一跳路由信息设置
        nh->fib_nh_scope = RT_SCOPE_NOWHERE;
        nh->fib_nh_dev = dev_get_by_index(net, nh->fib_nh_oif);
        err = -ENODEV;
        if (!nh->fib_nh_dev) goto failure;
        netdev_tracker_alloc(nh->fib_nh_dev, &nh->fib_nh_dev_tracker, GFP_KERNEL);
    } else {
        // 其他范围设置
        int linkdown = 0;
        change_nexthops(fi) {
            // 下一跳路由信息检查
            err = fib_check_nh(cfg->fc_nlinfo.nl_net, nexthop_nh, cfg->fc_table, cfg->fc_scope, extack);
            if (err != 0) goto failure;
            if (nexthop_nh->fib_nh_flags & RTNH_F_LINKDOWN) linkdown++;
        } endfor_nexthops(fi)

        if (linkdown == fi->fib_nhs)
            fi->fib_flags |= RTNH_F_LINKDOWN;
    }
    // 指定源地址时，检查源地址是否有效
    if (fi->fib_prefsrc && !fib_valid_prefsrc(cfg, fi->fib_prefsrc)) { goto err_inval; }

    if (!fi->nh) {
        change_nexthops(fi) {
            // 更新下一跳路由的的源地址
            fib_info_update_nhc_saddr(net, &nexthop_nh->nh_common, fi->fib_scope);
            if (nexthop_nh->fib_nh_gw_family == AF_INET6)
                fi->fib_nh_is_v6 = true;
        } endfor_nexthops(fi)
        // 更新下一跳路由权重
        fib_rebalance(fi);
    }

link_it:
    // 存在同样的路由时，释放创建的路由
    ofi = fib_find_info(fi);
    if (ofi) {
        fi->fib_dead = 1;
        free_fib_info(fi);
        refcount_inc(&ofi->fib_treeref);
        return ofi;
    }
    // 更新路由信息后，添加到路由信息(`fib_info_hash`)中
    refcount_set(&fi->fib_treeref, 1);
    refcount_set(&fi->fib_clntref, 1);
    spin_lock_bh(&fib_info_lock);
    fib_info_cnt++;
    hlist_add_head(&fi->fib_hash, &fib_info_hash[fib_info_hashfn(fi)]);

    if (fi->fib_prefsrc) {
        // 指定源地址时，添加到指定源地址路由信息(`fib_info_laddrhash`)中
        struct hlist_head *head;
        head = fib_info_laddrhash_bucket(net, fi->fib_prefsrc);
        hlist_add_head(&fi->fib_lhash, head);
    }
    if (fi->nh) {
        // nexthop存在时，添加到nexthop路由列表中
        list_add(&fi->nh_list, &nh->fi_list);
    } else {
        change_nexthops(fi) {
            struct hlist_head *head;
            if (!nexthop_nh->fib_nh_dev) continue;
            // 下一跳路由设备存在时，添加到路由设备(`fib_info_devhash`)中
            head = fib_info_devhash_bucket(nexthop_nh->fib_nh_dev);
            hlist_add_head(&nexthop_nh->nh_hash, head);
        } endfor_nexthops(fi)
    }
    spin_unlock_bh(&fib_info_lock);
    return fi;
    ...
}
```

`fib_nh_init` 函数初始化下一跳路由信息，如下：

```C
// file: net/ipv4/fib_semantics.c
int fib_nh_init(struct net *net, struct fib_nh *nh, struct fib_config *cfg, int nh_weight, 
        struct netlink_ext_ack *extack)
{
    int err;
    nh->fib_nh_family = AF_INET;
    // 初始化下一跳路由常用信息
    err = fib_nh_common_init(net, &nh->nh_common, cfg->fc_encap, cfg->fc_encap_type, cfg, GFP_KERNEL, extack);
    if (err) return err;

    // 下一跳路由的网卡、网关、flags设置
    nh->fib_nh_oif = cfg->fc_oif;
    nh->fib_nh_gw_family = cfg->fc_gw_family;
    if (cfg->fc_gw_family == AF_INET)
        nh->fib_nh_gw4 = cfg->fc_gw4;
    else if (cfg->fc_gw_family == AF_INET6)
        nh->fib_nh_gw6 = cfg->fc_gw6;
    nh->fib_nh_flags = cfg->fc_flags;

    // 路由classid设置
    nh->nh_tclassid = cfg->fc_flow;
    if (nh->nh_tclassid)
        atomic_inc(&net->ipv4.fib_num_tclassid_users);
    // 路由权重设置
    nh->fib_nh_weight = nh_weight;
    return 0;
}
```

`fib_nh_common_init`函数初始化下一跳路由常用信息，动态分配per-cpu路由表，设置轻量级路由隧道封装，如下：

```C
// file: net/ipv4/fib_semantics.c
int fib_nh_common_init(struct net *net, struct fib_nh_common *nhc, struct nlattr *encap, 
        u16 encap_type, void *cfg, gfp_t gfp_flags, struct netlink_ext_ack *extack)
{
    int err;
    // 动态分配per-CPU路由表
    nhc->nhc_pcpu_rth_output = alloc_percpu_gfp(struct rtable __rcu *, gfp_flags);
    if (!nhc->nhc_pcpu_rth_output) return -ENOMEM;

    if (encap) {
        // 设置路由封装
        struct lwtunnel_state *lwtstate;
        if (encap_type == LWTUNNEL_ENCAP_NONE) { ... }
        // 构建路由封装信息
        err = lwtunnel_build_state(net, encap_type, encap, nhc->nhc_family, cfg, &lwtstate, extack);
        if (err) goto lwt_failure;
        // 设置路由封装状态
        nhc->nhc_lwtstate = lwtstate_get(lwtstate);
    }
    return 0;

lwt_failure:
    rt_fibinfo_free_cpus(nhc->nhc_pcpu_rth_output);
    nhc->nhc_pcpu_rth_output = NULL;
    return err;
}
```

#### (4) 设置路由封装接口

`lwtunnel_build_state` 函数设置路由封装信息，获取封装类型后生成封装状态，如下：

```C
// file：net/core/lwtunnel.c
int lwtunnel_build_state(struct net *net, u16 encap_type, struct nlattr *encap, unsigned int family,
        const void *cfg, struct lwtunnel_state **lws, struct netlink_ext_ack *extack)
{
    const struct lwtunnel_encap_ops *ops;
    bool found = false;
    int ret = -EINVAL;

    // 检查封装类型
    if (encap_type == LWTUNNEL_ENCAP_NONE || encap_type > LWTUNNEL_ENCAP_MAX) { ... }

    ret = -EOPNOTSUPP;
    rcu_read_lock();
    // 获取封装类型的操作接口
    ops = rcu_dereference(lwtun_encaps[encap_type]);
    if (likely(ops && ops->build_state && try_module_get(ops->owner)))
        found = true;
    rcu_read_unlock();

    if (found) {
        // 生成封装信息
        ret = ops->build_state(net, encap, family, cfg, lws, extack);
        if (ret) module_put(ops->owner);
    } else {
        // netlink错误信息设置
        NL_SET_ERR_MSG_ATTR(extack, encap, "LWT encapsulation type not supported");
    }
    return ret;
}
```

### 4.2 ipv4删除路由

#### (1) `netlink`接口

`ip route del`命令从Linux内核中删除一条路由信息，对应 `PF_INET:RTM_DELROUTE` 类型的netlink接口，在内核中对应`inet_rtm_delroute`处理，如下：

```C
// file: net/ipv4/fib_frontend.c
static int inet_rtm_delroute(struct sk_buff *skb, struct nlmsghdr *nlh, struct netlink_ext_ack *extack)
{
    struct net *net = sock_net(skb->sk);
    struct fib_config cfg;
    struct fib_table *tb;
    int err;

    // 解析netlink请求，转换为`fib_config`配置信息
    err = rtm_to_fib_config(net, skb, nlh, &cfg, extack);
    if (err < 0) goto errout;

    // 设置nh_id时，确保nexthop存在
    if (cfg.fc_nh_id && !nexthop_find_by_id(net, cfg.fc_nh_id)) { ... }
    // 获取设置的路由表表
    tb = fib_get_table(net, cfg.fc_table);
    if (!tb) { ... }
    // 从路由表中删除路由配置信息
    err = fib_table_delete(net, tb, &cfg, extack);
errout:
    return err;
}
```

#### (2) 删除路由信息

`fib_table_delete` 函数删除路由配置信息，如下：

```C
// file: net/ipv4/fib_trie.c
int fib_table_delete(struct net *net, struct fib_table *tb, struct fib_config *cfg, struct netlink_ext_ack *extack)
{
    struct trie *t = (struct trie *) tb->tb_data;
    struct fib_alias *fa, *fa_to_delete;
    struct key_vector *l, *tp;
    u8 plen = cfg->fc_dst_len;
    u8 slen = KEYLENGTH - plen;
    dscp_t dscp;
    u32 key;

    key = ntohl(cfg->fc_dst);
    // 验证key长度是否正确
    if (!fib_valid_key_len(key, plen, extack)) return -EINVAL;

    // 获取路由节点
    l = fib_find_node(t, &tp, key);
    if (!l) return -ESRCH;

    // 获取路由前缀节点
    dscp = cfg->fc_dscp;
    fa = fib_find_alias(&l->leaf, slen, dscp, 0, tb->tb_id, false);
    if (!fa) return -ESRCH;

    fa_to_delete = NULL;
    hlist_for_each_entry_from(fa, fa_list) {
        struct fib_info *fi = fa->fa_info;
        // 路由不配时，退出查找
        if ((fa->fa_slen != slen) || (fa->tb_id != tb->tb_id) || (fa->fa_dscp != dscp))
            break;
        if ((!cfg->fc_type || fa->fa_type == cfg->fc_type) &&
            (cfg->fc_scope == RT_SCOPE_NOWHERE || fa->fa_info->fib_scope == cfg->fc_scope) &&
            (!cfg->fc_prefsrc || fi->fib_prefsrc == cfg->fc_prefsrc) &&
            (!cfg->fc_protocol || fi->fib_protocol == cfg->fc_protocol) &&
            fib_nh_match(net, cfg, fi, extack) == 0 && fib_metrics_match(cfg, fi)) {
            // 路由别名需要精确匹配
            fa_to_delete = fa;
            break;
        }
    }
    // 未找到时，返回错误
    if (!fa_to_delete) return -ESRCH;

    // 检查路由删除，路由更新通知链
    fib_notify_alias_delete(net, key, &l->leaf, fa_to_delete, extack);
    // netlink通知路由变化
    rtmsg_fib(RTM_DELROUTE, htonl(key), fa_to_delete, plen, tb->tb_id, &cfg->fc_nlinfo, 0);

    if (!plen) tb->tb_num_default--;
    // 从路由表中删掉路由别名
    fib_remove_alias(t, tp, l, fa_to_delete);
    // 刷新路由缓存
    if (fa_to_delete->fa_state & FA_S_ACCESSED)
        rt_cache_flush(cfg->fc_nlinfo.nl_net);
    // 释放路由信息和路由别名
    fib_release_info(fa_to_delete->fa_info);
    alias_free_mem_rcu(fa_to_delete);
    return 0;
}
```

`fib_release_info` 函数释放路由信息，如下：

```C
// file: net/ipv4/fib_semantics.c
void fib_release_info(struct fib_info *fi)
{
    spin_lock_bh(&fib_info_lock);
    // 路由使用计数为0时，
    if (fi && refcount_dec_and_test(&fi->fib_treeref)) {
        // 从路由信息(`fib_info_hash`)中移除
        hlist_del(&fi->fib_hash);
        // 更新路由数量
        WRITE_ONCE(fib_info_cnt, fib_info_cnt - 1);
        // 从指定源地址路由信息(`fib_info_laddrhash`)中移除
        if (fi->fib_prefsrc)
            hlist_del(&fi->fib_lhash);

        if (fi->nh) {
            // 从nexthop路由列表中移除
            list_del(&fi->nh_list);
        } else {
            change_nexthops(fi) {
                if (!nexthop_nh->fib_nh_dev) continue;
                // 从路由设备(`fib_info_devhash`)中移除
                hlist_del(&nexthop_nh->nh_hash);
            } endfor_nexthops(fi)
        }
        fi->fib_dead = 1;
        // 释放路由信息
        fib_info_put(fi);
    }
    spin_unlock_bh(&fib_info_lock);
}
```

#### (3) 释放路由信息

`fib_info_put`函数检查路由信息引用计数，为0时释放，如下：

```C
// file: include/net/ip_fib.h
static inline void fib_info_put(struct fib_info *fi)
{
    if (refcount_dec_and_test(&fi->fib_clntref))
        free_fib_info(fi);
}
```

`free_fib_info`函数实现路由信息的释放，如下：

```C
// file: net/ipv4/fib_semantics.c
void free_fib_info(struct fib_info *fi)
{
    // dead标记
    if (fi->fib_dead == 0) { return; }
    call_rcu(&fi->rcu, free_fib_info_rcu);
}
// file: net/ipv4/fib_semantics.c
static void free_fib_info_rcu(struct rcu_head *head)
{
    struct fib_info *fi = container_of(head, struct fib_info, rcu);
    if (fi->nh) {
        // 释放nexthop
        nexthop_put(fi->nh);
    } else {
        change_nexthops(fi) {
            // 释放下一跳路由信息
            fib_nh_release(fi->fib_net, nexthop_nh);
        } endfor_nexthops(fi);
    }
    // 释放指标信息
    ip_fib_metrics_put(fi->fib_metrics);
    kfree(fi);
}
// file: net/ipv4/fib_semantics.c
void fib_nh_release(struct net *net, struct fib_nh *fib_nh)
{
    if (fib_nh->nh_tclassid)
        atomic_dec(&net->ipv4.fib_num_tclassid_users);
    // 释放通用路由信息
    fib_nh_common_release(&fib_nh->nh_common);
}
```

`fib_nh_common_release` 函数释放通用路由信息，如下：

```C
// file: net/ipv4/fib_semantics.c
void fib_nh_common_release(struct fib_nh_common *nhc)
{
    netdev_put(nhc->nhc_dev, &nhc->nhc_dev_tracker);
    // 释放lwt状态信息
    lwtstate_put(nhc->nhc_lwtstate);
    // 释放output路由信息
    rt_fibinfo_free_cpus(nhc->nhc_pcpu_rth_output);
    // 释放input路由信息
    rt_fibinfo_free(&nhc->nhc_rth_input);
    // 释放异常路由信息
    free_nh_exceptions(nhc);
}
```

#### (4) 释放路由封装接口

`lwtstate_put` 函数释放路由封装信息，如下：

```C
// file: include/net/lwtunnel.h
static inline void lwtstate_put(struct lwtunnel_state *lws)
{
    if (!lws) return;
    if (atomic_dec_and_test(&lws->refcnt))
        lwtstate_free(lws);
}
// file: net/core/lwtunnel.c
void lwtstate_free(struct lwtunnel_state *lws)
{
    const struct lwtunnel_encap_ops *ops = lwtun_encaps[lws->type];
    if (ops->destroy_state) {
        ops->destroy_state(lws);
        kfree_rcu(lws, rcu);
    } else {
        kfree(lws);
    }
    module_put(ops->owner);
}
```

### 4.3 路由封装的实现过程(input)

#### (1) L3网络数据接收过程

在[TC的内核实现](./14-tc.md)中，我们分析了TC的实现过程，接下来我们继续后续过程，如下：

```C
// file: net/core/dev.c
static int __netif_receive_skb_core(struct sk_buff **pskb, bool pfmemalloc, struct packet_type **ppt_prev)
{
    ...
    // generic XDP
    // taps/sockfilter
    // classify/TC

skip_classify:
    if (pfmemalloc && !skb_pfmemalloc_protocol(skb)) goto drop;
    // VLAN协议处理
    if (skb_vlan_tag_present(skb)) { ... }
    // 软件路由处理
    rx_handler = rcu_dereference(skb->dev->rx_handler);
    if (rx_handler) { ... }
    // 再次检查VLAN协议后处理
    if (unlikely(skb_vlan_tag_present(skb)) && !netdev_uses_dsa(skb->dev)) { ... }

    // L3协议类型
    type = skb->protocol;
    if (likely(!deliver_exact)) {
        // 传送到指定协议
        deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type, &ptype_base[ntohs(type) & PTYPE_HASH_MASK]);
    }
    // 传送到网卡设备指定协议
	deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type, &orig_dev->ptype_specific);
    // 传送到网卡设备指定协议
    if (unlikely(skb->dev != orig_dev)) {
        deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type, &skb->dev->ptype_specific);
    }
    ...
}
```

`deliver_ptype_list_skb` 函数将skb传送到指定的L3协议类型处理，如下：

```C
//file: net/core/dev.c
static inline void deliver_ptype_list_skb(struct sk_buff *skb, struct packet_type **pt,
                struct net_device *orig_dev, __be16 type, struct list_head *ptype_list)
{
    struct packet_type *ptype, *pt_prev = *pt;
    list_for_each_entry_rcu(ptype, ptype_list, list) {
        if (ptype->type != type) continue;
        if (pt_prev) 
            // 传递skb到L3
            deliver_skb(skb, pt_prev, orig_dev);
        pt_prev = ptype;
    }
    *pt = pt_prev;
}
```

在相同协议时，通过批量方式传递L3层处理，如下：

```C
//file: net/core/dev.c
static void __netif_receive_skb_list_core(struct list_head *head, bool pfmemalloc)
{
    ...
    list_for_each_entry_safe(skb, next, head, list) {
        struct net_device *orig_dev = skb->dev;
        struct packet_type *pt_prev = NULL;

        skb_list_del_init(skb);
        __netif_receive_skb_core(&skb, pfmemalloc, &pt_prev);
        if (!pt_prev) continue;
        
        if (pt_curr != pt_prev || od_curr != orig_dev) {
            // 不同网络协议或网卡设备，批量传递
            __netif_receive_skb_list_ptype(&sublist, pt_curr, od_curr);
            INIT_LIST_HEAD(&sublist);
            pt_curr = pt_prev;
            od_curr = orig_dev;
        }
        list_add_tail(&skb->list, &sublist);
    }
    // 批量传递
    __netif_receive_skb_list_ptype(&sublist, pt_curr, od_curr);
}
```

`__netif_receive_skb_list_ptype` 以列表方式批量传递，如下：

```C
//file: net/core/dev.c
static inline void __netif_receive_skb_list_ptype(struct list_head *head, 
                struct packet_type *pt_prev, struct net_device *orig_dev)
{
    struct sk_buff *skb, *next;

    if (!pt_prev) return;
    if (list_empty(head)) return;
	
    if (pt_prev->list_func != NULL)
        // 支持列表批量接收
        INDIRECT_CALL_INET(pt_prev->list_func, ipv6_list_rcv, ip_list_rcv, head, pt_prev, orig_dev);
    else
        // 不支持时，以单个skb传递
        list_for_each_entry_safe(skb, next, head, list) {
            skb_list_del_init(skb);
            pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
        }
}
```

#### (2) ipv4协议接收

ipv4协议在Linux内核中的定义为`ip_packet_type`，如下：

```C
// file: net/ipv4/af_inet.c
static struct packet_type ip_packet_type __read_mostly = {
    .type = cpu_to_be16(ETH_P_IP),
    .func = ip_rcv,
    .list_func = ip_list_rcv,
};
```

在`fs_initcall`阶段注册ipv4网络协议栈时初始化，如下：

```C
// file: net/ipv4/af_inet.c
static int __init inet_init(void)
{
    ...
    dev_add_pack(&ip_packet_type);
    ...
}
fs_initcall(inet_init);
```

`ip_list_rcv` 以通过列表方式批量接收后处理，处理过程和单个处理过程类似，需要经过 `NFPROTO_IPV4:NF_INET_PRE_ROUTING` netfilter过程。我们只分析以单个skb处理过程，如下：

```C
// file：net/ipv4/ip_input.c
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    struct net *net = dev_net(dev);
    // 检查为本机网络包后，按照RFC1122进行ip协议检查格式，设置L4层数据位置
    skb = ip_rcv_core(skb, net);
    if (skb == NULL) return NET_RX_DROP;
    // netfilter hook点，检查通过后，调用`ip_rcv_finish`
    return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, net, NULL, skb, dev, NULL, ip_rcv_finish);
}
```

`ip_rcv_finish` 函数是skb为运行通过的正常的网络数据包后的处理过程，如下：

```C
// file：net/ipv4/ip_input.c
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct net_device *dev = skb->dev;
    int ret;
    // 入口设备从属于L3主设备时，传送SKB到其处理程序进行处理
    skb = l3mdev_ip_rcv(skb);
    if (!skb) return NET_RX_SUCCESS;
    // ipv4核心处理，确定路由路径
    ret = ip_rcv_finish_core(net, sk, skb, dev, NULL);
    // 没有丢弃的情况下，路由输入处理
    if (ret != NET_RX_DROP) ret = dst_input(skb);
    return ret;
}
```

`ip_rcv_finish_core` 函数进行skb接收的核心处理，确定路由信息后，检查ip选项信息，获取路由信息错误时丢弃skb，如下：

```C
// file: net/ipv4/ip_input.c
static int ip_rcv_finish_core(struct net *net, struct sock *sk, struct sk_buff *skb, 
            struct net_device *dev, const struct sk_buff *hint)
{
    const struct iphdr *iph = ip_hdr(skb);
    struct rtable *rt;

    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
    // hint存在时，daddr、tos相同时，检查saddr后，使用hint的路由
    if (ip_can_use_hint(skb, iph, hint)) {
        err = ip_route_use_hint(skb, iph->daddr, iph->saddr, iph->tos, dev, hint);
        if (unlikely(err)) goto drop_error;
    }
    // ip协议早期解析
    if (READ_ONCE(net->ipv4.sysctl_ip_early_demux) && !skb_dst(skb) && !skb->sk && !ip_is_fragment(iph)) {
        switch (iph->protocol) {
        case IPPROTO_TCP:
            if (READ_ONCE(net->ipv4.sysctl_tcp_early_demux)) {
                // tcp协议早期解析，检查tcp协议是否正确，确定已连接的sk，设置路由
                tcp_v4_early_demux(skb);
                iph = ip_hdr(skb);
            }
            break;
        case IPPROTO_UDP:
            if (READ_ONCE(net->ipv4.sysctl_udp_early_demux)) {
                // udp协议早期解析，检查udp协议是否正确，确定已连接的sk，设置路由
                err = udp_v4_early_demux(skb);
                if (unlikely(err)) goto drop_error;
                iph = ip_hdr(skb);
            }
            break;
        }
    }

    if (!skb_valid_dst(skb)) { 
        // 路由信息不存在时，确定路由
        err = ip_route_input_noref(skb, iph->daddr, iph->saddr, iph->tos, dev);
        if (unlikely(err)) goto drop_error;
    } else {
        struct in_device *in_dev = __in_dev_get_rcu(dev);
        if (in_dev && IN_DEV_ORCONF(in_dev, NOPOLICY))
            IPCB(skb)->flags |= IPSKB_NOPOLICY;
    }

    if (unlikely(skb_dst(skb)->tclassid)) {
        // 路由tclassid存在时，更新统计信息，通过`/proc/net/rt_acct`文件查看
        struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
        u32 idx = skb_dst(skb)->tclassid;
        st[idx&0xFF].o_packets++;
        st[idx&0xFF].o_bytes += skb->len;
        st[(idx>>16)&0xFF].i_packets++;
        st[(idx>>16)&0xFF].i_bytes += skb->len;
    }
    // ip选项存在时，解析
    if (iph->ihl > 5 && ip_rcv_options(skb, dev)) goto drop;

    rt = skb_rtable(skb);
    // 多包和广播路由信息更新
    if (rt->rt_type == RTN_MULTICAST) {
        __IP_UPD_PO_STATS(net, IPSTATS_MIB_INMCAST, skb->len);
    } else if (rt->rt_type == RTN_BROADCAST) {
        __IP_UPD_PO_STATS(net, IPSTATS_MIB_INBCAST, skb->len);
    } else if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
        struct in_device *in_dev = __in_dev_get_rcu(dev);
        // 网卡设备不支持多播或广播数据包时，丢弃
        if (in_dev && IN_DEV_ORCONF(in_dev, DROP_UNICAST_IN_L2_MULTICAST)) {
            drop_reason = SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST;
            goto drop;
        }
    }
    // 正确接收
    return NET_RX_SUCCESS;

drop:
    // 错误时，释放skb
    kfree_skb_reason(skb, drop_reason);
    return NET_RX_DROP;
drop_error:
    if (err == -EXDEV) {
        drop_reason = SKB_DROP_REASON_IP_RPFILTER;
        __NET_INC_STATS(net, LINUX_MIB_IPRPFILTER);
    }
    goto drop;
}
```

#### (3) 确定ipv4接收路由

`ip_route_input_noref` 函数确定输入的skb的路由信息，是对`ip_route_input_rcu`的调用封装，后者根据目标地址(daddr)类型进行不同方式的获取，如下：

```C
// file: net/ipv4/route.c
int ip_route_input_noref(struct sk_buff *skb, __be32 daddr, __be32 saddr, u8 tos, struct net_device *dev)
{
    struct fib_result res;
    ...    
    tos &= IPTOS_RT_MASK;
    rcu_read_lock();
    err = ip_route_input_rcu(skb, daddr, saddr, tos, dev, &res);
    rcu_read_unlock();
    return err;
}
// file: net/ipv4/route.c
static int ip_route_input_rcu(struct sk_buff *skb, __be32 daddr, __be32 saddr, 
            u8 tos, struct net_device *dev, struct fib_result *res)
{
    // 组播路由检查并获取
    if (ipv4_is_multicast(daddr)) {
        struct in_device *in_dev = __in_dev_get_rcu(dev);
        int our = 0;
        int err = -EINVAL;

        if (!in_dev) return err;
        our = ip_check_mc_rcu(in_dev, daddr, saddr, ip_hdr(skb)->protocol);
        // l3从设备获取主设备
        if (!our && netif_is_l3_slave(dev)) { ... }

        if (our || (!ipv4_is_local_multicast(daddr) && IN_DEV_MFORWARD(in_dev)) ) {
            // 发往本机的skb时或者在多路由支持转发的情况下，确定组播路由
            err = ip_route_input_mc(skb, daddr, saddr, tos, dev, our);
        }
        return err;
    }
    // 慢路径方式确定输入路由
    return ip_route_input_slow(skb, daddr, saddr, tos, dev, res);
}
```

`ip_route_input_slow` 函数过滤不符合条件的源地址和目的地址后，确定路由信息后，进行不同的设置。如下：

```C
// file: net/ipv4/route.c
static int ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                u8 tos, struct net_device *dev, struct fib_result *res)
{
    struct in_device *in_dev = __in_dev_get_rcu(dev);
    struct flow_keys *flkeys = NULL, _flkeys;
    struct net *net = dev_net(dev);
    struct ip_tunnel_info *tun_info;
    int err = -EINVAL;
    unsigned int flags = 0;
    u32 itag = 0;
    struct rtable *rth;
    struct flowi4 fl4;
    bool do_cache = true;

    // 设备不支持ipv4协议
    if (!in_dev) goto out;

    // 隧道信息存在时，获取隧道id
    tun_info = skb_tunnel_info(skb);
    if (tun_info && !(tun_info->mode & IP_TUNNEL_INFO_TX))
        fl4.flowi4_tun_key.tun_id = tun_info->key.tun_id;
    else
        fl4.flowi4_tun_key.tun_id = 0;
    skb_dst_drop(skb);

    // 源地址组播或广播地址时，标记为火星源（不能正常处理）
    if (ipv4_is_multicast(saddr) || ipv4_is_lbcast(saddr))
        goto martian_source;

    res->fi = NULL;
    res->table = NULL;
    // 目的地址为广播地址，或者源地址和目的地址都为0，对应广播处理
    if (ipv4_is_lbcast(daddr) || (saddr == 0 && daddr == 0)) 
        goto brd_input;

    // 源地址或目的地址为0时，标记为火星源或火星目的
    if (ipv4_is_zeronet(saddr)) goto martian_source;
    if (ipv4_is_zeronet(daddr)) goto martian_destination;

    // 源地址或目的地址为loopback时检查，不支持loopback路由时，标记为火星源或火星目的
    if (ipv4_is_loopback(daddr)) {
        if (!IN_DEV_NET_ROUTE_LOCALNET(in_dev, net)) goto martian_destination;
    } else if (ipv4_is_loopback(saddr)) {
        if (!IN_DEV_NET_ROUTE_LOCALNET(in_dev, net)) goto martian_source;
    }

    // 设置路由查找信息
    fl4.flowi4_l3mdev = 0;
    fl4.flowi4_oif = 0;
    fl4.flowi4_iif = dev->ifindex;
    fl4.flowi4_mark = skb->mark;
    fl4.flowi4_tos = tos;
    fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
    fl4.flowi4_flags = 0;
    fl4.daddr = daddr;
    fl4.saddr = saddr;
    fl4.flowi4_uid = sock_net_uid(net, NULL);
    fl4.flowi4_multipath_hash = 0;

    // 路由规则剖析，由`fib_rules_require_fldissect`选项控制
    if (fib4_rules_early_flow_dissect(net, skb, &fl4, &_flkeys)) {
        flkeys = &_flkeys;
    } else {
        fl4.flowi4_proto = 0;
        fl4.fl4_sport = 0;
        fl4.fl4_dport = 0;
    }
    // 查找路由信息
    err = fib_lookup(net, &fl4, res, 0);
    if (err != 0) {
        // 路由不存在时，no_route 处理
        if (!IN_DEV_FORWARD(in_dev)) err = -EHOSTUNREACH;
        goto no_route;
    }
    // 广播路由时处理
    if (res->type == RTN_BROADCAST) {
        // 广播路由在网卡设备支持转发时，创建路由信息，否则本地广播处理
        if (IN_DEV_BFORWARD(in_dev)) goto make_route;
        if (IPV4_DEVCONF_ALL(net, BC_FORWARDING)) do_cache = false;
        goto brd_input;
    }
    // 本地路由处理
    if (res->type == RTN_LOCAL) {
        // 本地路由时检查源地址，正确时进行本地输入处理，否则标记火星源
        err = fib_validate_source(skb, saddr, daddr, tos, 0, dev, in_dev, &itag);
        if (err < 0) goto martian_source;
        goto local_input;
    }
    // 其他类型时，网卡设备不支持转发时，标记为无路由
    if (!IN_DEV_FORWARD(in_dev)) {
        err = -EHOSTUNREACH;
        goto no_route;
    }
    // 不是直接路由或网关时，标记为火星目的
    if (res->type != RTN_UNICAST) goto martian_destination;

make_route:
    err = ip_mkroute_input(skb, res, in_dev, daddr, saddr, tos, flkeys);
out:  return err;
    ...
}
```

##### 1 路由不存在时处理过程

在路由信息不存在时，或者需要转发时但网卡设备不支持转发时，标记为无路由。增加无路由计数后，清除查找的路由结果后，跳转到本地处理。处理如下：

```C
// file: net/ipv4/route.c
static int ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                u8 tos, struct net_device *dev, struct fib_result *res)
{
    ...
no_route:
    RT_CACHE_STAT_INC(in_no_route);
    res->type = RTN_UNREACHABLE;
    res->fi = NULL;
    res->table = NULL;
    goto local_input;
    ...
}
```

##### 2 广播路由的处理过程

在目的地址为广播地址时，或者路由为广播类型时但网卡设备不支持转发时，进行本地广播处理。验证为ipv4网络数据包和源地址后，增加广播计数后，设置路由类型后进行本地处理，如下：

```C
// file: net/ipv4/route.c
static int ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                u8 tos, struct net_device *dev, struct fib_result *res)
{
    ...
brd_input:
    // 必须为ipv4网络数据包
    if (skb->protocol != htons(ETH_P_IP)) goto e_inval;
    // 源地址不为0时，验证源地址
    if (!ipv4_is_zeronet(saddr)) {
        err = fib_validate_source(skb, saddr, 0, tos, 0, dev, in_dev, &itag);
        if (err < 0) goto martian_source;
    }
    flags |= RTCF_BROADCAST;
    res->type = RTN_BROADCAST;
    RT_CACHE_STAT_INC(in_brd);

local_input:
}
```

##### 3 本地路由的处理过程

在路由为本地路由时、无路由和广播路由设置完成后，进行本地输入处理，如下

```C
// file: net/ipv4/route.c
static int ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                u8 tos, struct net_device *dev, struct fib_result *res)
{
    ...
local_input:
    if (IN_DEV_ORCONF(in_dev, NOPOLICY)) IPCB(skb)->flags |= IPSKB_NOPOLICY;

    do_cache &= res->fi && !itag;
    if (do_cache) {
        // 支持缓存路由时，使用获取的路由
        struct fib_nh_common *nhc = FIB_RES_NHC(*res);
        rth = rcu_dereference(nhc->nhc_rth_input);
        // 缓存有效时，设置skb的路由结果后退出
        if (rt_cache_valid(rth)) {
            skb_dst_set_noref(skb, &rth->dst);
            err = 0;
            goto out;
        }
    }
    // 不支持缓存路由或缓存路由无效时，创建默认的路由结果
    rth = rt_dst_alloc(ip_rt_get_dev(net, res), flags | RTCF_LOCAL, res->type, false);
    if (!rth) goto e_nobufs;

    // 设置路由输出处理，默认为bug处理
    rth->dst.output= ip_rt_bug;
#ifdef CONFIG_IP_ROUTE_CLASSID
    rth->dst.tclassid = itag;
#endif
    rth->rt_is_input = 1;

    RT_CACHE_STAT_INC(in_slow_tot);
    if (res->type == RTN_UNREACHABLE) {
        // 路由不可达时，设置输入处理为错误的ip包
        rth->dst.input = ip_error;
        rth->dst.error = -err;
        rth->rt_flags &= ~RTCF_LOCAL;
    }
    if (do_cache) {
        // 缓存路由时，设置input隧道封装输入
        struct fib_nh_common *nhc = FIB_RES_NHC(*res);
        rth->dst.lwtstate = lwtstate_get(nhc->nhc_lwtstate);
        if (lwtunnel_input_redirect(rth->dst.lwtstate)) {
            WARN_ON(rth->dst.input == lwtunnel_input);
            rth->dst.lwtstate->orig_input = rth->dst.input;
            rth->dst.input = lwtunnel_input;
        }
        // 不能缓存路由时，添加到非缓存列表中
        if (unlikely(!rt_cache_route(nhc, rth)))
            rt_add_uncached_list(rth);
    }
    // 设置skb路由结果
    skb_dst_set(skb, &rth->dst);
    err = 0;
    goto out;
    ...
}
```

##### 4 转发路由的处理过程

在路由信息为广播路由且网卡设备支持转发时，或者路由为网关时，创建输入的转发路由。`ip_mkroute_input` 函数实现该功能，在支持存在多路径时选择路径后，创建缓存路由结果，如下：

```C
// file: net/ipv4/route.c
static int ip_mkroute_input(struct sk_buff *skb, struct fib_result *res, struct in_device *in_dev,
    __be32 daddr, __be32 saddr, u32 tos, struct flow_keys *hkeys)
{
#ifdef CONFIG_IP_ROUTE_MULTIPATH
    // 多路径路由时选择路径
    if (res->fi && fib_info_num_path(res->fi) > 1) {
        int h = fib_multipath_hash(res->fi->fib_net, NULL, skb, hkeys);
        fib_select_multipath(res, h);
    }
#endif
    // 创建输入的路由信息
    return __mkroute_input(skb, res, in_dev, daddr, saddr, tos);
}
```

`__mkroute_input` 函数设置skb的下一跳转发路由，如下：

```C
// file: net/ipv4/route.c
static int __mkroute_input(struct sk_buff *skb, const struct fib_result *res, 
    struct in_device *in_dev, __be32 daddr, __be32 saddr, u32 tos)
{
    struct fib_nh_common *nhc = FIB_RES_NHC(*res);
    struct net_device *dev = nhc->nhc_dev;
    struct fib_nh_exception *fnhe;
    struct rtable *rth;
    struct in_device *out_dev;
    bool do_cache;
    u32 itag = 0;

    // 检查网卡设备的ipv4出口设置
    out_dev = __in_dev_get_rcu(dev);
    if (!out_dev) { }

    // 检查源地址，错误表示火星源
    err = fib_validate_source(skb, saddr, daddr, tos, FIB_RES_OIF(*res), in_dev->dev, in_dev, &itag);
    if (err < 0) {
        ip_handle_martian_source(in_dev->dev, in_dev, skb, daddr, saddr);
        goto cleanup;
    }

    do_cache = res->fi && !itag;
    //  出入口的网卡相同时，源支持直接发送设置
    if (out_dev == in_dev && err && IN_DEV_TX_REDIRECTS(out_dev) && skb->protocol == htons(ETH_P_IP)) {
        __be32 gw;
        gw = nhc->nhc_gw_family == AF_INET ? nhc->nhc_gw.ipv4 : 0;
        // 网卡共享信息或网关在线时标记直接转发
        if (IN_DEV_SHARED_MEDIA(out_dev) || inet_addr_onlink(out_dev, saddr, gw))
            IPCB(skb)->flags |= IPSKB_DOREDIRECT;
    }
    if (skb->protocol != htons(ETH_P_IP)) {
        // 出入口的网卡相同时，不支持ARP代理时，不创建路由。代理ARP允许ARP回复到同一个接口
        if (out_dev == in_dev && IN_DEV_PROXY_ARP_PVLAN(in_dev) == 0) {
            err = -EINVAL; goto cleanup; }
    }
    if (IN_DEV_ORCONF(in_dev, NOPOLICY))
        IPCB(skb)->flags |= IPSKB_NOPOLICY;

    // 获取异常路由
    fnhe = find_exception(nhc, daddr);
    if (do_cache) {
        // 缓存路由时，获取使用的路由信息
        if (fnhe) rth = rcu_dereference(fnhe->fnhe_rth_input);
        else rth = rcu_dereference(nhc->nhc_rth_input);
        // 路由缓存有效时，设置skb目标路由
        if (rt_cache_valid(rth)) {
            skb_dst_set_noref(skb, &rth->dst);
            goto out;
        }
    }
    // 重新分配路由信息
    rth = rt_dst_alloc(out_dev->dev, 0, res->type, IN_DEV_ORCONF(out_dev, NOXFRM));
    if (!rth) { ... }

    // 更新统计计数，设置路由input处理接口
    rth->rt_is_input = 1;
    RT_CACHE_STAT_INC(in_slow_tot);
    rth->dst.input = ip_forward;

    // 设置下一跳路由信息
    rt_set_nexthop(rth, daddr, res, fnhe, res->fi, res->type, itag, do_cache);
    // 设置路由封装重定向
    lwtunnel_set_redirect(&rth->dst);
    // 设置skb目标路由
    skb_dst_set(skb, &rth->dst);
out:
    err = 0;
 cleanup:
    return err;
}
```

#### (4) input路由封装设置

##### 1 本地路由封装设置

在路由为本地路由时、及无路由和广播路由设置完成后，进行本地输入处理时。在创建路由过程中，设置输入路由封装，如下

```C
// file: net/ipv4/route.c
static int ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                u8 tos, struct net_device *dev, struct fib_result *res)
{
    ...
local_input:
    if (IN_DEV_ORCONF(in_dev, NOPOLICY)) IPCB(skb)->flags |= IPSKB_NOPOLICY;

    do_cache &= res->fi && !itag;
    ...
    // 不支持缓存路由或缓存路由无效时，创建默认的路由结果
    rth = rt_dst_alloc(ip_rt_get_dev(net, res), flags | RTCF_LOCAL, res->type, false);
    if (!rth) goto e_nobufs;
    ...
    if (do_cache) {
        // 缓存路由时，设置input隧道封装输入
        struct fib_nh_common *nhc = FIB_RES_NHC(*res);
        rth->dst.lwtstate = lwtstate_get(nhc->nhc_lwtstate);
        if (lwtunnel_input_redirect(rth->dst.lwtstate)) {
            WARN_ON(rth->dst.input == lwtunnel_input);
            rth->dst.lwtstate->orig_input = rth->dst.input;
            rth->dst.input = lwtunnel_input;
        }
        // 不能缓存路由时，添加到非缓存列表中
        if (unlikely(!rt_cache_route(nhc, rth)))
            rt_add_uncached_list(rth);
    }
    // 设置skb路由结果
    skb_dst_set(skb, &rth->dst);
    err = 0;
    goto out;
    ...
}
```

##### 2 转发路由封装设置

转发路由在创建路由后，设置路由封装的重定向，`lwtunnel_set_redirect` 函数实现路由封装的重定向，如下：

```C
// file: include/net/lwtunnel.h
static inline void lwtunnel_set_redirect(struct dst_entry *dst)
{
    // output重定向
    if (lwtunnel_output_redirect(dst->lwtstate)) {
        dst->lwtstate->orig_output = dst->output;
        dst->output = lwtunnel_output;
    }
    // input重定向
    if (lwtunnel_input_redirect(dst->lwtstate)) {
        dst->lwtstate->orig_input = dst->input;
        dst->input = lwtunnel_input;
    }
}
```

#### (5) input路由封装调用

在通过`ip_rcv_finish_core`确定接收的路由后，接下来进行路由输入处理，如下：

```C
// file：net/ipv4/ip_input.c
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    ...
    // ipv4核心处理，确定路由路径
	ret = ip_rcv_finish_core(net, sk, skb, dev, NULL);
    // 没有丢弃的情况下，路由输入处理
    if (ret != NET_RX_DROP)
        ret = dst_input(skb);
    return ret;
}
```

`dst_input` 实现路由的输入处理，如下：

```C
// file: include/net/dst.h
static inline int dst_input(struct sk_buff *skb)
{
    return INDIRECT_CALL_INET(skb_dst(skb)->input, ip6_input, ip_local_deliver, skb);
}
```

优先进行 `ip6_input` 和 `ip_local_deliver` 处理。在设置封装路由时，设置`.input` 处理函数为 `lwtunnel_input`，实现如下：

```C
// file: net/core/lwtunnel.c
int lwtunnel_input(struct sk_buff *skb)
{
    struct dst_entry *dst = skb_dst(skb);
    const struct lwtunnel_encap_ops *ops;
    struct lwtunnel_state *lwtstate;
    int ret = -EINVAL;

    // 检查路由信息和路由封装设置正确
    if (!dst) goto drop;
    lwtstate = dst->lwtstate;    
    if (lwtstate->type == LWTUNNEL_ENCAP_NONE || lwtstate->type > LWTUNNEL_ENCAP_MAX)
        return 0;

    ret = -EOPNOTSUPP;
    rcu_read_lock();
    ops = rcu_dereference(lwtun_encaps[lwtstate->type]);
    // 检查并调用路由封装输入接口
    if (likely(ops && ops->input))
        ret = ops->input(skb);
    rcu_read_unlock();
    // 不支持时，释放skb
    if (ret == -EOPNOTSUPP) goto drop;

    return ret;
drop:
    kfree_skb(skb);
    return ret;
}
```

### 4.4 路由封装的设置过程(output)

#### (1) L4确定发送路由

在[Linux 网络栈监控和调优：发送数据（2017）](http://arthurchiao.art/blog/tuning-stack-tx-zh/)描述网络发送过程时，L4层通过`ip_route_output_flow` 函数确定发送的路由信息。此外，`ip_route_output*`系列函数均实现发送路由的确定。

`ip_route_output_flow` 函数实现如下：

```C
// file: net/ipv4/route.c
struct rtable *ip_route_output_flow(struct net *net, struct flowi4 *flp4, const struct sock *sk)
{
    // 确定ip层路由
    struct rtable *rt = __ip_route_output_key(net, flp4);
    if (IS_ERR(rt)) return rt;

    if (flp4->flowi4_proto) {
        flp4->flowi4_oif = rt->dst.dev->ifindex;
        // 转换路由查询
        rt = (struct rtable *)xfrm_lookup_route(net, &rt->dst, flowi4_to_flowi(flp4), sk, 0);
    }
    return rt;
}
```

`__ip_route_output_key` 函数经过多层调用后，调用`ip_route_output_key_hash_rcu`函数，如下:

```C
// file: include/net/route.h
static inline struct rtable *__ip_route_output_key(struct net *net, struct flowi4 *flp)
{
    return ip_route_output_key_hash(net, flp, NULL);
}
// file: net/ipv4/route.c
struct rtable *ip_route_output_key_hash(struct net *net, struct flowi4 *fl4, const struct sk_buff *skb)
{
    // 路由结果初始化
    struct fib_result res = { .type = RTN_UNSPEC, .fi = NULL, .table = NULL, .tclassid	= 0, };
    struct rtable *rth;
    // 设置input网卡索引为loopback
    fl4->flowi4_iif = LOOPBACK_IFINDEX;
    // tos设置
    ip_rt_fix_tos(fl4);

    rcu_read_lock();
    // 查找ip层路由
    rth = ip_route_output_key_hash_rcu(net, fl4, &res, skb);
    rcu_read_unlock();
    return rth;
}
```

`ip_route_output_key_hash_rcu` 函数查找ipv4出口的路由信息，如下：

```C
// file: net/ipv4/route.c
struct rtable *ip_route_output_key_hash_rcu(struct net *net, struct flowi4 *fl4,
                struct fib_result *res, const struct sk_buff *skb)
{
    struct net_device *dev_out = NULL;
    int orig_oif = fl4->flowi4_oif;
    unsigned int flags = 0;
    struct rtable *rth;
    int err;

    if (fl4->saddr) {
        // 源地址存在时，组播、广播、零地址时不能确定路由
        if (ipv4_is_multicast(fl4->saddr) || ipv4_is_lbcast(fl4->saddr) || ipv4_is_zeronet(fl4->saddr)) {
            rth = ERR_PTR(-EINVAL); goto out;
        }
        rth = ERR_PTR(-ENETUNREACH);
        // 未指定发送网卡时，目的地址为组播或广播地址时，使用源地址的网卡
        if (fl4->flowi4_oif == 0 && (ipv4_is_multicast(fl4->daddr) || ipv4_is_lbcast(fl4->daddr))) {
            // 通过源地址确定网卡设备
            dev_out = __ip_dev_find(net, fl4->saddr, false);
            if (!dev_out) goto out;
            
            // 设置out网卡索引后，创建路由
            fl4->flowi4_oif = dev_out->ifindex;
            goto make_route;
        }
        // 不是异步创建时，确定原地址存在
        if (!(fl4->flowi4_flags & FLOWI_FLAG_ANYSRC)) {
            if (!__ip_dev_find(net, fl4->saddr, false)) goto out;
        }
    }

    // 指定网卡时
    if (fl4->flowi4_oif) {
        // 确定指定的网卡存在
        dev_out = dev_get_by_index_rcu(net, fl4->flowi4_oif);
        rth = ERR_PTR(-ENODEV);
        if (!dev_out) goto out;

        // 确定网卡在线且支持ipv4协议
        if (!(dev_out->flags & IFF_UP) || !__in_dev_get_rcu(dev_out)) { 
            rth = ERR_PTR(-ENETUNREACH); goto out; }

        // 目的地址为本地组播地址、广播地址，IGMP协议时，源地址未设置时，确定源地址
        if (ipv4_is_local_multicast(fl4->daddr) || ipv4_is_lbcast(fl4->daddr) 
            || fl4->flowi4_proto == IPPROTO_IGMP) {
            if (!fl4->saddr) fl4->saddr = inet_select_addr(dev_out, 0, RT_SCOPE_LINK);
            goto make_route;
        }
        // 源地址未设置时，确定源地址
        if (!fl4->saddr) {
            if (ipv4_is_multicast(fl4->daddr))
                fl4->saddr = inet_select_addr(dev_out, 0, fl4->flowi4_scope);
            else if (!fl4->daddr)
                fl4->saddr = inet_select_addr(dev_out, 0, RT_SCOPE_HOST);
        }
    }

    if (!fl4->daddr) {
        // 目的地址未设置时，使用源地址。默认使用本地地址
        fl4->daddr = fl4->saddr;
        if (!fl4->daddr) 
            fl4->daddr = fl4->saddr = htonl(INADDR_LOOPBACK);
        // loopback 路由
        dev_out = net->loopback_dev;
        fl4->flowi4_oif = LOOPBACK_IFINDEX;
        res->type = RTN_LOCAL;
        flags |= RTCF_LOCAL;
        goto make_route;
    }

    // 从路由表中查找路由
    err = fib_lookup(net, fl4, res, 0);
    if (err) {
        res->fi = NULL;
        res->table = NULL;
        // 指定网卡时，目的地址是组播地址时，创建Link路由
        if (fl4->flowi4_oif && (ipv4_is_multicast(fl4->daddr) || !fl4->flowi4_l3mdev)) {
            // 路由表错误时，假设目的地址在LINK链路上
            if (fl4->saddr == 0)
                fl4->saddr = inet_select_addr(dev_out, 0, RT_SCOPE_LINK);
            res->type = RTN_UNICAST;
            goto make_route;
        }
        // 其他情况返回错误信息
        rth = ERR_PTR(err);
        goto out;
    }

    if (res->type == RTN_LOCAL) {
        // 源地址未设置时，确定源地址
        if (!fl4->saddr) {
            if (res->fi->fib_prefsrc)  fl4->saddr = res->fi->fib_prefsrc;
            else fl4->saddr = fl4->daddr;
        }
        // 确定出口网卡设置，L3主设备也是loopback的一种
        dev_out = l3mdev_master_dev_rcu(FIB_RES_DEV(*res)) ? : net->loopback_dev;
        // 设置查找信息
        orig_oif = FIB_RES_OIF(*res);
        fl4->flowi4_oif = dev_out->ifindex;
        flags |= RTCF_LOCAL;
        goto make_route;
    }
    // 确定发送的路径
    fib_select_path(net, res, fl4, skb);
    dev_out = FIB_RES_DEV(*res);

make_route:
    // 创建路由
    rth = __mkroute_output(res, fl4, orig_oif, dev_out, flags);
out:
    return rth;
}
```

#### (2) 确定ipv4发送路由

`__mkroute_output` 函数确定发送时使用路由信息，如下：

```C
// file: net/ipv4/route.c
static struct rtable *__mkroute_output(const struct fib_result *res, const struct flowi4 *fl4, 
    int orig_oif, struct net_device *dev_out, unsigned int flags)
{
    struct fib_info *fi = res->fi;
    struct fib_nh_exception *fnhe;
    struct in_device *in_dev;
    u16 type = res->type;
    struct rtable *rth;
    bool do_cache;

    // 网卡不支持ipv4，返回错误
    in_dev = __in_dev_get_rcu(dev_out);
    if (!in_dev) return ERR_PTR(-EINVAL);

    // 网卡不支持本机路由时，检查loopback地址
    if (likely(!IN_DEV_ROUTE_LOCALNET(in_dev)))
        if (ipv4_is_loopback(fl4->saddr) && !(dev_out->flags & IFF_LOOPBACK) && !netif_is_l3_master(dev_out))
            return ERR_PTR(-EINVAL);

    // 根据目的地址确定路由范围，零地址时返回错误信息
    if (ipv4_is_lbcast(fl4->daddr)) 
        type = RTN_BROADCAST;
    else if (ipv4_is_multicast(fl4->daddr))
        type = RTN_MULTICAST;
    else if (ipv4_is_zeronet(fl4->daddr))
        return ERR_PTR(-EINVAL);

    // flags确定
    if (dev_out->flags & IFF_LOOPBACK)
        flags |= RTCF_LOCAL;

    do_cache = true;
    if (type == RTN_BROADCAST) {
        flags |= RTCF_BROADCAST | RTCF_LOCAL;
        fi = NULL;
    } else if (type == RTN_MULTICAST) {
        flags |= RTCF_MULTICAST | RTCF_LOCAL;
        // 不支持组播时，清除`RTCF_LOCAL`标记
        if (!ip_check_mc_rcu(in_dev, fl4->daddr, fl4->saddr, fl4->flowi4_proto))
            flags &= ~RTCF_LOCAL;
        else
            do_cache = false;

        // 组播路由不存在时，使用默认值。不能使用网关地址
        if (fi && res->prefixlen < 4) fi = NULL;
    } else if ((type == RTN_LOCAL) && (orig_oif != 0) && (orig_oif != dev_out->ifindex)) {
        // 需要特定输出接口的本地路由不缓存结果。缓存路由时存在多个源时导致不正确的传输，传输到loopback中
        do_cache = false;
    }

    fnhe = NULL;
    do_cache &= fi != NULL;
    if (fi) {
        struct fib_nh_common *nhc = FIB_RES_NHC(*res);
        struct rtable __rcu **prth;
        // 查找异常路由
        fnhe = find_exception(nhc, fl4->daddr);
        // 不缓存路由时，创建新的路由
        if (!do_cache) goto add;
        // 确定输出路由
        if (fnhe) {
            prth = &fnhe->fnhe_rth_output;
        } else {
            if (unlikely(fl4->flowi4_flags & FLOWI_FLAG_KNOWN_NH &&
                    !(nhc->nhc_gw_family && nhc->nhc_scope == RT_SCOPE_LINK))) {
                // 知道下一跳地址时，但确定的下一跳不是网关时，创建新的路由
                do_cache = false; goto add; }
            prth = raw_cpu_ptr(nhc->nhc_pcpu_rth_output);
        }
        // 路由信息存在且有效时，返回路由结果
        rth = rcu_dereference(*prth);
        if (rt_cache_valid(rth) && dst_hold_safe(&rth->dst))
            return rth;
    }

add:
    // 创建路由
    rth = rt_dst_alloc(dev_out, flags, type, IN_DEV_ORCONF(in_dev, NOXFRM));
    if (!rth) return ERR_PTR(-ENOBUFS);
    // 设置路由的input网卡
    rth->rt_iif = orig_oif;
    // 更新统计信息
    RT_CACHE_STAT_INC(out_slow_tot);
    // 广播或组播地址输入/输出接口设置
    if (flags & (RTCF_BROADCAST | RTCF_MULTICAST)) {
        if (flags & RTCF_LOCAL && !(dev_out->flags & IFF_LOOPBACK)) {
            // 本地组播路由输出接口设置
            rth->dst.output = ip_mc_output;
            RT_CACHE_STAT_INC(out_slow_mc);
        }
#ifdef CONFIG_IP_MROUTE
        if (type == RTN_MULTICAST) {
            if (IN_DEV_MFORWARD(in_dev) && !ipv4_is_local_multicast(fl4->daddr)) {
                // 多路径下组播输入/输出接口设置
                rth->dst.input = ip_mr_input;
                rth->dst.output = ip_mc_output;
            }
        }
#endif
    }
    // 设置下一跳路由信息
    rt_set_nexthop(rth, fl4->daddr, res, fnhe, fi, type, 0, do_cache);
    // 设置路由封装重定向
    lwtunnel_set_redirect(&rth->dst);
    return rth;
}
```

#### (3) output路由封装设置

在创建输出路由后，设置路由封装的重定向，`lwtunnel_set_redirect` 函数实现路由封装的重定向。

#### (4) L3发送网络数据过程

L4在确定路由信息后发送skb，以TCP为例，调用`ip_push_pending_frames`发送skb，如下：

```C
// file: net/ipv4/ip_output.c
int ip_push_pending_frames(struct sock *sk, struct flowi4 *fl4)
{
    struct sk_buff *skb;
    // 设置skb ipv4信息
    skb = ip_finish_skb(sk, fl4);
    if (!skb) return 0;
    // ipv4发送skb
    return ip_send_skb(sock_net(sk), skb);
}
```

##### 1 skb设置ipv4信息

`ip_finish_skb` 函数从sk写队列中取出skb后，填充ipv4信息，如下：

```C
// file：include/net/ip.h
static inline struct sk_buff *ip_finish_skb(struct sock *sk, struct flowi4 *fl4)
{
    return __ip_make_skb(sk, fl4, &sk->sk_write_queue, &inet_sk(sk)->cork.base);
}
// file：net/ipv4/ip_output.c
struct sk_buff *__ip_make_skb(struct sock *sk, struct flowi4 *fl4, 
                struct sk_buff_head *queue, struct inet_cork *cork)
{
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct ip_options *opt = NULL;
    struct rtable *rt = (struct rtable *)cork->dst;
    struct iphdr *iph;
    __be16 df = 0;
    __u8 ttl;

    // 从队列中取出一个skb
    skb = __skb_dequeue(queue);
    if (!skb) goto out;
    tail_skb = &(skb_shinfo(skb)->frag_list);

    // 移动skb->data位置，确保有足够的空间写入ip 头信息
    if (skb->data < skb_network_header(skb))
        __skb_pull(skb, skb_network_offset(skb));

    // 写队列中的其他skb，添加到第一个skb的frag列表中
    while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
        __skb_pull(tmp_skb, skb_network_header_len(skb));
        *tail_skb = tmp_skb;
        tail_skb = &(tmp_skb->next);
        skb->len += tmp_skb->len;
        skb->data_len += tmp_skb->len;
        skb->truesize += tmp_skb->truesize;
        tmp_skb->destructor = NULL;
        tmp_skb->sk = NULL;
    }
    // 除非用户要求真正的pmtu发现，否则我们允许进行分段
    skb->ignore_df = ip_sk_ignore_df(sk);

    // DF 标记设置
    if (inet->pmtudisc == IP_PMTUDISC_DO || inet->pmtudisc == IP_PMTUDISC_PROBE ||
        (skb->len <= dst_mtu(&rt->dst) && ip_dont_fragment(sk, &rt->dst)))
        df = htons(IP_DF);

    // ip选项
    if (cork->flags & IPCORK_OPT) opt = cork->opt;
    
    // ttl设置
    if (cork->ttl != 0) 
        ttl = cork->ttl;
    else if (rt->rt_type == RTN_MULTICAST)
        ttl = inet->mc_ttl;
    else
        ttl = ip_select_ttl(inet, &rt->dst);

    // ipv4信息设置
    iph = ip_hdr(skb);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = (cork->tos != -1) ? cork->tos : inet->tos;
    iph->frag_off = df;
    iph->ttl = ttl;
    iph->protocol = sk->sk_protocol;
    // 源地址、目的地址设置
    ip_copy_addrs(iph, fl4);
    // iph->id设置，确定skb顺序
    ip_select_ident(net, skb, sk);

    // ipv4选项设置
    if (opt) {
        iph->ihl += opt->optlen >> 2;
        ip_options_build(skb, opt, cork->addr, rt);
    }
    // skb优先级、标记、发送时间设置
    skb->priority = (cork->tos != -1) ? cork->priority: sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;

    // skb设置路由信息
    cork->dst = NULL;
    skb_dst_set(skb, &rt->dst);

    if (iph->protocol == IPPROTO_ICMP) {
        // 发送的ICMP统计
        u8 icmp_type;
        if (sk->sk_type == SOCK_RAW && !inet_sk(sk)->hdrincl)
            icmp_type = fl4->fl4_icmp_type;
        else
            icmp_type = icmp_hdr(skb)->type;
        icmp_out_count(net, icmp_type);
    }
    ip_cork_release(cork);
out:
    return skb;
}
```

##### 2 ipv4发送skb

在skb创建完成后，`ip_send_skb`实现本地skb发送，如下：

```C
// file: net/ipv4/ip_output.c
int ip_send_skb(struct net *net, struct sk_buff *skb)
{
    int err;
    // 本地skb输出
    err = ip_local_out(net, skb->sk, skb);
    if (err) {
        // 错误代码转换后，增加统计信息
        if (err > 0) err = net_xmit_errno(err);
        if (err) IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
    }
    return err;
}
```

`ip_local_out` 实现调用`__ip_local_out`实现skb本地发送，返回值为1时，通过路由层发送。如下：

```C
// file: net/ipv4/ip_output.c
int ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    int err;
    // 本地skb发送
    err = __ip_local_out(net, sk, skb);
    // 路由发送
    if (likely(err == 1)) err = dst_output(net, sk, skb);
    return err;
}
```

`__ip_local_out` 实现本地skb发送，设置ipv4数据包长度、检验和后，设置skb协议字段后，进入`NFPROTO_IPV4:NF_INET_LOCAL_OUT` netfilter 检查后，通过路由发送，如下：

```C
// file: net/ipv4/ip_output.c
int __ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct iphdr *iph = ip_hdr(skb);
    // 设置ipv4头部长度，超过MTU时，设置为0
    iph_set_totlen(iph, skb->len);
    // ipv4头校验和计算
    ip_send_check(iph);

    // 通过l3主设备发送skb
    skb = l3mdev_ip_out(sk, skb);
    if (unlikely(!skb)) return 0;

    skb->protocol = htons(ETH_P_IP);
    // netfilter检查后发送
    return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT, net, sk, skb,  NULL, skb_dst(skb)->dev, dst_output);
}
```

#### (5) output路由封装调用

本地发送skb时，最后通过`dst_output`函数实现路由的发送，如下

```C
// file: include/net/dst.h
static inline int dst_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return INDIRECT_CALL_INET(skb_dst(skb)->output, ip6_output, ip_output, net, sk, skb);
}
```

优先进行`ip6_output`和`ip_output`处理。在设置封装路由时，设置`.output`处理函数为`lwtunnel_output`，实现如下：

```C
// file: net/core/lwtunnel.c
int lwtunnel_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct dst_entry *dst = skb_dst(skb);
    const struct lwtunnel_encap_ops *ops;
    struct lwtunnel_state *lwtstate;
    int ret = -EINVAL;

    // 检查路由信息和路由封装设置正确
    if (!dst) goto drop;
    lwtstate = dst->lwtstate;
    if (lwtstate->type == LWTUNNEL_ENCAP_NONE || lwtstate->type > LWTUNNEL_ENCAP_MAX)
        return 0;

    ret = -EOPNOTSUPP;
    rcu_read_lock();
    ops = rcu_dereference(lwtun_encaps[lwtstate->type]);
    // 检查并调用路由封装输出接口
    if (likely(ops && ops->output))
        ret = ops->output(net, sk, skb);
    rcu_read_unlock();
    // 不支持时，释放skb
    if (ret == -EOPNOTSUPP) goto drop;

    return ret;
drop:
    kfree_skb(skb);
    return ret;
}
```

#### (6) ipv4发送skb的过程

在UDP或TCP使用ipv4时，默认设置的`.output`接口为`ip_output`, 设置skb网卡设备和网络协议后，进入`NFPROTO_IPV4:NF_INET_POST_ROUTING` netfilter 检查后，调用`ip_finish_output`，如下：

```C
// file: net/ipv4/ip_output.c
int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct net_device *dev = skb_dst(skb)->dev, *indev = skb->dev;
    IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);
    // 设置skb网卡设备和协议
    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);
    // netfilter hook
    return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING, net, sk, skb, indev, dev,
                ip_finish_output, !(IPCB(skb)->flags & IPSKB_REROUTED));
}
```

`ip_finish_output` 函数检查`CGROUP_INET_EGRESS`后，调用`__ip_finish_output`, 如下：

```C
// file: net/ipv4/ip_output.c
static int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    int ret;
    // `CGROUP_INET_EGRESS` 检查
    ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
    switch (ret) {
    // 发送成功
    case NET_XMIT_SUCCESS: return __ip_finish_output(net, sk, skb);
    // 继续发送
    case NET_XMIT_CN: return __ip_finish_output(net, sk, skb) ? : ret;
    // 其他返回值时，释放skb
    default:  
        kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
        return ret;
    }
}
```

`__ip_finish_output` 函数检查skb gso 和分片设置后，通过`ip_finish_output2` 函数发送，如下：

```C
// file: net/ipv4/ip_output.c
static int __ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    unsigned int mtu;
#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
    // 转换路由存在时，重新路由发送
    if (skb_dst(skb)->xfrm) {
        IPCB(skb)->flags |= IPSKB_REROUTED;
        return dst_output(net, sk, skb);
    }
#endif
    // 计算目的路由的mtu，路由封装信息存在时，减去路由封装长度
    mtu = ip_skb_dst_mtu(sk, skb);
    // 支持gso时，进行GSO(Generic Segmentation Offload)处理，推迟数据分片
    if (skb_is_gso(skb)) return ip_finish_output_gso(net, sk, skb, mtu);
    // skb长度超过mtu时，进行ip分片发送
    if (skb->len > mtu || IPCB(skb)->frag_max_size)
        return ip_fragment(net, sk, skb, mtu, ip_finish_output2);
    // ipv4实际发送skb
    return ip_finish_output2(net, sk, skb);
}
```

在skb经过分片处理后，将skb封装成ipv4能够通过的skb后，调用 `ip_finish_output2` 进行最后的发送。如下：

```C
// file: net/ipv4/ip_output.c
static int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct dst_entry *dst = skb_dst(skb);
    struct rtable *rt = (struct rtable *)dst;
    struct net_device *dev = dst->dev;
    unsigned int hh_len = LL_RESERVED_SPACE(dev);
    struct neighbour *neigh;
    bool is_v6gw = false;

    // 组播和广播统计信息更新
    if (rt->rt_type == RTN_MULTICAST) {
        IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTMCAST, skb->len);
    } else if (rt->rt_type == RTN_BROADCAST)
        IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTBCAST, skb->len);

    // 确保skb有足够的空间设置L2协议信息
    if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
        skb = skb_expand_head(skb, hh_len);
        if (!skb) return -ENOMEM;
    }
    // 路由隧道发送skb，发送完成或错误时返回，其他情况继续后续处理
    if (lwtunnel_xmit_redirect(dst->lwtstate)) {
        int res = lwtunnel_xmit(skb);
        if (res < 0 || res == LWTUNNEL_XMIT_DONE)
            return res;
    }

    rcu_read_lock_bh();
    // 根据目的地址确定邻接路由，ipv4通过ARP协议实现，由`arp_tbl`维护
    neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);
    if (!IS_ERR(neigh)) {
        int res;
        // 确认邻接路由，存在后续skb后，更新邻接路由时间
        sock_confirm_neigh(skb, neigh);
        // 通过邻接路由发送
        res = neigh_output(neigh, skb, is_v6gw);
        rcu_read_unlock_bh();
        return res;
    }
    rcu_read_unlock_bh();
    
    // 邻接路由不存在时，记录错误信息后释放skb
    net_dbg_ratelimited("%s: No header cache and no neighbour!\n", __func__);
    kfree_skb_reason(skb, SKB_DROP_REASON_NEIGH_CREATEFAIL);
    return -EINVAL;
}
```

#### (7) xmit路由封装调用

在通过`ip_finish_output2`发送skb时，设置了路由传输设置时，通过`lwtunnel_xmit`发送skb，如下：

```C
// file: net/core/lwtunnel.c
int lwtunnel_xmit(struct sk_buff *skb)
{
    struct dst_entry *dst = skb_dst(skb);
    const struct lwtunnel_encap_ops *ops;
    struct lwtunnel_state *lwtstate;
    int ret = -EINVAL;

    // 检查路由信息和路由封装设置正确
    if (!dst) goto drop;
    lwtstate = dst->lwtstate;
    if (lwtstate->type == LWTUNNEL_ENCAP_NONE || lwtstate->type > LWTUNNEL_ENCAP_MAX)
        return 0;

    ret = -EOPNOTSUPP;
    rcu_read_lock();
    ops = rcu_dereference(lwtun_encaps[lwtstate->type]);
    // 检查并调用路由封装传输接口
    if (likely(ops && ops->xmit))
        ret = ops->xmit(net, sk, skb);
    rcu_read_unlock();
    // 不支持时，释放skb
    if (ret == -EOPNOTSUPP) goto drop;

    return ret;
drop:
    kfree_skb(skb);
    return ret;
}
```

### 4.5 `lwt_bpf`路由封装的实现

在通过netlink创建路由时，在设置路由封装信息时调用`lwtunnel_build_state`函数设置路由封装信息。Linux内核支持多种类型的路由封装，如下：

```C
// file: include/uapi/linux/lwtunnel.h
enum lwtunnel_encap_types {
    LWTUNNEL_ENCAP_NONE,
    LWTUNNEL_ENCAP_MPLS,
    LWTUNNEL_ENCAP_IP,
    LWTUNNEL_ENCAP_ILA,
    LWTUNNEL_ENCAP_IP6,
    LWTUNNEL_ENCAP_SEG6,
    LWTUNNEL_ENCAP_BPF,
    LWTUNNEL_ENCAP_SEG6_LOCAL,
    LWTUNNEL_ENCAP_RPL,
    LWTUNNEL_ENCAP_IOAM6,
    LWTUNNEL_ENCAP_XFRM,
    __LWTUNNEL_ENCAP_MAX,
};
```

这些路由封装类型通过`lwtunnel_encap_add_ops`函数注册到内核中，如下：

```C
// file: net/core/lwtunnel.c
int lwtunnel_encap_add_ops(const struct lwtunnel_encap_ops *ops, unsigned int num)
{
    if (num > LWTUNNEL_ENCAP_MAX) return -ERANGE;
    // 设置`lwtun_encaps`
    return !cmpxchg((const struct lwtunnel_encap_ops **)&lwtun_encaps[num], NULL, ops) ? 0 : -1;
}
```

使用`bpf`设置的封装信息，在内核中对应`bpf_encap_ops`路由封装类型。如下：

```C
// file: net/core/lwt_bpf.c
static const struct lwtunnel_encap_ops bpf_encap_ops = {
    .build_state    = bpf_build_state,
    .destroy_state  = bpf_destroy_state,
    .input          = bpf_input,
    .output         = bpf_output,
    .xmit           = bpf_xmit,
    .fill_encap     = bpf_fill_encap_info,
    .get_encap_size = bpf_encap_nlsize,
    .cmp_encap      = bpf_encap_cmp,
    .owner          = THIS_MODULE,
};
```

在`subsys_initcall`阶段注册的，如下：

```C
// file: net/core/lwt_bpf.c
static int __init bpf_lwt_init(void)
{
    return lwtunnel_encap_add_ops(&bpf_encap_ops, LWTUNNEL_ENCAP_BPF);
}
subsys_initcall(bpf_lwt_init)
```

#### (1) 创建bpf路由封装

`bpf_encap_ops`的`.build_state`接口设置为`bpf_build_state`，在通过netlink添加路由时创建路由封装状态。如下：

```C
// file: net/core/lwt_bpf.c
static int bpf_build_state(struct net *net, struct nlattr *nla, unsigned int family, const void *cfg,
            struct lwtunnel_state **ts, struct netlink_ext_ack *extack)
{
    struct nlattr *tb[LWT_BPF_MAX + 1];
    struct lwtunnel_state *newts;
    struct bpf_lwt *bpf;
    int ret;

    // 只支持`AF_INET`和`AF_INET6`家族
    if (family != AF_INET && family != AF_INET6) return -EAFNOSUPPORT;

    // 解析netlink请求信息
    ret = nla_parse_nested_deprecated(tb, LWT_BPF_MAX, nla, bpf_nl_policy, extack);
    if (ret < 0) return ret;
    // LWT_BPF_IN、LWT_BPF_OUT、LWT_BPF_XMIT必须设置一个
    if (!tb[LWT_BPF_IN] && !tb[LWT_BPF_OUT] && !tb[LWT_BPF_XMIT]) return -EINVAL;

    // 创建bpf路由封装信息
    newts = lwtunnel_state_alloc(sizeof(*bpf));
    if (!newts) return -ENOMEM;

    newts->type = LWTUNNEL_ENCAP_BPF;
    bpf = bpf_lwt_lwtunnel(newts);

    // INPUT路由封装设置
    if (tb[LWT_BPF_IN]) {
        newts->flags |= LWTUNNEL_STATE_INPUT_REDIRECT;
        ret = bpf_parse_prog(tb[LWT_BPF_IN], &bpf->in, BPF_PROG_TYPE_LWT_IN);
        if (ret  < 0) goto errout;
    }
    // OUTPUT路由封装设置
    if (tb[LWT_BPF_OUT]) {
        newts->flags |= LWTUNNEL_STATE_OUTPUT_REDIRECT;
        ret = bpf_parse_prog(tb[LWT_BPF_OUT], &bpf->out, BPF_PROG_TYPE_LWT_OUT);
        if (ret < 0) goto errout;
    }
    // XMIT路由封装设置
    if (tb[LWT_BPF_XMIT]) {
        newts->flags |= LWTUNNEL_STATE_XMIT_REDIRECT;
        ret = bpf_parse_prog(tb[LWT_BPF_XMIT], &bpf->xmit, BPF_PROG_TYPE_LWT_XMIT);
        if (ret < 0) goto errout;
    }
    // 转发的头部空间设置
    if (tb[LWT_BPF_XMIT_HEADROOM]) {
        u32 headroom = nla_get_u32(tb[LWT_BPF_XMIT_HEADROOM]);
        if (headroom > LWT_BPF_MAX_HEADROOM) { ret = -ERANGE; goto errout; }
        newts->headroom = headroom;
    }
    bpf->family = family;
    // 设置返回结果
    *ts = newts;
    return 0;

errout:
    bpf_destroy_state(newts);
    kfree(newts);
    return ret;
}
```

`INPUT`,`OUTPUT`,`XMIT`路由封装设置都调用`bpf_parse_prog`设置bpf程序，如下：

```C
// file: net/core/lwt_bpf.c
static int bpf_parse_prog(struct nlattr *attr, struct bpf_lwt_prog *prog, enum bpf_prog_type type)
{
    struct nlattr *tb[LWT_BPF_PROG_MAX + 1];
    struct bpf_prog *p;
    int ret;
    u32 fd;

    // 解析netlink请求信息
    ret = nla_parse_nested_deprecated(tb, LWT_BPF_PROG_MAX, attr, bpf_prog_policy, NULL);
    if (ret < 0) return ret;

    // `PROG_FD`和`PROG_NAME`都必须设置
    if (!tb[LWT_BPF_PROG_FD] || !tb[LWT_BPF_PROG_NAME]) return -EINVAL;

    // 设置bpf程序名称
    prog->name = nla_memdup(tb[LWT_BPF_PROG_NAME], GFP_ATOMIC);
    if (!prog->name) return -ENOMEM;

    // 根据fd获取bpf程序后设置
    fd = nla_get_u32(tb[LWT_BPF_PROG_FD]);
    p = bpf_prog_get_type(fd, type);
    if (IS_ERR(p)) return PTR_ERR(p);
    prog->prog = p;
    return 0;
}
```

#### (2) 释放bpf路由封装

`bpf_encap_ops`的`.destroy_state`接口设置为`bpf_destroy_state`，在删除路由时释放路由封装。如下：

```C
// file: net/core/lwt_bpf.c
static void bpf_destroy_state(struct lwtunnel_state *lwt)
{
    struct bpf_lwt *bpf = bpf_lwt_lwtunnel(lwt);
    bpf_lwt_prog_destroy(&bpf->in);
    bpf_lwt_prog_destroy(&bpf->out);
    bpf_lwt_prog_destroy(&bpf->xmit);
}
```

`bpf_lwt_prog_destroy` 函数释放`lwt_bpf`程序，如下：

```C
// file: net/core/lwt_bpf.c
static void bpf_lwt_prog_destroy(struct bpf_lwt_prog *prog)
{
    if (prog->prog)
        bpf_prog_put(prog->prog);
    kfree(prog->name);
}
```

#### (3) bpf_input路由封装实现

##### 1 运行bpf程序

在input路由封装(`lwtunnel_input`)中调用`.input`封装接口，`bpf_encap_ops`的`.input`接口设置为`bpf_input`，实现如下：

```C
// file: net/core/lwt_bpf.c
static int bpf_input(struct sk_buff *skb)
{
    struct dst_entry *dst = skb_dst(skb);
    struct bpf_lwt *bpf;
    int ret;

    bpf = bpf_lwt_lwtunnel(dst->lwtstate);
    if (bpf->in.prog) {
        // 运行lwt_bpf程序，不支持skb重定向
        ret = run_lwt_bpf(skb, &bpf->in, dst, NO_REDIRECT);
        // 出现错误时，返回
        if (ret < 0) return ret;
        if (ret == BPF_LWT_REROUTE)
            // 重新路由
            return bpf_lwt_input_reroute(skb);
    }
    // 原始输入接口不存在时，释放skb后返回
    if (unlikely(!dst->lwtstate->orig_input)) {
        kfree_skb(skb);
        return -EINVAL;
    }
    // 调用原始输入接口
    return dst->lwtstate->orig_input(skb);
}
```

`run_lwt_bpf`函数运行lwt_bpf程序，实现如下：

```C
// file: net/core/lwt_bpf.c
static int run_lwt_bpf(struct sk_buff *skb, struct bpf_lwt_prog *lwt,
        struct dst_entry *dst, bool can_redirect)
{
    int ret;

    // 禁用`Migration`和`BH`，用来保护`redirect_info` per-cpu变量
    migrate_disable();
    local_bh_disable();
    bpf_compute_data_pointers(skb);
    // 运行bpf程序
    ret = bpf_prog_run_save_cb(lwt->prog, skb); 
    switch (ret) {
    case BPF_OK:
    case BPF_LWT_REROUTE:
        // 返回值为`OK`和`LWT_REROUTE`时返回
        break;
    case BPF_REDIRECT:
        // 返回值为`REDIRECT`时
        if (unlikely(!can_redirect)) {
            // 不支持重定向时，记录日志信息，返回`OK`
            pr_warn_once("Illegal redirect return code in prog %s\n", lwt->name ? : "<unknown>");
            ret = BPF_OK;
        } else {
            // 支持重定向时，进行skb重定向
            skb_reset_mac_header(skb);
            ret = skb_do_redirect(skb);
            if (ret == 0) ret = BPF_REDIRECT;
        }
        break;
    case BPF_DROP:
        // 返回值为`DROP`时，释放skb
        kfree_skb(skb);
        ret = -EPERM; 
        break;
    default:
        // 其他值时，记录日志信息，释放skb
        pr_warn_once("bpf-lwt: Illegal return value %u, expect packet loss\n", ret);
        kfree_skb(skb);
        ret = -EINVAL;
        break;
    }
    local_bh_enable();
    migrate_enable();
    return ret;
}
```

##### 2 input重新路由处理

在运行`in_lwt_bpf`程序后，返回值为`BPF_LWT_REROUTE`时，需要重新设置路由信息后进行路由输入处理，实现如下：

```C
// file: net/core/lwt_bpf.c
static int bpf_lwt_input_reroute(struct sk_buff *skb)
{
    int err = -EINVAL;
    if (skb->protocol == htons(ETH_P_IP)) {
        // ipv4协议时，清除之前的路由信息后，重新设置input路由
        struct net_device *dev = skb_dst(skb)->dev;
        struct iphdr *iph = ip_hdr(skb);
        dev_hold(dev);
        skb_dst_drop(skb);
        // 确定输入路由
        err = ip_route_input_noref(skb, iph->daddr, iph->saddr, iph->tos, dev);
        dev_put(dev);
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        // ipv6协议时，清除之前的路由信息后，重新设置input路由
        skb_dst_drop(skb);
        err = ipv6_stub->ipv6_route_input(skb);
    } else {
        // 不支持其他协议
        err = -EAFNOSUPPORT;
    }
    // 出现错误时，释放skb
    if (err) goto err;
    // 路由输入处理
    return dst_input(skb);
err:
    kfree_skb(skb);
    return err;
}
```

#### (4) bpf_output路由封装实现

在output路由封装(`lwtunnel_output`)中调用`.output`封装接口， `bpf_encap_ops`的`.output`接口设置为`bpf_output`，实现如下：

```C
// file: net/core/lwt_bpf.c
static int bpf_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct dst_entry *dst = skb_dst(skb);
    struct bpf_lwt *bpf;
    int ret;

    bpf = bpf_lwt_lwtunnel(dst->lwtstate);
    if (bpf->out.prog) {
        // 运行lwt_bpf程序，不支持skb重定向
        ret = run_lwt_bpf(skb, &bpf->out, dst, NO_REDIRECT);
        if (ret < 0) return ret;
    }

    // 原始输出接口不存在时，记录日志信息后，释放skb后返回
    if (unlikely(!dst->lwtstate->orig_output)) {
        pr_warn_once("orig_output not set on dst for prog %s\n", bpf->out.name);
        kfree_skb(skb);
        return -EINVAL;
    }
    // 调用原始输出接口
    return dst->lwtstate->orig_output(net, sk, skb);
}
```

#### (5) bpf_xmit路由封装实现

##### 1 运行bpf程序

在`ip[6]_finish_output2`发送L3网络数据包的过程中，在路由传输(`lwtunnel_xmit`)中调用`.xmit`封装接口，`bpf_encap_ops`的`.xmit`接口设置为`bpf_xmit`，实现如下：

```C
// file: net/core/lwt_bpf.c
static int bpf_xmit(struct sk_buff *skb)
{
    struct dst_entry *dst = skb_dst(skb);
    struct bpf_lwt *bpf;

    bpf = bpf_lwt_lwtunnel(dst->lwtstate);
    if (bpf->xmit.prog) {
        // 记录skb硬件头部长度和协议类型
        int hh_len = dst->dev->hard_header_len;
        __be16 proto = skb->protocol;
        int ret;
        // 运行lwt_bpf程序，支持skb重定向
        ret = run_lwt_bpf(skb, &bpf->xmit, dst, CAN_REDIRECT);
        switch (ret) {
        case BPF_OK:
            // 修改头部协议后，释放skb，返回错误
            if (skb->protocol != proto) { kfree_skb(skb); return -EINVAL; }
            // 扩展L2头部信息时，检查L2头部空间是否足够，不足时扩展
            ret = xmit_check_hhlen(skb, hh_len);
            if (unlikely(ret)) return ret;
            // 返回`XMIT_CONTINUE`，继续后续处理
            return LWTUNNEL_XMIT_CONTINUE;
        case BPF_REDIRECT:
            // 返回值`REDIRECT`，表示传输完成
            return LWTUNNEL_XMIT_DONE;
        case BPF_LWT_REROUTE:
            // 传输时重定向路由
            return bpf_lwt_xmit_reroute(skb);
        default:
            return ret;
        }
    }
    // 默认值为L3层后处理
    return LWTUNNEL_XMIT_CONTINUE;
}
```

##### 2 重定向skb

在运行xmit bpf程序后，返回值为`BPF_REDIRECT`时，通过`skb_do_redirect`函数实现重定向。具体实现过程参见[TC的内核实现](./14-tc.md)相关章节。


##### 3 xmit重新路由处理

返回值为`BPF_LWT_REROUTE`时，调用`bpf_lwt_xmit_reroute`重新设置xmit路由，如下:

```C
// file: net/core/lwt_bpf.c
static int bpf_lwt_xmit_reroute(struct sk_buff *skb)
{
    struct net_device *l3mdev = l3mdev_master_dev_rcu(skb_dst(skb)->dev);
    int oif = l3mdev ? l3mdev->ifindex : 0;
    struct dst_entry *dst = NULL;
    int err = -EAFNOSUPPORT;
    struct sock *sk;
    struct net *net;
    bool ipv4;
    
    // 检查时ipv4还是ipv6，两者都不是时返回
    if (skb->protocol == htons(ETH_P_IP)) ipv4 = true;
    else if (skb->protocol == htons(ETH_P_IPV6)) ipv4 = false;
    else goto err;

    // 获取网络命名空间，获取完全连接sk
    sk = sk_to_full_sk(skb->sk);
    if (sk) {
        // sk存在时获取sk的网络命名空间和绑定的网卡
        if (sk->sk_bound_dev_if) oif = sk->sk_bound_dev_if;
        net = sock_net(sk);
    } else {
        // 使用路由的网络命名空间
        net = dev_net(skb_dst(skb)->dev);
    }
    // 确定ipv4或ipv6输出路由信息
    if (ipv4) {
        struct iphdr *iph = ip_hdr(skb);
        struct flowi4 fl4 = {};
        struct rtable *rt;
        // 设置ipv4路由查找信息
        fl4.flowi4_oif = oif;
        fl4.flowi4_mark = skb->mark;
        fl4.flowi4_uid = sock_net_uid(net, sk);
        fl4.flowi4_tos = RT_TOS(iph->tos);
        fl4.flowi4_flags = FLOWI_FLAG_ANYSRC;
        fl4.flowi4_proto = iph->protocol;
        fl4.daddr = iph->daddr;
        fl4.saddr = iph->saddr;
        // 获取ipv4输出路由，调用`ip_route_output_flow`
        rt = ip_route_output_key(net, &fl4);
        // 路由信息不存在时，释放skb，返回错误
        if (IS_ERR(rt)) { err = PTR_ERR(rt); goto err; }
        dst = &rt->dst;
    } else {
        struct ipv6hdr *iph6 = ipv6_hdr(skb);
        struct flowi6 fl6 = {};
        fl6.flowi6_oif = oif;
        fl6.flowi6_mark = skb->mark;
        fl6.flowi6_uid = sock_net_uid(net, sk);
        fl6.flowlabel = ip6_flowinfo(iph6);
        fl6.flowi6_proto = iph6->nexthdr;
        fl6.daddr = iph6->daddr;
        fl6.saddr = iph6->saddr;
        // 获取ipv6输出路由
        dst = ipv6_stub->ipv6_dst_lookup_flow(net, skb->sk, &fl6, NULL);
        if (IS_ERR(dst)) { err = PTR_ERR(dst); goto err; }
    }
    // 路由信息存在错误时，释放skb，返回错误
    if (unlikely(dst->error)) {
        err = dst->error;
        dst_release(dst);
        goto err;
    }
    // 调用`bpf_lwt_push_ip_encap`时保留了skb头部信息，这里重新设置了路由信息，因此需要重新检查空间是否足够
    err = skb_cow_head(skb, LL_RESERVED_SPACE(dst->dev));
    if (unlikely(err)) goto err;

    // 丢弃之前的路由信息，设置新的路由新
    skb_dst_drop(skb);
    skb_dst_set(skb, dst);
    
    // 进行路由输出处理
    err = dst_output(dev_net(skb_dst(skb)->dev), skb->sk, skb);
    if (unlikely(err)) return err;

    // 传输完成，`ip[6]_finish_output2`不进行后续处理
    return LWTUNNEL_XMIT_DONE;
err:
    // 错误时释放skb，返回错误码
    kfree_skb(skb);
    return err;
}
```

### 4.6 `lwt_seg6local`路由封装的实现

使用`seg6local`设置的封装信息，在内核中对应`seg6_local_ops`路由封装类型。如下：

```C
// file: net/ipv6/seg6_local.c
static const struct lwtunnel_encap_ops seg6_local_ops = {
    .build_state    = seg6_local_build_state,
    .destroy_state  = seg6_local_destroy_state,
    .input          = seg6_local_input,
    .fill_encap     = seg6_local_fill_encap,
    .get_encap_size = seg6_local_get_encap_size,
    .cmp_encap      = seg6_local_cmp_encap,
    .owner          = THIS_MODULE,
};
```

在`module_init`阶段初始化inet6网络协议栈过程中初始化的，如下：

```C
// file: net/ipv6/af_inet6.c
static int __init inet6_init(void)
    --> err = seg6_init();
        --> err = seg6_local_init();
            --> return lwtunnel_encap_add_ops(&seg6_local_ops, LWTUNNEL_ENCAP_SEG6_LOCAL);
...
module_init(inet6_init);
```

#### (1) 创建seg6local路由封装

##### 1 创建封装状态接口

`seg6_local_ops`的`.build_state`接口设置为`seg6_local_build_state`，在通过netlink添加路由时创建路由封装状态。如下：

```C
// file：net/ipv6/seg6_local.c
static int seg6_local_build_state(struct net *net, struct nlattr *nla, unsigned int family, 
            const void *cfg, struct lwtunnel_state **ts, struct netlink_ext_ack *extack)
{
    struct nlattr *tb[SEG6_LOCAL_MAX + 1];
    struct lwtunnel_state *newts;
    struct seg6_local_lwt *slwt;
    int err;

    // seg6local只支持INET6
    if (family != AF_INET6) return -EINVAL;
    // 解析netlink请求
    err = nla_parse_nested_deprecated(tb, SEG6_LOCAL_MAX, nla, seg6_local_policy, extack);
    if (err < 0) return err;
    // 必须存在`SEG6_LOCAL_ACTION`属性
    if (!tb[SEG6_LOCAL_ACTION]) return -EINVAL;

    // 创建路由封装状态
    newts = lwtunnel_state_alloc(sizeof(*slwt));
    if (!newts) return -ENOMEM;
    slwt = seg6_local_lwtunnel(newts);
    // 解析action
    slwt->action = nla_get_u32(tb[SEG6_LOCAL_ACTION]);
    err = parse_nla_action(tb, slwt, extack);
    if (err < 0) goto out_free;
    // seg6local生成路由封装状态
    err = seg6_local_lwtunnel_build_state(slwt, cfg, extack);
    if (err < 0) goto out_destroy_attrs;
    // 属性设置
    newts->type = LWTUNNEL_ENCAP_SEG6_LOCAL;
    newts->flags = LWTUNNEL_STATE_INPUT_REDIRECT;
    newts->headroom = slwt->headroom;

    // 设置返回结果
    *ts = newts;
    return 0;

out_destroy_attrs:
    destroy_attrs(slwt);
out_free:
    kfree(newts);
    return err;
}
```

##### 2 解析封装操作

`seg6local`支持多种方式的`action`，定义如下：

```C
// file: include/uapi/linux/seg6_local.h
enum {
    SEG6_LOCAL_ACTION_UNSPEC    = 0,
    /* node segment */
    SEG6_LOCAL_ACTION_END       = 1,
    ...
    /* custom BPF action */
    SEG6_LOCAL_ACTION_END_BPF   = 15,
    /* decap and lookup of DA in v4 or v6 table */
    SEG6_LOCAL_ACTION_END_DT46  = 16,
    __SEG6_LOCAL_ACTION_MAX,
};
#define SEG6_LOCAL_ACTION_MAX (__SEG6_LOCAL_ACTION_MAX - 1)
```

每个action对应一种处理方式，以action描述信息表示，定义如下：

```C
// file: net/ipv6/seg6_local.c
static struct seg6_action_desc seg6_action_table[] = {
    {
        .action     = SEG6_LOCAL_ACTION_END,
        .attrs      = 0,
        .optattrs   = SEG6_F_LOCAL_COUNTERS | SEG6_F_ATTR(SEG6_LOCAL_FLAVORS),
        .input      = input_action_end,
    },
    ...
    {
        .action     = SEG6_LOCAL_ACTION_END_BPF,
        .attrs      = SEG6_F_ATTR(SEG6_LOCAL_BPF),
        .optattrs   = SEG6_F_LOCAL_COUNTERS,
        .input      = input_action_end_bpf,
    },
};
```

`parse_nla_action` 函数解析设置的action，实现如下：

```C
// file：net/ipv6/seg6_local.c
static int parse_nla_action(struct nlattr **attrs, struct seg6_local_lwt *slwt, struct netlink_ext_ack *extack)
{
    struct seg6_action_param *param;
    struct seg6_action_desc *desc;
    unsigned long invalid_attrs;
    int i, err;

    // 获取action描述符，从`seg6_action_table`中获取
    desc = __get_action_desc(slwt->action);
    // action描述符不存在或在不支持input时，返回错误
    if (!desc) return -EINVAL;
    if (!desc->input) return -EOPNOTSUPP;

    slwt->desc = desc;
    slwt->headroom += desc->static_headroom;

    // 检查desc的必须属性和可选属性设置，不能同时包含同一属性
    invalid_attrs = desc->attrs & desc->optattrs;
    if (invalid_attrs) { return -EINVAL; }

    // 解析必须的属性
    for (i = SEG6_LOCAL_SRH; i < SEG6_LOCAL_MAX + 1; i++) {
        if (desc->attrs & SEG6_F_ATTR(i)) {
            if (!attrs[i]) return -EINVAL;
            // `seg6_action_params[]`表示所有的属性参数
            param = &seg6_action_params[i];
            err = param->parse(attrs, slwt, extack);
            if (err < 0) goto parse_attrs_err;
        }
    }
    // 解析可选的属性设置，同样通过`seg6_action_params[]`解析
    err = parse_nla_optional_attrs(attrs, slwt, extack);
    if (err < 0) goto parse_attrs_err;

    return 0;
parse_attrs_err:
    // 解析失败时，销毁属性设置
    __destroy_attrs(desc->attrs, i, slwt);
    return err;
}
```

`seg6_action_params[]` 变量存放`seg6local`支持的属性信息，如下：

```C
// file：net/ipv6/seg6_local.c
static struct seg6_action_param seg6_action_params[SEG6_LOCAL_MAX + 1] = {
    [SEG6_LOCAL_SRH] = { .parse = parse_nla_srh, .put = put_nla_srh,
                        .cmp = cmp_nla_srh, .destroy = destroy_attr_srh },
    ...
    [SEG6_LOCAL_BPF] = { .parse = parse_nla_bpf, .put = put_nla_bpf,
                        .cmp = cmp_nla_bpf, .destroy = destroy_attr_bpf },
    ...
};
```

使用`SEG6_LOCAL_BPF`时，对应的解析方式为`parse_nla_bpf`，实现如下：

```C
// file：net/ipv6/seg6_local.c
static int parse_nla_bpf(struct nlattr **attrs, struct seg6_local_lwt *slwt, struct netlink_ext_ack *extack)
{
    struct nlattr *tb[SEG6_LOCAL_BPF_PROG_MAX + 1];
    struct bpf_prog *p;
    int ret;
    u32 fd;

    // 解析netlink请求
    ret = nla_parse_nested_deprecated(tb, SEG6_LOCAL_BPF_PROG_MAX, attrs[SEG6_LOCAL_BPF], bpf_prog_policy, NULL);
    if (ret < 0) return ret;
    // `BPF_PROG` 和 `BPF_PROG_NAME` 属性必须存在
    if (!tb[SEG6_LOCAL_BPF_PROG] || !tb[SEG6_LOCAL_BPF_PROG_NAME]) return -EINVAL;

    // 获取bpf程序名称
    slwt->bpf.name = nla_memdup(tb[SEG6_LOCAL_BPF_PROG_NAME], GFP_KERNEL);
    if (!slwt->bpf.name) return -ENOMEM;
    // 获取bpf程序
    fd = nla_get_u32(tb[SEG6_LOCAL_BPF_PROG]);
    p = bpf_prog_get_type(fd, BPF_PROG_TYPE_LWT_SEG6LOCAL);
    if (IS_ERR(p)) { kfree(slwt->bpf.name); return PTR_ERR(p); }
    // 设置bpf程序
    slwt->bpf.prog = p;
    return 0;
}
```

##### 3 构建封装状态

`seg6_local_lwtunnel_build_state` 函数在解析`action`后，构建`action`自定义的构造操作，如下：

```C
// file：net/ipv6/seg6_local.c
static int seg6_local_lwtunnel_build_state(struct seg6_local_lwt *slwt, const void *cfg, struct netlink_ext_ack *extack)
{
    struct seg6_action_desc *desc = slwt->desc;
    struct seg6_local_lwtunnel_ops *ops;

    // 获取ops，存在`build_state`接口时调用
    ops = &desc->slwt_ops;
    if (!ops->build_state) return 0;
    return ops->build_state(slwt, cfg, extack);
}
```

`SEG6_LOCAL_ACTION_END_BPF`没有设置`build_state`接口。

#### (2) 释放seg6local路由封装

##### 1 释放封装状态接口

`seg6_local_ops`的`.destroy_state`接口设置为`seg6_local_destroy_state`，在删除路由时释放路由封装。如下：

```C
// file: net/ipv6/seg6_local.c
static void seg6_local_destroy_state(struct lwtunnel_state *lwt)
{
    struct seg6_local_lwt *slwt = seg6_local_lwtunnel(lwt);
    // 销毁封装状态和属性
    seg6_local_lwtunnel_destroy_state(slwt);
    destroy_attrs(slwt);
    return;
}
```

##### 2 释放封装状态

`seg6_local_lwtunnel_destroy_state` 函数释放`action`的封装状态，如下：

```C
// file: net/ipv6/seg6_local.c
static void seg6_local_lwtunnel_destroy_state(struct seg6_local_lwt *slwt)
{
    struct seg6_action_desc *desc = slwt->desc;
    struct seg6_local_lwtunnel_ops *ops;

    // 获取ops，存在`destroy_state`接口时调用
    ops = &desc->slwt_ops;
    if (!ops->destroy_state) return;
    ops->destroy_state(slwt);
}
```

`SEG6_LOCAL_ACTION_END_BPF`没有设置`destroy_state`接口。

##### 3 释放封装操作

`destroy_attrs` 函数释放设置的属性信息，实现如下：

```C
// file: net/ipv6/seg6_local.c
static void destroy_attrs(struct seg6_local_lwt *slwt)
{
    // 必须的属性和可选的属性
    unsigned long attrs = slwt->desc->attrs | slwt->parsed_optattrs;
    __destroy_attrs(attrs, SEG6_LOCAL_MAX + 1, slwt);
}
// file: net/ipv6/seg6_local.c
static void __destroy_attrs(unsigned long parsed_attrs, int max_parsed, struct seg6_local_lwt *slwt)
{
    struct seg6_action_param *param;
    int i;
    for (i = SEG6_LOCAL_SRH; i < max_parsed; ++i) {
        if (!(parsed_attrs & SEG6_F_ATTR(i))) continue;
        // 获取属性后，调用销毁接口
        param = &seg6_action_params[i];
        if (param->destroy) param->destroy(slwt);
    }
}
```

使用`SEG6_LOCAL_BPF`时，对应的销毁方式为`destroy_attr_bpf`，释放bpf程序名称和程序，实现如下：

```C
// file：net/ipv6/seg6_local.c
static void destroy_attr_bpf(struct seg6_local_lwt *slwt)
{
    kfree(slwt->bpf.name);
    if (slwt->bpf.prog) 
        bpf_prog_put(slwt->bpf.prog);
}
```

#### (3) seg6local_input路由封装实现

##### 1 `seg6local_input`封装接口

在input路由封装(`lwtunnel_input`)中调用`.input`封装接口，`seg6_local_ops`的`.input`接口设置为`seg6_local_input`，实现如下：

```C
// file：net/ipv6/seg6_local.c
static int seg6_local_input(struct sk_buff *skb)
{
    // 不是IPV6时，释放skb，返回错误
    if (skb->protocol != htons(ETH_P_IPV6)) { kfree_skb(skb); return -EINVAL; }

    // 进行NF_HOOK检查，在`/proc/sys/net/netfilter/nf_hooks_lwtunnel`文件在设置状态
    if (static_branch_unlikely(&nf_hooks_lwtunnel_enabled))
        return NF_HOOK(NFPROTO_IPV6, NF_INET_LOCAL_IN, dev_net(skb->dev), NULL, 
                        skb, skb->dev, NULL, seg6_local_input_core);

    return seg6_local_input_core(dev_net(skb->dev), NULL, skb);
}
```

`seg6_local_input_core` 实现核心的输入实现，调用`action->input`接口，如下：

```C
// file：net/ipv6/seg6_local.c
static int seg6_local_input_core(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct dst_entry *orig_dst = skb_dst(skb);
    unsigned int len = skb->len;
    ...

    slwt = seg6_local_lwtunnel(orig_dst->lwtstate);
    desc = slwt->desc;
    // 调用action的input接口
    rc = desc->input(skb, slwt);
    
    // 检查计数器开启状态，开启时，统计`seg6local`路由封装状态信息
    if (!seg6_lwtunnel_counters_enabled(slwt)) return rc;
    seg6_local_update_counters(slwt, len, rc);
    return rc;
}
```

##### 2 运行seg6local_bpf程序

使用`SEG6_LOCAL_BPF`时，设置的`.input`接口为`input_action_end_bpf`，实现如下：

```C
// file：net/ipv6/seg6_local.c
static int input_action_end_bpf(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
    struct seg6_bpf_srh_state *srh_state = this_cpu_ptr(&seg6_bpf_srh_states);
    struct ipv6_sr_hdr *srh;
    int ret;

    // 获取IPV6头部信息中的`IPPROTO_ROUTING`选项，不存在时释放skb后返回错误
    srh = get_and_validate_srh(skb);
    if (!srh) { kfree_skb(skb); return -EINVAL; }
    // 获取目的地址，移动srh到下一段
    advance_nextseg(srh, &ipv6_hdr(skb)->daddr);

    // 禁用抢占，保护`bpf_lwt_seg6_*`帮助函数中获取`srh_state` per-cpu状态
    preempt_disable();
    srh_state->srh = srh;
    srh_state->hdrlen = srh->hdrlen << 3;
    srh_state->valid = true;

    rcu_read_lock();
    // 计算skb中数据位置后，运行bpf程序
    bpf_compute_data_pointers(skb);
    ret = bpf_prog_run_save_cb(slwt->bpf.prog, skb);
    rcu_read_unlock();

    switch (ret) {
    case BPF_OK: case BPF_REDIRECT: break;
    // 返回值DROP，丢弃skb
    case BPF_DROP: goto drop;
    default:
        // 其他返回值，记录日志信息后，丢弃skb
        pr_warn_once("bpf-seg6local: Illegal return value %u\n", ret);
        goto drop;
    }
    // 存在srh时，检查srh是否有效，无效时丢弃skb
    if (srh_state->srh && !seg6_bpf_has_valid_srh(skb)) goto drop;

    preempt_enable();
    // 返回值不需要重定向时，检查下一跳路由
    if (ret != BPF_REDIRECT)
        seg6_lookup_nexthop(skb, NULL, 0);
    // 路由输入处理
    return dst_input(skb);
drop:
    // 丢弃skb时，释放skb后返回
    preempt_enable();
    kfree_skb(skb);
    return -EINVAL;
}
```

##### 3 获取下一跳路由

在返回值为`BPF_OK`，获取下一跳路由信息，`seg6_lookup_nexthop`函数实现该功能，如下：

```C
// file：net/ipv6/seg6_local.c
int seg6_lookup_nexthop(struct sk_buff *skb, struct in6_addr *nhaddr, u32 tbl_id)
{
    return seg6_lookup_any_nexthop(skb, nhaddr, tbl_id, false);
}
```

`seg6_lookup_any_nexthop` 函数实现任意下一跳路由的查找，实现如下：

```C
// file：net/ipv6/seg6_local.c
static int seg6_lookup_any_nexthop(struct sk_buff *skb, struct in6_addr *nhaddr, u32 tbl_id, bool local_delivery)
{
    struct net *net = dev_net(skb->dev);
    struct ipv6hdr *hdr = ipv6_hdr(skb);
    int flags = RT6_LOOKUP_F_HAS_SADDR;
    struct dst_entry *dst = NULL;
    struct rt6_info *rt;
    struct flowi6 fl6;
    int dev_flags = 0;

    // 设置ipv6路由查找信息
    memset(&fl6, 0, sizeof(fl6));
    fl6.flowi6_iif = skb->dev->ifindex;
    fl6.daddr = nhaddr ? *nhaddr : hdr->daddr;
    fl6.saddr = hdr->saddr;
    fl6.flowlabel = ip6_flowinfo(hdr);
    fl6.flowi6_mark = skb->mark;
    fl6.flowi6_proto = hdr->nexthdr;
    // 指定下一跳地址时，设置标记
    if (nhaddr) fl6.flowi6_flags = FLOWI_FLAG_KNOWN_NH;

    if (!tbl_id) {
        // 不指定路由表时，从所有的路由表中获取
        dst = ip6_route_input_lookup(net, skb->dev, &fl6, skb, flags);
    } else {
        // 指定路由表时，从指定的路由表中获取
        struct fib6_table *table;
        table = fib6_get_table(net, tbl_id);
        if (!table) goto out;
        // 从指定路由中获取
        rt = ip6_pol_route(net, table, 0, &fl6, skb, flags);
        dst = &rt->dst;
    }
    // loopback设置
    if (!local_delivery) dev_flags |= IFF_LOOPBACK;

    // 网卡设备的flags 和 dev_flags 不匹配时，表示无路由
    if (dst && (dst->dev->flags & dev_flags) && !dst->error) { 
        dst_release(dst); dst = NULL; 
    }

out:
    // 路由信息不存在时，设置ipv6的黑洞路由
    if (!dst) {
        rt = net->ipv6.ip6_blk_hole_entry;
        dst = &rt->dst;
        dst_hold(dst);
    }
    // 丢弃之前的路由，设置新的路由
    skb_dst_drop(skb);
    skb_dst_set(skb, dst);
    return dst->error;
}
```

## 5 内核实现--ipv6

### 5.1 ipv6添加路由

#### (1) `netlink`接口

`ip -6 route add` 命令向Linux内核中添加一条路由信息，对应 `PF_INET6:RTM_NEWROUTE` 类型的netlink接口，在内核中处理如下：

```C
// file: net/ipv6/route.c
int __init ip6_route_init(void)
{
    ...
    ret = rtnl_register_module(THIS_MODULE, PF_INET6, RTM_NEWROUTE, inet6_rtm_newroute, NULL, 0);
    ret = rtnl_register_module(THIS_MODULE, PF_INET6, RTM_DELROUTE, inet6_rtm_delroute, NULL, 0);
    ret = rtnl_register_module(THIS_MODULE, PF_INET6, RTM_GETROUTE, inet6_rtm_getroute, NULL, 
            RTNL_FLAG_DOIT_UNLOCKED);
    ...
}
```

在`module_init(inet6_init)`阶段初始化ipv6网络协议过程中进行初始化，如下：

```C
// file: net/ipv6/af_inet6.c
static int __init inet6_init(void)
{
    ...
    err = ip6_route_init();
    if (err) goto ip6_route_fail;
    ...
}
```

`inet6_rtm_newroute` 函数解析netlink请求信息后，添加到路由表中，如下：

```C
// file: net/ipv6/route.c
static int inet6_rtm_newroute(struct sk_buff *skb, struct nlmsghdr *nlh, struct netlink_ext_ack *extack)
{
    struct fib6_config cfg;
    int err;
    // 解析netlink请求，转换为`fib6_config`配置信息
    err = rtm_to_fib6_config(skb, nlh, &cfg, extack);
    if (err < 0) return err;

    if (cfg.fc_metric == 0) cfg.fc_metric = IP6_RT_PRIO_USER;

    if (cfg.fc_mp)
        // 添加多路径路由
        return ip6_route_multipath_add(&cfg, extack);
    else
        // 添加路由信息
        return ip6_route_add(&cfg, GFP_KERNEL, extack);
}
```

#### (2) 添加路由信息

`ip6_route_add` 函数添加路由信息，如下：

```C
// file: net/ipv6/route.c
int ip6_route_add(struct fib6_config *cfg, gfp_t gfp_flags, struct netlink_ext_ack *extack)
{
    struct fib6_info *rt;
    int err;
    // 创建路由信息
    rt = ip6_route_info_create(cfg, gfp_flags, extack);
    if (IS_ERR(rt)) return PTR_ERR(rt);

    // 插入路由信息
    err = __ip6_ins_rt(rt, &cfg->fc_nlinfo, extack);
    fib6_info_release(rt);
    return err;
}
```

`ip6_route_info_create` 函数创建路由信息，如下：

```C
// file: net/ipv6/route.c
static struct fib6_info *ip6_route_info_create(struct fib6_config *cfg, gfp_t gfp_flags, struct netlink_ext_ack *extack)
{
    struct net *net = cfg->fc_nlinfo.nl_net;
    struct fib6_info *rt = NULL;
    struct nexthop *nh = NULL;
    struct fib6_table *table;
    struct fib6_nh *fib6_nh;
    int err = -EINVAL;
    int addr_type;

    // `RTF_PCPU`和`RTF_CACHE`是内部标记
    if (cfg->fc_flags & RTF_PCPU) { ... }
    if (cfg->fc_flags & RTF_CACHE) { ... }
    // 输入参数检查
    if (cfg->fc_type > RTN_MAX) { ... }
    if (cfg->fc_dst_len > 128) { ... }
    if (cfg->fc_src_len > 128) { ... }
    if (cfg->fc_src_len) { ... }

    if (cfg->fc_nh_id) {
        // 下一跳检查
        nh = nexthop_find_by_id(net, cfg->fc_nh_id);
        if (!nh) { ... }
        err = fib6_check_nexthop(nh, cfg, extack);
        if (err) goto out;
    }

    err = -ENOBUFS;
    // 获取路由表，不存在时创建
    if (cfg->fc_nlinfo.nlh && !(cfg->fc_nlinfo.nlh->nlmsg_flags & NLM_F_CREATE)) {
        // 获取路由表，默认`RT6_TABLE_MAIN`，从`ipv6.fib_table_hash`中获取
        table = fib6_get_table(net, cfg->fc_table);
        if (!table) {
            // 不存在时，创建路由表，添加到`ipv6.fib_table_hash`中
            table = fib6_new_table(net, cfg->fc_table);
        }
    } else {
        table = fib6_new_table(net, cfg->fc_table);
    }
    // 获取路由表失败时，返回
    if (!table) goto out;

    err = -ENOMEM;
    // 分配路由信息
    rt = fib6_info_alloc(gfp_flags, !nh);
    if (!rt) goto out;

    // 路由指标信息初始化，默认`dst_default_metrics`
    rt->fib6_metrics = ip_fib_metrics_init(net, cfg->fc_mx, cfg->fc_mx_len, extack);
    if (IS_ERR(rt->fib6_metrics)) { ...  }

    if (cfg->fc_flags & RTF_ADDRCONF) rt->dst_nocount = true;

    // 路由过期时间设置
    if (cfg->fc_flags & RTF_EXPIRES)
        fib6_set_expires(rt, jiffies + clock_t_to_jiffies(cfg->fc_expires));
    else
        fib6_clean_expires(rt);

    // 路由信息设置，如：协议、路由表等
    if (cfg->fc_protocol == RTPROT_UNSPEC) cfg->fc_protocol = RTPROT_BOOT;
    rt->fib6_protocol = cfg->fc_protocol;

    rt->fib6_table = table;
    rt->fib6_metric = cfg->fc_metric;
    rt->fib6_type = cfg->fc_type ? : RTN_UNICAST;
    rt->fib6_flags = cfg->fc_flags & ~RTF_GATEWAY;

    // 目的地址前缀设置
    ipv6_addr_prefix(&rt->fib6_dst.addr, &cfg->fc_dst, cfg->fc_dst_len);
    rt->fib6_dst.plen = cfg->fc_dst_len;
    // 源地址前缀设置
    ipv6_addr_prefix(&rt->fib6_src.addr, &cfg->fc_src, cfg->fc_src_len);
    rt->fib6_src.plen = cfg->fc_src_len;

    if (nh) {
        // nexthop存在时，检查和设置
        if (rt->fib6_src.plen) { ... }
        if (!nexthop_get(nh)) { ... }
        rt->nh = nh;
        fib6_nh = nexthop_fib6_nh(rt->nh);
    } else {
        // 下一跳路由初始化
        err = fib6_nh_init(net, rt->fib6_nh, cfg, gfp_flags, extack);
        if (err) goto out;
        fib6_nh = rt->fib6_nh;
        // loopback路由时，拒绝
        addr_type = ipv6_addr_type(&cfg->fc_dst);
        if (fib6_is_reject(cfg->fc_flags, rt->fib6_nh->fib_nh_dev, addr_type))
            rt->fib6_flags = RTF_REJECT | RTF_NONEXTHOP;
    }
    if (!ipv6_addr_any(&cfg->fc_prefsrc)) {
        // 指定源地址时设置
        struct net_device *dev = fib6_nh->fib_nh_dev;
        // 检查源地址是否正确
        if (!ipv6_chk_addr(net, &cfg->fc_prefsrc, dev, 0)) { ... }
        rt->fib6_prefsrc.addr = cfg->fc_prefsrc;
        rt->fib6_prefsrc.plen = 128;
    } else
        rt->fib6_prefsrc.plen = 0;

    return rt;
out:
    fib6_info_release(rt);
    return ERR_PTR(err);
out_free:
    ip_fib_metrics_put(rt->fib6_metrics);
    kfree(rt);
    return ERR_PTR(err);
}
```

`fib6_nh_init` 函数初始化下一跳路由信息，如下：

```C
// file: net/ipv6/route.c
int fib6_nh_init(struct net *net, struct fib6_nh *fib6_nh, struct fib6_config *cfg, gfp_t gfp_flags,
        struct netlink_ext_ack *extack)
{
    struct net_device *dev = NULL;
    struct inet6_dev *idev = NULL;
    int addr_type;
    int err;

    // 路由协议设置
    fib6_nh->fib_nh_family = AF_INET6;
    // 开启路由分析时，上次检测时间设置
    fib6_nh->last_probe = jiffies;
        
    if (cfg->fc_is_fdb) {
        // 网桥路由时，设置网关地址
        fib6_nh->fib_nh_gw6 = cfg->fc_gateway;
        fib6_nh->fib_nh_gw_family = AF_INET6;
        return 0;
    }
    err = -ENODEV;
    // 指定网卡设备时，获取对应的网卡设备
    if (cfg->fc_ifindex) {
        dev = dev_get_by_index(net, cfg->fc_ifindex);
        if (!dev) goto out;
        idev = in6_dev_get(dev);
        if (!idev) goto out;
    }
    // nexthop onlink标记设置，需要网卡设备存在且在线
    if (cfg->fc_flags & RTNH_F_ONLINK) {
        if (!dev) { ... }
        if (!(dev->flags & IFF_UP)) { ... }
        fib6_nh->fib_nh_flags |= RTNH_F_ONLINK;
    }
    // 路由权重设置
    fib6_nh->fib_nh_weight = 1;

    // loopback路由检查
    addr_type = ipv6_addr_type(&cfg->fc_dst);
    if (fib6_is_reject(cfg->fc_flags, dev, addr_type)) {
        // 拒绝路由时，设置为loopback设备
        if (dev != net->loopback_dev) {
            if (dev) { dev_put(dev); in6_dev_put(idev); }
            // 设置为loopback_dev
            dev = net->loopback_dev;
            dev_hold(dev);
            idev = in6_dev_get(dev);
            if (!idev) { err = -ENODEV; goto out; }
        }
        goto pcpu_alloc;
    }
    // 网关路由设置
    if (cfg->fc_flags & RTF_GATEWAY) {
        err = ip6_validate_gw(net, cfg, &dev, &idev, extack);
        if (err) goto out;
        fib6_nh->fib_nh_gw6 = cfg->fc_gateway;
        fib6_nh->fib_nh_gw_family = AF_INET6;
    }
    err = -ENODEV;
    if (!dev) goto out;

    // 网络设备ipv6支持检查、在线情况检查
    if (idev->cnf.disable_ipv6) { ... }
    if (!(dev->flags & IFF_UP) && !cfg->fc_ignore_dev_down) { ... }

    // 路由在线情况检查
    if (!(cfg->fc_flags & (RTF_LOCAL | RTF_ANYCAST)) && !netif_carrier_ok(dev))
        fib6_nh->fib_nh_flags |= RTNH_F_LINKDOWN;

    // 路由通用信息初始化
    err = fib_nh_common_init(net, &fib6_nh->nh_common, cfg->fc_encap, cfg->fc_encap_type, cfg, gfp_flags, extack);
    if (err) goto out;

pcpu_alloc:
    // 动态分配per-CPU路由表
    fib6_nh->rt6i_pcpu = alloc_percpu_gfp(struct rt6_info *, gfp_flags);
    if (!fib6_nh->rt6i_pcpu) { ... }

    fib6_nh->fib_nh_dev = dev;
    netdev_tracker_alloc(dev, &fib6_nh->fib_nh_dev_tracker, gfp_flags);
    // 下一跳网卡索引
    fib6_nh->fib_nh_oif = dev->ifindex;
    err = 0;
out:
    if (idev) in6_dev_put(idev);

    if (err) {
        // 出现错误时，释放路由封装状态
        lwtstate_put(fib6_nh->fib_nh_lws);
        fib6_nh->fib_nh_lws = NULL;
        dev_put(dev);
    }
    return err;
}
```

### 5.2 ipv6删除路由

#### (1) `netlink`接口

`ip -6 route del` 命令从Linux内核中删除一条路由信息，对应 `PF_INET6:RTM_DELROUTE` 类型的netlink接口，在内核中对应`inet6_rtm_delroute`处理，如下：

```C
// file: net/ipv6/route.c
static int inet6_rtm_delroute(struct sk_buff *skb, struct nlmsghdr *nlh, struct netlink_ext_ack *extack)
{
    struct fib6_config cfg;
    int err;
    // 解析netlink请求，转换为ipv6路由配置信息
    err = rtm_to_fib6_config(skb, nlh, &cfg, extack);
    if (err < 0) return err;
    // 指定下一跳id时，但不存在时，返回错误信息
    if (cfg.fc_nh_id && !nexthop_find_by_id(sock_net(skb->sk), cfg.fc_nh_id)) {
        NL_SET_ERR_MSG(extack, "Nexthop id does not exist");
        return -EINVAL;
    }

    if (cfg.fc_mp)
        // 多路径下删除路由
        return ip6_route_multipath_del(&cfg, extack);
    else {
        // 单路径下删除
        cfg.fc_delete_all_nh = 1;
        return ip6_route_del(&cfg, extack);
    }
}
```

`ip6_route_del` 函数确定路由节点后删除路由，如下：

```C
// file: net/ipv6/route.c
static int ip6_route_del(struct fib6_config *cfg, struct netlink_ext_ack *extack)
{
    struct fib6_table *table;
    struct fib6_info *rt;
    struct fib6_node *fn;
    int err = -ESRCH;

    // 获取路由表
    table = fib6_get_table(cfg->fc_nlinfo.nl_net, cfg->fc_table);
    if (!table) { ... }
    rcu_read_lock();
    // 获取路由节点
    fn = fib6_locate(&table->tb6_root, &cfg->fc_dst, cfg->fc_dst_len, 
            &cfg->fc_src, cfg->fc_src_len, !(cfg->fc_flags & RTF_CACHE));

    if (fn) {
        for_each_fib6_node_rt_rcu(fn) {
            struct fib6_nh *nh;
            // nh_id 节点不匹配时查找下一个
            if (rt->nh && cfg->fc_nh_id && rt->nh->id != cfg->fc_nh_id)
                continue;
            // 删除缓存路由
            if (cfg->fc_flags & RTF_CACHE) { ... }
            // 指标或协议不匹配时，查找下一个路由
            if (cfg->fc_metric && cfg->fc_metric != rt->fib6_metric) continue;
            if (cfg->fc_protocol && cfg->fc_protocol != rt->fib6_protocol) continue;

            // 指定的下一跳路由存在时
            if (rt->nh) {
                if (!fib6_info_hold_safe(rt)) continue;
                rcu_read_unlock();
                // 删除路由信息
                return __ip6_del_rt(rt, &cfg->fc_nlinfo);
            }
            if (cfg->fc_nh_id) continue;
            
            // 下一跳路由存在时
            nh = rt->fib6_nh;
            // 网卡不匹配、网关不匹配时，查找下一个路由
            if (cfg->fc_ifindex && (!nh->fib_nh_dev || nh->fib_nh_dev->ifindex != cfg->fc_ifindex)) continue;
            if (cfg->fc_flags & RTF_GATEWAY && !ipv6_addr_equal(&cfg->fc_gateway, &nh->fib_nh_gw6)) continue;
            if (!fib6_info_hold_safe(rt)) continue;
            rcu_read_unlock();

            // 指定网关时，删除路由
            if (cfg->fc_flags & RTF_GATEWAY)
                return __ip6_del_rt(rt, &cfg->fc_nlinfo);
            // 删除兄弟路由节点
            return __ip6_del_rt_siblings(rt, cfg);
        }
    }
    rcu_read_unlock();
    return err;
}
```

#### (2) 释放路由信息

`ip6_del_cached_rt_nh`, `ip6_del_cached_rt`, `__ip6_del_rt`，`__ip6_del_rt_siblings` 等函数删除路由信息时，调用`fib6_info_release`释放路由信息，如下：

```C
// file: net/ipv6/ip6_fib.c
static inline void fib6_info_release(struct fib6_info *f6i)
{
    if (f6i && refcount_dec_and_test(&f6i->fib6_ref))
        call_rcu(&f6i->rcu, fib6_info_destroy_rcu);
}
// file: net/ipv6/ip6_fib.c
void fib6_info_destroy_rcu(struct rcu_head *head)
{
    struct fib6_info *f6i = container_of(head, struct fib6_info, rcu);
    WARN_ON(f6i->fib6_node);
    if (f6i->nh) 
        nexthop_put(f6i->nh); // 释放指定的下一跳路由
    else 
        fib6_nh_release(f6i->fib6_nh); // 释放下一跳路由信息
    // 释放指标信息
    ip_fib_metrics_put(f6i->fib6_metrics);
    kfree(f6i);
}
```

`fib6_nh_release` 函数释放创建的路由信息，如下

```C
// file：net/ipv6/route.c
void fib6_nh_release(struct fib6_nh *fib6_nh)
{
    struct rt6_exception_bucket *bucket;
    rcu_read_lock();
    // 删除异常路由
    fib6_nh_flush_exceptions(fib6_nh, NULL);
    bucket = fib6_nh_get_excptn_bucket(fib6_nh, NULL);
    if (bucket) { 
        rcu_assign_pointer(fib6_nh->rt6i_exception_bucket, NULL);
        kfree(bucket);
    }
    rcu_read_unlock();
    // 释放`rt6i_pcpu`
    fib6_nh_release_dsts(fib6_nh);
    free_percpu(fib6_nh->rt6i_pcpu);
    // 函数释放通用路由信息，在其中释放路由封装信息
    fib_nh_common_release(&fib6_nh->nh_common);
}
```

### 5.3 路由封装的实现过程(input)

#### (1) ipv6协议接收

ipv6协议在Linux内核中的定义为`ipv6_packet_type`，如下：

```C
// file: net/ipv6/af_inet6.c
static struct packet_type ipv6_packet_type __read_mostly = {
    .type = cpu_to_be16(ETH_P_IPV6),
    .func = ipv6_rcv,
    .list_func = ipv6_list_rcv,
};
```

在`module_init`阶段注册，如下：

```C
// file: net/ipv6/af_inet6.c
static int __init inet6_init(void)
{
    ...
    err = ipv6_packet_init();
    ...
    ipv6_stub = &ipv6_stub_impl;
    ipv6_bpf_stub = &ipv6_bpf_stub_impl;
    ...
}
module_init(inet6_init);

// file: net/ipv6/af_inet6.c
static int __init ipv6_packet_init(void)
{
    dev_add_pack(&ipv6_packet_type);
    return 0;
}
```

`ipv6_list_rcv` 以通过列表方式批量接收后处理，处理过程和单个处理过程类似，需要经过`NFPROTO_IPV6:NF_INET_PRE_ROUTING` netfilter过程。我们只分析以单个skb处理过程，如下：

```C
// file：net/ipv6/ip6_input.c
int ipv6_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    struct net *net = dev_net(skb->dev);
    // 检查为本机网络包后，按照RFC4291进行ipv6协议检查格式，设置L4层数据位置
   skb = ip6_rcv_core(skb, dev, net);
    if (skb == NULL)
        return NET_RX_DROP;
    // netfilter hook点，检查通过后，调用`ip6_rcv_finish`
    return NF_HOOK(NFPROTO_IPV6, NF_INET_PRE_ROUTING, net, NULL, skb, dev, NULL, ip6_rcv_finish);
}
```

`ip6_rcv_finish` 函数是skb为允许通过的正常的网络数据包后的处理过程，如下：

```C
// file：net/ipv6/ip6_input.c
int ip6_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    // 入口设备从属于L3主设备时，传送SKB到其处理程序进行处理
    skb = l3mdev_ip6_rcv(skb);
    if (!skb) return NET_RX_SUCCESS;
    // ipv6核心处理，确定路由路径
	ip6_rcv_finish_core(net, sk, skb);
    // 路由输入处理
    return dst_input(skb);
}
```

`ip6_rcv_finish_core` 函数进行skb接收的核心处理，确定路由信息，如下：

```C
// file: net/ipv6/ip6_input.c
static void ip6_rcv_finish_core(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    // ipv6协议早期解析，支持TCP和UDP协议
    if (READ_ONCE(net->ipv4.sysctl_ip_early_demux) && !skb_dst(skb) && !skb->sk) {
        switch (ipv6_hdr(skb)->nexthdr) {
        case IPPROTO_TCP:
            if (READ_ONCE(net->ipv4.sysctl_tcp_early_demux)) tcp_v6_early_demux(skb); break;
        case IPPROTO_UDP:
            if (READ_ONCE(net->ipv4.sysctl_udp_early_demux)) udp_v6_early_demux(skb); break;
        }
    }
    // 路由信息不存在时，确定接收路由
    if (!skb_valid_dst(skb)) ip6_route_input(skb);
}
```

#### (2) 确定ipv6接收路由

`ip6_route_input` 函数确定skb的输入路由信息，设置路由查找信息后查找，如下：

```C
// file: net/ipv6/route.c
void ip6_route_input(struct sk_buff *skb)
{
    const struct ipv6hdr *iph = ipv6_hdr(skb);
    struct net *net = dev_net(skb->dev);
    int flags = RT6_LOOKUP_F_HAS_SADDR | RT6_LOOKUP_F_DST_NOREF;
    struct ip_tunnel_info *tun_info;
    // 设置路由查找信息
    struct flowi6 fl6 = {
        .flowi6_iif = skb->dev->ifindex,
        .daddr = iph->daddr,
        .saddr = iph->saddr,
        .flowlabel = ip6_flowinfo(iph),
        .flowi6_mark = skb->mark,
        .flowi6_proto = iph->nexthdr,
    };
    struct flow_keys *flkeys = NULL, _flkeys;
    // 隧道信息存在时，设置查询的隧道id 
    tun_info = skb_tunnel_info(skb);
    if (tun_info && !(tun_info->mode & IP_TUNNEL_INFO_TX))
        fl6.flowi6_tun_key.tun_id = tun_info->key.tun_id;

    // 早期路由规则剖析，由`fib6_rules_require_fldissect`选项控制
    if (fib6_rules_early_flow_dissect(net, skb, &fl6, &_flkeys))
        flkeys = &_flkeys;

    if (unlikely(fl6.flowi6_proto == IPPROTO_ICMPV6))
        fl6.mp_hash = rt6_multipath_hash(net, &fl6, skb, flkeys);
    // 丢弃旧的路由信息，设置新的路由
    skb_dst_drop(skb);
    skb_dst_set_noref(skb, ip6_route_input_lookup(net, skb->dev, &fl6, skb, flags));
}
```

`ip6_route_input_lookup` 函数查找ipv6路由信息，如下：

```C
// file: net/ipv6/route.c
struct dst_entry *ip6_route_input_lookup(struct net *net, struct net_device *dev,
                    struct flowi6 *fl6, const struct sk_buff *skb, int flags)
{
    // 组播地址、本地链接地址、loopback地址，需要设置`RT6_LOOKUP_F_IFACE`标记
    if (rt6_need_strict(&fl6->daddr) && dev->type != ARPHRD_PIMREG)
        flags |= RT6_LOOKUP_F_IFACE;
    // 查询输入的路由信息
    return fib6_rule_lookup(net, fl6, skb, flags, ip6_pol_route_input);
}
```

`fib6_rule_lookup` 实现路由的查找，返回的路由信息出现`EAGAIN`错误时，返回`ip6_null_entry`，如下：

```C
// file: net/ipv6/route.c
struct dst_entry *fib6_rule_lookup(struct net *net, struct flowi6 *fl6, const struct sk_buff *skb, 
        int flags, pol_lookup_t lookup)
{
    struct rt6_info *rt;
    // 从ipv6主路由表中查找
    rt = pol_lookup_func(lookup, net, net->ipv6.fib6_main_tbl, fl6, skb, flags);
    if (rt->dst.error == -EAGAIN) {
        ip6_rt_put_flags(rt, flags);
        // `EAGAIN`错误时，返回`ip6_null_entry`路由
        rt = net->ipv6.ip6_null_entry;
        if (!(flags & RT6_LOOKUP_F_DST_NOREF))
            dst_hold(&rt->dst);
    }
    return &rt->dst;
}
```

`ip6_pol_route_input` 函数确定输入的路由信息，如下：

```C
// file: net/ipv6/route.c
INDIRECT_CALLABLE_SCOPE struct rt6_info *ip6_pol_route_input(struct net *net, 
        struct fib6_table *table, struct flowi6 *fl6, const struct sk_buff *skb, int flags)
{
    return ip6_pol_route(net, table, fl6->flowi6_iif, fl6, skb, flags);
}
```

`ip6_pol_route` 函数查询对应的路由信息，不存在时创建，如下：

```C
// file: net/ipv6/route.c
struct rt6_info *ip6_pol_route(struct net *net, struct fib6_table *table, int oif, 
                        struct flowi6 *fl6, const struct sk_buff *skb, int flags)
{
    struct fib6_result res = {};
    struct rt6_info *rt = NULL;
    int strict = 0;

    WARN_ON_ONCE((flags & RT6_LOOKUP_F_DST_NOREF) && !rcu_read_lock_held());
    // 检查是否是直接路由
    strict |= flags & RT6_LOOKUP_F_IFACE;
    strict |= flags & RT6_LOOKUP_F_IGNORE_LINKSTATE;
    if (net->ipv6.devconf_all->forwarding == 0)
        strict |= RT6_LOOKUP_F_REACHABLE;

    rcu_read_lock();
    // 查找ipv6路由信息，返回结果为`fib6_null_entry`，结束查找
    fib6_table_lookup(net, table, oif, fl6, &res, strict);
    if (res.f6i == net->ipv6.fib6_null_entry) goto out;
    // ipv6选择路由
    fib6_select_path(net, &res, fl6, oif, false, skb, strict);

    // 从异常路由表中查找
    rt = rt6_find_cached_rt(&res, &fl6->daddr, &fl6->saddr);
    if (rt) {
        // 存在路由时，结束查找
        goto out;
    } else if (unlikely((fl6->flowi6_flags & FLOWI_FLAG_KNOWN_NH) && !res.nh->fib_nh_gw_family)) {
        // 指定下一跳路由时，且非网关时，创建一个克隆路由，并添加到非缓存列表中
        rt = ip6_rt_cache_alloc(&res, &fl6->daddr, NULL);
        if (rt) { rt6_uncached_list_add(rt); rcu_read_unlock(); return rt; }
    } else {
        // 其他情况，创建一个percpu副本
        local_bh_disable();
        rt = rt6_get_pcpu_route(&res);
        if (!rt) rt = rt6_make_pcpu_route(net, &res);
        local_bh_enable();
    }
out:
    // 路由信息不存在时，为`fib6_null_entry`
    if (!rt) rt = net->ipv6.ip6_null_entry;
    if (!(flags & RT6_LOOKUP_F_DST_NOREF))
        ip6_hold_safe(net, &rt);
    rcu_read_unlock();
    return rt;
}
```

`ip6_rt_cache_alloc`和`rt6_make_pcpu_route`函数创建路由副本时，复制路由信息，以`ip6_rt_cache_alloc`为例，如下：

```C
// file: net/ipv6/route.c
static struct rt6_info *ip6_rt_cache_alloc(const struct fib6_result *res, 
        const struct in6_addr *daddr, const struct in6_addr *saddr)
{
    struct fib6_info *f6i = res->f6i;
    struct net_device *dev;
    struct rt6_info *rt;
    if (!fib6_info_hold_safe(f6i)) return NULL;

    dev = ip6_rt_get_dev_rcu(res);
    // 创建新的路由
    rt = ip6_dst_alloc(dev_net(dev), dev, 0);
    if (!rt) { fib6_info_release(f6i); return NULL; }
    // 复制路由信息
    ip6_rt_copy_init(rt, res);
    rt->rt6i_flags |= RTF_CACHE;
    rt->rt6i_dst.addr = *daddr;
    rt->rt6i_dst.plen = 128;

    // 非网关路由、存在下一跳路由时检测
    if (!rt6_is_gw_or_nonexthop(res)) { ...  }
    return rt;
}
```

`ip6_rt_copy_init` 函数设置路由信息，如下：

```C
// file: net/ipv6/route.c
static void ip6_rt_copy_init(struct rt6_info *rt, const struct fib6_result *res)
{
    const struct fib6_nh *nh = res->nh;
    const struct net_device *dev = nh->fib_nh_dev;
    struct fib6_info *f6i = res->f6i;
    // 设置路由dst信息
    ip6_rt_init_dst(rt, res);
    // 设置路由信息
    rt->rt6i_dst = f6i->fib6_dst;
    rt->rt6i_idev = dev ? in6_dev_get(dev) : NULL;
    rt->rt6i_flags = res->fib6_flags;
    if (nh->fib_nh_gw_family) {
        rt->rt6i_gateway = nh->fib_nh_gw6;
        rt->rt6i_flags |= RTF_GATEWAY;
    }
    // 设置路由来源信息
    rt6_set_from(rt, f6i);
#ifdef CONFIG_IPV6_SUBTREES
    rt->rt6i_src = f6i->fib6_src;
#endif
}
```

#### (3) input路由封装设置

`ip6_rt_init_dst` 设置路由dst信息，存在路由封装信息时，设置路由封装重定向，如下:

```C
// file: net/ipv6/route.c
static void ip6_rt_init_dst(struct rt6_info *rt, const struct fib6_result *res)
{
    struct fib6_info *f6i = res->f6i;
    // 查找的路由为拒绝路由时，根据不同的类型设置`input/output`接口
    if (res->fib6_flags & RTF_REJECT) { ip6_rt_init_dst_reject(rt, res->fib6_type); return;}
    // error和输出接口设置
    rt->dst.error = 0;
    rt->dst.output = ip6_output;
    // 路由输入接口设置
    if (res->fib6_type == RTN_LOCAL || res->fib6_type == RTN_ANYCAST) {
        rt->dst.input = ip6_input;
    } else if (ipv6_addr_type(&f6i->fib6_dst.addr) & IPV6_ADDR_MULTICAST) {
        rt->dst.input = ip6_mc_input;
    } else {
        rt->dst.input = ip6_forward;
    }
    // 存在路由封装信息时，设置路由封装重定向
    if (res->nh->fib_nh_lws) {
        rt->dst.lwtstate = lwtstate_get(res->nh->fib_nh_lws);
        lwtunnel_set_redirect(&rt->dst);
    }
    // 更新路由使用时间
    rt->dst.lastuse = jiffies;
}
```

#### (4) input路由封装调用

在通过`ip6_rcv_finish_core`确定接收的路由后，接下来进行路由输入处理，如下：

```C
// file：net/ipv6/ip6_input.c
int ip6_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    // 入口设备从属于L3主设备时，传送SKB到其处理程序进行处理
    skb = l3mdev_ip6_rcv(skb);
    if (!skb) return NET_RX_SUCCESS;
    // ipv6核心处理，确定路由路径
	ip6_rcv_finish_core(net, sk, skb);
    // 路由输入处理
    return dst_input(skb);
}
```

`dst_input` 实现路由的输入处理，如下：

```C
// file: include/net/dst.h
static inline int dst_input(struct sk_buff *skb)
{
    return INDIRECT_CALL_INET(skb_dst(skb)->input, ip6_input, ip_local_deliver, skb);
}
```

在设置封装路由时，设置`.input` 处理函数为 `lwtunnel_input`。实现过程见ipv4处理过程。

### 5.4 路由封装的设置过程(output)

#### (1) L4确定发送路由

在[Linux 网络栈监控和调优：发送数据（2017）](http://arthurchiao.art/blog/tuning-stack-tx-zh/)描述网络发送过程时，L4层通过`ip6_dst_lookup_flow`函数确定ipv6发送的路由信息。此外，`ip6_dst_lookup*`系列函数均实现发送路由的确定。

`ip6_sk_dst_lookup_flow` 函数实现如下：

```C
// file: net/ipv6/ip6_output.c
struct dst_entry *ip6_dst_lookup_flow(struct net *net, const struct sock *sk, struct flowi6 *fl6, 
                const struct in6_addr *final_dst)
{
    struct dst_entry *dst = NULL;
    int err;
    // 确定ipv6路由
    err = ip6_dst_lookup_tail(net, sk, &dst, fl6);
    if (err) return ERR_PTR(err);
	// 设置IPsec查找的最终目标地址
    if (final_dst) fl6->daddr = *final_dst;
    // 转换路由查询
    return xfrm_lookup_route(net, dst, flowi6_to_flowi(fl6), sk, 0);
}
```

`ip6_dst_lookup_tail` 函数通过`ip6_route_output`或`ip6_route_output_flags`确定发送的路由，如下:

```C
// file: net/ipv6/ip6_output.c
static int ip6_dst_lookup_tail(struct net *net, const struct sock *sk, struct dst_entry **dst, struct flowi6 *fl6)
{
    ...
    // 任意源地址时
    if (ipv6_addr_any(&fl6->saddr)) {
        // 确定路由信息
        *dst = ip6_route_output(net, sk, fl6);
        rt = (*dst)->error ? NULL : (struct rt6_info *)*dst;
        
        rcu_read_lock();
        // 确定发送的源地址
        from = rt ? rcu_dereference(rt->from) : NULL;
        err = ip6_route_get_saddr(net, from, &fl6->daddr, sk ? inet6_sk(sk)->srcprefs : 0, &fl6->saddr);
		rcu_read_unlock();

        if (err) goto out_err_release;
        // 路由出现错误时，设置为null，后续查找
        if ((*dst)->error) { dst_release(*dst); *dst = NULL; }
        // 指定网卡时，设置`IFACE`标记
        if (fl6->flowi6_oif) flags |= RT6_LOOKUP_F_IFACE;
    }
    // 路由不存在时，再次查找路由
    if (!*dst) *dst = ip6_route_output_flags(net, sk, fl6, flags);
    // 路由出现错误时，进入错误处理
    err = (*dst)->error;
    if (err) goto out_err_release;

    ...
    // ipv6映射ipv4检查
    if (ipv6_addr_v4mapped(&fl6->saddr) && !(ipv6_addr_v4mapped(&fl6->daddr) || ipv6_addr_any(&fl6->daddr))) {
        err = -EAFNOSUPPORT;
        goto out_err_release;
    }
	return 0;

out_err_release:
    // 出现错误时，释放dst路由，设置返回结果为空
    dst_release(*dst);
    *dst = NULL;
    if (err == -ENETUNREACH) IP6_INC_STATS(net, NULL, IPSTATS_MIB_OUTNOROUTES);
    return err;
}
```

#### (2) 确定ipv6发送路由

`ip6_route_output`函数是对`ip6_route_output_flags`函数的封装调用，如下：

```C
// file: include/net/ip6_route.h
static inline struct dst_entry *ip6_route_output(struct net *net, const struct sock *sk, struct flowi6 *fl6)
{
    return ip6_route_output_flags(net, sk, fl6, 0);
}
```

`ip6_route_output_flags` 函数确定发送时使用路由信息，如下：

```C
// file: net/ipv6/route.c
struct dst_entry *ip6_route_output_flags(struct net *net, const struct sock *sk, struct flowi6 *fl6, int flags)
{
    struct dst_entry *dst;
    struct rt6_info *rt6;

    rcu_read_lock();
    // 查找输出的路由
    dst = ip6_route_output_flags_noref(net, sk, fl6, flags);
    rt6 = (struct rt6_info *)dst;
    // 目标路由在不缓存列表中，不安全的持有时(引用计数不为0)，设置为`ip6_null_entry`
    if (list_empty(&rt6->rt6i_uncached) && !dst_hold_safe(dst)) {
        dst = &net->ipv6.ip6_null_entry->dst;
        dst_hold(dst);
    }
    rcu_read_unlock();
    return dst;
}
```

`ip6_route_output_flags_noref` 函数查找输出的路由，如下：

```C
// file: net/ipv6/route.c
static struct dst_entry *ip6_route_output_flags_noref(struct net *net, const struct sock *sk, 
                            struct flowi6 *fl6, int flags)
{
    bool any_src;
    if (ipv6_addr_type(&fl6->daddr) & (IPV6_ADDR_MULTICAST | IPV6_ADDR_LINKLOCAL)) {
        // 组播或本地地址时，通过L3主设备获取
        struct dst_entry *dst;
        dst = l3mdev_link_scope_lookup(net, fl6);
        if (dst) return dst;
    }
    // input网卡设置
    fl6->flowi6_iif = LOOPBACK_IFINDEX;
    
    flags |= RT6_LOOKUP_F_DST_NOREF;
    // 任意源(源地址为0)
    any_src = ipv6_addr_any(&fl6->saddr);
    // sk绑定网卡时，设置`IFACE`标记
    if ((sk && sk->sk_bound_dev_if) || rt6_need_strict(&fl6->daddr) || (fl6->flowi6_oif && any_src))
        flags |= RT6_LOOKUP_F_IFACE;
    
    // flags更新
    if (!any_src) flags |= RT6_LOOKUP_F_HAS_SADDR;
    else if (sk) flags |= rt6_srcprefs2flags(inet6_sk(sk)->srcprefs);
    // 查找输出路由信息
    return fib6_rule_lookup(net, fl6, NULL, flags, ip6_pol_route_output);
}
```

`ip6_pol_route_output` 函数查找输出方向的路由，如下：

```C
// file: net/ipv6/route.c
INDIRECT_CALLABLE_SCOPE struct rt6_info *ip6_pol_route_output(struct net *net, struct fib6_table *table,
                        struct flowi6 *fl6, const struct sk_buff *skb, int flags)
{
    return ip6_pol_route(net, table, fl6->flowi6_oif, fl6, skb, flags);
}
```

`ip6_pol_route` 函数查询对应的路由信息，不存在时创建，实现过程见上节内容。

#### (3) output路由封装设置

在创建输出路由后，设置路由封装的重定向，`lwtunnel_set_redirect` 函数实现路由封装的重定向。

#### (4) L3发送网络数据过程

L4在确定路由信息后发送skb，以ICMP为例，调用`ip6_push_pending_frames`发送skb，如下：

```C
// file: net/ipv6/ip6_output.c
int ip6_push_pending_frames(struct sock *sk)
{
    struct sk_buff *skb;
    // 设置skb ipv6信息
    skb = ip6_finish_skb(sk);
    if (!skb) return 0;
    // ipv6发送skb
    return ip6_send_skb(skb);
}
```

##### 1 skb设置ipv6信息

`ip6_finish_skb` 函数从sk写队列中取出skb后，填充ipv6信息，如下：

```C
// file：include/net/ipv6.h
static inline struct sk_buff *ip6_finish_skb(struct sock *sk)
{
    return __ip6_make_skb(sk, &sk->sk_write_queue, &inet_sk(sk)->cork, &inet6_sk(sk)->cork);
}
// file: net/ipv6/ip6_output.c
struct sk_buff *__ip6_make_skb(struct sock *sk, struct sk_buff_head *queue, 
                struct inet_cork_full *cork, struct inet6_cork *v6_cork)
{
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct in6_addr *final_dst;
    struct ipv6_pinfo *np = inet6_sk(sk);
    struct net *net = sock_net(sk);
    struct ipv6hdr *hdr;
    struct ipv6_txoptions *opt = v6_cork->opt;
    struct rt6_info *rt = (struct rt6_info *)cork->base.dst;
    struct flowi6 *fl6 = &cork->fl.u.ip6;
    unsigned char proto = fl6->flowi6_proto;

    // 从队列中取出一个skb
    skb = __skb_dequeue(queue);
    if (!skb) goto out;
    tail_skb = &(skb_shinfo(skb)->frag_list);

    // 移动skb->data位置，确保有足够的空间写入ip 头信息
    if (skb->data < skb_network_header(skb))
        __skb_pull(skb, skb_network_offset(skb));
    // 写队列中的其他skb，添加到第一个skb的frag列表中
    while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
        __skb_pull(tmp_skb, skb_network_header_len(skb));
        *tail_skb = tmp_skb;
        tail_skb = &(tmp_skb->next);
        skb->len += tmp_skb->len;
        skb->data_len += tmp_skb->len;
        skb->truesize += tmp_skb->truesize;
        tmp_skb->destructor = NULL;
        tmp_skb->sk = NULL;
    }
    // 除非用户要求真正的pmtu发现，否则我们允许进行分段
    skb->ignore_df = ip6_sk_ignore_df(sk);
    __skb_pull(skb, skb_network_header_len(skb));

    final_dst = &fl6->daddr;
    // ipv6选项设置
    if (opt && opt->opt_flen) ipv6_push_frag_opts(skb, opt, &proto);
    if (opt && opt->opt_nflen) ipv6_push_nfrag_opts(skb, opt, &proto, &final_dst, &fl6->saddr);

    // 获取ipv6头部信息
    skb_push(skb, sizeof(struct ipv6hdr));
    skb_reset_network_header(skb);
    hdr = ipv6_hdr(skb);
    // ipv6数据流标记设置
    ip6_flow_hdr(hdr, v6_cork->tclass, 
                ip6_make_flowlabel(net, skb, fl6->flowlabel, ip6_autoflowlabel(net, np), fl6));
    // ipv6信息设置
    hdr->hop_limit = v6_cork->hop_limit;
    hdr->nexthdr = proto;
    hdr->saddr = fl6->saddr;
    hdr->daddr = *final_dst;

    // skb优先级、标记、发送时间设置
    skb->priority = sk->sk_priority;
    skb->mark = cork->base.mark;
    skb->tstamp = cork->base.transmit_time;

    // skb设置路由信息
    ip6_cork_steal_dst(skb, cork);
    IP6_UPD_PO_STATS(net, rt->rt6i_idev, IPSTATS_MIB_OUT, skb->len);
    if (proto == IPPROTO_ICMPV6) {
        // 发送的ICMPV6统计
        struct inet6_dev *idev = ip6_dst_idev(skb_dst(skb));
        u8 icmp6_type;
        if (sk->sk_socket->type == SOCK_RAW && !inet_sk(sk)->hdrincl)
            icmp6_type = fl6->fl6_icmp_type;
        else
            icmp6_type = icmp6_hdr(skb)->icmp6_type;
        ICMP6MSGOUT_INC_STATS(net, idev, icmp6_type);
        ICMP6_INC_STATS(net, idev, ICMP6_MIB_OUTMSGS);
    }
    ip6_cork_release(cork, v6_cork);
out:
    return skb;
}
```

##### 2 ipv6发送skb

在skb创建完成后，`ip6_send_skb`实现本地skb发送，如下：

```C
// file: net/ipv6/ip6_output.c
int ip6_send_skb(struct sk_buff *skb)
{
    struct net *net = sock_net(skb->sk);
    struct rt6_info *rt = (struct rt6_info *)skb_dst(skb);
    int err;
    // 本地skb输出
    err = ip6_local_out(net, skb->sk, skb);
    if (err) {
        // 错误代码转换后，增加统计信息
        if (err > 0) err = net_xmit_errno(err);
        if (err) IP6_INC_STATS(net, rt->rt6i_idev, IPSTATS_MIB_OUTDISCARDS);
    }
    return err;
}
```

`ip6_local_out` 实现调用`__ip6_local_out`实现skb本地发送，返回值为1时，通过路由层发送。如下：

```C
// file: net/ipv6/output_core.c
int ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    int err;
    // 本地skb发送
    err = __ip6_local_out(net, sk, skb);
    // 路由发送
    if (likely(err == 1)) err = dst_output(net, sk, skb);
    return err;
}
```

`__ip6_local_out` 实现本地skb发送，设置ipv6数据包长度、skb协议字段后，进入`NFPROTO_IPV6:NF_INET_LOCAL_OUT` netfilter 检查后，通过路由发送，如下：

```C
// file: net/ipv6/output_core.c
int __ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    int len;
    // ipv6头部payload长度设置
    len = skb->len - sizeof(struct ipv6hdr);
    if (len > IPV6_MAXPLEN) len = 0;
    ipv6_hdr(skb)->payload_len = htons(len);
    // 下一个头部设置
    IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);

    // 通过l3主设备发送skb
    skb = l3mdev_ip6_out(sk, skb);
    if (unlikely(!skb)) return 0;

    skb->protocol = htons(ETH_P_IPV6);
    // netfilter检查后发送
    return nf_hook(NFPROTO_IPV6, NF_INET_LOCAL_OUT, net, sk, skb, NULL, skb_dst(skb)->dev, dst_output);
}
```

#### (5) output路由封装调用

本地发送skb时，最后通过`dst_output`函数实现路由的发送，如下

```C
// file: include/net/dst.h
static inline int dst_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return INDIRECT_CALL_INET(skb_dst(skb)->output, ip6_output, ip_output, net, sk, skb);
}
```

在设置封装路由时，设置`.output`处理函数为 `lwtunnel_output`。实现过程见上节内容。

#### (6) ipv6发送skb的过程

在UDP或TCP使用ipv6时，默认设置的`.output`接口为`ip6_output`, 设置skb网卡设备和网络协议后，进入`NFPROTO_IPV6:NF_INET_POST_ROUTING` netfilter hook检查后，调用`ip6_finish_output`，如下：

```C
// file: net/ipv6/ip6_output.c
int ip6_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct net_device *dev = skb_dst(skb)->dev, *indev = skb->dev;
    struct inet6_dev *idev = ip6_dst_idev(skb_dst(skb));
    // 设置skb网卡设备和协议
    skb->protocol = htons(ETH_P_IPV6);
    skb->dev = dev;
    // 禁用ipv6时，释放skb
    if (unlikely(idev->cnf.disable_ipv6)) {
        IP6_INC_STATS(net, idev, IPSTATS_MIB_OUTDISCARDS);
        kfree_skb_reason(skb, SKB_DROP_REASON_IPV6DISABLED);
        return 0;
    }
    // netfilter hook处理
    return NF_HOOK_COND(NFPROTO_IPV6, NF_INET_POST_ROUTING, net, sk, skb, indev, dev,
            ip6_finish_output, !(IP6CB(skb)->flags & IP6SKB_REROUTED));
}
```

`ip6_finish_output` 函数检查`CGROUP_INET_EGRESS`后，调用`__ip6_finish_output`, 如下：

```C
// file: net/ipv6/ip6_output.c
static int ip6_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    int ret;
    // `CGROUP_INET_EGRESS` 检查
    ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
    switch (ret) {
    case NET_XMIT_SUCCESS:
    case NET_XMIT_CN:
        // 发送成功或继续发送
        return __ip6_finish_output(net, sk, skb) ? : ret;
    default:
        // 其他返回值时，释放skb
        kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
        return ret;
    }
}
```

`__ip6_finish_output` 函数检查skb gso 和分片设置后，通过`ip6_finish_output2` 函数发送，如下：

```C
// file: net/ipv6/ip6_output.c
static int __ip6_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    unsigned int mtu;
#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
    // 转换路由存在时，重新路由发送
    if (skb_dst(skb)->xfrm) { 
        IP6CB(skb)->flags |= IP6SKB_REROUTED;
        return dst_output(net, sk, skb);
    }
#endif
    // 计算目的路由的mtu，路由封装信息存在时，减去路由封装长度
    mtu = ip6_skb_dst_mtu(skb);
    // 支持gso时，进行GSO(Generic Segmentation Offload)处理，推迟数据分片
    if (skb_is_gso(skb) && !(IP6CB(skb)->flags & IP6SKB_FAKEJUMBO) && !skb_gso_validate_network_len(skb, mtu))
        return ip6_finish_output_gso_slowpath_drop(net, sk, skb, mtu);

    if ((skb->len > mtu && !skb_is_gso(skb)) || dst_allfrag(skb_dst(skb)) ||
        (IP6CB(skb)->frag_max_size && skb->len > IP6CB(skb)->frag_max_size))
        // skb长度超过mtu时，进行ip分片发送
        return ip6_fragment(net, sk, skb, ip6_finish_output2);
    else
        // ipv6实际发送skb
        return ip6_finish_output2(net, sk, skb);
}
```

在skb经过分片处理后，将skb封装成ipv6能够通过的skb后，调用 `ip6_finish_output2` 进行最后的发送。如下：

```C
// file: net/ipv6/ip6_output.c
static int ip6_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct dst_entry *dst = skb_dst(skb);
    struct net_device *dev = dst->dev;
    struct inet6_dev *idev = ip6_dst_idev(dst);
    unsigned int hh_len = LL_RESERVED_SPACE(dev);
    const struct in6_addr *daddr, *nexthop;
    struct ipv6hdr *hdr;
    struct neighbour *neigh;
    int ret;

    // 确保skb有足够的空间设置L2协议信息
    if (unlikely(hh_len > skb_headroom(skb)) && dev->header_ops) {
        skb = skb_expand_head(skb, hh_len);
        if (!skb) { IP6_INC_STATS(net, idev, IPSTATS_MIB_OUTDISCARDS); return -ENOMEM; }
    }

    hdr = ipv6_hdr(skb);
    daddr = &hdr->daddr;
    // 目的地址是组播地址时
    if (ipv6_addr_is_multicast(daddr)) {

        if (!(dev->flags & IFF_LOOPBACK) && sk_mc_loop(sk) && 
            ((mroute6_is_socket(net, skb) && !(IP6CB(skb)->flags & IP6SKB_FORWARDED)) ||
            ipv6_chk_mcast_addr(dev, daddr, &hdr->saddr))) {
            // 本地组播发送时，复制skb
            struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
            if (newskb)
                // 本地网卡发送
                NF_HOOK(NFPROTO_IPV6, NF_INET_POST_ROUTING, net, sk, newskb, NULL, newskb->dev, dev_loopback_xmit);
            // hop_limit到达0时，释放skb
            if (hdr->hop_limit == 0) {
                IP6_INC_STATS(net, idev, IPSTATS_MIB_OUTDISCARDS);
                kfree_skb(skb);
                return 0;
            }
        }
        // 组播发送统计信息更新
        IP6_UPD_PO_STATS(net, idev, IPSTATS_MIB_OUTMCAST, skb->len);
        if (IPV6_ADDR_MC_SCOPE(daddr) <= IPV6_ADDR_SCOPE_NODELOCAL && !(dev->flags & IFF_LOOPBACK)) {
            kfree_skb(skb);
            return 0;
        }
    }
    // 路由隧道发送skb，发送完成或错误时返回，其他情况继续后续处理
    if (lwtunnel_xmit_redirect(dst->lwtstate)) {
        int res = lwtunnel_xmit(skb);
        if (res < 0 || res == LWTUNNEL_XMIT_DONE) return res;
    }

    rcu_read_lock_bh();
    // 获取下一跳地址后，确定邻接路由，ipv6通过ICMP协议实现，由`nd_tbl`维护
    nexthop = rt6_nexthop((struct rt6_info *)dst, daddr);
    neigh = __ipv6_neigh_lookup_noref(dev, nexthop);
    
    if (unlikely(IS_ERR_OR_NULL(neigh))) {
        // 邻接路由不存在时，创建邻接路由
        if (unlikely(!neigh)) neigh = __neigh_create(&nd_tbl, nexthop, dev, false);
        // 邻接路由不存在时，更新统计信息后释放skb
        if (IS_ERR(neigh)) {
            rcu_read_unlock_bh();
            IP6_INC_STATS(net, idev, IPSTATS_MIB_OUTNOROUTES);
            kfree_skb_reason(skb, SKB_DROP_REASON_NEIGH_CREATEFAIL);
            return -EINVAL;
        }
    }
    // 确认邻接路由，存在后续skb后，更新邻接路由时间
    sock_confirm_neigh(skb, neigh);
    // 通过邻接路由发送
    ret = neigh_output(neigh, skb, false);
    rcu_read_unlock_bh();
    return ret;
}
```

#### (7) xmit路由封装调用

在通过`ip6_finish_output2`发送skb时，设置了路由传输设置时，通过`lwtunnel_xmit`发送skb。实现过程见上节内容。

## 6 总结

本文通过`test_lwt_bpf`示例程序分析了Linux内核使用BPF实现轻量级隧道封装的实现过程，通过`lwt_bpf`和`seg6local`实现对L3网络数据Input和Output路由的控制。

## 参考资料

* [Netfilter Conntrack Sysfs variables](https://www.kernel.org/doc/html/latest/networking/nf_conntrack-sysctl.html)
* [ip-route - routing table management](https://www.man7.org/linux/man-pages/man8/ip-route.8.html)
* [Lightweight & flow based tunneling](https://lwn.net/Articles/650778/)
* [BPF for lightweight tunnel encapsulation](https://lwn.net/Articles/705609/)
* [Requirements for Internet Hosts -- Communication Layers](https://www.rfc-editor.org/rfc/rfc1122.html)
* [IP Version 6 Addressing Architecture](https://www.rfc-editor.org/rfc/rfc4291.html)
* [FIB nexthop Exception是什么](https://switch-router.gitee.io/blog/fib_nh_exception/)
* [Linux 网络栈接收数据（RX）：原理及内核实现（2022）](https://arthurchiao.art/blog/linux-net-stack-implementation-rx-zh/)
* [Linux 网络栈监控和调优：发送数据（2017）](http://arthurchiao.art/blog/tuning-stack-tx-zh/)
* [BPF 进阶笔记（一）：BPF 程序（BPF Prog）类型详解：使用场景、函数签名、执行位置及程序示例](https://arthurchiao.art/blog/bpf-advanced-notes-1-zh/)