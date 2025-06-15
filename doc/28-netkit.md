# NETKIT的内核实现

## 0 前言

在虚拟化时代，虚拟网络扮演着重要的角色。除了生产使用之外，虚拟网络还可以在许多其他需要准确模拟功能的环境中有效采用，例如部署前的测试、假设场景的评估和研究。今天我们借助`tc_netkit`示例程序分析通过BPF程序实现可编程网络的实现过程。

## 1 简介

Netkit是一个独立的低成本解决方案，用于模拟计算机网络。在Netkit环境中，每个网络设备都是由虚拟机实现的，并且通过使用虚拟冲突域（或者虚拟集线器）来模拟互连链路。

## 2 `tc_netkit`示例程序

### 2.1 BPF程序

BPF程序源码参见[test_tc_link.c](../src/test_tc_link.c)，主要内容如下：

```C
bool seen_tc1;
bool seen_tc2;
...

SEC("tc/ingress")
int tc1(struct __sk_buff *skb)
{
    struct ethhdr eth = {};
    if (skb->protocol != __bpf_constant_htons(ETH_P_IP)) goto out;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth))) goto out;
    seen_eth = eth.h_proto == bpf_htons(ETH_P_IP);
    seen_host = skb->pkt_type == PACKET_HOST;
    if (seen_host && set_type) {
        eth.h_dest[0] = 4;
        if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0)) goto fail;
        bpf_skb_change_type(skb, PACKET_MULTICAST);
    }
out:
    seen_tc1 = true;
fail:
    return TCX_NEXT;
}

SEC("tc/egress")
int tc2(struct __sk_buff *skb)
{
    seen_tc2 = true;
    return TCX_NEXT;
}
...
```

该程序包含多个BPF程序，使用`tc/ingress` 和 `tc/egress` 前缀。参数为`__sk_buff`类型。

### 2.2 用户程序

用户程序源码参见[tc_netkit.c](../src/tc_netkit.c)，该文件包含多个测试程序，我们分析附加多个BPF程序的情况，如下：

#### 1 附加BPF程序

```C
// 测试附加多个BPF的情况
void serial_test_tc_netkit_multi_links(void)
{
    serial_test_tc_netkit_multi_links_target(NETKIT_L2, BPF_NETKIT_PRIMARY);
    serial_test_tc_netkit_multi_links_target(NETKIT_L3, BPF_NETKIT_PRIMARY);
    serial_test_tc_netkit_multi_links_target(NETKIT_L2, BPF_NETKIT_PEER);
    serial_test_tc_netkit_multi_links_target(NETKIT_L3, BPF_NETKIT_PEER);
}
```

`serial_test_tc_netkit_multi_links_target`函数进行`NETKIT`的适应性测试，如下：

```C
static void serial_test_tc_netkit_multi_links_target(int mode, int target)
{
    LIBBPF_OPTS(bpf_prog_query_opts, optq);
    LIBBPF_OPTS(bpf_netkit_opts, optl);
    __u32 prog_ids[3], link_ids[3];
    __u32 pid1, pid2, lid1, lid2;
    struct test_tc_link *skel;
    struct bpf_link *link;
    int err, ifindex;
    // 创建`netkit`设备
    err = create_netkit(mode, NETKIT_PASS, NETKIT_PASS, &ifindex, 
                        ETKIT_SCRUB_DEFAULT, NETKIT_SCRUB_DEFAULT, 0);
    if (err) return;

    // 打开BPF程序
    skel = test_tc_link__open();
    if (!ASSERT_OK_PTR(skel, "skel_open")) goto cleanup;

    // 修改BPF程序附加类型
    ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc1, target), 0, "tc1_attach_type");
    ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc2, target), 0, "tc2_attach_type");

    // 加载BPF程序
    err = test_tc_link__load(skel);
    if (!ASSERT_OK(err, "skel_load")) goto cleanup;
    ...
    // 附加`netkit`类型的BPF程序
    link = bpf_program__attach_netkit(skel->progs.tc1, ifindex, &optl);
    if (!ASSERT_OK_PTR(link, "link_attach")) goto cleanup;
    skel->links.tc1 = link;
    ...
    // 重置`.bss`区域
    tc_skel_reset_all_seen(skel);
    // 发送`ICMP`包，测试
    ASSERT_EQ(send_icmp(), 0, "icmp_pkt");
    // 判断测试结果
    ASSERT_EQ(skel->bss->seen_tc1, true, "seen_tc1");
    ASSERT_EQ(skel->bss->seen_eth, true, "seen_eth");
    ASSERT_EQ(skel->bss->seen_tc2, false, "seen_tc2");
    
    LIBBPF_OPTS_RESET(optl,
        .flags = BPF_F_BEFORE,
        .relative_fd = bpf_program__fd(skel->progs.tc1),
    );
    // 附加第二个BPF程序
    link = bpf_program__attach_netkit(skel->progs.tc2, ifindex, &optl);
    if (!ASSERT_OK_PTR(link, "link_attach")) goto cleanup;
    skel->links.tc2 = link;
    ...

    // 重置`.bss`区域
    tc_skel_reset_all_seen(skel);
    // 发送`ICMP`包，测试
    ASSERT_EQ(send_icmp(), 0, "icmp_pkt");

    // 判断测试结果
    ASSERT_EQ(skel->bss->seen_tc1, true, "seen_tc1");
    ASSERT_EQ(skel->bss->seen_eth, true, "seen_eth");
    ASSERT_EQ(skel->bss->seen_tc2, true, "seen_tc2");
cleanup:
    // 销毁BPF程序
    test_tc_link__destroy(skel);
    // 判断`netlink`程序是否已经分离
    assert_mprog_count_ifindex(ifindex, target, 0);
    // 销毁`netlink`
    destroy_netkit();
}
```

#### 2 读取数据过程

`tc1` 和 `tc2` BPF程序修改全局变量，用户空间读取全局变量的方式获取数据。

### 2.3 编译运行

`tc_netkit`程序是Linux内核自带的测试程序，在`tools/testing/selftests/bpf/prog_tests/`目录下。编译后运行，如下：

```bash
$ cd tools/testing/selftests/bpf/
$ sudo make
$ sudo test_progs -t tc_netkit
#423     tc_netkit_basic:OK
#424     tc_netkit_device:OK
#425     tc_netkit_multi_links:OK
#426     tc_netkit_multi_opts:OK
#427     tc_netkit_neigh_links:OK
#428     tc_netkit_pkt_type:OK
#429     tc_netkit_scrub:OK
Summary: 7/0 PASSED, 0 SKIPPED, 0 FAILED
```

## 3 `netkit`附加BPF的过程

`test_tc_link.c`文件中BPF程序的SEC名称为 `SEC("tcx/ingress")` 和 `SEC("tcx/egress")` ，但在附加BPF程序之前修改附加类型为 `BPF_NETKIT_PRIMARY` 或 `BPF_NETKIT_PEER`。 实际的前缀应该为 `SEC("netkit/primary")` 和 `SEC("tnetkit/peer")`，在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("netkit/primary",   SCHED_CLS, BPF_NETKIT_PRIMARY, SEC_NONE),
    SEC_DEF("netkit/peer",      SCHED_CLS, BPF_NETKIT_PEER, SEC_NONE),
    ...
};
```

`netkit/primary` 和 `netkit/peer` 前缀不支持自动附加。

### 3.1 创建`netkit`

用户空间使用`netkit`时，首先需要创建`netkit`，示例程序中通过`create_netkit`函数创建`netkit`网卡设备，并设置IP地址信息，如下：

```C
// file: ../src/tc_netkit.c
// 本地和对端网卡名称
#define netkit_peer "nk0"
#define netkit_name "nk1"

static int create_netkit(int mode, int policy, int peer_policy, int *ifindex,
            int scrub, int peer_scrub, __u32 flags)
{
    struct rtnl_handle rth = { .fd = -1 };
    struct iplink_req req = {};
    struct rtattr *linkinfo, *data;
    // 网卡类型
    const char *type = "netkit";
    int err;
    // 打开`netlink`
    err = rtnl_open(&rth, 0);
    if (!ASSERT_OK(err, "open_rtnetlink")) return err;
    // 设置`netlink`请求消息头
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    req.n.nlmsg_type = RTM_NEWLINK;
    req.i.ifi_family = AF_UNSPEC;

    // 设置`netlink`请求消息内容
    // 设置网卡接口名称
    addattr_l(&req.n, sizeof(req), IFLA_IFNAME, netkit_name, strlen(netkit_name));
    // 设置网卡接口类型
    linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
    addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, type, strlen(type));
    // 设置网卡接口属性
    data = addattr_nest(&req.n, sizeof(req), IFLA_INFO_DATA);
    addattr32(&req.n, sizeof(req), IFLA_NETKIT_POLICY, policy);
    addattr32(&req.n, sizeof(req), IFLA_NETKIT_PEER_POLICY, peer_policy);
    addattr32(&req.n, sizeof(req), IFLA_NETKIT_SCRUB, scrub);
    addattr32(&req.n, sizeof(req), IFLA_NETKIT_PEER_SCRUB, peer_scrub);
    addattr32(&req.n, sizeof(req), IFLA_NETKIT_MODE, mode);
    if (flags & FLAG_ADJUST_ROOM) {
        addattr16(&req.n, sizeof(req), IFLA_NETKIT_HEADROOM, NETKIT_HEADROOM);
        addattr16(&req.n, sizeof(req), IFLA_NETKIT_TAILROOM, NETKIT_TAILROOM);
    }
    addattr_nest_end(&req.n, data);
    addattr_nest_end(&req.n, linkinfo);
    // `netlink`交互
    err = rtnl_talk(&rth, &req.n, NULL);
    ASSERT_OK(err, "talk_rtnetlink");
    // 关闭`netlink`
    rtnl_close(&rth);
    // 获取网卡索引
    *ifindex = if_nametoindex(netkit_name);

    ASSERT_GT(*ifindex, 0, "retrieve_ifindex");
    // 创建网络命名空间
    ASSERT_OK(system("ip netns add foo"), "create netns");
    // 启用`netkit`网卡(`nk1`)和设置IP地址
    ASSERT_OK(system("ip link set dev " netkit_name " up"), "up primary");
    ASSERT_OK(system("ip addr add dev " netkit_name " 10.0.0.1/24"), "addr primary");
    // 设置`netkit`网卡的MAC地址
    if (mode == NETKIT_L3) {
        ASSERT_EQ(system("ip link set dev " netkit_name " addr ee:ff:bb:cc:aa:dd 2> /dev/null"), 512, "set hwaddress");
    } else {
        ASSERT_OK(system("ip link set dev " netkit_name " addr ee:ff:bb:cc:aa:dd"), "set hwaddress");
    }
    if (flags & FLAG_SAME_NETNS) {
        // 相同命名空间下，启用对端网卡(`nk0`)和设置IP地址
        ASSERT_OK(system("ip link set dev " netkit_peer " up"), "up peer");
        ASSERT_OK(system("ip addr add dev " netkit_peer " 10.0.0.2/24"), "addr peer");
    } else {
        // 不同命名空间下，启用对端网卡(`nk0`)和设置IP地址
        ASSERT_OK(system("ip link set " netkit_peer " netns foo"), "move peer");
        ASSERT_OK(system("ip netns exec foo ip link set dev " netkit_peer " up"), "up peer");
        ASSERT_OK(system("ip netns exec foo ip addr add dev " netkit_peer " 10.0.0.2/24"), "addr peer");
    }
    return err;
}
```

### 3.2 附加`netkit`

用户空间程序通过 `bpf_program__attach_netkit` 函数手动附加。`bpf_program__attach_netkit`函数检查输入的选项后，使用`bpf_link`方式加载NETKIT类型的BPF程序，如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link *bpf_program__attach_netkit(const struct bpf_program *prog, int ifindex,
            const struct bpf_netkit_opts *opts)
{
    LIBBPF_OPTS(bpf_link_create_opts, link_create_opts);
    __u32 relative_id;
    int relative_fd;
    // 检查`opts`选项
    if (!OPTS_VALID(opts, bpf_netkit_opts)) return libbpf_err_ptr(-EINVAL);
    // 获取相对id和相对fd
    relative_id = OPTS_GET(opts, relative_id, 0);
    relative_fd = OPTS_GET(opts, relative_fd, 0);

    // 检查网卡索引是否正确
    if (!ifindex) { ... }
    // 不能同时设置相对id和相对fd
    if (relative_fd && relative_id) { ... }
    // 设置`netkit`属性
    link_create_opts.netkit.expected_revision = OPTS_GET(opts, expected_revision, 0);
    link_create_opts.netkit.relative_fd = relative_fd;
    link_create_opts.netkit.relative_id = relative_id;
    link_create_opts.flags = OPTS_GET(opts, flags, 0);

    // target_fd/ifindex 在 LINK_CREATE 中是同一个字段
    return bpf_program_attach_fd(prog, ifindex, "netkit", &link_create_opts);
}
```

`bpf_program__attach_fd` 函数设置link属性后，调用`bpf_link_create`进行实际的创建，如下：

```C
// file: libbpf/src/libbpf.c
static struct bpf_link * bpf_program_attach_fd(const struct bpf_program *prog,
            int target_fd, const char *target_name, const struct bpf_link_create_opts *opts)
{
    enum bpf_attach_type attach_type;
    struct bpf_link *link;
    ...
    // 获取BPF程序fd
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) { ... }

    // 分配link，并设置detach接口
    link = calloc(1, sizeof(*link));
    if (!link) return libbpf_err_ptr(-ENOMEM);
    link->detach = &bpf_link__detach_fd;

    // 创建link
    attach_type = bpf_program__expected_attach_type(prog);
    link_fd = bpf_link_create(prog_fd, target_fd, attach_type, &opts);
    if (link_fd < 0) { ... }
    // 设置link->fd
    link->fd = link_fd;
    return link;
}
```

`bpf_link_create`在设置和检查`bpf_attr`属性后，使用`BPF_LINK_CREATE`指令进行BPF系统调用。如下：

```C
// file: libbpf/src/bpf.c
int bpf_link_create(int prog_fd, int target_fd, enum bpf_attach_type attach_type,
            const struct bpf_link_create_opts *opts)
{
    const size_t attr_sz = offsetofend(union bpf_attr, link_create);
    __u32 target_btf_id, iter_info_len;
    union bpf_attr attr;

    ...
    iter_info_len = OPTS_GET(opts, iter_info_len, 0);
    target_btf_id = OPTS_GET(opts, target_btf_id, 0);

    // 检查字段的设置情况，不能同时有效
    if (iter_info_len || target_btf_id) { ... }

    // attr属性设置
    memset(&attr, 0, attr_sz);
    attr.link_create.prog_fd = prog_fd;
    attr.link_create.target_fd = target_fd;
    attr.link_create.attach_type = attach_type;
    attr.link_create.flags = OPTS_GET(opts, flags, 0);

    // 设置了`btf_id`，直接进行处理
    if (target_btf_id) {
        attr.link_create.target_btf_id = target_btf_id;
        goto proceed;
    }
    // 根据附加类型设置opts属性
    switch (attach_type) {
    ...
    case BPF_NETKIT_PRIMARY:
    case BPF_NETKIT_PEER:
        // 设置`netkit`属性
        relative_fd = OPTS_GET(opts, netkit.relative_fd, 0);
        relative_id = OPTS_GET(opts, netkit.relative_id, 0);
        if (relative_fd && relative_id) return libbpf_err(-EINVAL);
        if (relative_id) {
            attr.link_create.netkit.relative_id = relative_id;
            attr.link_create.flags |= BPF_F_ID;
        } else {
            attr.link_create.netkit.relative_fd = relative_fd;
        }
        attr.link_create.netkit.expected_revision = OPTS_GET(opts, netkit.expected_revision, 0);
        if (!OPTS_ZEROED(opts, netkit)) return libbpf_err(-EINVAL);
        break;
        ...
    }
proceed:
    // BPF系统调用，使用`BPF_LINK_CREATE`指令
    fd = sys_bpf_fd(BPF_LINK_CREATE, &attr, attr_sz);
    // 创建link成功后返回
    if (fd >= 0) return fd;

    // 出现`EINVAL`错误时，重新尝试
    err = -errno;
    if (err != -EINVAL) return libbpf_err(err);
    ...
}
```

### 3.3 删除`netkit`

用户空间使用`netkit`完成后，需要删除`netkit`，示例程序中通过`destroy_netkit`函数删除创建`netkit`网卡设备。如下：

`destroy_netkit`函数销毁`netkit`，删除创建的网卡设备和命名空间，实现如下：

```C
// file: ../src/tc_netkit.c
static void destroy_netkit(void)
{
    // 删除网卡设备
    ASSERT_OK(system("ip link del dev " netkit_name), "del primary");
    // 删除网络命名空间
    ASSERT_OK(system("ip netns del foo"), "delete netns");
    ASSERT_EQ(if_nametoindex(netkit_name), 0, netkit_name "_ifindex");
}
```

## 4 内核实现

### 4.1 创建/销毁`NETKIT`网卡

#### 1 创建`NETKIT`网卡

##### (1) 用户空间`netlink`接口

用户空间在创建`netkit`网卡设备时，设置的 `网络协议:消息类型` 为 `AF_UNSPEC:RTM_NEWLINK`, 如下：

```C
// file: ../src/tc_netkit.c
static int create_netkit(int mode, int policy, int peer_policy, int *ifindex, bool same_netns)
{
    // 网卡类型
    const char *type = "netkit";

    // 打开`netlink`
    err = rtnl_open(&rth, 0);
    if (!ASSERT_OK(err, "open_rtnetlink")) return err;

    // 设置`netlink`请求消息头
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    req.n.nlmsg_type = RTM_NEWLINK;
    req.i.ifi_family = AF_UNSPEC;
    ...
}
```

##### (2) 内核空间`netlink`接口

在内核中相应的处理设置为：

```C
// file: net/core/rtnetlink.c
void __init rtnetlink_init(void)
{
    ...
    rtnl_register_many(rtnetlink_rtnl_msg_handlers);
}
static const struct rtnl_msg_handler rtnetlink_rtnl_msg_handlers[] __initconst = {
    {.msgtype = RTM_NEWLINK, .doit = rtnl_newlink, .flags = RTNL_FLAG_DOIT_PERNET},
     ...
};
```

`rtnl_newlink` 函数为 `PF_UNSPEC:RTM_NEWLINK` 设置的处理方式，在分配必要的内存后，调用`__rtnl_newlink`函数。实现如下：

```C
// file: net/core/rtnetlink.c
static int rtnl_newlink(struct sk_buff *skb, struct nlmsghdr *nlh, struct netlink_ext_ack *extack)
{
    struct net *tgt_net, *link_net = NULL, *peer_net = NULL;
    struct nlattr **tb, **linkinfo, **data = NULL;
    struct rtnl_link_ops *ops = NULL;
    struct rtnl_newlink_tbs *tbs;
    struct rtnl_nets rtnl_nets;
    int ops_srcu_index;
    int ret;

    // 分配`newlink`需要的内存空间
    tbs = kmalloc(sizeof(*tbs), GFP_KERNEL);
    if (!tbs) return -ENOMEM;

    tb = tbs->tb;
    // 解析netlink消息属性
    ret = nlmsg_parse_deprecated(nlh, sizeof(struct ifinfomsg), tb, IFLA_MAX, ifla_policy, extack);
    if (ret < 0) goto free;

    // 验证rtnetlink请求不存在多个网络命名空间的情况
    ret = rtnl_ensure_unique_netns(tb, extack, false);
    if (ret < 0) goto free;

    linkinfo = tbs->linkinfo;
    if (tb[IFLA_LINKINFO]) {
        // 存在linkinfo属性时，解析linkinfo
        ret = nla_parse_nested_deprecated(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO], ifla_info_policy, NULL);
        if (ret < 0) goto free;
    } else {    
        memset(linkinfo, 0, sizeof(tbs->linkinfo));
    }

    if (linkinfo[IFLA_INFO_KIND]) {
        char kind[MODULE_NAME_LEN];
        // `INFO_KIND`属性存在的情况下，根据`kind`获取网卡的`.ops`操作接口
        nla_strscpy(kind, linkinfo[IFLA_INFO_KIND], sizeof(kind));
        ops = rtnl_link_ops_get(kind, &ops_srcu_index);
#ifdef CONFIG_MODULES
    if (!ops) {
            request_module("rtnl-link-%s", kind);
            ops = rtnl_link_ops_get(kind, &ops_srcu_index);
        }
#endif
    }

    rtnl_nets_init(&rtnl_nets);

    // `ops`存在的情况下，验证`IFLA_INFO_DATA`
    if (ops) {
        ...

        // `IFLA_INFO_DATA`属性存在的情况下，解析`IFLA_INFO_DATA`
        if (ops->maxtype && linkinfo[IFLA_INFO_DATA]) {
            ret = nla_parse_nested_deprecated(tbs->attr, ops->maxtype, linkinfo[IFLA_INFO_DATA], ops->policy, extack);
            if (ret < 0) goto put_ops;
            data = tbs->attr;
        }
        // `validate`函数存在的情况下，调用`validate`函数进行验证
        if (ops->validate) {
            ret = ops->validate(tb, data, extack);
            if (ret < 0) goto put_ops;
        }
        // 获取`peer_net`
        if (ops->peer_type) {
            peer_net = rtnl_get_peer_net(ops, tb, data, extack);
            if (IS_ERR(peer_net)) { ret = PTR_ERR(peer_net); goto put_ops; }
            // `peer_net`存在的情况下，添加到网络命名空间中
            if (peer_net) rtnl_nets_add(&rtnl_nets, peer_net);
        }
    }
    // 获取目标网络
    tgt_net = rtnl_link_get_net_capable(skb, sock_net(skb->sk), tb, CAP_NET_ADMIN);
    if (IS_ERR(tgt_net)) { ret = PTR_ERR(tgt_net); goto put_net; }
    // 添加`tgt_net`到网络命名空间中
    rtnl_nets_add(&rtnl_nets, tgt_net);

    // 获取`IFLA_LINK_NETNSID`属性，获取网络命名空间
    if (tb[IFLA_LINK_NETNSID])if (tb[IFLA_LINK_NETNSID]) {
        int id = nla_get_s32(tb[IFLA_LINK_NETNSID]);

        link_net = get_net_ns_by_id(tgt_net, id);
        if (!link_net) { ... }
        // 添加`link_net`到网络命名空间中
        rtnl_nets_add(&rtnl_nets, link_net);
        // 验证`link_net`网络命名空间的权限
        if (!netlink_ns_capable(skb, link_net->user_ns, CAP_NET_ADMIN)) { ret = -EPERM; goto put_net; }
    }

    rtnl_nets_lock(&rtnl_nets);
    // 创建新的网卡
    ret = __rtnl_newlink(skb, nlh, ops, tgt_net, link_net, peer_net, tbs, data, extack);
    rtnl_nets_unlock(&rtnl_nets);

put_net:
    rtnl_nets_destroy(&rtnl_nets);
put_ops:
    if (ops) rtnl_link_ops_put(ops, ops_srcu_index);
free:
    kfree(tbs);
    return ret;
}
```

`__rtnl_newlink`函数解析用户空间设置后，在指定网卡的情况下修改网卡设置；否则，创建新建的网卡设置，如下：

```C
// file: net/core/rtnetlink.c
static int __rtnl_newlink(struct sk_buff *skb, struct nlmsghdr *nlh, const struct rtnl_link_ops *ops,
            struct net *tgt_net, struct net *link_net, struct net *peer_net,
            struct rtnl_newlink_tbs *tbs, struct nlattr **data, struct netlink_ext_ack *extack)
{
    struct nlattr ** const tb = tbs->tb;
    struct net *net = sock_net(skb->sk);
    struct net *device_net;
    struct net_device *dev;
    struct ifinfomsg *ifm;
    bool link_specified;

    // 获取网卡所在的网络命名空间
    device_net = (nlh->nlmsg_flags & NLM_F_CREATE) && (nlh->nlmsg_flags & NLM_F_EXCL) ?
            tgt_net : net;

    // 获取网卡设备
    ifm = nlmsg_data(nlh);
    if (ifm->ifi_index > 0) {
        link_specified = true;
        // 根据`ifm->ifi_index`获取网卡设备
        dev = __dev_get_by_index(device_net, ifm->ifi_index);
    } else if (ifm->ifi_index < 0) {
        NL_SET_ERR_MSG(extack, "ifindex can't be negative");
        return -EINVAL;
    } else if (tb[IFLA_IFNAME] || tb[IFLA_ALT_IFNAME]) {
        link_specified = true;
        // 根据`ifm->ifi_name`获取网卡设备
        dev = rtnl_dev_get(device_net, tb);
    } else {
        link_specified = false;
        dev = NULL;
    }

    // 网卡设备存在的情况下，修改网卡信息
    if (dev) return rtnl_changelink(skb, nlh, ops, dev, tgt_net, tbs, data, extack);

    if (!(nlh->nlmsg_flags & NLM_F_CREATE)) {
        if (link_specified || !tb[IFLA_GROUP]) return -ENODEV;
        // 修改网卡信息
        return rtnl_group_changelink(skb, net, tgt_net, nla_get_u32(tb[IFLA_GROUP]), ifm, extack, tb);
    }

    if (tb[IFLA_MAP] || tb[IFLA_PROTINFO]) return -EOPNOTSUPP;
    if (!ops) { NL_SET_ERR_MSG(extack, "Unknown device type"); return -EOPNOTSUPP; }

    // 创建网卡信息
    return rtnl_newlink_create(skb, ifm, ops, tgt_net, link_net, peer_net, nlh, tb, data, extack);
}
```

在设置`INFO_KIND`属性存在的情况下, 通过`rtnl_link_ops_get`函数获取对应的操作接口，如下：

```C
// file: net/core/rtnetlink.c
static const struct rtnl_link_ops *rtnl_link_ops_get(const char *kind)
{
    const struct rtnl_link_ops *ops;
    // 遍历`link_ops`列表，逐项获取
    list_for_each_entry(ops, &link_ops, list) {
        if (!strcmp(ops->kind, kind)) return ops;
    }
    return NULL;
}
```

##### (3) 创建网卡的过程

`rtnl_newlink_create` 函数创建网卡设备，实现如下：

```C
// file: net/core/rtnetlink.c
static int rtnl_newlink_create(struct sk_buff *skb, struct ifinfomsg *ifm, const struct rtnl_link_ops *ops,
                struct net *tgt_net, struct net *link_net, struct net *peer_net, const struct nlmsghdr *nlh, 
                struct nlattr **tb, struct nlattr **data, struct netlink_ext_ack *extack)
{
    unsigned char name_assign_type = NET_NAME_USER;
    struct rtnl_newlink_params params = {
        .src_net = sock_net(skb->sk),
        .link_net = link_net,
        .peer_net = peer_net,
        .tb = tb,
        .data = data,
    };
    u32 portid = NETLINK_CB(skb).portid;
    struct net_device *dev;
    char ifname[IFNAMSIZ];
    int err;

    // `ops`操作接口，`.alloc`或者`.setup`接口必须设置一个
    if (!ops->alloc && !ops->setup) return -EOPNOTSUPP;
    // 获取网络接口名称
    if (tb[IFLA_IFNAME]) {
        nla_strscpy(ifname, tb[IFLA_IFNAME], IFNAMSIZ);
    } else {
        snprintf(ifname, IFNAMSIZ, "%s%%d", ops->kind);
        name_assign_type = NET_NAME_ENUM;
    }

    // 创建新的网卡
    dev = rtnl_create_link(tgt_net, ifname, name_assign_type, ops, tb, extack);
    if (IS_ERR(dev)) { err = PTR_ERR(dev); goto out; }

    // 设置网卡索引
    dev->ifindex = ifm->ifi_index;
    
    // 注册网卡设备
    if (ops->newlink)
        err = ops->newlink(link_net ? : net, dev, tb, data, extack);
    else
        err = register_netdevice(dev);
    if (err < 0) { free_netdev(dev); goto out; }
    
    netdev_lock_ops(dev);
    // 配置网卡
    err = rtnl_configure_link(dev, ifm, portid, nlh);
    if (err < 0) goto out_unregister;
    if (tb[IFLA_MASTER]) {
        err = do_set_master(dev, nla_get_u32(tb[IFLA_MASTER]), extack);
        if (err) goto out_unregister;
    }
    netdev_unlock_ops(dev);
out:
    return err;
out_unregister:
    netdev_unlock_ops(dev);
    // 失败时的注销过程
    if (ops->newlink) {
        LIST_HEAD(list_kill); 
        ops->dellink(dev, &list_kill);
        unregister_netdevice_many(&list_kill);
    } else {
        unregister_netdevice(dev);
    }
    goto out;
}
```

`rtnl_create_link`函数创建新的网卡，设置网卡的基本属性，实现如下：

```C
// file: net/core/rtnetlink.c
struct net_device *rtnl_create_link(struct net *net, const char *ifname,
                unsigned char name_assign_type, const struct rtnl_link_ops *ops,
                struct nlattr *tb[], struct netlink_ext_ack *extack)
{
    struct net_device *dev;
    unsigned int num_tx_queues = 1;
    unsigned int num_rx_queues = 1;
    int err;

    // 获取发送队列数量
    if (tb[IFLA_NUM_TX_QUEUES]) num_tx_queues = nla_get_u32(tb[IFLA_NUM_TX_QUEUES]);
    else if (ops->get_num_tx_queues) num_tx_queues = ops->get_num_tx_queues();
    // 获取接收队列数量
    if (tb[IFLA_NUM_RX_QUEUES]) num_rx_queues = nla_get_u32(tb[IFLA_NUM_RX_QUEUES]);
    else if (ops->get_num_rx_queues) num_rx_queues = ops->get_num_rx_queues();
    // 验证队列数量
    if (num_tx_queues < 1 || num_tx_queues > 4096) { ... }
    if (num_rx_queues < 1 || num_rx_queues > 4096) { ... }

    if (ops->alloc) {
        // `.alloc`接口创建网卡设备
        dev = ops->alloc(tb, ifname, name_assign_type, num_tx_queues, num_rx_queues);
        if (IS_ERR(dev)) return dev;
    } else {
        // 创建网卡设备
        dev = alloc_netdev_mqs(ops->priv_size, ifname, name_assign_type, ops->setup,
                num_tx_queues, num_rx_queues);
    }
    // 创建失败时，返回错误信息
    if (!dev) return ERR_PTR(-ENOMEM);
    // 验证`link`消息
    err = validate_linkmsg(dev, tb, extack);
    if (err < 0) { free_netdev(dev); return ERR_PTR(err); }

    // 设置网卡设备
    dev_net_set(dev, net);
    dev->rtnl_link_ops = ops;
    dev->rtnl_link_state = RTNL_LINK_INITIALIZING;

    // 存在`MTU`时，设置网卡的mtu
    if (tb[IFLA_MTU]) {
        u32 mtu = nla_get_u32(tb[IFLA_MTU]);
        err = dev_validate_mtu(dev, mtu, extack);
        if (err) { ... }
        dev->mtu = mtu;
    }
    // 其他网卡属性设置
    ...
    return dev;
}
```

`alloc_netdev_mqs`函数分配专用数据区域的`net_device`结构，供驱动程序使用，并执行基本的初始化。此外，为设备上的每个队列分配队列结构。实现如下：

```C
// file: net/core/dev.c
struct net_device *alloc_netdev_mqs(int sizeof_priv, const char *name,
        unsigned char name_assign_type, void (*setup)(struct net_device *),
        unsigned int txqs, unsigned int rxqs)
{
    struct net_device *dev;
    size_t napi_config_sz;
    unsigned int maxqs;

    BUG_ON(strlen(name) >= sizeof(dev->name));
    // 发送队列、接收队列数量检查
    if (txqs < 1) { ... }
    if (rxqs < 1) { ... }

    maxqs = max(txqs, rxqs);
    // 分配`net_device`结构
    dev = kvzalloc(struct_size(dev, priv, sizeof_priv), GFP_KERNEL_ACCOUNT | __GFP_RETRY_MAYFAIL);
    if (!dev) return NULL;

    dev->priv_len = sizeof_priv;
    // 初始化网卡计数器追踪器
    ref_tracker_dir_init(&dev->refcnt_tracker, 128, name);
    // 初始化网卡设备的引用计数
#ifdef CONFIG_PCPU_DEV_REFCNT
    dev->pcpu_refcnt = alloc_percpu(int);
    if (!dev->pcpu_refcnt) goto free_dev;
    __dev_hold(dev);
#else
    refcount_set(&dev->dev_refcnt, 1);
#endif
    // 初始化网卡IP地址列表
    if (dev_addr_init(dev)) goto free_pcpu;
    // 初始化网卡MAC地址列表
    dev_mc_init(dev);
    // 初始化网卡单波地址列表 
    dev_uc_init(dev);
    // 设置网络命名空间
    dev_net_set(dev, &init_net);
    // 网卡`GSO`，`TSO`属性设置
    dev->gso_max_size = GSO_LEGACY_MAX_SIZE;
    dev->xdp_zc_max_segs = 1;
    dev->gso_max_segs = GSO_MAX_SEGS;
    dev->gro_max_size = GRO_LEGACY_MAX_SIZE;
    dev->gso_ipv4_max_size = GSO_LEGACY_MAX_SIZE;
    dev->gro_ipv4_max_size = GRO_LEGACY_MAX_SIZE;
    dev->tso_max_size = TSO_LEGACY_MAX_SIZE;
    dev->tso_max_segs = TSO_MAX_SEGS;
    dev->upper_level = 1;
    dev->lower_level = 1;
#ifdef CONFIG_LOCKDEP
    dev->nested_level = 0;
    INIT_LIST_HEAD(&dev->unlink_list);
#endif
    // 网卡需要的列表
    INIT_LIST_HEAD(&dev->napi_list);
    INIT_LIST_HEAD(&dev->unreg_list);
    INIT_LIST_HEAD(&dev->close_list);
    INIT_LIST_HEAD(&dev->link_watch_list);
    INIT_LIST_HEAD(&dev->adj_list.upper);
    INIT_LIST_HEAD(&dev->adj_list.lower);
    INIT_LIST_HEAD(&dev->ptype_all);
    INIT_LIST_HEAD(&dev->ptype_specific);
    INIT_LIST_HEAD(&dev->net_notifier_list);
#ifdef CONFIG_NET_SCHED
    hash_init(dev->qdisc_hash);
#endif
    // 网卡私有标记设置
    dev->priv_flags = IFF_XMIT_DST_RELEASE | IFF_XMIT_DST_RELEASE_PERM;
    // 回调函数设置网卡
    setup(dev);

    // 网卡接收队列长度设置
    if (!dev->tx_queue_len) {
        dev->priv_flags |= IFF_NO_QUEUE;
        dev->tx_queue_len = DEFAULT_TX_QUEUE_LEN;
    }
    // 设置网卡接发送列数量，并分配发送队列
    dev->num_tx_queues = txqs;
    dev->real_num_tx_queues = txqs;
    if (netif_alloc_netdev_queues(dev)) goto free_all;
    // 设置网卡接收队列数量，并分配接收队列
    dev->num_rx_queues = rxqs;
    dev->real_num_rx_queues = rxqs;
    if (netif_alloc_rx_queues(dev)) goto free_all;

    // 创建`ethtool`
    dev->ethtool = kzalloc(sizeof(*dev->ethtool), GFP_KERNEL_ACCOUNT);
    if (!dev->ethtool) goto free_all;
    // 创建`cfg`
    dev->cfg = kzalloc(sizeof(*dev->cfg), GFP_KERNEL_ACCOUNT);
    if (!dev->cfg) goto free_all;
    dev->cfg_pending = dev->cfg;
    // 创建`napi`
    napi_config_sz = array_size(maxqs, sizeof(*dev->napi_config));
    dev->napi_config = kvzalloc(napi_config_sz, GFP_KERNEL_ACCOUNT);
    if (!dev->napi_config) goto free_all;

    // 设置网卡名称
    strcpy(dev->name, name);
    dev->name_assign_type = name_assign_type;
    dev->group = INIT_NETDEV_GROUP;
    // 网卡`ethtool_ops`接口设置
    if (!dev->ethtool_ops) dev->ethtool_ops = &default_ethtool_ops;

    // 网卡`nfhook`初始化
    nf_hook_netdev_init(dev);
    return dev;
    // 失败时的清理
free_all:
    free_netdev(dev);
    return NULL;
free_pcpu:
#ifdef CONFIG_PCPU_DEV_REFCNT
    free_percpu(dev->pcpu_refcnt);
free_dev:
#endif
    netdev_freemem(dev);
    return NULL;
}
```

#### 2 销毁`NETKIT`网卡

##### (1) 用户空间命令

用户空间通过 `ip link del dev %netkit_name%` 命令删除已存在的网卡。

##### (2) 内核空间`netlink`接口

在内核中相应的处理设置为：

```C
// file: net/core/rtnetlink.c
static const struct rtnl_msg_handler rtnetlink_rtnl_msg_handlers[] __initconst = {
    ...
    {.msgtype = RTM_DELLINK, .doit = rtnl_dellink, .flags = RTNL_FLAG_DOIT_PERNET_WIP},
    ...
} ;
```

`rtnl_dellink` 函数为 `PF_UNSPEC:RTM_DELLINK` 设置的处理方式，在验证用户空间的`netlink`设置后，获取相应的网卡设备后，删除网卡设备。实现如下：

```C
// file: net/core/rtnetlink.c
static int rtnl_dellink(struct sk_buff *skb, struct nlmsghdr *nlh, struct netlink_ext_ack *extack)
{
    struct ifinfomsg *ifm = nlmsg_data(nlh);
    struct net *net = sock_net(skb->sk);
    u32 portid = NETLINK_CB(skb).portid;
    struct net *tgt_net = net;
    struct net_device *dev = NULL;
    ...

    // 解析netlink消息属性
    err = nlmsg_parse_deprecated(nlh, sizeof(*ifm), tb, IFLA_MAX, ifla_policy, extack);
    if (err < 0) return err;
    // 验证rtnetlink请求只存在单一网络命名空间的情况
    err = rtnl_ensure_unique_netns(tb, extack, true);
    if (err < 0) return err;

    // 获取目标网络命名空间
    if (tb[IFLA_TARGET_NETNSID]) {
        netnsid = nla_get_s32(tb[IFLA_TARGET_NETNSID]);
        tgt_net = rtnl_get_net_ns_capable(NETLINK_CB(skb).sk, netnsid);
        if (IS_ERR(tgt_net)) return PTR_ERR(tgt_net);
    }

    rtnl_net_lock(tgt_net);
    // 获取设置的网卡设置，通过网络设备索引(ifm->ifi_index)或名称获取
    if (ifm->ifi_index > 0)
        dev = __dev_get_by_index(tgt_net, ifm->ifi_index);
    else if (tb[IFLA_IFNAME] || tb[IFLA_ALT_IFNAME])
        dev = rtnl_dev_get(net, tb);
    
    if (dev)
        // 删除网卡设备
        err = rtnl_delete_link(dev, portid, nlh);
    else if (ifm->ifi_index > 0 || tb[IFLA_IFNAME] || tb[IFLA_ALT_IFNAME])
        err = -ENODEV;
    else if (tb[IFLA_GROUP])
        // 从group中删除网卡设备
        err = rtnl_group_dellink(tgt_net, nla_get_u32(tb[IFLA_GROUP]));
    else
        err = -EINVAL;
    
    rtnl_net_unlock(tgt_net);
    if (netnsid >= 0) put_net(tgt_net);
    return err;
}
```

`rtnl_delete_link`函数调用`ops->dellink`接口删除网卡后，通知网卡注销消息，实现如下：

```C
// file: net/core/rtnetlink.c
int rtnl_delete_link(struct net_device *dev, u32 portid, const struct nlmsghdr *nlh)
{
    const struct rtnl_link_ops *ops;
    LIST_HEAD(list_kill);

    ops = dev->rtnl_link_ops;
    if (!ops || !ops->dellink) return -EOPNOTSUPP;
    // `.dellink`接口删除网卡
    ops->dellink(dev, &list_kill);
    // 通知网卡注销消息
    unregister_netdevice_many_notify(&list_kill, portid, nlh);
    return 0;
}
```

#### 3 `NETKIT`网卡的实现过程

##### (1) 网卡操作接口的注册/注销过程

用户空间在创建网卡时，设置的类型为`netkit`，在内核中对应操作接口为`netkit_link_ops`，如下：

```C
// file: drivers/net/netkit.c
#define DRV_NAME "netkit"
static struct rtnl_link_ops netkit_link_ops = {
    .kind       = DRV_NAME,
    .priv_size  = sizeof(struct netkit),
    .setup      = netkit_setup,
    .newlink    = netkit_new_link,
    .dellink    = netkit_del_link,
    .changelink = netkit_change_link,
    .get_link_net   = netkit_get_link_net,
    .get_size   = netkit_get_size,
    .fill_info  = netkit_fill_info,
    .policy     = netkit_policy,
    .validate   = netkit_validate,
    .peer_type  = IFLA_NETKIT_PEER_INFO,
    .maxtype    = IFLA_NETKIT_MAX,
};
```

* 注册过程
  
在`module_init`阶段注册到内核中，如下：

```C
// file: drivers/net/netkit.c
static __init int netkit_init(void)
{
    BUILD_BUG_ON((int)NETKIT_NEXT != (int)TCX_NEXT ||
            (int)NETKIT_PASS != (int)TCX_PASS ||
            (int)NETKIT_DROP != (int)TCX_DROP ||
            (int)NETKIT_REDIRECT != (int)TCX_REDIRECT);
    // 注册`ops`
    return rtnl_link_register(&netkit_link_ops);
}
module_init(netkit_init);
```

`rtnl_link_register`函数注册网络操作接口到内核中，实现如下：

```C
// file: drivers/net/netkit.c
int rtnl_link_register(struct rtnl_link_ops *ops)
{
    struct rtnl_link_ops *tmp;
    int err;
    // 检查最大的类型，避免栈空间溢出
    if (WARN_ON(ops->maxtype > RTNL_MAX_TYPE ||
            ops->slave_maxtype > RTNL_SLAVE_MAX_TYPE))
        return -EINVAL;

    // 检查必要的`.dellink`接口
    if ((ops->alloc || ops->setup) && !ops->dellink)
        ops->dellink = unregister_netdevice_queue;
    // 初始化`srcu`(sleep-RCU)结构
    err = init_srcu_struct(&ops->srcu);
    if (err) return err;
    
    mutex_lock(&link_ops_mutex);
    list_for_each_entry(tmp, &link_ops, list) {
        // 检查`ops`是否存在
        if (!strcmp(ops->kind, tmp->kind)) { err = -EEXIST; goto unlock; }
    }
    // 添加到`link_ops`列表中
    list_add_tail_rcu(&ops->list, &link_ops);
unlock:
    mutex_unlock(&link_ops_mutex);
    return err;
}
```

* 注销过程

在`module_exit`阶段注销，如下：

```C
// file: drivers/net/netkit.c
static __exit void netkit_exit(void)
{
    //  注销`ops`
    rtnl_link_unregister(&netkit_link_ops);
}
module_exit(netkit_exit);
```

`rtnl_link_unregister`函数注销网络操作接口，实现如下：

```C
// file: net/core/rtnetlink.c
void rtnl_link_unregister(struct rtnl_link_ops *ops)
{
    struct net *net;
    // 从`link_ops`列表中删除`ops`
    mutex_lock(&link_ops_mutex);
    list_del_rcu(&ops->list);
    mutex_unlock(&link_ops_mutex);

    // 同步`srcu`后，清理
    synchronize_srcu(&ops->srcu);
    cleanup_srcu_struct(&ops->srcu);

    down_write(&pernet_ops_rwsem);
    rtnl_lock_unregistering_all();

    // 遍历所有的命名空间，删除网络设置
    for_each_net(net)
        __rtnl_kill_links(net, ops);

    rtnl_unlock();
    up_write(&pernet_ops_rwsem);
}
```

`__rtnl_kill_links`函数从网络命名空间中删除`rtnl_link_ops`对应的网卡，实现如下：

```C
// file: net/core/rtnetlink.c
static void __rtnl_kill_links(struct net *net, struct rtnl_link_ops *ops)
{
    struct net_device *dev;
    LIST_HEAD(list_kill);
    // 遍历网络命名空间中所有的网卡
    for_each_netdev(net, dev) {
        // 网卡`.rtnl_link_ops`操作接口相同时，删除网卡设备
        if (dev->rtnl_link_ops == ops)
            ops->dellink(dev, &list_kill);
    }
    // 注销多个网卡设备
    unregister_netdevice_many(&list_kill);
}
```

##### (2) 网卡的设置接口

在创建`netkit`网卡时，`netkit`不支持`.alloc`接口，提供了`.setup`接口。`netkit`网卡的`.setup`接口设置为`netkit_setup`，对网卡进行初始化设置，如下：

```C
// file: drivers/net/netkit.c
static void netkit_setup(struct net_device *dev)
{
    // 网卡支持的硬件特性
    static const netdev_features_t netkit_features_hw_vlan =
        NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX |
        NETIF_F_HW_VLAN_STAG_TX | NETIF_F_HW_VLAN_STAG_RX;
    static const netdev_features_t netkit_features =
        netkit_features_hw_vlan | NETIF_F_SG | NETIF_F_FRAGLIST | 
        NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_SCTP_CRC |
        NETIF_F_HIGHDMA | NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL;

    // 设置以太网网卡设备
    ether_setup(dev);
    // 网卡`mtu`设置
    dev->max_mtu = ETH_MAX_MTU;
    dev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
    // 网卡`flags`设置
    dev->flags |= IFF_NOARP;
    dev->priv_flags &= ~IFF_TX_SKB_SHARING;
    dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
    dev->priv_flags |= IFF_PHONY_HEADROOM;
    dev->priv_flags |= IFF_NO_QUEUE;
    dev->priv_flags |= IFF_DISABLE_NETPOLL;
    dev->lltx = true;
    // 网卡`ethtool_ops`和`netdev_ops`接口设置
    dev->ethtool_ops = &netkit_ethtool_ops;
    dev->netdev_ops  = &netkit_netdev_ops;
    // 网卡特性设置
    dev->features |= netkit_features | NETIF_F_LLTX;
    dev->hw_features = netkit_features;
    dev->hw_enc_features = netkit_features;
    dev->mpls_features = NETIF_F_HW_CSUM | NETIF_F_GSO_SOFTWARE;
    dev->vlan_features = dev->features & ~netkit_features_hw_vlan;

    dev->needs_free_netdev = true;

    netif_set_tso_max_size(dev, GSO_MAX_SIZE);
}
```

`ether_setup`函数设置以太网网卡设备，使用以太网通用字段设置，如下：

```C
// file: net/ethernet/eth.c
void ether_setup(struct net_device *dev)
{
    // 以太网通用字段设置
    dev->header_ops     = &eth_header_ops;
    dev->type           = ARPHRD_ETHER;
    dev->hard_header_len    = ETH_HLEN;
    dev->min_header_len = ETH_HLEN;
    dev->mtu            = ETH_DATA_LEN;
    dev->min_mtu        = ETH_MIN_MTU;
    dev->max_mtu        = ETH_DATA_LEN;
    dev->addr_len       = ETH_ALEN;
    dev->tx_queue_len   = DEFAULT_TX_QUEUE_LEN;
    dev->flags          = IFF_BROADCAST|IFF_MULTICAST;
    dev->priv_flags     |= IFF_TX_SKB_SHARING;
    // 网卡广播地址设置
    eth_broadcast_addr(dev->broadcast);
}
```

`netif_set_tso_max_size`函数设置支持的TSO帧最大大小，如下：

```C
// file: net/core/dev.c
void netif_set_tso_max_size(struct net_device *dev, unsigned int size)
{
    dev->tso_max_size = min(GSO_MAX_SIZE, size);
    if (size < READ_ONCE(dev->gso_max_size))
        netif_set_gso_max_size(dev, size);
    if (size < READ_ONCE(dev->gso_ipv4_max_size))
        netif_set_gso_ipv4_max_size(dev, size);
}
```

##### (3) 网卡的注册接口

在创建网卡后，支持`.newlink`接口时，进行自定义注册。设置为`netkit_new_link`，实现如下：

```C
// file: drivers/net/netkit.c
static int netkit_new_link(struct net_device *dev, struct rtnl_newlink_params *params,
        struct netlink_ext_ack *extack)
{
    struct net *peer_net = rtnl_newlink_peer_net(params);
    enum netkit_scrub scrub_prim = NETKIT_SCRUB_DEFAULT;
    enum netkit_scrub scrub_peer = NETKIT_SCRUB_DEFAULT;
    // 默认策略和工作模式
    enum netkit_action default_prim = NETKIT_PASS;
    enum netkit_action default_peer = NETKIT_PASS;
    enum netkit_mode mode = NETKIT_L3;
    struct netkit *nk;
    ...

    tbp = tb;
    if (data) {
        // 用户空间网卡设置
        if (data[IFLA_NETKIT_MODE]) 
            mode = nla_get_u32(data[IFLA_NETKIT_MODE]);
        if (data[IFLA_NETKIT_PEER_INFO]) {
            attr = data[IFLA_NETKIT_PEER_INFO];
            ifmp = nla_data(attr);
            rtnl_nla_parse_ifinfomsg(peer_tb, attr, extack);
            tbp = peer_tb;
        }
        if (data[IFLA_NETKIT_SCRUB])
            scrub_prim = nla_get_u32(data[IFLA_NETKIT_SCRUB]);
        if (data[IFLA_NETKIT_PEER_SCRUB])
            scrub_peer = nla_get_u32(data[IFLA_NETKIT_PEER_SCRUB]);
        if (data[IFLA_NETKIT_POLICY]) {
            attr = data[IFLA_NETKIT_POLICY];
            default_prim = nla_get_u32(attr);
            err = netkit_check_policy(default_prim, attr, extack);
            if (err < 0) return err;
        }
        if (data[IFLA_NETKIT_PEER_POLICY]) {
            attr = data[IFLA_NETKIT_PEER_POLICY];
            default_peer = nla_get_u32(attr);
            err = netkit_check_policy(default_peer, attr, extack);
            if (err < 0) return err;
        }
        if (data[IFLA_NETKIT_HEADROOM])
            headroom = nla_get_u16(data[IFLA_NETKIT_HEADROOM]);
        if (data[IFLA_NETKIT_TAILROOM])
            tailroom = nla_get_u16(data[IFLA_NETKIT_TAILROOM]);
    }

    // 对端网卡名称设置
    if (ifmp && tbp[IFLA_IFNAME]) {
        nla_strscpy(ifname, tbp[IFLA_IFNAME], IFNAMSIZ);
        ifname_assign_type = NET_NAME_USER;
    } else {
        strscpy(ifname, "nk%d", IFNAMSIZ);
        ifname_assign_type = NET_NAME_ENUM;
    }
    // 网卡工作模式检查
    if (mode != NETKIT_L2 && (tb[IFLA_ADDRESS] || tbp[IFLA_ADDRESS]))
        return -EOPNOTSUPP;
    // 创建对端网卡
    peer = rtnl_create_link(peer_net, ifname, ifname_assign_type, &netkit_link_ops, tbp, extack);
    if (IS_ERR(peer)) { ... }
    // 对端网卡TSO设置，继承当前网卡设置
    netif_inherit_tso_max(peer, dev);
    // header,tail设置
    if (headroom) {
        peer->needed_headroom = headroom;
        dev->needed_headroom = headroom;
    }
    if (tailroom) {
        peer->needed_tailroom = tailroom;
        dev->needed_tailroom = tailroom;
    }

    // 网卡工作在L2模式下，对端网卡随机化MAC地址
    if (mode == NETKIT_L2 && !(ifmp && tbp[IFLA_ADDRESS]))
        eth_hw_addr_random(peer);
    // 对端网卡索引设置
    if (ifmp && dev->ifindex)
        peer->ifindex = ifmp->ifi_index;
    // 对端网卡私有数据设置
    nk = netkit_priv(peer);
    nk->primary = false;
    nk->policy = policy_peer;
    nk->scrub = scrub_peer;
    nk->mode = mode;
    nk->headroom = headroom;
    bpf_mprog_bundle_init(&nk->bundle);
    // 注册对端网卡
    err = register_netdevice(peer);
    put_net(net);
    if (err < 0) goto err_register_peer;
    netif_carrier_off(peer);
    // L2模式下，对端网卡不支持`ARP`
    if (mode == NETKIT_L2)
        dev_change_flags(peer, peer->flags & ~IFF_NOARP, NULL);
    // 配置对端网卡
    err = rtnl_configure_link(peer, NULL, 0, NULL);
    if (err < 0) goto err_configure_peer;

    // 网卡工作在L2模式下，本地网卡随机化MAC地址
    if (mode == NETKIT_L2 && !tb[IFLA_ADDRESS])
        eth_hw_addr_random(dev);
    // 本地网卡名称设置
    if (tb[IFLA_IFNAME])
        nla_strscpy(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
    else
        strscpy(dev->name, "nk%d", IFNAMSIZ);
    // 本地网卡私有数据设置
    nk = netkit_priv(dev);
    nk->primary = true;
    nk->policy = policy_prim;
    nk->scrub = scrub_prim;
    nk->mode = mode;
    nk->headroom = headroom;
    bpf_mprog_bundle_init(&nk->bundle);
    // 注册本地网卡
    err = register_netdevice(dev);
    if (err < 0) goto err_configure_peer;
    netif_carrier_off(dev);
    if (mode == NETKIT_L2)
        dev_change_flags(dev, dev->flags & ~IFF_NOARP, NULL);
    // 本地网卡、对端网卡设置
    rcu_assign_pointer(netkit_priv(dev)->peer, peer);
    rcu_assign_pointer(netkit_priv(peer)->peer, dev);
    return 0;
err_configure_peer:
    unregister_netdevice(peer);
    return err;
err_register_peer:
    free_netdev(peer);
    return err;
}
```

`netkit`网卡的私有数据对应的数据是`struct netkit`结构，定义如下：

```C
// file: drivers/net/netkit.c
struct netkit {
    struct net_device __rcu *peer;
    struct bpf_mprog_entry __rcu *active;
    enum netkit_action policy;
    enum netkit_scrub scrub;
    struct bpf_mprog_bundle bundle;

    enum netkit_mode mode;
    bool primary;
    u32 headroom;
};
```

`.peer`字段表示对端网卡；`.active`字段表示使用的`mprog`。

##### (4) 网卡的清理接口

在删除网卡时，调用`.dellink`接口进行网卡的清理操作，`netkit`网卡的该接口设置为`netkit_del_link`，实现如下：

```C
// file: drivers/net/netkit.c
static void netkit_del_link(struct net_device *dev, struct list_head *head)
{
    struct netkit *nk = netkit_priv(dev);
    // 获取对端网卡
    struct net_device *peer = rtnl_dereference(nk->peer);
    // 设置对端为NULL后，注销本地网卡
    RCU_INIT_POINTER(nk->peer, NULL);
    unregister_netdevice_queue(dev, head);
    if (peer) {
        // 对端网卡设置对端为NULL后，注销对端网卡
        nk = netkit_priv(peer);
        RCU_INIT_POINTER(nk->peer, NULL);
        unregister_netdevice_queue(peer, head);
    }
}
```

`unregister_netdevice_queue`函数从内核中删除网卡设备，实现如下：

```C
// file: net/core/dev.c
void unregister_netdevice_queue(struct net_device *dev, struct list_head *head)
{
    ASSERT_RTNL();
    if (head) {
        // 列表存在时，添加到列表尾部
        list_move_tail(&dev->unreg_list, head);
    } else {
        // 不存在时，添加到队列中后移除
        LIST_HEAD(single);
        list_add(&dev->unreg_list, &single);
        unregister_netdevice_many(&single);
    }
}
```

### 4.2 注册BPF程序

#### 1 BPF系统调用

`BPF_LINK_CREATE` 是BPF系统调用，如下：

```C
// file: kernel/bpf/syscall.c
SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
{
    return __sys_bpf(cmd, USER_BPFPTR(uattr), size);
}

static int __sys_bpf(int cmd, bpfptr_t uattr, unsigned int size)
{
    ...
    switch (cmd) {
    ...
    case BPF_LINK_CREATE: err = link_create(&attr, uattr); break;
    ...
    }
    return err;
}
```

#### 2 `BPF_LINK_CREATE`

`link_create` 在检查BFP程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 `netkit/primary` 和 `netkit/peer` 前缀设置的程序类型为`BPF_PROG_TYPE_SCHED_CLS`, 附加类型为`BPF_NETKIT_PRIMARY/BPF_NETKIT_PEER`, 对应 `netkit_link_attach` 处理函数。如下：

```C
// file: kernel/bpf/syscall.c
static int link_create(union bpf_attr *attr, bpfptr_t uattr)
{
    ...
    // 获取 bpf_prog
    prog = bpf_prog_get(attr->link_create.prog_fd);
    if (IS_ERR(prog)) return PTR_ERR(prog);

    // 检查 PROG_TYPE 和 expected_attach_type 是否匹配
    ret = bpf_prog_attach_check_attach_type(prog, attr->link_create.attach_type);
    if (ret) goto out;

    switch (prog->type) {
    ...
    case BPF_PROG_TYPE_SCHED_CLS:
        if (attr->link_create.attach_type == BPF_TCX_INGRESS ||
            attr->link_create.attach_type == BPF_TCX_EGRESS)
            ret = tcx_link_attach(attr, prog); 
        else
            // `netkit`
            ret = netkit_link_attach(attr, prog);
        break;
    ...
    }
    ...
}
```

#### 3 `netkit_link_attach`

`netkit_link_attach` 函数检查用户输入的参数信息，获取设置的网卡设备后，初始化`netkit_link` 的信息后，附加`netkit`。如下：

```C
// file: drivers/net/netkit.c
int netkit_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    struct bpf_link_primer link_primer;
    struct netkit_link *nkl;
    struct net_device *dev;
    int ret;

    rtnl_lock();
    // 获取网卡设备
    dev = netkit_dev_fetch(current->nsproxy->net_ns, 
            attr->link_create.target_ifindex, attr->link_create.attach_type);
    if (IS_ERR(dev)) { ... }
    // 分配`netkit_link`
    nkl = kzalloc(sizeof(*nkl), GFP_KERNEL_ACCOUNT);
    if (!nkl) { ... }
    // 初始化`netkit_link`
    ret = netkit_link_init(nkl, &link_primer, attr, dev, prog);
    if (ret) { ... }
    // 以Link方式附加`netkit`BPF程序
    ret = netkit_link_prog_attach(&nkl->link, attr->link_create.flags,
                attr->link_create.netkit.relative_fd, attr->link_create.netkit.expected_revision);
    if (ret) {
        nkl->dev = NULL;
        bpf_link_cleanup(&link_primer);
        goto out;
    }
    // fd 和 file 进行关联
    ret = bpf_link_settle(&link_primer);
out:
    rtnl_unlock();
    return ret;
}
```

`netkit_dev_fetch`函数获取指定的类型的`netkit`网卡设备，实现如下：

```C
// file: drivers/net/netkit.c
static struct net_device *netkit_dev_fetch(struct net *net, u32 ifindex, u32 which)
{
    struct net_device *dev;
    struct netkit *nk;

    ASSERT_RTNL();
    // `netkit`类型检查
    switch (which) {
    case BPF_NETKIT_PRIMARY:
    case BPF_NETKIT_PEER:
        break;
    default:
        return ERR_PTR(-EINVAL);
    }
    // 获取索引对应的网卡设备
    dev = __dev_get_by_index(net, ifindex);
    if (!dev) return ERR_PTR(-ENODEV);
    // 检查是否是`netkit`网卡设备
    if (dev->netdev_ops != &netkit_netdev_ops) return ERR_PTR(-ENXIO);

    // 获取网卡私有数据
    nk = netkit_priv(dev);
    if (!nk->primary) return ERR_PTR(-EACCES);
    if (which == BPF_NETKIT_PEER) {
        // 对端设备时，获取对端网卡
        dev = rcu_dereference_rtnl(nk->peer);
        if (!dev) return ERR_PTR(-ENODEV);
    }
    return dev;
}
```

`netkit_link_init`函数初始化`netkit_link`设置，如下：

```C
// file: drivers/net/netkit.c
static int netkit_link_init(struct netkit_link *nkl, struct bpf_link_primer *link_primer,
            const union bpf_attr *attr, struct net_device *dev, struct bpf_prog *prog)
{
    // 设置link属性
    bpf_link_init(&nkl->link, BPF_LINK_TYPE_NETKIT, &netkit_link_lops, prog);
    nkl->location = attr->link_create.attach_type;
    nkl->dev = dev;
    // 提供用户空间使用的 fd, id，anon_inode 信息
    return bpf_link_prime(&nkl->link, link_primer);
}
```

#### 4 `netkit_link_prog_attach`

`netkit_link_prog_attach` 函数附加`netkit`BPF程序到`PRIMARY/PEER`设备，如下：

```C
// file: drivers/net/netkit.c
static int netkit_link_prog_attach(struct bpf_link *link, u32 flags, u32 id_or_fd, u64 revision)
{
    struct netkit_link *nkl = netkit_link(link);
    struct bpf_mprog_entry *entry, *entry_new;
    struct net_device *dev = nkl->dev;
    int ret;

    ASSERT_RTNL();
    // 获取`mprog`
    entry = netkit_entry_fetch(dev, true);
    // 附加BPF程序到`mprog`中
    ret = bpf_mprog_attach(entry, &entry_new, link->prog, link, NULL, flags, id_or_fd, revision);
    if (!ret) {
        if (entry != entry_new) {
            // 新旧的`mprog`不同时，更新网卡设备(`dev`)
            netkit_entry_update(dev, entry_new);
            netkit_entry_sync();
        }
        // 释放旧的mprog
        bpf_mprog_commit(entry);
    }
    return ret;
}
```

##### (1) 获取`mprog`

`netkit_entry_fetch`函数获取网卡设备(`dev`)上的BPF列表，如下：

```C
// file: drivers/net/netkit.c
static struct bpf_mprog_entry *netkit_entry_fetch(struct net_device *dev, bool bundle_fallback)
{
    struct netkit *nk = netkit_priv(dev);
    struct bpf_mprog_entry *entry;

    ASSERT_RTNL();
    // 获取`active`的BPF列表
    entry = rcu_dereference_rtnl(nk->active);
    if (entry) return entry;
    // 获取失败时，按需使用`bundle.a`
    if (bundle_fallback) return &nk->bundle.a;
    return NULL;
}
```

##### (2) `mprog`附加BPF程序

`bpf_mprog_attach`函数实现`mprog`附加BPF程序，将BPF程序按照`id`或`fd`附加到指定的位置。具体实现过程参见[TC EXPRESS的内核实现](./27-tc_express.md#3-mprog附加bpf程序)中`mprog附加BPF程序`章节。

##### (3) 设置`mprog`

`netkit_entry_update`函数更新网卡设备上的`mprog`，修改`active`，如下：

```C
// file: drivers/net/netkit.c
static void netkit_entry_update(struct net_device *dev, struct bpf_mprog_entry *entry)
{
    struct netkit *nk = netkit_priv(dev);

    ASSERT_RTNL();
    rcu_assign_pointer(nk->active, entry);
}
```

### 4.3 注销BPF程序的过程

#### 1 `netkit_link_lops`接口

在`netkit_link_lops`函数附加link过程中，设置了用户空间操作`bpf_link`的文件接口，如下：

```C
// file: drivers/net/netkit.c
static int netkit_link_init(struct netkit_link *nkl, struct bpf_link_primer *link_primer,
            const union bpf_attr *attr, struct net_device *dev, struct bpf_prog *prog)
{
    // 设置link属性
    bpf_link_init(&nkl->link, BPF_LINK_TYPE_NETKIT, &netkit_link_lops, prog);
    nkl->location = attr->link_create.attach_type;
    nkl->dev = dev;
    // 提供用户空间使用的 fd, id，anon_inode 信息
    return bpf_link_prime(&nkl->link, link_primer);
}
```

`netkit_link_lops` 是设置的文件操作接口，定义如下：

```C
// file: drivers/net/netkit.c
static const struct bpf_link_ops netkit_link_lops = {
    .release    = netkit_link_release,
    .detach     = netkit_link_detach,
    .dealloc    = netkit_link_dealloc,
    .update_prog    = netkit_link_update,
    .show_fdinfo    = netkit_link_fdinfo,
    .fill_link_info = netkit_link_fill_info,
};
```

#### 2 更新bpf程序

`.update_prog`更新接口，更新当前设置的bpf程序，设置为`netkit_link_update`, 更新`netkit`设置的BPF程序。实现如下:

```C
// file: drivers/net/netkit.c
static int netkit_link_update(struct bpf_link *link, struct bpf_prog *nprog, struct bpf_prog *oprog)
{
    struct netkit_link *nkl = netkit_link(link);
    struct bpf_mprog_entry *entry, *entry_new;
    struct net_device *dev;
    int ret = 0;

    rtnl_lock();
    // 获取`dev`
    dev = nkl->dev;
    if (!dev) { ret = -ENOLINK; goto out; }
    // 替换的prog必须是当前设置的prog
    if (oprog && link->prog != oprog) { ret = -EPERM; goto out; }
    oprog = link->prog;
    // 新旧的程序相同时，释放新的程序
    if (oprog == nprog) { bpf_prog_put(nprog); goto out; }
    // 获取`dev`的`mporg`
    entry = netkit_entry_fetch(dev, false);
    if (!entry) { ret = -ENOENT; goto out; }

    // 以替换的方式附加新的程序
    ret = bpf_mprog_attach(entry, &entry_new, nprog, link, oprog,
            BPF_F_REPLACE | BPF_F_ID, link->prog->aux->id, 0);
    if (!ret) {
        // 成功时，修改`link`设置的BPF程序
        WARN_ON_ONCE(entry != entry_new);
        oprog = xchg(&link->prog, nprog);
        bpf_prog_put(oprog);
        bpf_mprog_commit(entry);
    }
out:
    rtnl_unlock();
    return ret;
}
```

#### 3 注销接口

`.release`接口释放`bpf_link`关联的程序。`netkit_link_release`函数从`mprog`中分离BPF程序，如下：

```C
// file: drivers/net/netkit.c
static void netkit_link_release(struct bpf_link *link)
{
    struct netkit_link *nkl = netkit_link(link);
    struct bpf_mprog_entry *entry, *entry_new;
    struct net_device *dev;
    int ret = 0;

    rtnl_lock();
    // 获取`dev`
    dev = nkl->dev;
    if (!dev) goto out;
    // 获取网卡设备的`mprog`
    entry = netkit_entry_fetch(dev, false);
    if (!entry) { ret = -ENOENT; goto out; }
    // 分离`mprog`
    ret = bpf_mprog_detach(entry, &entry_new, link->prog, link, 0, 0, 0);
    if (!ret) {
        // 新的`mprog`不活跃时，设置为null
        if (!bpf_mprog_total(entry_new)) entry_new = NULL;
        // 更新网卡设备的`mprog`
        netkit_entry_update(dev, entry_new);
        netkit_entry_sync();
        //  提交`mprog`
        bpf_mprog_commit(entry);
        nkl->dev = NULL;
    }
out:
    WARN_ON_ONCE(ret);
    rtnl_unlock();
}
```

`bpf_mprog_detach`函数分离`mprog`上的BPF程序，具体实现过程参见[TC EXPRESS的内核实现](./27-tc_express.md#3-注销接口)中`注销接口`章节。

#### 4 分离接口

`.detach`接口分离`bpf_link`关联的程序。`netkit_link_detach`分离`netkit_link`，如下：

```C
// file: drivers/net/netkit.c
static int netkit_link_detach(struct bpf_link *link)
{
    netkit_link_release(link);
    return 0;
}
```

#### 5 释放接口

`.dealloc`接口释放`bpf_link`。`netkit_link_dealloc`释放`netkit_link`，如下：

```C
// file: drivers/net/netkit.c
static void netkit_link_dealloc(struct bpf_link *link)
{
    kfree(netkit_link(link));
}
```

### 4.4 BPF调用过程

在创建`netkit`网卡时设置的网卡设备操作接口为`netkit_netdev_ops`, 定义如下：

```C
// file: drivers/net/netkit.c
static const struct net_device_ops netkit_netdev_ops = {
    .ndo_open       = netkit_open,
    .ndo_stop       = netkit_close,
    .ndo_start_xmit     = netkit_xmit,
    .ndo_set_rx_mode    = netkit_set_multicast,
    .ndo_set_rx_headroom    = netkit_set_headroom,
    .ndo_set_mac_address    = netkit_set_macaddr,
    .ndo_get_iflink     = netkit_get_iflink,
    .ndo_get_peer_dev   = netkit_peer_dev,
    .ndo_get_stats64    = netkit_get_stats,
    .ndo_uninit         = netkit_uninit,
    .ndo_features_check = passthru_features_check,
};
```

`.ndo_start_xmit`接口是网卡设备发送skb的接口，设置为`netkit_xmit`，实现如下：

```C
// file: drivers/net/netkit.c
static netdev_tx_t netkit_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct bpf_net_context __bpf_net_ctx, *bpf_net_ctx;
    struct netkit *nk = netkit_priv(dev);
    // 默认的过滤结果
    enum netkit_action ret = READ_ONCE(nk->policy);
    netdev_tx_t ret_dev = NET_XMIT_SUCCESS;
    const struct bpf_mprog_entry *entry;
    struct net_device *peer;
    int len = skb->len;

    bpf_net_ctx = bpf_net_ctx_set(&__bpf_net_ctx);
    rcu_read_lock();
    // 获取对端网卡
    peer = rcu_dereference(nk->peer);
    // 对端网卡不存在或者未启动时，丢弃skb
    if (unlikely(!peer || !(peer->flags & IFF_UP) ||
            !pskb_may_pull(skb, ETH_HLEN) || skb_orphan_frags(skb, GFP_ATOMIC)))
        goto drop;
    // 设置skb转发
    netkit_prep_forward(skb, !net_eq(dev_net(dev), dev_net(peer)), nk->scrub);
    // skb目的地址不匹配时设置协议
    eth_skb_pkt_type(skb, peer);
    skb->dev = peer;

    // 获取`netkit`设置的`mprog`
    entry = rcu_dereference(nk->active);
    // `mprog`存在时，运行
    if (entry) ret = netkit_run(entry, skb, ret);
    switch (ret) {
    case NETKIT_NEXT:
    case NETKIT_PASS:
        // `NEXT`和`PASS`时，重新设置skb的协议和更新校验和
        eth_skb_pull_mac(skb);
        skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);
        // 成功添加到接收队列时，更新发送和接收计数
        if (likely(__netif_rx(skb) == NET_RX_SUCCESS)) {
            dev_sw_netstats_tx_add(dev, 1, len);
            dev_sw_netstats_rx_add(peer, len);
        } else {
            goto drop_stats;
        }
        break;
    case NETKIT_REDIRECT:
        // `REDIRECT`时，更新发送计数后，进行重定向
        dev_sw_netstats_tx_add(dev, 1, len);
        skb_do_redirect(skb);
        break;
    case NETKIT_DROP:
    default:
drop:
        // 丢弃或默认情况，丢弃skb
        kfree_skb(skb);
drop_stats:
        // 必要时，更新丢弃计数
        dev_core_stats_tx_dropped_inc(dev);
        ret_dev = NET_XMIT_DROP;
        break;
    }
    rcu_read_unlock();
    bpf_net_ctx_clear(bpf_net_ctx);
    return ret_dev;
}
```

`netkit_run`函数执行进行`netkit`BPF程序判决，实现如下：

```C
// file: drivers/net/netkit.c
static __always_inline int
netkit_run(const struct bpf_mprog_entry *entry, struct sk_buff *skb, enum netkit_action ret)
{
    const struct bpf_mprog_fp *fp;
    const struct bpf_prog *prog;
    // 遍历`mprog`，逐项运行BPF程序
    bpf_mprog_foreach_prog(entry, fp, prog) {
        bpf_compute_data_pointers(skb);
        ret = bpf_prog_run(prog, skb);
        if (ret != NETKIT_NEXT) break;
    }
    return ret;
}
```

## 5 总结

本文通过`tc_netkit`示例程序分析了基于BPF可编程网卡的内核实现过程。`netkit`通过在内核中建立虚拟网络的方式在发送到对端网卡前实现过滤，减轻了内核的开销。

## 参考资料

* [The BPF-programmable network device](https://lwn.net/Articles/949960/)
* [Add bpf programmable net device](https://lwn.net/Articles/948301/)
* [BPF Programmable Netdevice](https://lpc.events/event/17/contributions/1581/attachments/1292/2602/lpc_netkit_devs.pdf)
* [netkit - manpage](https://netkit-jh.github.io/docs/man/netkit-manpage-netkit)
* [Emulating Computer Networks with Netkit](https://www.netkit.org/assets/publications/Emulating%20Computer%20Networks%20with%20Netkit.pdf)
