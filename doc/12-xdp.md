# XDP的内核实现

## 0 前言

今天我们借助`xdp`示例程序分析 XDP BPF程序的内核实现过程。

## 1 简介

XDP(eXpress Data Path)提供了BPF框架，可以在Linux内核中实现高性能可编程数据包处理。它在软件中尽早(在网络驱动程序收到数据包时)运行BPF程序，在`skb`进入网络协议栈之前进行处理，在应对DDos攻击、转发和负载均衡、网络协议栈前过滤、流量采集监测等方面广泛引用。

## 2 `xdp`示例程序

### 2.1 BPF程序

BPF程序源码参见[xdp.bpf.c](../src/xdp.bpf.c)，主要内容如下：

```C
SEC("xdp")
int xdp_pass(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    int pkt_sz = data_end - data;

    bpf_printk("packet size is %d", pkt_sz);
    return XDP_PASS;
}
```

该程序包含一个BPF程序`xdp_pass`，使用`xdp`前缀。参数为`xdp_md`类型，定义如下：

```C
// file: vmlinux/vmlinux.h
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};
```

`.data` 和 `.data_end` 表示网络数据包的开始和结束地址；
`.data_meta` 初始阶段时一个空闲的内存地址，XDP程序和其他层交换数据包元数据时使用；
`.ingress_ifindex` 和 `.rx_queue_index` 表示接收数据包的网络接口和RX队列索引；
`.egress_ifindex` 表示发送数据包的网络接口。

### 2.2 用户程序

用户程序源码参见[xdp.c](../src/xdp.c)，主要内容如下：

#### 1 附加BPF程序

```C
// 网络接口索引
#define LO_IFINDEX 3
int main(int argc, char **argv)
{
    DECLARE_LIBBPF_OPTS(bpf_xdp_attach_opts, xdp_opts);
    struct xdp_bpf *skel;
    ...
    // 设置 libbpf 调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);
    // 打开并加载BPF程序
    skel = xdp_bpf__open_and_load();
    if (!skel) { ... }
    // 附加BPF程序
    prog_fd = bpf_program__fd(skel->progs.xdp_pass);
    err = bpf_xdp_attach(LO_IFINDEX, prog_fd, 0, &xdp_opts);
    if (err) { ... }
    // 设置`INT`处理函数
    if (signal(SIGINT, sig_int) == SIG_ERR) { ... }
    
    while (!stop) {
        fprintf(stderr, ".");
        sleep(1);
    }
    // 分离BPF程序
    err = bpf_xdp_detach(LO_IFINDEX, 0, &xdp_opts);
    if (err) { ... }
cleanup:
    // 销毁BPF程序
    xdp_bpf__destroy(skel);
    return -err;
}
```

#### 2 读取数据过程

`xdp_pass` BPF程序获取网络包的长度，通过 `bpf_printk` 输出到 `/sys/kernel/debug/tracing/trace_pipe` 文件中。

### 2.3 编译运行

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make xdp 
$ sudo ./xdp 
libbpf: loading object 'xdp_bpf' from buffer
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

在`xdp`程序运行的过程中打开另一个bash窗口查看输出结果，如下：

```bash
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
  irq/29-iwlwifi-479     [005] d.s41 320423.612242: bpf_trace_printk: packet size is 66
  irq/29-iwlwifi-479     [005] d.s41 320423.612698: bpf_trace_printk: packet size is 66
  irq/29-iwlwifi-479     [005] d.s41 320424.017885: bpf_trace_printk: packet size is 126
...
```

## 3 xdp附加BPF的过程

`xdp.bpf.c`文件中BPF程序的SEC名称为 `SEC("xdp")` ，在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("xdp.frags/devmap", XDP, BPF_XDP_DEVMAP, SEC_XDP_FRAGS),
    SEC_DEF("xdp/devmap",       XDP, BPF_XDP_DEVMAP, SEC_ATTACHABLE),
    SEC_DEF("xdp.frags/cpumap", XDP, BPF_XDP_CPUMAP, SEC_XDP_FRAGS),
    SEC_DEF("xdp/cpumap",       XDP, BPF_XDP_CPUMAP, SEC_ATTACHABLE),
    SEC_DEF("xdp.frags",        XDP, BPF_XDP, SEC_XDP_FRAGS),
    SEC_DEF("xdp",              XDP, BPF_XDP, SEC_ATTACHABLE_OPT),
    ...
};
```

`xdp` 所有的前缀都不支持自动附加，需要通过手动方式附加。

### 3.1 `netlink`方式附加

libbpf提供了`netlink`方式加载XDP类型的程序，如示例程序展示的那样，使用 `bpf_xdp_attach` 函数附加XDP程序，`bpf_xdp_detach` 函数分离XDP程序。

`bpf_xdp_detach` 函数检查设置的选项后，检查`old_prog_fd`参数设置，最后调用 `__bpf_set_link_xdp_fd_replace` 函数，实现如下：

```C
// file: libbpf/src/netlink.c
int bpf_xdp_attach(int ifindex, int prog_fd, __u32 flags, const struct bpf_xdp_attach_opts *opts)
{
    // 检查opts属性设置
    if (!OPTS_VALID(opts, bpf_xdp_attach_opts)) return libbpf_err(-EINVAL);

    // 获取设置的`old_prog_fd`值，存在时修改flags标记，不存在时设置为-1，
    old_prog_fd = OPTS_GET(opts, old_prog_fd, 0);
    if (old_prog_fd)
        flags |= XDP_FLAGS_REPLACE;
    else
        old_prog_fd = -1;

    err = __bpf_set_link_xdp_fd_replace(ifindex, prog_fd, old_prog_fd, flags);
    return libbpf_err(err);
}
```

`__bpf_set_link_xdp_fd_replace` 函数设置`nlattr`属性后，发送netlink请求，实现XDP类型程序的附加。如下：

```C
// file: libbpf/src/netlink.c
static int __bpf_set_link_xdp_fd_replace(int ifindex, int fd, int old_fd, __u32 flags)
{
    struct nlattr *nla;
    int ret;
    struct libbpf_nla_req req;

    // req属性设置
    memset(&req, 0, sizeof(req));
    // netlink消息头信息设置
    req.nh.nlmsg_len      = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_flags    = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_type     = RTM_SETLINK;
    // `ifinfomsg`消息类型设置 
    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index  = ifindex;

    // XDP消息内容设置，每个消息对应`nlattr`结构
    nla = nlattr_begin_nested(&req, IFLA_XDP);
    if (!nla) return -EMSGSIZE;
    ret = nlattr_add(&req, IFLA_XDP_FD, &fd, sizeof(fd));
    if (ret < 0) return ret;
    if (flags) {
        ret = nlattr_add(&req, IFLA_XDP_FLAGS, &flags, sizeof(flags));
        if (ret < 0) return ret;
    }
    if (flags & XDP_FLAGS_REPLACE) {
        ret = nlattr_add(&req, IFLA_XDP_EXPECTED_FD, &old_fd, sizeof(old_fd));
        if (ret < 0) return ret;
    }
    nlattr_end_nested(&req, nla);

    // 发送`NETLINK_ROUTE`类型
    return libbpf_netlink_send_recv(&req, NETLINK_ROUTE, NULL, NULL, NULL);
}
```

`libbpf_nla_req` 结构是libbpf使用的netlink请求内容，包含：消息头结构(`struct nlmsghdr`)、消息类型 (`ifinfomsg`, `tcmsg`, `genlmsghdr`中的一种)、消息内容(`char buf[128]`)，定义如下：

```C
// file: libbpf/src/nlattr.h
struct libbpf_nla_req {
    struct nlmsghdr nh;
    union {
        struct ifinfomsg ifinfo;
        struct tcmsg tc;
        struct genlmsghdr gnl;
    };
    char buf[128];
};
```

`libbpf_netlink_send_recv` 函数实现netlink的数据发送和结束过程，如下：

```C
// file: libbpf/src/netlink.c
static int libbpf_netlink_send_recv(struct libbpf_nla_req *req, int proto, 
            __dump_nlmsg_t parse_msg, libbpf_dump_nlmsg_t parse_attr, void *cookie)
{
    __u32 nl_pid = 0;
    int sock, ret;
    // 打开netlink socket
    sock = libbpf_netlink_open(&nl_pid, proto);
    if (sock < 0) return sock;

    req->nh.nlmsg_pid = 0;
    req->nh.nlmsg_seq = time(NULL);
    // 发送 netlink 请求
    if (send(sock, req, req->nh.nlmsg_len, 0) < 0) { ...  }
    // 接收 netlink 消息
    ret = libbpf_netlink_recv(sock, nl_pid, req->nh.nlmsg_seq, parse_msg, parse_attr, cookie);
out:
    // 关闭 netlink socket
    libbpf_netlink_close(sock);
    return ret;
}
```

`libbpf_netlink_open` 函数打开netlink socket，使用方式和TCP/UDP socket 类似，如下：

```C
// file: libbpf/src/netlink.c
static int libbpf_netlink_open(__u32 *nl_pid, int proto)
{
    struct sockaddr_nl sa;
    socklen_t addrlen;
    int one = 1, ret;
    int sock;

    // 设置 sockaddr
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    // 打开 socket
    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, proto);
    if (sock < 0) return -errno;
    // 设置socket属性
    if (setsockopt(sock, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one)) < 0) { ... }
    // 绑定sock地址
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) { ...}
    // 获取sock名称
    addrlen = sizeof(sa);
    if (getsockname(sock, (struct sockaddr *)&sa, &addrlen) < 0) { ... }
    if (addrlen != sizeof(sa)) { ... }

    // 获取netlink的pid，通过这个pid，判读是否是发送的消息
    *nl_pid = sa.nl_pid;
    return sock;
    
    // 错误时关闭sock 
cleanup:
    close(sock);
    return ret;
}
```

`bpf_xdp_detach` 函数实现XDP类型程序的分离，也是调用 `bpf_xdp_detach` 函数(传递的参数不同)，如下：

```C
// file: libbpf/src/netlink.c
int bpf_xdp_detach(int ifindex, __u32 flags, const struct bpf_xdp_attach_opts *opts)
{
    return bpf_xdp_attach(ifindex, -1, flags, opts);
}
```

### 3.2 `bpf_link`方式附加

`bpf_program__attach_xdp` 函数使用`bpf_link`方式加载XDP类型的BPF程序，如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link *bpf_program__attach_xdp(const struct bpf_program *prog, int ifindex)
{
    // target_fd/target_ifindex 在 LINK_CREATE 中是同一个字段
    return bpf_program__attach_fd(prog, ifindex, 0, "xdp");
}
```

`bpf_program__attach_fd` 函数设置link属性后，调用`bpf_link_create`进行实际的创建，如下：

```C
// file: libbpf/src/libbpf.c
static struct bpf_link * bpf_program__attach_fd(const struct bpf_program *prog, 
                            int target_fd, int btf_id, const char *target_name)
{
    
    DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts, .target_btf_id = btf_id);
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
    if (pfd < 0) { ... }
    // 设置link->fd
    link->fd = pfd;
    return link;
}
```

`bpf_link_create` 在设置和检查`bpf_attr`属性后，使用 `BPF_LINK_CREATE` 指令进行BPF系统调用。如下：

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
    switch (attach_type) {
    ...
    default:
        if (!OPTS_ZEROED(opts, flags)) return libbpf_err(-EINVAL);
        break;
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

## 4 内核实现

### 4.1 `netlink`方式附加

#### 1 初始化

`initcall`阶段初始初始化`netlink`协议，如下：

```C
// file: net/netlink/af_netlink.c
core_initcall(netlink_proto_init);
```

`netlink_proto_init` 函数实现netlink相关的初始化，包括：注册`netlink`协议、创建`nl_table`、注册`netlink`协议处理、注册网络子系统处理接口、初始化netlink等。详细的初始化过程参见[linux netlink详解1-netlink初始化](https://www.cnblogs.com/xinghuo123/p/13782009.html)，实现如下：

```C
// file: net/netlink/af_netlink.c
static int __init netlink_proto_init(void)
{
    // 注册 netlink_proto
    int err = proto_register(&netlink_proto, 0);
    if (err != 0) goto out;
    ...
    
    // 创建 nl_table，每种协议类型占用一项，后续内核中创的不同协议类型的netlink都保存在该表中
    nl_table = kcalloc(MAX_LINKS, sizeof(*nl_table), GFP_KERNEL);
    if (!nl_table) goto panic;

    // nl_table的hash函数初始化
    for (i = 0; i < MAX_LINKS; i++) {
        if (rhashtable_init(&nl_table[i].hash, &netlink_rhashtable_params) < 0) {...}
    }

    // nl_table[NETLINK_USERSOCK] 属性设置
    netlink_add_usersock_entry();

    // 注册netlink协议处理，将netlink的socket创建函数注册到系统中
    sock_register(&netlink_family_ops);
    // 注册网络命名空间子系统的初始化和退出函数，网络命名空间创建/注销时调用初始化/退出函数
    register_pernet_subsys(&netlink_net_ops);
    register_pernet_subsys(&netlink_tap_net_ops);
    // rtnetlink初始化
    rtnetlink_init();
out:
    return err;
panic:
    panic("netlink_init: Cannot allocate nl_table\n");
}
```

`rtnetlink_init` 函数注册`rtnetlink`网络子系统接口，注册`PF_UNSPEC` 和 `PF_BRIDGE` 协议操作，如下：

```C
// file: net/core/rtnetlink.c
void __init rtnetlink_init(void)
{
    // 注册 rtnetlink 网络操作接口
    if (register_pernet_subsys(&rtnetlink_net_ops))
        panic("rtnetlink_init: cannot initialize rtnetlink\n");

    register_netdevice_notifier(&rtnetlink_dev_notifier);

    // 注册 rtnetlink 消息类型处理
    rtnl_register(PF_UNSPEC, RTM_GETLINK, rtnl_getlink, rtnl_dump_ifinfo, 0);
    rtnl_register(PF_UNSPEC, RTM_SETLINK, rtnl_setlink, NULL, 0);
    rtnl_register(PF_UNSPEC, RTM_NEWLINK, rtnl_newlink, NULL, 0);
    rtnl_register(PF_UNSPEC, RTM_DELLINK, rtnl_dellink, NULL, 0);
    ...

    rtnl_register(PF_BRIDGE, RTM_GETLINK, NULL, rtnl_bridge_getlink, 0);
    rtnl_register(PF_BRIDGE, RTM_DELLINK, rtnl_bridge_dellink, NULL, 0);
    rtnl_register(PF_BRIDGE, RTM_SETLINK, rtnl_bridge_setlink, NULL, 0);
    ...
}
```

`rtnetlink_net_ops` 定义如下：

```C
// file: net/core/rtnetlink.c
static struct pernet_operations rtnetlink_net_ops = {
    .init = rtnetlink_net_init,
    .exit = rtnetlink_net_exit,
};
```

`.init` 设置为 `rtnetlink_net_init` , 在网络命名空间创建时，创建内核使用的`rtnetlink` socket，通过这个socket可以接收用户空间发送的rtnetlink消息。如下：

```C
// file: net/core/rtnetlink.c
static int __net_init rtnetlink_net_init(struct net *net)
{
    struct sock *sk;
    struct netlink_kernel_cfg cfg = {
        .groups		= RTNLGRP_MAX,
        // rtnetlink_rcv 函数可以接收用户空间发送的消息
        .input		= rtnetlink_rcv,
        .cb_mutex	= &rtnl_mutex,
        .flags		= NL_CFG_F_NONROOT_RECV,
        .bind		= rtnetlink_bind,
    };
    // 创建内核netlink
    sk = netlink_kernel_create(net, NETLINK_ROUTE, &cfg);
    if (!sk) return -ENOMEM;
    // rtnl 字段表示 rtnetlink socket 
    net->rtnl = sk;
    return 0;
}
```

`rtnl_register` 函数注册 rtnetlink 消息类型，如下：

```C
// file: net/core/rtnetlink.c
void rtnl_register(int protocol, int msgtype, rtnl_doit_func doit, rtnl_dumpit_func dumpit, unsigned int flags)
{
    ...
    err = rtnl_register_internal(NULL, protocol, msgtype, doit, dumpit, flags);
    if (err) ...
}

static int rtnl_register_internal(struct module *owner, int protocol, int msgtype, 
                rtnl_doit_func doit, rtnl_dumpit_func dumpit, unsigned int flags)
{
    ...
    rtnl_lock();
    // 获取网络协议类型的处理接口，不存在时创建
    tab = rtnl_dereference(rtnl_msg_handlers[protocol]);
    if (tab == NULL) {
        tab = kcalloc(RTM_NR_MSGTYPES, sizeof(void *), GFP_KERNEL);
        if (!tab) goto unlock;
        rcu_assign_pointer(rtnl_msg_handlers[protocol], tab);
    }
    // 获取消息类型的处理接口，不存在时创建
    old = rtnl_dereference(tab[msgindex]);
    if (old) {
        link = kmemdup(old, sizeof(*old), GFP_KERNEL);
        if (!link) goto unlock;
    } else {
        link = kzalloc(sizeof(*link), GFP_KERNEL);
        if (!link) goto unlock;
    }

    // 处理接口属性设置
    link->owner = owner;
    if (doit) link->doit = doit;
    if (dumpit) link->dumpit = dumpit;

    WARN_ON(rtnl_msgtype_kind(msgtype) != RTNL_KIND_DEL && (flags & RTNL_FLAG_BULK_DEL_SUPPORTED));
    link->flags |= flags;

    // 设置 protocol:msgtype 对应的处理接口
    rcu_assign_pointer(tab[msgindex], link);
    ret = 0;
    if (old) kfree_rcu(old, rcu);
unlock:
    rtnl_unlock();
    return ret;
}
```

`rtnl_msg_handlers` 变量表示所有网络协议的`rtnetlink`处理接口，包括127种真实的网络协议和自定义的协议（编号128以上），如下  

```C
// file: net/core/rtnetlink.c
static struct rtnl_link __rcu *__rcu *rtnl_msg_handlers[RTNL_FAMILY_MAX + 1];

// file： include/uapi/linux/rtnetlink.h
#define RTNL_FAMILY_IPMR		128
#define RTNL_FAMILY_IP6MR		129
#define RTNL_FAMILY_MAX			129
```

#### 2 `netlink`接口

libbpf在创建netlink请求时，设置的 `网络协议:消息类型` 为 `AF_UNSPEC:RTM_SETLINK`, 如下：

```C
// file: libbpf/src/netlink.c
static int __bpf_set_link_xdp_fd_replace(int ifindex, int fd, int old_fd, __u32 flags)
{
    ...
    // req属性设置
    memset(&req, 0, sizeof(req));
    // netlink消息头信息设置
    req.nh.nlmsg_len      = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_flags    = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_type     = RTM_SETLINK;
    // `ifinfomsg`消息类型设置 
    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index  = ifindex;
    ...
}
```

在内核中相应的处理设置为：

```C
// file: net/core/rtnetlink.c
void __init rtnetlink_init(void)
{
    ...
    rtnl_register(PF_UNSPEC, RTM_SETLINK, rtnl_setlink, NULL, 0);
    ...
}
```

`rtnl_getlink` 函数为 `PF_UNSPEC:RTM_SETLINK` 设置的处理方式，验证netlink消息格式正确后，获取设置的网络设备后，调用 `do_setlink` 进行设置。实现如下：

```C
// file: net/core/rtnetlink.c
static int rtnl_setlink(struct sk_buff *skb, struct nlmsghdr *nlh, struct netlink_ext_ack *extack)
{
    struct net *net = sock_net(skb->sk);
    struct nlattr *tb[IFLA_MAX+1];
    ...

    // 解析netlink消息属性
    err = nlmsg_parse_deprecated(nlh, sizeof(*ifm), tb, IFLA_MAX, ifla_policy, extack);
    if (err < 0) goto errout;

    // 验证rtnetlink请求不存在多个网络命名空间的情况
    err = rtnl_ensure_unique_netns(tb, extack, false);
    if (err < 0) goto errout;

    // 获取设置的网卡设置，通过网络设备索引(ifm->ifi_index)或名称获取
    ifm = nlmsg_data(nlh);
    if (ifm->ifi_index > 0)
        dev = __dev_get_by_index(net, ifm->ifi_index);
    else if (tb[IFLA_IFNAME] || tb[IFLA_ALT_IFNAME])
        dev = rtnl_dev_get(net, tb);
    else
        goto errout;

    // 设备不存在时退出
    if (dev == NULL) { ...}

    // 设置link
    err = do_setlink(skb, dev, ifm, extack, tb, 0);
errout:
    return err;
}
```

`do_setlink` 函数进行消息处理，在验证请求的属性参数(`nlattr`)后进行对应的处理。XDP属性处理如下：

```C
// file：net/core/rtnetlink.c
static int do_setlink(const struct sk_buff *skb, struct net_device *dev, 
    struct ifinfomsg *ifm, struct netlink_ext_ack *extack, struct nlattr **tb, int status)
{
    const struct net_device_ops *ops = dev->netdev_ops;
    ...
    // 验证link类型消息
    err = validate_linkmsg(dev, tb, extack);
    if (err < 0) return err;
    // 获取设备名称
    if (tb[IFLA_IFNAME])
        nla_strscpy(ifname, tb[IFLA_IFNAME], IFNAMSIZ);
    else
        ifname[0] = '\0';
    ...
    // XDP属性
    if (tb[IFLA_XDP]) {
        struct nlattr *xdp[IFLA_XDP_MAX + 1];
        u32 xdp_flags = 0;
        // 解析XDP消息属性信息
        err = nla_parse_nested_deprecated(xdp, IFLA_XDP_MAX, tb[IFLA_XDP], ifla_xdp_policy, NULL);
        if (err < 0) goto errout;
        // 获取设置的flags
        if (xdp[IFLA_XDP_FLAGS]) {
            xdp_flags = nla_get_u32(xdp[IFLA_XDP_FLAGS]);
            ...
        }
        if (xdp[IFLA_XDP_FD]) {
            int expected_fd = -1;
            // 获取附加的prog
            if (xdp_flags & XDP_FLAGS_REPLACE) {
                ...
                expected_fd = nla_get_s32(xdp[IFLA_XDP_EXPECTED_FD]);
            }
            // 修改网络设备接收端的bpf程序
            err = dev_change_xdp_fd(dev, extack, nla_get_s32(xdp[IFLA_XDP_FD]), expected_fd, xdp_flags);
            if (err) goto errout;
            status |= DO_SETLINK_NOTIFY;
        }
    }
    ...
}
```

`dev_change_xdp_fd` 函数获取设置的bpf程序后，调用`dev_xdp_attach`函数修改网络设备接收端的bpf程序，如下：

```C
// file：net/core/rtnetlink.c
int dev_change_xdp_fd(struct net_device *dev, struct netlink_ext_ack *extack,
            int fd, int expected_fd, u32 flags)
{
    // 获取xdp模式
    enum bpf_xdp_mode mode = dev_xdp_mode(dev, flags);
    ...
    // 获取设置的prog
    if (fd >= 0) { 
        new_prog = bpf_prog_get_type_dev(fd, BPF_PROG_TYPE_XDP, mode != XDP_MODE_SKB);
        if (IS_ERR(new_prog)) return PTR_ERR(new_prog);
    }
    // 获取之前的prog
    if (expected_fd >= 0) {
        old_prog = bpf_prog_get_type_dev(expected_fd, BPF_PROG_TYPE_XDP, mode != XDP_MODE_SKB);
        if (IS_ERR(old_prog)) { ... }
    }
    // 附加BPF程序
    err = dev_xdp_attach(dev, extack, NULL, new_prog, old_prog, flags);

err_out:
    // 清理操作
    if (err && new_prog) bpf_prog_put(new_prog);
    if (old_prog) bpf_prog_put(old_prog);
    return err;
}
```

### 4.2 `bpf_link`方式附加

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

`link_create` 在检查BFP程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 `xdp` 前缀设置的程序类型为`BPF_PROG_TYPE_XDP`, 对应 `bpf_xdp_link_attach` 处理函数。如下：

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
#ifdef CONFIG_NET
    case BPF_PROG_TYPE_XDP:
        ret = bpf_xdp_link_attach(attr, prog);
        break;
#endif
    ...
    }
    ...
}
```

#### 3 `bpf_xdp_link_attach`

`bpf_xdp_link_attach` 函数获取索引对应的网卡设备后，设置`xdp_link`的信息后，附加BPF程序到网卡设备上。如下：

```C
// file: net/core/dev.c
int bpf_xdp_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    struct net *net = current->nsproxy->net_ns;
    struct bpf_xdp_link *link;
    struct net_device *dev;
    ...

    rtnl_lock();
    // 获取网络接口索引对应的网卡设备    
    dev = dev_get_by_index(net, attr->link_create.target_ifindex);

    // 创建 link
    link = kzalloc(sizeof(*link), GFP_USER);
    if (!link) { ... }
    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_XDP, &bpf_xdp_link_lops, prog);
    link->dev = dev;
    link->flags = attr->link_create.flags;
    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    if (err) { ... }

    // 附加xdp
    err = dev_xdp_attach_link(dev, NULL, link);
    rtnl_unlock();

    // fd 和 file 进行关联
    fd = bpf_link_settle(&link_primer);
    dev_put(dev);
    return fd;

unlock:
    rtnl_unlock();
out_put_dev:
    dev_put(dev);
    return err;
}
```

`dev_xdp_attach_link` 函数是对 `dev_xdp_attach` 函数的调用封装。如下：

```C
// file: net/core/dev.c
static int dev_xdp_attach_link(struct net_device *dev, struct netlink_ext_ack *extack, struct bpf_xdp_link *link)
{
    return dev_xdp_attach(dev, extack, link, NULL, NULL, link->flags);
}
```

### 4.3 注册XDP程序

#### 1 附加接口

`dev_xdp_attach` 函数设置或清除网络设备接收端的BPF程序，经过一系列检查后调用 `dev_xdp_install` 函数安装xdp程序，如下：

```C
// file：net/core/dev.c
static int dev_xdp_attach(struct net_device *dev, struct netlink_ext_ack *extack, struct bpf_xdp_link *link, 
                struct bpf_prog *new_prog, struct bpf_prog *old_prog, u32 flags)
{
    unsigned int num_modes = hweight32(flags & XDP_FLAGS_MODES);
    ...

    // xdp_link和netlink方式不能同时设置
    if (link && (new_prog || old_prog)) return -EINVAL;
    // xdp_link只支持XDP模式设置
    if (link && (flags & ~XDP_FLAGS_MODES)) { ... }
    // 一次只能设置一种模式
    if (num_modes > 1) { ... }
    // 多义性检查，已经加载BPF程序时，需要明确模式
    if (!num_modes && dev_xdp_prog_count(dev) > 1) { ... }
    // old_prog存在时，隐含`REPLACE`标记
    if (old_prog && !(flags & XDP_FLAGS_REPLACE)) { ... }

    mode = dev_xdp_mode(dev, flags);

    // 不能替换xdp_link设置的bpf程序
    if (dev_xdp_link(dev, mode)) { ... }
    // 在上层设备设置BPF程序时，不能设置
    netdev_for_each_upper_dev_rcu(dev, upper, iter) {
        if (dev_xdp_prog_count(upper) > 0) { ... }
    }
    // 获取当前设置的bpf程序
    cur_prog = dev_xdp_prog(dev, mode);
    // xdp_link模式下不能替换附加的bpf程序
    if (link && cur_prog) { ...  }
    // 替换bpf程序时检查，必须是当前附加的bpf程序
    if ((flags & XDP_FLAGS_REPLACE) && cur_prog != old_prog) { ...  }

    // 获取xdp_link设置的bpf程序
    if (link) new_prog = link->link.prog;

    if (new_prog) {
        // offload模式，在硬件上运行XDP程序
        bool offload = mode == XDP_MODE_HW;
        enum bpf_xdp_mode other_mode = mode == XDP_MODE_SKB 
                    ? XDP_MODE_DRV : XDP_MODE_SKB;
        // 设置`UPDATE_IF_NOEXIST`标记时，不能替换当前程序
        if ((flags & XDP_FLAGS_UPDATE_IF_NOEXIST) && cur_prog) { ... }
        // 非硬件模式下只能设置一个
        if (!offload && dev_xdp_prog(dev, other_mode)) { ... }
        // 非硬件模式下，类型检查
        if (!offload && bpf_prog_is_offloaded(new_prog->aux)) { ... }
        // 硬件模式下检查
        if (bpf_prog_is_dev_bound(new_prog->aux) && !bpf_offload_dev_match(new_prog, dev)) { ... }
        if (new_prog->expected_attach_type == BPF_XDP_DEVMAP) { ... }
        if (new_prog->expected_attach_type == BPF_XDP_CPUMAP) { ... }
    }

    if (new_prog != cur_prog) {
        // 获取附加操作接口
        bpf_op = dev_xdp_bpf_op(dev, mode);
        if (!bpf_op) { ... }
        // 设置xdp程序
        err = dev_xdp_install(dev, mode, bpf_op, extack, flags, new_prog);
        if (err) return err;
    }

    // 保存bpf程序
    if (link) dev_xdp_set_link(dev, mode, link);
    else dev_xdp_set_prog(dev, mode, new_prog);
    // 释放当前设置的bpf程序
    if (cur_prog) bpf_prog_put(cur_prog);
    return 0;
}
```

`dev_xdp_install` 函数安装XDP程序，如下：

```C
// file：net/core/dev.c
static int dev_xdp_install(struct net_device *dev, enum bpf_xdp_mode mode, bpf_op_t bpf_op, 
                struct netlink_ext_ack *extack, u32 flags, struct bpf_prog *prog)
{
    struct netdev_bpf xdp;
    // 设置xdp属性
    memset(&xdp, 0, sizeof(xdp));
    xdp.command = mode == XDP_MODE_HW ? XDP_SETUP_PROG_HW : XDP_SETUP_PROG;
    xdp.extack = extack;
    xdp.flags = flags;
    xdp.prog = prog;

    if (prog) bpf_prog_inc(prog);
    // xdp程序操作
    err = bpf_op(dev, &xdp);
    if (err) { ... }

    // 非硬件模式下，BPF调度程序设置
    if (mode != XDP_MODE_HW)
        bpf_prog_change_xdp(dev_xdp_prog(dev, mode), prog);
    return 0;
}
```

#### 2 XDP附加方式

XDP程序支持三种附加方式，定义如下：

```C
// file: include/linux/netdevice.h
enum bpf_xdp_mode {
    XDP_MODE_SKB = 0,
    XDP_MODE_DRV = 1,
    XDP_MODE_HW = 2,
    __MAX_XDP_MODE
};
```

对应含义为：

`XDP_MODE_SKB`：通用XDP(Generic XDP)，在网卡驱动不支持XDP时，运行在由Linux内核的`receive_skb()`函数中；
`XDP_MODE_DRV`：原生XDP(Native XDP)，运行在硬件驱动实现的的`poll()`函数中;
`XDP_MODE_HW`：卸载XDP(Offloaded XDP)，将XDP程序offload到网卡中，这需要网卡硬件的支持，JIT编译器将BPF代码翻译成网卡原生指令并在网卡上运行。

网卡设备结构中可以设置这三种类型的BPF程序，同时只能设置一种。如下：

```C
// file: include/linux/netdevice.h
struct net_device {
    ...
    struct bpf_xdp_entity   xdp_state[__MAX_XDP_MODE];
    ...
};

// file: include/linux/netdevice.h
struct bpf_xdp_entity {
    struct bpf_prog *prog;
    struct bpf_xdp_link *link;
};
```

`dev_xdp_mode` 函数获取用户设置的xdp模式，如下：

```C
// file：net/core/dev.c
static enum bpf_xdp_mode dev_xdp_mode(struct net_device *dev, u32 flags)
{
    if (flags & XDP_FLAGS_HW_MODE) return XDP_MODE_HW;
    if (flags & XDP_FLAGS_DRV_MODE) return XDP_MODE_DRV;
    if (flags & XDP_FLAGS_SKB_MODE) return XDP_MODE_SKB;
    return dev->netdev_ops->ndo_bpf ? XDP_MODE_DRV : XDP_MODE_SKB;
}
```

设置标记位时转换为对应的模式；没有设置时，在网卡驱动支持时使用原生模式，否则使用通用模式。

#### 3 注册通用XDP

在安装XDP程序前，`dev_xdp_bpf_op` 函数获取XDP的操作接口，如下：

```C
// file：net/core/dev.c
static bpf_op_t dev_xdp_bpf_op(struct net_device *dev, enum bpf_xdp_mode mode)
{
    switch (mode) {
    case XDP_MODE_SKB: 
        return generic_xdp_install;
    case XDP_MODE_DRV:
    case XDP_MODE_HW:
        return dev->netdev_ops->ndo_bpf;
    default:
        return NULL;
    }
}
```

通用XDP模式下对应 `generic_xdp_install` 操作接口，设置网卡设备的`xdp_prog`，初次设置时禁用网卡的LRO和GRO_HW功能。实现如下：

```C
// file：net/core/dev.c
static int generic_xdp_install(struct net_device *dev, struct netdev_bpf *xdp)
{
    struct bpf_prog *old = rtnl_dereference(dev->xdp_prog);
    struct bpf_prog *new = xdp->prog;
    int ret = 0;

    switch (xdp->command) {
    case XDP_SETUP_PROG:
        // 修改xdp程序
        rcu_assign_pointer(dev->xdp_prog, new);
        if (old) bpf_prog_put(old);

        if (old && !new) {
            // 卸载程序时，减少计数
            static_branch_dec(&generic_xdp_needed_key);
        } else if (new && !old) {
            // 设置程序时，增加计数
            static_branch_inc(&generic_xdp_needed_key);
            // 禁用网卡设备的 LRO(Large Receive Offload) 和 GRO_HW(HW Generic Receive Offload)功能
            dev_disable_lro(dev);
            dev_disable_gro_hw(dev);
        }
        break;
    default:
        ret = -EINVAL;
        break;
    }
    return ret;
}
```

#### 4 注册原生/卸载XDP

原生/卸载模式下，设置XDP需要网卡驱动的支持。以Linux ixgbe系列网卡为例，`netdev_ops` 设置为 `ixgbe_netdev_ops`, 定义如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
static const struct net_device_ops ixgbe_netdev_ops = {
    ...
    .ndo_bpf        = ixgbe_xdp,
    ...
};
```

`ixgbe_xdp` 设置网卡驱动的bpf程序，实现如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
static int ixgbe_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
    struct ixgbe_adapter *adapter = netdev_priv(dev);

    switch (xdp->command) {
    case XDP_SETUP_PROG:
        return ixgbe_xdp_setup(dev, xdp->prog);
    case XDP_SETUP_XSK_POOL:
        return ixgbe_xsk_pool_setup(adapter, xdp->xsk.pool, xdp->xsk.queue_id);
    default:
        return -EINVAL;
    }
}
```

可以看到，该系列网卡只支持驱动层设置XDP程序，不支持硬件设置。

`ixgbe_xdp_setup` 函数设置网卡驱动的XDP程序，实现如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
static int ixgbe_xdp_setup(struct net_device *dev, struct bpf_prog *prog)
{
    int i, frame_size = dev->mtu + ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN;
    struct ixgbe_adapter *adapter = netdev_priv(dev);

    // 设置前检查
    if (adapter->flags & IXGBE_FLAG_SRIOV_ENABLED) return -EINVAL;
    if (adapter->flags & IXGBE_FLAG_DCB_ENABLED) return -EINVAL;

    // 检查RX接收队列
    for (i = 0; i < adapter->num_rx_queues; i++) {
        struct ixgbe_ring *ring = adapter->rx_ring[i];
        if (ring_is_rsc_enabled(ring)) return -EINVAL;
        if (frame_size > ixgbe_rx_bufsz(ring)) return -EINVAL;
    }
    if (nr_cpu_ids > IXGBE_MAX_XDP_QS * 2) return -ENOMEM;
    
    // 替换XDP程序
    old_prog = xchg(&adapter->xdp_prog, prog);
    need_reset = (!!prog != !!old_prog);

    if (need_reset) {
        // 清除prog时，需要等待`ndo_xsk_wakeup`完成
        if (!prog) synchronize_rcu();
        // tc设置
        err = ixgbe_setup_tc(dev, adapter->hw_tcs);
        if (err) return -EINVAL;
        // 清除prog时，清除相关标记
        if (!prog) xdp_features_clear_redirect_target(dev);
    } else {
        // 设置每个接收队列的bpf程序
        for (i = 0; i < adapter->num_rx_queues; i++) {
            WRITE_ONCE(adapter->rx_ring[i]->xdp_prog, adapter->xdp_prog);
        }
    }
    // 释放旧的程序
    if (old_prog) bpf_prog_put(old_prog);

    // 初次设置时的初始化
    if (need_reset && prog) {
        num_queues = min_t(int, adapter->num_rx_queues, adapter->num_xdp_queues);
        for (i = 0; i < num_queues; i++)
            if (adapter->xdp_ring[i]->xsk_pool)
                (void)ixgbe_xsk_wakeup(adapter->netdev, i, XDP_WAKEUP_RX);
        // 设置网卡设备支持XDP重定向
        xdp_features_set_redirect_target(dev, true);
    }
}
```

### 4.4 注销XDP程序

#### 1 `netlink`方式

修改netlink请求，设置旧的程序fd，新的程序fd设置为`-1`。重新发送netlink请求，实现XDP程序的注销。

#### 2 `bpf_link`方式

##### (1) `bpf_xdp_link_lops`接口

在创建xdp_link时，设置了link的操作接口，`bpf_xdp_link_lops` 是我们设置的`link->ops`，如下：

```C
// file: net/core/dev.c
int bpf_xdp_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_XDP, &bpf_xdp_link_lops, prog);
    link->dev = dev;
    link->flags = attr->link_create.flags;
    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    ...
}
```

定义如下：

```C
// file: net/core/dev.c
static const struct bpf_link_ops bpf_xdp_link_lops = {
    .release = bpf_xdp_link_release,
    .dealloc = bpf_xdp_link_dealloc,
    .detach = bpf_xdp_link_detach,
    .show_fdinfo = bpf_xdp_link_show_fdinfo,
    .fill_link_info = bpf_xdp_link_fill_link_info,
    .update_prog = bpf_xdp_link_update,
};
```

##### (2) 更新bpf程序

* BPF系统调用
  
`BPF_LINK_UPDATE` 是BPF系统调用，如下：

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
    case BPF_LINK_UPDATE: err = link_update(&attr); break;
    ...
    }
    return err;
}
```

`link_update` 在获取link和设置的bpf程序后，调用`ops->update_prog` 接口。如下：

```C
// file: kernel/bpf/syscall.c
static int link_update(union bpf_attr *attr)
{
    ...
    // 检查设置的参数
    if (CHECK_ATTR(BPF_LINK_UPDATE)) return -EINVAL;

    flags = attr->link_update.flags;
    if (flags & ~BPF_F_REPLACE) return -EINVAL;

    // 获取 link 和 new_prog
    link = bpf_link_get_from_fd(attr->link_update.link_fd);
    if (IS_ERR(link)) return PTR_ERR(link);
    new_prog = bpf_prog_get(attr->link_update.new_prog_fd);
    if (IS_ERR(new_prog)) { ... }

    // 获取 old_prog
    if (flags & BPF_F_REPLACE) {
        old_prog = bpf_prog_get(attr->link_update.old_prog_fd);
        if (IS_ERR(old_prog)) { ...  }
    } else if (attr->link_update.old_prog_fd) { ... }

    // ops更新接口调用
    if (link->ops->update_prog)
        ret = link->ops->update_prog(link, new_prog, old_prog);
    else
        ret = -EINVAL;
    
    ...
}
```

* `xdp_link`更新

`.update_prog` 更新接口，更新当前设置的bpf程序，设置为 `bpf_xdp_link_update` 。实现如下:

```C
// file：net/core/dev.c
static int bpf_xdp_link_update(struct bpf_link *link, struct bpf_prog *new_prog, 
                struct bpf_prog *old_prog)
{
    struct bpf_xdp_link *xdp_link = container_of(link, struct bpf_xdp_link, link);
    ...
    rtnl_lock();
    ...
    // 获取`mode`和`bpf_op`后，调用`dev_xdp_install`
    mode = dev_xdp_mode(xdp_link->dev, xdp_link->flags);
    bpf_op = dev_xdp_bpf_op(xdp_link->dev, mode);
    err = dev_xdp_install(xdp_link->dev, mode, bpf_op, NULL, xdp_link->flags, new_prog);
    if (err) goto out_unlock;

    // 修改link设置的prog
    old_prog = xchg(&link->prog, new_prog);
    bpf_prog_put(old_prog);

out_unlock:
    rtnl_unlock();
    return err;
}
```

##### (3) 注销bpf程序

`.release` 释放接口，分离当前设置的bpf程序，设置为 `bpf_xdp_link_release` 。实现如下:

```C
// file：net/core/dev.c
static void bpf_xdp_link_release(struct bpf_link *link)
{
    struct bpf_xdp_link *xdp_link = container_of(link, struct bpf_xdp_link, link);

    rtnl_lock();
    if (xdp_link->dev) {
        WARN_ON(dev_xdp_detach_link(xdp_link->dev, NULL, xdp_link));
        xdp_link->dev = NULL;
    }
    rtnl_unlock();
}
```

在获取`xdp_link`后，检查`dev`属性后，调用 `dev_xdp_detach_link` 函数进行分离实现。后者获取`mode`和`bpf_op`后，调用 `dev_xdp_install` 进行xdp程序设置。如下：

```C
// file：net/core/dev.c
static int dev_xdp_detach_link(struct net_device *dev, struct netlink_ext_ack *extack, 
                struct bpf_xdp_link *link)
{
    ...
    mode = dev_xdp_mode(dev, link->flags);
    // 是否为当前link
    if (dev_xdp_link(dev, mode) != link) return -EINVAL;

    bpf_op = dev_xdp_bpf_op(dev, mode);
    WARN_ON(dev_xdp_install(dev, mode, bpf_op, NULL, 0, NULL));
    dev_xdp_set_link(dev, mode, NULL);
    return 0;
}
```

### 4.5 网络协议栈接收数据过程(L2部分)

XDP处理网络数据，在继续之前我们首先对网络协议栈接收数据过程进行简单了解下。

在网卡收到数据后，网卡将DMA数据复制到RX队列中，通过IRQ硬件中断。在硬件中断处理过程中触发内核的软件中断，软件中断处理将数据从RX队列中复制到内核协议栈，进行后续协议处理。Linux内核网络栈接收数据过程非常复杂，具体过程可以参见[Linux 网络栈接收数据（RX）：原理及内核实现（2022）](https://arthurchiao.art/blog/linux-net-stack-implementation-rx-zh/)。

#### 1 硬件中断

以Linux ixgbe系列网卡为例，在网卡设备初始化时，初始化硬件中断，如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
int ixgbe_open(struct net_device *netdev)
        // 分配TX队列所需的资源
    --> err = ixgbe_setup_all_tx_resources(adapter);
        --> for (i = 0; i < adapter->num_tx_queues; i++)
            --> ixgbe_setup_tx_resources(adapter->tx_ring[i]);
        --> for (j = 0; j < adapter->num_xdp_queues; j++)
            --> err = ixgbe_setup_tx_resources(adapter->xdp_ring[j]);
        // 分配RX队列所需的资源
    --> err = ixgbe_setup_all_rx_resources(adapter);
        --> for (i = 0; i < adapter->num_rx_queues; i++) 
            --> err = ixgbe_setup_rx_resources(adapter, adapter->rx_ring[i]);
        // IRQ中断设置
    --> ixgbe_request_irq(adapter);
            // MSI-X 中断设置
        --> ixgbe_request_msix_irqs(adapter);
            --> for (vector = 0; vector < adapter->num_q_vectors; vector++)
                --> struct ixgbe_q_vector *q_vector = adapter->q_vector[vector];
                --> struct msix_entry *entry = &adapter->msix_entries[vector];
                    // 设置每个队列的IRQ
                --> err = request_irq(entry->vector, &ixgbe_msix_clean_rings, 0, q_vector->name, q_vector);
            --> err = request_irq(adapter->msix_entries[vector].vector, 
                    ixgbe_msix_other, 0, netdev->name, adapter);
            // MSI 中断设置
        --> request_irq(adapter->pdev->irq, ixgbe_intr, 0, netdev->name, adapter);
```

以MSI-X中断为例，设置的中断处理函数为 `ixgbe_msix_clean_rings` ，实现如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
static irqreturn_t ixgbe_msix_clean_rings(int irq, void *data)
{
    struct ixgbe_q_vector *q_vector = data;
    if (q_vector->rx.ring || q_vector->tx.ring)
        napi_schedule_irqoff(&q_vector->napi);
    return IRQ_HANDLED;
}
```

`napi_schedule_irqoff` 函数触发RX软中断，进而调度NAPI poll。调用过程如下：

```C
// file: include/linux/netdevice.h
static inline void napi_schedule_irqoff(struct napi_struct *n)
    --> if (napi_schedule_prep(n))
        --> __napi_schedule_irqoff(n);
            --> ____napi_schedule(this_cpu_ptr(&softnet_data), n);
                    // 添加到`softnet_data`列表中
                --> list_add_tail(&napi->poll_list, &sd->poll_list);
                    // 触发RX软件中断
                --> __raise_softirq_irqoff(NET_RX_SOFTIRQ);
```

#### 2 RX软中断

在`NET_RX_SOFTIRQ`软中断触发执行，`NET_RX_SOFTIRQ`软中断在`subsys_initcall`阶段初始化，如下：

```C
// file: net/core/dev.c
static int __init net_dev_init(void)
{
    ...
    for_each_possible_cpu(i) {
        struct work_struct *flush = per_cpu_ptr(&flush_works, i);
        struct softnet_data *sd = &per_cpu(softnet_data, i);
        // 工作队列初始化
        INIT_WORK(flush, flush_backlog);
        // softnet_data初始化
        skb_queue_head_init(&sd->input_pkt_queue);
        ...
    }
    ...
    // 注册本地连接(lookback)
    if (register_pernet_device(&loopback_net_ops)) goto out;
    ...
    // 注册TX/RX软中断
    open_softirq(NET_TX_SOFTIRQ, net_tx_action);
    open_softirq(NET_RX_SOFTIRQ, net_rx_action);
}
subsys_initcall(net_dev_init);
```

`net_rx_action` 是网络接收的软中断设置的处理函数，实现过程如下：

```C
// file: net/core/dev.c
static __latent_entropy void net_rx_action(struct softirq_action *h)
        // 接收网络数据包的接收队列
    --> struct softnet_data *sd = this_cpu_ptr(&softnet_data);
        // 读取的时间限制
    --> unsigned long time_limit = jiffies + usecs_to_jiffies(READ_ONCE(netdev_budget_usecs));
        // 读取的预算限制
    --> int budget = READ_ONCE(netdev_budget);
        // 将接收队列复制到`list`中
    --> list_splice_init(&sd->poll_list, &list);
    --> for (;;)
            // 释放defer列表中的skb
        --> skb_defer_free_flush(sd);
            // 接收队列为空时退出
        --> if (list_empty(&list)) { ... }
            // 获取接收队列的第一项
        --> n = list_first_entry(&list, struct napi_struct, poll_list);
            // poll接口
        --> budget -= napi_poll(n, &repoll);
            --> work = __napi_poll(n, &do_repoll);
                    // 执行网卡驱动的poll接口
                --> work = n->poll(n, weight);
            // 预算用完或者时间限制用完后退出
        --> if (unlikely(budget <= 0 || time_after_eq(jiffies, time_limit))) { ... }
        // 重新设置接收队列
    --> list_splice_tail_init(&sd->poll_list, &list);
    --> list_splice_tail(&repoll, &list);
    --> list_splice(&list, &sd->poll_list);
        // 接收队列不为空时，重新开启RX软中断
    --> if (!list_empty(&sd->poll_list)) __raise_softirq_irqoff(NET_RX_SOFTIRQ);
        // 唤醒其他CPU接收
    --> net_rps_action_and_irq_enable(sd);
```

`net_rx_action` 函数遍历接收队列，逐个执行网卡设备设置的`poll`函数接口。

#### 3 NAPI poll

以Linux ixgbe系列网卡设置的`poll`接口为`ixgbe_poll`

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_lib.c
static int ixgbe_alloc_q_vector(struct ixgbe_adapter *adapter, ...)
{
    ...
    netif_napi_add(adapter->netdev, &q_vector->napi, ixgbe_poll);
    ...
}
```

`ixgbe_poll` 函数发送TX队列中网络数据包、复制RX队列的数据包到内核协议栈中，如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
int ixgbe_poll(struct napi_struct *napi, int budget)
{
    struct ixgbe_q_vector *q_vector = container_of(napi, struct ixgbe_q_vector, napi);
    struct ixgbe_adapter *adapter = q_vector->adapter;
    ...

    // 遍历所有的TX队列发送数据
    ixgbe_for_each_ring(ring, q_vector->tx) {
        bool wd = ring->xsk_pool ? 
                ixgbe_clean_xdp_tx_irq(q_vector, ring, budget) :
                ixgbe_clean_tx_irq(q_vector, ring, budget);
        if (!wd) clean_complete = false;
    }
    // 预算用完后返回
    if (budget <= 0) return budget;

    // 计算RX的预算
    if (q_vector->rx.count > 1)
        per_ring_budget = max(budget/q_vector->rx.count, 1);
    else
        per_ring_budget = budget;

    // 遍历所有的RX队列接收数据
    ixgbe_for_each_ring(ring, q_vector->rx) {
        int cleaned = ring->xsk_pool ?
                ixgbe_clean_rx_irq_zc(q_vector, ring, per_ring_budget) :
                ixgbe_clean_rx_irq(q_vector, ring, per_ring_budget);
        work_done += cleaned;
        if (cleaned >= per_ring_budget)
            clean_complete = false;
    }
    // 所有的工作未完成(TX或RX队列有数据)，返回预算
    if (!clean_complete) return budget;

    // 所有的工作都完成(TX和RX队列中无数据)，退出poll模式
    if (likely(napi_complete_done(napi, work_done))) {
        if (adapter->rx_itr_setting & 1)
            ixgbe_set_itr(q_vector);
        if (!test_bit(__IXGBE_DOWN, &adapter->state))
            ixgbe_irq_enable_queues(adapter, BIT_ULL(q_vector->v_idx));
    }
    return min(work_done, budget - 1);
}
```

#### 4 处理RX队列

`ixgbe_clean_rx_irq` 函数实现网络数据包从RX缓存区复制数据到内核中，实现如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
static int ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
                struct ixgbe_ring *rx_ring, const int budget)
{
    unsigned int total_rx_bytes = 0, total_rx_packets = 0, frame_sz = 0;
    struct ixgbe_adapter *adapter = q_vector->adapter;
    u16 cleaned_count = ixgbe_desc_unused(rx_ring);
    unsigned int offset = rx_ring->rx_offset;
    struct xdp_buff xdp;
    ...
    // frame_sz设置
#if (PAGE_SIZE < 8192)
    frame_sz = ixgbe_rx_frame_truesize(rx_ring, 0);
#endif
    // xdp_buff初始化，设置xdp_rxq信息
    xdp_init_buff(&xdp, frame_sz, &rx_ring->xdp_rxq);

    while (likely(total_rx_packets < budget)) {
        // 归还缓冲区给硬件，批量归还
        if (cleaned_count >= IXGBE_RX_BUFFER_WRITE) {
            ixgbe_alloc_rx_buffers(rx_ring, cleaned_count);
            cleaned_count = 0;
        }
        // 获取RX队列的描述符和大小 
        rx_desc = IXGBE_RX_DESC(rx_ring, rx_ring->next_to_clean);
        size = le16_to_cpu(rx_desc->wb.upper.length);

        // dma 内存屏障
        dma_rmb();
        
        // 获取RX缓冲区数据
        rx_buffer = ixgbe_get_rx_buffer(rx_ring, rx_desc, &skb, size, &rx_buffer_pgcnt);

        // 网络数据包开始位置时，构建xdp_buff信息，运行BPF程序
        if (!skb) {
            unsigned char *hard_start;
            // 数据包开始位置
            hard_start = page_address(rx_buffer->page) + rx_buffer->page_offset - offset;
            // 设置xdp数据位置信息
            xdp_prepare_buff(&xdp, hard_start, offset, size, true);
            xdp_buff_clear_frags_flag(&xdp);
#if (PAGE_SIZE > 4096)
            xdp.frame_sz = ixgbe_rx_frame_truesize(rx_ring, size);
#endif
            // 运行XDP程序
            skb = ixgbe_run_xdp(adapter, rx_ring, &xdp);
        }

        if (IS_ERR(skb)) {
            // XDP程序判断skb包不能继续处理的的情况(返回值 != XDP_PASS)
            unsigned int xdp_res = -PTR_ERR(skb);
            if (xdp_res & (IXGBE_XDP_TX | IXGBE_XDP_REDIR)) {
                xdp_xmit |= xdp_res;
                ixgbe_rx_buffer_flip(rx_ring, rx_buffer, size);
            } else {
                rx_buffer->pagecnt_bias++;
            }
            total_rx_packets++;
            total_rx_bytes += size;
        } else if (skb) {
            // 不是完整的skb包，从RX缓冲区中获取数据
            ixgbe_add_rx_frag(rx_ring, rx_buffer, skb, size);
        } else if (ring_uses_build_skb(rx_ring)) {
            // 构建skb，数据内容复用RX缓冲区
            skb = ixgbe_build_skb(rx_ring, rx_buffer, &xdp, rx_desc);
        } else {
            // 构建skb，数据内容从RX缓冲区中复制
            skb = ixgbe_construct_skb(rx_ring, rx_buffer, &xdp, rx_desc);
        }

        // 获取缓冲区失败时退出
        if (!skb) {
            rx_ring->rx_stats.alloc_rx_buff_failed++;
            rx_buffer->pagecnt_bias++;
            break;
        }
        // 更新RX缓冲区位置
        ixgbe_put_rx_buffer(rx_ring, rx_buffer, skb, rx_buffer_pgcnt);
        cleaned_count++;

        // 检查skb是否完整，不完整时放到RX缓冲区上
        if (ixgbe_is_non_eop(rx_ring, rx_desc, skb))
            continue;
        // 检查skb布局是否正确
        if (ixgbe_cleanup_headers(rx_ring, rx_desc, skb))
            continue;
        
        // 更新接收字节数
        total_rx_bytes += skb->len;
        // 填充校验和、时间戳、VLANN和网络协议
        ixgbe_process_skb_fields(rx_ring, rx_desc, skb);
        // 接收的skb处理
        ixgbe_rx_skb(q_vector, skb);
        // 更新预算计数
        total_rx_packets++;
    }
    // XDP重定向处理，清空重定向
    if (xdp_xmit & IXGBE_XDP_REDIR)
        xdp_do_flush_map();
    // XDP更新转发队列
    if (xdp_xmit & IXGBE_XDP_TX) {
        struct ixgbe_ring *ring = ixgbe_determine_xdp_ring(adapter);
        ixgbe_xdp_ring_update_tail_locked(ring);
    }

    // 更新计数
    u64_stats_update_begin(&rx_ring->syncp);
    rx_ring->stats.packets += total_rx_packets;
    rx_ring->stats.bytes += total_rx_bytes;
    u64_stats_update_end(&rx_ring->syncp);
    q_vector->rx.total_packets += total_rx_packets;
    q_vector->rx.total_bytes += total_rx_bytes;

    return total_rx_packets;
}
```

#### 5 GRO处理

在检查skb布局正确后，填充校验和、网络协议等字段后，`ixgbe_rx_skb` 函数实现skb的后续处理，实现如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
void ixgbe_rx_skb(struct ixgbe_q_vector *q_vector, struct sk_buff *skb)
{
    napi_gro_receive(&q_vector->napi, skb);
}
```

GRO（Generic Receive Offloading）是对LRO的软件实现，对分片的数据包进行重组后提交到更上层。`napi_gro_receive` 实现GRO处理后提交到内核协议栈进行L2层处理，如下：

```C
// file: net/core/gro.c
gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
    gro_result_t ret;
    skb_mark_napi_id(skb, napi);
    trace_napi_gro_receive_entry(skb);

    // 获取GRO偏移量
    skb_gro_reset_offset(skb, 0);
    ret = napi_skb_finish(napi, skb, dev_gro_receive(napi, skb));
    
    trace_napi_gro_receive_exit(ret);
    return ret;
}
```

`dev_gro_receive` 函数实现GRO数据接收，返回结果，这里不进行展开分析。`napi_skb_finish` 根据GRO结果进行对应处理，如下：

```C
// file: net/core/gro.c
static gro_result_t napi_skb_finish(struct napi_struct *napi, struct sk_buff *skb, gro_result_t ret)
{
    switch (ret) {
    case GRO_NORMAL: // 正常情况
        gro_normal_one(napi, skb, 1);
        break;
    case GRO_MERGED_FREE: // 合并的情况，释放skb
        if (NAPI_GRO_CB(skb)->free == NAPI_GRO_FREE_STOLEN_HEAD)
            napi_skb_free_stolen_head(skb);
        else if (skb->fclone != SKB_FCLONE_UNAVAILABLE)
            __kfree_skb(skb);
        else
            __kfree_skb_defer(skb);
        break;
    case GRO_HELD:
    case GRO_MERGED:
    case GRO_CONSUMED:
        break;
    }
    return ret;
}
```

`gro_normal_one` 函数将skb存放到接收队列中，到一定数量（`gro_normal_batch`）时，调用`gro_normal_list` 函数批量送到协议栈中，如下：

```C
// file: include/net/gro.h
static inline void gro_normal_one(struct napi_struct *napi, struct sk_buff *skb, int segs)
{
    // 添加到`napi` RX列表中
    list_add_tail(&skb->list, &napi->rx_list);
    napi->rx_count += segs;
    // int gro_normal_batch __read_mostly = 8;
    if (napi->rx_count >= READ_ONCE(gro_normal_batch))
        gro_normal_list(napi);
}

// file: include/net/gro.h
static inline void gro_normal_list(struct napi_struct *napi)
{
    if (!napi->rx_count) return;
    netif_receive_skb_list_internal(&napi->rx_list);
    // 清空`napi` RX列表
    INIT_LIST_HEAD(&napi->rx_list);
    napi->rx_count = 0;
}
```

#### 6 L2处理

`netif_receive_skb_list_internal` 函数检查接收时间戳设置（`netstamp_needed_key`），启用时打上时间戳；在开启`rps_needed` 选项的情况下，将打时间戳的任务分散到其他CPU上。我们只分析`RPS`未开启的默认情况，在设置RX时间戳后调用`__netif_receive_skb_list` 函数，如下：

```C
// file: net/core/dev.c
void netif_receive_skb_list_internal(struct list_head *head)
{
    struct sk_buff *skb, *next;
    struct list_head sublist;

    INIT_LIST_HEAD(&sublist);
    list_for_each_entry_safe(skb, next, head, list) {
        // 标记RX时间
        net_timestamp_check(READ_ONCE(netdev_tstamp_prequeue), skb);
        skb_list_del_init(skb);
        // 延时设置RX时间戳
        if (!skb_defer_rx_timestamp(skb))
            list_add_tail(&skb->list, &sublist);
    }
    list_splice_init(&sublist, head);

    rcu_read_lock();
#ifdef CONFIG_RPS
    if (static_branch_unlikely(&rps_needed)) { ...  }
#endif
    __netif_receive_skb_list(head);
    rcu_read_unlock();
}
```

`__netif_receive_skb_list` 检查`pfmemalloc`分段情况，将skb列表分成多个段，每个段都调用 `__netif_receive_skb_list_core` 函数。如下：

```C
// file: net/core/dev.c
static void __netif_receive_skb_list(struct list_head *head)
{
    unsigned long noreclaim_flag = 0;
    struct sk_buff *skb, *next;
    bool pfmemalloc = false; /* Is current sublist PF_MEMALLOC? */

    list_for_each_entry_safe(skb, next, head, list) {
        if ((sk_memalloc_socks() && skb_pfmemalloc(skb)) != pfmemalloc) {
            struct list_head sublist;
            // 将列表分成两段
            list_cut_before(&sublist, head, &skb->list);
            if (!list_empty(&sublist))
                __netif_receive_skb_list_core(&sublist, pfmemalloc);
            // 切换`pfmemalloc`
            pfmemalloc = !pfmemalloc;
            if (pfmemalloc)
                noreclaim_flag = memalloc_noreclaim_save();
            else
                memalloc_noreclaim_restore(noreclaim_flag);
        }
    }
    // 处理剩余的部分
    if (!list_empty(head))
        __netif_receive_skb_list_core(head, pfmemalloc);
    if (pfmemalloc)
        memalloc_noreclaim_restore(noreclaim_flag);
}
```

`__netif_receive_skb_list_core` 函数遍历skb列表，调用 `__netif_receive_skb_core` 函数判断确定每个skb包的L3处理方式(`packet_type`)，对同一个设备的同一种类型网络数据包批量处理，如下：

```C
// file: net/core/dev.c
static void __netif_receive_skb_list_core(struct list_head *head, bool pfmemalloc)
{
    INIT_LIST_HEAD(&sublist);
    list_for_each_entry_safe(skb, next, head, list) {
        struct net_device *orig_dev = skb->dev;
        struct packet_type *pt_prev = NULL;
        skb_list_del_init(skb);
        // 判断网络数据包类型
        __netif_receive_skb_core(&skb, pfmemalloc, &pt_prev);
        if (!pt_prev)
            continue;
        if (pt_curr != pt_prev || od_curr != orig_dev) {
            // 不同类型或不同设备时，处理之前的列表
            __netif_receive_skb_list_ptype(&sublist, pt_curr, od_curr);
            // 初始化新列表
            INIT_LIST_HEAD(&sublist);
            pt_curr = pt_prev;
            od_curr = orig_dev;
        }
        list_add_tail(&skb->list, &sublist);
    }
    // 批量处理
    __netif_receive_skb_list_ptype(&sublist, pt_curr, od_curr);
}
```

`__netif_receive_skb_core` 函数完成网络数据包送到协议栈的工作，每个进入协议栈的网络包都需要经过这个步骤。这个函数做的事情非常多，后续将逐步分析每个功能。按顺序包括：

1. 处理SKB事件戳；
2. 通用XDP处理：软件执行XDP程序；
3. 处理VLAN协议头；
4. TAP处理，如：tcpdump抓包等；
5. TC处理，处理`INGRESS`规则或TC BPF程序、Netfilter处理；
6. VLAN处理；
7. RX路由处理；
8. 确定L3协议后发送。

### 4.6 卸载模式(Offloaded)执行XDP程序

在网卡硬件中运行，从DMA复制到RX队列过程中执行BPF程序，是物理层(L1)和数据链路层(L2)之间的过程。目前只有少量硬件支持，略过分析过程。

### 4.7 原生模式(Native)执行XDP程序

#### 1 执行XDP程序

在从RX缓冲区中获取网络数据包时，构建`xdp_buff`信息后，调用`ixgbe_run_xdp`函数，在网卡驱动层面运行XDP程序，实现如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
static struct sk_buff *ixgbe_run_xdp(struct ixgbe_adapter *adapter,
                struct ixgbe_ring *rx_ring, struct xdp_buff *xdp)
{
    int err, result = IXGBE_XDP_PASS;
    struct ixgbe_ring *ring;
    struct xdp_frame *xdpf;
    u32 act;

    // 获取bpf程序
    xdp_prog = READ_ONCE(rx_ring->xdp_prog);
    if (!xdp_prog) goto xdp_out;
    
    // 获取xdp_frame
    prefetchw(xdp->data_hard_start); /* xdp_frame write */
    // 运行BPF程序
    act = bpf_prog_run_xdp(xdp_prog, xdp);
    switch (act) {
    case XDP_PASS:
        break;
    case XDP_TX:
        xdpf = xdp_convert_buff_to_frame(xdp);
        ...
        ring = ixgbe_determine_xdp_ring(adapter);
        ...
        result = ixgbe_xmit_xdp_ring(ring, xdpf);
        if (result == IXGBE_XDP_CONSUMED) goto out_failure;
        break;
    case XDP_REDIRECT:
        err = xdp_do_redirect(adapter->netdev, xdp, xdp_prog);
        if (err) goto out_failure;
        result = IXGBE_XDP_REDIR;
        break;
    default:
        bpf_warn_invalid_xdp_action(rx_ring->netdev, xdp_prog, act);
        fallthrough;
    case XDP_ABORTED:
out_failure:
        trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
        fallthrough; /* handle aborts by dropping packet */
    case XDP_DROP:
        result = IXGBE_XDP_CONSUMED;
        break;
    }
xdp_out:
    return ERR_PTR(-result);
}
```

`bpf_prog_run_xdp` 函数运行XDP程序，获取执行结果，如下：

```C
// file: include/linux/filter.h
static __always_inline u32 bpf_prog_run_xdp(const struct bpf_prog *prog, struct xdp_buff *xdp)
{
    // 运行BPF程序
    u32 act = __bpf_prog_run(prog, xdp, BPF_DISPATCHER_FUNC(xdp));

    if (static_branch_unlikely(&bpf_master_redirect_enabled_key)) {
        // 多个网卡绑定时，检查是否在网卡间重定向
        if (act == XDP_TX && netif_is_bond_slave(xdp->rxq->dev))
            act = xdp_master_redirect(xdp);
    }
    return act;
}
```

根据 `bpf_prog_run_xdp` 函数执行完成后的返回结果，决定接下来如何处理这个数据包。XDP程序支持的返回结果如下：

* XDP_PASS : 将数据包交还给内核网络协议栈继续后续处理，XDP程序运行可能修改数据包内容；
* XDP_DROP : 丢弃数据包，主要用于报文过滤的安全场景；
* XDP_TX ： 转发数据包，将接收的数据包从同一个网卡上再次发送出去，主要用于负载均衡场景；
* XDP_REDIRECT：重定向数据包，有两种重定向方式：重定向到另一个网卡发送数据（类似`XDP_TX`）; 或者将数据包重定向到其他CPU处理（类似`XDP_PASS`），当前CPU继续网络数据包的后续处理；
* XDP_ABORTED : 表示bpf程序发生异常，通过`tracepoint`记录错误信息后，丢弃该数据包；
* default ：其他值的情况，内核记录和`tracepoint`记录错误信息后，丢弃改数据包；

#### 2 XDP_TX的实现过程

`bpf_prog_run_xdp` 函数返回为`XDP_TX`时，将网络数据包从同一个网卡上发送出去，执行过程如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
    case XDP_TX:
        xdpf = xdp_convert_buff_to_frame(xdp);
        ...
        ring = ixgbe_determine_xdp_ring(adapter);
        ...
        result = ixgbe_xmit_xdp_ring(ring, xdpf);
        if (result == IXGBE_XDP_CONSUMED) goto out_failure;
        break;
```

`xdp_convert_buff_to_frame` 函数将 `struct xdp_buff` 结构转换为 `struct xdp_frame` , 设置 `xdp_frame` 属性，如下：

```C
// file: include/net/xdp.h
static inline struct xdp_frame *xdp_convert_buff_to_frame(struct xdp_buff *xdp)
{
    struct xdp_frame *xdp_frame;
    if (xdp->rxq->mem.type == MEM_TYPE_XSK_BUFF_POOL)
        return xdp_convert_zc_to_xdp_frame(xdp);

    // xdp_frame 为 xdp 开始位置
    xdp_frame = xdp->data_hard_start;
    if (unlikely(xdp_update_frame_from_buff(xdp, xdp_frame) < 0))
        return NULL;

    xdp_frame->mem = xdp->rxq->mem;
    return xdp_frame;
}
```

以 `xdp_update_frame_from_buff` 为例，实现如下：

```C
// file: include/net/xdp.h
static inline int xdp_update_frame_from_buff(struct xdp_buff *xdp, struct xdp_frame *xdp_frame)
{
    int metasize, headroom;

    headroom = xdp->data - xdp->data_hard_start;
    metasize = xdp->data - xdp->data_meta;
    metasize = metasize > 0 ? metasize : 0;
    // 检查xdp空间是否正确
    if (unlikely((headroom - metasize) < sizeof(*xdp_frame)))return -ENOSPC;
    if (unlikely(xdp->data_end > xdp_data_hard_end(xdp))) { ... }
    // 设置 `xdp_frame` 属性
    xdp_frame->data = xdp->data;
    xdp_frame->len  = xdp->data_end - xdp->data;
    xdp_frame->headroom = headroom - sizeof(*xdp_frame);
    xdp_frame->metasize = metasize;
    xdp_frame->frame_sz = xdp->frame_sz;
    xdp_frame->flags = xdp->flags;
    return 0;
}
```

`ixgbe_determine_xdp_ring` 函数确定TX队列，如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe.h
static inline struct ixgbe_ring *ixgbe_determine_xdp_ring(struct ixgbe_adapter *adapter)
{
    int index = ixgbe_determine_xdp_q_idx(smp_processor_id());
    return adapter->xdp_ring[index];
}
```

`ixgbe_xmit_xdp_ring` 函数将`xdp_frame`映射到`dma`中，如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
int ixgbe_xmit_xdp_ring(struct ixgbe_ring *ring, struct xdp_frame *xdpf)
{
    struct skb_shared_info *sinfo = xdp_get_shared_info_from_frame(xdpf);
    u8 nr_frags = unlikely(xdp_frame_has_frags(xdpf)) ? sinfo->nr_frags : 0;
    u16 i = 0, index = ring->next_to_use;
    struct ixgbe_tx_buffer *tx_head = &ring->tx_buffer_info[index];
    struct ixgbe_tx_buffer *tx_buff = tx_head;
    union ixgbe_adv_tx_desc *tx_desc = IXGBE_TX_DESC(ring, index);
    u32 cmd_type, len = xdpf->len;
    void *data = xdpf->data;

    if (unlikely(ixgbe_desc_unused(ring) < 1 + nr_frags))
        return IXGBE_XDP_CONSUMED;
    // xdp_frame 数据内容设置
    tx_head->bytecount = xdp_get_frame_len(xdpf);
    tx_head->gso_segs = 1;
    tx_head->xdpf = xdpf;
    tx_desc->read.olinfo_status = cpu_to_le32(tx_head->bytecount << IXGBE_ADVTXD_PAYLEN_SHIFT);

    for (;;) {
        dma_addr_t dma;
        // dma映射
        dma = dma_map_single(ring->dev, data, len, DMA_TO_DEVICE);
        if (dma_mapping_error(ring->dev, dma)) goto unmap;
        // 设置`tx_buff` addr 和 len
        dma_unmap_len_set(tx_buff, len, len);
        dma_unmap_addr_set(tx_buff, dma, dma);

        cmd_type = IXGBE_ADVTXD_DTYP_DATA | IXGBE_ADVTXD_DCMD_DEXT |
                    IXGBE_ADVTXD_DCMD_IFCS | len;
        tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);
        tx_desc->read.buffer_addr = cpu_to_le64(dma);
        tx_buff->protocol = 0;

        if (++index == ring->count) index = 0;
        if (i == nr_frags) break;

        // 映射 skb->frags区域
        tx_buff = &ring->tx_buffer_info[index];
        tx_desc = IXGBE_TX_DESC(ring, index);
        tx_desc->read.olinfo_status = 0;
        data = skb_frag_address(&sinfo->frags[i]);
        len = skb_frag_size(&sinfo->frags[i]);
        i++;
    }
    // 设置描述符类型
    tx_desc->read.cmd_type_len |= cpu_to_le32(IXGBE_TXD_CMD);

    // 避免潜在的资源竞争
    smp_wmb();
    // 更新ring
    tx_head->next_to_watch = tx_desc;
    ring->next_to_use = index;
    return IXGBE_XDP_TX;
unmap:
    // 错误时取消dma内存映射
    ...
    return IXGBE_XDP_CONSUMED;
}
```

#### 3 XDP_REDIRECT的实现过程

##### (1) 重定向接口

`XDP_REDIRECT`通过三个步骤实现的，如下：

1. `bpf_redirect()` 和 `bpf_redirect_map()` 帮助程序(helpers)将查找的重定向目标以及其他元数据存储在 `bpf_redirect_info` per-CPU变量中;
2. 当程序返回`XDP_REDIRECT`时，驱动程序将调用`xdp_do_redirect()`，使用 `bpf_redirect_info` 变量中的信息将重定向队列添加到指定map类型的批量队列中(bulk queue);
3. 在退出其 NAPI 轮询循环之前，驱动程序将调用`xdp_do_flush()`，它将刷新所有不同的批量队列，从而完成重定向。

`xdp_do_redirect` 函数获取per-CPU变量 `bpf_redirect_info`, 转发`xsk`或`frame`, 实现如下：

```C
// file: net/core/filter.c
int xdp_do_redirect(struct net_device *dev, struct xdp_buff *xdp, struct bpf_prog *xdp_prog)
{
    struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
    enum bpf_map_type map_type = ri->map_type;

    if (map_type == BPF_MAP_TYPE_XSKMAP) {
        /* XDP_REDIRECT is not supported AF_XDP yet. */
        if (unlikely(xdp_buff_has_frags(xdp)))
            return -EOPNOTSUPP;
        return __xdp_do_redirect_xsk(ri, dev, xdp, xdp_prog);
    }
    return __xdp_do_redirect_frame(ri, dev, xdp_convert_buff_to_frame(xdp), xdp_prog);
}
```

`xdp_do_redirect` 获取重定向信息，在`XSKMAP`(AF_XDP) 时，调用 `__xdp_do_redirect_xsk()` 函数以`xsk`包形式实现重定向。其他类型的重定向，调用 `__xdp_do_redirect_frame()` 函数以`frame`形式实现重定向。`xsk`或`frame`处理重定向时，按照设置的map类型进行不同的处理，在处理完成时，调用 `_trace_xdp_redirect_map()` (正确重定向) 或 `_trace_xdp_redirect_map_err()` (重定向错误) 记录处理结果，如下：

```C
// file: net/core/filter.c
static __always_inline int __xdp_do_redirect_frame(struct bpf_redirect_info *ri, 
        struct net_device *dev, struct xdp_frame *xdpf, struct bpf_prog *xdp_prog)
{
    enum bpf_map_type map_type = ri->map_type;
    void *fwd = ri->tgt_value;
    u32 map_id = ri->map_id;
    ...
    ri->map_id = 0; /* Valid map id idr range: [1,INT_MAX[ */
    ri->map_type = BPF_MAP_TYPE_UNSPEC;

    if (unlikely(!xdpf)) { err = -EOVERFLOW; goto err; }

    switch (map_type) {
    case BPF_MAP_TYPE_DEVMAP:
        fallthrough;
        ...
    default:
        err = -EBADRQC;
    }

    if (unlikely(err)) goto err;
    _trace_xdp_redirect_map(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index);
    return 0;
err:
    _trace_xdp_redirect_map_err(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index, err);
    return err;
}
```

##### (2) 通过`ifindex`重定向

通过`ifindex`将网络数据包重定向到其他网卡。在BPF程序中调用 `bpf_xdp_redirect` 函数，设置重定向信息，如下：

```C
// file: net/core/filter.c
BPF_CALL_2(bpf_xdp_redirect, u32, ifindex, u64, flags)
{
    struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
    if (unlikely(flags))  return XDP_ABORTED;

    ri->tgt_index = ifindex;
    ri->map_id = INT_MAX;
    ri->map_type = BPF_MAP_TYPE_UNSPEC;
    return XDP_REDIRECT;
}
```

在 `xdp_do_redirect()` 中通过`frame`形式实现重定向，如下：

```C
// file: net/core/filter.c
static __always_inline int __xdp_do_redirect_frame(struct bpf_redirect_info *ri, 
        struct net_device *dev, struct xdp_frame *xdpf, struct bpf_prog *xdp_prog)
{
    enum bpf_map_type map_type = ri->map_type;
    void *fwd = ri->tgt_value;
    u32 map_id = ri->map_id;
    ...
    switch (map_type) {
    ...
    case BPF_MAP_TYPE_UNSPEC: // 默认重定向，重定向到`ifindex`
        if (map_id == INT_MAX) {
            fwd = dev_get_by_index_rcu(dev_net(dev), ri->tgt_index);
            if (unlikely(!fwd)) { err = -EINVAL; break; }
            err = dev_xdp_enqueue(fwd, xdpf, dev);
            break;
        }
        allthrough;
    default:
        err = -EBADRQC;
    }
}
```

通过`dev_get_by_index_rcu()`函数获取`ifindex`对应的`dev`设备后，调用 `dev_xdp_enqueue` 函数，如下：

```C
// file: kernel/bpf/devmap.c
int dev_xdp_enqueue(struct net_device *dev, struct xdp_frame *xdpf, struct net_device *dev_rx)
{
    return __xdp_enqueue(dev, xdpf, dev_rx, NULL);
}
```

`__xdp_enqueue()` 函数检查`xdpf`长度，能够转发时，调用 `bq_enqueue()` 函数添加到队列中。如下

```C
// file: kernel/bpf/devmap.c
static inline int __xdp_enqueue(struct net_device *dev, struct xdp_frame *xdpf,
                    struct net_device *dev_rx, struct bpf_prog *xdp_prog)
{
    // 支持性检查
    if (!(dev->xdp_features & NETDEV_XDP_ACT_NDO_XMIT)) return -EOPNOTSUPP;
    if (unlikely(!(dev->xdp_features & NETDEV_XDP_ACT_NDO_XMIT_SG) &&
            xdp_frame_has_frags(xdpf)))
        return -EOPNOTSUPP;

    // 检查转发frame长度
    err = xdp_ok_fwd_dev(dev, xdp_get_frame_len(xdpf));
    if (unlikely(err)) return err;
    // 添加到队列中
    bq_enqueue(dev, xdpf, dev_rx, xdp_prog);
    return 0;
}
```

`bq_enqueue` 函数将`xdp_frame`添加到当前CPU的 `dev_flush_list` 队列中，达到一定数量时批量发送，如下：

```C
// file: kernel/bpf/devmap.c
static void bq_enqueue(struct net_device *dev, struct xdp_frame *xdpf,
                struct net_device *dev_rx, struct bpf_prog *xdp_prog)
{
    // 获取 bulk_queue
    struct list_head *flush_list = this_cpu_ptr(&dev_flush_list);
    struct xdp_dev_bulk_queue *bq = this_cpu_ptr(dev->xdp_bulkq);

    // 批量发送
    if (unlikely(bq->count == DEV_MAP_BULK_SIZE))
        bq_xmit_all(bq, 0);

    if (!bq->dev_rx) {
        // 设置bp属性，接收的设备和xdp程序
        bq->dev_rx = dev_rx;
        bq->xdp_prog = xdp_prog;
        list_add(&bq->flush_node, flush_list);
    }
    bq->q[bq->count++] = xdpf;
}
```

`bq_xmit_all` 函数发送`bulk_queue`队列中的`xdp_frame`，如下：

```C
// file: kernel/bpf/devmap.c
static void bq_xmit_all(struct xdp_dev_bulk_queue *bq, u32 flags)
{
    struct net_device *dev = bq->dev;
    unsigned int cnt = bq->count;
    // 数量为0时，直接返回
    if (unlikely(!cnt)) return;

    // 加载`xdp_frame`内容
    for (i = 0; i < cnt; i++) {
        struct xdp_frame *xdpf = bq->q[i];
        prefetch(xdpf);
    }
    if (bq->xdp_prog) {
        // 运行xdp程序
        to_send = dev_map_bpf_prog_run(bq->xdp_prog, bq->q, cnt, dev);
        if (!to_send) goto out;
    }
    // 调用XDP发送接口，发送失败时，设置错误码和发送数量
    sent = dev->netdev_ops->ndo_xdp_xmit(dev, to_send, bq->q, flags);
    if (sent < 0) { err = sent; sent = 0; }

    // 释放未发送的`xdp_frame`
    for (i = sent; unlikely(i < to_send); i++)
        xdp_return_frame_rx_napi(bq->q[i]);
out:
    bq->count = 0;
    trace_xdp_devmap_xmit(bq->dev_rx, dev, sent, cnt - sent, err);
}
```

在`xdp_prog`存在的情况下，再次运行XDP程序。 `dev_map_bpf_prog_run` 函数完成这项工作，过滤`PASS`的`xdpf`，其他结果时释放`xdpf`。如下：

```C
// file: kernel/bpf/devmap.c
static int dev_map_bpf_prog_run(struct bpf_prog *xdp_prog, 
            struct xdp_frame **frames, int n, struct net_device *dev)
{
    struct xdp_txq_info txq = { .dev = dev };
    struct xdp_buff xdp;
    int i, nframes = 0;

    for (i = 0; i < n; i++) {
        struct xdp_frame *xdpf = frames[i];
        // `xdp_frame` 转换为 `xdp_buff`
        xdp_convert_frame_to_buff(xdpf, &xdp);
        xdp.txq = &txq;
        // 运行XDP程序
        act = bpf_prog_run_xdp(xdp_prog, &xdp);
        switch (act) {
        case XDP_PASS:
            // 更新`xdp_frame`，失败时释放，否则添加到`frames`中
            err = xdp_update_frame_from_buff(&xdp, xdpf);
            if (unlikely(err < 0)) xdp_return_frame_rx_napi(xdpf);
            else frames[nframes++] = xdpf;
            break;
        default:
            bpf_warn_invalid_xdp_action(NULL, xdp_prog, act);
            fallthrough;
        case XDP_ABORTED:
            trace_xdp_exception(dev, xdp_prog, act);
            fallthrough;
        case XDP_DROP:
            // 其他情况释放`xdp_frame`
            xdp_return_frame_rx_napi(xdpf);
            break;
        }
    }
    return nframes; /* sent frames count */
}
```

##### (3) 通过`devmap`重定向

* `bpf_redirect_map`的实现过程

在BPF程序中调用 `bpf_redirect_map` 函数，设置重定向信息，如下：

```C
// file: samples/bpf/xdp_redirect_map_multi.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct bpf_devmap_val));
    __uint(max_entries, 32);
} forward_map_native SEC(".maps");

static int xdp_redirect_map(struct xdp_md *ctx, void *forward_map)
{
    ...
    return bpf_redirect_map(forward_map, 0, BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
}

SEC("xdp")
int xdp_redirect_map_native(struct xdp_md *ctx)
{
    return xdp_redirect_map(ctx, &forward_map_native);
}
```

map类型为`DEVMAP`或`DEVMAP_HASH`时，重定向到其他`dev`中。调用 `bpf_redirect_map()` 时会调用 `map->ops->map_redirect()` 函数。 `DEVMAP`或`DEVMAP_HASH`对应的`bpf_mpa_ops`定义如下：

```C
// file: kernel/bpf/devmap.c
BTF_ID_LIST_SINGLE(dev_map_btf_ids, struct, bpf_dtab)
const struct bpf_map_ops dev_map_ops = {
    ...
    .map_btf_id = &dev_map_btf_ids[0],
    .map_redirect = dev_map_redirect,
};

// file: kernel/bpf/devmap.c
const struct bpf_map_ops dev_map_hash_ops = {
    ...
    .map_btf_id = &dev_map_btf_ids[0],
    .map_redirect = dev_hash_map_redirect,
};
```

`dev_map_redirect()` 和 `dev_hash_map_redirect()` 设置重定向信息，如下：

```C
// file: kernel/bpf/devmap.c
static long dev_map_redirect(struct bpf_map *map, u64 ifindex, u64 flags)
{
    return __bpf_xdp_redirect_map(map, ifindex, flags, 
            BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS, __dev_map_lookup_elem);
}
// file: kernel/bpf/devmap.c
static long dev_hash_map_redirect(struct bpf_map *map, u64 ifindex, u64 flags)
{
    return __bpf_xdp_redirect_map(map, ifindex, flags,
                BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS, __dev_map_hash_lookup_elem);
}
```

`__bpf_xdp_redirect_map()` 设置 `bpf_redirect_info` per-CPU变量信息，如下：

```C
// file: include/linux/filter.h
static __always_inline long __bpf_xdp_redirect_map(struct bpf_map *map, u64 index,
        u64 flags, const u64 flag_mask, void *lookup_elem(struct bpf_map *map, u32 key))
{
    struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
    const u64 action_mask = XDP_ABORTED | XDP_DROP | XDP_PASS | XDP_TX;

    // 检查flags设置情况，不能使用其他bit位置
    if (unlikely(flags & ~(action_mask | flag_mask)))
        return XDP_ABORTED;

    // 获取`index`对应的值
    ri->tgt_value = lookup_elem(map, index);
    if (unlikely(!ri->tgt_value) && !(flags & BPF_F_BROADCAST)) {
        // 查找失败时，清除`bpf_redirect_info`信息。在一个eBPF程序中执行多次查找时，使用最后一次
        ri->map_id = INT_MAX; /* Valid map id idr range: [1,INT_MAX[ */
        ri->map_type = BPF_MAP_TYPE_UNSPEC;
        return flags & action_mask;
    }
    // 设置重定向信息
    ri->tgt_index = index;
    ri->map_id = map->id;
    ri->map_type = map->map_type;

    // 根据标记设置map值，广播时设置map值
    if (flags & BPF_F_BROADCAST) {
        WRITE_ONCE(ri->map, map);
        ri->flags = flags;
    } else {
        WRITE_ONCE(ri->map, NULL);
        ri->flags = 0;
    }
    return XDP_REDIRECT;
}
```

在 `xdp_do_redirect()` 中通过`frame`形式实现重定向，如下：

```C
// file: net/core/filter.c
static __always_inline int __xdp_do_redirect_frame(struct bpf_redirect_info *ri, 
        struct net_device *dev, struct xdp_frame *xdpf, struct bpf_prog *xdp_prog)
{
    enum bpf_map_type map_type = ri->map_type;
    void *fwd = ri->tgt_value;
    u32 map_id = ri->map_id;
    ...
    switch (map_type) {
    case BPF_MAP_TYPE_DEVMAP:
        fallthrough;
    case BPF_MAP_TYPE_DEVMAP_HASH:
        map = READ_ONCE(ri->map);
        if (unlikely(map)) { 
            WRITE_ONCE(ri->map, NULL);
            err = dev_map_enqueue_multi(xdpf, dev, map, ri->flags & BPF_F_EXCLUDE_INGRESS);
        } else {
            err = dev_map_enqueue(fwd, xdpf, dev);
        }
        break;
    ...
    }
}
```

* 单个DEV的情况

map类型为`DEVMAP`或`DEVMAP_HASH`时，没有设置`ri->map`时，调用 `dev_map_enqueue()` 函数，如下：

```C
// file: kernel/bpf/devmap.c
int dev_map_enqueue(struct bpf_dtab_netdev *dst, struct xdp_frame *xdpf, struct net_device *dev_rx)
{
    struct net_device *dev = dst->dev;
    return __xdp_enqueue(dev, xdpf, dev_rx, dst->xdp_prog);
}
```

在获取设置的`dev`后，调用`__xdp_enqueue()` 函数将`xdpf`添加到队列中。`__xdp_enqueue()` 的实现见上一节。

* 多个DEV的情况

map类型为`DEVMAP`或`DEVMAP_HASH`时，设置`ri->map`时，调用 `dev_map_enqueue_multi()` 函数，如下：

```C
// file: kernel/bpf/devmap.c
int dev_map_enqueue_multi(struct xdp_frame *xdpf, struct net_device *dev_rx,
        struct bpf_map *map, bool exclude_ingress)
{
    struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
    struct bpf_dtab_netdev *dst, *last_dst = NULL;
    int excluded_devices[1+MAX_NEST_DEV];
    ...
    // 排除指定的`dev`
    if (exclude_ingress) {
        num_excluded = get_upper_ifindexes(dev_rx, excluded_devices);
        excluded_devices[num_excluded++] = dev_rx->ifindex;
    }
    if (map->map_type == BPF_MAP_TYPE_DEVMAP) {
        for (i = 0; i < map->max_entries; i++) {
            // 遍历所有map列表，获取目标
            dst = rcu_dereference_check(dtab->netdev_map[i], rcu_read_lock_bh_held());
            // xdpf不支持时 或者 目标网卡在排除列表中，进行下一项
            if (!is_valid_dst(dst, xdpf)) continue;
            if (is_ifindex_excluded(excluded_devices, num_excluded, dst->dev->ifindex))
                continue;
            // last_dst 最后一个添加到队列中
            if (!last_dst) { last_dst = dst; continue;}
            // 复制xdpf后，添加到队列中
            err = dev_map_enqueue_clone(last_dst, dev_rx, xdpf);
            if (err) return err; 
            last_dst = dst;
        }
    } else { /* BPF_MAP_TYPE_DEVMAP_HASH */
        for (i = 0; i < dtab->n_buckets; i++) {
            // 遍历hash列表
            head = dev_map_index_hash(dtab, i);
            // 遍历hash列表中的目标项
            hlist_for_each_entry_rcu(dst, head, index_hlist, lockdep_is_held(&dtab->index_lock)) {
                // xdpf不支持时 或者 目标网卡在排除列表中，进行下一项
                if (!is_valid_dst(dst, xdpf)) continue;
                if (is_ifindex_excluded(excluded_devices, num_excluded, dst->dev->ifindex))
                    continue;
                // last_dst 最后一个添加到队列中
                if (!last_dst) { last_dst = dst; continue;}
                err = dev_map_enqueue_clone(last_dst, dev_rx, xdpf);
                if (err) return err; 
                last_dst = dst;
            }
        }
    }
    if (last_dst)
        // 提交最后一项
        bq_enqueue(last_dst->dev, xdpf, dev_rx, last_dst->xdp_prog);
    else
        // 转发目标为空时，释放xdpf
        xdp_return_frame_rx_napi(xdpf); /* dtab is empty */
    return 0;
}
```

`dev_map_enqueue_multi()` 函数遍历map中设置转发目标，在支持`xdpf`转发且不在排除列表中时，复制`xdpf`后添加到队列中。转发目标为空时，释放`xdpf`。`dev_map_enqueue_clone()` 函数复制`xdpf`后，添加到队列中，如下：

```C
// file: kernel/bpf/devmap.c
static int dev_map_enqueue_clone(struct bpf_dtab_netdev *obj,
            struct net_device *dev_rx, struct xdp_frame *xdpf)
{
    struct xdp_frame *nxdpf;
    nxdpf = xdpf_clone(xdpf);
    if (!nxdpf) return -ENOMEM;

    bq_enqueue(obj->dev, nxdpf, dev_rx, obj->xdp_prog);
    return 0;
}
```

`bq_enqueue()` 的实现过程见上节内容。

##### (4) 通过`cpumap`重定向

* `bpf_redirect_map`的实现过程

在BPF程序中调用 `bpf_redirect_map` 函数，设置重定向信息，如下：

```C
// file: tools/testing/selftests/bpf/progs/xdp_features.c
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_cpumap_val));
    __uint(max_entries, 1);
} cpu_map SEC(".maps");

SEC("xdp")
int xdp_do_redirect(struct xdp_md *xdp)
{
    ...
    return bpf_redirect_map(&cpu_map, 0, 0);
}
```

map类型为`CPUMAP`时，重定向到其他CPU上。`CPUMAP`的 `bpf_map_ops` 定义如下：

```C
// file: kernel/bpf/cpumap.c
BTF_ID_LIST_SINGLE(cpu_map_btf_ids, struct, bpf_cpu_map)
const struct bpf_map_ops dev_map_ops = {
    ...
    .map_btf_id	    = &cpu_map_btf_ids[0],
    .map_redirect   = cpu_map_redirect,
};
```

`cpu_map_redirect()` 设置重定向信息，如下：

```C
// file: kernel/bpf/cpumap.c
static long cpu_map_redirect(struct bpf_map *map, u64 index, u64 flags)
{
    return __bpf_xdp_redirect_map(map, index, flags, 0, __cpu_map_lookup_elem);
}
```

* `cpu_map`生产者的实现过程

在 `xdp_do_redirect()` 中通过`frame`形式实现重定向，如下：

```C
// file: net/core/filter.c
static __always_inline int __xdp_do_redirect_frame(struct bpf_redirect_info *ri, 
        struct net_device *dev, struct xdp_frame *xdpf, struct bpf_prog *xdp_prog)
{
    enum bpf_map_type map_type = ri->map_type;
    void *fwd = ri->tgt_value;
    u32 map_id = ri->map_id;
    ...
    switch (map_type) {
    ...
    case BPF_MAP_TYPE_CPUMAP:
        err = cpu_map_enqueue(fwd, xdpf, dev);
        break;
    ...
    }
    ...
}
```

`cpu_map_enqueue()` 函数设置`xdpf`后调用`bq_enqueue()`函数，如下：

```C
// file: kernel/bpf/cpumap.c
int cpu_map_enqueue(struct bpf_cpu_map_entry *rcpu, struct xdp_frame *xdpf, struct net_device *dev_rx)
{
    xdpf->dev_rx = dev_rx;
    bq_enqueue(rcpu, xdpf);
    return 0;
}
```

`bq_enqueue()` 函数将`xdpf`添加到`cpu_map_flush_list` per-CPU变量中`bulk_queue`中，到达一定数量时(`CPU_MAP_BULK_SIZE`) 批量刷新。如下：

```C
// file: kernel/bpf/cpumap.c
static void bq_enqueue(struct bpf_cpu_map_entry *rcpu, struct xdp_frame *xdpf)
{
    struct list_head *flush_list = this_cpu_ptr(&cpu_map_flush_list);
    struct xdp_bulk_queue *bq = this_cpu_ptr(rcpu->bulkq);

    // 批量刷新bulk_queue
    if (unlikely(bq->count == CPU_MAP_BULK_SIZE))
        bq_lush_to_queue(bq);

    // 添加xdpf
    bq->q[bq->count++] = xdpf;
    if (!bq->flush_node.prev)
        list_add(&bq->flush_node, flush_list);
}
```

`bq_flush_to_queue()` 函数将`xdpf`从`bulk_queue`移动到`ptr_ring`中，如下：

```C
// file: kernel/bpf/cpumap.c
static void bq_flush_to_queue(struct xdp_bulk_queue *bq)
{
    struct bpf_cpu_map_entry *rcpu = bq->obj;
    unsigned int processed = 0, drops = 0;
    const int to_cpu = rcpu->cpu;
    struct ptr_ring *q;
    ...
    if (unlikely(!bq->count)) return;

    q = rcpu->queue;
    spin_lock(&q->producer_lock);
    for (i = 0; i < bq->count; i++) {
        struct xdp_frame *xdpf = bq->q[i];
        // 移动到`ptr_ring`
        err = __ptr_ring_produce(q, xdpf);
        // 出现错误时，释放`xdpf`
        if (err) { drops++; xdp_return_frame_rx_napi(xdpf); }
        processed++;
    }
    bq->count = 0;
    spin_unlock(&q->producer_lock);
    // 删除`bq`
    __list_del_clearprev(&bq->flush_node);
    // 通过`tracepoint`记录信息
    trace_xdp_cpumap_enqueue(rcpu->map_id, processed, drops, to_cpu);
}
```

`__ptr_ring_produce()` 函数将`xdpf`移动到`ptr_ring->queue`中，`ptr_ring->queue` 是个环形缓冲区。实现如下：

```C
// file: kernel/bpf/cpumap.c
static inline int __ptr_ring_produce(struct ptr_ring *r, void *ptr)
{
    // 数量为0 或者 队列中有值，返回错误信息
    if (unlikely(!r->size) || r->queue[r->producer]) return -ENOSPC;

    smp_wmb();
    // 设置ptr后，更新生产者位置
    WRITE_ONCE(r->queue[r->producer++], ptr);
    if (unlikely(r->producer >= r->size))
        r->producer = 0;
    return 0;
}
```

* `cpu_map`消费者的实现过程

在使用`bpf_map_update_elem` 添加变量时，调用`.map_update_elem`接口。`cpu_map`设置的接口为`.map_update_elem = cpu_map_update_elem`，在更新map参数时，创建`bpf_cpu_map_entry`, 如下：

```C
// file: kernel/bpf/cpumap.c
static long cpu_map_update_elem(struct bpf_map *map, void *key, void *value, u64 map_flags)
{
    struct bpf_cpu_map *cmap = container_of(map, struct bpf_cpu_map, map);
    struct bpf_cpumap_val cpumap_value = {};
    struct bpf_cpu_map_entry *rcpu;
    // 重定向的CPU
    u32 key_cpu = *(u32 *)key;

    memcpy(&cpumap_value, value, map->value_size);

    if (unlikely(map_flags > BPF_EXIST)) return -EINVAL;
    if (unlikely(key_cpu >= cmap->map.max_entries)) return -E2BIG;
    if (unlikely(map_flags == BPF_NOEXIST)) return -EEXIST;
    // qsize数量限制
    if (unlikely(cpumap_value.qsize > 16384)) return -EOVERFLOW;
    // 确保CPU是可用的CPU
    if (key_cpu >= nr_cpumask_bits || !cpu_possible(key_cpu)) return -ENODEV;

    if (cpumap_value.qsize == 0) {
        rcpu = NULL; /* Same as deleting */
    } else {
        // 更新qsize，需要重新分配`bpf_cpu_map_entry`
        rcpu = __cpu_map_entry_alloc(map, &cpumap_value, key_cpu);
        if (!rcpu) return -ENOMEM;
        rcpu->cmap = cmap;
    }
    rcu_read_lock();
    __cpu_map_entry_replace(cmap, key_cpu, rcpu);
    rcu_read_unlock();
    return 0;
}
```

`__cpu_map_entry_alloc()` 函数创建`cpu_map`内部结构，创建`rcpu`使用的`bulkq`、存放`xdpf`的队列、`kthread`等信息，如下：

```C
// file: kernel/bpf/cpumap.c
static struct bpf_cpu_map_entry *
__cpu_map_entry_alloc(struct bpf_map *map, struct bpf_cpumap_val *value, u32 cpu)
{
    fd = value->bpf_prog.fd;
    // cpu对应numa节点
    numa = cpu_to_node(cpu);
    // 创建`rcpu`
    rcpu = bpf_map_kmalloc_node(map, sizeof(*rcpu), gfp | __GFP_ZERO, numa);
    // 创建percpu变量`bulkq`
    rcpu->bulkq = bpf_map_alloc_percpu(map, sizeof(*rcpu->bulkq), sizeof(void *), gfp);

    // 设置每个CPU的`bulkq`属性
    for_each_possible_cpu(i) {
        bq = per_cpu_ptr(rcpu->bulkq, i);
        bq->obj = rcpu;
    }
    // 创建`queue`
    rcpu->queue = bpf_map_kmalloc_node(map, sizeof(*rcpu->queue), gfp, numa);
    // `rcpu->queue` 初始化，分配`xdpf`的内存空间，初始化`ptr_ring`
    err = ptr_ring_init(rcpu->queue, value->qsize, gfp);

    // rcpu属性设置
    rcpu->cpu    = cpu;
    rcpu->map_id = map->id;
    rcpu->value.qsize  = value->qsize;
    // 设置bpf程序的情况，检查并设置xdp程序
    if (fd > 0 && __cpu_map_load_bpf_program(rcpu, map, fd)) goto free_ptr_ring;

    // 设置 `kthread`
    rcpu->kthread = kthread_create_on_node(cpu_map_kthread_run, rcpu, numa,
                           "cpumap/%d/map:%d", cpu, map->id);

    get_cpu_map_entry(rcpu); /* 1-refcnt for being in cmap->cpu_map[] */
    get_cpu_map_entry(rcpu); /* 1-refcnt for kthread */

    // 确保 kthread 运行在指定的CPU上
    kthread_bind(rcpu->kthread, cpu);
    wake_up_process(rcpu->kthread);
    return rcpu;
    ...
}
```

创建 `rcpu->kthread` 的执行函数为 `cpu_map_kthread_run`。该函数获取`rcpu->queue`队列中`xdpf`，运行XDP程序后，将`xdpf`转换为`skb`,发送到内核协议栈进行后续处理，实现如下：

```C
// file: kernel/bpf/cpumap.c
static int cpu_map_kthread_run(void *data)
{
    struct bpf_cpu_map_entry *rcpu = data;
    set_current_state(TASK_INTERRUPTIBLE);
    while (!kthread_should_stop() || !__ptr_ring_empty(rcpu->queue)) {
        ...
        void *frames[CPUMAP_BATCH];
        void *skbs[CPUMAP_BATCH];
        LIST_HEAD(list);
        
        // kthread 唤醒检查 
        if (__ptr_ring_empty(rcpu->queue)) {
            // 二次唤醒
        } else { sched = cond_resched(); }

        // 消费`rcpu->queue`，批量从queue中获取数据
        n = __ptr_ring_consume_batched(rcpu->queue, frames, CPUMAP_BATCH);
        // 检查`frames`，确定`xdpf`和`skb`
        for (i = 0, xdp_n = 0; i < n; i++) {
            void *f = frames[i];
            struct page *page;
            // bit0标记，表示为`skb`, 直接添加到skb列表中
            if (unlikely(__ptr_test_bit(0, &f))) {
                struct sk_buff *skb = f;
                __ptr_clear_bit(0, &skb);
                list_add_tail(&skb->list, &list);
                continue;
            }
            frames[xdp_n++] = f;
            // 加载`xdpf`数据
            page = virt_to_page(f);
            prefetchw(page);
        }
        // 进行内核协议栈前运行XDP程序
        nframes = cpu_map_bpf_prog_run(rcpu, frames, xdp_n, &stats, &list);
        if (nframes) {
            // 分配skb需要的内存
            m = kmem_cache_alloc_bulk(skbuff_cache, gfp, nframes, skbs);
            if (unlikely(m == 0)) { ...  }
        }

        local_bh_disable();
        for (i = 0; i < nframes; i++) {
            struct xdp_frame *xdpf = frames[i];
            struct sk_buff *skb = skbs[i];
            // 将`xdpf`转换为`skb`
            skb = __xdp_build_skb_from_frame(xdpf, skb, xdpf->dev_rx);
            if (!skb) {
                // 转换失败时，释放`xdpf`
                xdp_return_frame(xdpf);
                continue;
            }
            // 成功时，添加到skb列表中
            list_add_tail(&skb->list, &list);
        }
        // 发送到内核协议栈进行处理
        netif_receive_skb_list(&list);

        // 通过Tracepoint记录日志
        trace_xdp_cpumap_kthread(rcpu->map_id, n, kmem_alloc_drops, sched, &stats);
        local_bh_enable(); /* resched point, may call do_softirq() */
    }
    __set_current_state(TASK_RUNNING);
    put_cpu_map_entry(rcpu);
    return 0;
}
```

`cpu_map_bpf_prog_run` 函数对重定向到该CPU的`xdpf`和`skb`检查，如下：

```C
// file: kernel/bpf/cpumap.c
static int cpu_map_bpf_prog_run(struct bpf_cpu_map_entry *rcpu, void **frames,
            int xdp_n, struct xdp_cpumap_stats *stats, struct list_head *list)
{
    int nframes;
    // 没有设置xdp程序时，返回
    if (!rcpu->prog) return xdp_n;

    rcu_read_lock_bh();
    // 运行XDP程序，检查xdpf
    nframes = cpu_map_bpf_prog_run_xdp(rcpu, frames, xdp_n, stats);
    // 存在重定向时，刷新
    if (stats->redirect) xdp_do_flush();

    if (unlikely(!list_empty(list)))
        // 运行XDP程序，检查skb
        cpu_map_bpf_prog_run_skb(rcpu, list, stats);

    rcu_read_unlock_bh(); /* resched point, may call do_softirq() */
    return nframes;
}
```

`cpu_map_bpf_prog_run_xdp` 函数检查`xdpf`，这些`xdpf`由原生模式XDP重定向的。记录`PASS`的`xdpf`，`REDIRECT`时再次重定向，其他情况释放`xdpf`。如下：

```C
// file: kernel/bpf/cpumap.c
static int cpu_map_bpf_prog_run_xdp(struct bpf_cpu_map_entry *rcpu,
                void **frames, int n, struct xdp_cpumap_stats *stats)
{
    struct xdp_rxq_info rxq; 
    struct xdp_buff xdp;
    
    // 设置`NO_DIRECT`标记
    xdp_set_return_frame_no_direct();
    xdp.rxq = &rxq;

    for (i = 0; i < n; i++) {
        struct xdp_frame *xdpf = frames[i];
        rxq.dev = xdpf->dev_rx;
        rxq.mem = xdpf->mem;
        // 转换为`xdpf`转换为`xdp_buff`
        xdp_convert_frame_to_buff(xdpf, &xdp);
        // 运行XDP程序
        act = bpf_prog_run_xdp(rcpu->prog, &xdp);

        switch (act) {
        case XDP_PASS:
            // 转换为`xdpf`, 失败时释放`xdpf`，成功时添加到`frames`中
            err = xdp_update_frame_from_buff(&xdp, xdpf);
            if (err < 0) { xdp_return_frame(xdpf); stats->drop++;
            } else { frames[nframes++] = xdpf; stats->pass++; }
            break;
        case XDP_REDIRECT:
            // 再次重定向，失败时释放`xdpf`，成功时增加`redirect`计数
            err = xdp_do_redirect(xdpf->dev_rx, &xdp, rcpu->prog);
            if (unlikely(err)) { xdp_return_frame(xdpf); stats->drop++;
            } else { stats->redirect++; }
            break;
        default:
            bpf_warn_invalid_xdp_action(NULL, rcpu->prog, act);
            fallthrough;
        case XDP_DROP:
            // 其他返回值，释放`xdpf`
            xdp_return_frame(xdpf);
            stats->drop++;
            break;
        }
    }
    // 清除`NO_DIRECT`标记，
    xdp_clear_return_frame_no_direct();
    return nframes;
}
```

`cpu_map_bpf_prog_run_skb` 函数检查`skb`，这些`skb`由通用模式XDP重定向的。执行过程在下节介绍。

##### (5) 通过`xskmap`重定向

* `bpf_redirect_map`的实现过程

在BPF程序中调用 `bpf_redirect_map` 函数，设置重定向信息，如下：

```C
// file: tools/testing/selftests/bpf/progs/xsk_xdp_progs.c
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsk SEC(".maps");

SEC("xdp") 
int xsk_def_prog(struct xdp_md *xdp)
{
    return bpf_redirect_map(&xsk, 0, XDP_DROP);
}
```

map类型为`XSKMAP`时，重定向到`xsk`(AF_XDP类型的socket)。`XSKMAP`的 `bpf_map_ops` 定义如下：

```C
// file: net/xdp/xskmap.c
BTF_ID_LIST_SINGLE(xsk_map_btf_ids, struct, xsk_map)
const struct bpf_map_ops xsk_map_ops = {
    ...
    .map_btf_id = &xsk_map_btf_ids[0],
    .map_redirect = xsk_map_redirect,
};
```

`xsk_map_redirect()` 设置重定向信息，如下：

```C
// file: net/xdp/xskmap.c
static long xsk_map_redirect(struct bpf_map *map, u64 index, u64 flags)
{
    return __bpf_xdp_redirect_map(map, index, flags, 0, __xsk_map_lookup_elem);
}
```

* 内核重定向`xdp_buff`

在 `xdp_do_redirect()` 中调用`__xdp_do_redirect_xsk`，以`xsk`形式实现重定向，如下：

```C
// file: net/core/filter.c
int xdp_do_redirect(struct net_device *dev, struct xdp_buff *xdp, struct bpf_prog *xdp_prog)
{
    struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
    enum bpf_map_type map_type = ri->map_type;

    if (map_type == BPF_MAP_TYPE_XSKMAP) {
        if (unlikely(xdp_buff_has_frags(xdp)))
            return -EOPNOTSUPP;
        return __xdp_do_redirect_xsk(ri, dev, xdp, xdp_prog);
    }
    return __xdp_do_redirect_frame(ri, dev, xdp_convert_buff_to_frame(xdp), xdp_prog);
}
```

`__xdp_do_redirect_xsk` 函数设置`bpf_redirect_info`信息后，调用`__xsk_map_redirect()`函数实现重定向。如下

```C
// file: net/core/filter.c
static inline int __xdp_do_redirect_xsk(struct bpf_redirect_info *ri,
            struct net_device *dev, struct xdp_buff *xdp, struct bpf_prog *xdp_prog)
{
    enum bpf_map_type map_type = ri->map_type;
    void *fwd = ri->tgt_value;
    u32 map_id = ri->map_id;

    ri->map_id = 0; /* Valid map id idr range: [1,INT_MAX[ */
    ri->map_type = BPF_MAP_TYPE_UNSPEC;
    err = __xsk_map_redirect(fwd, xdp);
    if (unlikely(err)) goto err;
    // 通过Tracepoint记录日志
    _trace_xdp_redirect_map(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index);
    return 0;
err:
    _trace_xdp_redirect_map_err(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index, err);
    return err;
}
```

`__xsk_map_redirect` 函数通过`xsk`接收`xdp_buff`, 并将`xsk`添加到刷新列表中，如下：

```C
// file: net/xdp/xsk.c
int __xsk_map_redirect(struct xdp_sock *xs, struct xdp_buff *xdp)
{
    struct list_head *flush_list = this_cpu_ptr(&xskmap_flush_list);
    // xsk接收数据
    int err = xsk_rcv(xs, xdp);
    if (err) return err;
    // 添加到刷新列表中
    if (!xs->flush_node.prev)
        list_add(&xs->flush_node, flush_list);
    return 0;
}
```

`xsk_rcv` 函数实现`xsk`数据的接收，检查`xsk`和`xdp_buff`状态后，通过`__xsk_rcv_zc` 或 `__xsk_rcv` 接收数据。 如下：

```C
// file: net/xdp/xsk.c
static int xsk_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
    // 确认`xsk`处于绑定状态，`xsk`和`xdp_buff`是同样设备和同一队列
    err = xsk_rcv_check(xs, xdp);
    if (err) return err;

    if (xdp->rxq->mem.type == MEM_TYPE_XSK_BUFF_POOL) {
        len = xdp->data_end - xdp->data;
        // 在xdp支持pool时，直接添加
        return __xsk_rcv_zc(xs, xdp, len);
    }
    // 接收数据
    err = __xsk_rcv(xs, xdp);
    // 失败时释放`xdp_buff`
    if (!err) xdp_return_buff(xdp);
    return err;
}
```

`__xsk_rcv` 函数在`xdp->rxq`不支持时pool时，复制`xdp_buff`后，调用`__xsk_rcv_zc`添加到`xsk`接收队列中，如下：

```C
// file: net/xdp/xsk.c
static int __xsk_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
    struct xdp_buff *xsk_xdp;
    u32 len;

    // 计算`xdp_buff`长度，超过`xsk->pool`支持的长度时返回
    len = xdp->data_end - xdp->data;
    if (len > xsk_pool_get_rx_frame_size(xs->pool)) { 
        xs->rx_dropped++;
        return -ENOSPC;
    }
    // 从`xsk->pool`获取`xsk_xdp`，失败时返回
    xsk_xdp = xsk_buff_alloc(xs->pool);
    if (!xsk_xdp) { xs->rx_dropped++; return -ENOMEM; }

    // 复制`xsk_xdp`内容
    xsk_copy_xdp(xsk_xdp, xdp, len);
    err = __xsk_rcv_zc(xs, xsk_xdp, len);
    if (err) {
        // 失败时释放`xsk_xdp`
        xsk_buff_free(xsk_xdp);
        return err;
    }
    return 0;
}
```

`__xsk_rcv_zc` 函数实现`xsk`的数据接收，如下：

```C
// file: net/xdp/xsk.c
static int __xsk_rcv_zc(struct xdp_sock *xs, struct xdp_buff *xdp, u32 len)
{
    struct xdp_buff_xsk *xskb = container_of(xdp, struct xdp_buff_xsk, xdp);
    u64 addr;
    // 获取`xskb`地址
    addr = xp_get_handle(xskb);
    // 添加到`xsk->rx`接收队列中，失败时增加接收队列已满(`rx_queue_full`)的计数
    err = xskq_prod_reserve_desc(xs->rx, addr, len);
    if (err) {
        xs->rx_queue_full++;
        return err;
    }
    // 释放`xskb`到`pool`中
    xp_release(xskb);
    return 0;
}
```

`xskq_prod_reserve_desc`函数将`addr`和`len`添加到队列中，如下：

```C
// file: net/xdp/xsk_queue.h
static inline int xskq_prod_reserve_desc(struct xsk_queue *q, u64 addr, u32 len)
{
    // 接收发送队列
    struct xdp_rxtx_ring *ring = (struct xdp_rxtx_ring *)q->ring;
    u32 idx;
    // 队列已满的情况下返回
    if (xskq_prod_is_full(q)) return -ENOBUFS;

    // 获取desc位置后设置 addr 和 len
    idx = q->cached_prod++ & q->ring_mask;
    ring->desc[idx].addr = addr;
    ring->desc[idx].len = len;
    return 0;
}
```

* 用户空间接收`xdp_buff`

用户空间创建`AF_XDP`类型的socket，通过内存映射接收数据。具体实现过程参数见[AF_XDP技术详解](https://rexrock.github.io/post/af_xdp1/)。

##### (6) 刷新重定向

在通过NAPI poll中处理RX队列时，在用完接收预算后，检查XDP执行状态，存在重定向时刷新重定向map，如下：

```C
// file: drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
static int ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector, 
            struct ixgbe_ring *rx_ring,  const int budget)
{
    ...
    if (xdp_xmit & IXGBE_XDP_REDIR)
        xdp_do_flush_map();
    ...
}
```

`xdp_do_flush_map` 定义为 `xdp_do_flush`， 如下：

```C
// file: include/linux/filter.h
#define xdp_do_flush_map xdp_do_flush
```

`xdp_do_flush()` 函数刷新`devmap`,`cpumap`和`xskmap`，如下：

```C
// file: net/core/filter.c
void xdp_do_flush(void)
{
    __dev_flush();
    __cpu_map_flush();
    __xsk_map_flush();
}
```

`__dev_flush` 函数刷新`dev_flush_list`, 在通过`devmap`重定向时，将`bulk_queue`添加到`dev_flush_list`。此时，调用`bq_xmit_all`发送队列中的`xdpf`。如下：

```C
// file: kernel/bpf/devmap.c
void __dev_flush(void)
{
    struct list_head *flush_list = this_cpu_ptr(&dev_flush_list);
    struct xdp_dev_bulk_queue *bq, *tmp;

    list_for_each_entry_safe(bq, tmp, flush_list, flush_node) {
        bq_xmit_all(bq, XDP_XMIT_FLUSH);
        bq->dev_rx = NULL;
        bq->xdp_prog = NULL;
        __list_del_clearprev(&bq->flush_node);
    }
}
```

`__cpu_map_flush` 函数刷新`cpu_map_flush_list`, 在通过`cpumap`重定向时，将`bulk_queue`添加到`cpu_map_flush_list`。此时，调用`bq_flush_to_queue`将`bulk_queue`中`xdpf`转移到`rx`队列中，并唤醒`kthread`。如下：

```C
// file: kernel/bpf/cpumap.c
void __cpu_map_flush(void)
{
    struct list_head *flush_list = this_cpu_ptr(&cpu_map_flush_list);
    struct xdp_bulk_queue *bq, *tmp;

    list_for_each_entry_safe(bq, tmp, flush_list, flush_node) {
        bq_flush_to_queue(bq);
        wake_up_process(bq->obj->kthread);
    }
}
```

`__xsk_map_flush` 函数刷新`xskmap_flush_list`, 在通过`xskmap`重定向时，将`xsk`添加到`xskmap_flush_list`。此时，调用`xsk_flush`唤醒`xsk`。如下：

```C
// file: net/xdp/xsk.c
void __xsk_map_flush(void)
{
    struct list_head *flush_list = this_cpu_ptr(&xskmap_flush_list);
    struct xdp_sock *xs, *tmp;

    list_for_each_entry_safe(xs, tmp, flush_list, flush_node) {
        xsk_flush(xs);
        __list_del_clearprev(&xs->flush_node);
    }
}
```

### 4.8 通用模式(Generic)执行XDP程序

#### 1 执行XDP程序

`__netif_receive_skb_core` 函数检查每个进入协议栈之前网络数据包，在设置时间戳后进行通用模式XDP处理。在网卡驱动不支持XDP处理时，XDP程序推迟到这里来执行。如下：

```C
// file: net/core/dev.c
static int __netif_receive_skb_core(struct sk_buff **pskb, bool pfmemalloc, 
                struct packet_type **ppt_prev)
{
    ...
    // 前面未设置时间戳时，在这里打上时间戳
    net_timestamp_check(!READ_ONCE(netdev_tstamp_prequeue), skb);

    trace_netif_receive_skb(skb);
    orig_dev = skb->dev;

    // 重置skb网络头、传输头、mac地址位置
    skb_reset_network_header(skb);
    if (!skb_transport_header_was_set(skb))
        skb_reset_transport_header(skb);
    skb_reset_mac_len(skb);

    pt_prev = NULL;

another_round:
    // 网络设备ifindex设置
    skb->skb_iif = skb->dev->ifindex;
    // 增加处理计数
    __this_cpu_inc(softnet_data.processed);

    if (static_branch_unlikely(&generic_xdp_needed_key)) {
        int ret2;
        migrate_disable();
        // 执行通用XDP程序
        ret2 = do_xdp_generic(rcu_dereference(skb->dev->xdp_prog), skb);
        migrate_enable();
        // 除PASS外的状态都
        if (ret2 != XDP_PASS) {
            ret = NET_RX_DROP;
            goto out;
        }
    }
    ...
out:
    *pskb = skb;
    return ret;
}
```

`do_xdp_generic` 函数执行XDP程序，对 `XP_REDIRECT` 和 `XDP_TX` 返回结果进行特殊处理，如下：

```C
// file: net/core/dev.c
int do_xdp_generic(struct bpf_prog *xdp_prog, struct sk_buff *skb)
{
    if (xdp_prog) {
        ...
        act = netif_receive_generic_xdp(skb, &xdp, xdp_prog);
        if (act != XDP_PASS) {
            switch (act) {
            case XDP_REDIRECT:
                err = xdp_do_generic_redirect(skb->dev, skb, &xdp, xdp_prog);
                if (err) goto out_redir;
                break; 
            case XDP_TX:
                generic_xdp_tx(skb, xdp_prog);
                break;
            }
            return XDP_DROP;
        }
    }
    return XDP_PASS;
out_redir:
    kfree_skb_reason(skb, SKB_DROP_REASON_XDP);
    return XDP_DROP;
}
```

`netif_receive_generic_xdp` 函数将skb数据包转换为线性地址后运行XDP程序，如下：

```C
// file: net/core/dev.c
static u32 netif_receive_generic_xdp(struct sk_buff *skb,
                struct xdp_buff *xdp, struct bpf_prog *xdp_prog)
{
    // 默认状态，DROP
    u32 act = XDP_DROP;

    // 通过重定向进入的数据包不进行`XDP`处理
    if (skb_is_redirected(skb))
        return XDP_PASS;

    // XDP 数据包必须是线性的，并且必须有足够的余量(XDP_PACKET_HEADROOM 字节)
    if (skb_cloned(skb) || skb_is_nonlinear(skb) ||
        skb_headroom(skb) < XDP_PACKET_HEADROOM) {
        int hroom = XDP_PACKET_HEADROOM - skb_headroom(skb);
        int troom = skb->tail + skb->data_len - skb->end;

        // 扩展skb 头部信息，失败时丢弃skb
        if (pskb_expand_head(skb, 
                    hroom > 0 ? ALIGN(hroom, NET_SKB_PAD) : 0,
                    troom > 0 ? troom + 128 : 0, GFP_ATOMIC))
            goto do_drop;
        // 将skb分散的frags内容转换为线性内容，失败时丢弃skb
        if (skb_linearize(skb)) goto do_drop;
    }
    // 运行XDP程序
    act = bpf_prog_run_generic_xdp(skb, xdp, xdp_prog);
    switch (act) {
    case XDP_REDIRECT:
    case XDP_TX:
    case XDP_PASS:
        break;
    default:
        bpf_warn_invalid_xdp_action(skb->dev, xdp_prog, act);
        fallthrough;
    case XDP_ABORTED:
        trace_xdp_exception(skb->dev, xdp_prog, act);
        fallthrough;
    case XDP_DROP:
    do_drop:
        // 其他释放skb
        kfree_skb(skb);
        break;
    }
    return act;
}
```

`bpf_prog_run_generic_xdp` 函数组织`xdp_buff`信息、记录原始数据位置后运行XDP程序，之后，重新组织skb。如下：

```C
// file: net/core/dev.c
u32 bpf_prog_run_generic_xdp(struct sk_buff *skb, struct xdp_buff *xdp, struct bpf_prog *xdp_prog)
{
    ...
    // 保存skb位置
    mac_len = skb->data - skb_mac_header(skb);
    hard_start = skb->data - skb_headroom(skb);

    frame_sz = (void *)skb_end_pointer(skb) - hard_start;
    frame_sz += SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

    // 组织`xdp_buff`内容
    rxqueue = netif_get_rxqueue(skb);
    xdp_init_buff(xdp, frame_sz, &rxqueue->xdp_rxq);
    xdp_prepare_buff(xdp, hard_start, skb_headroom(skb) - mac_len,
                skb_headlen(skb) + mac_len, true);

    // 记录原始数据信息
    orig_data_end = xdp->data_end;
    orig_data = xdp->data;
    eth = (struct ethhdr *)xdp->data;
    orig_host = ether_addr_equal_64bits(eth->h_dest, skb->dev->dev_addr);
    orig_bcast = is_multicast_ether_addr_64bits(eth->h_dest);
    orig_eth_type = eth->h_proto;
    
    // 运行XDP程序 
    act = bpf_prog_run_xdp(xdp_prog, xdp);

    // 检查是否调用`bpf_xdp_adjust_head`调整头部位置
    off = xdp->data - orig_data;
    if (off) {
        if (off > 0) __skb_pull(skb, off);
        else if (off < 0) __skb_push(skb, -off);

        skb->mac_header += off;
        skb_reset_network_header(skb);
    }

    // 检查是否调用`bpf_xdp_adjust_tail`调整尾部位置
    off = xdp->data_end - orig_data_end;
    if (off != 0) {
        skb_set_tail_pointer(skb, xdp->data_end - xdp->data);
        skb->len += off; /* positive on grow, negative on shrink */
    }

    // 检查是否调整eth内容
    eth = (struct ethhdr *)xdp->data;
    if ((orig_eth_type != eth->h_proto) ||
        (orig_host != ether_addr_equal_64bits(eth->h_dest, skb->dev->dev_addr)) ||
        (orig_bcast != is_multicast_ether_addr_64bits(eth->h_dest))) {
        __skb_push(skb, ETH_HLEN);
        skb->pkt_type = PACKET_HOST;
        skb->protocol = eth_type_trans(skb, skb->dev);
    }

    // REDIRECT/TX提供L2数据包，这里需要保证skb内容正确，由调用者执行重定向
    switch (act) {
    case XDP_REDIRECT:
    case XDP_TX:
        __skb_push(skb, mac_len);
        break;
    case XDP_PASS:
        metalen = xdp->data - xdp->data_meta;
        if (metalen)
            skb_metadata_set(skb, metalen);
        break;
    }
    return act;
}
```

#### 2 XDP_TX的过程

`netif_receive_generic_xdp` 函数返回为`XDP_TX`时，将网络数据包从同一个网卡上发送出去，`generic_xdp_tx` 实现这项功能，实现如下：

```C
// file: net/core/dev.c
void generic_xdp_tx(struct sk_buff *skb, struct bpf_prog *xdp_prog)
{
    struct net_device *dev = skb->dev;
    struct netdev_queue *txq;
    bool free_skb = true;
    int cpu, rc;

    // 选择TX发送队列
    txq = netdev_core_pick_tx(dev, skb, NULL);
    cpu = smp_processor_id();
    // 锁定TX队列
    HARD_TX_LOCK(dev, txq, cpu);
    if (!netif_xmit_frozen_or_drv_stopped(txq)) {
        // 发送skb
        rc = netdev_start_xmit(skb, dev, txq, 0);
        if (dev_xmit_complete(rc))
            free_skb = false;
    }
    HARD_TX_UNLOCK(dev, txq);
    if (free_skb) {
        // 发送失败时，记录日志信息、增加失败计数、释放skb
        trace_xdp_exception(dev, xdp_prog, XDP_TX);
        dev_core_stats_tx_dropped_inc(dev);
        kfree_skb(skb);
    }
}
```

`netdev_start_xmit` 调用网卡设备发送接口发送数据，如下：

```C
// file: include/linux/netdevice.h
static inline netdev_tx_t netdev_start_xmit(struct sk_buff *skb, 
            struct net_device *dev, struct netdev_queue *txq, bool more)
{
    const struct net_device_ops *ops = dev->netdev_ops;
    netdev_tx_t rc;
    rc = __netdev_start_xmit(ops, skb, dev, more);
    if (rc == NETDEV_TX_OK)
        txq_trans_update(txq);
    return rc;
}

// file: include/linux/netdevice.h
static inline netdev_tx_t __netdev_start_xmit(const struct net_device_ops *ops,
                struct sk_buff *skb, struct net_device *dev, bool more)
{
    __this_cpu_write(softnet_data.xmit.more, more);
    return ops->ndo_start_xmit(skb, dev);
}
```

#### 3 XDP_REDIRECT的过程

##### (1) 重定向接口

`netif_receive_generic_xdp` 函数返回为`XDP_REDIRECT`时，将网络数据包从其他网卡上发送出去，`xdp_do_generic_redirect` 实现这项功能，实现如下：

```C
// file: net/core/filter.c
int xdp_do_generic_redirect(struct net_device *dev, struct sk_buff *skb,
            struct xdp_buff *xdp, struct bpf_prog *xdp_prog)
{
    struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
    enum bpf_map_type map_type = ri->map_type;
    void *fwd = ri->tgt_value;
    u32 map_id = ri->map_id;
    int err;

    ri->map_id = 0; /* Valid map id idr range: [1,INT_MAX[ */
    ri->map_type = BPF_MAP_TYPE_UNSPEC;
    
    // 通过`ifindex`重定向
    if (map_type == BPF_MAP_TYPE_UNSPEC && map_id == INT_MAX) { ... }

    // map方式重定向
    return xdp_do_generic_redirect_map(dev, skb, xdp, xdp_prog, fwd, map_type, map_id);
err:
    _trace_xdp_redirect_err(dev, xdp_prog, ri->tgt_index, err);
    return err;
}
```

##### (2) 通过`ifindex`重定向

通过`ifindex`重定向时，获取`ifindex`对应的`dev`设备后，调用 `generic_xdp_tx` 函数发送数据。如下：

```C
// file: net/core/filter.c
int xdp_do_generic_redirect(struct net_device *dev, struct sk_buff *skb,
            struct xdp_buff *xdp, struct bpf_prog *xdp_prog)
{
    ...
    if (map_type == BPF_MAP_TYPE_UNSPEC && map_id == INT_MAX) {
        // 通过`ifindex`重定向时，获取`ifindex`对应的`dev`设备后，调用 `generic_xdp_tx` 函数
        fwd = dev_get_by_index_rcu(dev_net(dev), ri->tgt_index);
        if (unlikely(!fwd)) { err = -EINVAL; goto err; }

        // 检查转发skb长度
        err = xdp_ok_fwd_dev(fwd, skb->len);
        if (unlikely(err)) goto err;

        skb->dev = fwd;
        _trace_xdp_redirect(dev, xdp_prog, ri->tgt_index);
        generic_xdp_tx(skb, xdp_prog);
        return 0;
    }
    ...
}
```

##### (3) 通过`devmap`重定向

在 `xdp_do_generic_redirect_map()` 中通过`map`形式实现重定向，如下：

```C
// file: net/core/filter.c
static int xdp_do_generic_redirect_map(struct net_device *dev, struct sk_buff *skb, 
                struct xdp_buff *xdp, struct bpf_prog *xdp_prog, void *fwd,
                enum bpf_map_type map_type, u32 map_id)
{
    struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
    switch (map_type) {
    case BPF_MAP_TYPE_DEVMAP:
        fallthrough;
    case BPF_MAP_TYPE_DEVMAP_HASH:
        map = READ_ONCE(ri->map);
        if (unlikely(map)) {
            WRITE_ONCE(ri->map, NULL);
            err = dev_map_redirect_multi(dev, skb, xdp_prog, map, ri->flags & BPF_F_EXCLUDE_INGRESS);
        } else {
            err = dev_map_generic_redirect(fwd, skb, xdp_prog);
        }
        if (unlikely(err)) goto err;
        break;
    ...
    }
    ...
}
```

* 单个DEV的情况

map类型为`DEVMAP`或`DEVMAP_HASH`时，没有设置`ri->map`时，调用 `dev_map_generic_redirect()` 函数，如下：

```C
// file: kernel/bpf/devmap.c
int dev_map_generic_redirect(struct bpf_dtab_netdev *dst, struct sk_buff *skb, struct bpf_prog *xdp_prog)
{
    // 检查转发skb长度
    int err = xdp_ok_fwd_dev(dst->dev, skb->len);
    if (unlikely(err)) return err;

    // 运行XDP，只转发`XDP_PASS`
    if (dev_map_bpf_prog_run_skb(skb, dst) != XDP_PASS)
        return 0;

    skb->dev = dst->dev;
    generic_xdp_tx(skb, xdp_prog);
    return 0;
}
```

在获取设置的`dev`后，检查`skb`长度后，运行XDP程序检查是否为`XDP_PASS`, 在能够发送的情况下调用 `generic_xdp_tx()` 函数发送`skb`。

`dev_map_bpf_prog_run_skb` 函数通过XDP程序过滤转发的skb，如下：

```C
// file: kernel/bpf/devmap.c
static u32 dev_map_bpf_prog_run_skb(struct sk_buff *skb, struct bpf_dtab_netdev *dst)
{
    struct xdp_txq_info txq = { .dev = dst->dev };
    struct xdp_buff xdp;
    u32 act;

    // xdp程序不存在时，返回 PASS
    if (!dst->xdp_prog) return XDP_PASS;

    // 跳过mac信息
    __skb_pull(skb, skb->mac_len);
    xdp.txq = &txq;

    act = bpf_prog_run_generic_xdp(skb, &xdp, dst->xdp_prog);
    switch (act) {
    case XDP_PASS:
        // 重新设置mac信息
        __skb_push(skb, skb->mac_len);
        break;
    default:
        bpf_warn_invalid_xdp_action(NULL, dst->xdp_prog, act);
        fallthrough;
    case XDP_ABORTED:
        trace_xdp_exception(dst->dev, dst->xdp_prog, act);
        fallthrough;
    case XDP_DROP:
        // 其他结果，释放skb
        kfree_skb(skb);
        break;
    }
    return act;
}
```

* 多个DEV的情况

map类型为`DEVMAP`或`DEVMAP_HASH`时，设置`ri->map`时，调用 `dev_map_redirect_multi()` 函数，如下：

```C
// file: kernel/bpf/devmap.c
int dev_map_redirect_multi(struct net_device *dev, struct sk_buff *skb,
            struct bpf_prog *xdp_prog, struct bpf_map *map, bool exclude_ingress)
{
    struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
    struct bpf_dtab_netdev *dst, *last_dst = NULL;
    int excluded_devices[1+MAX_NEST_DEV];
    ...
    // 排除指定的`dev`
    if (exclude_ingress) {
        num_excluded = get_upper_ifindexes(dev, excluded_devices);
        excluded_devices[num_excluded++] = dev->ifindex;
    }
    if (map->map_type == BPF_MAP_TYPE_DEVMAP) {
        for (i = 0; i < map->max_entries; i++) {
            // 遍历所有map列表，获取目标
           dst = rcu_dereference_check(dtab->netdev_map[i], rcu_read_lock_bh_held());
            // dst不存在时 或者 目标网卡在排除列表中，进行下一项
            if (!dst) continue;
            if (is_ifindex_excluded(excluded_devices, num_excluded, dst->dev->ifindex))
                continue;
            // last_dst 最后一个添加到队列中
            if (!last_dst) { last_dst = dst; continue;}
            // 复制xdpf后，添加到队列中
            err = dev_map_redirect_clone(last_dst, skb, xdp_prog);
            if (err) return err; 
            last_dst = dst;
        }
    } else { /* BPF_MAP_TYPE_DEVMAP_HASH */
        for (i = 0; i < dtab->n_buckets; i++) {
            // 遍历hash列表
            head = dev_map_index_hash(dtab, i);
            // 遍历hash列表中的目标项
            hlist_for_each_entry_safe(dst, next, head, index_hlist) {
                // dst不存在时 或者 目标网卡在排除列表中，进行下一项
                if (!dst) continue;
                if (is_ifindex_excluded(excluded_devices, num_excluded, dst->dev->ifindex))
                    continue;
                // last_dst 最后一个添加到队列中
                if (!last_dst) { last_dst = dst; continue;}
                err = dev_map_redirect_clone(last_dst, skb, xdp_prog);
                if (err) return err; 
                last_dst = dst;
            }
        }
    }
    if (last_dst)
        // 重定向最后一项
        return dev_map_generic_redirect(last_dst, skb, xdp_prog);
    // 转发目标为空时，释放skb
    consume_skb(skb);
    return 0;
}
```

`dev_map_redirect_multi()` 函数遍历map中设置转发目标，在`dst`存在且不在排除列表中时，复制`skb`后以单个dev形式转发。转发目标为空时，释放`skb`。`dev_map_redirect_clone()` 函数复制`skb`后以单个dev形式转发，如下：

```C
// file: kernel/bpf/devmap.c
static int dev_map_redirect_clone(struct bpf_dtab_netdev *dst, 
        struct sk_buff *skb, struct bpf_prog *xdp_prog)
{
    struct sk_buff *nskb;
    // 复制skb
    nskb = skb_clone(skb, GFP_ATOMIC);
    if (!nskb) return -ENOMEM;
    // 单个dev转发，失败时释放skb
    err = dev_map_generic_redirect(dst, nskb, xdp_prog);
    if (unlikely(err)) { consume_skb(nskb);    return err; }

    return 0;
}
```

##### (4) 通过`cpumap`重定向

在 `xdp_do_generic_redirect_map()` 中通过`map`形式实现重定向，如下：

```C
// file: net/core/filter.c
static int xdp_do_generic_redirect_map(struct net_device *dev, struct sk_buff *skb, 
                struct xdp_buff *xdp, struct bpf_prog *xdp_prog, void *fwd,
                enum bpf_map_type map_type, u32 map_id)
{
    struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
    switch (map_type) {
    ...
    case BPF_MAP_TYPE_CPUMAP:
        err = cpu_map_generic_redirect(fwd, skb);
        if (unlikely(err)) goto err;
        break;
    ...
    }
    ...
}
```

`cpu_map_generic_redirect` 函数设置`skb`重定向信息，设置`skb`地址的bit0位置置1，通过bit0位置区分是`skb`还是`xdpf`。设置`skb`后，添加到`ptr_ring`中，之后唤起`kthread`。如下：

```C
// file: kernel/bpf/cpumap.c
int cpu_map_generic_redirect(struct bpf_cpu_map_entry *rcpu, struct sk_buff *skb)
{
    int ret;
    // 设置skb信息，设置重定向信息、将skb地址bit0值置1
    __skb_pull(skb, skb->mac_len);
    skb_set_redirected(skb, false);
    __ptr_set_bit(0, &skb);
    // 添加到`ptr_ring`中
    ret = ptr_ring_produce(rcpu->queue, skb);
    if (ret < 0) goto trace;
    // 唤起kthread
    wake_up_process(rcpu->kthread);
trace:
    trace_xdp_cpumap_enqueue(rcpu->map_id, !ret, !!ret, rcpu->cpu);
    return ret;
}
```

`ptr_ring_produce` 函数时对`__ptr_ring_produce` 函数的封装，如下：

```C
// file: kernel/bpf/cpumap.c
static inline int ptr_ring_produce(struct ptr_ring *r, void *ptr)
{
    int ret;
    spin_lock(&r->producer_lock);
    ret = __ptr_ring_produce(r, ptr);
    spin_unlock(&r->producer_lock);
    return ret;
}
```

创建 `rcpu->kthread` 的执行函数为 `cpu_map_kthread_run`。该函数的执行过程见上节描述。在将`skb`发送到内核协议栈之前运行`XDP`程序，`cpu_map_bpf_prog_run` 函数对重定向到改CPU的`xdpf`和`skb`检查，如下：

```C
// file: kernel/bpf/cpumap.c
static int cpu_map_bpf_prog_run(struct bpf_cpu_map_entry *rcpu, void **frames,
            int xdp_n, struct xdp_cpumap_stats *stats, struct list_head *list)
{
    int nframes;
    // 没有设置xdp程序时，返回
    if (!rcpu->prog) return xdp_n;

    rcu_read_lock_bh();
    // 运行XDP程序，检查xdpf
    nframes = cpu_map_bpf_prog_run_xdp(rcpu, frames, xdp_n, stats);
    if (stats->redirect)
        xdp_do_flush();

    if (unlikely(!list_empty(list)))
        // 运行XDP程序，检查skb
        cpu_map_bpf_prog_run_skb(rcpu, list, stats);

    rcu_read_unlock_bh(); /* resched point, may call do_softirq() */
    return nframes;
}
```

`cpu_map_bpf_prog_run_skb` 函数实现对重定向的`skb`进行过滤，如下：

```C
// file: kernel/bpf/cpumap.c
static void cpu_map_bpf_prog_run_skb(struct bpf_cpu_map_entry *rcpu,
                struct list_head *listp, struct xdp_cpumap_stats *stats)
{
    ...
    list_for_each_entry_safe(skb, tmp, listp, list) {
        //  运行XDP程序
        act = bpf_prog_run_generic_xdp(skb, &xdp, rcpu->prog);
        switch (act) {
        case XDP_PASS:
            break;
        case XDP_REDIRECT:
            // 重定向时，移除skb，再次重定向，失败时释放`skb`，成功时增加`redirect`计数
            skb_list_del_init(skb);
            err = xdp_do_generic_redirect(skb->dev, skb, &xdp, rcpu->prog);
            if (unlikely(err)) { kfree_skb(skb); stats->drop++; } 
            else { stats->redirect++; }
            return;
        default:
            bpf_warn_invalid_xdp_action(NULL, rcpu->prog, act);
            fallthrough;
        case XDP_ABORTED:
            trace_xdp_exception(skb->dev, rcpu->prog, act);
            fallthrough;
        case XDP_DROP:
            // 其他结果，移除skb，失败时释放`skb`，增加`drop`计数
            skb_list_del_init(skb);
            kfree_skb(skb);
            stats->drop++;
            return;
        }
    }
}
```

##### (5) 通过`xskmap`重定向

在 `xdp_do_generic_redirect_map()` 中通过`map`形式实现重定向，如下：

```C
// file: net/core/filter.c
static int xdp_do_generic_redirect_map(struct net_device *dev, struct sk_buff *skb, 
                struct xdp_buff *xdp, struct bpf_prog *xdp_prog, void *fwd,
                enum bpf_map_type map_type, u32 map_id)
{
    struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
    switch (map_type) {
    ...
    case BPF_MAP_TYPE_XSKMAP:
        err = xsk_generic_rcv(fwd, xdp);
        if (err) goto err;
        consume_skb(skb);
        break;
    ...
    }
    ...
}
```

`xsk_generic_rcv` 函数实现`xdp_buff`的转发，检查和接收`xdp_buff`后，刷新`xsk`，如下：

```C
// file: net/xdp/xsk.c
int xsk_generic_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
    int err;
    spin_lock_bh(&xs->rx_lock);

    // 确认`xsk`处于绑定状态，`xsk`和`xdp_buff`是同样设备和同一队列
    err = xsk_rcv_check(xs, xdp);
    if (!err) {
        // `xsk`接收数据
        err = __xsk_rcv(xs, xdp);
        // 刷新xsk，唤醒sock
        xsk_flush(xs);
    }
    spin_unlock_bh(&xs->rx_lock);
    return err;
}
```

## 5 总结

本文通过`xdp`示例程序分析了`XDP BPF`的内核实现过程。

XDP在Linux内核中实现高性能可编程数据包处理，在网络驱动程序收到数据包时进行处理，如：`XDP_DROP`告诉驱动程序在早期阶段丢弃数据包，以极低的成本执行任何类型的高效网络策略，在应对任何类型的`DDoS`攻击的情况下是理想的选择。

另一方面，XDP与Linux内核及其基础设施协同工作，通过BPF帮助程序中重用所有内核网络驱动程序、用户空间工具及其他可用的内核基础设施。

## 参考资料

* [Introduction to Netlink](https://kernel.org/doc/html/next/userspace-api/netlink/intro.html)
* [linux netlink详解1-netlink初始化](https://www.cnblogs.com/xinghuo123/p/13782009.html)
* [Linux 网络栈接收数据（RX）：原理及内核实现（2022）](https://arthurchiao.art/blog/linux-net-stack-implementation-rx-zh/)
* [XDP](https://docs.cilium.io/en/latest/bpf/progtypes/#xdp)
* [Cilium：BPF 和 XDP 参考指南（2021）](https://arthurchiao.art/blog/cilium-bpf-xdp-reference-guide-zh/)
* [AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
* [AF_XDP技术详解](https://rexrock.github.io/post/af_xdp1/)
* [XDP (eXpress Data Path)：在操作系统内核中实现快速、可编程包处理（ACM，2018）](https://arthurchiao.art/blog/xdp-paper-acm-2018-zh/)
* [深入理解 Cilium 的 eBPF 收发包路径（datapath）（KubeCon, 2019）](https://arthurchiao.art/blog/understanding-ebpf-datapath-in-cilium-zh/)