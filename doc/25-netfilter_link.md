# NETFILTER_LINK的内核实现

## 0 前言

在[IPTABLES_BPF内核实现](./16-iptables_bpf.md)中我们分析了通过`iptables`工具添加BPF程序到`netfilter`的实现过程，可以看到整个过程比较复杂。Linux v6.4 添加了 `BPF_PROG_TYPE_NETFILTER` 类型的BPF程序，通过Link的方式附加BPF程序到`netfilter`中，今天我们基于`netfilter_link_attach`程序分析`NETFILTER-LINK`的实现过程。

## 1 简介

内核协议栈内有包过滤(netfilter)功能，在内核协议中设置特定的hook，每个进入网络系统的包（接收或发送）在经过协议栈时都会触发这些hook，程序可以通过注册hook函数的方式在一些关键路径上处理网络流量。

## 2 `netfilter_link_attach`示例程序

### 2.1 BPF程序

BPF程序源码参见[netfilter_link_attach.bpf.c](../src/netfilter_link_attach.bpf.c)，主要内容如下：

```C
#define NF_ACCEPT 1

SEC("netfilter")
int nf_link_attach_test(struct bpf_nf_ctx *ctx)
{
    return NF_ACCEPT;
}
```

该程序包括一个BPF程序`nf_link_attach_test`，使用 `netfilter` 前缀。参数为`struct bpf_nf_ctx`结构，定义如下：

```C
//file: vmlinux.h
struct bpf_nf_ctx {
    const struct nf_hook_state *state;
    struct sk_buff *skb;
};
```

### 2.2 用户程序

用户程序源码参见[netfilter_link_attach.c](../src/netfilter_link_attach.c)，主要内容如下：

#### 1 附加BPF程序

```C
int main(int argc, char **argv)
{
    struct netfilter_link_attach_bpf *skel;
    LIBBPF_OPTS(bpf_netfilter_opts, opts);
    ...
    // 设置 libbpf 调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);
    // 打开并加载BPF程序
    skel = netfilter_link_attach_bpf__open_and_load();

    for (i = 0; i < ARRAY_SIZE(nf_hook_link_tests); i++) {
        struct bpf_link *link;
        // 设置附加选项
#define X(opts, m, i)	opts.m = nf_hook_link_tests[(i)].m
        X(opts, pf, i);
        X(opts, hooknum, i);
        X(opts, priority, i);
        X(opts, flags, i);
#undef X
        // 附加BPF程序
        link = bpf_program__attach_netfilter(prog, &opts);
        ...
    }
out:
    // 销毁BPF程序
    netfilter_link_attach_bpf__destroy(skel);
    return 0;
}
```

#### 2 读取数据过程

`nf_link_attach_test` BPF程序无输出数据，用户空间判断是否运行成功。

### 2.3 编译运行

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make netfilter_link_attach 
$ sudo ./netfilter_link_attach 
libbpf: loading object 'netfilter_link_attach_bpf' from buffer
...
main:PASS:netfilter_link_attach_bpf_open_and_load 0 nsec
main:PASS:attach program 0 nsec
....
libbpf: prog 'nf_link_attach_test': failed to attach to netfilter: Device or resource busy
main:PASS:attach program with same pf/hook/priority 0 nsec
main:PASS:link destroy 0 nsec
main:PASS:program reattach successful 0 nsec
main:PASS:link destroy 0 nsec
```

## 3 `netfilter`附加BPF的过程

`netfilter_link_attach.bpf.c`文件中BPF程序的SEC名称为 `SEC("netfilter")` , 在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("netfilter",    NETFILTER, BPF_NETFILTER, SEC_NONE),
    ...
};
```

`netfilter`前缀不支持自动附加，用户空间通过 `bpf_program__attach_netfilter` 函数进行附加，实现过程如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link *bpf_program__attach_netfilter(const struct bpf_program *prog,
                    const struct bpf_netfilter_opts *opts)
{
    LIBBPF_OPTS(bpf_link_create_opts, lopts);
    struct bpf_link *link;
    int prog_fd, link_fd;

    if (!OPTS_VALID(opts, bpf_netfilter_opts)) return libbpf_err_ptr(-EINVAL);
    // 获取`prog_fd`
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) { ... }

    // 创建link，设置分离接口
    link = calloc(1, sizeof(*link));
    if (!link) return libbpf_err_ptr(-ENOMEM);
    link->detach = &bpf_link__detach_fd;

    // 设置`netfilter`属性
    lopts.netfilter.pf = OPTS_GET(opts, pf, 0);
    lopts.netfilter.hooknum = OPTS_GET(opts, hooknum, 0);
    lopts.netfilter.priority = OPTS_GET(opts, priority, 0);
    lopts.netfilter.flags = OPTS_GET(opts, flags, 0);

    // 创建link
    link_fd = bpf_link_create(prog_fd, 0, BPF_NETFILTER, &lopts);
    if (link_fd < 0) { ... }
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
    case BPF_NETFILTER:
        // 设置`netfilter`属性
        attr.link_create.netfilter.pf = OPTS_GET(opts, netfilter.pf, 0);
        attr.link_create.netfilter.hooknum = OPTS_GET(opts, netfilter.hooknum, 0);
        attr.link_create.netfilter.priority = OPTS_GET(opts, netfilter.priority, 0);
        attr.link_create.netfilter.flags = OPTS_GET(opts, netfilter.flags, 0);
        if (!OPTS_ZEROED(opts, netfilter)) return libbpf_err(-EINVAL);
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

## 4 内核实现

### 4.1 BPF系统调用

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

#### 1 `BPF_LINK_CREATE`

`link_create` 在检查BFP程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 `netfilter` 设置的程序类型为`BPF_PROG_TYPE_NETFILTER`, 对应 `bpf_nf_link_attach` 处理函数。如下：

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
    case BPF_PROG_TYPE_NETFILTER:
        ret = bpf_nf_link_attach(attr, prog);
        break;
    ...
    }
    ...
}
```

#### 2 `bpf_nf_link_attach`

`bpf_nf_link_attach` 函数检查用户输入的参数信息，设置 `bpf_nf_link` 的信息后，注册 `nf_hook_ops` 接口。如下：

```C
// file: net/netfilter/nf_bpf_link.c
int bpf_nf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    struct net *net = current->nsproxy->net_ns;
    struct bpf_link_primer link_primer;
    struct bpf_nf_link *link;
    int err;
    // 不支持`flags`设置
    if (attr->link_create.flags) return -EINVAL;
    // 检查用户空间`attr`属性设置
    err = bpf_nf_check_pf_and_hooks(attr);
    if (err) return err;

    // 创建`link`
    link = kzalloc(sizeof(*link), GFP_USER);
    if (!link) return -ENOMEM;
    // 设置`link`属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_NETFILTER, &bpf_nf_link_lops, prog);

    // `hook_ops`属性设置，BPF程序运行属性设置
    link->hook_ops.hook = nf_hook_run_bpf;
    link->hook_ops.hook_ops_type = NF_HOOK_OP_BPF;
    link->hook_ops.priv = prog;
    // `hook_ops`属性设置，hook属性设置
    link->hook_ops.pf = attr->link_create.netfilter.pf;
    link->hook_ops.priority = attr->link_create.netfilter.priority;
    link->hook_ops.hooknum = attr->link_create.netfilter.hooknum;
    // `link`属性设置
    link->net = net;
    link->dead = false;
    link->defrag_hook = NULL;

    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    if (err) { ... }

    if (attr->link_create.netfilter.flags & BPF_F_NETFILTER_IP_DEFRAG) {
        // 设置`IP_DEFRAG`标记时，启用IP分片
        err = bpf_nf_enable_defrag(link);
        if (err) { bpf_link_cleanup(&link_primer); return err; }
    }
    // 注册net_hooks
    err = nf_register_net_hook(net, &link->hook_ops);
    if (err) {
        // 失败时的清理
        bpf_nf_disable_defrag(link);
        bpf_link_cleanup(&link_primer);
        return err;
    }
    // fd 和 file 进行关联
    return bpf_link_settle(&link_primer);
}
```

`bpf_nf_check_pf_and_hooks`函数检查用户空间设置的`nf hook`点，如下：

```C
// file: net/netfilter/nf_bpf_link.c
static int bpf_nf_check_pf_and_hooks(const union bpf_attr *attr)
{
    int prio;
    // 目前只支持IPV4，IPV6协议家族
    switch (attr->link_create.netfilter.pf) {
    case NFPROTO_IPV4:
    case NFPROTO_IPV6:
        if (attr->link_create.netfilter.hooknum >= NF_INET_NUMHOOKS) return -EPROTO;
        break;
    default:
        return -EAFNOSUPPORT;
    }
    // 只支持`IP_DEFRAG`标记设置
    if (attr->link_create.netfilter.flags & ~BPF_F_NETFILTER_IP_DEFRAG)
        return -EOPNOTSUPP;
    // 优先级检查，确保链接确认(`conntrack confirm`)在最后
    prio = attr->link_create.netfilter.priority;
    if (prio == NF_IP_PRI_FIRST) return -ERANGE;  /* sabotage_in and other warts */
    else if (prio == NF_IP_PRI_LAST) return -ERANGE;  /* e.g. conntrack confirm */
    else if ((attr->link_create.netfilter.flags & BPF_F_NETFILTER_IP_DEFRAG) &&
        prio <= NF_IP_PRI_CONNTRACK_DEFRAG)
        return -ERANGE;  /* cannot use defrag if prog runs before nf_defrag */
    return 0;
}
```

#### 3 注册`nf_hook`

`nf_register_net_hook`函数实现`nfhook`的注册，如下：

```C
// file: net/netfilter/core.c
int nf_register_net_hook(struct net *net, const struct nf_hook_ops *reg)
{
    int err;
    if (reg->pf == NFPROTO_INET) {
        if (reg->hooknum == NF_INET_INGRESS) {
            err = __nf_register_net_hook(net, NFPROTO_INET, reg);
            if (err < 0) return err;
        } else {
            // NFPROTO_INET时，注册ipv4和ipv6
            err = __nf_register_net_hook(net, NFPROTO_IPV4, reg);
            if (err < 0) return err;
            err = __nf_register_net_hook(net, NFPROTO_IPV6, reg);
            if (err < 0) {
                __nf_unregister_net_hook(net, NFPROTO_IPV4, reg);
                return err;
            }
        }
    } else {
        // 注册其他协议的hook
        err = __nf_register_net_hook(net, reg->pf, reg);
        if (err < 0) return err;
    }
    return 0;
}
```

`__nf_register_net_hook`函数实现`nfhook`的注册，如下：

```C
// file: net/netfilter/core.c
static int __nf_register_net_hook(struct net *net, int pf, const struct nf_hook_ops *reg)
{
    struct nf_hook_entries *p, *new_hooks;
    struct nf_hook_entries __rcu **pp;
    int err;

    // NETDEV和INET两种协议支持的hook检查，
    switch (pf) {
    case NFPROTO_NETDEV: ... break;
    case NFPROTO_INET: ... break;
    }

    // 获取hooks列表指针
    pp = nf_hook_entry_head(net, pf, reg->hooknum, reg->dev);
    if (!pp) return -EINVAL;

    mutex_lock(&nf_hook_mutex);
    p = nf_entry_dereference(*pp);
    // 创建新的内存空间，复制旧的hooks后，添加新的hook
    new_hooks = nf_hook_entries_grow(p, reg);

    // new_hooks正常，则修改hooks列表地址指向位置，完成hooks的修改
    if (!IS_ERR(new_hooks)) {
        // 验证hooks，调整优先级
        hooks_validate(new_hooks);
        // 修改hooks列表地址指向位置，完成hooks的修改
        rcu_assign_pointer(*pp, new_hooks);
    }
    mutex_unlock(&nf_hook_mutex);
    // new_hooks有错误，则返回错误码
    if (IS_ERR(new_hooks)) return PTR_ERR(new_hooks);

    // ingress/egress hook时，增加队列长度
    if (nf_ingress_hook(reg, pf)) net_inc_ingress_queue();
    if (nf_egress_hook(reg, pf)) net_inc_egress_queue();
    // 增加hooks的static_key计数
    nf_static_key_inc(reg, pf);

    // 释放旧的hooks
    nf_hook_entries_free(p);
    return 0;
}
```

`nf_hook_entry_head`函数获取对应协议和hooknum的hooks列表指针，如下：

```C
// file: net/netfilter/core.c
static struct nf_hook_entries __rcu **
nf_hook_entry_head(struct net *net, int pf, unsigned int hooknum, struct net_device *dev)
{
    switch (pf) {
    case NFPROTO_NETDEV: break;
    case NFPROTO_ARP:
        // 获取net->nf.hooks_arp[hooknum]
        if (WARN_ON_ONCE(ARRAY_SIZE(net->nf.hooks_arp) <= hooknum)) return NULL;
        return net->nf.hooks_arp + hooknum;
    case NFPROTO_BRIDGE:
        // 获取net->nf.hooks_bridge[hooknum]
        if (WARN_ON_ONCE(ARRAY_SIZE(net->nf.hooks_bridge) <= hooknum)) return NULL;
        return net->nf.hooks_bridge + hooknum;
    case NFPROTO_INET:
        // NFPROTO_INET::NF_INET_INGRESS对应网卡设备的`dev->nf_hooks_ingress`
        if (WARN_ON_ONCE(hooknum != NF_INET_INGRESS)) return NULL;
        if (!dev || dev_net(dev) != net) { WARN_ON_ONCE(1); return NULL; }
        return &dev->nf_hooks_ingress;
    case NFPROTO_IPV4:
        // 获取net->nf.hooks_ipv4[hooknum]
        if (WARN_ON_ONCE(ARRAY_SIZE(net->nf.hooks_ipv4) <= hooknum)) return NULL;
        return net->nf.hooks_ipv4 + hooknum;
    case NFPROTO_IPV6:
        // 获取net->nf.hooks_ipv6[hooknum]
        if (WARN_ON_ONCE(ARRAY_SIZE(net->nf.hooks_ipv6) <= hooknum)) return NULL;
        return net->nf.hooks_ipv6 + hooknum;
    default:
        // 默认返回NULL
        WARN_ON_ONCE(1); return NULL;
    }
    // NFPROTO_NETDEV:NF_NETDEV_IN[E]GRESS，对应网卡设备的`dev->nf_hooks_in[e]gress`
    if (hooknum == NF_NETDEV_INGRESS) {
        if (dev && dev_net(dev) == net) return &dev->nf_hooks_ingress;
    }
    if (hooknum == NF_NETDEV_EGRESS) {
        if (dev && dev_net(dev) == net) return &dev->nf_hooks_egress;
    }
    WARN_ON_ONCE(1);
    return NULL;
}
```

`nf_hook_entries_grow`函数实现hooks表的动态扩容，实现如下：

```C
// file: net/netfilter/core.c
static struct nf_hook_entries *nf_hook_entries_grow(const struct nf_hook_entries *old, const struct nf_hook_ops *reg)
{
    unsigned int i, alloc_entries, nhooks, old_entries;
    struct nf_hook_ops **orig_ops = NULL;
    struct nf_hook_ops **new_ops;
    struct nf_hook_entries *new;
    bool inserted = false;

    // 默认增加一个hooks
    alloc_entries = 1;
    old_entries = old ? old->num_hook_entries : 0;

    if (old) {
        // 获取旧的hooks中有效的hook数量
        orig_ops = nf_hook_entries_get_hook_ops(old);
        for (i = 0; i < old_entries; i++) {
            // dummy_ops表示删除的hook
            if (orig_ops[i] != &dummy_ops)
                alloc_entries++;
            // BPF hook 设置不同的优先级，主要为了避免两个BPF程序间的排序问题
            if (reg->priority == orig_ops[i]->priority &&
                    reg->hook_ops_type == NF_HOOK_OP_BPF)
            return ERR_PTR(-EBUSY);
        }
    }
    // 每个family/hooknum最多支持1024个hook
    if (alloc_entries > MAX_HOOK_COUNT) return ERR_PTR(-E2BIG);

    // 创建新的hooks表
    new = allocate_hook_entries_size(alloc_entries);
    if (!new) return ERR_PTR(-ENOMEM);
    // 获取hook_ops位置
    new_ops = nf_hook_entries_get_hook_ops(new);

    i = 0;
    nhooks = 0;
    while (i < old_entries) {
        // 跳过删除的hook
        if (orig_ops[i] == &dummy_ops) { ++i; continue; }

        // 从旧表中复制hook_ops，注销的hook按照优先级插入到列表中
        if (inserted || reg->priority > orig_ops[i]->priority) {
            new_ops[nhooks] = (void *)orig_ops[i];
            new->hooks[nhooks] = old->hooks[i];
            i++;
        } else {
            new_ops[nhooks] = (void *)reg;
            new->hooks[nhooks].hook = reg->hook;
            new->hooks[nhooks].priv = reg->priv;
            inserted = true;
        }
        nhooks++;
    }
    // 默认情况，注册的hook没有添加时，添加到最后
    if (!inserted) {
        new_ops[nhooks] = (void *)reg;
        new->hooks[nhooks].hook = reg->hook;
        new->hooks[nhooks].priv = reg->priv;
    }
    return new;
}
```

`allocate_hook_entries_size`函数分配hooks列表需要的内存，`nf_hook_entries`按照 `nf_hook_entries | nf_hook_entry * num | nf_hook_ops * num | nf_hook_entries_rcu_head` 的内存分布注册hook列表。如下：

```C
// file: net/netfilter/core.c
static struct nf_hook_entries *allocate_hook_entries_size(u16 num)
{
    struct nf_hook_entries *e;
    size_t alloc = sizeof(*e) +
                sizeof(struct nf_hook_entry) * num +
                sizeof(struct nf_hook_ops *) * num +
                sizeof(struct nf_hook_entries_rcu_head);
    // num为0时，直接返回
    if (num == 0) return NULL;
    // 分配需要的内存空间，设置hooks的数量
    e = kvzalloc(alloc, GFP_KERNEL_ACCOUNT);
    if (e) e->num_hook_entries = num;
    return e;
}
```

### 4.2 注销BPF程序的过程

#### 1 `bpf_nf_link_lops`接口

在`bpf_nf_link_attach`函数附加netfilter过程中，设置了用户空间操作`bpf_link`的文件接口，如下：

```C
// file: net/netfilter/nf_bpf_link.c
int bpf_nf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_NETFILTER, &bpf_nf_link_lops, prog);
    ...
    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    ...
}
```

`bpf_nf_link_lops` 是设置的文件操作接口，定义如下：

```C
// file: net/netfilter/nf_bpf_link.c
static const struct bpf_link_ops bpf_nf_link_lops = {
    .release = bpf_nf_link_release,
    .dealloc = bpf_nf_link_dealloc,
    .detach = bpf_nf_link_detach,
    .show_fdinfo = bpf_nf_link_show_info,
    .fill_link_info = bpf_nf_link_fill_link_info,
    .update_prog = bpf_nf_link_update,
};
```

#### 2 更新bpf程序

`.update_prog`更新接口，更新当前设置的bpf程序，设置为`bpf_nf_link_update`, 目前不支持更新。实现如下:

```C
// file: net/netfilter/nf_bpf_link.c
static int bpf_nf_link_update(struct bpf_link *link, struct bpf_prog *new_prog, struct bpf_prog *old_prog)
{
    return -EOPNOTSUPP;
}
```

#### 3 注销接口

`.release`接口释放`bpf_link`关联的程序。`bpf_nf_link_release`注销`netfilter`，如下：

```C
// file: net/netfilter/nf_bpf_link.c
static void bpf_nf_link_release(struct bpf_link *link)
{
    struct bpf_nf_link *nf_link = container_of(link, struct bpf_nf_link, link);
    if (nf_link->dead) return;

    // 确保不会重复释放
    if (!cmpxchg(&nf_link->dead, 0, 1)) {
        // 注销`nfhook`
        nf_unregister_net_hook(nf_link->net, &nf_link->hook_ops);
        // 禁用IP分片
        bpf_nf_disable_defrag(nf_link);
    }
}
```

`nf_unregister_net_hook` 函数注销`nfhook`，如下：

```C
// file: net/netfilter/core.c
void nf_unregister_net_hook(struct net *net, const struct nf_hook_ops *reg)
{
    if (reg->pf == NFPROTO_INET) {
        if (reg->hooknum == NF_INET_INGRESS) {
            __nf_unregister_net_hook(net, NFPROTO_INET, reg);
        } else {
            __nf_unregister_net_hook(net, NFPROTO_IPV4, reg);
            __nf_unregister_net_hook(net, NFPROTO_IPV6, reg);
        }
    } else {
        __nf_unregister_net_hook(net, reg->pf, reg);
    }
}
```

`__nf_unregister_net_hook`函数实现单个hook的注销，如下：

```C
// file: net/netfilter/core.c
static void __nf_unregister_net_hook(struct net *net, int pf, const struct nf_hook_ops *reg)
{
    struct nf_hook_entries __rcu **pp;
    struct nf_hook_entries *p;

    // 获取hooks列表指针
    pp = nf_hook_entry_head(net, pf, reg->hooknum, reg->dev);
    if (!pp) return;

    mutex_lock(&nf_hook_mutex);
    p = nf_entry_dereference(*pp);
    // 检查指向的hook是否存在，不存在时返回
    if (WARN_ON_ONCE(!p)) { mutex_unlock(&nf_hook_mutex); return; }

    // 删除hook，将对应的hook_ops标记为`dummy_ops`
    if (nf_remove_net_hook(p, reg)) {
        // 删除成功后，减少hooks的static_key计数
        if (nf_ingress_hook(reg, pf)) net_dec_ingress_queue();
        if (nf_egress_hook(reg, pf)) net_dec_egress_queue();
        nf_static_key_dec(reg, pf);
    } else {
        WARN_ONCE(1, "hook not found, pf %d num %d", pf, reg->hooknum);
    }
    // 收缩hooks列表，返回旧的hooks列表
    p = __nf_hook_entries_try_shrink(p, pp);
    mutex_unlock(&nf_hook_mutex);
    if (!p) return;

    // nf_queue_handler删除nf_hook
    nf_queue_nf_hook_drop(net);
    // 释放旧的hooks列表
    nf_hook_entries_free(p);
}
```

`nf_remove_net_hook`函数删除指定hook，将对应的hook_ops设置为`dummy_ops`，如下：

```C
// file: net/netfilter/core.c
static bool nf_remove_net_hook(struct nf_hook_entries *old, const struct nf_hook_ops *unreg)
{
    struct nf_hook_ops **orig_ops;
    unsigned int i;
    // 获取hook_ops列表指针
    orig_ops = nf_hook_entries_get_hook_ops(old);
    for (i = 0; i < old->num_hook_entries; i++) {
        if (orig_ops[i] != unreg) continue;
        // 确定删除的hook后，设置hook接口为accept_all，表示所有数据包都通过
        WRITE_ONCE(old->hooks[i].hook, accept_all);
        // 设置hook_ops为`dummy_ops`，表示删除成功
        WRITE_ONCE(orig_ops[i], (void *)&dummy_ops);
        return true;
    }
    return false;
}
```

`__nf_hook_entries_try_shrink`函数重新计算hooks列表需要的内存空间，释放已删除的hook，如下：

```C
// file: net/netfilter/core.c
static void *__nf_hook_entries_try_shrink(struct nf_hook_entries *old, struct nf_hook_entries __rcu **pp)
{
    unsigned int i, j, skip = 0, hook_entries;
    struct nf_hook_entries *new = NULL;
    struct nf_hook_ops **orig_ops;
    struct nf_hook_ops **new_ops;

    if (WARN_ON_ONCE(!old)) return NULL;
    // 计算已经删除的hook个数
    orig_ops = nf_hook_entries_get_hook_ops(old);
    for (i = 0; i < old->num_hook_entries; i++) {
        if (orig_ops[i] == &dummy_ops) skip++;
    }
    // 所有hook都删除时，进行设置操作，此时设置为NULL
    hook_entries = old->num_hook_entries;
    if (skip == hook_entries) goto out_assign;

    // 不存在删除的，直接返回
    if (skip == 0) return NULL;
    // 重新计算hook数量后，分配内存空间
    hook_entries -= skip;
    new = allocate_hook_entries_size(hook_entries);
    if (!new) return NULL;

    // 复制旧的hook到新的hooks列表中，跳过`dummy_ops`
    new_ops = nf_hook_entries_get_hook_ops(new);
    for (i = 0, j = 0; i < old->num_hook_entries; i++) {
        if (orig_ops[i] == &dummy_ops)
            continue;
        // 复制hook和hook_ops
        new->hooks[j] = old->hooks[i];
        new_ops[j] = (void *)orig_ops[i];
        j++;
    }
    // 验证hooks列表
    hooks_validate(new);
out_assign:
    // 将hooks列表地址指向新的hooks列表，完成hooks的修改
    rcu_assign_pointer(*pp, new);
    return old;
}
```

`nf_hook_entries_free`函数释放hooks列表，如下：

```C
// file: net/netfilter/core.c
static void nf_hook_entries_free(struct nf_hook_entries *e)
{
    struct nf_hook_entries_rcu_head *head;
    struct nf_hook_ops **ops;
    unsigned int num;
    if (!e) return;

    // 获取hook_ops
    num = e->num_hook_entries;
    ops = nf_hook_entries_get_hook_ops(e);
    // 最后一个hook_ops后面是`nf_hook_entries_rcu_head`
    head = (void *)&ops[num];
    head->allocation = e;
    // rcu释放hook列表
    call_rcu(&head->head, __nf_hook_entries_free);
}
```

#### 4 分离接口

`.detach`接口分离`bpf_link`关联的程序。`bpf_nf_link_detach`释放`nf_link`，如下：

```C
// file: net/netfilter/nf_bpf_link.c
static int bpf_nf_link_detach(struct bpf_link *link)
{
    bpf_nf_link_release(link);
    return 0;
}
```

#### 5 释放接口

`.dealloc`接口释放`bpf_link`。`bpf_nf_link_dealloc`释放`nf_link`，如下：

```C
// file: net/netfilter/nf_bpf_link.c
static void bpf_nf_link_dealloc(struct bpf_link *link)
{
    struct bpf_nf_link *nf_link = container_of(link, struct bpf_nf_link, link);
    kfree(nf_link);
}
```

### 4.3 BPF调用过程

#### 1 `nf_hook`接口

在`netfilter`框架中，`NF_HOOK`函数是整个框架的核心，它负责将数据包送入`hook`点后执行相应的过滤。在Linux内核中我们可以通过 `NF_HOOK`, `NF_HOOK_COND` 和 `NF_HOOK_LIST` 宏进行HOOK点处理。以`NF_HOOK`宏为例，其定义如下：

```C
// file：include/linux/netfilter.h
static inline int NF_HOOK(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk, struct sk_buff *skb,
    struct net_device *in, struct net_device *out, int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
    // 执行nf_hook函数
    int ret = nf_hook(pf, hook, net, sk, skb, in, out, okfn);
    if (ret == 1)
        // 返回值为1时，表示允许网络数据包通过
        ret = okfn(net, sk, skb);
    return ret;
}
```

`nf_hook`函数是核心的处理过程，实现如下：

```C
// file：include/linux/netfilter.h
static inline int nf_hook(u_int8_t pf, unsigned int hook, struct net *net, struct sock *sk, 
            struct sk_buff *skb, struct net_device *indev, struct net_device *outdev,
            int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
    struct nf_hook_entries *hook_head = NULL;
    int ret = 1;

    // static_key检查，
    if (__builtin_constant_p(pf) && __builtin_constant_p(hook) &&
        !static_key_false(&nf_hooks_needed[pf][hook]))
        return 1;

    rcu_read_lock();
    // 获取hook点列表，根据不同的协议和hook点获取
    switch (pf) {
    case NFPROTO_IPV4: hook_head = rcu_dereference(net->nf.hooks_ipv4[hook]); break;
    case NFPROTO_IPV6: hook_head = rcu_dereference(net->nf.hooks_ipv6[hook]); break;
    case NFPROTO_ARP: hook_head = rcu_dereference(net->nf.hooks_arp[hook]); break;
    case NFPROTO_BRIDGE: hook_head = rcu_dereference(net->nf.hooks_bridge[hook]); break;
    default: WARN_ON_ONCE(1); break;
    }

    // hook点列表存在时
    if (hook_head) {
        struct nf_hook_state state;
        // 状态初始化
        nf_hook_state_init(&state, hook, pf, indev, outdev, sk, net, okfn);
        // 进行hook处理
        ret = nf_hook_slow(skb, &state, hook_head, 0);
    }
    rcu_read_unlock();
    return ret;
}
```

`nf_hook_slow`函数遍历hooks列表，逐项进行判决，根据判决结果进行不同的处理。如下：

```C
// file: net/netfilter/core.c
int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state,
    const struct nf_hook_entries *e, unsigned int s)
{
    unsigned int verdict;
    int ret;
    for (; s < e->num_hook_entries; s++) {
        // 进行防火墙规则的执行
        verdict = nf_hook_entry_hookfn(&e->hooks[s], skb, state);
        switch (verdict & NF_VERDICT_MASK) {
        case NF_ACCEPT: 
            // ACCEPT表示skb通过
            break;
        case NF_DROP:
            // DROP表示丢弃skb
            kfree_skb_reason(skb, SKB_DROP_REASON_NETFILTER_DROP);
            // 转换判决结果
            ret = NF_DROP_GETERR(verdict);
            if (ret == 0) ret = -EPERM;
            return ret;
        case NF_QUEUE:
            // QUEUE处理
            ret = nf_queue(skb, state, s, verdict);
            if (ret == 1) continue;
            return ret;
        case NF_STOLEN:
            // 丢弃处理，skb修改后发送，丢弃原始skb
            return NF_DROP_GETERR(verdict);
        default:
            // 默认处理规则
            WARN_ON_ONCE(1);
            return 0;
        }
    }
    return 1;
}
```

`nf_hook_entry_hookfn`函数进行防火墙规则的执行，如下：

```C
// file: include/linux/netfilter.h
static inline int nf_hook_entry_hookfn(const struct nf_hook_entry *entry, 
                    struct sk_buff *skb, struct nf_hook_state *state)
{   
    // 调用hook接口
    return entry->hook(entry->priv, skb, state);
}
```

#### 2 `nf_hook_run_bpf`

在通过`nf_register_net_hook`函数注册`nf_hook_ops`时，设置`nf_hook_entry->hook`接口为`nf_hook_ops->hook`，如下：

```C
// file: net/netfilter/core.c
static struct nf_hook_entries * 
    nf_hook_entries_grow(const struct nf_hook_entries *old, const struct nf_hook_ops *reg)
{
    ...
    struct nf_hook_entries *new;
    ...
    // 设置新的hook项
    if (!inserted) {
        new_ops[nhooks] = (void *)reg;
        new->hooks[nhooks].hook = reg->hook;
        new->hooks[nhooks].priv = reg->priv;
    }
    return new;
}
```

在注册`nf-hook`时设置的操作接口为`nf_hook_run_bpf`, 如下：

```C
// file: net/netfilter/nf_bpf_link.c
int bpf_nf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    link->hook_ops.hook = nf_hook_run_bpf;
    link->hook_ops.hook_ops_type = NF_HOOK_OP_BPF;
    link->hook_ops.priv = prog;
    ...
}
```

`nf_hook_run_bpf`函数是`netfilter link`的防火墙规则执行函数，实现如下：

```C
// file: net/netfilter/nf_bpf_link.c
static unsigned int nf_hook_run_bpf(void *bpf_prog, struct sk_buff *skb, const struct nf_hook_state *s)
{
    const struct bpf_prog *prog = bpf_prog;
    // 设置`nf_ctx`上下文
    struct bpf_nf_ctx ctx = { .state = s, .skb = skb, };
    // 运行BPF程序
    return bpf_prog_run(prog, &ctx);
}
```

## 5 总结

本文通过`netfilter_link_attach`示例程序分析了`netfilter_link`的内核实现过程。

`netfilter_link` 通过Link的方式添加BPF程序到netfilter中，而不用借助`iptables`工具，更加方便的netfilter进行控制。

## 参考资料

* [bpf: add netfilter program type](https://lwn.net/Articles/929711/)
* [bpf, netfilter: minimal support for bpf prog](https://lwn.net/Articles/922663/)
* [Support defragmenting IPv(4|6) packets in BPF](https://lwn.net/Articles/938065/)
