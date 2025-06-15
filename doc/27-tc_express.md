# TC EXPRESS的内核实现

## 0 前言

在[TC的内核实现](./14-tc.md)，我们分析了在INGRESS和EGRESS路径上对网络数据包流量控制(TC)的实现过程，TC通过`netlink`的方式附加到内核中，今天我们借助`tcx`示例程序分析通过Link方式附加TC的实现过程。

## 1 简介

TC(traffic control，流量控制)运行在网络栈中的`hook`点中，在INGRESS和EGRESS路径上对每个进入或离开的网络数据包进行控制，具有完全可观测性，在容器安全策略、转发和负载均衡、流量采集监测、网络数据包调度器预处理等方面广泛引用。

## 2 `tcx`示例程序

### 2.1 BPF程序

BPF程序源码参见[tcx.bpf.c](../src/tcx.bpf.c)，主要内容如下：

```C
SEC("tcx/ingress")
int tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TCX_PASS;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TCX_PASS;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TCX_PASS;

    bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TCX_PASS;
}
```

该程序包含一个BPF程序`tc_ingress`，使用`tcx/ingress`前缀。参数为`__sk_buff`类型。

### 2.2 用户程序

用户程序源码参见[tcx.c](../src/tcx.c)，主要内容如下：

#### 1 附加BPF程序

```C
int main(int argc, char **argv)
{
    LIBBPF_OPTS(bpf_tcx_opts, optl);
    struct tcx_bpf *skel;
    int err;

    // 设置 libbpf 调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);

    // 打开并加载BPF程序
    skel = tcx_bpf__open_and_load();
    if (!skel) { ... }
    // 在`loopback`上附加`tcx`
    skel->links.tc_ingress = bpf_program__attach_tcx(skel->progs.tc_ingress, LO_IFINDEX, &optl);
    if ((err = libbpf_get_error(skel->links.tc_ingress)) != 0) { ... }
    // 设置`INT`处理函数
    if (signal(SIGINT, sig_int) == SIG_ERR) { ... }

    while (!exiting) {
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    // 销毁BPF程序
    tcx_bpf__destroy(skel);
    return -err;
}
```

#### 2 读取数据过程

`tc_ingress` BPF程序获取网络包的长度和TTL后，通过 `bpf_printk` 输出到 `/sys/kernel/debug/tracing/trace_pipe` 文件中。

### 2.3 编译运行

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make tcx 
$ sudo ./tcx 
libbpf: loading object 'tcx_bpf' from buffer
libbpf: elf: section(3) tcx/ingress, size 144, link 0, flags 6, type=1
...
libbpf: map 'tcx_bpf.rodata': created successfully, fd=3
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF program.
```

在另一个终端中运行，如下：

```bash
$ $ sudo cat /sys/kernel/debug/tracing/trace_pipe
 irq/178-rtw89_p-914     [000] ..s2. 561255.862417: bpf_trace_printk: Got IP packet: tot_len: 2908, ttl: 52
 irq/178-rtw89_p-914     [000] ..s2. 561255.863041: bpf_trace_printk: Got IP packet: tot_len: 1480, ttl: 52
 ...
 ```

## 3 tcx附加BPF的过程

`tcx.bpf.c`文件中BPF程序的SEC名称为 `SEC("tcx/ingress")` , 在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("tc/ingress",   SCHED_CLS, BPF_TCX_INGRESS, SEC_NONE), /* alias for tcx */
    SEC_DEF("tc/egress",    SCHED_CLS, BPF_TCX_EGRESS, SEC_NONE),  /* alias for tcx */
    SEC_DEF("tcx/ingress",  SCHED_CLS, BPF_TCX_INGRESS, SEC_NONE),
    SEC_DEF("tcx/egress",   SCHED_CLS, BPF_TCX_EGRESS, SEC_NONE),
    ...
};
```

`tc[x]/ingress` 和 `tc[x]/egress` 前缀不支持自动附加。用户通过 `bpf_program__attach_tcx` 函数手动附加。

`bpf_program__attach_tcx`函数检查输入的选项后，使用`bpf_link`方式加载TC类型的BPF程序，如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link * bpf_program__attach_tcx(const struct bpf_program *prog, int ifindex,
        const struct bpf_tcx_opts *opts)
{
    LIBBPF_OPTS(bpf_link_create_opts, link_create_opts);
    __u32 relative_id;
    int relative_fd;
    // 检查`opts`选项
    if (!OPTS_VALID(opts, bpf_tcx_opts)) return libbpf_err_ptr(-EINVAL);
    // 获取相对id和相对fd
    relative_id = OPTS_GET(opts, relative_id, 0);
    relative_fd = OPTS_GET(opts, relative_fd, 0);

    // 检查网卡索引是否正确
    if (!ifindex) { ... }
    // 不能同时设置相对id和相对fd
    if (relative_fd && relative_id) { ... }
    // 设置`tcx`属性
    link_create_opts.tcx.expected_revision = OPTS_GET(opts, expected_revision, 0);
    link_create_opts.tcx.relative_fd = relative_fd;
    link_create_opts.tcx.relative_id = relative_id;
    link_create_opts.flags = OPTS_GET(opts, flags, 0);

    // target_fd/ifindex 在 LINK_CREATE 中是同一个字段
    return bpf_program_attach_fd(prog, ifindex, "tcx", &link_create_opts);
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
    case BPF_TCX_INGRESS:
    case BPF_TCX_EGRESS:
        // 设置`tcx`属性
        relative_fd = OPTS_GET(opts, tcx.relative_fd, 0);
        relative_id = OPTS_GET(opts, tcx.relative_id, 0);
        if (relative_fd && relative_id) return libbpf_err(-EINVAL);
        if (relative_id) {
            attr.link_create.tcx.relative_id = relative_id;
            attr.link_create.flags |= BPF_F_ID;
        } else {
            attr.link_create.tcx.relative_fd = relative_fd;
        }
        attr.link_create.tcx.expected_revision = OPTS_GET(opts, tcx.expected_revision, 0);
        if (!OPTS_ZEROED(opts, tcx)) return libbpf_err(-EINVAL);
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

### 4.1 注册BPF程序

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

`link_create` 在检查BFP程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 `tc[x]/ingress` 和 `tc[x]/egress` 前缀设置的程序类型为`BPF_PROG_TYPE_SCHED_CLS`, 附加类型为`BPF_TCX_INGRESS/BPF_TCX_EGRESS`, 对应 `tcx_link_attach` 处理函数。如下：

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
            // `tcx`
            ret = tcx_link_attach(attr, prog); 
        else
            ret = netkit_link_attach(attr, prog);
        break;
    ...
    }
    ...
}
```

#### 3 `tcx_link_attach`

`tcx_link_attach` 函数检查用户输入的参数信息，获取设置的网卡设备后，初始化`tcx_link` 的信息后，附加`tcx`。如下：

```C
// file: kernel/bpf/tcx.c
int tcx_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    // 获取当前的网络命名空间
    struct net *net = current->nsproxy->net_ns;
    struct bpf_link_primer link_primer;
    struct net_device *dev;
    struct tcx_link *tcx;
    int ret;

    rtnl_lock();
    // 获取索引对应的网卡设备
    dev = __dev_get_by_index(net, attr->link_create.target_ifindex);
    if (!dev) { ... }
    // 创建 link
    tcx = kzalloc(sizeof(*tcx), GFP_USER);
    if (!tcx) { ... }
    // 初始化`tcx_link`
    ret = tcx_link_init(tcx, &link_primer, attr, dev, prog);
    if (ret) { ... }
    // 附加tcx
    ret = tcx_link_prog_attach(&tcx->link, attr->link_create.flags,
            attr->link_create.tcx.relative_fd, attr->link_create.tcx.expected_revision);
    if (ret) { ... }
    // fd 和 file 进行关联
    ret = bpf_link_settle(&link_primer);
out:
    rtnl_unlock();
    return ret;
}
```

`tcx_link_init`函数初始化`tcx_link`设置，如下：

```C
// file: kernel/bpf/tcx.c
static int tcx_link_init(struct tcx_link *tcx, struct bpf_link_primer *link_primer,
            const union bpf_attr *attr, struct net_device *dev, struct bpf_prog *prog)
{
    // 设置link属性
    bpf_link_init(&tcx->link, BPF_LINK_TYPE_TCX, &tcx_link_lops, prog);
    tcx->location = attr->link_create.attach_type;
    tcx->dev = dev;
    // 提供用户空间使用的 fd, id，anon_inode 信息
    return bpf_link_prime(&tcx->link, link_primer);
}
```

#### 4 `tcx_link_prog_attach`

`tcx_link_prog_attach` 函数附加`tcx`BPF程序到`INGRESS/EGRESS`路径下，如下：

```C
// file: kernel/bpf/tcx.c
static int tcx_link_prog_attach(struct bpf_link *link, u32 flags, u32 id_or_fd, u64 revision)
{
    struct tcx_link *tcx = tcx_link(link);
    bool created, ingress = tcx->location == BPF_TCX_INGRESS;
    struct bpf_mprog_entry *entry, *entry_new;
    struct net_device *dev = tcx->dev;
    int ret;

    ASSERT_RTNL();
    // 获取`mprog`
    entry = tcx_entry_fetch_or_create(dev, ingress, &created);
    if (!entry) return -ENOMEM;
    // 附加BPF程序到`mprog`中
    ret = bpf_mprog_attach(entry, &entry_new, link->prog, link, NULL, flags, id_or_fd, revision);
    if (!ret) {
        if (entry != entry_new) {
            // 新旧的`mprog`不同时，更新网卡设备(`dev`)
            tcx_entry_update(dev, entry_new, ingress);
            tcx_entry_sync();
            tcx_skeys_inc(ingress);
        }
        // 释放旧的mprog
        bpf_mprog_commit(entry);
    } else if (created) {
        // 附加失败时，释放旧的mprog
        tcx_entry_free(entry);
    }
    return ret;
}
```

##### (1) 获取或创建`mprog`

`tcx_entry_fetch_or_create`函数获取或创建网卡设备(`dev`)上的`ingress/egress`路径的BPF列表，如下：

```C
// file: kernel/bpf/tcx.c
static inline struct bpf_mprog_entry *
tcx_entry_fetch_or_create(struct net_device *dev, bool ingress, bool *created)
{
    // 获取`ingress/egress`路径的BPF列表
    struct bpf_mprog_entry *entry = tcx_entry_fetch(dev, ingress);
    *created = false;
    if (!entry) {
        // 不存在时创建
        entry = tcx_entry_create();
        if (!entry) return NULL;
        *created = true;
    }
    return entry;
}
```

`tcx_entry_fetch`函数获取`ingress/egress`路径的BPF列表，即，获取`tcx_ingress/tcx_egress`，如下：

```C
// file: kernel/bpf/tcx.c
static inline struct bpf_mprog_entry * tcx_entry_fetch(struct net_device *dev, bool ingress)
{
    ASSERT_RTNL();
    if (ingress)
        return rcu_dereference_rtnl(dev->tcx_ingress);
    else
        return rcu_dereference_rtnl(dev->tcx_egress);
}
```

如果`tcx_ingress/tcx_egress`尚未分配时，调用`tcx_entry_create`函数创建，如下：

```C
// file: kernel/bpf/tcx.c
static inline struct bpf_mprog_entry *tcx_entry_create_noprof(void)
{
    struct tcx_entry *tcx = kzalloc(sizeof(*tcx), GFP_KERNEL);
    if (tcx) {
        // 初始化`mprog_bundle`
        bpf_mprog_bundle_init(&tcx->bundle);
        return &tcx->bundle.a;
    }
    return NULL;
}
#define tcx_entry_create(...)   alloc_hooks(tcx_entry_create_noprof(__VA_ARGS__))
```

`bpf_mprog_bundle_init`函数初始化`mprog_bundle`，设置`bundle`的层次关系，如下：

```C
// file: kernel/bpf/tcx.c
static inline void bpf_mprog_bundle_init(struct bpf_mprog_bundle *bundle)
{
    BUILD_BUG_ON(sizeof(bundle->a.fp_items[0]) > sizeof(u64));
    BUILD_BUG_ON(ARRAY_SIZE(bundle->a.fp_items) != ARRAY_SIZE(bundle->cp_items));
    
    memset(bundle, 0, sizeof(*bundle));
    // 设置`revision`
    atomic64_set(&bundle->revision, 1);
    // 设置`a`,`b`的层次结构
    bundle->a.parent = bundle;
    bundle->b.parent = bundle;
}
```

##### (2) 核心数据结构的定义

`struct tcx_entry`结构是实际分配的数据结构, 定义如下：

```C
// file: include/net/tcx.h
struct tcx_entry {
    struct mini_Qdisc __rcu *miniq;
    struct bpf_mprog_bundle bundle;
    u32 miniq_active;
    struct rcu_head rcu;
};
```

`.miniq`字段是传统TC使用的`Qdisc`，`.miniq_active`字段表示`miniq`是否启用。

`struct bpf_mprog_bundle`结构是`mprog`的集合，定义如下：

```C
// file: include/linux/bpf_mprog.h
struct bpf_mprog_bundle {
    struct bpf_mprog_entry a;
    struct bpf_mprog_entry b;
    struct bpf_mprog_cp cp_items[BPF_MPROG_MAX];
    struct bpf_prog *ref;
    atomic64_t revision;
    u32 count;
};
```

`.a`和`.b`字段是`bpf_mprog_entry`结构，在更新时进行切换。

`struct bpf_mprog_entry`结构是`mprog`的列表，定义如下：

```C
// file: include/linux/bpf_mprog.h
struct bpf_mprog_entry {
    struct bpf_mprog_fp fp_items[BPF_MPROG_MAX];
    struct bpf_mprog_bundle *parent;
};
```

`bpf_mprog_cp`和`bpf_mprog_fp`结构是BPF_LINK和BPF_PROG在`mprog`的表示，如下：

```C
// file: include/linux/bpf_mprog.h
struct bpf_mprog_fp {
    struct bpf_prog *prog;
};
// file: include/linux/bpf_mprog.h
struct bpf_mprog_cp {
    struct bpf_link *link;
};
```

`BPF_MPROG_MAX`定义了`mprog`支持的BPF程序数量，定义如下：

```C
// file: include/linux/bpf_mprog.h
#define BPF_MPROG_MAX 64
```

##### (3) `mprog`附加BPF程序

`bpf_mprog_attach`函数实现`mprog`附加BPF程序，将BPF程序按照`id`或`fd`附加到指定的位置，如下：

```C
// file: kernel/bpf/mprog.c
int bpf_mprog_attach(struct bpf_mprog_entry *entry, struct bpf_mprog_entry **entry_new,
        struct bpf_prog *prog_new, struct bpf_link *link, struct bpf_prog *prog_old,
        u32 flags, u32 id_or_fd, u64 revision)
{
    struct bpf_tuple rtuple, ntuple = {
        .prog = prog_new, .link = link,
    }, otuple = {
        .prog = prog_old, .link = link,
    };
    int ret, idx = -ERANGE, tidx;
    // 检查`revision`
    if (revision && revision != bpf_mprog_revision(entry)) return -ESTALE;
    // `prog`存在时，返回错误
    if (bpf_mprog_exists(entry, prog_new)) return -EEXIST;

    // 根据`id`或`fd`获取`rtuple`中的`link`或`prog`，作为相对位置
    ret = bpf_mprog_tuple_relative(&rtuple, id_or_fd, flags & ~BPF_F_REPLACE, prog_new->type);
    if (ret) return ret;

    if (flags & BPF_F_REPLACE) {
        // 获取旧的prog在`mprog`中的位置
        tidx = bpf_mprog_pos_exact(entry, &otuple);
        if (tidx < 0) { ret = tidx; goto out; }
        idx = tidx;
    } else if (bpf_mprog_total(entry) == bpf_mprog_max()) {
        // BPF程序数量超过`mprog`最大限制时，返回错误
        ret = -ERANGE;
        goto out;
    }
    if (flags & BPF_F_BEFORE) {
        // 获取相对位置的前一个位置
        tidx = bpf_mprog_pos_before(entry, &rtuple);
        if (tidx < -1 || (idx >= -1 && tidx != idx)) {
            ret = tidx < -1 ? tidx : -ERANGE;
            goto out;
        }
        idx = tidx;
    }
    if (flags & BPF_F_AFTER) {
        // 获取相对位置的后一个位置
        tidx = bpf_mprog_pos_after(entry, &rtuple);
        if (tidx < -1 || (idx >= -1 && tidx != idx)) {
            ret = tidx < 0 ? tidx : -ERANGE;
            goto out;
        }
        idx = tidx;
    }
    if (idx < -1) {
        // 修改的位置无效时，但相对位置的`prog`存在时，返回错误
        if (rtuple.prog || flags) { ret = -EINVAL; goto out; }
        // 否则，在`mprog`的最后添加
        idx = bpf_mprog_total(entry);
        flags = BPF_F_AFTER;
    }
    // 修改位置超出`mprog`数量时，返回错误
    if (idx >= bpf_mprog_max()) { ret = -ERANGE; goto out; }

    if (flags & BPF_F_REPLACE)
        // 替换指定位置的BPF程序
        ret = bpf_mprog_replace(entry, entry_new, &ntuple, idx);
    else
        // 在指定位置插入BPF程序
        ret = bpf_mprog_insert(entry, entry_new, &ntuple, idx, flags);
out:
    bpf_mprog_tuple_put(&rtuple);
    return ret;
}
```

`bpf_mprog_replace`函数替换`mprog`指定位置的BPF程序，如下：

```C
// file: kernel/bpf/mprog.c
static int bpf_mprog_replace(struct bpf_mprog_entry *entry,
                struct bpf_mprog_entry **entry_new, struct bpf_tuple *ntuple, int idx)
{
    struct bpf_mprog_fp *fp;
    struct bpf_mprog_cp *cp;
    struct bpf_prog *oprog;
    // 读取指定位置的`fp`(`prog`)和`cp`(`link`)
    bpf_mprog_read(entry, idx, &fp, &cp);
    oprog = READ_ONCE(fp->prog);
    // 使用`tuple`中`link`和`prog`替换`fp`和`cp`
    bpf_mprog_write(fp, cp, ntuple);
    if (!ntuple->link) {
        WARN_ON_ONCE(cp->link);
        // 释放旧的prog
        bpf_prog_put(oprog);
    }
    // 修改`entry_new`
    *entry_new = entry;
    return 0;
}
```

`bpf_mprog_insert`函数在`mprog`指定位置插入BPF程序，如下：

```C
// file: kernel/bpf/mprog.c
static int bpf_mprog_insert(struct bpf_mprog_entry *entry, struct bpf_mprog_entry **entry_new,
                struct bpf_tuple *ntuple, int idx, u32 flags)
{
    int total = bpf_mprog_total(entry);
    struct bpf_mprog_entry *peer;
    struct bpf_mprog_fp *fp;
    struct bpf_mprog_cp *cp;
    // 获取`mprog`的对端
    peer = bpf_mprog_peer(entry);
    // 拷贝`mprog`到对端
    bpf_mprog_entry_copy(peer, entry);
    if (idx == total) 
        goto insert;
    else if (flags & BPF_F_BEFORE) 
        idx += 1;
    // `mprog`添加`entry`
    bpf_mprog_entry_grow(peer, idx);
insert:
    // 读取指定位置的`fp`(`prog``)和`cp`(`link``)
    bpf_mprog_read(peer, idx, &fp, &cp);
    // 使用`tuple`中`link`和`prog`替换`fp`和`cp`
    bpf_mprog_write(fp, cp, ntuple);
    // 增加`perr`的`count`计数
    bpf_mprog_inc(peer);
    // 修改`entry_new`
    *entry_new = peer;
    return 0;
}
```

`bpf_mprog_peer`获取`entry`的对方，即：`struct bpf_mprog_bundle`中的`a`或`b`，如下:

```C
// file: include/linux/bpf_mprog.h
static inline struct bpf_mprog_entry *bpf_mprog_peer(const struct bpf_mprog_entry *entry)
{
    if (entry == &entry->parent->a)
        return &entry->parent->b;
    else
        return &entry->parent->a;
}
```

`bpf_mprog_entry_grow`在指定位置添加`entry`，通过移动内存空间实现，如下：

```C
// file: include/linux/bpf_mprog.h
static inline void bpf_mprog_entry_grow(struct bpf_mprog_entry *entry, int idx)
{
    // 获取`entry`的当前数量
    int total = bpf_mprog_total(entry);
    // 移动`fp`内存空间
    memmove(entry->fp_items + idx + 1, entry->fp_items + idx,
        (total - idx) * sizeof(struct bpf_mprog_fp));
    // 移动`cp`内存空间
    memmove(entry->parent->cp_items + idx + 1, entry->parent->cp_items + idx,
        (total - idx) * sizeof(struct bpf_mprog_cp));
}
```

##### (4) 设置`mprog`

`tcx_entry_update`函数更新网卡设备上的`mprog`，修改`tcx_ingress`和`tcx_egress`，如下：

```C
// file: include/net/tcx.h
static inline void
tcx_entry_update(struct net_device *dev, struct bpf_mprog_entry *entry, bool ingress)
{
    ASSERT_RTNL();
    if (ingress)
        rcu_assign_pointer(dev->tcx_ingress, entry);
    else
        rcu_assign_pointer(dev->tcx_egress, entry);
}
```

`tcx_skeys_inc`函数更新 `tcx_needed_key` ，`ingress_needed_key` 或 `egress_needed_key` 的`STATIC_KEY` 计数，此时增加计数，如下：

```C
// file: include/net/tcx.h
static inline void tcx_skeys_inc(bool ingress)
{
    tcx_inc(); // 增加`tcx_needed_key`计数
    if (ingress)
        net_inc_ingress_queue(); // 增加`ingress_needed_key`计数
    else
        net_inc_egress_queue(); // 增加`egress_needed_key`计数
}
```

`bpf_mprog_commit`函数提交`mprog`，增加`revision`计数，如下：

```C
// file: include/linux/bpf_mprog.h
static inline void bpf_mprog_commit(struct bpf_mprog_entry *entry)
{
    // 完全释放`mprog`
    bpf_mprog_complete_release(entry);
    // 更新`revision`
    bpf_mprog_revision_new(entry);
}
static inline void bpf_mprog_complete_release(struct bpf_mprog_entry *entry)
{
    if (entry->parent->ref) {
        // 在非Link的场景下，只能通过释放引用计数的方式删除prog
        bpf_prog_put(entry->parent->ref);
        entry->parent->ref = NULL;
    }
}
static inline void bpf_mprog_revision_new(struct bpf_mprog_entry *entry)
{
    // 增加`revision`
    atomic64_inc(&entry->parent->revision);
}
```

在设置`mprog`失败的情况下，通过`tcx_entry_free`函数释放`mprog`，如下：

```C
// file: include/net/tcx.h
static inline void tcx_entry_free(struct bpf_mprog_entry *entry)
{
    kfree_rcu(tcx_entry(entry), rcu);
}
```

### 4.2 注销BPF程序的过程

#### 1 `tcx_link_lops`接口

在`tcx_link_init`函数附加link过程中，设置了用户空间操作`bpf_link`的文件接口，如下：

```C
// file: kernel/bpf/tcx.c
static int tcx_link_init(struct tcx_link *tcx, struct bpf_link_primer *link_primer,
            const union bpf_attr *attr, struct net_device *dev, struct bpf_prog *prog)
{
    // 设置link属性
    bpf_link_init(&tcx->link, BPF_LINK_TYPE_TCX, &tcx_link_lops, prog);
    ...
    // 提供用户空间使用的 fd, id，anon_inode 信息
    return bpf_link_prime(&tcx->link, link_primer);
}
```

`tcx_link_lops` 是设置的文件操作接口，定义如下：

```C
// file: kernel/bpf/tcx.c
static const struct bpf_link_ops tcx_link_lops = {
    .release    = tcx_link_release,
    .detach     = tcx_link_detach,
    .dealloc    = tcx_link_dealloc,
    .update_prog    = tcx_link_update,
    .show_fdinfo    = tcx_link_fdinfo,
    .fill_link_info = tcx_link_fill_info,
};
```

#### 2 更新bpf程序

`.update_prog`更新接口，更新当前设置的bpf程序，设置为`tcx_link_update`, 更新`tcx`设置的BPF程序。实现如下:

```C
// file: kernel/bpf/tcx.c
static int tcx_link_update(struct bpf_link *link, struct bpf_prog *nprog, struct bpf_prog *oprog)
{
    struct tcx_link *tcx = tcx_link(link);
    bool ingress = tcx->location == BPF_TCX_INGRESS;
    struct bpf_mprog_entry *entry, *entry_new;
    struct net_device *dev;
    int ret = 0;

    rtnl_lock();
    // 获取`dev`
    dev = tcx->dev;
    if (!dev) { ret = -ENOLINK; goto out; }
    // 替换的prog必须是当前设置的prog
    if (oprog && link->prog != oprog) { ret = -EPERM; goto out; }
    oprog = link->prog;
    // 新旧的程序相同时，释放新的程序
    if (oprog == nprog) { bpf_prog_put(nprog); goto out; }
    // 获取`dev`的`mporg`
    entry = tcx_entry_fetch(dev, ingress);
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

`.release`接口释放`bpf_link`关联的程序。`tcx_link_release`函数从`mprog`中分离BPF程序，如下：

```C
// file: kernel/bpf/tcx.c
static void tcx_link_release(struct bpf_link *link)
{
    struct tcx_link *tcx = tcx_link(link);
    bool ingress = tcx->location == BPF_TCX_INGRESS;
    struct bpf_mprog_entry *entry, *entry_new;
    struct net_device *dev;
    int ret = 0;

    rtnl_lock();
    // 获取`dev`
    dev = tcx->dev;
    if (!dev) goto out;
    // 获取网卡设备的`mprog`
    entry = tcx_entry_fetch(dev, ingress);
    if (!entry) { ret = -ENOENT; goto out; }
    // 分离`mprog`
    ret = bpf_mprog_detach(entry, &entry_new, link->prog, link, 0, 0, 0);
    if (!ret) {
        // 新的`mprog`不活跃时，设置为null
        if (!tcx_entry_is_active(entry_new)) entry_new = NULL;
        // 更新网卡设备的`mprog`
        tcx_entry_update(dev, entry_new, ingress);
        tcx_entry_sync();
        // 减少`tcx_needed_key`,`ingress_needed_key`或`egress_needed_key`的`STATIC_KEY`计数
        tcx_skeys_dec(ingress);
        //  提交`mprog`
        bpf_mprog_commit(entry);
        // 新的`mprog`不存在时，释放旧的`mprog`
        if (!entry_new) tcx_entry_free(entry);
        tcx->dev = NULL;
    }
out:
    WARN_ON_ONCE(ret);
    rtnl_unlock();
}
```

`bpf_mprog_detach`函数分离`mprog`上的BPF程序，实现如下：

```C
// file: kernel/bpf/mprog.c
int bpf_mprog_detach(struct bpf_mprog_entry *entry, struct bpf_mprog_entry **entry_new,
            struct bpf_prog *prog, struct bpf_link *link, u32 flags, u32 id_or_fd, u64 revision)
{
    struct bpf_tuple rtuple, dtuple = {
        .prog = prog,
        .link = link,
    };
    int ret, idx = -ERANGE, tidx;
    // 分离前的检查
    if (flags & BPF_F_REPLACE) return -EINVAL;
    if (revision && revision != bpf_mprog_revision(entry)) return -ESTALE;
    if (!bpf_mprog_total(entry)) return -ENOENT;
    // 根据`id`或`fd`获取`rtuple`中的`link`或`prog`，作为相对位置
    ret = bpf_mprog_tuple_relative(&rtuple, id_or_fd, flags, prog ? prog->type : BPF_PROG_TYPE_UNSPEC);
    if (ret) return ret;
    if (dtuple.prog) {
        // 删除的`prog`存在时，获取指定位置
        tidx = bpf_mprog_pos_exact(entry, &dtuple);
        if (tidx < 0) { ret = tidx; goto out; }
        idx = tidx;
    }
    if (flags & BPF_F_BEFORE) {
        // 获取相对位置的前一个位置
        tidx = bpf_mprog_pos_before(entry, &rtuple);
        if (tidx < -1 || (idx >= -1 && tidx != idx)) {
            ret = tidx < -1 ? tidx : -ERANGE; goto out;
        }
        idx = tidx;
    }
    if (flags & BPF_F_AFTER) {
        // 获取相对位置的后一个位置
        tidx = bpf_mprog_pos_after(entry, &rtuple);
        if (tidx < -1 || (idx >= -1 && tidx != idx)) {
            ret = tidx < 0 ? tidx : -ERANGE; goto out;
        }
        idx = tidx;
    }
    if (idx < -1) {
        // 修改的位置无效时，但相对位置的`prog`存在时，返回错误
        if (rtuple.prog || flags) { ret = -EINVAL; goto out; }
        // 否则，在`mprog`的最后删除
        idx = bpf_mprog_total(entry);
        flags = BPF_F_AFTER;
    }
    // 修改位置超出`mprog`数量时，返回错误
    if (idx >= bpf_mprog_max()) { ret = -ERANGE; goto out; }
    // 获取指定位置的`prog`或`link`
    ret = bpf_mprog_fetch(entry, &dtuple, idx);
    if (ret) goto out;
    // 删除指定的`prog`
    ret = bpf_mprog_delete(entry, entry_new, &dtuple, idx);
out:
    bpf_mprog_tuple_put(&rtuple);
    return ret;
}
```

`bpf_mprog_delete`函数删除`mprog`中指定位置的`prog`，实现如下：

```C
// file: kernel/bpf/mprog.c
static int bpf_mprog_delete(struct bpf_mprog_entry *entry,
            struct bpf_mprog_entry **entry_new, struct bpf_tuple *dtuple, int idx)
{
    int total = bpf_mprog_total(entry);
    struct bpf_mprog_entry *peer;
    // 获取对端的`mprog`，作为新的`mprog`
    peer = bpf_mprog_peer(entry);
    // 复制`mprog`到对端
    bpf_mprog_entry_copy(peer, entry);
    // 检查并调整删除的位置
    if (idx == -1) 
        idx = 0;
    else if (idx == total)
        idx = total - 1;
    // 缩小新的`mprog`
    bpf_mprog_entry_shrink(peer, idx);
    // 减少新的`mprog`
    bpf_mprog_dec(peer);
    // 标记旧的`prog`为释放状态(非`Link`方式附加的)
    bpf_mprog_mark_for_release(peer, dtuple);
    // 设置为新的`mprog`
    *entry_new = peer;
    return 0;
}
```

`bpf_mprog_entry_shrink` 函数缩小`mprog`， 实现如下：

```C
// file: include/linux/bpf_mprog.h
static inline void bpf_mprog_entry_shrink(struct bpf_mprog_entry *entry, int idx)
{
    int total = ARRAY_SIZE(entry->fp_items);
    // 移动`fp_items`内存空间，删除`prog`
    memmove(entry->fp_items + idx, entry->fp_items + idx + 1,
        (total - idx - 1) * sizeof(struct bpf_mprog_fp));
    // 移动`cp_items`内存空间，删除`link`
    memmove(entry->parent->cp_items + idx, entry->parent->cp_items + idx + 1,
        (total - idx - 1) * sizeof(struct bpf_mprog_cp));
}
```

`bpf_mprog_mark_for_release` 函数标记`mprog`为释放状态，如下：

```C
// file: include/linux/bpf_mprog.h
static inline void bpf_mprog_mark_for_release(struct bpf_mprog_entry *entry, struct bpf_tuple *tuple)
{
    // `link`不存在时，设置`prog`
    WARN_ON_ONCE(entry->parent->ref);
    if (!tuple->link) entry->parent->ref = tuple->prog;
}
```

#### 4 分离接口

`.detach`接口分离`bpf_link`关联的程序。`tcx_link_detach`分离`tcx_link`，如下：

```C
// file: kernel/bpf/tcx.c
static int tcx_link_detach(struct bpf_link *link)
{
    // 释放`link`
    tcx_link_release(link);
    return 0;
}
```

#### 5 释放接口

`.dealloc`接口释放`bpf_link`。`tcx_link_dealloc`释放`tcx_link`，如下：

```C
// file: kernel/bpf/tcx.c
static void tcx_link_dealloc(struct bpf_link *link)
{
    kfree(tcx_link(link));
}
```

### 4.3 传统TC的适配实现

传统TC使用`clsact`创建`Qdisc`，定义如下：

```C
// file: net/sched/sch_ingress.c
static struct Qdisc_ops clsact_qdisc_ops __read_mostly = {
    .cl_ops         =   &clsact_class_ops,
    .id             =   "clsact",
    .priv_size      =   sizeof(struct clsact_sched_data),
    .static_flags   =   TCQ_F_INGRESS | TCQ_F_CPUSTATS,
    .init           =   clsact_init,
    .destroy        =   clsact_destroy,
    .dump           =   ingress_dump,
    .ingress_block_set  =   clsact_ingress_block_set,
    .egress_block_set   =   clsact_egress_block_set,
    .ingress_block_get  =   clsact_ingress_block_get,
    .egress_block_get   =   clsact_egress_block_get,
    .owner          =   THIS_MODULE,
};
```

其实现过程参见[TC的内核实现](./14-tc.md#43-clsact的实现)中`clsact的实现`章节。传统TC在初始化阶段通过`mprog`获取`miniq`，在销毁阶段释放`mprog`。具体实现如下：

#### 1 初始化过程

在创建`qdisc`后，调用`.init`接口进行初始化。`clsact_init`函数实现`clsact`类型的qdisc的初始化，如下：

```C
// file: net/sched/sch_ingress.c
static int clsact_init(struct Qdisc *sch, struct nlattr *opt, truct netlink_ext_ack *extack)
{
    struct clsact_sched_data *q = qdisc_priv(sch);
    struct net_device *dev = qdisc_dev(sch);
    struct bpf_mprog_entry *entry;
    bool created;
    int err;

    if (sch->parent != TC_H_CLSACT) return -EOPNOTSUPP;

    net_inc_ingress_queue();
    net_inc_egress_queue();
    // 创建`ingress`路径上`mprog`
    entry = tcx_entry_fetch_or_create(dev, true, &created);
    if (!entry) return -ENOMEM;
    // 增加`mprog`启用计数
    tcx_miniq_inc(entry);
    // miniqp_ingress初始化
    mini_qdisc_pair_init(&q->miniqp_ingress, sch, &tcx_entry(entry)->miniq);
    // 更新网卡设备上`ingress`路径上的`mprog`
    if (created) tcx_entry_update(dev, entry, true);

    // ingress_block扩展信息设置
    q->ingress_block_info.binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS;
    q->ingress_block_info.chain_head_change = clsact_chain_head_change;
    q->ingress_block_info.chain_head_change_priv = &q->miniqp_ingress;
    // ingress_block获取扩展信息
    err = tcf_block_get_ext(&q->ingress_block, sch, &q->ingress_block_info, extack);
    if (err) return err;
    // miniqp_ingress初始block
    mini_qdisc_pair_block_init(&q->miniqp_ingress, q->ingress_block);

    // 创建`egress`路径上`mprog`
    entry = tcx_entry_fetch_or_create(dev, false, &created);
    if (!entry) return -ENOMEM;
    tcx_miniq_inc(entry);
    // miniqp_egress初始化
    mini_qdisc_pair_init(&q->miniqp_egress, sch, &tcx_entry(entry)->miniq);
    // 更新网卡设备上`egress`路径上的`mprog`
    if (created) tcx_entry_update(dev, entry, false);
    // egress_block扩展信息设置
    q->egress_block_info.binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS;
    q->egress_block_info.chain_head_change = clsact_chain_head_change;
    q->egress_block_info.chain_head_change_priv = &q->miniqp_egress;
    // egress_block获取扩展信息
    return tcf_block_get_ext(&q->egress_block, sch, &q->egress_block_info, extack);
}
```

`tcx_miniq_inc`函数修改`mprog`启用状态，增加`miniq`的启用计数，其实现如下：

```C
// file: include/net/tcx.h
static inline void tcx_miniq_inc(struct bpf_mprog_entry *entry)
{
    ASSERT_RTNL();
    // 设置`miniq_active`启用状态标记
    tcx_entry(entry)->miniq_active++;
}
```

#### 2 销毁过程

在销毁`Qdisc`时调用`.destroy`接口，销毁`clsact`，设置为`clsact_destroy`函数。如下：

```C
// file: net/sched/sch_ingress.c
static void clsact_destroy(struct Qdisc *sch)
{
    struct clsact_sched_data *q = qdisc_priv(sch);
    struct net_device *dev = qdisc_dev(sch);
    // 获取`ingress`、`egress`路径上的`mprog`
    struct bpf_mprog_entry *ingress_entry = rtnl_dereference(dev->tcx_ingress);
    struct bpf_mprog_entry *egress_entry = rtnl_dereference(dev->tcx_egress);

    if (sch->parent != TC_H_CLSACT) return;
    // 释放`egress_block`和`ingress_block`额外设置
    tcf_block_put_ext(q->ingress_block, sch, &q->ingress_block_info);
    tcf_block_put_ext(q->egress_block, sch, &q->egress_block_info);
    
    if (ingress_entry) {
        // 标记`ingress`路径上`mprog`处于停用状态
        tcx_miniq_set_active(ingress_entry, false);
        if (!tcx_entry_is_active(ingress_entry)) {
            // `mprog`不活跃时，修改`ingress`路径上的`mprog`为null
            tcx_entry_update(dev, NULL, true);
            tcx_entry_free(ingress_entry);
        }
    }
    if (egress_entry) {
        // 标记`egress`路径上`mprog`处于停用状态
        tcx_miniq_set_active(egress_entry, false);
        if (!tcx_entry_is_active(egress_entry)) {
            // `mprog`不活跃时，修改`egress`路径上的`mprog`为null
            tcx_entry_update(dev, NULL, false);
            tcx_entry_free(egress_entry);
        }
    }
    // 减少`ingress_needed_key`和`egress_needed_key`计数
    net_dec_ingress_queue();
    net_dec_egress_queue();
}
```

### 4.4 BPF调用过程

#### 1 网络数据接收(INGRESS)路径的实现过程

`sch_handle_ingress` 函数实现INGRESS路径TC的处理，如下：

```C
// file: net/core/dev.c
static inline struct sk_buff * sch_handle_ingress(struct sk_buff *skb, struct packet_type **pt_prev, 
    int *ret, struct net_device *orig_dev, bool *another)
{
    // 获取网卡设备`ingress`路径上的`mprog`
    struct bpf_mprog_entry *entry = rcu_dereference_bh(skb->dev->tcx_ingress);
    enum skb_drop_reason drop_reason = SKB_DROP_REASON_TC_INGRESS;
    struct bpf_net_context __bpf_net_ctx, *bpf_net_ctx;
    int sch_ret;

    // `mprog`不存在时，直接返回`skb`
    if (!entry) return skb;
    // 设置`net_ctx`
    bpf_net_ctx = bpf_net_ctx_set(&__bpf_net_ctx);
    if (*pt_prev) {
        // 传送skb
        *ret = deliver_skb(skb, *pt_prev, orig_dev);
        *pt_prev = NULL;
    }
    // skb->cb 属性设置后，更新流量统计信息
    qdisc_skb_cb(skb)->pkt_len = skb->len;
    tcx_set_ingress(skb, true);

    if (static_branch_unlikely(&tcx_needed_key)) {
        // 执行`tcx`，判决`skb`
        sch_ret = tcx_run(entry, skb, true);
        if (sch_ret != TC_ACT_UNSPEC)
            goto ingress_verdict;
    }
    // 执行`tc`，判决`skb`
    sch_ret = tc_run(tcx_entry(entry), skb, &drop_reason);
ingress_verdict:
    // 执行判决结果
    switch (sch_ret) {
    case TC_ACT_REDIRECT:
        __skb_push(skb, skb->mac_len);
        // 重定向skb，需要重新处理时，进行下一轮处理
        if (skb_do_redirect(skb) == -EAGAIN) {
            __skb_pull(skb, skb->mac_len); *another = true; break;
        }
        // 否则返回结果表示正确发送
        *ret = NET_RX_SUCCESS;
        bpf_net_ctx_clear(bpf_net_ctx);
        return NULL;
    case TC_ACT_SHOT:
        // 丢弃skb，返回结果表示丢弃
        kfree_skb_reason(skb, drop_reason);
        *ret = NET_RX_DROP;
        bpf_net_ctx_clear(bpf_net_ctx);
        return NULL;
    case TC_ACT_STOLEN:
    case TC_ACT_QUEUED:
    case TC_ACT_TRAP:
        // 释放skb，返回结果表示正确发送
        consume_skb(skb);
        fallthrough;
    case TC_ACT_CONSUMED:
        *ret = NET_RX_SUCCESS;
        bpf_net_ctx_clear(bpf_net_ctx);
        return NULL;
    }
    bpf_net_ctx_clear(bpf_net_ctx);
    return skb;
}
```

##### (1) TCX判决处理

`tcx_run`函数执行进行`tcx`BPF程序判决，实现如下：

```C
// file: net/core/dev.c
static __always_inline enum tcx_action_base
tcx_run(const struct bpf_mprog_entry *entry, struct sk_buff *skb, const bool needs_mac)
{
    const struct bpf_mprog_fp *fp;
    const struct bpf_prog *prog;
    int ret = TCX_NEXT;
    // 需要`mac`信息时，保留mac地址内容
    if (needs_mac) __skb_push(skb, skb->mac_len);
    // 遍历`mprog`，逐项运行BPF程序
    bpf_mprog_foreach_prog(entry, fp, prog) {
        bpf_compute_data_pointers(skb);
        ret = bpf_prog_run(prog, skb);
        if (ret != TCX_NEXT) break;
    }
    // 恢复mac地址内容
    if (needs_mac) __skb_pull(skb, skb->mac_len);
    return tcx_action_code(skb, ret);
}
```

`tcx_action_code`函数转换`TCX`判决结果，实现如下：

```C
// file: net/core/dev.c
static inline enum tcx_action_base tcx_action_code(struct sk_buff *skb, int code)
{
    switch (code) {
    case TCX_PASS:
        // 设置`tc_index`为`classid`
        skb->tc_index = qdisc_skb_cb(skb)->tc_classid;
        fallthrough;
    case TCX_DROP:
    case TCX_REDIRECT:
        return code;
    case TCX_NEXT:
    default:
        // 默认返回`TCX_NEXT`
        return TCX_NEXT;
    }
}
```

##### (2) TC判决处理

`tc_run`函数实现传统TC的判决处理，实现如下：

```C
// file: net/core/dev.c
static int tc_run(struct tcx_entry *entry, struct sk_buff *skb,
            enum skb_drop_reason *drop_reason)
{
    int ret = TC_ACT_UNSPEC;
#ifdef CONFIG_NET_CLS_ACT
    // 获取`miniq`
    struct mini_Qdisc *miniq = rcu_dereference_bh(entry->miniq);
    struct tcf_result res;
    // `miniq`不存在时，返回
    if (!miniq) return ret;

    // 系统不进行TC处理时，返回
    if (!static_branch_likely(&tcf_sw_enabled_key)) return ret;

    // `miniq`的`block`不进行TC处理时，返回
    if (tcf_block_bypass_sw(miniq->block)) return ret;

    // skb->cb 属性设置后，更新流量统计信息
    tc_skb_cb(skb)->mru = 0;
    tc_skb_cb(skb)->post_ct = false;
    res.drop_reason = *drop_reason;
    mini_qdisc_bstats_cpu_update(miniq, skb);

    // tc判决处理
    ret = tcf_classify(skb, miniq->block, miniq->filter_list, &res, false);
    switch (ret) {
    case TC_ACT_SHOT:
        // 丢弃skb，统计丢弃计数后释放skb，返回结果表示丢弃
        *drop_reason = res.drop_reason;
        mini_qdisc_qstats_cpu_drop(miniq);
        break;
    case TC_ACT_OK:
    case TC_ACT_RECLASSIFY:
        // 设置`tc_index`为`classid`
        skb->tc_index = TC_H_MIN(res.classid);
        break;
    }
#endif /* CONFIG_NET_CLS_ACT */
    return ret;
}
```

#### 2 网络数据发送(EGRESS)路径的实现过程

`sch_handle_egress` 函数实现EGRESS路径TC的处理，如下：

```C
// file: net/core/dev.c
static __always_inline struct sk_buff *
sch_handle_egress(struct sk_buff *skb, int *ret, struct net_device *dev)
{
    // 获取`egress`路径上的`mprog`
    struct bpf_mprog_entry *entry = rcu_dereference_bh(dev->tcx_egress);
    enum skb_drop_reason drop_reason = SKB_DROP_REASON_TC_EGRESS;
    struct bpf_net_context __bpf_net_ctx, *bpf_net_ctx;
    int sch_ret;
    // `mprog`不存在时，返回
    if (!entry) return skb;
    bpf_net_ctx = bpf_net_ctx_set(&__bpf_net_ctx);

    if (static_branch_unlikely(&tcx_needed_key)) {
        // 执行`tcx`，判决`skb`
        sch_ret = tcx_run(entry, skb, false);
        if (sch_ret != TC_ACT_UNSPEC) goto egress_verdict;
    }
    // 执行`tc`，判决`skb`
    sch_ret = tc_run(tcx_entry(entry), skb, &drop_reason);
egress_verdict:
    switch (sch_ret) {
    case TC_ACT_REDIRECT:
        // 重定向skb，返回结果表示正确发送
        skb_do_redirect(skb);
        *ret = NET_XMIT_SUCCESS;
        bpf_net_ctx_clear(bpf_net_ctx);
        return NULL;
    case TC_ACT_SHOT:
        // 丢弃skb，返回结果表示丢弃
        kfree_skb_reason(skb, drop_reason);
        *ret = NET_XMIT_DROP;
        bpf_net_ctx_clear(bpf_net_ctx);
        return NULL;
    case TC_ACT_STOLEN:
    case TC_ACT_QUEUED:
    case TC_ACT_TRAP:
        // 释放skb，返回结果表示正确发送
        consume_skb(skb);
        fallthrough;
    case TC_ACT_CONSUMED:
        *ret = NET_XMIT_SUCCESS;
        bpf_net_ctx_clear(bpf_net_ctx);
        return NULL;
    }
    bpf_net_ctx_clear(bpf_net_ctx);
    return skb;
}
```

#### 3 `tc`重定向实现过程

其实现过程参见[TC的内核实现](./14-tc.md#410-tc重定向实现过程)中`tc重定向实现过程`章节。

## 5 总结

本文通过`tcx`示例程序分析了`tc express`的内核实现过程。`tcx`通过Link方式附加TC类型的BPF程序，通过`mprog`方式在保留传统tc的方式上，支持多个BPF程序的附加。

## 参考资料

* [BPF link support for tc BPF programs](https://lwn.net/Articles/937650/)
* [Generic multi-prog API, tcx links and meta device for BPF](http://vger.kernel.org/bpfconf2023_material/tcx_meta_netdev_borkmann.pdf)
* [Cilium's BPF kernel datapath revamped](https://lpc.events/event/16/contributions/1353/attachments/1068/2130/plumbers_2022_tc_bpf_links.pdf)
