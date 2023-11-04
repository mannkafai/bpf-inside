# SK_LOOKUP的内核实现

## 0 前言

在前几篇文章中，我们分析了网络数据包在内核中的L2、L3处理流程，今天我们继续分析网络数据包在内核中的L4处理流程，即TCP/UDP数据包在内核中的处理流程，我们借助`sk_lookup`示例程序分析使用BPF查找L4 socket的过程。

## 1 简介

SK_LOOKUP类型(BPF_PROG_TYPE_SK_LOOKUP)的程序将可编程性引入到本地传送数据包时查找socket过程中，解决无法绑定地址或端口的情况，如：因端口冲突导致`INADRR_ANY`不可用的情况，或者L7代理在所有或大范围端口接收连接的情况。

## 2 `sk_lookup`示例程序

### 2.1 BPF程序

BPF程序源码参见[test_sk_lookup.c](../src/test_sk_lookup.c)，主要内容如下：

```C
SEC("sk_lookup")
int lookup_pass(struct bpf_sk_lookup *ctx)
{
    return SK_PASS;
}
SEC("sk_reuseport")
int reuseport_pass(struct sk_reuseport_md *ctx)
{
    return SK_PASS;
}
...
```

该程序包含多个BPF程序，使用`sk_lookup`和`sk_reuseport`前缀，参数为`bpf_sk_lookup`和`sk_reuseport_md`类型。

### 2.3 用户程序

#### 1 附加BPF程序

用户程序源码参见[sk_lookup.c](../src/sk_lookup.c)，主要内容如下：

```C
static struct bpf_link *attach_lookup_prog(struct bpf_program *prog)
{
    struct bpf_link *link;
    int net_fd;
    // 获取网络命名空间文件描述符
    net_fd = open("/proc/self/ns/net", O_RDONLY);
    if (CHECK(net_fd < 0, "open", "failed\n")) { ... }

    // 附加sk_lookup BPF程序到网络命名空间
    link = bpf_program__attach_netns(prog, net_fd);
    if (!ASSERT_OK_PTR(link, "bpf_program__attach_netns")) { ... }
    close(net_fd);
    return link;
}
static int attach_reuseport(int sock_fd, struct bpf_program *reuseport_prog)
{
    int err, prog_fd;
    // 获取bpf程序fd
    prog_fd = bpf_program__fd(reuseport_prog);
    if (prog_fd < 0) { ... }
    // 附加reuseport BPF程序到socket
    err = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd));
    if (err) return -1;
    return 0;
}
```

#### 2 读取数据过程

`lookup_pass` 和 `reuseport_pass` BPF程序直接返回结果。

### 2.3 编译运行

`sk_lookup`程序是Linux内核自带的测试程序，在`tools/testing/selftests/bpf/prog_tests/`目录下。编译后运行，如下：

```bash
$ cd tools/testing/selftests/bpf/
$ sudo make
$ sudo ./test_progs -t sk_lookup -vvv
bpf_testmod.ko is already unloaded.
Loading bpf_testmod.ko...
Failed to load bpf_testmod.ko into the kernel: -8
WARNING! Selftests relying on bpf_testmod.ko will be skipped.
libbpf: loading object 'cgroup_skb_sk_lookup_kern' from buffer
...
run_cgroup_bpf_test:PASS:skel_open_load 0 nsec
run_cgroup_bpf_test:PASS:cgroup_join 0 nsec
...
run_multi_prog_lookup:PASS:connect 0 nsec
run_multi_prog_lookup:PASS:connect 0 nsec
run_multi_prog_lookup:PASS:bpf_map_lookup_elem 0 nsec
run_multi_prog_lookup:PASS:bpf_map_lookup_elem 0 nsec
run_multi_prog_lookup:PASS:bpf_map_lookup_elem 0 nsec
run_multi_prog_lookup:PASS:bpf_map_lookup_elem 0 nsec
#170/50  sk_lookup/multi prog - redir, redir:OK
#170     sk_lookup:OK
Summary: 2/50 PASSED, 0 SKIPPED, 0 FAILED
```

## 3 附加BPF的过程

`test_sk_lookup.c`文件中BPF程序的SEC名称为 `SEC("sk_lookup")` 和 `SEC("sk_reuseport")` ，在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("sk_reuseport/migrate", SK_REUSEPORT, BPF_SK_REUSEPORT_SELECT_OR_MIGRATE, SEC_ATTACHABLE),
    SEC_DEF("sk_reuseport",     SK_REUSEPORT, BPF_SK_REUSEPORT_SELECT, SEC_ATTACHABLE),
    SEC_DEF("sk_lookup",        SK_LOOKUP, BPF_SK_LOOKUP, SEC_ATTACHABLE),
    ...
};
```

`sk_lookup`和`sk_reuseport`前缀不支持自动附加，需要通过手动方式附加。

### 3.1 附加`SK_LOOKUP`

`attach_lookup_prog`函数附加sk_lookup BPF程序到网络命名空间，在获取网络命名空间文件后附加BPF程序到网络命名空间。如下：

```C
static struct bpf_link *attach_lookup_prog(struct bpf_program *prog)
{
    struct bpf_link *link;
    int net_fd;
    // 获取网络命名空间文件描述符
    net_fd = open("/proc/self/ns/net", O_RDONLY);
    if (CHECK(net_fd < 0, "open", "failed\n")) { ... }
    // 附加sk_lookup BPF程序到网络命名空间
    link = bpf_program__attach_netns(prog, net_fd);
    if (!ASSERT_OK_PTR(link, "bpf_program__attach_netns")) { ... }
    close(net_fd);
    return link;
}
```

`bpf_program__attach_netns`函数附加BPF程序到网络命名空间，实现如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link * bpf_program__attach_netns(const struct bpf_program *prog, int netns_fd)
{
    return bpf_program__attach_fd(prog, netns_fd, 0, "netns");
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

### 3.2 附加`SK_REUSEPORT`

`attach_reuseport`函数附加reuseport BPF程序到socket，通过`SOL_SOCKET:SO_ATTACH_REUSEPORT_EBPF`选项设置BPF程序，实现如下：

```C
static int attach_reuseport(int sock_fd, struct bpf_program *reuseport_prog)
{
    int err, prog_fd;
    // 获取bpf程序fd
    prog_fd = bpf_program__fd(reuseport_prog);
    if (prog_fd < 0) { ... }
    // 附加reuseport BPF程序到socket
    err = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd));
    if (err) return -1;
    return 0;
}
```

## 4 内核实现

### 4.1 附加`SK_LOOKUP`

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

`link_create` 在检查BFP程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 `sk_lookup` 前缀设置的程序类型为`BPF_PROG_TYPE_SK_LOOKUP`, 对应 `netns_bpf_link_create` 处理函数。如下：

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
    case BPF_PROG_TYPE_FLOW_DISSECTOR:
    case BPF_PROG_TYPE_SK_LOOKUP:
        ret = netns_bpf_link_create(attr, prog);
        break;
    ...
    }
    ...
}
```

#### 3 `netns_bpf_link_create`

`netns_bpf_link_create` 函数获取对应的网络命名空间后，设置`net_link`的信息后，附加BPF程序到网络命名空间上。如下：

```C
// file: kernel/bpf/net_namespace.c
int netns_bpf_link_create(const union bpf_attr *attr, struct bpf_prog *prog)
{
    enum netns_bpf_attach_type netns_type;
    struct bpf_netns_link *net_link;
    struct net *net;

    if (attr->link_create.flags) return -EINVAL;
    // BPF程序类型转换
    type = attr->link_create.attach_type;
    netns_type = to_netns_bpf_attach_type(type);
    if (netns_type < 0) return -EINVAL;

    // 获取指定的网络命名空间
    net = get_net_ns_by_fd(attr->link_create.target_fd);
    if (IS_ERR(net)) return PTR_ERR(net);
    // 创建 net_link
    net_link = kzalloc(sizeof(*net_link), GFP_USER);
    if (!net_link) { ... }
    // 设置link属性
    bpf_link_init(&net_link->link, BPF_LINK_TYPE_NETNS, &bpf_netns_link_ops, prog);
    net_link->net = net;
    net_link->type = type;
    net_link->netns_type = netns_type;

    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&net_link->link, &link_primer);
    if (err) { ... }
    // 附加BPF程序到网络命名空间
    err = netns_bpf_link_attach(net, &net_link->link, netns_type);
	if (err) { ... }

    put_net(net);
    // fd 和 file 进行关联
    return bpf_link_settle(&link_primer);
out_put_net:
    put_net(net);
    return err;
}
```

`to_netns_bpf_attach_type` 函数将BPF程序类型转换为网络命名空间支持的类型，目前支持 `BPF_FLOW_DISSECTOR` 和 `BPF_SK_LOOKUP` 两种类型的程序，如下：

```C
// file: include/linux/bpf-netns.h
static inline enum netns_bpf_attach_type
to_netns_bpf_attach_type(enum bpf_attach_type attach_type)
{
    switch (attach_type) {
    case BPF_FLOW_DISSECTOR: return NETNS_BPF_FLOW_DISSECTOR;
    case BPF_SK_LOOKUP: return NETNS_BPF_SK_LOOKUP;
    default: return NETNS_BPF_INVALID;
    }
}
```

#### 4 `netns_bpf_link_attach`

`netns_bpf_link_attach`函数附加BPF程序到网络命名空间，如下：

```C
// file: kernel/bpf/net_namespace.c
static int netns_bpf_link_attach(struct net *net, struct bpf_link *link, enum netns_bpf_attach_type type)
{
    struct bpf_netns_link *net_link = container_of(link, struct bpf_netns_link, link);
    struct bpf_prog_array *run_array;
    ...

    mutex_lock(&netns_bpf_mutex);
    // 获取指定类型的BPF程序数量
    cnt = link_count(net, type);
    // 检查BPF程序数量是否超过最大限制，FLOW_DISSECTOR最大1个，SK_LOOKUP最大64个
    if (cnt >= netns_bpf_max_progs(type)) { ... }
    // Links和直接附加程序不兼容
    if (net->bpf.progs[type]) { ...	}

    switch (type) {
    case NETNS_BPF_FLOW_DISSECTOR:
        // FLOW_DISSECTOR类型BPF程序附加检查
        err = flow_dissector_bpf_prog_attach_check(net, link->prog); break;
    case NETNS_BPF_SK_LOOKUP: 
        // SK_LOOKUP不进行检查
        err = 0; break;
    default: err = -EINVAL; break;
    }
    if (err) goto out_unlock;

    // 分配BPF程序数组空间
    run_array = bpf_prog_array_alloc(cnt + 1, GFP_KERNEL);
    if (!run_array) { ...	}

    // 添加net_link到links列表中
    list_add_tail(&net_link->node, &net->bpf.links[type]);
    // 填充BPF程序到数组中
    fill_prog_array(net, type, run_array);
    // 替换BPF程序列表后，释放旧的程序列表
    run_array = rcu_replace_pointer(net->bpf.run_array[type], run_array, 
                    lockdep_is_held(&netns_bpf_mutex));
    bpf_prog_array_free(run_array);

    // 更新SK_LOOKUP和FLOW_DISSECTOR的计数，标记附加点已使用
    netns_bpf_attach_type_need(type);
out_unlock:
    mutex_unlock(&netns_bpf_mutex);
    return err;
}
```

### 4.2 注销`SK_LOOKUP`

#### 1 `bpf_netns_link_ops`接口

在创建net_link时，设置了link的操作接口，`bpf_netns_link_ops` 是我们设置的`link->ops`，如下：

```C
// file: kernel/bpf/net_namespace.c
int netns_bpf_link_create(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    // 设置link属性
    bpf_link_init(&net_link->link, BPF_LINK_TYPE_NETNS, &bpf_netns_link_ops, prog);
    net_link->net = net;
    net_link->type = type;
    net_link->netns_type = netns_type;
    // 提供用户空间使用的 fd, id，anon_inode信息
    err = bpf_link_prime(&net_link->link, &link_primer);
    ...
}
```

定义如下：

```C
// file: kernel/bpf/net_namespace.c
static const struct bpf_link_ops bpf_netns_link_ops = {
    .release = bpf_netns_link_release,
    .dealloc = bpf_netns_link_dealloc,
    .detach = bpf_netns_link_detach,
    .update_prog = bpf_netns_link_update_prog,
    .fill_link_info = bpf_netns_link_fill_info,
    .show_fdinfo = bpf_netns_link_show_fdinfo,
};
```

#### 2 更新bpf程序

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

* `net_link`更新

`.update_prog` 更新接口，更新当前设置的bpf程序，设置为 `bpf_netns_link_update_prog` 。实现如下:

```C
// file：kernel/bpf/net_namespace.c
static int bpf_netns_link_update_prog(struct bpf_link *link, 
            struct bpf_prog *new_prog, struct bpf_prog *old_prog)
{
    struct bpf_netns_link *net_link = container_of(link, struct bpf_netns_link, link);
    enum netns_bpf_attach_type type = net_link->netns_type;
    struct bpf_prog_array *run_array;

    // BPF程序及类型检查
    if (old_prog && old_prog != link->prog) return -EPERM;
    if (new_prog->type != link->prog->type) return -EINVAL;

    mutex_lock(&netns_bpf_mutex);
    // 网络命名空间检查
    net = net_link->net;
    if (!net || !check_net(net)) { ... }

    run_array = rcu_dereference_protected(net->bpf.run_array[type], lockdep_is_held(&netns_bpf_mutex));
    // 查找对应的net_link后替换对应的程序
    idx = link_index(net, type, net_link);
    // 更新程序数组中指定索引的程序
    ret = bpf_prog_array_update_at(run_array, idx, new_prog);
    if (ret) goto out_unlock;
    // 替换link关联的程序，释放旧的程序
    old_prog = xchg(&link->prog, new_prog);
    bpf_prog_put(old_prog);

out_unlock:
    mutex_unlock(&netns_bpf_mutex);
    return ret;
}
```

#### 3 注销bpf程序

`.release` 释放接口，分离当前设置的bpf程序，设置为 `bpf_netns_link_release` 。实现如下:

```C
// file：kernel/bpf/net_namespace.c
static void bpf_netns_link_release(struct bpf_link *link)
{
    struct bpf_netns_link *net_link = container_of(link, struct bpf_netns_link, link);
    enum netns_bpf_attach_type type = net_link->netns_type;
    struct bpf_prog_array *old_array, *new_array;
    ...

    mutex_lock(&netns_bpf_mutex);
    // 获取网络命名空间
    net = net_link->net;
    if (!net) goto out_unlock;
    // 标记附加点未使用
    netns_bpf_attach_type_unneed(type);
    // 记录当前附加点的位置
    idx = link_index(net, type, net_link);
    // 从列表中删除附加点
    list_del(&net_link->node);

    cnt = link_count(net, type);
    if (!cnt) {
        // 计算为0时，用NULL替换`run_array`
        netns_bpf_run_array_detach(net, type);
        goto out_unlock;
    }
    old_array = rcu_dereference_protected(net->bpf.run_array[type], lockdep_is_held(&netns_bpf_mutex));
    new_array = bpf_prog_array_alloc(cnt, GFP_KERNEL);
    if (!new_array) {
        // 分配失败，用`dummy_bpf_prog`替换指定位置的BPF程序
        WARN_ON(bpf_prog_array_delete_safe_at(old_array, idx));
        goto out_unlock;
    }
    // 填充BPF程序数组，替换后释放旧的BPF程序数组
    fill_prog_array(net, type, new_array);
    rcu_assign_pointer(net->bpf.run_array[type], new_array);
    bpf_prog_array_free(old_array);

out_unlock:
    net_link->net = NULL;
    mutex_unlock(&netns_bpf_mutex);
}
```

### 4.3 附加/注销`SK_REUSEPORT`

#### 1 `setsockopt`系统调用

用户通过 `setsockopt` 系统调用附加BPF程序，`setsockopt` 系统调用实现如下：

```C
// file: net/socket.c
SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, 
        char __user *, optval, int, optlen)
{
    return __sys_setsockopt(fd, level, optname, optval, optlen);
}

// file: net/socket.c
int __sys_setsockopt(int fd, int level, int optname, char __user *user_optval, int optlen)
{
    sockptr_t optval = USER_SOCKPTR(user_optval);
    char *kernel_optval = NULL;
    int err, fput_needed;
    struct socket *sock;

    // 检查选项长度
    if (optlen < 0) return -EINVAL;
    // 获取sock 
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (!sock) return err;
    // LSM安全检查
    err = security_socket_setsockopt(sock, level, optname);
    if (err) goto out_put;

    if (!in_compat_syscall())
        // CGROUP SETSOCKOPT BPF程序检查
        err = BPF_CGROUP_RUN_PROG_SETSOCKOPT(sock->sk, &level, &optname,
                    user_optval, &optlen, &kernel_optval);
    // 错误时退出
    if (err < 0) goto out_put;
    if (err > 0) { err = 0; goto out_put; }

    if (kernel_optval)
        optval = KERNEL_SOCKPTR(kernel_optval);
    // 判断是否使用SOL_SOCKET
    if (level == SOL_SOCKET && !sock_use_custom_sol_socket(sock))
        err = sock_setsockopt(sock, level, optname, optval, optlen);
    else if (unlikely(!sock->ops->setsockopt))
        err = -EOPNOTSUPP;
    else    
        err = sock->ops->setsockopt(sock, level, optname, optval, optlen);
    // 释放内核`optval`
    kfree(kernel_optval);
out_put:
    // 释放sock->file
    fput_light(sock->file, fput_needed);
    return err;
}
```

#### 2 `setsockopt`实现

BPF程序使用 `SOL_SOCKET` 级别进行设置，对应 `sock_setsockopt` 函数。`sock_setsockopt()` 调用 `sk_setsockopt()`, 后者对`optname`进行对应的操作。其实现如下：

```C
// file: net/core/sock.c
int sock_setsockopt(struct socket *sock, int level, int optname, 
    sockptr_t optval, unsigned int optlen)
{
    return sk_setsockopt(sock->sk, level, optname, optval, optlen);
}
// file: net/core/sock.c
int sk_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen)
{
    struct socket *sock = sk->sk_socket;
    int val;
    ...
    // 无参数选项设置
    if (optname == SO_BINDTODEVICE) 
        return sock_setbindtodevice(sk, optval, optlen);
    // 检查参数长度是否正确
    if (optlen < sizeof(int)) return -EINVAL;
    // 获取参数值
    if (copy_from_sockptr(&val, optval, sizeof(val)))
        return -EFAULT;

    valbool = val ? 1 : 0;
    sockopt_lock_sock(sk);
    switch (optname) {
    ...
    // 设置`SO_REUSEPORT`选项
    case SO_REUSEPORT:
        sk->sk_reuseport = valbool;
    break;
    // 以BPF指令方式附加REUSEPORT程序
    case SO_ATTACH_REUSEPORT_CBPF: {
        struct sock_fprog fprog;
        // 复制BPF指令
        ret = copy_bpf_fprog_from_user(&fprog, optval, optlen);
        if (!ret) ret = sk_reuseport_attach_filter(&fprog, sk);
        break;
    }
    // 以FD方式附加REUSEPORT程序
    case SO_ATTACH_REUSEPORT_EBPF:
        ret = -EINVAL;
        if (optlen == sizeof(u32)) {
            // 复制BPF fd
            if (copy_from_sockptr(&ufd, optval, sizeof(ufd))) break;
            ret = sk_reuseport_attach_bpf(ufd, sk); 
        }
        break;
    // 分离REUSEPORT程序
    case SO_DETACH_REUSEPORT_BPF:
        ret = reuseport_detach_prog(sk);
        break;
    ...
    }
    sockopt_release_sock(sk);
    return ret;
}
```

#### 3 `ATTACH_REUSEPORT_CBPF`选项

`ATTACH_REUSEPORT_CBPF`选项通过传统方式附加BPF程序，在复制用户空间的BPF程序后，通过`sk_reuseport_attach_filter()`函数附加到socket上，实现如下：

```C
// file: net/core/filter.c
int sk_reuseport_attach_filter(struct sock_fprog *fprog, struct sock *sk)
{
    // 将BPF指令生成BPF程序
    struct bpf_prog *prog = __get_filter(fprog, sk);
    int err;
    if (IS_ERR(prog)) return PTR_ERR(prog);
    // 检查BPF程序大小是否超过系统最大限制，`net.core.optmem_max`选项
    if (bpf_prog_size(prog->len) > READ_ONCE(sysctl_optmem_max))
        err = -ENOMEM;
    else
        // 附加BPF程序到socket上
        err = reuseport_attach_prog(sk, prog);
    // 出现错误时释放BPF程序
    if (err) __bpf_prog_release(prog);
    return err;
}
```

`reuseport_attach_prog`函数实现`reuseport`BPF程序的附加，实现如下：

```C
// file: net/core/sock_reuseport.c
int reuseport_attach_prog(struct sock *sk, struct bpf_prog *prog)
{
    struct sock_reuseport *reuse;
    struct bpf_prog *old_prog;

    if (sk_unhashed(sk)) {
        // sk不在hash列表中(不完全连接时)，创建`sk_reuseport_cb`需要的空间
        int err;
        if (!sk->sk_reuseport) return -EINVAL;
        // 创建`sk_reuseport_cb`
        err = reuseport_alloc(sk, false);
        if (err) return err;
    } else if (!rcu_access_pointer(sk->sk_reuseport_cb)) {
        // SO_REUSEPORT未绑定时，返回错误码
        return -EINVAL;
    }

    spin_lock_bh(&reuseport_lock);
    // 替换BPF程序
    reuse = rcu_dereference_protected(sk->sk_reuseport_cb, lockdep_is_held(&reuseport_lock));
    old_prog = rcu_dereference_protected(reuse->prog, lockdep_is_held(&reuseport_lock));
    rcu_assign_pointer(reuse->prog, prog);
    spin_unlock_bh(&reuseport_lock);
    // 释放旧的BPF程序
    sk_reuseport_prog_free(old_prog);
    return 0;
}
```

`reuseport_alloc`函数分配`sk_reuseport_cb`空间，实现如下：

```C
// file: net/core/sock_reuseport.c
int reuseport_alloc(struct sock *sk, bool bind_inany)
{
    struct sock_reuseport *reuse;
    int id, ret = 0;
    spin_lock_bh(&reuseport_lock);

    // 检查sk_reuseport_cb是否已经分配
    reuse = rcu_dereference_protected(sk->sk_reuseport_cb, lockdep_is_held(&reuseport_lock));
    if (reuse) {
        if (reuse->num_closed_socks) {
            // 关闭的sock重新使用之前的`reuseport`
            ret = reuseport_resurrect(sk, reuse, NULL, bind_inany);
            goto out;
        }
        // 设置reuse->bind_inany
        if (bind_inany) reuse->bind_inany = bind_inany;
        goto out;
    }
    // 分配`reuseport`空间，最多支持128个sock
    reuse = __reuseport_alloc(INIT_SOCKS);
    if (!reuse) { ... }
    // 分配id
    id = ida_alloc(&reuseport_ida, GFP_ATOMIC);
    if (id < 0) { ... }
    // 设置reuse属性
    reuse->reuseport_id = id;
    reuse->bind_inany = bind_inany;
    reuse->socks[0] = sk;
    reuse->num_socks = 1;
    reuseport_get_incoming_cpu(sk, reuse);
    // 设置`sk->sk_reuseport_cb`
    rcu_assign_pointer(sk->sk_reuseport_cb, reuse);
out:
    spin_unlock_bh(&reuseport_lock);
    return ret;
}
```

#### 4 `ATTACH_REUSEPORT_EBPF`选项

`ATTACH_REUSEPORT_EBPF`选项通过现代方式附加BPF程序，通过FD方式设置BPF程序，通过`sk_reuseport_attach_bpf()`函数附加到socket上，实现如下：

```C
// file: net/core/filter.c
int sk_reuseport_attach_bpf(u32 ufd, struct sock *sk)
{
    struct bpf_prog *prog;
    int err;
    // FILTER锁定时不能附加
    if (sock_flag(sk, SOCK_FILTER_LOCKED)) return -EPERM;

    // 获取BPF程序，支持`SOCKET_FILTER`和`SK_REUSEPORT`两种类型程序
    prog = bpf_prog_get_type(ufd, BPF_PROG_TYPE_SOCKET_FILTER);
    if (PTR_ERR(prog) == -EINVAL)
        prog = bpf_prog_get_type(ufd, BPF_PROG_TYPE_SK_REUSEPORT);
    if (IS_ERR(prog)) return PTR_ERR(prog);

    if (prog->type == BPF_PROG_TYPE_SK_REUSEPORT) {
        // `SK_REUSEPORT`类型程序只支持IPV4/IPV6的TCP/UDP协议的socket
        if ((sk->sk_type != SOCK_STREAM && sk->sk_type != SOCK_DGRAM) ||
            (sk->sk_protocol != IPPROTO_UDP && sk->sk_protocol != IPPROTO_TCP) ||
            (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)) {
            err = -ENOTSUPP;
            goto err_prog_put;
        }
    } else {
        // `SOCKET_FILTER`类型程序检查资源限制
        if (bpf_prog_size(prog->len) > READ_ONCE(sysctl_optmem_max)) {
            err = -ENOMEM;
            goto err_prog_put;
        }
    }
    // 附加BPF程序到socket上
    err = reuseport_attach_prog(sk, prog);
err_prog_put:
    if (err) bpf_prog_put(prog);
    return err;
}
```

#### 5 `DETACH_REUSEPORT_BPF`选项

`DETACH_REUSEPORT_BPF`选项分离`REUSEPORT`BPF程序，对应`reuseport_detach_prog()`函数，实现如下：

```C
// file: net/core/sock_reuseport.c
int reuseport_detach_prog(struct sock *sk)
{
    struct sock_reuseport *reuse;
    struct bpf_prog *old_prog;

    old_prog = NULL;
    spin_lock_bh(&reuseport_lock);
    reuse = rcu_dereference_protected(sk->sk_reuseport_cb, lockdep_is_held(&reuseport_lock));
    // `sk_reuseport_cb`不存在时返回
    if (!reuse) {
        spin_unlock_bh(&reuseport_lock);
        return sk->sk_reuseport ? -ENOENT : -EINVAL;
    }
    // sk不在hash列表中(不完全连接时)，且`reuse`存在关闭的socket时返回
    if (sk_unhashed(sk) && reuse->num_closed_socks) {
        spin_unlock_bh(&reuseport_lock);
        return -ENOENT;
    }
    // 设置BPF为NULL
    old_prog = rcu_replace_pointer(reuse->prog, old_prog, lockdep_is_held(&reuseport_lock));
    spin_unlock_bh(&reuseport_lock);
    
    // 旧的BPF程序存在时，释放旧的BPF程序
    if (!old_prog) return -ENOENT;
    sk_reuseport_prog_free(old_prog);
    return 0;
}
```

### 4.4 `SK_LOOKUP`在UDP的实现过程

#### 1 添加/分离`reuseport`

在使用UDP类型的socket时，通过`bind`系统调用绑定本机地址和端口时，可以指定`reuseport`选项，以支持多个socket绑定同一个端口。实现如下：

##### (1) `bind`系统调用

```C
// file: net/socket.c
SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
{
    return __sys_bind(fd, umyaddr, addrlen);
}
// file: net/socket.c
int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
    struct socket *sock;
    struct sockaddr_storage address;
    int err, fput_needed;
    // 根据fd获取socket
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (sock) {
        // 复制地址到内核空间
        err = move_addr_to_kernel(umyaddr, addrlen, &address);
        if (!err) {
            // LSM安全检查
            err = security_socket_bind(sock, (struct sockaddr *)&address, addrlen);
            // socket绑定地址
            if (!err) err = sock->ops->bind(sock, (struct sockaddr *) &address, addrlen);
        }
        fput_light(sock->file, fput_needed);
    }
    return err;
}
```

IPV4的UDP协议在Linux内核中定义如下：

```C
// file: net/ipv4/af_inet.c
static struct inet_protosw inetsw_array[] =
{
    ...
    {
        .type =       SOCK_DGRAM,
        .protocol =   IPPROTO_UDP,
        .prot =       &udp_prot,
        .ops =        &inet_dgram_ops,
        .flags =      INET_PROTOSW_PERMANENT,
    },
    ...
};
```

`.ops`操作接口设置为`inet_dgram_ops`，定义如下：

```C
// file: net/ipv4/af_inet.c
const struct proto_ops inet_dgram_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    .release        = inet_release,
    .bind           = inet_bind,
    .connect        = inet_dgram_connect,
    ...
};
EXPORT_SYMBOL(inet_dgram_ops);
```

`.prot`定义为`udp_prot`，定义如下：

```C
// file: net/ipv4/udp.c
struct proto udp_prot = {
    .name           = "UDP",
    ...
    .hash           = udp_lib_hash,
    .unhash         = udp_lib_unhash,
    .rehash         = udp_v4_rehash,
    .get_port       = udp_v4_get_port,
    .put_port       = udp_lib_unhash,
    ...
};
```

`.bind`接口设置为`inet_bind`，实现如下：

```C
// file: net/ipv4/af_inet.c
int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    struct sock *sk = sock->sk;
    u32 flags = BIND_WITH_LOCK;
    int err;

    // socket的bind方法，如：RAW socket
    if (sk->sk_prot->bind) {
        return sk->sk_prot->bind(sk, uaddr, addr_len);
    }
    // 检查地址长度是否正确
    if (addr_len < sizeof(struct sockaddr_in)) return -EINVAL;

    // CGROUP INET_BIND BPF程序检查
    err = BPF_CGROUP_RUN_PROG_INET_BIND_LOCK(sk, uaddr, CGROUP_INET4_BIND, &flags);
    if (err) return err;
    
    // ipv4的`bind`实现
    return __inet_bind(sk, uaddr, addr_len, flags);
}
```

udp协议没有设置`bind`接口，因此，`__inet_bind`函数实现具体的`bind`操作，如下：

```C
// file: net/ipv4/af_inet.c
int __inet_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len, u32 flags)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    unsigned short snum;

    ...
    // 绑定时的权限检查
    snum = ntohs(addr->sin_port);
    err = -EACCES;
    if (!(flags & BIND_NO_CAP_NET_BIND_SERVICE) && snum && 
        inet_port_requires_bind_service(net, snum) && !ns_capable(net->user_ns, CAP_NET_BIND_SERVICE))
        goto out;
    if (flags & BIND_WITH_LOCK) lock_sock(sk);

    // 检查socket是否存活、多次绑定
    err = -EINVAL;
    if (sk->sk_state != TCP_CLOSE || inet->inet_num) goto out_release_sock;
    inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;
    if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
        inet->inet_saddr = 0;  /* Use device */

    // 检查socket是否允许绑定端口
    if (snum || !(inet->bind_address_no_port || (flags & BIND_FORCE_ADDRESS_NO_PORT))) {
        // `.get_port`接口，检查绑定的端口
        err = sk->sk_prot->get_port(sk, snum);
        if (err) {
            // 端口绑定失败时，清除源地址
            inet->inet_saddr = inet->inet_rcv_saddr = 0;
            goto out_release_sock;
        }
        if (!(flags & BIND_FROM_BPF)) {
            // 运行CGROUP程序，检查端口是否允许绑定
            err = BPF_CGROUP_RUN_PROG_INET4_POST_BIND(sk);
            if (err) {
                // 运行失败时，清除源地址，并释放绑定的端口
                inet->inet_saddr = inet->inet_rcv_saddr = 0;
                if (sk->sk_prot->put_port) sk->sk_prot->put_port(sk);
                goto out_release_sock;
            }
        }
    }
    // 绑定成功时，设置socket的源端口
    if (inet->inet_rcv_saddr) sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
    if (snum) sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
    inet->inet_sport = htons(inet->inet_num);
    inet->inet_daddr = 0;
    inet->inet_dport = 0;
    sk_dst_reset(sk);
    err = 0;
out_release_sock:
    if (flags & BIND_WITH_LOCK)
        release_sock(sk);
out:
    return err;
}
```

在绑定端口的过程中，使用`sk_prot->get_port`接口检查绑定的端口。

##### (2) 添加`reuseport`

`.get_port`接口设置为`udp_v4_get_port`，在计算hash值后，获取端口。实现如下：

```C
// file: net/ipv4/udp.c
int udp_v4_get_port(struct sock *sk, unsigned short snum)
{
    // 计算空地址、源地址的hash值
    unsigned int hash2_nulladdr = ipv4_portaddr_hash(sock_net(sk), htonl(INADDR_ANY), snum);
    unsigned int hash2_partial = ipv4_portaddr_hash(sock_net(sk), inet_sk(sk)->inet_rcv_saddr, 0);

    udp_sk(sk)->udp_portaddr_hash = hash2_partial;
    // udp获取端口
    return udp_lib_get_port(sk, snum, hash2_nulladdr);
}
```

`udp_lib_get_port`函数是UDP/-Lite协议查找端口的核心函数，同时支持ipv4和ipv6，实现如下：

```C
// file: net/ipv4/udp.c
int udp_lib_get_port(struct sock *sk, unsigned short snum, unsigned int hash2_nulladdr)
{
    struct udp_table *udptable = udp_get_table_prot(sk);
    struct udp_hslot *hslot, *hslot2;
    struct net *net = sock_net(sk);
    int error = -EADDRINUSE;

    if (!snum) {
        // 未指定端口时，随机选择一个端口
        DECLARE_BITMAP(bitmap, PORTS_PER_CHAIN);
        unsigned short first, last;
        int low, high, remaining;
        unsigned int rand;

        // 获取端口范围，由`net.ipv4.ip_local_port_rang`控制
        inet_sk_get_local_port_range(sk, &low, &high);
        remaining = (high - low) + 1;

        rand = get_random_u32();
        first = reciprocal_scale(rand, remaining) + low;

        rand = (rand | 1) * (udptable->mask + 1);
        last = first + udptable->mask + 1;
        do {
            hslot = udp_hashslot(udptable, net, first);
            bitmap_zero(bitmap, PORTS_PER_CHAIN);
            spin_lock_bh(&hslot->lock);
            // 检查端口是否被占用
            udp_lib_lport_inuse(net, snum, hslot, bitmap, sk, udptable->log);

            snum = first;
            do {
                // 在可用范围内选择一个端口，跳过占用的端口和保留端口
                if (low <= snum && snum <= high &&
                    !test_bit(snum >> udptable->log, bitmap) &&
                    !inet_is_local_reserved_port(net, snum))
                    // 找到一个可用的端口
                    goto found;
                snum += rand;
            } while (snum != first);
            spin_unlock_bh(&hslot->lock);
            cond_resched();
        } while (++first != last);
        // 未找到可用的端口
        goto fail;
    } else {
        // 指定端口的情况下，检查端口是否可用
        hslot = udp_hashslot(udptable, net, snum);
        spin_lock_bh(&hslot->lock);
        if (hslot->count > 10) {
            // hash数量超过10时，重新设置hash
            int exist;
            unsigned int slot2 = udp_sk(sk)->udp_portaddr_hash ^ snum;

            slot2          &= udptable->mask;
            hash2_nulladdr &= udptable->mask;

            hslot2 = udp_hashslot2(udptable, slot2);
            if (hslot->count < hslot2->count)
                goto scan_primary_hash;
            // 检查端口是否被占用
            exist = udp_lib_lport_inuse2(net, snum, hslot2, sk);
            if (!exist && (hash2_nulladdr != slot2)) {
                hslot2 = udp_hashslot2(udptable, hash2_nulladdr);
                exist = udp_lib_lport_inuse2(net, snum, hslot2, sk);
            }
            if (exist)
                goto fail_unlock;
            else
                goto found;
        }
scan_primary_hash:
        // 检查端口是否被占用
        if (udp_lib_lport_inuse(net, snum, hslot, NULL, sk, 0))
            goto fail_unlock;
    }
found:
    // 绑定的端口可用时，更新端口信息
    inet_sk(sk)->inet_num = snum;
    udp_sk(sk)->udp_port_hash = snum;
    udp_sk(sk)->udp_portaddr_hash ^= snum;
    if (sk_unhashed(sk)) {
        // 设置`reuseport`时，添加到`reuseport`列表中
        if (sk->sk_reuseport && udp_reuseport_add_sock(sk, hslot)) {
            inet_sk(sk)->inet_num = 0;
            udp_sk(sk)->udp_port_hash = 0;
            udp_sk(sk)->udp_portaddr_hash ^= snum;
            goto fail_unlock;
        }
        // 没有设置`reuseport`时，添加到`hash`列表中
        sk_add_node_rcu(sk, &hslot->head);
        hslot->count++;
        sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);

        hslot2 = udp_hashslot2(udptable, udp_sk(sk)->udp_portaddr_hash);
        spin_lock(&hslot2->lock);
        if (IS_ENABLED(CONFIG_IPV6) && sk->sk_reuseport && sk->sk_family == AF_INET6)
            hlist_add_tail_rcu(&udp_sk(sk)->udp_portaddr_node, &hslot2->head);
        else
            hlist_add_head_rcu(&udp_sk(sk)->udp_portaddr_node, &hslot2->head);
        hslot2->count++;
        spin_unlock(&hslot2->lock);
    }
    sock_set_flag(sk, SOCK_RCU_FREE);
    error = 0;
fail_unlock:
    spin_unlock_bh(&hslot->lock);
fail:
    return error;
}
```

`udp_reuseport_add_sock`函数从hash列表中找到匹配的sock后，添加到`reuseport`列表中，如下：

```C
// file: net/ipv4/udp.c
static int udp_reuseport_add_sock(struct sock *sk, struct udp_hslot *hslot)
{
    struct net *net = sock_net(sk);
    kuid_t uid = sock_i_uid(sk);
    struct sock *sk2;
    sk_for_each(sk2, &hslot->head) {
        if (net_eq(sock_net(sk2), net) && sk2 != sk &&
            sk2->sk_family == sk->sk_family && 
            ipv6_only_sock(sk2) == ipv6_only_sock(sk) &&
            (udp_sk(sk2)->udp_port_hash == udp_sk(sk)->udp_port_hash) &&
            (sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
            sk2->sk_reuseport && uid_eq(uid, sock_i_uid(sk2)) &&
            inet_rcv_saddr_equal(sk, sk2, false)) {
            // 存在相同的reuseport组时，添加到sk到reuseport组中
            return reuseport_add_sock(sk, sk2, inet_rcv_saddr_any(sk));
        }
    }
    // 不存在时，分配`reuseport`
    return reuseport_alloc(sk, inet_rcv_saddr_any(sk));
}
```

`reuseport_add_sock`函数将一个socket添加到另一个socket的`reuseport`列表中，如下：

```C
// file: net/core/sock_reuseport.c
int reuseport_add_sock(struct sock *sk, struct sock *sk2, bool bind_inany)
{
    struct sock_reuseport *old_reuse, *reuse;
    // `reuseport`不存在时，分配
    if (!rcu_access_pointer(sk2->sk_reuseport_cb)) {
        int err = reuseport_alloc(sk2, bind_inany);
        if (err) return err;
    }

    spin_lock_bh(&reuseport_lock);
    reuse = rcu_dereference_protected(sk2->sk_reuseport_cb, lockdep_is_held(&reuseport_lock));
    old_reuse = rcu_dereference_protected(sk->sk_reuseport_cb, lockdep_is_held(&reuseport_lock));
    if (old_reuse && old_reuse->num_closed_socks) {
        // sk关闭时，重新使用`reuseport`
        int err = reuseport_resurrect(sk, old_reuse, reuse, reuse->bind_inany);
        spin_unlock_bh(&reuseport_lock);
        return err;
    }
    // `reuseport`占用时，不能添加
    if (old_reuse && old_reuse->num_socks != 1) {
        spin_unlock_bh(&reuseport_lock);
        return -EBUSY;
    }

    if (reuse->num_socks + reuse->num_closed_socks == reuse->max_socks) {
        // `reuseport`的`sock`空间都占满时，扩容`reuseport`
        reuse = reuseport_grow(reuse);
        if (!reuse) { spin_unlock_bh(&reuseport_lock); return -ENOMEM; }
    }
    // 添加`sk`到`reuseport`中
    __reuseport_add_sock(sk, reuse);
    rcu_assign_pointer(sk->sk_reuseport_cb, reuse);

    spin_unlock_bh(&reuseport_lock);
    // 释放旧的`reuseport`
    if (old_reuse) call_rcu(&old_reuse->rcu, reuseport_free_rcu);
    return 0;
}
```

##### (3) 分离`reuseport`

`.put_port`接口在`.get_port`接口绑定失败时进行清理，设置为`udp_lib_unhash`，分离`reuseport`程序。`.unhash`接口在释放socket时调用，同样设置为`udp_lib_unhash`，其实现如下：

```C
// file: net/ipv4/udp.c
void udp_lib_unhash(struct sock *sk)
{
    if (sk_hashed(sk)) {
        struct udp_table *udptable = udp_get_table_prot(sk);
        struct udp_hslot *hslot, *hslot2;
        // 计算`hash`值
        hslot = udp_hashslot(udptable, sock_net(sk), udp_sk(sk)->udp_port_hash);
        hslot2 = udp_hashslot2(udptable, udp_sk(sk)->udp_portaddr_hash);

        spin_lock_bh(&hslot->lock);
        // 分离`reuseport`
        if (rcu_access_pointer(sk->sk_reuseport_cb))
            reuseport_detach_sock(sk);
        if (sk_del_node_init_rcu(sk)) {
            // 从hash列表中移除
            hslot->count--;
            inet_sk(sk)->inet_num = 0;
            sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
            
            spin_lock(&hslot2->lock);
            hlist_del_init_rcu(&udp_sk(sk)->udp_portaddr_node);
            hslot2->count--;
            spin_unlock(&hslot2->lock);
        }
        spin_unlock_bh(&hslot->lock);
    }
}
```

`reuseport_detach_sock`函数分离`reuseport`，实现如下：

```C
// file: net/ipv4/udp.c
void reuseport_detach_sock(struct sock *sk)
{
    struct sock_reuseport *reuse;

    spin_lock_bh(&reuseport_lock);
    reuse = rcu_dereference_protected(sk->sk_reuseport_cb, lockdep_is_held(&reuseport_lock));
    if (!reuse) goto out;

    // 通知BPF端，从`sockarray`的map中删除
    bpf_sk_reuseport_detach(sk);
    rcu_assign_pointer(sk->sk_reuseport_cb, NULL);
    // 分离`reuseport`
    if (!__reuseport_detach_closed_sock(sk, reuse))
        __reuseport_detach_sock(sk, reuse);
    // 计数为0时，释放`reuseport`
    if (reuse->num_socks + reuse->num_closed_socks == 0)
        call_rcu(&reuse->rcu, reuseport_free_rcu);
out:
    spin_unlock_bh(&reuseport_lock);
}
```

`__reuseport_detach_closed_sock`函数分离已关闭的socket的`reuseport`，如下：

```C
// file: net/core/sock_reuseport.c
static bool __reuseport_detach_closed_sock(struct sock *sk, struct sock_reuseport *reuse)
{
    // 查找`reuseport`
    int i = reuseport_sock_index(sk, reuse, true);
    if (i == -1) return false;
    
    // 设置`reuseport`中关闭的socket
    reuse->socks[i] = reuse->socks[reuse->max_socks - reuse->num_closed_socks];
    WRITE_ONCE(reuse->num_closed_socks, reuse->num_closed_socks - 1);
    reuseport_put_incoming_cpu(sk, reuse);
    return true;
}
```

`__reuseport_detach_sock`函数分离socket的`reuseport`，如下：

```C
// file: net/core/sock_reuseport.c
static bool __reuseport_detach_sock(struct sock *sk, struct sock_reuseport *reuse)
{
    int i = reuseport_sock_index(sk, reuse, false);
    if (i == -1) return false;
    // 设置`reuseport`中socket
    reuse->socks[i] = reuse->socks[reuse->num_socks - 1];
    reuse->num_socks--;
    reuseport_put_incoming_cpu(sk, reuse);
    return true;
}
```

#### 2 本地网络数据包的接收过程(L3)

在网络数据包是本地的情况下，L3路由的`.input`接口设置为`ip_local_deliver`，实现如下：

```C
// file: net/ipv4/ip_input.c
int ip_local_deliver(struct sk_buff *skb)
{
    struct net *net = dev_net(skb->dev);
    // IP分片处理
    if (ip_is_fragment(ip_hdr(skb))) {
        if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER)) return 0;
    }
    // NF_HOOK处理，正常通过后调用`ip_local_deliver_finish`接口
    return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN, net, NULL, skb, skb->dev, NULL, ip_local_deliver_finish);
}
```

`ip_local_deliver_finish`函数清除skb传送时间、保留L3头部信息后，调用`ip_protocol_deliver_rcu`函数进入L4处理流程，如下：

```C
// file: net/ipv4/ip_input.c
static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{   
    // 清除skb传送时间
    skb_clear_delivery_time(skb);
    // 保留L3头部信息
    __skb_pull(skb, skb_network_header_len(skb));

    rcu_read_lock();
    ip_protocol_deliver_rcu(net, skb, ip_hdr(skb)->protocol);
    rcu_read_unlock();
    return 0;
}
```

`ip_protocol_deliver_rcu`函数根据L4协议号调用相应的处理函数，如下：

```C
// file: net/ipv4/ip_input.c
void ip_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol)
{
    const struct net_protocol *ipprot;
    int raw, ret;

resubmit:
    raw = raw_local_deliver(skb, protocol);
    // 获取L4协议处理信息
    ipprot = rcu_dereference(inet_protos[protocol]);
    if (ipprot) {
        ...
        // L4协议处理
        ret = INDIRECT_CALL_2(ipprot->handler, tcp_v4_rcv, udp_rcv, skb);
        if (ret < 0) { ...  }
        __IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
    } else {
        ...
    }
}
```

#### 3 UDP数据包的接收实现过程

对于IPV4的UDP协议，L4的处理入口为`udp_rcv`，是对`__udp4_lib_rcv`函数的封装，实现如下：

```C
// file: net/ipv4/udp.c
int udp_rcv(struct sk_buff *skb)
{
    return __udp4_lib_rcv(skb, dev_net(skb->dev)->ipv4.udp_table, IPPROTO_UDP);
}
```

`__udp4_lib_rcv`函数实现UDP包的核心接收过程，在获取socket后，检查校验和。实现如下：

```C
// file: net/ipv4/udp.c
int __udp4_lib_rcv(struct sk_buff *skb, struct udp_table *udptable, int proto)
{
    struct rtable *rt = skb_rtable(skb);
    struct net *net = dev_net(skb->dev);
    ...

    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
    // 验证skb，检验skb是否能够包含UDP头部
    if (!pskb_may_pull(skb, sizeof(struct udphdr))) goto drop;

    // 获取UDP头部信息
    uh   = udp_hdr(skb);
    ulen = ntohs(uh->len);
    saddr = ip_hdr(skb)->saddr;
    daddr = ip_hdr(skb)->daddr;

    if (ulen > skb->len) goto short_packet;
    if (proto == IPPROTO_UDP) {
        // UDP验证长度
        if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen)) goto short_packet;
        uh = udp_hdr(skb);
    }
    // 初始化UDP校验和
    if (udp4_csum_init(skb, uh, proto)) goto csum_error;

    // 从skb中获取socket
    sk = skb_steal_sock(skb, &refcounted);
    if (sk) {
        struct dst_entry *dst = skb_dst(skb);
        int ret;
        if (unlikely(rcu_dereference(sk->sk_rx_dst) != dst))
            udp_sk_rx_dst_set(sk, dst);
        ret = udp_unicast_rcv_skb(sk, skb, uh);
        if (refcounted) sock_put(sk);
        return ret;
    }
    // 组播或多播时的接收处理接口
    if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
        return __udp4_lib_mcast_deliver(net, skb, uh, saddr, daddr, udptable, proto);

    // 根据源端口/目的端口确定相应的udp socket
    sk = __udp4_lib_lookup_skb(skb, uh->source, uh->dest, udptable);
    if (sk)
        // 单波的接收处理接口
        return udp_unicast_rcv_skb(sk, skb, uh);
    // XFRM处理
    if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) goto drop;
    nf_reset_ct(skb);

    // 不存在相应的socket时，校验和不正确时静默丢弃skb
    if (udp_lib_checksum_complete(skb)) goto csum_error;

    // 校验和正确，但不存在对应的udp socket时，更新统计信息、发送不可达信息后丢弃skb
    drop_reason = SKB_DROP_REASON_NO_SOCKET;
    __UDP_INC_STATS(net, UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);
    icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

    kfree_skb_reason(skb, drop_reason);
    return 0;

short_packet:
    // skb过短时，丢弃skb
    drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
    net_dbg_ratelimited("UDP%s: short packet: From %pI4:%u %d/%d to %pI4:%u\n", ...);
    goto drop;
csum_error:
    // 校验和不正确时，丢弃skb
    drop_reason = SKB_DROP_REASON_UDP_CSUM;
    net_dbg_ratelimited("UDP%s: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n", ...);
    __UDP_INC_STATS(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_UDPLITE);
drop:
    __UDP_INC_STATS(net, UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);
    kfree_skb_reason(skb, drop_reason);
    return 0;
}
```

#### 4 UDP确定socket的实现过程

`__udp4_lib_lookup_skb`函数根据源/目的端口号确定对应的socket，在获取源地址、目的地址、源端口、目的端口信息后，调用`__udp4_lib_lookup`函数获取socket，如下：

```C
// file: net/ipv4/udp.c
static inline struct sock *__udp4_lib_lookup_skb(struct sk_buff *skb,
            __be16 sport, __be16 dport, struct udp_table *udptable)
{
    const struct iphdr *iph = ip_hdr(skb);
    return __udp4_lib_lookup(dev_net(skb->dev), iph->saddr, sport, iph->daddr, dport, 
                inet_iif(skb), inet_sdif(skb), udptable, skb);
}
```

`__udp4_lib_lookup`函数通过指定地址或任意地址匹配socket，在获取socket的过程中调用`sk_lookup`和`reuseport` BPF程序，如下：

```C
// file: net/ipv4/udp.c
struct sock *__udp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport, __be32 daddr, __be16 dport, 
                            int dif, int sdif, struct udp_table *udptable, struct sk_buff *skb)
{
    unsigned short hnum = ntohs(dport);
    unsigned int hash2, slot2;
    struct udp_hslot *hslot2;
    struct sock *result, *sk;

    // 目的地址、目的端口确定hash值
    hash2 = ipv4_portaddr_hash(net, daddr, hnum);
    slot2 = hash2 & udptable->mask;
    hslot2 = &udptable->hash2[slot2];
    // 查找已链接或特定地址的socket
    result = udp4_lib_lookup2(net, saddr, sport, daddr, hnum, dif, sdif, hslot2, skb);
    if (!IS_ERR_OR_NULL(result) && result->sk_state == TCP_ESTABLISHED)
        goto done;

    // 通过EBPF程序查找socket
    if (static_branch_unlikely(&bpf_sk_lookup_enabled)) {
        sk = udp4_lookup_run_bpf(net, udptable, skb, saddr, sport, daddr, hnum, dif);
        if (sk) { result = sk; goto done; }
    }
    // 获取到特定地址的socket，或者获取出错时，退出查找
    if (result) goto done;

    // 查找任意地址的socket
    hash2 = ipv4_portaddr_hash(net, htonl(INADDR_ANY), hnum);
    slot2 = hash2 & udptable->mask;
    hslot2 = &udptable->hash2[slot2];
    result = udp4_lib_lookup2(net, saddr, sport, htonl(INADDR_ANY), hnum, dif, sdif, hslot2, skb);

done:
    // 出现错误时返回NULL，其他情况返回查找结果
    if (IS_ERR(result)) return NULL;
    return result;
}
```

##### (1) 确定socket的过程

`udp4_lib_lookup2`函数根据源信息和目的信息确定socket，如下：

```C
// file: net/ipv4/udp.c
static struct sock *udp4_lib_lookup2(struct net *net, __be32 saddr, __be16 sport, __be32 daddr, unsigned int hnum,
                        int dif, int sdif, struct udp_hslot *hslot2, struct sk_buff *skb)
{
    struct sock *sk, *result;
    int score, badness;

    result = NULL;
    badness = 0;
    udp_portaddr_for_each_entry_rcu(sk, &hslot2->head) {
        // 计算得分，根据分数情况计算最佳匹配
        score = compute_score(sk, net, saddr, sport, daddr, hnum, dif, sdif);
        if (score > badness) {
            // 超过当前得分时，查找`reuseport`
            result = lookup_reuseport(net, sk, skb, saddr, sport, daddr, hnum);
            // 如果`reuse`组有连接，则回退重新计算得分
            if (result && !reuseport_has_conns(sk)) return result;
            result = result ? : sk;
            badness = score;
        }
    }
    return result;
}
```

`compute_score`函数计算socket的得分，如下：

```C
// file: net/ipv4/udp.c
static int compute_score(struct sock *sk, struct net *net, __be32 saddr, __be16 sport,
                __be32 daddr, unsigned short hnum, int dif, int sdif)
{
    int score;
    struct inet_sock *inet;
    bool dev_match;
    
    // 网络命名空间不同、目的端口不同，则不匹配
    if (!net_eq(sock_net(sk), net) || udp_sk(sk)->udp_port_hash != hnum || 
        ipv6_only_sock(sk))
        return -1;
    // sk的源地址不是skb的目的地址，则不匹配
    if (sk->sk_rcv_saddr != daddr) return -1;
    // 网络协议得分情况，IPV4协议2分，其他(IPV6)协议1分
    score = (sk->sk_family == PF_INET) ? 2 : 1;

    inet = inet_sk(sk);
    // sk目的地址存在时，计算得分情况
    if (inet->inet_daddr) {
        // 和源地址不匹配时，不得分，否则加4分
        if (inet->inet_daddr != saddr) return -1;
        score += 4;
    }
    // sk目的端口存在时，计算得分情况
    if (inet->inet_dport) {
        // 和源端口不匹配时，不得分，否则加4分
        if (inet->inet_dport != sport) return -1;
        score += 4;
    }
    // 检查网卡设备是否匹配
    dev_match = udp_sk_bound_dev_eq(net, sk->sk_bound_dev_if, dif, sdif);
    // 网卡设备不匹配时，不得分。网卡设备绑定网卡时，加4分
    if (!dev_match) return -1;
    if (sk->sk_bound_dev_if) score += 4;

    // 运行在同一个CPU时，加1分
    if (READ_ONCE(sk->sk_incoming_cpu) == raw_smp_processor_id()) score++;
    return score;
}
```

`lookup_reuseport`函数根据`reuseport`查找socket，如下：

```C
// file: net/ipv4/udp.c
static struct sock *lookup_reuseport(struct net *net, struct sock *sk, struct sk_buff *skb,
                    __be32 saddr, __be16 sport, __be32 daddr, unsigned short hnum)
{
    struct sock *reuse_sk = NULL;
    u32 hash;
    // 存在`reuseport`且未连接状态时
    if (sk->sk_reuseport && sk->sk_state != TCP_ESTABLISHED) {
        // 计算hash值
        hash = udp_ehashfn(net, daddr, hnum, saddr, sport);
        // `reuseport`选择socket
        reuse_sk = reuseport_select_sock(sk, hash, skb, sizeof(struct udphdr));
    }
    return reuse_sk;
}
```

##### (2) `reuseport`确定socket

`reuseport_select_sock`函数从`SO_REUSEPORT`组中选择一个socket，如下：

```C
// file: net/core/sock_reuseport.c
struct sock *reuseport_select_sock(struct sock *sk, u32 hash, struct sk_buff *skb, int hdr_len)
{
    struct sock_reuseport *reuse;
    struct bpf_prog *prog;
    struct sock *sk2 = NULL;
    u16 socks;

    rcu_read_lock();
    reuse = rcu_dereference(sk->sk_reuseport_cb);
    if (!reuse) goto out;
    
    // 获取BPF程序和socket的数量 
    prog = rcu_dereference(reuse->prog);
    socks = READ_ONCE(reuse->num_socks);
    if (likely(socks)) {
        smp_rmb();
        if (!prog || !skb) goto select_by_hash;
        
        // 根据BPF程序类型运行不同的BPF程序
        if (prog->type == BPF_PROG_TYPE_SK_REUSEPORT)
            sk2 = bpf_run_sk_reuseport(reuse, sk, prog, skb, NULL, hash);
        else
            sk2 = run_bpf_filter(reuse, socks, prog, skb, hdr_len);

select_by_hash:
        // 不存在BPF程序或者BPF程序返回错误，回退到通过hash选择socket
        if (!sk2)
            sk2 = reuseport_select_sock_by_hash(reuse, hash, socks);
    }
out:
    rcu_read_unlock();
    return sk2;
}
```

`bpf_run_sk_reuseport`函数运行`SK_REUSEPORT`类型的BPF程序，初始化`sk_reuseport_kern`信息后运行BPF程序，如下：

```C
// file: net/core/filter.c
struct sock *bpf_run_sk_reuseport(struct sock_reuseport *reuse, struct sock *sk,
                struct bpf_prog *prog, struct sk_buff *skb, struct sock *migrating_sk, u32 hash)
{
    struct sk_reuseport_kern reuse_kern;
    enum sk_action action;
    // 初始化sk_reuseport_kern信息
    bpf_init_reuseport_kern(&reuse_kern, reuse, sk, skb, migrating_sk, hash);
    // 运行BPF程序
    action = bpf_prog_run(prog, &reuse_kern);
    // PASS的情况，返回选择的socket，否则返回错误信息
    if (action == SK_PASS)
        return reuse_kern.selected_sk;
    else
        return ERR_PTR(-ECONNREFUSED);
}
```

`run_bpf_filter`函数运行`SOCKFILTER`类型的BPF程序，如下：

```C
// file: net/core/sock_reuseport.c
static struct sock *run_bpf_filter(struct sock_reuseport *reuse, u16 socks,
                    struct bpf_prog *prog, struct sk_buff *skb, int hdr_len)
{
    struct sk_buff *nskb = NULL;
    u32 index;
    // skb共享时，复制skb
    if (skb_shared(skb)) {
        nskb = skb_clone(skb, GFP_ATOMIC);
        if (!nskb) return NULL;
        skb = nskb;
    }
    // 临时保留协议头数据
    if (!pskb_pull(skb, hdr_len)) { kfree_skb(nskb); return NULL; }
    // 运行BPF程序，获取索引信息
    index = bpf_prog_run_save_cb(prog, skb);
    // 获取skb头部信息
    __skb_push(skb, hdr_len);
    consume_skb(nskb);

    // 获取socket，超过`reuse`组数量时，返回null
    if (index >= socks) return NULL;
    return reuse->socks[index];
}
```

##### (3) `sk_lookup`确定socket

在通过指定地址时精确查找sock失败时，在设置`sk_lookup` BPF程序时，`udp4_lookup_run_bpf`函数通过BPF程序确定socket，如下：

```C
// file: net/ipv4/udp.c
static struct sock *udp4_lookup_run_bpf(struct net *net, struct udp_table *udptable, struct sk_buff *skb, 
                        __be32 saddr, __be16 sport, __be32 daddr, u16 hnum, const int dif)
{
    struct sock *sk, *reuse_sk;
    bool no_reuseport;
    // 检查udptable是否一致
    if (udptable != net->ipv4.udp_table) return NULL; /* only UDP is supported */
    
    // 运行sk_lookup BPF程序，获取socket
    no_reuseport = bpf_sk_lookup_run_v4(net, IPPROTO_UDP, saddr, sport, daddr, hnum, dif, &sk);
    if (no_reuseport || IS_ERR_OR_NULL(sk)) return sk;

    // 通过`reuseport`确定socket
    reuse_sk = lookup_reuseport(net, sk, skb, saddr, sport, daddr, hnum);
    if (reuse_sk) sk = reuse_sk;
    return sk;
}
```

`bpf_sk_lookup_run_v4`函数通过SK_LOOKUP BPF程序确定socket，如下：

```C
// file: net/ipv4/udp.c
static inline bool bpf_sk_lookup_run_v4(struct net *net, int protocol, const __be32 saddr, const __be16 sport,
                    const __be32 daddr, const u16 dport, const int ifindex, struct sock **psk)
{
    struct bpf_prog_array *run_array;
    struct sock *selected_sk = NULL;
    bool no_reuseport = false;

    rcu_read_lock();
    // 获取SK_LOOKUP BPF程序
    run_array = rcu_dereference(net->bpf.run_array[NETNS_BPF_SK_LOOKUP]);
    if (run_array) {
        // 设置运行上下文
        struct bpf_sk_lookup_kern ctx = {
            .family     = AF_INET,
            .protocol   = protocol,
            .v4.saddr   = saddr,
            .v4.daddr   = daddr,
            .sport      = sport,
            .dport      = dport,
            .ingress_ifindex    = ifindex,
        };
        u32 act;
        // 运行SK_LOOKUP BPF程序，根据返回结果判断后续处理过程
        act = BPF_PROG_SK_LOOKUP_RUN_ARRAY(run_array, ctx, bpf_prog_run);
        if (act == SK_PASS) {
            selected_sk = ctx.selected_sk;
            no_reuseport = ctx.no_reuseport;
        } else {
            selected_sk = ERR_PTR(-ECONNREFUSED);
        }
    }
    rcu_read_unlock();
    *psk = selected_sk;
    return no_reuseport;
}
```

`BPF_PROG_SK_LOOKUP_RUN_ARRAY`宏展开后运行`bpf_prog_run`函数，`SK_LOOKUP` BPF程序运行的返回值为`SK_PASS`和`SK_DROP`，运行`SK_LOOKUP` BPF程序后后续的处理过程如下：

* `SK_PASS && ctx.selected_sk != NULL` ：使用`ctx.selected_sk`作为返回值；
* `SK_PASS && ctx.selected_sk == NULL` ：继续基于`htable`查找socket；
* `SK_DROP`：返回`-ECONNREFUSED`错误；终止后续的查找。
  
### 4.5 `SK_LOOKUP`在TCP的实现过程

#### 1 添加/分离`reuseport`

在使用TCP类型的socket时，通过`bind`系统调用绑定本机地址和端口时，在`listen`系统调用时指定`reuseport`选项，以支持多个进程绑定同一个端口。实现如下：

##### (1) `listen`系统调用

```C
// file: net/socket.c
SYSCALL_DEFINE2(listen, int, fd, int, backlog)
{
    return __sys_listen(fd, backlog);
}
// file: net/socket.c
int __sys_listen(int fd, int backlog)
{
    struct socket *sock;
    int err, fput_needed;
    int somaxconn;
    // 根据fd获取socket
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (sock) {
        // 获取系统级别的全连接队列最大长度，对应`net.core.somaxconn`选项参数
        somaxconn = READ_ONCE(sock_net(sock->sk)->core.sysctl_somaxconn);
        // 队列长度超过系统设置时，使用系统设置的值
        if ((unsigned int)backlog > somaxconn) backlog = somaxconn;
        // LSM安全检查
        err = security_socket_listen(sock, backlog);
        // `listen`接口调用
        if (!err) err = sock->ops->listen(sock, backlog);
        fput_light(sock->file, fput_needed);
    }
    return err;
}
```

TCP协议在内核中的实现如下：

```C
// file: net/ipv4/af_inet.c
static struct inet_protosw inetsw_array[] =
{
    {
        .type =     SOCK_STREAM,
        .protocol = IPPROTO_TCP,
        .prot =     &tcp_prot,
        .ops =      &inet_stream_ops,
        .flags =    INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK,
    },
    ...
};
```

`.ops`操作设置为`inet_stream_ops`，定义如下：

```C
// file: net/ipv4/af_inet.c
const struct proto_ops inet_stream_ops = {
    .family     = PF_INET,
    .owner      = THIS_MODULE,
    .release    = inet_release,
    .bind       = inet_bind,
    ...
    .listen     = inet_listen,
    ...
};
```

`.prot`操作设置为`tcp_prot`，定义如下：

```C
// file: net/ipv4/tcp_ipv4.c
struct proto tcp_prot = {
    .name           = "TCP",
    .owner          = THIS_MODULE,
    .close          = tcp_close,
    ...
    .hash           = inet_hash,
    .unhash         = inet_unhash,
    .get_port       = inet_csk_get_port,
    .put_port       = inet_put_port,
    ...
};
```

`.bind`接口设置为`inet_bind`，其实现过程参见前文。

`.get_port`接口设置为`inet_csk_get_port`，获取绑定的本地端口。

##### (2) 开启监听时添加`reuseport`

`ops->listen`接口设置为`inet_listen`，将socket修改到监听状态，实现如下：

```C
// file: net/ipv4/af_inet.c
int inet_listen(struct socket *sock, int backlog)
{
    struct sock *sk = sock->sk;
    unsigned char old_state;
    int err, tcp_fastopen;

    lock_sock(sk);
    err = -EINVAL;
    // sock状态和类型检查，只支持未连接的TCP socket
    if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM) goto out;
    // sk状态检查，不支持已关闭或监听的socket
    old_state = sk->sk_state;
    if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN))) goto out;
    // 全连接队列长度设置
    WRITE_ONCE(sk->sk_max_ack_backlog, backlog);
    if (old_state != TCP_LISTEN) {
        // TCP_FASTOPEN选项设置，对应`net.core.tcp_fastopen`选项参数
        tcp_fastopen = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_fastopen);
        if ((tcp_fastopen & TFO_SERVER_WO_SOCKOPT1) &&
            (tcp_fastopen & TFO_SERVER_ENABLE) &&
            !inet_csk(sk)->icsk_accept_queue.fastopenq.max_qlen) {
            fastopen_queue_tune(sk, backlog);
            tcp_fastopen_init_key_once(sock_net(sk));
        }
        // 开始sk监听
        err = inet_csk_listen_start(sk);
        if (err) goto out;
        // 调用`BPF_SOCK_OPS`程序
        tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_LISTEN_CB, 0, NULL);
    }
    err = 0;
out:
    release_sock(sk);
    return err;
}
```

`inet_csk_listen_start`函数开始socket监听，实现如下：

```C
// file: net/ipv4/inet_connection_sock.c
int inet_csk_listen_start(struct sock *sk)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct inet_sock *inet = inet_sk(sk);
    int err;
    // 检查sk是否能够监听
    err = inet_ulp_can_listen(sk);
    if (unlikely(err)) return err;
    // 分配全连接队列
    reqsk_queue_alloc(&icsk->icsk_accept_queue);
    // sk初始化，清除全连接数量和ACK信息
    sk->sk_ack_backlog = 0;
    inet_csk_delack_init(sk);

    // 修改sk状态为监听状态
    inet_sk_state_store(sk, TCP_LISTEN);
    // `.get_port`接口获取监听的端口
    err = sk->sk_prot->get_port(sk, inet->inet_num);
    if (!err) {
        inet->inet_sport = htons(inet->inet_num);
        sk_dst_reset(sk);
        // `.hash`接口调用
        err = sk->sk_prot->hash(sk);
        if (likely(!err)) return 0;
    }
    // 失败时，修改为关闭状态
    inet_sk_set_state(sk, TCP_CLOSE);
    return err;
}
```

`.hash`接口设置`inet_hash`，在sk未关闭时进行hash操作，实现如下：

```C
// file: net/ipv4/inet_hashtables.c
int inet_hash(struct sock *sk)
{
    int err = 0;
    if (sk->sk_state != TCP_CLOSE)
        err = __inet_hash(sk, NULL);
    return err;
}
```

`__inet_hash`函数实现具体的操作，实现如下：

```C
// file: net/ipv4/inet_hashtables.c
int __inet_hash(struct sock *sk, struct sock *osk)
{
    struct inet_hashinfo *hashinfo = tcp_or_dccp_get_hashinfo(sk);
    struct inet_listen_hashbucket *ilb2;
    int err = 0;

    if (sk->sk_state != TCP_LISTEN) {
        // 非监听状态的sk，添加tcp连接到hash中
        local_bh_disable();
        inet_ehash_nolisten(sk, osk, NULL);
        local_bh_enable();
        return 0;
    }
    // 监听状态的sk，添加到连接的hash中
    WARN_ON(!sk_unhashed(sk));
    ilb2 = inet_lhash2_bucket_sk(hashinfo, sk);

    spin_lock(&ilb2->lock);
    if (sk->sk_reuseport) {
        // `reuseport`添加sk
        err = inet_reuseport_add_sock(sk, ilb2);
        if (err) goto unlock;
    }
    // 添加到hash列表中
    if (IS_ENABLED(CONFIG_IPV6) && sk->sk_reuseport && 
        sk->sk_family == AF_INET6)
        __sk_nulls_add_node_tail_rcu(sk, &ilb2->nulls_head);
    else
        __sk_nulls_add_node_rcu(sk, &ilb2->nulls_head);
    sock_set_flag(sk, SOCK_RCU_FREE);
    // 添加`sk_prot`使用计数
    sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
unlock:
    spin_unlock(&ilb2->lock);
    return err;
}
```

在开启`reuseport`的情况下，`inet_reuseport_add_sock`函数添加sk到`reuseport`中，如下：

```C
// file: net/ipv4/inet_hashtables.c
static int inet_reuseport_add_sock(struct sock *sk, struct inet_listen_hashbucket *ilb)
{
    struct inet_bind_bucket *tb = inet_csk(sk)->icsk_bind_hash;
    const struct hlist_nulls_node *node;
    struct sock *sk2;
    kuid_t uid = sock_i_uid(sk);

    sk_nulls_for_each_rcu(sk2, node, &ilb->nulls_head) {
        if (sk2 != sk && sk2->sk_family == sk->sk_family &&
            ipv6_only_sock(sk2) == ipv6_only_sock(sk) &&
            sk2->sk_bound_dev_if == sk->sk_bound_dev_if &&
            inet_csk(sk2)->icsk_bind_hash == tb &&
            sk2->sk_reuseport && uid_eq(uid, sock_i_uid(sk2)) &&
            inet_rcv_saddr_equal(sk, sk2, false))
            // 相同组的`reuseport`，添加sock
            return reuseport_add_sock(sk, sk2, inet_rcv_saddr_any(sk));
    }
    // 不同组时，分配`reuseport`
    return reuseport_alloc(sk, inet_rcv_saddr_any(sk));
}
```

##### (3) 停止监听时分离`reuseport`

在关闭socket时，会调用`.unhash`接口，tcp协议的接口设置为`inet_unhash`，实现如下：

```C
// file: net/ipv4/inet_hashtables.c
void inet_unhash(struct sock *sk)
{
    struct inet_hashinfo *hashinfo = tcp_or_dccp_get_hashinfo(sk);
    if (sk_unhashed(sk)) return;

    if (sk->sk_state == TCP_LISTEN) {
        struct inet_listen_hashbucket *ilb2;
        ilb2 = inet_lhash2_bucket_sk(hashinfo, sk);
        spin_lock(&ilb2->lock);
        if (sk_unhashed(sk)) { spin_unlock_bh(lock); return; }
        // 分离reuseport
        if (rcu_access_pointer(sk->sk_reuseport_cb))
            reuseport_stop_listen_sock(sk);
        // 从hash列表中删除sk
        __sk_nulls_del_node_init_rcu(sk);
        sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
        spin_unlock(&ilb2->lock);
    } else {
        spinlock_t *lock = inet_ehash_lockp(hashinfo, sk->sk_hash);
        spin_lock_bh(lock);
        if (sk_unhashed(sk)) { spin_unlock_bh(lock); return; }
        // 从hash列表中删除sk
        __sk_nulls_del_node_init_rcu(sk);
        sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
        spin_unlock_bh(lock);
    }
}
```

监听状态的socket在退出时，会清除设置的`reuseport`信息。`reuseport_stop_listen_sock`函数完成该功能，实现如下：

```C
// file: net/core/sock_reuseport.c
void reuseport_stop_listen_sock(struct sock *sk)
{
    if (sk->sk_protocol == IPPROTO_TCP) {
        struct sock_reuseport *reuse;
        struct bpf_prog *prog;

        spin_lock_bh(&reuseport_lock);
        reuse = rcu_dereference_protected(sk->sk_reuseport_cb, lockdep_is_held(&reuseport_lock));
        prog = rcu_dereference_protected(reuse->prog, lockdep_is_held(&reuseport_lock));

        if (READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_migrate_req) ||
            (prog && prog->expected_attach_type == BPF_SK_REUSEPORT_SELECT_OR_MIGRATE)) {
            // 迁移功能允许时，将sk从监听状态移动到关闭状态
            bpf_sk_reuseport_detach(sk);
            __reuseport_detach_sock(sk, reuse);
            __reuseport_add_closed_sock(sk, reuse);
            
            spin_unlock_bh(&reuseport_lock);
            return;
        }
        spin_unlock_bh(&reuseport_lock);
    }
    // 迁移功能未开启时，直接分离`reuseport`
    reuseport_detach_sock(sk);
}
```

#### 2 TCP数据包的接收实现过程

IPV4协议下TCP网络数据包接收入口为`tcp_v4_rcv`，实现如下：

```C
// file: net/ipv4/tcp_ipv4.c
int tcp_v4_rcv(struct sk_buff *skb)
{
    struct net *net = dev_net(skb->dev);
    enum skb_drop_reason drop_reason;
    int sdif = inet_sdif(skb);
    int dif = inet_iif(skb);
    const struct iphdr *iph;
    const struct tcphdr *th;
    ...
    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
    if (skb->pkt_type != PACKET_HOST) goto discard_it;

    __TCP_INC_STATS(net, TCP_MIB_INSEGS);
    // 保留TCP头部信息
    if (!pskb_may_pull(skb, sizeof(struct tcphdr))) goto discard_it;

    th = (const struct tcphdr *)skb->data;
    // 检查TCP首部信息，不正确时丢弃skb
    if (unlikely(th->doff < sizeof(struct tcphdr) / 4)) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        goto bad_packet;
    }
    // 保留TCP首部信息
    if (!pskb_may_pull(skb, th->doff * 4)) goto discard_it;
    // TCP校验和初始化
    if (skb_checksum_init(skb, IPPROTO_TCP, inet_compute_pseudo))
        goto csum_error;

    th = (const struct tcphdr *)skb->data;
    iph = ip_hdr(skb);
lookup:
    // 查找TCP socket
    sk = __inet_lookup_skb(net->ipv4.tcp_death_row.hashinfo, 
            skb, __tcp_hdrlen(th), th->source, th->dest, sdif, &refcounted);
    // socket不存在时
    if (!sk) goto no_tcp_socket;

process:
    if (sk->sk_state == TCP_TIME_WAIT)
        goto do_time_wait;

    if (sk->sk_state == TCP_NEW_SYN_RECV) {
        struct request_sock *req = inet_reqsk(sk);
        bool req_stolen = false;
        struct sock *nsk;
        
        sk = req->rsk_listener;
        // 检查是否丢弃skb
        if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
            drop_reason = SKB_DROP_REASON_XFRM_POLICY;
        else
            drop_reason = tcp_inbound_md5_hash(sk, skb, 
                    &iph->saddr, &iph->daddr, AF_INET, dif, sdif);
        // drop_reason不为0，丢弃skb
        if (unlikely(drop_reason)) { ... }
        // 校验和不正确时，丢弃skb
        if (tcp_checksum_complete(skb)) { reqsk_put(req); goto csum_error; }

        if (unlikely(sk->sk_state != TCP_LISTEN)) {
            // `reuseport`获取socket
            nsk = reuseport_migrate_sock(sk, req_to_sk(req), skb);
            if (!nsk) {
                inet_csk_reqsk_queue_drop_and_put(sk, req);
                goto lookup;
            }
            sk = nsk;
        } else {
            sock_hold(sk);
        }
        refcounted = true;
        nsk = NULL;
        ...
    }
    ...
}
```

#### 3 TCP确定socket的实现过程

`__inet_lookup_skb`函数根据源/目的端口号确定对应的socket，在获取源地址、目的地址、源端口、目的端口信息后，调用`__inet_lookup`函数获取socket，如下：

```C
// file: include/net/inet_hashtables.h
static inline struct sock *__inet_lookup_skb(struct inet_hashinfo *hashinfo, struct sk_buff *skb, 
        int doff, const __be16 sport, const __be16 dport, const int sdif, bool *refcounted)
{
    struct sock *sk = skb_steal_sock(skb, refcounted);
    const struct iphdr *iph = ip_hdr(skb);
    // skb中存在sk时，返回
    if (sk) return sk;

    return __inet_lookup(dev_net(skb_dst(skb)->dev), hashinfo, skb,
        doff, iph->saddr, sport, iph->daddr, dport, inet_iif(skb), sdif, refcounted);
}
```

`__inet_lookup`函数从已连接的队列或监听的队列中查找关联的socket，实现如下：

```C
// file: include/net/inet_hashtables.h
static inline struct sock *__inet_lookup(struct net *net, struct inet_hashinfo *hashinfo,
            struct sk_buff *skb, int doff, const __be32 saddr, const __be16 sport, const __be32 daddr, 
            const __be16 dport, const int dif, const int sdif, bool *refcounted)
{
    u16 hnum = ntohs(dport);
    struct sock *sk;
    // 查找已连接的socket，遍历hash表，根据源/目的地址和端口查找
    sk = __inet_lookup_established(net, hashinfo, saddr, sport, daddr, hnum, dif, sdif);
    *refcounted = true;
    if (sk) return sk;

    // 查找监听的socket
    *refcounted = false;
    return __inet_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, hnum, dif, sdif);
}
```

##### (1) 确定监听socket的过程

`__inet_lookup_listener`函数查找监听的socket，实现如下：

```C
// file: net/ipv4/inet_hashtables.c
struct sock *__inet_lookup_listener(struct net *net, struct inet_hashinfo *hashinfo, 
            struct sk_buff *skb, int doff, const __be32 saddr, __be16 sport, 
            const __be32 daddr, const unsigned short hnum, const int dif, const int sdif)
{
    struct inet_listen_hashbucket *ilb2;
    struct sock *result = NULL;
    unsigned int hash2;

    // 从BPF程序中直接查找
    if (static_branch_unlikely(&bpf_sk_lookup_enabled)) {
        result = inet_lookup_run_bpf(net, hashinfo, skb, doff, saddr, sport, daddr, hnum, dif);
        if (result) goto done;
    }

    // 根据指定的地址和端口确定socket
    hash2 = ipv4_portaddr_hash(net, daddr, hnum);
    ilb2 = inet_lhash2_bucket(hashinfo, hash2);
    result = inet_lhash2_lookup(net, ilb2, skb, doff, saddr, sport, daddr, hnum, dif, sdif);
    if (result) goto done;

    // 根据任意地址和端口确定socket
    hash2 = ipv4_portaddr_hash(net, htonl(INADDR_ANY), hnum);
    ilb2 = inet_lhash2_bucket(hashinfo, hash2);
    result = inet_lhash2_lookup(net, ilb2, skb, doff, saddr, sport, htonl(INADDR_ANY), hnum, dif, sdif);
done:
    if (IS_ERR(result)) return NULL;
    return result;
}
```

##### (2) `sk_lookup`确定监听的socket

`inet_lookup_run_bpf`函数运行BPF程序查找socket，实现如下：

```C
// file: net/ipv4/inet_hashtables.c
static inline struct sock *inet_lookup_run_bpf(struct net *net, struct inet_hashinfo *hashinfo,
            struct sk_buff *skb, int doff, __be32 saddr, __be16 sport, 
            __be32 daddr, u16 hnum, const int dif)
{
    struct sock *sk, *reuse_sk;
    bool no_reuseport;
    // 检查是否为TCP连接
    if (hashinfo != net->ipv4.tcp_death_row.hashinfo) return NULL;
    // 运行`sk_lookup` BPF程序
    no_reuseport = bpf_sk_lookup_run_v4(net, IPPROTO_TCP, saddr, sport, daddr, hnum, dif, &sk);
    if (no_reuseport || IS_ERR_OR_NULL(sk)) return sk;
    // 运行`reuseport` BPF程序
    reuse_sk = lookup_reuseport(net, sk, skb, doff, saddr, sport, daddr, hnum);
    if (reuse_sk) sk = reuse_sk;
    return sk;
}
```

##### (3) `reuseport`确定监听的socket

`inet_lhash2_lookup`函数计算得分情况后，运行`reuseport`BPF程序，如下：

```C
// file: net/ipv4/inet_hashtables.c
static struct sock *inet_lhash2_lookup(struct net *net, struct inet_listen_hashbucket *ilb2,
                struct sk_buff *skb, int doff, const __be32 saddr, __be16 sport,
                const __be32 daddr, const unsigned short hnum, const int dif, const int sdif)
{
    struct sock *sk, *result = NULL;
    struct hlist_nulls_node *node;
    int score, hiscore = 0;

    sk_nulls_for_each_rcu(sk, node, &ilb2->nulls_head) {
        // 计算得分情况
        score = compute_score(sk, net, hnum, daddr, dif, sdif);
        if (score > hiscore) {
            // 运行`reuseport`BPF程序
            result = lookup_reuseport(net, sk, skb, doff, saddr, sport, daddr, hnum);
            if (result) return result;
            result = sk;
            hiscore = score;
        }
    }
    return result;
}
```

`compute_score`函数计算TCP连接的得分情况，参与计算的属性包括：绑定的网卡、网络协议、当前CPU等。如下：

```C
// file: net/ipv4/inet_hashtables.c
static inline int compute_score(struct sock *sk, struct net *net, 
                const unsigned short hnum, const __be32 daddr, const int dif, const int sdif)
{
    int score = -1;
    if (net_eq(sock_net(sk), net) && sk->sk_num == hnum && !ipv6_only_sock(sk)) {
        // 源地址不同时返回错误
        if (sk->sk_rcv_saddr != daddr) return -1;
        // 绑定的网卡不同时返回错误
        if (!inet_sk_bound_dev_eq(net, sk->sk_bound_dev_if, dif, sdif)) return -1;
        // 存在绑定设备时，得两分
        score =  sk->sk_bound_dev_if ? 2 : 1;
        // ipv4加一分
        if (sk->sk_family == PF_INET) score++;
        // skb在同一个CPU上加一分
        if (READ_ONCE(sk->sk_incoming_cpu) == raw_smp_processor_id()) score++;
    }
    return score;
}
```

`lookup_reuseport`函数查找reuseport的socket，实现如下：

```C
// file: net/ipv4/inet_hashtables.c
static inline struct sock *lookup_reuseport(struct net *net, struct sock *sk, struct sk_buff *skb, int doff,
                        __be32 saddr, __be16 sport, __be32 daddr, unsigned short hnum)
{
    struct sock *reuse_sk = NULL;
    u32 phash;
    if (sk->sk_reuseport) {
        // 计算源/目的信息的连接hash值
        phash = inet_ehashfn(net, daddr, hnum, saddr, sport);
        reuse_sk = reuseport_select_sock(sk, phash, skb, doff);
    }
    return reuse_sk;
}
```

##### (4) 确定普通socket的过程

`reuseport_migrate_sock`函数从`SO_REUSEPORT`组中选择socket，实现如下：

```C
// file: net/core/sock_reuseport.c
struct sock *reuseport_migrate_sock(struct sock *sk, struct sock *migrating_sk, struct sk_buff *skb)
{
    struct sock_reuseport *reuse;
    struct sock *nsk = NULL;
    bool allocated = false;
    struct bpf_prog *prog;
    ...

    rcu_read_lock();
    // 获取`reuseport`设置
    reuse = rcu_dereference(sk->sk_reuseport_cb);
    if (!reuse) goto out;
    // 没有关联sockets时退出
    socks = READ_ONCE(reuse->num_socks);
    if (unlikely(!socks)) goto failure;

    smp_rmb();
    hash = migrating_sk->sk_hash;
    // 检查BPF程序类型
    prog = rcu_dereference(reuse->prog);
    if (!prog || prog->expected_attach_type != BPF_SK_REUSEPORT_SELECT_OR_MIGRATE) {
        // BPF程序类型不匹配时，ipv4迁移TCP请求
        if (READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_migrate_req)) goto select_by_hash;
        goto failure;
    }
    // skb不存在时，分配空的skb
    if (!skb) { skb = alloc_skb(0, GFP_ATOMIC); ... }
    // 运行`SK_REUSEPORT` BPF程序
    nsk = bpf_run_sk_reuseport(reuse, sk, prog, skb, migrating_sk, hash);
    // 释放分配的skb
    if (allocated) kfree_skb(skb);

select_by_hash:
    // 未找到sk时，通过hash确定socket
    if (!nsk) nsk = reuseport_select_sock_by_hash(reuse, hash, socks);
    // 增加查找结果的引用计数
    if (IS_ERR_OR_NULL(nsk) || unlikely(!refcount_inc_not_zero(&nsk->sk_refcnt))) {
        nsk = NULL;
        goto failure;
    }
out:
    rcu_read_unlock();
    return nsk;
failure:
    // 失败时，增加统计计数
    __NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMIGRATEREQFAILURE);
    goto out;
}
```

## 5 总结

本文通过内核中的`sk_lookup`示例程序分析了Linux内核使用BPF确定TCP监听的socket、UDP连接的socket，通过可编程的方式解决无法通过`bind`调用将套接字绑定到地址的设置场景。

## 参考资料

* [Linux Kernel Selftests](https://www.kernel.org/doc/html/latest/dev-tools/kselftest.html)
* [BPF sk_lookup program](https://www.kernel.org/doc/html/latest/bpf/prog_sk_lookup.html)
* [Socket listen 多地址需求与 SK_LOOKUP BPF 的诞生](https://arthurchiao.art/blog/birth-of-sk-lookup-bpf-zh/)