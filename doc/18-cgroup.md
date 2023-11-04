# CGROUP_BPF的内核实现

## 0 前言

在前几篇文章中在分析网络相关的实现过程中，我们接触了`CGROUP`相关内容。今天，我们借助`cgroup_link`示例程序分析BPF在cgroup中的应用。

## 1 简介

`cgroup`(`control group`)是Linux内核提供的物理资源隔离机制，通过这种机制，可以实现对Linux进程或者进程组的资源限制、隔离和统计功能。Linux内核针对cgroup提供了丰富的BPF控制功能，实现在cgroup级别对进程、socket、设备文件 （device file）等进行动态控制。

## 2 `cgroup_link`示例程序

### 2.1 BPF程序

BPF程序源码参见[test_cgroup_link.c](../src/test_cgroup_link.c)，主要内容如下：

```C
int calls = 0;
int alt_calls = 0;

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb)
{
    __sync_fetch_and_add(&calls, 1);
    return 1;
}
SEC("cgroup_skb/egress")
int egress_alt(struct __sk_buff *skb)
{
    __sync_fetch_and_add(&alt_calls, 1);
    return 1;
}
```

该程序包括2个BPF程序 `egress` 和 `egress_alt` ，使用 `cgroup_skb` 前缀。

### 2.2 用户程序

用户程序源码参见[cgroup_link.c](../src/cgroup_link.c)，主要内容如下：

#### 1 附加BPF程序

```C
void serial_test_cgroup_link(void)
{
    struct {
        const char *path;
        int fd;
    } cgs[] = {
        { "/cg1" },
        { "/cg1/cg2" },
        { "/cg1/cg2/cg3" },
        { "/cg1/cg2/cg3/cg4" },
    };
    int last_cg = ARRAY_SIZE(cgs) - 1, cg_nr = ARRAY_SIZE(cgs);
    DECLARE_LIBBPF_OPTS(bpf_link_update_opts, link_upd_opts);
    struct bpf_link *links[ARRAY_SIZE(cgs)] = {}, *tmp_link;
    // 打开并加载BPF程序
    skel = test_cgroup_link__open_and_load();
    // 获取`egress`程序fd
    prog_fd = bpf_program__fd(skel->progs.egress);
    // 设置cgroup环境
    err = setup_cgroup_environment();
    // 创建并获取cgroup
    for (i = 0; i < cg_nr; i++) {
        cgs[i].fd = create_and_get_cgroup(cgs[i].path);
    }
    // 加入cgroup
    err = join_cgroup(cgs[last_cg].path);
    ...
    // 传统方式附加cgroup BPF程序
    err = bpf_prog_attach(prog_fd, cgs[last_cg].fd, BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI);
    ...
    // link方式附加cgroup BPF程序
    links[last_cg] = bpf_program__attach_cgroup(skel->progs.egress, cgs[last_cg].fd);

    // 测试
    ping_and_check(cg_nr + 1, 0);

    // 分离link
    bpf_link__destroy(links[last_cg]);
    links[last_cg] = NULL;
    // 传统方式分离cgroup BPF程序
    err = bpf_prog_detach2(prog_fd, cgs[last_cg].fd, BPF_CGROUP_INET_EGRESS);
    ...
}
```

#### 2 读取数据过程

`egress` 和 `egress_alt` BPF程序将采集的数据通过全局变量方式传递，用户空间程序读取这些全局变量。

### 2.3 编译运行

`cgroup_link`程序也是Linux内核自带的测试程序，在`tools/testing/selftests/bpf/prog_tests/`目录下。编译后运行，如下：

```bash
$ cd tools/testing/selftests/bpf/
$ sudo make
$ sudo ./test_progs -t cgroup_link -vvv
bpf_testmod.ko is already unloaded.
Loading bpf_testmod.ko...
Failed to load bpf_testmod.ko into the kernel: -8
WARNING! Selftests relying on bpf_testmod.ko will be skipped.
libbpf: loading object 'test_cgroup_link' from buffer
....
serial_test_cgroup_link:PASS:skel_open_load 0 nsec
serial_test_cgroup_link:PASS:cg_init 0 nsec
serial_test_cgroup_link:PASS:cg_create 0 nsec
...
serial_test_cgroup_link:PASS:cg_join 0 nsec
serial_test_cgroup_link:PASS:cg_attach 0 nsec
...
ping_and_check:PASS:call_cnt 0 nsec
ping_and_check:PASS:alt_call_cnt 0 nsec
ping_and_check:PASS:call_cnt 0 nsec
ping_and_check:PASS:alt_call_cnt 0 nsec
#38      cgroup_link:OK
Summary: 1/0 PASSED, 0 SKIPPED, 0 FAILED
```

## 3 cgroup附加BPF的过程

`cgroup`支持多种前缀类型的bpf程序，libbpf中支持cgroup BPF程序如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("lsm_cgroup+",          LSM, BPF_LSM_CGROUP, SEC_ATTACH_BTF),
    SEC_DEF("sockops",              SOCK_OPS, BPF_CGROUP_SOCK_OPS, SEC_ATTACHABLE_OPT),
    SEC_DEF("cgroup_skb/ingress",   CGROUP_SKB, BPF_CGROUP_INET_INGRESS, SEC_ATTACHABLE_OPT),
    SEC_DEF("cgroup_skb/egress",    CGROUP_SKB, BPF_CGROUP_INET_EGRESS, SEC_ATTACHABLE_OPT),
    SEC_DEF("cgroup/skb",           CGROUP_SKB, 0, SEC_NONE),
    SEC_DEF("cgroup/sock_create",   CGROUP_SOCK, BPF_CGROUP_INET_SOCK_CREATE, SEC_ATTACHABLE),
    SEC_DEF("cgroup/sock_release",  CGROUP_SOCK, BPF_CGROUP_INET_SOCK_RELEASE, SEC_ATTACHABLE),
    SEC_DEF("cgroup/sock",          CGROUP_SOCK, BPF_CGROUP_INET_SOCK_CREATE, SEC_ATTACHABLE_OPT),
    SEC_DEF("cgroup/post_bind4",    CGROUP_SOCK, BPF_CGROUP_INET4_POST_BIND, SEC_ATTACHABLE),
    SEC_DEF("cgroup/post_bind6",    CGROUP_SOCK, BPF_CGROUP_INET6_POST_BIND, SEC_ATTACHABLE),
    SEC_DEF("cgroup/bind4",         CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_BIND, SEC_ATTACHABLE),
    SEC_DEF("cgroup/bind6",         CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_BIND, SEC_ATTACHABLE),
    SEC_DEF("cgroup/connect4",      CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT, SEC_ATTACHABLE),
    SEC_DEF("cgroup/connect6",      CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_CONNECT, SEC_ATTACHABLE),
    SEC_DEF("cgroup/sendmsg4",      CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_SENDMSG, SEC_ATTACHABLE),
    SEC_DEF("cgroup/sendmsg6",      CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_SENDMSG, SEC_ATTACHABLE),
    SEC_DEF("cgroup/recvmsg4",      CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_RECVMSG, SEC_ATTACHABLE),
    SEC_DEF("cgroup/recvmsg6",      CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_RECVMSG, SEC_ATTACHABLE),
    SEC_DEF("cgroup/getpeername4",  CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_GETPEERNAME, SEC_ATTACHABLE),
    SEC_DEF("cgroup/getpeername6",  CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_GETPEERNAME, SEC_ATTACHABLE),
    SEC_DEF("cgroup/getsockname4",  CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_GETSOCKNAME, SEC_ATTACHABLE),
    SEC_DEF("cgroup/getsockname6",  CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_GETSOCKNAME, SEC_ATTACHABLE),
    SEC_DEF("cgroup/sysctl",        CGROUP_SYSCTL, BPF_CGROUP_SYSCTL, SEC_ATTACHABLE),
    SEC_DEF("cgroup/getsockopt",    CGROUP_SOCKOPT, BPF_CGROUP_GETSOCKOPT, SEC_ATTACHABLE),
    SEC_DEF("cgroup/setsockopt",    CGROUP_SOCKOPT, BPF_CGROUP_SETSOCKOPT, SEC_ATTACHABLE),
    SEC_DEF("cgroup/dev",           CGROUP_DEVICE, BPF_CGROUP_DEVICE, SEC_ATTACHABLE_OPT),
    ...
};
```

cgroup BPF程序都不支持自动附加，需要手动附加。

### 3.1 传统方式附加和分离

传统方式附加cgroup BPF程序时，通过`bpf_prog_attach`函数实现，设置`opts->flags`后调用`bpf_prog_attach_opts`，如下：

```C
// file: libbpf/src/bpf.c
int bpf_prog_attach(int prog_fd, int target_fd, enum bpf_attach_type type, unsigned int flags)
{
    DECLARE_LIBBPF_OPTS(bpf_prog_attach_opts, opts, .flags = flags, );
    return bpf_prog_attach_opts(prog_fd, target_fd, type, &opts);
}
```

`bpf_prog_attach_opts` 函数实现BPF程序的附加，如下：

```C
// file: libbpf/src/bpf.c
int bpf_prog_attach_opts(int prog_fd, int target_fd, enum bpf_attach_type type,
        const struct bpf_prog_attach_opts *opts)
{
    const size_t attr_sz = offsetofend(union bpf_attr, replace_bpf_fd);
    union bpf_attr attr;
    int ret;
    // 检查opts是否有效
    if (!OPTS_VALID(opts, bpf_prog_attach_opts)) return libbpf_err(-EINVAL);
    // 设置bpf系统调用的属性
    memset(&attr, 0, attr_sz);
    attr.target_fd = target_fd;
    attr.attach_bpf_fd = prog_fd;
    attr.attach_type   = type;
    attr.attach_flags  = OPTS_GET(opts, flags, 0);
    attr.replace_bpf_fd = OPTS_GET(opts, replace_prog_fd, 0);
    // BPF系统调用，使用`BPF_PROG_ATTACH`指令
    ret = sys_bpf(BPF_PROG_ATTACH, &attr, attr_sz);
    return libbpf_err_errno(ret);
}
```

`bpf_prog_detach2` 函数实现cgroup BPF程序的分离，如下：

```C
// file: libbpf/src/bpf.c
int bpf_prog_detach2(int prog_fd, int target_fd, enum bpf_attach_type type)
{
    const size_t attr_sz = offsetofend(union bpf_attr, replace_bpf_fd);
    union bpf_attr attr;
    int ret;
    // 设置bpf系统调用的属性
    memset(&attr, 0, attr_sz);
    attr.target_fd = target_fd;
    attr.attach_bpf_fd = prog_fd;
    attr.attach_type = type;
    // BPF系统调用，使用`BPF_PROG_DETACH`指令
    ret = sys_bpf(BPF_PROG_DETACH, &attr, attr_sz);
    return libbpf_err_errno(ret);
}
```

### 3.2 Link方式附加

`bpf_program__attach_cgroup` 函数通过link方式附加cgroup BPF程序。实现过程如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link *
bpf_program__attach_cgroup(const struct bpf_program *prog, int cgroup_fd)
{
    return bpf_program__attach_fd(prog, cgroup_fd, 0, "cgroup");
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
    default:
        // 默认附加类型
        if (!OPTS_ZEROED(opts, flags)) return libbpf_err(-EINVAL);
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

`bpf_link__destroy`函数实现link的销毁，在销毁的过程中分离bpf程序。

## 4 内核实现

### 4.1 附加CGROUP_BPF程序

#### 1 传统方式附加

##### (1) BPF系统调用

传统方式使用`BPF_PROG_ATTACH` BPF系统调用，如下：

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
    case BPF_PROG_ATTACH: err = bpf_prog_attach(&attr); break;
    ...
    }
    return err;
}
```

##### (2) `BPF_PROG_ATTACH`

`bpf_prog_attach` 在检查BPF程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。cgroup类型的bpf程序, 对应 `cgroup_bpf_prog_attach` 处理函数。如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_prog_attach(const union bpf_attr *attr)
{
    enum bpf_prog_type ptype;
    struct bpf_prog *prog;
    int ret;

    // 检查bpf_attr属性
    if (CHECK_ATTR(BPF_PROG_ATTACH)) return -EINVAL;
    if (attr->attach_flags & ~BPF_F_ATTACH_MASK) return -EINVAL;

    // 获取附加程序类型
    ptype = attach_type_to_prog_type(attr->attach_type);
    if (ptype == BPF_PROG_TYPE_UNSPEC) return -EINVAL;
    
    // 获取 bpf_prog
    prog = bpf_prog_get_type(attr->attach_bpf_fd, ptype);
    if (IS_ERR(prog)) return PTR_ERR(prog);
    
    // 检查 PROG_TYPE 和 expected_attach_type 是否匹配
    if (bpf_prog_attach_check_attach_type(prog, attr->attach_type)) { ... }

    switch (ptype) {
    ...
    case BPF_PROG_TYPE_CGROUP_DEVICE:
    case BPF_PROG_TYPE_CGROUP_SKB:
    case BPF_PROG_TYPE_CGROUP_SOCK:
    case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
    case BPF_PROG_TYPE_CGROUP_SOCKOPT:
    case BPF_PROG_TYPE_CGROUP_SYSCTL:
    case BPF_PROG_TYPE_SOCK_OPS:
    case BPF_PROG_TYPE_LSM:
        // bpf程序类型检查，`LSM`程序的附加类型为`BPF_LSM_CGROUP`
        if (ptype == BPF_PROG_TYPE_LSM && prog->expected_attach_type != BPF_LSM_CGROUP)
            ret = -EINVAL;
        else
            // 附加到cgroup
            ret = cgroup_bpf_prog_attach(attr, ptype, prog);
        break;
    default:
        ret = -EINVAL;
    }
    // 附加失败时，释放bpf程序
    if (ret) bpf_prog_put(prog);
    return ret;
}
```

`cgroup_bpf_prog_attach` 函数实现bpf程序附加到cgroup，实现如下：

```C
// file: kernel/bpf/cgroup.c
int cgroup_bpf_prog_attach(const union bpf_attr *attr, enum bpf_prog_type ptype, struct bpf_prog *prog)
{
    struct bpf_prog *replace_prog = NULL;
    struct cgroup *cgrp;
    int ret;

    // 获取cgroup
    cgrp = cgroup_get_from_fd(attr->target_fd);
    if (IS_ERR(cgrp)) return PTR_ERR(cgrp);

    // 检查cgroup是否替换之前附加的bpf程序
    if ((attr->attach_flags & BPF_F_ALLOW_MULTI) && (attr->attach_flags & BPF_F_REPLACE)) {
        // 获取替换的bpf程序
        replace_prog = bpf_prog_get_type(attr->replace_bpf_fd, ptype);
        if (IS_ERR(replace_prog)) { cgroup_put(cgrp); return PTR_ERR(replace_prog); }
    }
    // 附加bpf程序到cgroup
    ret = cgroup_bpf_attach(cgrp, prog, replace_prog, NULL, attr->attach_type, attr->attach_flags);
    
    // 释放之前的bpf程序和cgroup
    if (replace_prog) bpf_prog_put(replace_prog);
    cgroup_put(cgrp);
    return ret;
}
```

#### 2 Link方式附加

##### (1) BPF系统调用

Link方式附加使用`BPF_LINK_CREATE` BPF系统调用，如下：

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

##### (2) `BPF_LINK_CREATE`

`link_create` 在检查BPF程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 cgroup类型的bpf程序, 对应 `cgroup_bpf_link_attach` 处理函数。如下：

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
    case BPF_PROG_TYPE_CGROUP_SKB:
    case BPF_PROG_TYPE_CGROUP_SOCK:
    case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
    case BPF_PROG_TYPE_SOCK_OPS:
    case BPF_PROG_TYPE_CGROUP_DEVICE:
    case BPF_PROG_TYPE_CGROUP_SYSCTL:
    case BPF_PROG_TYPE_CGROUP_SOCKOPT:
        ret = cgroup_bpf_link_attach(attr, prog);
        break;
    ...
    }
    ...
}
```

##### (3) `cgroup_bpf_link_attach`

`cgroup_bpf_link_attach` 函数检查用户输入的参数信息，获取cgroup后，设置 `cgroup_link` 的信息后，附加bpf程序。如下：

```C
// file: kernel/bpf/cgroup.c
int cgroup_bpf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    struct bpf_link_primer link_primer;
    struct bpf_cgroup_link *link;
    struct cgroup *cgrp;
    int err;

    // 不支持用户设置flags
    if (attr->link_create.flags) return -EINVAL;
    // 获取cgroup
    cgrp = cgroup_get_from_fd(attr->link_create.target_fd);
    if (IS_ERR(cgrp)) return PTR_ERR(cgrp);

    // 创建 link
    link = kzalloc(sizeof(*link), GFP_USER);
    if (!link) { ... }

    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_CGROUP, &bpf_cgroup_link_lops, prog);
    link->cgroup = cgrp;
    link->type = attr->link_create.attach_type;

    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    if (err) { ... }
    
    // 附加bpf程序到cgroup
    err = cgroup_bpf_attach(cgrp, NULL, NULL, link, link->type, BPF_F_ALLOW_MULTI);
    if (err) { ... }
    // fd 和 file 进行关联
    return bpf_link_settle(&link_primer);

out_put_cgroup:
    cgroup_put(cgrp);
    return err;
}
```

#### 3 注册BPF程序

`cgroup_bpf_attach` 函数实现BPF附加到cgroup中，是对`__cgroup_bpf_attach`函数的调用封装，如下：

```C
// file: kernel/bpf/cgroup.c
static int cgroup_bpf_attach(struct cgroup *cgrp, struct bpf_prog *prog, struct bpf_prog *replace_prog,
            struct bpf_cgroup_link *link, enum bpf_attach_type type, u32 flags)
{
    int ret;
    mutex_lock(&cgroup_mutex);
    ret = __cgroup_bpf_attach(cgrp, prog, replace_prog, link, type, flags);
    mutex_unlock(&cgroup_mutex);
    return ret;
}
```

`__cgroup_bpf_attach` 函数实现cgroup和BPF程序的关联，如下：

```C
// file: kernel/bpf/cgroup.c
static int __cgroup_bpf_attach(struct cgroup *cgrp, struct bpf_prog *prog, struct bpf_prog *replace_prog,
            struct bpf_cgroup_link *link, enum bpf_attach_type type, u32 flags)
{
    // 保存标志
    u32 saved_flags = (flags & (BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI));
    struct bpf_prog *old_prog = NULL;
    // 存储方式(storage)，支持`SHARED`和`PERCPU`两种类型
    struct bpf_cgroup_storage *storage[MAX_BPF_CGROUP_STORAGE_TYPE] = {};
    struct bpf_cgroup_storage *new_storage[MAX_BPF_CGROUP_STORAGE_TYPE] = {};
    // 附加的bpf程序
    struct bpf_prog *new_prog = prog ? : link->link.prog;
    enum cgroup_bpf_attach_type atype;
    struct bpf_prog_list *pl;
    struct hlist_head *progs;
    int err;

    // 检查flags的组合是否合法
    if (((flags & BPF_F_ALLOW_OVERRIDE) && (flags & BPF_F_ALLOW_MULTI)) ||
        ((flags & BPF_F_REPLACE) && !(flags & BPF_F_ALLOW_MULTI)))
        return -EINVAL;
    // link方式不能替换bpf程序
    if (link && (prog || replace_prog)) return -EINVAL;
    // 替换bpf程序时，隐含BPF_F_REPLACE标记
    if (!!replace_prog != !!(flags & BPF_F_REPLACE)) return -EINVAL;

    // 获取附加类型，LSM_GROUP支持`CGROUP_LSM_NUM`(10)种类型，其他类型一一对应
    atype = bpf_cgroup_atype_find(type, new_prog->aux->attach_btf_id);
    if (atype < 0) return -EINVAL;
    // 获取附加类型对应的附加程序列表
    progs = &cgrp->bpf.progs[atype];

    // 层次性检查，如果父级附加了不可覆盖的程序，不允许将新程序附加到后代 cgroup。
    // 如果父级具有可覆盖或支持多个程序，则允许附加
    if (!hierarchy_allows_attach(cgrp, atype)) return -EPERM;
    // cgroup存在bpf程序时，检查是否支持覆盖和多程序标记
    if (!hlist_empty(progs) && cgrp->bpf.flags[atype] != saved_flags) return -EPERM;
    // bpf数量检查，同一种类型数据不能超过`BPF_CGROUP_MAX_PROGS`(64)个
    if (prog_list_length(progs) >= BPF_CGROUP_MAX_PROGS) return -E2BIG;

    // 获取附加的cgroup程序的位置
    pl = find_attach_entry(progs, prog, link, replace_prog, flags & BPF_F_ALLOW_MULTI);
    if (IS_ERR(pl)) return PTR_ERR(pl);

    // bpf程序关联`CGROUP_STORAGE`和`PERCPU_CGROUP_STORAGE`类型map时，获取存储方式
    if (bpf_cgroup_storages_alloc(storage, new_storage, type, prog ? : link->link.prog, cgrp))
        return -ENOMEM;

    if (pl) {
        // pl存在时，使用之前的位置
        old_prog = pl->prog;
    } else {
        // pl不存在时，创建新的pl，添加到progs的最后
        struct hlist_node *last = NULL;
        pl = kmalloc(sizeof(*pl), GFP_KERNEL);
        if (!pl) { bpf_cgroup_storages_free(new_storage); return -ENOMEM; }
        if (hlist_empty(progs))
            hlist_add_head(&pl->node, progs);
        else
            hlist_for_each(last, progs) {
                if (last->next) continue;
                hlist_add_behind(&pl->node, last);
                break;
            }
    }
    // pl属性设置
    pl->prog = prog;
    pl->link = link;
    bpf_cgroup_storages_assign(pl->storage, storage);
    cgrp->bpf.flags[atype] = saved_flags;

    if (type == BPF_LSM_CGROUP) {
        // `BPF_LSM_CGROUP`类型时，使用`bpf_shim_tramp_link`关联`bpf_trampoline`
        // 创建新的bpf程序后设置LSM
        err = bpf_trampoline_link_cgroup_shim(new_prog, atype);
        if (err) goto cleanup;
    }

    // 更新有效的bpf程序
    err = update_effective_progs(cgrp, atype);
    if (err) goto cleanup_trampoline;

    if (old_prog) {
        // 存在旧的程序时，释放
        if (type == BPF_LSM_CGROUP) bpf_trampoline_unlink_cgroup_shim(old_prog);
        bpf_prog_put(old_prog);
    } else {
        // 不存在时，增加启用计数
        static_branch_inc(&cgroup_bpf_enabled_key[atype]);
    }
    // cgroup和storage关联
    bpf_cgroup_storages_link(new_storage, cgrp, type);
    return 0;

cleanup_trampoline:
    // 清理`LSM_CGROUP`程序
    if (type == BPF_LSM_CGROUP)
        bpf_trampoline_unlink_cgroup_shim(new_prog);

cleanup:
    if (old_prog) {
        pl->prog = old_prog;
        pl->link = NULL;
    }
    bpf_cgroup_storages_free(new_storage);
    if (!old_prog) {
        hlist_del(&pl->node);
        kfree(pl);
    }
    return err;
}
```

`update_effective_progs` 函数更新cgroup有效bpf程序，释放旧的程序。如下：

```C
// file: kernel/bpf/cgroup.c
static int update_effective_progs(struct cgroup *cgrp, enum cgroup_bpf_attach_type atype)
{
    struct cgroup_subsys_state *css;
    int err;
    // 重新计算和分配有效的bpf程序列表
    css_for_each_descendant_pre(css, &cgrp->self) {
        struct cgroup *desc = container_of(css, struct cgroup, self);
        if (percpu_ref_is_zero(&desc->bpf.refcnt)) continue;
        // 重新计算有效程序，设置到未启用列表(`inactive`)中
        err = compute_effective_progs(desc, atype, &desc->bpf.inactive);
        if (err) goto cleanup;
    }
    // 启用bpf程序列表
    css_for_each_descendant_pre(css, &cgrp->self) {
        struct cgroup *desc = container_of(css, struct cgroup, self);
        
        if (percpu_ref_is_zero(&desc->bpf.refcnt)) {
            // 引用计数为0时，释放未启用的程序列表
            if (unlikely(desc->bpf.inactive)) {
                bpf_prog_array_free(desc->bpf.inactive);
                desc->bpf.inactive = NULL;
            }
            continue;
        }
        // 将未启用的(`inactive`)程序设置为有效(`effective`),释放之前有效的bpf程序
        activate_effective_progs(desc, atype, desc->bpf.inactive);
        desc->bpf.inactive = NULL;
    }
    return 0;
cleanup:
    // 出现错误时，释放未启用的程序列表
    css_for_each_descendant_pre(css, &cgrp->self) {
        struct cgroup *desc = container_of(css, struct cgroup, self);
        bpf_prog_array_free(desc->bpf.inactive);
        desc->bpf.inactive = NULL;
    }
    return err;
}
```

`activate_effective_progs` 函数更新cgroup有效的BPF程序列表，如下：

```C
// file: kernel/bpf/cgroup.c
static void activate_effective_progs(struct cgroup *cgrp, enum cgroup_bpf_attach_type atype, 
    struct bpf_prog_array *old_array)
{
    // rcu替换有效程序
    old_array = rcu_replace_pointer(cgrp->bpf.effective[atype], old_array, lockdep_is_held(&cgroup_mutex));
    // 释放之前有效的bpf程序列表
    bpf_prog_array_free(old_array);
}
```

### 4.2 注销CGROUP_BPF程序

#### 1 传统方式

##### (1) BPF系统调用

传统方式使用`BPF_PROG_ATTACH` BPF系统调用，如下：

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
    case BPF_PROG_DETACH: err = bpf_prog_detach(&attr); break;
    ...
    }
    return err;
}
```

##### (2) `BPF_PROG_DETACH`

`bpf_prog_detach` 在检查BPF程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理，cgroup类型的bpf程序, 对应 `cgroup_bpf_prog_detach` 处理函数。如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_prog_detach(const union bpf_attr *attr)
{
    enum bpf_prog_type ptype;
    // 检查bpf_attr属性
    if (CHECK_ATTR(BPF_PROG_DETACH)) return -EINVAL;
    // 获取附加程序类型
    ptype = attach_type_to_prog_type(attr->attach_type);

    switch (ptype) {
    ...
    case BPF_PROG_TYPE_CGROUP_DEVICE:
    case BPF_PROG_TYPE_CGROUP_SKB:
    case BPF_PROG_TYPE_CGROUP_SOCK:
    case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
    case BPF_PROG_TYPE_CGROUP_SOCKOPT:
    case BPF_PROG_TYPE_CGROUP_SYSCTL:
    case BPF_PROG_TYPE_SOCK_OPS:
    case BPF_PROG_TYPE_LSM:
        return cgroup_bpf_prog_detach(attr, ptype);
    default:
        return -EINVAL;
    }
}
```

`cgroup_bpf_prog_detach` 函数获取bpf程序和cgroup后，分类程序，实现如下：

```C
// file: kernel/bpf/cgroup.c
int cgroup_bpf_prog_detach(const union bpf_attr *attr, enum bpf_prog_type ptype)
{
    struct bpf_prog *prog;
    struct cgroup *cgrp;
    int ret;
    // 获取cgroup
    cgrp = cgroup_get_from_fd(attr->target_fd);
    if (IS_ERR(cgrp)) return PTR_ERR(cgrp);
    // 获取bpf程序
    prog = bpf_prog_get_type(attr->attach_bpf_fd, ptype);
    if (IS_ERR(prog)) prog = NULL;
    // cgroup分离bpf程序
    ret = cgroup_bpf_detach(cgrp, prog, attr->attach_type);
    if (prog) bpf_prog_put(prog);

    cgroup_put(cgrp);
    return ret;
```

#### 2 Link方式

##### (1) `bpf_cgroup_link_lops`接口

在附加`cgroup_bpf_link_attach`过程中，设置了用户空间操作`bpf_link`的文件接口，如下：

```C
// file: kernel/bpf/cgroup.c
int cgroup_bpf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_CGROUP, &bpf_cgroup_link_lops, prog);
    link->cgroup = cgrp;
    link->type = attr->link_create.attach_type;
    ...
    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    ...
}
```

`bpf_cgroup_link_lops` 是设置的文件操作接口，定义如下：

```C
// file: kernel/bpf/cgroup.c
static const struct bpf_link_ops bpf_cgroup_link_lops = {
    .release = bpf_cgroup_link_release,
    .dealloc = bpf_cgroup_link_dealloc,
    .detach = bpf_cgroup_link_detach,
    .update_prog = cgroup_bpf_replace,
    .show_fdinfo = bpf_cgroup_link_show_fdinfo,
    .fill_link_info = bpf_cgroup_link_fill_link_info,
};
```

##### (2) 更新bpf程序

`.update_prog`更新接口，更新当前设置的bpf程序，设置为`cgroup_bpf_replace`。实现如下:

```C
// file: kernel/bpf/cgroup.c
static int cgroup_bpf_replace(struct bpf_link *link, struct bpf_prog *new_prog, struct bpf_prog *old_prog)
{
    struct bpf_cgroup_link *cg_link;
    int ret;
    // 获取cgroup_link
    cg_link = container_of(link, struct bpf_cgroup_link, link);

    mutex_lock(&cgroup_mutex);
    // cgroup和替换程序检查
    if (!cg_link->cgroup) { ret = -ENOLINK; goto out_unlock; }
    if (old_prog && link->prog != old_prog) { ret = -EPERM; goto out_unlock; }
    // 替换cgroup程序
    ret = __cgroup_bpf_replace(cg_link->cgroup, cg_link, new_prog);
out_unlock:
    mutex_unlock(&cgroup_mutex);
    return ret;
}
```

`__cgroup_bpf_replace` 替换cgroup程序并将更改传播到后代，如下：

```C
// file: kernel/bpf/cgroup.c
static int __cgroup_bpf_replace(struct cgroup *cgrp, struct bpf_cgroup_link *link, struct bpf_prog *new_prog)
{
    enum cgroup_bpf_attach_type atype;
    struct bpf_prog *old_prog;
    struct bpf_prog_list *pl;
    struct hlist_head *progs;
    bool found = false;

    // 获取附加类型
    atype = bpf_cgroup_atype_find(link->type, new_prog->aux->attach_btf_id);
    if (atype < 0) return -EINVAL;

    progs = &cgrp->bpf.progs[atype];
    // 替换前后的程序类型要保持一致
    if (link->link.prog->type != new_prog->type) return -EINVAL;

    // 遍历所有程序，查找link
    hlist_for_each_entry(pl, progs, node) {
        if (pl->link == link) { found = true; break; }
    }
    if (!found) return -ENOENT;
    // 替换程序
    old_prog = xchg(&link->link.prog, new_prog);
    // 更新link中bpf程序到所有的后代中
    replace_effective_prog(cgrp, atype, link);
    bpf_prog_put(old_prog);
    return 0;
}
```

##### (3) 注销接口

`.release`接口释放`bpf_link`关联的程序，设置为`bpf_cgroup_link_release` 。实现如下:

```C
// file: kernel/bpf/cgroup.c
static void bpf_cgroup_link_release(struct bpf_link *link)
{
    struct bpf_cgroup_link *cg_link = container_of(link, struct bpf_cgroup_link, link);
    struct cgroup *cg;

    if (!cg_link->cgroup) return;

    mutex_lock(&cgroup_mutex);
    // 重新检查cgroup是否存在
    if (!cg_link->cgroup) { mutex_unlock(&cgroup_mutex); return; }
    // 分离bpf程序
    WARN_ON(__cgroup_bpf_detach(cg_link->cgroup, NULL, cg_link, cg_link->type));

    if (cg_link->type == BPF_LSM_CGROUP)
        // 分离LSM_CGROUP类型的程序
        bpf_trampoline_unlink_cgroup_shim(cg_link->link.prog);
    
    // 更新cgroup_link
    cg = cg_link->cgroup;
    cg_link->cgroup = NULL;
    mutex_unlock(&cgroup_mutex);
    cgroup_put(cg);
}
```

#### 3 注销BPF程序

`cgroup_bpf_detach` 函数分离bpf程序，实现bpf程序的注销，是对`__cgroup_bpf_detach`函数的调用封装，如下：

```C
// file: kernel/bpf/cgroup.c
static int cgroup_bpf_detach(struct cgroup *cgrp, struct bpf_prog *prog, enum bpf_attach_type type)
{
    int ret;
    mutex_lock(&cgroup_mutex);
    ret = __cgroup_bpf_detach(cgrp, prog, NULL, type);
    mutex_unlock(&cgroup_mutex);
    return ret;
}
```

`__cgroup_bpf_detach` 函数实现cgroup和BPF程序的分离，如下：

```C
// file: kernel/bpf/cgroup.c
static int __cgroup_bpf_detach(struct cgroup *cgrp, struct bpf_prog *prog,
            struct bpf_cgroup_link *link, enum bpf_attach_type type)
{
    enum cgroup_bpf_attach_type atype;
    struct bpf_prog *old_prog;
    struct bpf_prog_list *pl;
    struct hlist_head *progs;
    u32 attach_btf_id = 0;
    u32 flags;

    // 获取attach_btf_id
    if (prog) attach_btf_id = prog->aux->attach_btf_id;
    if (link) attach_btf_id = link->link.prog->aux->attach_btf_id;

    // 获取附加类型
    atype = bpf_cgroup_atype_find(type, attach_btf_id);
    if (atype < 0) return -EINVAL;

    progs = &cgrp->bpf.progs[atype];
    flags = cgrp->bpf.flags[atype];
    
    // prog和link只能使用一种方式
    if (prog && link) return -EINVAL;

    // 获取分离程序的位置
    pl = find_detach_entry(progs, prog, link, flags & BPF_F_ALLOW_MULTI);
    if (IS_ERR(pl)) return PTR_ERR(pl);

    // 标记为删除，重新计算有效程序时，忽略
    old_prog = pl->prog;
    pl->prog = NULL;
    pl->link = NULL;

    // 更新有效程序
    if (update_effective_progs(cgrp, atype)) {
        // 更新失败时，将prog替换为dummy prog
        pl->prog = old_prog;
        pl->link = link;
        purge_effective_progs(cgrp, old_prog, link, atype);
    }
    // 从cgroup列表中删除
    hlist_del(&pl->node);
    kfree(pl);
    // 最后一个程序被分离，清空flags
    if (hlist_empty(progs)) cgrp->bpf.flags[atype] = 0;
    if (old_prog) {
        // 存在旧的bpf程序时，释放
        if (type == BPF_LSM_CGROUP) bpf_trampoline_unlink_cgroup_shim(old_prog);
        bpf_prog_put(old_prog);
    }
    // 减少启用计数
    static_branch_dec(&cgroup_bpf_enabled_key[atype]);
    return 0;
}
```

### 4.3 LSM_CGROUP的实现过程

#### 1 获取附加类型

在附加、替换、分离BPF程序时，需要获取附加类型，通过`bpf_cgroup_atype_find`函数获取附加类型，如下：

```C
// file: kernel/bpf/cgroup.c
static enum cgroup_bpf_attach_type
bpf_cgroup_atype_find(enum bpf_attach_type attach_type, u32 attach_btf_id)
{
    int i;
    lockdep_assert_held(&cgroup_mutex);

    // 其他类型程序获取附加类型，和附加类型一一对应
    if (attach_type != BPF_LSM_CGROUP)
        return to_cgroup_bpf_attach_type(attach_type);

    // 附加类型为LSM_CGROUP时，通过附加btf_id获取附加类型
    for (i = 0; i < ARRAY_SIZE(cgroup_lsm_atype); i++)
        if (cgroup_lsm_atype[i].attach_btf_id == attach_btf_id)
            return CGROUP_LSM_START + i;
    // 没有找到附加类型, 获取btf_id为0的附加类型
    for (i = 0; i < ARRAY_SIZE(cgroup_lsm_atype); i++)
        if (cgroup_lsm_atype[i].attach_btf_id == 0)
            return CGROUP_LSM_START + i;

    return -E2BIG;
}
```

`cgroup_lsm_atype` 和 `CGROUP_LSM_NUM` 定义如下：

```C
// file: kernel/bpf/cgroup.c
static struct cgroup_lsm_atype cgroup_lsm_atype[CGROUP_LSM_NUM];

// file: include/linux/bpf-cgroup-defs.h
#ifdef CONFIG_BPF_LSM
#define CGROUP_LSM_NUM 10
#else
#define CGROUP_LSM_NUM 0
#endif
```

#### 2 附加过程

LSM_CGROUP附加BPF程序时，除了正常的附加过程外，还需要进行额外的附加操作，通过 `bpf_trampoline_link_cgroup_shim` 函数创建蹦床后设置`LSM HOOK`，如下：

```C
// file: kernel/bpf/trampoline.c
int bpf_trampoline_link_cgroup_shim(struct bpf_prog *prog, int cgroup_atype)
{
    struct bpf_shim_tramp_link *shim_link = NULL;
    struct bpf_attach_target_info tgt_info = {};
    struct bpf_trampoline *tr;
    bpf_func_t bpf_func;
    u64 key;
    int err;
    
    // 获取附加类型对应的附加目标信息
    err = bpf_check_attach_target(NULL, prog, NULL, prog->aux->attach_btf_id, &tgt_info);
    if (err) return err;
    // 计算bpf_trampoline的key
    key = bpf_trampoline_compute_key(NULL, prog->aux->attach_btf, prog->aux->attach_btf_id);
    // 获取lsm_cgroup的执行函数
    bpf_lsm_find_cgroup_shim(prog, &bpf_func);
    // 获取bpf_trampoline
    tr = bpf_trampoline_get(key, &tgt_info);
    if (!tr) return  -ENOMEM;

    mutex_lock(&tr->mutex);
    // 从tr中根据func获取shim_link
    shim_link = cgroup_shim_find(tr, bpf_func);
    if (shim_link) {
        // 更新shim_link的引用计数，使用已经存在的shim附加新的bpf程序
        bpf_link_inc(&shim_link->link.link);
        
        mutex_unlock(&tr->mutex);
        bpf_trampoline_put(tr);
        return 0;
    }
    // 创建新的shim_link
    shim_link = cgroup_shim_alloc(prog, bpf_func, cgroup_atype);
    if (!shim_link) { err = -ENOMEM; goto err; }
    // 将shim_link附加到trampoline中
    err = __bpf_trampoline_link_prog(&shim_link->link, tr);
    if (err) goto err;

    shim_link->trampoline = tr;
    mutex_unlock(&tr->mutex);
    return 0;
err:
    mutex_unlock(&tr->mutex);
    if (shim_link) bpf_link_put(&shim_link->link.link);
    bpf_trampoline_put(tr); 
    return err;
}
```

`bpf_lsm_find_cgroup_shim` 函数获取BPF的执行函数，根据LSM HOOK函数函数原型进行获取，如下：

```C
// file: kernel/bpf/bpf_lsm.c
void bpf_lsm_find_cgroup_shim(const struct bpf_prog *prog, bpf_func_t *bpf_func)
{
    const struct btf_param *args __maybe_unused;
    // LSM HOOK函数没有参数，或者在`bpf_lsm_current_hooks`中，使用`__cgroup_bpf_run_lsm_current`
    if (btf_type_vlen(prog->aux->attach_func_proto) < 1 || 
        btf_id_set_contains(&bpf_lsm_current_hooks, prog->aux->attach_btf_id)) {
        *bpf_func = __cgroup_bpf_run_lsm_current;
        return;
    }
    // 获取函数参数
    args = btf_params(prog->aux->attach_func_proto);

    if (args[0].type == btf_sock_ids[BTF_SOCK_TYPE_SOCKET])
        // 第一个参数是`socket`类型，使用`__cgroup_bpf_run_lsm_socket`
        *bpf_func = __cgroup_bpf_run_lsm_socket;
    else if (args[0].type == btf_sock_ids[BTF_SOCK_TYPE_SOCK])
        // 第一个参数是`sock`类型，使用`__cgroup_bpf_run_lsm_sock`
        *bpf_func = __cgroup_bpf_run_lsm_sock;
    else
        // 默认使用`__cgroup_bpf_run_lsm_current`
        *bpf_func = __cgroup_bpf_run_lsm_current;
}
```

`cgroup_shim_alloc` 函数创建新的`shim_link`, 如下：

```C
// file: kernel/bpf/trampoline.c
static struct bpf_shim_tramp_link *cgroup_shim_alloc(const struct bpf_prog *prog, bpf_func_t bpf_func, int cgroup_atype)
{
    struct bpf_shim_tramp_link *shim_link = NULL;
    struct bpf_prog *p;

    // 创建shim_link
    shim_link = kzalloc(sizeof(*shim_link), GFP_USER);
    if (!shim_link) return NULL;

    // 分配prog
    p = bpf_prog_alloc(1, 0);
    if (!p) { kfree(shim_link); return NULL; }

    // prog属性数值
    p->jited = false;
    p->bpf_func = bpf_func;
    p->aux->cgroup_atype = cgroup_atype;
    p->aux->attach_func_proto = prog->aux->attach_func_proto;
    p->aux->attach_btf_id = prog->aux->attach_btf_id;
    p->aux->attach_btf = prog->aux->attach_btf;
    btf_get(p->aux->attach_btf);
    // BPF程序类型和附加类型设置
    p->type = BPF_PROG_TYPE_LSM;
    p->expected_attach_type = BPF_LSM_MAC;
    bpf_prog_inc(p);
    // 设置link属性
    bpf_link_init(&shim_link->link.link, BPF_LINK_TYPE_UNSPEC, &bpf_shim_tramp_link_lops, p);
    // 设置`cgroup_lsm_atype[]`中对应附加位置的的btf_id和引用计数
    bpf_cgroup_atype_get(p->aux->attach_btf_id, cgroup_atype);

    return shim_link;
}
```

#### 3 注销过程

LSM_CGROUP注销BPF程序时，除了正常的注销过程外，还需要通过 `bpf_trampoline_unlink_cgroup_shim` 函数销毁设置的`LSM HOOK`和蹦床，如下：

```C
// file: kernel/bpf/trampoline.c
void bpf_trampoline_unlink_cgroup_shim(struct bpf_prog *prog)
{
    struct bpf_shim_tramp_link *shim_link = NULL;
    struct bpf_trampoline *tr;
    bpf_func_t bpf_func;
    u64 key;

    // 计算bpf_trampoline的key
    key = bpf_trampoline_compute_key(NULL, prog->aux->attach_btf, prog->aux->attach_btf_id);

    bpf_lsm_find_cgroup_shim(prog, &bpf_func);
    // 查找bpf_trampoline
    tr = bpf_trampoline_lookup(key);
    if (WARN_ON_ONCE(!tr)) return;

    mutex_lock(&tr->mutex);
    // 从tr中根据func获取shim_link
    shim_link = cgroup_shim_find(tr, bpf_func);
    mutex_unlock(&tr->mutex);

    // shim_link存在时，释放
    if (shim_link) bpf_link_put(&shim_link->link.link);

    bpf_trampoline_put(tr); /* bpf_trampoline_lookup above */
}
```

在初始化`shim_link`过程中，设置的`link->ops`为`bpf_shim_tramp_link_lops`, 定义如下：

```C
// file: kernel/bpf/trampoline.c
static const struct bpf_link_ops bpf_shim_tramp_link_lops = {
    .release = bpf_shim_tramp_link_release,
    .dealloc = bpf_shim_tramp_link_dealloc,
};
```

`.release`接口释放`bpf_link`关联的程序，设置为`bpf_shim_tramp_link_release` 。实现如下:

```C
// file: kernel/bpf/trampoline.c
static void bpf_shim_tramp_link_release(struct bpf_link *link)
{
    struct bpf_shim_tramp_link *shim_link = container_of(link, struct bpf_shim_tramp_link, link.link);
    if (!shim_link->trampoline) return;
    // 将link和trampoline解除关联
    WARN_ON_ONCE(bpf_trampoline_unlink_prog(&shim_link->link, shim_link->trampoline));
    // 释放trampoline
    bpf_trampoline_put(shim_link->trampoline);
}
```

### 4.4 CGROUP_BPF程序的触发过程

CGROUP可以设置多种类型的BPF程序，如下：

```C
// file: include/linux/bpf-cgroup-defs.h
enum cgroup_bpf_attach_type {
    CGROUP_BPF_ATTACH_TYPE_INVALID = -1,
    CGROUP_INET_INGRESS = 0,
    CGROUP_INET_EGRESS,
    CGROUP_INET_SOCK_CREATE,
    CGROUP_SOCK_OPS,
    CGROUP_DEVICE,
    CGROUP_INET4_BIND,
    CGROUP_INET6_BIND,
    CGROUP_INET4_CONNECT,
    CGROUP_INET6_CONNECT,
    CGROUP_INET4_POST_BIND,
    CGROUP_INET6_POST_BIND,
    CGROUP_UDP4_SENDMSG,
    CGROUP_UDP6_SENDMSG,
    CGROUP_SYSCTL,
    CGROUP_UDP4_RECVMSG,
    CGROUP_UDP6_RECVMSG,
    CGROUP_GETSOCKOPT,
    CGROUP_SETSOCKOPT,
    CGROUP_INET4_GETPEERNAME,
    CGROUP_INET6_GETPEERNAME,
    CGROUP_INET4_GETSOCKNAME,
    CGROUP_INET6_GETSOCKNAME,
    CGROUP_INET_SOCK_RELEASE,
    CGROUP_LSM_START,
    CGROUP_LSM_END = CGROUP_LSM_START + CGROUP_LSM_NUM - 1,
    MAX_CGROUP_BPF_ATTACH_TYPE
};
```

下面将逐一分析其在内核的触发过程。

#### 1 `CGROUP_INET_INGRESS`

##### (1) 实现过程

`CGROUP_INET_INGRESS`对进入CGROUP的网络数据包进行检查，在内核中通过`BPF_CGROUP_RUN_PROG_INET_INGRESS`宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb)           \
({                                                          \
    int __ret = 0;                                          \
    if (cgroup_bpf_enabled(CGROUP_INET_INGRESS) &&          \
        cgroup_bpf_sock_enabled(sk, CGROUP_INET_INGRESS))   \
        __ret = __cgroup_bpf_run_filter_skb(sk, skb,        \
                                    CGROUP_INET_INGRESS);   \
    __ret;                                                  \
})
```

`cgroup_bpf_enabled` 函数判断附加类型的BPF是否可用，检查`cgroup_bpf_enabled_key[]`是否启用，如下：

```C
// file: include/linux/bpf-cgroup.h
#define cgroup_bpf_enabled(atype) static_branch_unlikely(&cgroup_bpf_enabled_key[atype])
```

`cgroup_bpf_sock_enabled` 函数判断socket是否附加了cgroup bpf程序，如下：

```C
// file: include/linux/bpf-cgroup.h
static inline bool cgroup_bpf_sock_enabled(struct sock *sk, enum cgroup_bpf_attach_type type)
{
    // 获取sk所属的cgroup
    struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    struct bpf_prog_array *array;
    // 检查是否附加了有效的bpf程序
    array = rcu_access_pointer(cgrp->bpf.effective[type]);
    return array != &bpf_empty_prog_array.hdr;
}
```

在socket设置了有效的cgroup bpf程序后，调用`__cgroup_bpf_run_filter_skb`函数，如下：

```C
// file: kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_skb(struct sock *sk, struct sk_buff *skb, enum cgroup_bpf_attach_type atype)
{
    unsigned int offset = skb->data - skb_network_header(skb);
    struct sock *save_sk;
    void *saved_data_end;
    struct cgroup *cgrp;
    int ret;

    // sk不存在或不是完全连接的sk时，返回
    if (!sk || !sk_fullsock(sk)) return 0;
    // 仅支持INET和INET6网络家族
    if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) return 0;

    // 获取sk所属的cgroup
    cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    // 修改skb，不能修改L2数据
    save_sk = skb->sk;
    skb->sk = sk;
    __skb_push(skb, offset);

    // 计算skb的结束位置，保存skb结束地址到skb->cb中
    bpf_compute_and_save_data_end(skb, &saved_data_end);

    if (atype == CGROUP_INET_EGRESS) {
        // 运行cgroup egress bpf程序
        ...
    } else {
        // 运行cgroup ingress bpf程序
        ret = bpf_prog_run_array_cg(&cgrp->bpf, atype, skb, __bpf_prog_run_save_cb, 0, NULL);
        // 转换返回值，大于0的返回值，表示错误
        if (ret && !IS_ERR_VALUE((long)ret)) ret = -EFAULT;
    }
    // 恢复skb信息
    bpf_restore_data_end(skb, saved_data_end);
    __skb_pull(skb, offset);
    skb->sk = save_sk;
    
    return ret;
}
```

`bpf_prog_run_array_cg` 函数运行cgroup bpf程序，实现如下：

```C
// file: kernel/bpf/cgroup.c
static __always_inline int bpf_prog_run_array_cg(const struct cgroup_bpf *cgrp, 
    enum cgroup_bpf_attach_type atype, const void *ctx, bpf_prog_run_fn run_prog, int retval, u32 *ret_flags)
{
    const struct bpf_prog_array_item *item;
    const struct bpf_prog *prog;
    const struct bpf_prog_array *array;
    struct bpf_run_ctx *old_run_ctx;
    struct bpf_cg_run_ctx run_ctx;
    u32 func_ret;

    // 默认返回值设置
    run_ctx.retval = retval;
    migrate_disable();
    rcu_read_lock();
    // 获取cgroup bpf程序
    array = rcu_dereference(cgrp->effective[atype]);
    item = &array->items[0];
    // 设置cgroup bpf程序运行上下文
    old_run_ctx = bpf_set_run_ctx(&run_ctx.run_ctx);
    // 遍历cgroup bpf程序
    while ((prog = READ_ONCE(item->prog))) {
        run_ctx.prog_item = item;
        // 运行bpf程序
        func_ret = run_prog(prog, ctx);
        // 存在返回标记时，计算返回标记和返回值
        if (ret_flags) { *(ret_flags) |= (func_ret >> 1); func_ret &= 1; }
        // 返回值非0时，检查返回值是否为错误码
        if (!func_ret && !IS_ERR_VALUE((long)run_ctx.retval))
            run_ctx.retval = -EPERM;
        // 运行下一个程序
        item++;
    }
    // 恢复cgroup bpf程序运行上下文
    bpf_reset_run_ctx(old_run_ctx);
    rcu_read_unlock();
    migrate_enable();
    // 返回运行结果
    return run_ctx.retval;
}
```

##### (2) TCP的触发过程

TCP通过`tcp_filter`函数过滤接收的skb，如下：

```C
// file: net/ipv4\tcp_ipv4.c
int tcp_filter(struct sock *sk, struct sk_buff *skb)
{
    struct tcphdr *th = (struct tcphdr *)skb->data;
    return sk_filter_trim_cap(sk, skb, th->doff * 4);
}
```

在接收网络数据包过程中实现对接收数据包进行过滤，在`sk_filter_trim_cap`函数中调用，如下：

```C
// file: net/core\filter.c
int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
{
    int err;
    struct sk_filter *filter;

    if (skb_pfmemalloc(skb) && !sock_flag(sk, SOCK_MEMALLOC)) {
        NET_INC_STATS(sock_net(sk), LINUX_MIB_PFMEMALLOCDROP);
        return -ENOMEM;
    }
    // CGROUP_INET_INGRESS BPF处理
    err = BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb);
    if (err) return err;

    err = security_sock_rcv_skb(sk, skb);
    if (err) return err;

    rcu_read_lock();
    // socket filter过滤
    filter = rcu_dereference(sk->sk_filter);
    if (filter) {
        struct sock *save_sk = skb->sk;
        unsigned int pkt_len;
        skb->sk = sk;
        pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
        skb->sk = save_sk;
        err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
    }
    rcu_read_unlock();
    return err;
}
```

##### (3) UDP的触发过程

UDP在通过`udp[v6]_queue_rcv_one_skb`函数接收skb时，过滤skb，如下：

```C
// file: net/ipv4\udp.c
static int udp_queue_rcv_one_skb(struct sock *sk, struct sk_buff *skb)
{
    ...
    if (sk_filter_trim_cap(sk, skb, sizeof(struct udphdr))) {
        drop_reason = SKB_DROP_REASON_SOCKET_FILTER;
        goto drop;
    }
    ...
}
```

#### 2 `CGROUP_INET_EGRESS`

##### (1) 实现过程

`CGROUP_INET_EGRESS`对从CGROUP出去的网络数据包进行检查，在内核中通过`BPF_CGROUP_RUN_PROG_INET_EGRESS`宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb)                            \
({                                                                          \
    int __ret = 0;                                                          \
    if (cgroup_bpf_enabled(CGROUP_INET_EGRESS) && sk && sk == skb->sk) {    \
        typeof(sk) __sk = sk_to_full_sk(sk);                                \
        if (sk_fullsock(__sk) &&                                            \
            cgroup_bpf_sock_enabled(__sk, CGROUP_INET_EGRESS))              \
            __ret = __cgroup_bpf_run_filter_skb(__sk, skb,                  \
                                CGROUP_INET_EGRESS);                        \
    }                                                                       \
    __ret;                                                                  \
})
```

在socket设置了有效的cgroup bpf程序后，调用`__cgroup_bpf_run_filter_skb`函数，如下：

```C
// file: kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_skb(struct sock *sk, struct sk_buff *skb, enum cgroup_bpf_attach_type atype)
{
    unsigned int offset = skb->data - skb_network_header(skb);
    struct sock *save_sk;
    void *saved_data_end;
    struct cgroup *cgrp;
    int ret;

    // sk不存在或不是完全连接的sk时，返回
    if (!sk || !sk_fullsock(sk)) return 0;
    // 支持INET和INET6网络家族
    if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) return 0;

    // 获取sk所属的cgroup
    cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    // 修改skb，不能修改L2数据
    save_sk = skb->sk;
    skb->sk = sk;
    __skb_push(skb, offset);

    // 计算skb的结束位置，保存skb结束地址到skb->cb中
    bpf_compute_and_save_data_end(skb, &saved_data_end);

    if (atype == CGROUP_INET_EGRESS) {
        u32 flags = 0; bool cn;
        // 运行cgroup egress bpf程序
        ret = bpf_prog_run_array_cg(&cgrp->bpf, atype, skb, __bpf_prog_run_save_cb, 0, &flags);
        // 根据`flags`和返回值，换算返回值
        cn = flags & BPF_RET_SET_CN;
        if (ret && !IS_ERR_VALUE((long)ret)) ret = -EFAULT;
        if (!ret) ret = (cn ? NET_XMIT_CN : NET_XMIT_SUCCESS);
        else ret = (cn ? NET_XMIT_DROP : ret);
    } else {
        // 运行cgroup ingress bpf程序
        ...
    }
    // 恢复skb信息
    bpf_restore_data_end(skb, saved_data_end);
    __skb_pull(skb, offset);
    skb->sk = save_sk;
    
    return ret;
}
```

`CGROUP EGRESS` BPF程序的返回值表示为：0--丢弃网络数据包；1--保留网络数据包；2--丢弃网络数据包后继续；3--保留网络数据包后继续。将BPF程序的返回值转换为`NET_XMIT`类型的返回值，对应关系为：`0:NET_XMIT_SUCCESS`--网络数据包继续后续处理；`1:NET_XMIT_DROP`--丢弃网络数据包；`2:NET_XMIT_CN`--网络数据包继续后续处理；`3:-err`--出现错误，丢弃网络数据包。

##### (2) IPV4的触发过程

在UDP单播、TCP的情况下，L3设置的网络数据包通过`ip_finish_output`函数发送，在发送过程中进行`CGROUP_INET_EGRESS`检查。如下：

```C
// file: net/ipv4/ip_output.c
static int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    int ret;
    // CGROUP_INET_EGRESS BPF处理
    ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
    switch (ret) {
    case NET_XMIT_SUCCESS:
        // `SUCCESS`:继续后续发送
        return __ip_finish_output(net, sk, skb);
    case NET_XMIT_CN:
        // `CN`:继续后续发送，成功时使用BPF程序的返回值
        return __ip_finish_output(net, sk, skb) ? : ret;
    default:
        // 其他值丢弃网络数据包
        kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
        return ret;
    }
}
```

在UDP组播或广播的情况下，L3设置的网络数据包通过`ip_mc_finish_output`函数发送，实现如下：

```C
// file: net/ipv4/ip_output.c
static int ip_mc_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct rtable *new_rt;
    bool do_cn = false;
    int ret, err;
    // CGROUP_INET_EGRESS BPF处理
    ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
    switch (ret) {
    case NET_XMIT_CN:
        // `CN`:设置相关标记
        do_cn = true;
        fallthrough;
    case NET_XMIT_SUCCESS:
        break;
    default:
        // 其他值丢弃网络数据包
        kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
        return ret;
    }
    // 重置`rt_iif`，复制路由信息
    new_rt = rt_dst_clone(net->loopback_dev, skb_rtable(skb));
    if (new_rt) {
        new_rt->rt_iif = 0;
        skb_dst_drop(skb);
        skb_dst_set(skb, &new_rt->dst);
    }
    // 本地网卡发送
    err = dev_loopback_xmit(net, sk, skb);
    // 设置返回值
    return (do_cn && err) ? ret : err;
}
```

##### (3) IPV6的触发过程

IPV6的情况下，L3设置的网络数据包通过`ip6_finish_output`函数发送，在发送过程中进行`CGROUP_INET_EGRESS`检查。如下：

```C
// file: net/ipv6/ip6_output.c
static int ip6_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    int ret;

    ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
    switch (ret) {
    case NET_XMIT_SUCCESS:
    case NET_XMIT_CN:
        // `SUCCESS`、`CN`发送网络数据包
        return __ip6_finish_output(net, sk, skb) ? : ret;
    default:
        // 其他值丢弃网络数据包
        kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
        return ret;
    }
}
```

#### 3 `CGROUP_INET_SOCK_CREATE`

##### (1) 实现过程

`CGROUP_INET_SOCK_CREATE`在创建socket时(`socket`系统调用)进行检查，在内核中通过`BPF_CGROUP_RUN_PROG_INET_SOCK`宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET_SOCK(sk)               \
    BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET_SOCK_CREATE)
```

`BPF_CGROUP_RUN_SK_PROG`宏定义如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_SK_PROG(sk, atype)               \
({                                                      \
    int __ret = 0;                                      \
    if (cgroup_bpf_enabled(atype)) {                    \
        __ret = __cgroup_bpf_run_filter_sk(sk, atype);  \
    }                                                   \
    __ret;                                              \
})
```

在socket设置了有效的cgroup bpf程序后，调用`__cgroup_bpf_run_filter_sk`函数，如下：

```C
// file: kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_sk(struct sock *sk, enum cgroup_bpf_attach_type atype)
{
    // 获取sk所属的cgroup后，运行cgroup bpf程序
    struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    return bpf_prog_run_array_cg(&cgrp->bpf, atype, sk, bpf_prog_run, 0, NULL);
}
```

`socket`系统调用的实现如下：

```C
// file: net/socket.c
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
    return __sys_socket(family, type, protocol);
}
// file: net/socket.c
int __sys_socket(int family, int type, int protocol)
{
    struct socket *sock;
    int flags;
    // 创建socket
    sock = __sys_socket_create(family, type, protocol);
    if (IS_ERR(sock)) return PTR_ERR(sock);

    flags = type & ~SOCK_TYPE_MASK;
    if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
        flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;
    // socket关联fd
    return sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
}
```

`__sys_socket_create` 函数创建对应的socket，调用过程如下：

```C
// file: net/socket.c
static struct socket *__sys_socket_create(int family, int type, int protocol)
    --> sock_create(family, type, protocol, &sock);
        --> __sock_create(current->nsproxy->net_ns, family, type, protocol, res, 0);
```

`__sock_create` 函数创建一个socket，在创建期间进行LSM安全检查。实现如下：

```C
// file: net/socket.c
int __sock_create(struct net *net, int family, int type, int protocol,
            struct socket **res, int kern)
{
    int err;
    struct socket *sock;
    const struct net_proto_family *pf;

    // 检查协议是否在范围内
    if (family < 0 || family >= NPROTO) return -EAFNOSUPPORT;
    if (type < 0 || type >= SOCK_MAX) return -EINVAL;
    // 兼容性检查，
    if (family == PF_INET && type == SOCK_PACKET) {
        family = PF_PACKET;
    }
    // 创建socket前LSM安全检查
    err = security_socket_create(family, type, protocol, kern);
    if (err) return err;

    // 创建inode和socket对象
    sock = sock_alloc();
    if (!sock) { ... }
    // 设置sock类型
    sock->type = type;

#ifdef CONFIG_MODULES
    // 网络家族不存在时，尝试以module方式加载
    if (rcu_access_pointer(net_families[family]) == NULL)
        request_module("net-pf-%d", family);
#endif
    ...
    // 获取对应的网络家族
    pf = rcu_dereference(net_families[family]);
    ...    
    // 网络家族创建接口
    err = pf->create(net, sock, protocol, kern);
    if (err < 0) goto out_module_put;
    ...
    // 创建socket后LSM安全检查
    err = security_socket_post_create(sock, family, type, protocol, kern);
    if (err) goto out_sock_release;
    // 设置返回结果
    *res = sock;
    return 0;
    ...
}
```

`sock_map_fd` 函数将`socket`映射为用户空间使用的`fd`，实现如下：

```C
// file: net/socket.c
static int sock_map_fd(struct socket *sock, int flags)
{
    struct file *newfile;
    // 获取未使用的fd，获取失败时释放sock
    int fd = get_unused_fd_flags(flags);
    if (unlikely(fd < 0)) { sock_release(sock); return fd; }
    // 将sock和文件绑定，成功时将文件和fd关联
    newfile = sock_alloc_file(sock, flags, NULL);
    if (!IS_ERR(newfile)) { fd_install(fd, newfile); return fd; }
    // 创建文件失败时，释放fd
    put_unused_fd(fd);
    return PTR_ERR(newfile);
}
```

`sock_alloc_file` 函数将sock和文件进行绑定，实现如下：

```C
// file: net/socket.c
struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
{
    struct file *file;
    if (!dname) dname = sock->sk ? sock->sk->sk_prot_creator->name : "";

    // 创建sock昵称，失败时释放sock
    file = alloc_file_pseudo(SOCK_INODE(sock), sock_mnt, dname,
            O_RDWR | (flags & O_NONBLOCK), &socket_file_ops);
    if (IS_ERR(file)) { sock_release(sock); return file; }
    // 绑定sock和file
    sock->file = file;
    file->private_data = sock;
    stream_open(SOCK_INODE(sock), file);
    return file;
}
```

##### (2) IPV4的触发过程

IPV4在内核中协议定义为`inet_family_ops`，如下：

```C
// file: net/ipv4/af_inet.c
static const struct net_proto_family inet_family_ops = {
    .family = PF_INET,
    .create = inet_create,
    .owner  = THIS_MODULE,
};
```

`.create`接口设置为`inet_create`，实现如下：

```C
// file: net/ipv4/af_inet.c
static int inet_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    struct sock *sk;
    struct inet_protosw *answer;
    struct inet_sock *inet;
    struct proto *answer_prot;
    unsigned char answer_flags;
    int try_loading_module = 0;
    int err;
    // 检查协议类型
    if (protocol < 0 || protocol >= IPPROTO_MAX) return -EINVAL;
    // 设置sock状态未连接状态
    sock->state = SS_UNCONNECTED;

lookup_protocol:
    err = -ESOCKTNOSUPPORT;
    rcu_read_lock();
    // 查找请求的 类型/协议
    list_for_each_entry_rcu(answer, &inetsw[sock->type], list) {
        err = 0;
        // 精确匹配协议
        if (protocol == answer->protocol) {
            if (protocol != IPPROTO_IP) break;
        } else {
            // 两个通用匹配情况
            if (IPPROTO_IP == protocol) { protocol = answer->protocol; break; }
            if (IPPROTO_IP == answer->protocol) break;
        }
        err = -EPROTONOSUPPORT;
    }
    // 如果没有找到，尝试加载协议模块后重新查找
    if (unlikely(err)) { ... }

    // `SOCK_RAW`类型检查权限
    err = -EPERM;
    if (sock->type == SOCK_RAW && !kern && !ns_capable(net->user_ns, CAP_NET_RAW))
        goto out_rcu_unlock;
    // 查找结果设置
    sock->ops = answer->ops;
    answer_prot = answer->prot;
    answer_flags = answer->flags;
    rcu_read_unlock();

    WARN_ON(!answer_prot->slab);
    err = -ENOMEM;
    // 分配sk
    sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer_prot, kern);
    if (!sk) goto out;

    err = 0;
    if (INET_PROTOSW_REUSE & answer_flags) sk->sk_reuse = SK_CAN_REUSE;

    inet = inet_sk(sk);
    inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;
    inet->nodefrag = 0;
    // `SOCK_RAW`协议设置
    if (SOCK_RAW == sock->type) {
        inet->inet_num = protocol;
        if (IPPROTO_RAW == protocol) inet->hdrincl = 1;
    }
    // 路径MTU发现设置，`net.ipv4.ip_no_pmtu_disc`参数
    if (READ_ONCE(net->ipv4.sysctl_ip_no_pmtu_disc))
        inet->pmtudisc = IP_PMTUDISC_DONT;
    else
        inet->pmtudisc = IP_PMTUDISC_WANT;

    inet->inet_id = 0;
    // sk初始化数据
    sock_init_data(sock, sk);
    // sk属性设置
    sk->sk_destruct     = inet_sock_destruct;
    sk->sk_protocol     = protocol;
    sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
    sk->sk_txrehash = READ_ONCE(net->core.sysctl_txrehash);
    // inet属性设置
    inet->uc_ttl    = -1;
    inet->mc_loop   = 1;
    inet->mc_ttl    = 1;
    inet->mc_all    = 1;
    inet->mc_index  = 0;
    inet->mc_list   = NULL;
    inet->rcv_tos   = 0;

    if (inet->inet_num) {
        // 源端口设置
        inet->inet_sport = htons(inet->inet_num);
        // 添加到协议hash链表中
        err = sk->sk_prot->hash(sk);
        // 失败时释放sk
        if (err) { sk_common_release(sk); goto out; }
    }

    if (sk->sk_prot->init) {
        // sk协议初始化接口
        err = sk->sk_prot->init(sk);
        if (err) { sk_common_release(sk); goto out; }
    }

    if (!kern) {
        // 用户空间创建的socket，进行BPF程序检查
        err = BPF_CGROUP_RUN_PROG_INET_SOCK(sk);
        if (err) { sk_common_release(sk); goto out; }
    }
out:
    return err;
out_rcu_unlock:
    rcu_read_unlock();
    goto out;
}
```

##### (3) IPV6的触发过程

IPV6在内核中协议定义为`inet_family_ops`，如下：

```C
// file: net/ipv6/af_inet6.c
static const struct net_proto_family inet6_family_ops = {
    .family = PF_INET6,
    .create = inet6_create,
    .owner  = THIS_MODULE,
};
```

`.create`接口设置为`inet6_create`，实现如下：

```C
// file: net/ipv6/af_inet6.c
static int inet6_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    struct inet_sock *inet;
    struct ipv6_pinfo *np;
    struct sock *sk;
    struct inet_protosw *answer;
    struct proto *answer_prot;
    unsigned char answer_flags;
    int try_loading_module = 0;
    int err;
    // 检查协议类型
    if (protocol < 0 || protocol >= IPPROTO_MAX) return -EINVAL;

lookup_protocol:
    err = -ESOCKTNOSUPPORT;
    rcu_read_lock();
    // 查找请求的 类型/协议
    list_for_each_entry_rcu(answer, &inetsw6[sock->type], list) {
        err = 0;
        // 精确匹配协议
        if (protocol == answer->protocol) {
            if (protocol != IPPROTO_IP) break;
        } else {
            // 两个通用匹配情况
            if (IPPROTO_IP == protocol) { protocol = answer->protocol; break; }
            if (IPPROTO_IP == answer->protocol) break;
        }
        err = -EPROTONOSUPPORT;
    }
    // 如果没有找到，尝试加载协议模块后重新查找
    if (unlikely(err)) { ... }

    // `SOCK_RAW`类型检查权限
    err = -EPERM;
    if (sock->type == SOCK_RAW && !kern && !ns_capable(net->user_ns, CAP_NET_RAW))
        goto out_rcu_unlock;

    // 查找结果设置
    sock->ops = answer->ops;
    answer_prot = answer->prot;
    answer_flags = answer->flags;
    rcu_read_unlock();

    WARN_ON(!answer_prot->slab);

    err = -ENOBUFS;
    // 分配sk
    sk = sk_alloc(net, PF_INET6, GFP_KERNEL, answer_prot, kern);
    if (!sk) goto out;
    // sk初始化数据
    sock_init_data(sock, sk);

    err = 0;
    if (INET_PROTOSW_REUSE & answer_flags) sk->sk_reuse = SK_CAN_REUSE;

    inet = inet_sk(sk);
    inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;
    // `SOCK_RAW`协议设置
    if (SOCK_RAW == sock->type) {
        inet->inet_num = protocol;
        if (IPPROTO_RAW == protocol) inet->hdrincl = 1;
    }
    // sk属性设置
    sk->sk_destruct     = inet6_sock_destruct;
    sk->sk_family       = PF_INET6;
    sk->sk_protocol     = protocol;

    sk->sk_backlog_rcv  = answer->prot->backlog_rcv;
    // `ipv6_pinfo`属性设置
    inet_sk(sk)->pinet6 = np = inet6_sk_generic(sk);
    np->hop_limit   = -1;
    np->mcast_hops  = IPV6_DEFAULT_MCASTHOPS;
    np->mc_loop = 1;
    np->mc_all  = 1;
    np->pmtudisc    = IPV6_PMTUDISC_WANT;
    np->repflow = net->ipv6.sysctl.flowlabel_reflect &  FLOWLABEL_REFLECT_ESTABLISHED;
    sk->sk_ipv6only = net->ipv6.sysctl.bindv6only;
    sk->sk_txrehash = READ_ONCE(net->core.sysctl_txrehash);

    // ipv4初始化，我们可以使用ipv6 API来处理ipv4
    inet->uc_ttl    = -1;
    inet->mc_loop   = 1;
    inet->mc_ttl    = 1;
    inet->mc_index  = 0;
    RCU_INIT_POINTER(inet->mc_list, NULL);
    inet->rcv_tos   = 0;
    // 路径MTU发现设置，`net.ipv4.ip_no_pmtu_disc`参数
    if (READ_ONCE(net->ipv4.sysctl_ip_no_pmtu_disc))
        inet->pmtudisc = IP_PMTUDISC_DONT;
    else
        inet->pmtudisc = IP_PMTUDISC_WANT;

    if (inet->inet_num) {
        // 源端口设置
        inet->inet_sport = htons(inet->inet_num);
        // 添加到协议hash链表中
        err = sk->sk_prot->hash(sk);
        // 失败时释放sk
        if (err) { sk_common_release(sk); goto out; }
    }
    if (sk->sk_prot->init) {
        // sk协议初始化接口
        err = sk->sk_prot->init(sk);
        if (err) { sk_common_release(sk); goto out; }
    }
    if (!kern) {
        // 用户空间创建的socket，进行BPF程序检查
        err = BPF_CGROUP_RUN_PROG_INET_SOCK(sk);
        if (err) { sk_common_release(sk); goto out; }
    }
out:
    return err;
out_rcu_unlock:
    rcu_read_unlock();
    goto out;
}
```

#### 4 `CGROUP_SOCK_OPS`

##### (1) 实现过程

`CGROUP_SOCK_OPS`也称为`TCP-BPF`，是一种通过BPF程序拦截`socket`操作，然后动态设置TCP参数的机制。在内核中通过 `BPF_CGROUP_RUN_PROG_SOCK_OPS` 和 `BPF_CGROUP_RUN_PROG_SOCK_OPS_SK` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_SOCK_OPS(sock_ops)                      \
({                                                                  \
    int __ret = 0;                                                  \
    if (cgroup_bpf_enabled(CGROUP_SOCK_OPS) && (sock_ops)->sk) {    \
        typeof(sk) __sk = sk_to_full_sk((sock_ops)->sk);            \
        if (__sk && sk_fullsock(__sk))                              \
            __ret = __cgroup_bpf_run_filter_sock_ops(__sk,          \
                        sock_ops, CGROUP_SOCK_OPS);                 \
    }                                                               \
    __ret;                                                          \
})

// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_SOCK_OPS_SK(sock_ops, sk)       \
({                                                          \
    int __ret = 0;                                          \
    if (cgroup_bpf_enabled(CGROUP_SOCK_OPS))                \
        __ret = __cgroup_bpf_run_filter_sock_ops(sk,        \
                            sock_ops, CGROUP_SOCK_OPS);     \
    __ret;                                                  \
})
```

在sock设置了有效的cgroup bpf程序后，调用`__cgroup_bpf_run_filter_sock_ops`函数，如下：

```C
// file: kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_sock_ops(struct sock *sk, struct bpf_sock_ops_kern *sock_ops,
            enum cgroup_bpf_attach_type atype)
{
    // 获取sk所属的cgroup后，运行cgroup bpf程序
    struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    return bpf_prog_run_array_cg(&cgrp->bpf, atype, sock_ops, bpf_prog_run, 0, NULL);
}
```

##### (2) TCP的触发过程

Linux内核中定义的`BPF_SOCK_OPS`操作如下：

```C
// file: include/uapi/linux/bpf.h
enum {
    BPF_SOCK_OPS_VOID,
    BPF_SOCK_OPS_TIMEOUT_INIT,
    BPF_SOCK_OPS_RWND_INIT,
    BPF_SOCK_OPS_TCP_CONNECT_CB,
    BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
    BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
    BPF_SOCK_OPS_NEEDS_ECN,	
    BPF_SOCK_OPS_BASE_RTT,
    BPF_SOCK_OPS_RTO_CB,
    BPF_SOCK_OPS_RETRANS_CB,
    BPF_SOCK_OPS_STATE_CB,
    BPF_SOCK_OPS_TCP_LISTEN_CB,	
    BPF_SOCK_OPS_RTT_CB,
    BPF_SOCK_OPS_PARSE_HDR_OPT_CB,
    BPF_SOCK_OPS_HDR_OPT_LEN_CB,
    BPF_SOCK_OPS_WRITE_HDR_OPT_CB,
};
```

这些操作分成两类，一类时`get`操作，返回值是获取的某个信息；另一类是带`_CB`后缀，表示用来修改连接的状态。这些操作主要通过`tcp_call_bpf`函数实现的，如下：

```C
// file: include/net/tcp.h
static inline int tcp_call_bpf(struct sock *sk, int op, u32 nargs, u32 *args)
{
    struct bpf_sock_ops_kern sock_ops;
    int ret;
    // 设置`sock_ops`属性
    memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));
    if (sk_fullsock(sk)) { sock_ops.is_fullsock = 1; sock_owned_by_me(sk); }
    
    sock_ops.sk = sk;
    sock_ops.op = op;
    // 复制参数值
    if (nargs > 0) memcpy(sock_ops.args, args, nargs * sizeof(*args));

    // 运行`SOCK_OPS` BPF程序
    ret = BPF_CGROUP_RUN_PROG_SOCK_OPS(&sock_ops);
    if (ret == 0) ret = sock_ops.reply;
    else ret = -1;
    return ret;
}
```

此外，还有两个函数变体 `tcp_call_bpf_2arg` 和 `tcp_call_bpf_3arg` ，分别传递2个和3个额外的参数，实现如下：

```C
// file: include/net/tcp.h
static inline int tcp_call_bpf_2arg(struct sock *sk, int op, u32 arg1, u32 arg2)
{
    u32 args[2] = {arg1, arg2};
    return tcp_call_bpf(sk, op, 2, args);
}
// file: include/net/tcp.h
static inline int tcp_call_bpf_3arg(struct sock *sk, int op, u32 arg1, u32 arg2, u32 arg3)
{
    u32 args[3] = {arg1, arg2, arg3};
    return tcp_call_bpf(sk, op, 3, args);
}
```

* `BPF_SOCK_OPS_TIMEOUT_INIT`

返回`SYN-RTO`的值，默认值为`-1`。在 `tcp_timeout_init` 函数中调用，如下：

```C
// file: include/net/tcp.h
static inline u32 tcp_timeout_init(struct sock *sk)
{
    int timeout;
    // 调用0个额外参数的 `SOCK_OPS` BPF程序
    timeout = tcp_call_bpf(sk, BPF_SOCK_OPS_TIMEOUT_INIT, 0, NULL);
    // timeout <= 0, 使用默认值1秒
    if (timeout <= 0) timeout = TCP_TIMEOUT_INIT;
    return min_t(int, timeout, TCP_RTO_MAX);
}
```

* `BPF_SOCK_OPS_RWND_INIT`

返回初始通告窗口值，默认值为`-1`。在 `tcp_rwnd_init_bpf` 函数中调用，如下：

```C
// file: include/net/tcp.h
static inline u32 tcp_rwnd_init_bpf(struct sock *sk)
{
    int rwnd;
    // 调用0个额外参数的 `SOCK_OPS` BPF程序
    rwnd = tcp_call_bpf(sk, BPF_SOCK_OPS_RWND_INIT, 0, NULL);
    // 初始窗口值小于0，设置为0
    if (rwnd < 0) rwnd = 0;
    return rwnd;
}
```

* `BPF_SOCK_OPS_TCP_CONNECT_CB`

在TCP客户端建立连接(`connect`系统调用)前调用，如下：

```C
// file: net/ipv4/tcp_output.c
int tcp_connect(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct sk_buff *buff;
    int err;
    // 调用0个额外参数的 `SOCK_OPS` BPF程序
    tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_CONNECT_CB, 0, NULL);

    if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
        return -EHOSTUNREACH; /* Routing failure or similar. */
    
    // TCP连接初始化，在其中调用`tcp_rwnd_init_bpf`、`tcp_timeout_init`函数
    tcp_connect_init(sk);

    if (unlikely(tp->repair)) { tcp_finish_connect(sk, NULL); return 0; }
    // 分配skb
    buff = tcp_stream_alloc_skb(sk, 0, sk->sk_allocation, true);
    if (unlikely(!buff)) return -ENOBUFS;
    // 初始化skb
    tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
    tcp_mstamp_refresh(tp);
    tp->retrans_stamp = tcp_time_stamp(tp);
    tcp_connect_queue_skb(sk, buff);
    // SYN中设置`ECN`状态
    tcp_ecn_send_syn(sk, buff);
    // 添加skb到发送队列中
    tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);

    // 发送SYN数据包，包括Fast Open的数据
    err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) :
            tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
    if (err == -ECONNREFUSED) return err;

    // 修改`tp->snd_nxt`
    WRITE_ONCE(tp->snd_nxt, tp->write_seq);
    tp->pushed_seq = tp->write_seq;
    buff = tcp_send_head(sk);
    if (unlikely(buff)) {
        WRITE_ONCE(tp->snd_nxt, TCP_SKB_CB(buff)->seq);
        tp->pushed_seq	= TCP_SKB_CB(buff)->seq;
    }
    TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);

    // 设置重传定时器，重传SYN直到响应
    inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
    return 0;
}
```

* `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB`

在TCP客户端建立连接(`connect`系统调用)后，进入`SYN_SENT`状态，在接收到服务端的ACK后，完成三次握手时调用，如下：

```C
// file: net/ipv4/tcp_input.c
void tcp_finish_connect(struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    // 设置sk为`ESTABLISHED`状态
    tcp_set_state(sk, TCP_ESTABLISHED);
    icsk->icsk_ack.lrcvtime = tcp_jiffies32;
    if (skb) {
        icsk->icsk_af_ops->sk_rx_dst_set(sk, skb);
        security_inet_conn_established(sk, skb);
        sk_mark_napi_id(sk, skb);
    }
    // 初始化拥塞窗口以开始传输，此时为主动建立的连接
    tcp_init_transfer(sk, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, skb);

    tp->lsndtime = tcp_jiffies32;
    // 激活保活定时器
    if (sock_flag(sk, SOCK_KEEPOPEN))
        inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tp));
    // 首部预测标记设置
    if (!tp->rx_opt.snd_wscale) __tcp_fast_path_on(tp, tp->snd_wnd);
    else tp->pred_flags = 0;
}
```

`tcp_init_transfer`函数在建立连接时初始化拥塞窗口，如下:

```C
// file: net/ipv4/tcp_input.c
void tcp_init_transfer(struct sock *sk, int bpf_op, struct sk_buff *skb)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    // MTU探测设置
    tcp_mtup_init(sk);
    icsk->icsk_af_ops->rebuild_header(sk);
    // 初始化指标参数
    tcp_init_metrics(sk);

    // 初始化拥塞窗口
    if (tp->total_retrans > 1 && tp->undo_marker) tcp_snd_cwnd_set(tp, 1);
    else tcp_snd_cwnd_set(tp, tcp_init_cwnd(tp, __sk_dst_get(sk)));
    tp->snd_cwnd_stamp = tcp_jiffies32;
    // 连接连接时调用BPF程序
    bpf_skops_established(sk, bpf_op, skb);
    // 初始化拥塞控制
    if (!icsk->icsk_ca_initialized) tcp_init_congestion_control(sk);
    // 初始化传输需要的空间
    tcp_init_buffer_space(sk);
}
```

`bpf_skops_established`函数在建立TCP连接前调用BPF程序，如下:

```C
// file: net/ipv4/tcp_input.c
static void bpf_skops_established(struct sock *sk, int bpf_op, struct sk_buff *skb)
{
    struct bpf_sock_ops_kern sock_ops;
    sock_owned_by_me(sk);
    // 设置`sock_ops`参数
    memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));
    sock_ops.op = bpf_op;
    sock_ops.is_fullsock = 1;
    sock_ops.sk = sk;
    // 初始化`sock_ops`数据的开始、结束位置
    if (skb) bpf_skops_init_skb(&sock_ops, skb, tcp_hdrlen(skb));
    // 运行`SOCK_OPS` BPF程序
    BPF_CGROUP_RUN_PROG_SOCK_OPS(&sock_ops);
}
```

* `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`

在TCP服务端接收客户端连接申请后(`SYN_RECV`状态)，建立与客户端的连接时调用，如下：

```C
// file: net/ipv4/tcp_input.c
int tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    const struct tcphdr *th = tcp_hdr(skb);
    struct request_sock *req;
    int queued = 0;
    bool acceptable;
    SKB_DR(reason);

    // `CLOSE`,`LISTEN`,`SYN_SENT`状态处理
    switch (sk->sk_state) {
	case TCP_CLOSE: ...
	case TCP_LISTEN: ...
	case TCP_SYN_SENT: ...
    }

    // 刷新TCP socket时间戳
    tcp_mstamp_refresh(tp);
    tp->rx_opt.saw_tstamp = 0;
    req = rcu_dereference_protected(tp->fastopen_rsk, lockdep_sock_is_held(sk));
    // 快速打开的请求处理过程
    if (req) {
        bool req_stolen;
        WARN_ON_ONCE(sk->sk_state != TCP_SYN_RECV && sk->sk_state != TCP_FIN_WAIT1);
        // SYN_RECV套接字的传入数据包的处理
        if (!tcp_check_req(sk, skb, req, true, &req_stolen)) {
            SKB_DR_SET(reason, TCP_FASTOPEN); goto discard;
        }
    }
    // tcp头部标记检查，确定是有效的tcp数据包
    if (!th->ack && !th->rst && !th->syn) { 
        SKB_DR_SET(reason, TCP_FLAGS); goto discard;
    }
    // 基于`PAWS`和`seqno`进行校验
    if (!tcp_validate_incoming(sk, skb, th, 0)) return 0;
    /* step 5: check the ACK field */
    // 检查接收的TCP数据包的ACK字段
    acceptable = tcp_ack(sk, skb, FLAG_SLOWPATH | FLAG_UPDATE_TS_RECENT | FLAG_NO_CHALLENGE_ACK) > 0;
    if (!acceptable) {
        // 不能处理的TCP数据包，`SYN_RECV`状态时，发送`RST`
        if (sk->sk_state == TCP_SYN_RECV) return 1;	
        // 其他情况丢弃skb
        tcp_send_challenge_ack(sk);
        SKB_DR_SET(reason, TCP_OLD_ACK);
        goto discard;
    }
	switch (sk->sk_state) {
    case TCP_SYN_RECV:
        tp->delivered++; /* SYN-ACK delivery isn't tracked in tcp_ack */
        // 计算（上一个）SYNACK和ACK完成三次握手之间经过的时间
        if (!tp->srtt_us) tcp_synack_rtt_meas(sk, req);

        if (req) {
            // 处理TCP快速打开的请求
            tcp_rcv_synrecv_state_fastopen(sk);
        } else {
            // 处理正常客户端的请求
            tcp_try_undo_spurious_syn(sk);
            tp->retrans_stamp = 0;
            // 初始化拥塞窗口以开始传输，此时为被动建立的连接
            tcp_init_transfer(sk, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, skb);
            WRITE_ONCE(tp->copied_seq, tp->rcv_nxt);
        }
        smp_mb();
        tcp_set_state(sk, TCP_ESTABLISHED);
        sk->sk_state_change(sk);
        // 唤醒用户空间等待
        if (sk->sk_socket) sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
        // 发送窗口的位置和窗口设置
        tp->snd_una = TCP_SKB_CB(skb)->ack_seq;
        tp->snd_wnd = ntohs(th->window) << tp->rx_opt.snd_wscale;
        tcp_init_wl(tp, TCP_SKB_CB(skb)->seq);
        // 开启时间戳选项时，MSS减去时间戳的长度
        if (tp->rx_opt.tstamp_ok) tp->advmss -= TCPOLEN_TSTAMP_ALIGNED;

        if (!inet_csk(sk)->icsk_ca_ops->cong_control)
            tcp_update_pacing_rate(sk);

        tp->lsndtime = tcp_jiffies32;
        // 初始化`RCV_MSS`值
        tcp_initialize_rcv_mss(sk);
        tcp_fast_path_on(tp);
        break;
	case TCP_FIN_WAIT1:  { ... }
	case TCP_CLOSING: ...
	case TCP_LAST_ACK: ...
    }
    ...
    ...
    ...
    if (!queued) {
discard:
        tcp_drop_reason(sk, skb, reason);
    }
    return 0;
consume:
    __kfree_skb(skb);
    return 0;
}
```

* `BPF_SOCK_OPS_NEEDS_ECN`

检查TCP连接的拥塞控制是否需要`ECN`，如下：

```C
// file: include/net/tcp.h
static inline bool tcp_bpf_ca_needs_ecn(struct sock *sk)
{
    return (tcp_call_bpf(sk, BPF_SOCK_OPS_NEEDS_ECN, 0, NULL) == 1);
}
```

在创建TCP连接时调用，如下：

```C
// file: net/ipv4/tcp_input.c
static void tcp_ecn_create_request(struct request_sock *req, const struct sk_buff *skb,
                    const struct sock *listen_sk, const struct dst_entry *dst)
{
    const struct tcphdr *th = tcp_hdr(skb);
    const struct net *net = sock_net(listen_sk);
    bool th_ecn = th->ece && th->cwr;
    bool ect, ecn_ok;
    u32 ecn_ok_dst;
    // 检查是否启用`ecn`
    if (!th_ecn) return;

    ect = !INET_ECN_is_not_ect(TCP_SKB_CB(skb)->ip_dsfield);
    ecn_ok_dst = dst_feature(dst, DST_FEATURE_ECN_MASK);
    // 检查是否开启`ECN`, 通过`net.ipv4.tcp_ecn`参数控制
    ecn_ok = READ_ONCE(net->ipv4.sysctl_tcp_ecn) || ecn_ok_dst;

    if (((!ect || th->res1) && ecn_ok) || tcp_ca_needs_ecn(listen_sk) ||
        (ecn_ok_dst & DST_FEATURE_ECN_CA) || tcp_bpf_ca_needs_ecn((struct sock *)req))
        inet_rsk(req)->ecn_ok = 1;
}
```

或者，在接收`SYN`后发送`SYN-ACK`过程中调用，以ipv4为例，设置`.send_synack`接口为`tcp_v4_send_synack`，实现如下：

```C
// file: net/ipv4/tcp_ipv4.c
static int tcp_v4_send_synack(const struct sock *sk, struct dst_entry *dst, struct flowi *fl, 
            struct request_sock *req, struct tcp_fastopen_cookie *foc, 
            enum tcp_synack_type synack_type, struct sk_buff *syn_skb)
{
    const struct inet_request_sock *ireq = inet_rsk(req);
    struct flowi4 fl4;
    int err = -1;
    struct sk_buff *skb;
    u8 tos;

    // 获取路由信息
    if (!dst && (dst = inet_csk_route_req(sk, &fl4, req)) == NULL) return -1;
    // 创建`synack`标记的skb
    skb = tcp_make_synack(sk, dst, req, foc, synack_type, syn_skb);

    if (skb) {
        // 发送检查
        __tcp_v4_send_check(skb, ireq->ir_loc_addr, ireq->ir_rmt_addr);
        // 获取tos
        tos = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_reflect_tos) ?
                (tcp_rsk(req)->syn_tos & ~INET_ECN_MASK) | (inet_sk(sk)->tos & INET_ECN_MASK) : 
                inet_sk(sk)->tos;
        // `ECN`标记设置，检查`ECN`是否开启
        if (!INET_ECN_is_capable(tos) && tcp_bpf_ca_needs_ecn((struct sock *)req))
            tos |= INET_ECN_ECT_0;

        rcu_read_lock();
        // 填充IP信息后发送
        err = ip_build_and_send_pkt(skb, sk, ireq->ir_loc_addr, ireq->ir_rmt_addr,
                rcu_dereference(ireq->ireq_opt), tos);
        rcu_read_unlock();
        err = net_xmit_eval(err);
    }
    return err;
}
```

或者，在建立连接期间发送的`SYN-ACK`的数据包，如下：

```C
// file: net/ipv4/tcp_output.c
static void tcp_ecn_send_synack(struct sock *sk, struct sk_buff *skb)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_CWR;

    if (!(tp->ecn_flags & TCP_ECN_OK)) 
        TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_ECE;
    else if (tcp_ca_needs_ecn(sk) || tcp_bpf_ca_needs_ecn(sk))
        INET_ECN_xmit(sk);
}
```

* `BPF_SOCK_OPS_BASE_RTT`

获取基础的RTT。正确的RTT基于传输路径，并且可以取决于拥塞控制算法。内核中`nv`拥塞控制算法在初始化过程中获取基础RTT，如下：

```C
// file: net/ipv4/tcp_nv.c
static struct tcp_congestion_ops tcpnv __read_mostly = {
    .init       = tcpnv_init,
    .ssthresh   = tcpnv_recalc_ssthresh,
    .cong_avoid = tcpnv_cong_avoid,
    .set_state  = tcpnv_state,
    .undo_cwnd  = tcp_reno_undo_cwnd,
    .pkts_acked = tcpnv_acked,
    .get_info   = tcpnv_get_info,
    .owner      = THIS_MODULE,
    .name       = "nv",
};
```

在`.init`接口中调用，如下：

```C
// file: net/ipv4/tcp_nv.c
static void tcpnv_init(struct sock *sk)
{
    struct tcpnv *ca = inet_csk_ca(sk);
    int base_rtt;
    tcpnv_reset(ca, sk);

    // 获取基准的RTT，检查`SOCK_OPS` BPF程序是否提供RRT
    base_rtt = tcp_call_bpf(sk, BPF_SOCK_OPS_BASE_RTT, 0, NULL);
    if (base_rtt > 0) {
        ca->nv_base_rtt = base_rtt;
        ca->nv_lower_bound_rtt = (base_rtt * 205) >> 8; /* 80% */
    } else {
        ca->nv_base_rtt = 0;
        ca->nv_lower_bound_rtt = 0;
    }
    // ca使用的参数初始化
    ca->nv_allow_cwnd_growth = 1;
    ca->nv_min_rtt_reset_jiffies = jiffies + 2 * HZ;
    ca->nv_min_rtt = NV_INIT_RTT;
    ca->nv_min_rtt_new = NV_INIT_RTT;
    ca->nv_min_cwnd = NV_MIN_CWND;
    ca->nv_catchup = 0;
    ca->cwnd_growth_factor = 0;
}
```

* `BPF_SOCK_OPS_RTO_CB`

在发送超时(RTO)时触发，如下：

```C
// file: net/ipv4/tcp_timer.c
static int tcp_write_timeout(struct sock *sk)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    struct net *net = sock_net(sk);
    bool expired = false, do_reset;
    int retry_until;

    if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
        if (icsk->icsk_retransmits)  __dst_negative_advice(sk);
        // 获取重传次数，可通过`net.ipv4.tcp_syn_retries`参数设置
        retry_until = icsk->icsk_syn_retries ? : READ_ONCE(net->ipv4.sysctl_tcp_syn_retries);
        expired = icsk->icsk_retransmits >= retry_until;
    } else {
        // 放弃回应TCP连接的重试次数，通过`net.ipv4.tcp_retries1`参数设置，默认3
        if (retransmits_timed_out(sk, READ_ONCE(net->ipv4.sysctl_tcp_retries1), 0)) {
            // MTU探测
            tcp_mtu_probing(icsk, sk);
            __dst_negative_advice(sk);
        }
        // 丢弃激活的TCP连接的重试次数，通过`net.ipv4.tcp_retries3`参数设置，默认15
        retry_until = READ_ONCE(net->ipv4.sysctl_tcp_retries2);
        if (sock_flag(sk, SOCK_DEAD)) {
            // 连接关闭时的重试次数
            const bool alive = icsk->icsk_rto < TCP_RTO_MAX;
            retry_until = tcp_orphan_retries(sk, alive);
            do_reset = alive || !retransmits_timed_out(sk, retry_until, 0);
            if (tcp_out_of_resources(sk, do_reset)) return 1;
        }
    }
    // 检查是否传输超时
    if (!expired) 
        expired = retransmits_timed_out(sk, retry_until, icsk->icsk_user_timeout);
    tcp_fastopen_active_detect_blackhole(sk, expired);

    // 设置`RTO`标记时，调用`RTO` BPF程序
    if (BPF_SOCK_OPS_TEST_FLAG(tp, BPF_SOCK_OPS_RTO_CB_FLAG))
        tcp_call_bpf_3arg(sk, BPF_SOCK_OPS_RTO_CB, icsk->icsk_retransmits, icsk->icsk_rto, (int)expired);
    // 发送超时时，写入错误
    if (expired) { tcp_write_err(sk); return 1; }

    if (sk_rethink_txhash(sk)) {
        tp->timeout_rehash++;
        __NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPTIMEOUTREHASH);
    }
    return 0;
}
```

* `BPF_SOCK_OPS_RETRANS_CB`

在重传skb时触发，如下：

```C
// file: net/ipv4/tcp_output.c
int __tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    unsigned int cur_mss;
    int diff, len, err;
    int avail_wnd;

    // 不能确定MTU探测的大小
    if (icsk->icsk_mtup.probe_size) icsk->icsk_mtup.probe_size = 0;

    if (skb_still_in_host_queue(sk, skb)) return -EBUSY;
    // skb序号在确认的发送窗口数据前的处理
    if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) { ... }
    // 重新构建头部信息
    if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk)) return -EHOSTUNREACH; 
    
    // 当前mss和wnd大小
    cur_mss = tcp_current_mss(sk);
    avail_wnd = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

    // 接收方缩小窗口时，skb不在新窗口时，不发送。窗口为0时发送探测零窗口探测帧
    if (avail_wnd <= 0) {
        if (TCP_SKB_CB(skb)->seq != tp->snd_una) return -EAGAIN;
        avail_wnd = cur_mss;
    }
    // 发送长度计算，超过窗口大小时，减少发送长度
    len = cur_mss * segs;
    if (len > avail_wnd) {
        len = rounddown(avail_wnd, cur_mss);
        if (!len) len = avail_wnd;
    }
    if (skb->len > len) {
        // skb超过发送长度时，进行分片
        if (tcp_fragment(sk, TCP_FRAG_IN_RTX_QUEUE, skb, len, cur_mss, GFP_ATOMIC))
            return -ENOMEM; /* We'll try again later. */
    } else {
        if (skb_unclone_keeptruesize(skb, GFP_ATOMIC)) return -ENOMEM;
        // 发送长度计算
        diff = tcp_skb_pcount(skb);
        tcp_set_skb_tso_segs(skb, cur_mss);
        diff -= tcp_skb_pcount(skb);
        if (diff) tcp_adjust_pcount(sk, skb, diff);
        avail_wnd = min_t(int, avail_wnd, cur_mss);
        if (skb->len < avail_wnd)
            tcp_retrans_try_collapse(sk, skb, avail_wnd);
    }

    /* RFC3168, section 6.1.1.1. ECN fallback */
    if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN_ECN) == TCPHDR_SYN_ECN)
        tcp_ecn_clear_syn(sk, skb);
    // 更新全局和本地的TCP统计信息
    segs = tcp_skb_pcount(skb);
    TCP_ADD_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS, segs);
    if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
        __NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSYNRETRANS);
    tp->total_retrans += segs;
    tp->bytes_retrans += skb->len;

    if (unlikely((NET_IP_ALIGN && ((unsigned long)skb->data & 3)) || skb_headroom(skb) >= 0xFFFF)) {
        // skb->data需要对齐时，按照CPU架构对齐后发送skb
        ...
    } else {
        // 无对齐要求时，直接发送skb
        err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
    }
    // `EVER_RETRANS`标记是为了避免从未发生的传输时间戳标记为低RTT样本
    TCP_SKB_CB(skb)->sacked |= TCPCB_EVER_RETRANS;
    // 设置`RETRANS_CB`标记时，调用`RETRANS_CB` BPF程序
    if (BPF_SOCK_OPS_TEST_FLAG(tp, BPF_SOCK_OPS_RETRANS_CB_FLAG))
        tcp_call_bpf_3arg(sk, BPF_SOCK_OPS_RETRANS_CB, TCP_SKB_CB(skb)->seq, segs, err);

    // 发送成功时，通过`tracepoint`统计，否则更新重传失败次数
    if (likely(!err)) {
        trace_tcp_retransmit_skb(sk, skb);
    } else if (err != -EBUSY) {
        NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPRETRANSFAIL, segs);
    }
    return err;
}
```

* `BPF_SOCK_OPS_STATE_CB`

在tcp状态变化时触发，如下：

```C
void tcp_set_state(struct sock *sk, int state)
{
	int oldstate = sk->sk_state;
    ...
    BTF_TYPE_EMIT_ENUM(BPF_TCP_ESTABLISHED);
    
    // 设置`STATE_CB`标记时，调用`STATE_CB` BPF程序
    if (BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk), BPF_SOCK_OPS_STATE_CB_FLAG))
        tcp_call_bpf_2arg(sk, BPF_SOCK_OPS_STATE_CB, oldstate, state);
    // 特殊状态的处理
    switch (state) {
    case TCP_ESTABLISHED:
        if (oldstate != TCP_ESTABLISHED) TCP_INC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
        break;
    case TCP_CLOSE:
        if (oldstate == TCP_CLOSE_WAIT || oldstate == TCP_ESTABLISHED)
            TCP_INC_STATS(sock_net(sk), TCP_MIB_ESTABRESETS);
        sk->sk_prot->unhash(sk);
        if (inet_csk(sk)->icsk_bind_hash && !(sk->sk_userlocks & SOCK_BINDPORT_LOCK))
            inet_put_port(sk);
        fallthrough;
    default:
        if (oldstate == TCP_ESTABLISHED) TCP_DEC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
    }
    // 设置`sk`状态
    inet_sk_state_store(sk, state);
}
```

* `BPF_SOCK_OPS_TCP_LISTEN_CB`

在服务端开启监听(`listen`系统调用)时触发，如下：

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

* `BPF_SOCK_OPS_RTT_CB`

在每次计算RTT时触发，如下：

```C
// file: include/net/tcp.h
static inline void tcp_bpf_rtt(struct sock *sk)
{
    if (BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk), BPF_SOCK_OPS_RTT_CB_FLAG))
        tcp_call_bpf(sk, BPF_SOCK_OPS_RTT_CB, 0, NULL);
}
```

* `BPF_SOCK_OPS_PARSE_HDR_OPT_CB`

解析TCP头部信息，在处理已建立连接的网络数据包时(`tcp_validate_incoming`函数中)触发，其实现如下：

```C
// file: net/ipv4/tcp_input.c
static void bpf_skops_parse_hdr(struct sock *sk, struct sk_buff *skb)
{
    bool unknown_opt = tcp_sk(sk)->rx_opt.saw_unknown &&
                BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk), BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);
    bool parse_all_opt = BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk), BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG);
    struct bpf_sock_ops_kern sock_ops;
    // 检查sk标记设置，需要设置`UNKNOWN_HDR_OPT`或者`ALL_HDR_OPT`
    if (likely(!unknown_opt && !parse_all_opt)) return;

    // `SYN_RECV`，`SYN_SENT`，`LISTEN`三种状态通过其他方式调用
    switch (sk->sk_state) {
    case TCP_SYN_RECV:
    case TCP_SYN_SENT:
    case TCP_LISTEN:
        return;
    }
    sock_owned_by_me(sk);
    // 设置`sock_ops`参数
    memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));
    sock_ops.op = BPF_SOCK_OPS_PARSE_HDR_OPT_CB;
    sock_ops.is_fullsock = 1;
    sock_ops.sk = sk;
    bpf_skops_init_skb(&sock_ops, skb, tcp_hdrlen(skb));
    // 运行`SOCK_OPS` BPF程序
    BPF_CGROUP_RUN_PROG_SOCK_OPS(&sock_ops);
}
```

* `BPF_SOCK_OPS_HDR_OPT_LEN_CB`

为`BPF_SOCK_OPS_WRITE_HDR_OPT_CB`预留TCP选项头部空间，在计算建立的TCP连接的选项时( `tcp_established_options` 函数中 )调用。其实现如下：

```C
// file: net/ipv4/tcp_output.c
static void bpf_skops_hdr_opt_len(struct sock *sk, struct sk_buff *skb, 
            struct request_sock *req, struct sk_buff *syn_skb, enum tcp_synack_type synack_type, 
            struct tcp_out_options *opts,  unsigned int *remaining)
{
    struct bpf_sock_ops_kern sock_ops;
    int err;
    // 检查sk标记设置，需要设置`WRITE_HDR_OPT` 或者 已经设置了`remaining`
    if (likely(!BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk), BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG)) || !*remaining)
        return;

    // 设置`sock_ops`参数
    memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));
    sock_ops.op = BPF_SOCK_OPS_HDR_OPT_LEN_CB;
    if (req) {
        sock_ops.sk = (struct sock *)req;
        sock_ops.syn_skb = syn_skb;
    } else {
        sock_owned_by_me(sk);
        sock_ops.is_fullsock = 1;
        sock_ops.sk = sk;
    }
    // 参数设置
    sock_ops.args[0] = bpf_skops_write_hdr_opt_arg0(skb, synack_type);
    sock_ops.remaining_opt_len = *remaining;
    // skb存在时，设置`sock_ops`数据起止位置
    if (skb) bpf_skops_init_skb(&sock_ops, skb, 0);
    // 运行`SOCK_OPS_SK` BPF程序
    err = BPF_CGROUP_RUN_PROG_SOCK_OPS_SK(&sock_ops, sk);
    // 出现错误，或者预留长度相同时返回
    if (err || sock_ops.remaining_opt_len == *remaining) return;

    // 更新`remaining`参数，按照4字节对齐
    opts->bpf_opt_len = *remaining - sock_ops.remaining_opt_len;
    opts->bpf_opt_len = (opts->bpf_opt_len + 3) & ~3;
    *remaining -= opts->bpf_opt_len;
}
```

在BPF程序中 `bpf_reserve_hdr_opt()` 函数用于预留空间。

* `BPF_SOCK_OPS_WRITE_HDR_OPT_CB`

写入TCP选项，在发送skb( `__tcp_transmit_skb` 函数中 ) 或者 生成`SYNACK`类型的skb( `tcp_make_synack` 中)触发。在`bpf_skops_write_hdr_opt` 函数中调用，其实现如下：

```C
// file: net/ipv4/tcp_output.c
static void bpf_skops_write_hdr_opt(struct sock *sk, struct sk_buff *skb, struct request_sock *req,
                struct sk_buff *syn_skb, enum tcp_synack_type synack_type, struct tcp_out_options *opts)
{
    u8 first_opt_off, nr_written, max_opt_len = opts->bpf_opt_len;
    struct bpf_sock_ops_kern sock_ops;
    int err;
    // 最大选项长度为0时返回
    if (likely(!max_opt_len)) return;

    // 设置`sock_ops`参数
    memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));
    sock_ops.op = BPF_SOCK_OPS_WRITE_HDR_OPT_CB;
    if (req) {
        sock_ops.sk = (struct sock *)req;
        sock_ops.syn_skb = syn_skb;
    } else {
        sock_owned_by_me(sk);
        sock_ops.is_fullsock = 1;
        sock_ops.sk = sk;
    }
    // 参数设置
    sock_ops.args[0] = bpf_skops_write_hdr_opt_arg0(skb, synack_type);
    sock_ops.remaining_opt_len = max_opt_len;
    first_opt_off = tcp_hdrlen(skb) - max_opt_len;
    bpf_skops_init_skb(&sock_ops, skb, first_opt_off);

    // 运行`SOCK_OPS_SK` BPF程序
    err = BPF_CGROUP_RUN_PROG_SOCK_OPS_SK(&sock_ops, sk);
    // 计算写入的长度
    if (err) nr_written = 0;
    else nr_written = max_opt_len - sock_ops.remaining_opt_len;
    // 填充skb中剩余空间
    if (nr_written < max_opt_len)
        memset(skb->data + first_opt_off + nr_written, TCPOPT_NOP, max_opt_len - nr_written);
}
```

#### 5 `CGROUP_DEVICE`

##### (1) 实现过程

`CGROUP_DEVICE`用于检查文件的权限，在创建`inode`时需要检查其权限。在内核中通过`BPF_CGROUP_RUN_PROG_DEVICE_CGROUP`宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(atype, major, minor, access)          \
({                                                                              \
    int __ret = 0;                                                              \
    if (cgroup_bpf_enabled(CGROUP_DEVICE))                                      \
        __ret = __cgroup_bpf_check_dev_permission(atype, major, minor,          \
                                access, CGROUP_DEVICE);                         \
                                                                                \
    __ret;                                                                      \
})
```

在device设置了有效的cgroup bpf程序后，调用`__cgroup_bpf_check_dev_permission`函数，如下：

```C
// file: kernel/bpf/cgroup.c
int __cgroup_bpf_check_dev_permission(short dev_type, u32 major, u32 minor,
                    short access, enum cgroup_bpf_attach_type atype)
{
    struct cgroup *cgrp;
    // 设置上下文
    struct bpf_cgroup_dev_ctx ctx = {
        .access_type = (access << 16) | dev_type,
        .major = major,
        .minor = minor,
    };
    int ret;

    rcu_read_lock();
    // 获取所属的cgroup后，运行cgroup bpf程序
    cgrp = task_dfl_cgroup(current);
    ret = bpf_prog_run_array_cg(&cgrp->bpf, atype, &ctx, bpf_prog_run, 0, NULL);
    rcu_read_unlock();
    return ret;
}
```

##### (2) 触发过程

在创建`inode`时检查权限，在检查过程中通过cgroup bpf程序检查，如下：

```C
// file: fs/namei.c
int inode_permission(struct mnt_idmap *idmap, struct inode *inode, int mask)
    --> retval = sb_permission(inode->i_sb, inode, mask);
    --> retval = do_inode_permission(idmap, inode, mask);
    --> retval = devcgroup_inode_permission(inode, mask);
        --> return devcgroup_check_permission(type, imajor(inode), iminor(inode), access);
    --> return security_inode_permission(inode, mask);
```

`devcgroup_check_permission` 函数检查`devcgroup`的权限，如下：

```C
// file: security/device_cgroup.c
int devcgroup_check_permission(short type, u32 major, u32 minor, short access)
{
    // 运行`DEVICE` BPF程序
    int rc = BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(type, major, minor, access);
    if (rc) return rc;
    #ifdef CONFIG_CGROUP_DEVICE
        // 传统方式检查权限
        return devcgroup_legacy_check_permission(type, major, minor, access);
    #else /* CONFIG_CGROUP_DEVICE */
        return 0;
    #endif /* CONFIG_CGROUP_DEVICE */
}
```

#### 6 `CGROUP_INET4_BIND`

##### (1) 实现过程

`CGROUP_INET4_BIND`在ipv4的socket在绑定地址(`bind`系统调用)时调用，通过 `BPF_CGROUP_RUN_PROG_INET_BIND_LOCK` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET_BIND_LOCK(sk, uaddr, atype, bind_flags)    \
({                                                                          \
    u32 __flags = 0;                                                        \
    int __ret = 0;                                                          \
    if (cgroup_bpf_enabled(atype))	{                                       \
        lock_sock(sk);                                                      \
        __ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, atype,         \
                                NULL, &__flags);                            \
        release_sock(sk);                                                   \
        if (__flags & BPF_RET_BIND_NO_CAP_NET_BIND_SERVICE)                 \
            *bind_flags |= BIND_NO_CAP_NET_BIND_SERVICE;                    \
    }                                                                       \
    __ret;                                                                  \
})
```

在设置了有效的cgroup bpf程序后，调用`__cgroup_bpf_run_filter_sock_addr`函数，该函数在运行bpf程序时指定的sk和用户空间的地址，支持`INET`和`INET6`。如下：

```C
// file: kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_sock_addr(struct sock *sk, struct sockaddr *uaddr,
                    enum cgroup_bpf_attach_type atype, void *t_ctx, u32 *flags)
{
    // 设置BPF上下文
    struct bpf_sock_addr_kern ctx = {
        .sk = sk,
        .uaddr = uaddr,
        .t_ctx = t_ctx,
    };
    struct sockaddr_storage unspec;
    struct cgroup *cgrp;
    // 检查socket的family，支持`INET`和`INET6`
    if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
        return 0;
    // 设置用户空间地址
    if (!ctx.uaddr) {
        memset(&unspec, 0, sizeof(unspec));
        ctx.uaddr = (struct sockaddr *)&unspec;
    }
    // 获取所属的cgroup后，运行cgroup bpf程序
    cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    return bpf_prog_run_array_cg(&cgrp->bpf, atype, &ctx, bpf_prog_run, 0, flags);
}
```

`bind`系统调用实现如下：

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
    // 获取fd对应的socket
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (sock) {
        // 将用户空间的地址复制到内核空间
        err = move_addr_to_kernel(umyaddr, addrlen, &address);
        if (!err) {
            // LSM安全检查
            err = security_socket_bind(sock, (struct sockaddr *)&address, addrlen);
            // `.bind`接口调用
            if (!err) err = sock->ops->bind(sock, (struct sockaddr *)&address, addrlen);
        }
        fput_light(sock->file, fput_needed);
    }
    return err;
}
```

##### (2) 触发过程

ipv4下TCP、UDP、RAW类型的socket在Linux内核中的`.bind`接口都设置为`inet_bind`，如下：

```C
// file: net/ipv4/af_inet.c
// TCP
const struct proto_ops inet_stream_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    .release        = inet_release,
    .bind           = inet_bind,
    ...
};
// UDP
const struct proto_ops inet_dgram_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    .release        = inet_release,
    .bind           = inet_bind,
    ...
};
// RAW
static const struct proto_ops inet_sockraw_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    .release        = inet_release,
    .bind           = inet_bind,
    ...
};
```

其实现如下：

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

    // INET4_BIND BPF程序检查
    err = BPF_CGROUP_RUN_PROG_INET_BIND_LOCK(sk, uaddr, CGROUP_INET4_BIND, &flags);
    if (err) return err;
    // ipv4的`bind`实现
    return __inet_bind(sk, uaddr, addr_len, flags);
}
```

#### 7 `CGROUP_INET6_BIND`

##### (1) 实现过程

`CGROUP_INET6_BIND`的实现过程和`CGROUP_INET4_BIND`类似，在ipv6的socket在绑定地址(`bind`系统调用)时调用，通过通过 `BPF_CGROUP_RUN_PROG_INET_BIND_LOCK` 宏实现。

##### (2) 触发过程

ipv6下TCP、UDP类型的socket在Linux内核中的`.bind`接口都设置为`inet6_bind`，如下：

```C
// file: net/ipv6/af_inet6.c
// TCP
const struct proto_ops inet6_stream_ops = {
    .family         = PF_INET6,
    .owner          = THIS_MODULE,
    .release        = inet6_release,
    .bind           = inet6_bind,
    ...
};
// UDP
const struct proto_ops inet6_dgram_ops = {
    .family         = PF_INET6,
    .owner          = THIS_MODULE,
    .release        = inet6_release,
    .bind           = inet6_bind,
    ...
};
```

其实现如下：

```C
// file: net/ipv6/af_inet6.c
int inet6_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    struct sock *sk = sock->sk;
    u32 flags = BIND_WITH_LOCK;
    const struct proto *prot;
    int err = 0;

    prot = READ_ONCE(sk->sk_prot);
    // socket设置了自己的bind方法时，使用
    if (prot->bind) return prot->bind(sk, uaddr, addr_len);
    // 检查地址长度是否正确
    if (addr_len < SIN6_LEN_RFC2133) return -EINVAL;

    // INET6_BIND BPF程序检查
    err = BPF_CGROUP_RUN_PROG_INET_BIND_LOCK(sk, uaddr, CGROUP_INET6_BIND, &flags);
    if (err) return err;
    // ipv6的`bind`实现
    return __inet6_bind(sk, uaddr, addr_len, flags);
}
```

#### 8 `CGROUP_INET4_CONNECT`

##### (1) 实现过程

`CGROUP_INET4_CONNECT`在ipv4的socket在连接到其他地址前(`connect`系统调用)调用，通过 `BPF_CGROUP_RUN_PROG_INET4_CONNECT` 宏 或 `BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT(sk, uaddr)                    \
    BPF_CGROUP_RUN_SA_PROG(sk, uaddr, CGROUP_INET4_CONNECT)

#define BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr)               \
    BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_INET4_CONNECT, NULL)
```

`BPF_CGROUP_RUN_SA_PROG` 宏和 `BPF_CGROUP_RUN_SA_PROG_LOCK` 宏在检查对应类型的BPF程序开启后运行BPF程序，其定义如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_SA_PROG(sk, uaddr, atype)                        \
({                                                                      \
    int __ret = 0;                                                      \
    if (cgroup_bpf_enabled(atype))                                      \
        __ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, atype,     \
                                NULL, NULL);                            \
    __ret;                                                              \
})

// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, atype, t_ctx)            \
({                                                                      \
    int __ret = 0;                                                      \
    if (cgroup_bpf_enabled(atype))	{                                   \
        lock_sock(sk);                                                  \
        __ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, atype,     \
                                t_ctx, NULL);                           \
        release_sock(sk);                                               \
    }                                                                   \
    __ret;                                                              \
})
```

`connect`系统调用实现如下：

```C
// file: net/socket.c
SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr, int, addrlen)
{
    return __sys_connect(fd, uservaddr, addrlen);
}
// file: net/socket.c
int __sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
    int ret = -EBADF;
    struct fd f;
    // 根据fd获取文件信息
    f = fdget(fd);
    if (f.file) {
        struct sockaddr_storage address;
        // 复制连接地址到内核空间
        ret = move_addr_to_kernel(uservaddr, addrlen, &address);
        // connect操作
        if (!ret) ret = __sys_connect_file(f.file, &address, addrlen, 0);
        fdput(f);
    }
    return ret;
}
```

`__sys_connect_file`函数实现尝试连接到服务器地址，实现如下：

```C
// file: net/socket.c
int __sys_connect_file(struct file *file, struct sockaddr_storage *address, int addrlen, int file_flags)
{
    struct socket *sock;
    int err;
    // 根据file获取socket
    sock = sock_from_file(file);
    if (!sock) { err = -ENOTSOCK; goto out; }
    // LSM安全检查
    err = security_socket_connect(sock, (struct sockaddr *)address, addrlen);
    if (err) goto out;
    // `.connect`接口调用
    err = sock->ops->connect(sock, (struct sockaddr *)address, addrlen, sock->file->f_flags | file_flags);
out:
    return err;
}
```

##### (2) TCP的触发过程

TCP在内核中的`.ops`设置为`inet_stream_ops`, `.prot`设置为`tcp_prot`。如下：

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
}
```

`inet_stream_ops`的`.connect`接口设置为 `inet_stream_connect`，如下：

```C
// file: net/ipv4/af_inet.c
const struct proto_ops inet_stream_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    ...
    .connect        = inet_stream_connect,
    ...
};
```

是对 `__inet_stream_connect` 函数的封装，其实现如下：

```C
// file: net/ipv4/af_inet.c
int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags)
{
    int err;
    lock_sock(sock->sk);
    err = __inet_stream_connect(sock, uaddr, addr_len, flags, 0);
    release_sock(sock->sk);
    return err;
}
```

`__inet_stream_connect` 函数完成数据流连接的建立，如下：

```C
// file: net/ipv4/af_inet.c
int __inet_stream_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags, int is_sendmsg)
{
    struct sock *sk = sock->sk;
    int err;
    long timeo;

    // 用户空间地址检查
    if (uaddr) {
        if (addr_len < sizeof(uaddr->sa_family)) return -EINVAL;
        if (uaddr->sa_family == AF_UNSPEC) {
            err = sk->sk_prot->disconnect(sk, flags);
            sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
            goto out;
        }
    }
    // 检查sk状态
    switch (sock->state) {
    default: err = -EINVAL; goto out;
    case SS_CONNECTED: err = -EISCONN; goto out;
    case SS_CONNECTING:
        if (inet_sk(sk)->defer_connect)
            err = is_sendmsg ? -EINPROGRESS : -EISCONN;
        else
            err = -EALREADY;
        break;
    case SS_UNCONNECTED:
        // 未连接状态时
        err = -EISCONN;
        if (sk->sk_state != TCP_CLOSE) goto out;
        // 检查并调用`.pre_connect`接口
        if (BPF_CGROUP_PRE_CONNECT_ENABLED(sk)) {
            err = sk->sk_prot->pre_connect(sk, uaddr, addr_len);
            if (err) goto out;
        }
        // 调用`.connect`接口
        err = sk->sk_prot->connect(sk, uaddr, addr_len);
        if (err < 0) goto out;
        // 修改状态为连接中
        sock->state = SS_CONNECTING;
        if (!err && inet_sk(sk)->defer_connect) goto out;
        err = -EINPROGRESS;
        break;
    }
    // 获取发送超时时间
    timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);
    // `SYN_SENT` 或 `SYN_RECV` 状态时等待连接建立
    if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
        int writebias = (sk->sk_protocol == IPPROTO_TCP) &&
                tcp_sk(sk)->fastopen_req &&
                tcp_sk(sk)->fastopen_req->data ? 1 : 0;
        // 设置等待时间时，等待连接建立
        if (!timeo || !inet_wait_for_connect(sk, timeo, writebias)) goto out;
        err = sock_intr_errno(timeo);
        if (signal_pending(current)) goto out;
    }
    // RST关闭连接、连接超时、ICMP错误、用户进程关闭时，进行关闭处理
    if (sk->sk_state == TCP_CLOSE) goto sock_error;
    // 设置为已连接状态
    sock->state = SS_CONNECTED;
    err = 0;
out:
    return err;

sock_error:
    // 出现错误时，断开连接
    err = sock_error(sk) ? : -ECONNABORTED;
    sock->state = SS_UNCONNECTED;
    if (sk->sk_prot->disconnect(sk, flags))
        sock->state = SS_DISCONNECTING;
    goto out;
}
```

在上面的建立连接过程中，在调用`.pre_connect`接口之后，调用 `.connect` 接口。`tcp_prot`的`.pre_connect`接口设置为`tcp_v4_pre_connect`，如下：

```C
// file: net/ipv4/tcp_ipv4.c
struct proto tcp_prot = {
    .name           = "TCP",
    .owner          = THIS_MODULE,
    .close          = tcp_close,
    .pre_connect    = tcp_v4_pre_connect,
    .connect        = tcp_v4_connect,
    .disconnect     = tcp_disconnect,
    ...
};
```

其实现如下：

```C
// file: net/ipv4/tcp_ipv4.c
static int tcp_v4_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    // 检查地址长度
    if (addr_len < sizeof(struct sockaddr_in)) return -EINVAL;
    sock_owned_by_me(sk);
    // 运行`INET4_CONNECT`类型的CGROUP BPF程序
    return BPF_CGROUP_RUN_PROG_INET4_CONNECT(sk, uaddr);
}
```

##### (3) UDP的触发过程

UDP在内核中的`.ops`设置为`inet_dgram_ops`, `.prot`设置为`udp_prot`。如下：

```C
// file: net/ipv4/af_inet.c
static struct inet_protosw inetsw_array[] =
{
    ...
    {
        .type =         SOCK_DGRAM,
        .protocol =     IPPROTO_UDP,
        .prot =         &udp_prot,
        .ops =          &inet_dgram_ops,
        .flags =        INET_PROTOSW_PERMANENT,
    },
    ...
}
```

`inet_dgram_ops`的`.connect`接口设置为 `inet_dgram_connect`，如下：

```C
// file: net/ipv4/af_inet.c
const struct proto_ops inet_dgram_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    ...
    .connect        = inet_dgram_connect,
    ...
};
```

其实现如下：

```C
// file: net/ipv4/af_inet.c
int inet_dgram_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags)
{
    struct sock *sk = sock->sk;
    const struct proto *prot;
    int err;
    // 检查用户空间设置的地址长度
    if (addr_len < sizeof(uaddr->sa_family)) return -EINVAL;

    prot = READ_ONCE(sk->sk_prot);
    // 检查地址的协议家族
    if (uaddr->sa_family == AF_UNSPEC) return prot->disconnect(sk, flags);
    // 检查并调用`.pre_connect`接口
    if (BPF_CGROUP_PRE_CONNECT_ENABLED(sk)) {
        err = prot->pre_connect(sk, uaddr, addr_len);
        if (err) return err;
    }
    if (data_race(!inet_sk(sk)->inet_num) && inet_autobind(sk)) return -EAGAIN;
    // 调用`.connect`接口
    return prot->connect(sk, uaddr, addr_len);
}
```

和TCP类似，在连接过程中，在调用`.pre_connect`接口之后调用 `.connect` 接口。`udp_prot`的`.pre_connect`接口设置为`udp_pre_connect`，如下：

```C
// file: net/ipv4/udp.c
struct proto udp_prot = {
    .name           = "UDP",
    .owner          = THIS_MODULE,
    .close          = udp_lib_close,
    .pre_connect    = udp_pre_connect,
    .connect        = ip4_datagram_connect,
    .disconnect     = udp_disconnect,
    ...
};
```

其实现如下：

```C
// file: net/ipv4/udp.c
int udp_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    // 检查地址长度
    if (addr_len < sizeof(struct sockaddr_in)) return -EINVAL;
    // 运行`INET4_CONNECT`类型的CGROUP BPF程序
    return BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr);
}
```

##### (4) ICMP的触发过程

ICMP在内核中的`.ops`设置为`inet_sockraw_ops`, `.prot`设置为`ping_prot`。如下：

```C
// file: net/ipv4/af_inet.c
static struct inet_protosw inetsw_array[] =
{
    ...
    {
        .type =         SOCK_DGRAM,
        .protocol =     IPPROTO_ICMP,
        .prot =         &ping_prot,
        .ops =          &inet_sockraw_ops,
        .flags =        INET_PROTOSW_REUSE,
    },
    ...
}
```

`inet_sockraw_ops`的`.connect`接口设置为 `inet_dgram_connect`，见上。

`ping_prot`的`.pre_connect`接口设置为`ping_pre_connect`，如下：

```C
// file: net/ipv4/ping.c
struct proto ping_prot = {
    .name =     "PING",
    .owner =    THIS_MODULE,
    .init =     ping_init_sock,
    .close =    ping_close,
    .pre_connect =  ping_pre_connect,
    .connect =  ip4_datagram_connect,
    .disconnect =   __udp_disconnect,
    ...
};
```

其实现如下：

```C
// file: net/ipv4/ping.c
static int ping_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    // 检查地址长度
    if (addr_len < sizeof(struct sockaddr_in)) return -EINVAL;
    // 运行`INET4_CONNECT`类型的CGROUP BPF程序
    return BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr);
}
```

#### 9 `CGROUP_INET6_CONNECT`

##### (1) 实现过程

`CGROUP_INET6_CONNECT`在ipv6的socket在连接到其他地址前(`connect`系统调用)调用，实现过程和 `CGROUP_INET4_CONNECT` 类似，也是通过 `BPF_CGROUP_RUN_PROG_INET6_CONNECT` 和 `BPF_CGROUP_RUN_PROG_INET6_CONNECT_LOCK` 宏实现。，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET6_CONNECT(sk, uaddr)                    \
    BPF_CGROUP_RUN_SA_PROG(sk, uaddr, CGROUP_INET6_CONNECT)

#define BPF_CGROUP_RUN_PROG_INET6_CONNECT_LOCK(sk, uaddr)               \
    BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_INET6_CONNECT, NULL)
```

`BPF_CGROUP_RUN_SA_PROG` 宏和 `BPF_CGROUP_RUN_SA_PROG_LOCK` 宏的实现见上。

##### (2) TCP的触发过程

TCP在内核中的`.ops`设置为`inet6_stream_ops`, `.prot`设置为`tcpv6_prot`。如下：

```C
// file: net/ipv6/tcp_ipv6.c
static struct inet_protosw tcpv6_protosw = {
    .type       =   SOCK_STREAM,
    .protocol   =   IPPROTO_TCP,
    .prot       =   &tcpv6_prot,
    .ops        =   &inet6_stream_ops,
    .flags      =   INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK,
};
```

`inet6_stream_ops`的`.connect`接口设置为 `inet_stream_connect`，如下：

```C
// file: net/ipv6/af_inet6.c
const struct proto_ops inet6_stream_ops = {
    .family         = PF_INET6,
    .owner          = THIS_MODULE,
    ...
    .connect        = inet_stream_connect,
    ...
};
```

`inet_stream_connect` 的实现见上节。

`tcpv6_prot`的`.pre_connect`接口设置为`tcp_v6_pre_connect`，如下：

```C
// file: net/ipv6/tcp_ipv6.c
struct proto tcpv6_prot = {
    .name           = "TCPv6",
    .owner          = THIS_MODULE,
    .close          = tcp_close,
    .pre_connect    = tcp_v6_pre_connect,
    .connect        = tcp_v6_connect,
    .disconnect     = tcp_disconnect,
    ...
};
```

其实现如下：

```C
// file:net/ipv6/tcp_ipv6.c
static int tcp_v6_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    // 检查地址长度
    if (addr_len < SIN6_LEN_RFC2133) return -EINVAL;
    sock_owned_by_me(sk);
    // 运行`INET6_CONNECT`类型的CGROUP BPF程序
    return BPF_CGROUP_RUN_PROG_INET6_CONNECT(sk, uaddr);
}
```

##### (3) UDP的触发过程

UDP在内核中的`.ops`设置为`inet_dgram_ops`, `.prot`设置为`udp_prot`。如下：

```C
// file: net/ipv6/udp.c
static struct inet_protosw udpv6_protosw = {
    .type       = SOCK_DGRAM,
    .protocol   = IPPROTO_UDP,
    .prot       = &udpv6_prot,
    .ops        = &inet6_dgram_ops,
    .flags      = INET_PROTOSW_PERMANENT,
};
```

`inet6_dgram_ops`的`.connect`接口设置为 `inet_dgram_connect`，如下：

```C
// file: net/ipv6/af_inet6.c
const struct proto_ops inet6_dgram_ops = {
    .family         = PF_INET6,
    .owner          = THIS_MODULE,
    ...
    .connect        = inet_dgram_connect,
    ...
};
```

`inet_dgram_connect`的实现参见上节。`udpv6_prot`的`.pre_connect`接口设置为`udpv6_pre_connect`，如下：

```C
// file: net/ipv6/udp.c
struct proto udpv6_prot = {
    .name           = "UDPv6",
    .owner          = THIS_MODULE,
    .close          = udp_lib_close,
    .pre_connect    = udpv6_pre_connect,
    .connect        = ip6_datagram_connect,
    .disconnect     = udp_disconnect,
    ...
};
```

其实现如下：

```C
// file: net/ipv6/udp.c
static int udpv6_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    if (addr_len < offsetofend(struct sockaddr, sa_family)) return -EINVAL;
    // ipv4地址的处理过程
    if (uaddr->sa_family == AF_INET) {
        if (ipv6_only_sock(sk)) return -EAFNOSUPPORT;
        return udp_pre_connect(sk, uaddr, addr_len);
	}
    // ipv6地址长度检查
    if (addr_len < SIN6_LEN_RFC2133) return -EINVAL;
    // 运行`INET6_CONNECT`类型的CGROUP BPF程序
    return BPF_CGROUP_RUN_PROG_INET6_CONNECT_LOCK(sk, uaddr);
}
```

#### 10 `CGROUP_INET4_POST_BIND`

##### (1) 实现过程

`CGROUP_INET4_POST_BIND`在ipv4的socket在绑定地址(`bind`系统调用)后调用，通过 `BPF_CGROUP_RUN_PROG_INET4_POST_BIND` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET4_POST_BIND(sk)             \
    BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET4_POST_BIND)
```

##### (2) 触发过程

TCP、UDP在绑定地址的过程中，设定的`.bind`接口为`inet_bind`函数，最终调用 `__inet_bind`函数。该函数实现具体的`bind`操作，如下：

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
            // 运行`INET4_POST_BIND` CGROUP程序
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

#### 11 `CGROUP_INET6_POST_BIND`

##### (1) 实现过程

`CGROUP_INET6_POST_BIND`在ipv6的socket在绑定地址(`bind`系统调用)后调用，通过 `BPF_CGROUP_RUN_PROG_INET6_POST_BIND` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET6_POST_BIND(sk)             \
    BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET6_POST_BIND)
```

##### (2) 触发过程

TCP、UDP在绑定地址的过程中，设定的`.bind`接口为`inet6_bind`函数，最终调用 `__inet6_bind`函数。该函数实现具体的`bind`操作，如下：

```C
// file: net/ipv6/af_inet6.c
static int __inet6_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len, u32 flags)
{
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)uaddr;
    struct inet_sock *inet = inet_sk(sk);
    struct ipv6_pinfo *np = inet6_sk(sk);
    struct net *net = sock_net(sk);
    ...

    // 地址不是`AF_INET6`时返回错误 
    if (addr->sin6_family != AF_INET6) return -EAFNOSUPPORT;
    // 多播的地址不能进行数据流连接
    addr_type = ipv6_addr_type(&addr->sin6_addr);
    if ((addr_type & IPV6_ADDR_MULTICAST) && sk->sk_type == SOCK_STREAM) return -EINVAL;
    // 绑定时的权限检查
    snum = ntohs(addr->sin6_port);
    if (!(flags & BIND_NO_CAP_NET_BIND_SERVICE) && snum && inet_port_requires_bind_service(net, snum) &&
        !ns_capable(net->user_ns, CAP_NET_BIND_SERVICE))
        return -EACCES;

    if (flags & BIND_WITH_LOCK) lock_sock(sk);
    // 检查socket是否存活、多次绑定
    if (sk->sk_state != TCP_CLOSE || inet->inet_num) { err = -EINVAL; goto out; }

    // 检查绑定的地址是否属于本机地址
    if (addr_type == IPV6_ADDR_MAPPED) {
        // IPV4映射IPV6时的处理
        struct net_device *dev = NULL;
        int chk_addr_ret;
        if (ipv6_only_sock(sk)) { err = -EINVAL; goto out; }
        rcu_read_lock();
        // 绑定网卡时，获取绑定的网卡设备
        if (sk->sk_bound_dev_if) {
            dev = dev_get_by_index_rcu(net, sk->sk_bound_dev_if);
            if (!dev) { err = -ENODEV; goto out_unlock; }
        }
        v4addr = addr->sin6_addr.s6_addr32[3];
        chk_addr_ret = inet_addr_type_dev_table(net, dev, v4addr);
        rcu_read_unlock();

        if (!inet_addr_valid_or_nonlocal(net, inet, v4addr, chk_addr_ret)) {
            err = -EADDRNOTAVAIL;
            goto out;
        }
    } else {
        if (addr_type != IPV6_ADDR_ANY) {
            struct net_device *dev = NULL;
            rcu_read_lock();
            if (__ipv6_addr_needs_scope_id(addr_type)) {
                if (addr_len >= sizeof(struct sockaddr_in6) && addr->sin6_scope_id) {
                    sk->sk_bound_dev_if = addr->sin6_scope_id;
                }
                // 绑定本机地址时，需要指定网卡
                if (!sk->sk_bound_dev_if) { err = -EINVAL; goto out_unlock; }
            }
            // 获取绑定的网卡设备
            if (sk->sk_bound_dev_if) {
                dev = dev_get_by_index_rcu(net, sk->sk_bound_dev_if);
                if (!dev) { err = -ENODEV; goto out_unlock; }
            }
            // 只有未指定和映射的等效ipv4地址有效，其他ipv4地址无效
            v4addr = LOOPBACK4_IPV6;
            if (!(addr_type & IPV6_ADDR_MULTICAST)) {
                if (!ipv6_can_nonlocal_bind(net, inet) && !ipv6_chk_addr(net, &addr->sin6_addr, dev, 0)) {
                    err = -EADDRNOTAVAIL;
                    goto out_unlock;
                }
            }
            rcu_read_unlock();
        }
    }
    // 设置源地址
    inet->inet_rcv_saddr = v4addr;
    inet->inet_saddr = v4addr;
    sk->sk_v6_rcv_saddr = addr->sin6_addr;
    if (!(addr_type & IPV6_ADDR_MULTICAST)) np->saddr = addr->sin6_addr;
    // 检查是否只支持ipv6地址
    saved_ipv6only = sk->sk_ipv6only;
    if (addr_type != IPV6_ADDR_ANY && addr_type != IPV6_ADDR_MAPPED)
        sk->sk_ipv6only = 1;

    // 检查socket是否允许绑定端口
    if (snum || !(inet->bind_address_no_port || (flags & BIND_FORCE_ADDRESS_NO_PORT))) {
        // `.get_port`接口，检查绑定的端口
        err = sk->sk_prot->get_port(sk, snum);
        if (err) {
            // 端口绑定失败时，重置ipv4地址
            sk->sk_ipv6only = saved_ipv6only;
            inet_reset_saddr(sk);
            goto out;
        }
        if (!(flags & BIND_FROM_BPF)) {
            // 运行`INET6_POST_BIND` CGROUP程序
            err = BPF_CGROUP_RUN_PROG_INET6_POST_BIND(sk);
            if (err) {
                sk->sk_ipv6only = saved_ipv6only;
                inet_reset_saddr(sk);
                if (sk->sk_prot->put_port) sk->sk_prot->put_port(sk);
                goto out;
            }
        }
    }
    // 绑定成功时，设置socket的源端口
    if (addr_type != IPV6_ADDR_ANY) sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
    if (snum) sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
    inet->inet_sport = htons(inet->inet_num);
    inet->inet_dport = 0;
    inet->inet_daddr = 0;
out:
    if (flags & BIND_WITH_LOCK) release_sock(sk);
    return err;
out_unlock:
    rcu_read_unlock();
    goto out;
}
```

#### 12 `CGROUP_UDP4_SENDMSG`

##### (1) 实现过程

`CGROUP_UDP4_SENDMSG`在ipv4的UDP socket发送消息(`send`,`sendmsg`等系统调用)时调用，通过 `BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk, uaddr, t_ctx)         \
    BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP4_SENDMSG, t_ctx)
```

##### (2) 触发过程

ipv4下的UDP设置的发送接口(`.sendmsg`)为`udp_sendmsg`, 如下：

```C
// file: net/ipv4/udp.c
struct proto udp_prot = {
    .name           = "UDP",
    .owner          = THIS_MODULE,
    ...
    .sendmsg        = udp_sendmsg,
    ...
};
```

其实现如下：

```C
// file: net/ipv4/udp.c
int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
    struct inet_sock *inet = inet_sk(sk);
    struct udp_sock *up = udp_sk(sk);
    DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
    struct flowi4 fl4_stack;
    struct flowi4 *fl4;
    int ulen = len;
    ...

    // 每次最大发送65535字节
    if (len > 0xFFFF) return -EMSGSIZE;
    // 检查发送标记，不支持`OOB`标记
    if (msg->msg_flags & MSG_OOB) return -EOPNOTSUPP;
    // 获取`frag`的回调函数
    getfrag = is_udplite ? udplite_getfrag : ip_generic_getfrag;

    fl4 = &inet->cork.fl.u.ip4;
    // 等待发送帧的处理
    if (up->pending) { ... }
    // 发送长度加上udp协议头
    ulen += sizeof(struct udphdr);

    if (usin) {
        // 目的地址存在时，检查源地址
        if (msg->msg_namelen < sizeof(*usin)) return -EINVAL;
        if (usin->sin_family != AF_INET) {
            if (usin->sin_family != AF_UNSPEC) return -EAFNOSUPPORT;
        }
        daddr = usin->sin_addr.s_addr;
        dport = usin->sin_port;
        if (dport == 0) return -EINVAL;
    } else {
        // 目的地址不存在时，使用已连接的地址
        if (sk->sk_state != TCP_ESTABLISHED) return -EDESTADDRREQ;
        daddr = inet->inet_daddr;
        dport = inet->inet_dport;
        connected = 1;
    }

    ipcm_init_sk(&ipc, inet);
    ipc.gso_size = READ_ONCE(up->gso_size);
    // 存在辅助数据时，发送辅助数据
    if (msg->msg_controllen) {
        err = udp_cmsg_send(sk, msg, &ipc.gso_size);
        if (err > 0) err = ip_cmsg_send(sk, msg, &ipc, sk->sk_family == AF_INET6);
        if (unlikely(err < 0)) { kfree(ipc.opt); return err; }
        if (ipc.opt) free = 1;
        connected = 0;
    }
    // 存在ip选项时，复制ip选项
    if (!ipc.opt) {
        struct ip_options_rcu *inet_opt;
        rcu_read_lock();
        inet_opt = rcu_dereference(inet->inet_opt);
        if (inet_opt) {
            memcpy(&opt_copy, inet_opt, sizeof(*inet_opt) + inet_opt->opt.optlen);
            ipc.opt = &opt_copy.opt;
        }
        rcu_read_unlock();
    }
    // 已经设置`UDP4_SENDMSG` BPF程序且未连接时
    if (cgroup_bpf_enabled(CGROUP_UDP4_SENDMSG) && !connected) {
        // 运行`UDP4_SENDMSG` CGROUP程序
        err = BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk, (struct sockaddr *)usin, &ipc.addr);
        if (err) goto out_free;
        if (usin) {
            // BPF程序设置无效端口时，拒绝发送
            if (usin->sin_port == 0) { err = -EINVAL; goto out_free; }
            // 重新获取源地址和端口
            daddr = usin->sin_addr.s_addr;
            dport = usin->sin_port;
        }
    }
    // 源地址获取
    saddr = ipc.addr;
    ipc.addr = faddr = daddr;
    if (ipc.opt && ipc.opt->opt.srr) {
        if (!daddr) { err = -EINVAL; goto out_free; }
        faddr = ipc.opt->opt.faddr;
        connected = 0;
    }
    // 获取tos
    tos = get_rttos(&ipc, inet);
    if (sock_flag(sk, SOCK_LOCALROUTE) || (msg->msg_flags & MSG_DONTROUTE) ||
        (ipc.opt && ipc.opt->opt.is_strictroute)) {
        tos |= RTO_ONLINK;
        connected = 0;
    }
    // 获取发送时的源地址
    if (ipv4_is_multicast(daddr)) {
        if (!ipc.oif || netif_index_is_l3_master(sock_net(sk), ipc.oif))
            ipc.oif = inet->mc_index;
        if (!saddr) saddr = inet->mc_addr;
        connected = 0;
    } else if (!ipc.oif) {
        ipc.oif = inet->uc_index;
    } else if (ipv4_is_lbcast(daddr) && inet->uc_index) {
        if (ipc.oif != inet->uc_index &&
            ipc.oif == l3mdev_master_ifindex_by_index(sock_net(sk), inet->uc_index)) {
            ipc.oif = inet->uc_index;
        }
    }
    // 连接状态时，获取路由信息
    if (connected) rt = (struct rtable *)sk_dst_check(sk, 0);
    // 路由信息不存在时，获取路由
    if (!rt) {
        struct net *net = sock_net(sk);
        __u8 flow_flags = inet_sk_flowi_flags(sk);
        fl4 = &fl4_stack;
        flowi4_init_output(fl4, ipc.oif, ipc.sockc.mark, tos, RT_SCOPE_UNIVERSE, sk->sk_protocol,
                                flow_flags, faddr, saddr, dport, inet->inet_sport, sk->sk_uid);
        security_sk_classify_flow(sk, flowi4_to_flowi_common(fl4));
        // 获取发送的路由
        rt = ip_route_output_flow(net, fl4, sk);
        if (IS_ERR(rt)) { ... }
        err = -EACCES;
        // 检查路由标记
        if ((rt->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST))
            goto out;
        if (connected) sk_dst_set(sk, dst_clone(&rt->dst));
    }
    // 确认标记时，进行确认
    if (msg->msg_flags&MSG_CONFIRM) goto do_confirm;
back_from_confirm:
    saddr = fl4->saddr;
    if (!ipc.addr) daddr = ipc.addr = fl4->daddr;
    // 确定邻接路由后，快速发送skb
    if (!corkreq) {
        struct inet_cork cork;
        skb = ip_make_skb(sk, fl4, getfrag, msg, ulen, 
                sizeof(struct udphdr), &ipc, &rt, &cork, msg->msg_flags);
        err = PTR_ERR(skb);
        if (!IS_ERR_OR_NULL(skb)) err = udp_send_skb(skb, fl4, &cork);
        goto out;
    }

    lock_sock(sk);
    // 存在等待的帧，释放socket
    if (unlikely(up->pending)) { ... }
    // 设置ipv4的路由信息
    fl4 = &inet->cork.fl.u.ip4;
    fl4->daddr = daddr;
    fl4->saddr = saddr;
    fl4->fl4_dport = dport;
    fl4->fl4_sport = inet->inet_sport;
    up->pending = AF_INET;

do_append_data:
    // 生成skb
    up->len += ulen;
    err = ip_append_data(sk, fl4, getfrag, msg, ulen, sizeof(struct udphdr), &ipc, &rt,
            corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
    // 发送等待skb
    if (err) udp_flush_pending_frames(sk);
	else if (!corkreq) err = udp_push_pending_frames(sk);
    else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
        up->pending = 0;
    release_sock(sk);

out:
    // 释放路由信息
    ip_rt_put(rt);
out_free:
    if (free) kfree(ipc.opt);
    if (!err) return len;
    // 内存不足时，增加统计信息
    if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
        UDP_INC_STATS(sock_net(sk), UDP_MIB_SNDBUFERRORS, is_udplite);
    }
    return err;

do_confirm:
    // 邻接路由确认
    if (msg->msg_flags & MSG_PROBE) dst_confirm_neigh(&rt->dst, &fl4->daddr);
    if (!(msg->msg_flags&MSG_PROBE) || len) goto back_from_confirm;
    err = 0;
    goto out;
}
```

#### 13 `CGROUP_UDP6_SENDMSG`

##### (1) 实现过程

`CGROUP_UDP6_SENDMSG`在ipv6的UDP socket发送消息(`sendmsg`等系统调用)时调用，通过 `BPF_CGROUP_RUN_PROG_UDP6_SENDMSG_LOCK` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_UDP6_SENDMSG_LOCK(sk, uaddr, t_ctx)         \
    BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP6_SENDMSG, t_ctx)
```

##### (2) 触发过程

ipv6下的UDP设置的发送接口(`.sendmsg`)为`udpv6_sendmsg`, 如下：

```C
// file: net/ipv6/udp.c
struct proto udpv6_prot = {
    .name           = "UDPv6",
	.owner          = THIS_MODULE,
    ...
    .sendmsg        = udpv6_sendmsg,
    ...
};
```

其实现如下：

```C
// file: net/ipv6/udp.c
int udpv6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
    struct ipv6_txoptions opt_space;
    struct udp_sock *up = udp_sk(sk);
    struct inet_sock *inet = inet_sk(sk);
    struct ipv6_pinfo *np = inet6_sk(sk);
    DECLARE_SOCKADDR(struct sockaddr_in6 *, sin6, msg->msg_name);
    struct in6_addr *daddr, *final_p, final;
    ...
    int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
    // ipv6信息设置
    ipcm6_init(&ipc6);
    ipc6.gso_size = READ_ONCE(up->gso_size);
    ipc6.sockc.tsflags = sk->sk_tsflags;
    ipc6.sockc.mark = sk->sk_mark;

    if (sin6) {
        // 发送目的地址存在时的检查
        if (addr_len < offsetof(struct sockaddr, sa_data)) return -EINVAL;
        switch (sin6->sin6_family) {
        case AF_INET6:
            if (addr_len < SIN6_LEN_RFC2133) return -EINVAL;
            daddr = &sin6->sin6_addr;
            if (ipv6_addr_any(daddr) && ipv6_addr_v4mapped(&np->saddr))
                ipv6_addr_set_v4mapped(htonl(INADDR_LOOPBACK), daddr);
            break;
        case AF_INET: goto do_udp_sendmsg;
        case AF_UNSPEC:
            msg->msg_name = sin6 = NULL;
            msg->msg_namelen = addr_len = 0;
            daddr = NULL;
            break;
        default: return -EINVAL;
        }
    } else if (!up->pending) {
        if (sk->sk_state != TCP_ESTABLISHED) return -EDESTADDRREQ;
        daddr = &sk->sk_v6_daddr;
    } else
        daddr = NULL;

    if (daddr) {
        // 目的地址存在时，且是IPV4映射IPV6地址时，通过ipv4协议发送
        if (ipv6_addr_v4mapped(daddr)) {
            struct sockaddr_in sin;
            sin.sin_family = AF_INET;
            sin.sin_port = sin6 ? sin6->sin6_port : inet->inet_dport;
            sin.sin_addr.s_addr = daddr->s6_addr32[3];
            msg->msg_name = &sin;
            msg->msg_namelen = sizeof(sin);
do_udp_sendmsg:
            err = ipv6_only_sock(sk) ? -ENETUNREACH : udp_sendmsg(sk, msg, len);
            msg->msg_name = sin6;
            msg->msg_namelen = addr_len;
            return err;
        }
    }
    // 发送长度检查，ipv6支持的udp数据包长度为`INT_MAX`
    if (len > INT_MAX - sizeof(struct udphdr)) return -EMSGSIZE;
    // `getfrag`接口
    getfrag  =  is_udplite ?  udplite_getfrag : ip_generic_getfrag;
    if (up->pending) {
        // 待发送的帧是ipv4协议时，通过ipv4协议发送
        if (up->pending == AF_INET) return udp_sendmsg(sk, msg, len);
        // 待发送的帧检查
        lock_sock(sk);
        if (likely(up->pending)) {
            if (unlikely(up->pending != AF_INET6)) 
            { release_sock(sk); return -EAFNOSUPPORT; }
            dst = NULL;
            goto do_append_data;
        }
        release_sock(sk);
    }
    // 发送长度计算
    ulen += sizeof(struct udphdr);
    // 清空路由信息
    memset(fl6, 0, sizeof(*fl6));
    if (sin6) {
        // 指定发送地址时，必须指定发送的端口
        if (sin6->sin6_port == 0) return -EINVAL;
        // 路由信息设置
        fl6->fl6_dport = sin6->sin6_port;
        daddr = &sin6->sin6_addr;
        if (np->sndflow) {
            fl6->flowlabel = sin6->sin6_flowinfo&IPV6_FLOWINFO_MASK;
            if (fl6->flowlabel & IPV6_FLOWLABEL_MASK) {
                flowlabel = fl6_sock_lookup(sk, fl6->flowlabel);
                if (IS_ERR(flowlabel)) return -EINVAL;
            }
        }
        if (sk->sk_state == TCP_ESTABLISHED && ipv6_addr_equal(daddr, &sk->sk_v6_daddr))
            daddr = &sk->sk_v6_daddr;
        if (addr_len >= sizeof(struct sockaddr_in6) && sin6->sin6_scope_id &&
            __ipv6_addr_needs_scope_id(__ipv6_addr_type(daddr)))
            fl6->flowi6_oif = sin6->sin6_scope_id;
    } else {
        // 未指定发送地址时，使用连接的目的地址
        if (sk->sk_state != TCP_ESTABLISHED) return -EDESTADDRREQ;
        fl6->fl6_dport = inet->inet_dport;
        daddr = &sk->sk_v6_daddr;
        fl6->flowlabel = np->flow_label;
        connected = true;
    }
    // 获取路由信息的出口网卡
    if (!fl6->flowi6_oif) fl6->flowi6_oif = READ_ONCE(sk->sk_bound_dev_if);
    if (!fl6->flowi6_oif) fl6->flowi6_oif = np->sticky_pktinfo.ipi6_ifindex;

    fl6->flowi6_uid = sk->sk_uid;
    // 存在辅助数据时，发送辅助数据
    if (msg->msg_controllen) {
        opt = &opt_space;
        memset(opt, 0, sizeof(struct ipv6_txoptions));
        opt->tot_len = sizeof(*opt);
        ipc6.opt = opt;
        err = udp_cmsg_send(sk, msg, &ipc6.gso_size);
        if (err > 0) err = ip6_datagram_send_ctl(sock_net(sk), sk, msg, fl6, &ipc6);
        if (err < 0) { fl6_sock_release(flowlabel); return err; }
        if ((fl6->flowlabel&IPV6_FLOWLABEL_MASK) && !flowlabel) {
            flowlabel = fl6_sock_lookup(sk, fl6->flowlabel);
            if (IS_ERR(flowlabel)) return -EINVAL;
        }
        if (!(opt->opt_nflen|opt->opt_flen)) opt = NULL;
        connected = false;
    }
    // 获取ipv6选项
    if (!opt) { opt = txopt_get(np); opt_to_free = opt; }
    if (flowlabel) opt = fl6_merge_options(&opt_space, flowlabel, opt);
    opt = ipv6_fixup_options(&opt_space, opt);
    ipc6.opt = opt;
    // 路由信息源/目睹地址、源端口设置
    fl6->flowi6_proto = sk->sk_protocol;
    fl6->flowi6_mark = ipc6.sockc.mark;
    fl6->daddr = *daddr;
    if (ipv6_addr_any(&fl6->saddr) && !ipv6_addr_any(&np->saddr))
        fl6->saddr = np->saddr;
    fl6->fl6_sport = inet->inet_sport;
    // 设置`UDP6_SENDMSG` BPF程序且未连接时
    if (cgroup_bpf_enabled(CGROUP_UDP6_SENDMSG) && !connected) {
        // 运行`UDP6_SENDMSG` CGROUP程序
        err = BPF_CGROUP_RUN_PROG_UDP6_SENDMSG_LOCK(sk, (struct sockaddr *)sin6, &fl6->saddr);
        if (err) goto out_no_dst;
        if (sin6) {
            // 只执行BPF程序修改IPV6，不支持修改为IPV4映射IPV6地址
            if (ipv6_addr_v4mapped(&sin6->sin6_addr)) { err = -ENOTSUPP; goto out_no_dst; }
            // BPF程序设置无效端口时，拒绝
            if (sin6->sin6_port == 0) { err = -EINVAL; goto out_no_dst; }
            // 修改路由信息
            fl6->fl6_dport = sin6->sin6_port;
            fl6->daddr = sin6->sin6_addr;
        }
    }
    // 任意地址设置
    if (ipv6_addr_any(&fl6->daddr)) fl6->daddr.s6_addr[15] = 0x1; /* :: means loopback (BSD'ism) */
    final_p = fl6_update_dst(fl6, opt, &final);
    if (final_p) connected = false;
    // 路由信息的出口设备设置
    if (!fl6->flowi6_oif && ipv6_addr_is_multicast(&fl6->daddr)) {
        fl6->flowi6_oif = np->mcast_oif; connected = false;
    } else if (!fl6->flowi6_oif)
        fl6->flowi6_oif = np->ucast_oif;
        
    security_sk_classify_flow(sk, flowi6_to_flowi_common(fl6));
    if (ipc6.tclass < 0) ipc6.tclass = np->tclass;
    // 路由标记设置
    fl6->flowlabel = ip6_make_flowinfo(ipc6.tclass, fl6->flowlabel);
    // 查找目的路由
    dst = ip6_sk_dst_lookup_flow(sk, fl6, final_p, connected);
    if (IS_ERR(dst)) { err = PTR_ERR(dst); dst = NULL; goto out; }
    // 获取路由跳数
    if (ipc6.hlimit < 0) ipc6.hlimit = ip6_sk_dst_hoplimit(np, fl6, dst);

    if (msg->msg_flags&MSG_CONFIRM) goto do_confirm;
back_from_confirm:
    if (!corkreq) {
        // 确定邻接路由后，快速发送skb
        struct sk_buff *skb;
        skb = ip6_make_skb(sk, getfrag, msg, ulen, sizeof(struct udphdr), &ipc6,
                (struct rt6_info *)dst, msg->msg_flags, &cork);
        err = PTR_ERR(skb);
        if (!IS_ERR_OR_NULL(skb)) err = udp_v6_send_skb(skb, fl6, &cork.base);
        goto out_no_dst;
    }

    lock_sock(sk);
    // 存在等待的帧，释放socket
    if (unlikely(up->pending)) { ... }
    // 等待设置
    up->pending = AF_INET6;
do_append_data:
    if (ipc6.dontfrag < 0) ipc6.dontfrag = np->dontfrag;
    // 生成skb
    up->len += ulen;
    err = ip6_append_data(sk, getfrag, msg, ulen, sizeof(struct udphdr), &ipc6, fl6, 
                (struct rt6_info *)dst, corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
    // 发送等待的skb
    if (err) udp_v6_flush_pending_frames(sk);
    else if (!corkreq) err = udp_v6_push_pending_frames(sk);
    else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
        up->pending = 0;
    // 转换错误码
    if (err > 0) err = np->recverr ? net_xmit_errno(err) : 0;
    release_sock(sk);

out:
    dst_release(dst);
out_no_dst:
    fl6_sock_release(flowlabel);
    txopt_put(opt_to_free);
    if (!err) return len;
    // 内存不足时，增加统计信息
    if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
        UDP6_INC_STATS(sock_net(sk), UDP_MIB_SNDBUFERRORS, is_udplite);
    }
    return err;

do_confirm:
    // 邻接路由确认
    if (msg->msg_flags & MSG_PROBE) dst_confirm_neigh(dst, &fl6->daddr);
    if (!(msg->msg_flags&MSG_PROBE) || len) goto back_from_confirm;
    err = 0;
    goto out;
}
```

#### 14 `CGROUP_SYSCTL`

##### (1) 实现过程

`CGROUP_SYSCTL`在访问、修改`systel`参数时调用，通过 `BPF_CGROUP_RUN_PROG_SYSCTL` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_SYSCTL(head, table, write, buf, count, pos)     \
({                                                                          \
    int __ret = 0;                                                          \
    if (cgroup_bpf_enabled(CGROUP_SYSCTL))                                  \
        __ret = __cgroup_bpf_run_filter_sysctl(head, table, write,          \
                        buf, count, pos, CGROUP_SYSCTL);                    \
    __ret;                                                                  \
})
```

`__cgroup_bpf_run_filter_sysctl`函数在访问`sysctl`时运行，无论是读取还是写入，并且可以允许或拒绝此类访问，其实现如下：

```C
// file: kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_sysctl(struct ctl_table_header *head, struct ctl_table *table, int write,
                char **buf, size_t *pcount, loff_t *ppos, enum cgroup_bpf_attach_type atype)
{
    // 运行上下文设置
    struct bpf_sysctl_kern ctx = {
        .head = head, .table = table, .write = write, .ppos = ppos,
        .cur_val = NULL, .cur_len = PAGE_SIZE, 
        .new_val = NULL, .new_len = 0, .new_updated = 0,
    };
    struct cgroup *cgrp;
    loff_t pos = 0;
    int ret;
    // 设置当前的值和长度
    ctx.cur_val = kmalloc_track_caller(ctx.cur_len, GFP_KERNEL);
    if (!ctx.cur_val || table->proc_handler(table, 0, ctx.cur_val, &ctx.cur_len, &pos)) {
        ctx.cur_len = 0;
    }
    // 写入的新值和长度设置
    if (write && *buf && *pcount) {
        ctx.new_val = kmalloc_track_caller(PAGE_SIZE, GFP_KERNEL);
        ctx.new_len = min_t(size_t, PAGE_SIZE, *pcount);
        if (ctx.new_val) { memcpy(ctx.new_val, *buf, ctx.new_len); } 
        else { ctx.new_len = 0; }
    }

    rcu_read_lock();
    // 获取cgroup后，运行BPF程序
    cgrp = task_dfl_cgroup(current);
    ret = bpf_prog_run_array_cg(&cgrp->bpf, atype, &ctx, bpf_prog_run, 0,  NULL);
    rcu_read_unlock();
    // 释放当前值
    kfree(ctx.cur_val);
    if (ret == 1 && ctx.new_updated) {
        // 新值修改时，设置返回结果
        kfree(*buf);
        *buf = ctx.new_val;
        *pcount = ctx.new_len;
    } else {
        // 新值未修改时，释放
        kfree(ctx.new_val);
    }
    return ret;
}
```

##### (2) 触发过程

`proc_sys`文件设置的操作接口为`proc_sys_file_operations`, 定义如下：

```C
// file: fs/proc/proc_sysctl.c
static const struct file_operations proc_sys_file_operations = {
    .open           = proc_sys_open,
    .poll           = proc_sys_poll,
    .read_iter      = proc_sys_read,
    .write_iter     = proc_sys_write,
    .splice_read    = generic_file_splice_read,
    .splice_write   = iter_file_splice_write,
    .llseek         = default_llseek,
};
```

`.read_iter` 和 `.write_iter` 接口分别设置为 `proc_sys_read` 和 `proc_sys_write`，在读取/写入文件时调用。实现如下：

```C
// file: fs/proc/proc_sysctl.c
static ssize_t proc_sys_read(struct kiocb *iocb, struct iov_iter *iter)
{
    return proc_sys_call_handler(iocb, iter, 0);
}
static ssize_t proc_sys_write(struct kiocb *iocb, struct iov_iter *iter)
{
    return proc_sys_call_handler(iocb, iter, 1);
}
```

两者都是调用`proc_sys_call_handler`函数，其实现如下：

```C
// file: fs/proc/proc_sysctl.c
static ssize_t proc_sys_call_handler(struct kiocb *iocb, struct iov_iter *iter, int write)
{
    struct inode *inode = file_inode(iocb->ki_filp);
    struct ctl_table_header *head = grab_header(inode);
    struct ctl_table *table = PROC_I(inode)->sysctl_entry;
    size_t count = iov_iter_count(iter);
    char *kbuf;
    ssize_t error;
    // 获取文件头信息
    if (IS_ERR(head)) return PTR_ERR(head);
    // 权限检查
    error = -EPERM;
    if (sysctl_perm(head, table, write ? MAY_WRITE : MAY_READ)) goto out;
    // sysctl表处理接口必须设置
    error = -EINVAL;
    if (!table->proc_handler) goto out;
    // 数量太大时直接退出
    error = -ENOMEM;
    if (count >= KMALLOC_MAX_SIZE) goto out;
	
    // 分配缓冲区
    kbuf = kvzalloc(count + 1, GFP_KERNEL);
    if (!kbuf) goto out;
    if (write) {
        // 写入操作时，复制缓冲区
        error = -EFAULT;
        if (!copy_from_iter_full(kbuf, count, iter)) goto out_free_buf;
        kbuf[count] = '\0';
    }
    // 运行`PROG_SYSCTL`BPF程序
    error = BPF_CGROUP_RUN_PROG_SYSCTL(head, table, write, &kbuf, &count, &iocb->ki_pos);
    if (error) goto out_free_buf;
    
    // 调用sysctl表处理接口
    error = table->proc_handler(table, write, kbuf, &count, &iocb->ki_pos);
    if (error) goto out_free_buf;

    if (!write) {
        // 读取时，将缓冲区转换为`iter`
        error = -EFAULT;
        if (copy_to_iter(kbuf, count, iter) < count) goto out_free_buf;
    }
    error = count;
    
out_free_buf:
    kvfree(kbuf);
out:
    sysctl_head_finish(head);
    return error;
}
```

#### 15 `CGROUP_UDP4_RECVMSG`

##### (1) 实现过程

`CGROUP_UDP4_RECVMSG`在ipv4的UDP socket接收消息(`recv`,`recvmsg`等系统调用)时调用，通过 `BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk, uaddr)                \
    BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP4_RECVMSG, NULL)
```

##### (2) 触发过程

ipv4下的UDP设置的接收接口(`.recvmsg`)为`udp_recvmsg`, 如下：

```C
// file: net/ipv4/udp.c
struct proto udp_prot = {
    .name           = "UDP",
    .owner          = THIS_MODULE,
    ...
    .recvmsg        = udp_recvmsg,
    ...
};
```

其实现如下：

```C
// file: net/ipv4/udp.c
int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
{
    struct inet_sock *inet = inet_sk(sk);
    DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name);
    struct sk_buff *skb;
    unsigned int ulen, copied;
    int off, err, peeking = flags & MSG_PEEK;
    int is_udplite = IS_UDPLITE(sk);
    bool checksum_valid = false;

    // 指定错误标记时，获取错误信息
    if (flags & MSG_ERRQUEUE) return ip_recv_error(sk, msg, len, addr_len);
try_again:
    // 获取第一个skb
    off = sk_peek_offset(sk, flags);
    skb = __skb_recv_udp(sk, flags, &off, &err);
    if (!skb) return err;
    // 计算复制的长度
    ulen = udp_skb_len(skb);
    copied = len;
    if (copied > ulen - off) copied = ulen - off;
    else if (copied < ulen) msg->msg_flags |= MSG_TRUNC;
    // 检查检验和是否有效
    if (copied < ulen || peeking || (is_udplite && UDP_SKB_CB(skb)->partial_cov)) {
        checksum_valid = udp_skb_csum_unnecessary(skb) || 
                    !__udp_lib_checksum_complete(skb);
        if (!checksum_valid) goto csum_copy_err;
    }
    if (checksum_valid || udp_skb_csum_unnecessary(skb)) {
        // 校验和有效或者不需要校验和时，复制数据
        if (udp_skb_is_linear(skb))
            err = copy_linear_skb(skb, copied, off, &msg->msg_iter);
        else
            err = skb_copy_datagram_msg(skb, off, msg, copied);
    } else {
        // 计算校验和后复制数据
        err = skb_copy_and_csum_datagram_msg(skb, off, msg);
        if (err == -EINVAL) goto csum_copy_err;
    }
    // 出现错误时，更新统计信息
    if (unlikely(err)) {
        if (!peeking) {
            atomic_inc(&sk->sk_drops);
            UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
        }
        kfree_skb(skb);
        return err;
    }
    if (!peeking) UDP_INC_STATS(sock_net(sk), UDP_MIB_INDATAGRAMS, is_udplite);
    // 接收辅助数据(接收时间等信息)
	sock_recv_cmsgs(msg, sk, skb);

    if (sin) {
        // 复制地址信息
        sin->sin_family = AF_INET;
        sin->sin_port = udp_hdr(skb)->source;
        sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
        memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
        *addr_len = sizeof(*sin);
        // 运行`UDP4_RECVMSG`BPF程序
        BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk, (struct sockaddr *)sin);
    }
    // 获取GRO信息
    if (udp_sk(sk)->gro_enabled) udp_cmsg_recv(msg, sk, skb);
    // 获取控制信息
    if (inet->cmsg_flags) ip_cmsg_recv_offset(msg, sk, skb, sizeof(struct udphdr), off);

    // 计算复制的数据长度，有截断时返回实际的长度
    err = copied;
    if (flags & MSG_TRUNC) err = ulen;
    // 释放skb
    skb_consume_udp(sk, skb, peeking ? -err : err);
    return err;

csum_copy_err:
    // 校验和失败时，从读取队列中移除skb时，更新统计计数
    if (!__sk_queue_drop_skb(sk, &udp_sk(sk)->reader_queue, skb, flags, udp_skb_destructor)) {
        UDP_INC_STATS(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
        UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
    }
    kfree_skb(skb);

    // 重新开始一个新的数据包
    cond_resched();
    msg->msg_flags &= ~MSG_TRUNC;
    goto try_again;
}
```

#### 16 `CGROUP_UDP6_RECVMSG`

##### (1) 实现过程

`CGROUP_UDP6_RECVMSG`在ipv6的UDP socket接收消息(`recvmsg`等系统调用)时调用，通过 `BPF_CGROUP_RUN_PROG_UDP6_RECVMSG_LOCK` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_UDP6_RECVMSG_LOCK(sk, uaddr)                \
    BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP6_RECVMSG, NULL)
```

##### (2) 触发过程

ipv6下的UDP设置的接收接口(`.recvmsg`)为`udpv6_recvmsg`, 如下：

```C
// file: net/ipv6/udp.c
struct proto udpv6_prot = {
    .name           = "UDPv6",
    .owner          = THIS_MODULE,
    ...
    .recvmsg        = udpv6_recvmsg,
    ...
};
```

其实现如下：

```C
// file: net/ipv6/udp.c
int udpv6_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
{
    struct ipv6_pinfo *np = inet6_sk(sk);
    struct inet_sock *inet = inet_sk(sk);
    struct sk_buff *skb;
    ...

    // 指定错误标记时，获取错误信息
    if (flags & MSG_ERRQUEUE) return ipv6_recv_error(sk, msg, len, addr_len);
    // 接收路径MTU(`PATHMTU`)
    if (np->rxpmtu && np->rxopt.bits.rxpmtu) return ipv6_recv_rxpmtu(sk, msg, len, addr_len);

try_again:
    // 获取第一个skb
    off = sk_peek_offset(sk, flags);
    skb = __skb_recv_udp(sk, flags, &off, &err);
    if (!skb) return err;
    // 计算复制的长度
    ulen = udp6_skb_len(skb);
    copied = len;
    if (copied > ulen - off) copied = ulen - off;
    else if (copied < ulen) msg->msg_flags |= MSG_TRUNC;
    // 检查是否是ipv4的数据包
    is_udp4 = (skb->protocol == htons(ETH_P_IP));
    mib = __UDPX_MIB(sk, is_udp4);
    // 检查检验和是否有效
    if (copied < ulen || peeking || (is_udplite && UDP_SKB_CB(skb)->partial_cov)) {
        checksum_valid = udp_skb_csum_unnecessary(skb) ||
            !__udp_lib_checksum_complete(skb);
        if (!checksum_valid) goto csum_copy_err;
    }
    if (checksum_valid || udp_skb_csum_unnecessary(skb)) {
        // 校验和有效或者不需要校验和时，复制数据
        if (udp_skb_is_linear(skb))
            err = copy_linear_skb(skb, copied, off, &msg->msg_iter);
        else
            err = skb_copy_datagram_msg(skb, off, msg, copied);
    } else {
        // 计算校验和后复制数据
        err = skb_copy_and_csum_datagram_msg(skb, off, msg);
        if (err == -EINVAL) goto csum_copy_err;
    }
    // 出现错误时，更新统计信息
    if (unlikely(err)) {
        if (!peeking) {
            atomic_inc(&sk->sk_drops);
            SNMP_INC_STATS(mib, UDP_MIB_INERRORS);
        }
        kfree_skb(skb);
        return err;
    }
    if (!peeking) SNMP_INC_STATS(mib, UDP_MIB_INDATAGRAMS);
    // 接收辅助数据(接收时间等信息)
    sock_recv_cmsgs(msg, sk, skb);

    if (msg->msg_name) {
        // 复制地址信息
        DECLARE_SOCKADDR(struct sockaddr_in6 *, sin6, msg->msg_name);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = udp_hdr(skb)->source;
        sin6->sin6_flowinfo = 0;
        if (is_udp4) {
            ipv6_addr_set_v4mapped(ip_hdr(skb)->saddr, &sin6->sin6_addr);
            sin6->sin6_scope_id = 0;
        } else {
            sin6->sin6_addr = ipv6_hdr(skb)->saddr;
            sin6->sin6_scope_id = ipv6_iface_scope_id(&sin6->sin6_addr, inet6_iif(skb));
        }
        *addr_len = sizeof(*sin6);
        // 运行`UDP6_RECVMSG`BPF程序
        BPF_CGROUP_RUN_PROG_UDP6_RECVMSG_LOCK(sk, (struct sockaddr *)sin6);
    }
    // 获取GRO信息
    if (udp_sk(sk)->gro_enabled) udp_cmsg_recv(msg, sk, skb);
    // 获取解析选项信息
    if (np->rxopt.all) ip6_datagram_recv_common_ctl(sk, msg, skb);
    // 获取控制信息
    if (is_udp4) {
        if (inet->cmsg_flags) ip_cmsg_recv_offset(msg, sk, skb, sizeof(struct udphdr), off);
    } else {
        if (np->rxopt.all) ip6_datagram_recv_specific_ctl(sk, msg, skb);
    }
    // 计算复制的数据长度，有截断时返回实际的长度
    err = copied;
    if (flags & MSG_TRUNC) err = ulen;
    // 释放skb
    skb_consume_udp(sk, skb, peeking ? -err : err);
    return err;

csum_copy_err:
    // 校验和失败时，从读取队列中移除skb时，更新统计计数
    if (!__sk_queue_drop_skb(sk, &udp_sk(sk)->reader_queue, skb, flags, udp_skb_destructor)) {
        SNMP_INC_STATS(mib, UDP_MIB_CSUMERRORS);
        SNMP_INC_STATS(mib, UDP_MIB_INERRORS);
    }
    kfree_skb(skb);

    // 重新开始一个新的数据包
    cond_resched();
    msg->msg_flags &= ~MSG_TRUNC;
    goto try_again;
}
```

#### 17 `CGROUP_GETSOCKOPT`

##### (1) 实现过程

`CGROUP_GETSOCKOPT`在获取socket选项信息(`getsockopt`系统调用)时调用，通过 `BPF_CGROUP_RUN_PROG_GETSOCKOPT` 宏(用户空间) 和 `BPF_CGROUP_RUN_PROG_GETSOCKOPT_KERN` 宏(内核空间)实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_GETSOCKOPT(sock, level, optname, optval, optlen,    \
                            max_optlen, retval)                                 \
({                                                                              \
    int __ret = retval;                                                         \
    if (cgroup_bpf_enabled(CGROUP_GETSOCKOPT) &&                                \
        cgroup_bpf_sock_enabled(sock, CGROUP_GETSOCKOPT))                       \
        if (!(sock)->sk_prot->bpf_bypass_getsockopt ||                          \
            !INDIRECT_CALL_INET_1((sock)->sk_prot->bpf_bypass_getsockopt,       \
                    tcp_bpf_bypass_getsockopt, level, optname))                 \
            __ret = __cgroup_bpf_run_filter_getsockopt(                         \
                sock, level, optname, optval, optlen,                           \
                max_optlen, retval);                                            \
    __ret;                                                                      \
})

// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_GETSOCKOPT_KERN(sock, level, optname, optval,       \
                            optlen, retval)                                     \
({                                                                              \
    int __ret = retval;                                                         \
    if (cgroup_bpf_enabled(CGROUP_GETSOCKOPT))                                  \
        __ret = __cgroup_bpf_run_filter_getsockopt_kern(                        \
            sock, level, optname, optval, optlen, retval);                      \
    __ret;                                                                      \
})
```

`__cgroup_bpf_run_filter_getsockopt` 函数实现用户空间的选项获取，如下：

```C
// file: kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_getsockopt(struct sock *sk, int level, int optname, 
                char __user *optval, int __user *optlen, int max_optlen, int retval)
{
    struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    struct bpf_sockopt_buf buf = {};
    // 上下文设置
    struct bpf_sockopt_kern ctx = {
        .sk = sk, .level = level,
        .optname = optname, .current_task = current,
    };
    int ret;
    // 选项内存空间和长度设置
    ctx.optlen = max_optlen;
    max_optlen = sockopt_alloc_buf(&ctx, max_optlen, &buf);
    if (max_optlen < 0) return max_optlen;

	if (!retval) {
        // 复制用户空间设置的选项值和选项长度
        if (get_user(ctx.optlen, optlen)) { ret = -EFAULT; goto out; }
        if (ctx.optlen < 0) { ret = -EFAULT; goto out; }
        if (copy_from_user(ctx.optval, optval, min(ctx.optlen, max_optlen)) != 0) {
            ret = -EFAULT; goto out; }
	}

    lock_sock(sk);
    // 运行`GETSOCKOPT`BPF程序
    ret = bpf_prog_run_array_cg(&cgrp->bpf, CGROUP_GETSOCKOPT, &ctx, bpf_prog_run, retval, NULL);
    release_sock(sk);
    // 运行失败时退出
    if (ret < 0) goto out;
    // 检查选项长度
    if (optval && (ctx.optlen > max_optlen || ctx.optlen < 0)) { ret = -EFAULT; goto out; }
    if (ctx.optlen != 0) {
        // 复制选项值和选项长度到用户空间
        if (optval && copy_to_user(optval, ctx.optval, ctx.optlen)) { ret = -EFAULT; goto out; }
        if (put_user(ctx.optlen, optlen)) { ret = -EFAULT; goto out; }
    }
out:
    // 释放内核使用的缓冲区
	sockopt_free_buf(&ctx, &buf);
	return ret;
}
```

`__cgroup_bpf_run_filter_getsockopt_kern` 函数实现内核空间的选项获取，如下：

```C
// file: kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_getsockopt_kern(struct sock *sk, int level,
                        int optname, void *optval, int *optlen, int retval)
{
    struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    // 设置运行的上下文
    struct bpf_sockopt_kern ctx = {
        .sk = sk, .level = level,
        .optname = optname, .optlen = *optlen, .optval = optval,
        .optval_end = optval + *optlen, .current_task = current,
    };
    int ret;
    // 运行`GETSOCKOPT`BPF程序
    ret = bpf_prog_run_array_cg(&cgrp->bpf, CGROUP_GETSOCKOPT, &ctx, bpf_prog_run, retval, NULL);
    if (ret < 0) return ret;
    // 检查运行后的长度
    if (ctx.optlen > *optlen) return -EFAULT;
    // 修改选项长度
    if (ctx.optlen != 0) *optlen = ctx.optlen;
    return ret;
}
```

##### (2) 通用选项的触发过程

`getsockopt`系统调用获取socket选项，如下：

```C
// file: net/socket.c
SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname,
        char __user *, optval, int __user *, optlen)
{
    return __sys_getsockopt(fd, level, optname, optval, optlen);
}
```

`__sys_getsockopt` 函数进行具体的获取操作，实现如下：

```C
// file: net/socket.c
int __sys_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
    int err, fput_needed;
    struct socket *sock;
    int max_optlen;
    // 根据fd获取socket
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (!sock) return err;
    // LSM安全检查
    err = security_socket_getsockopt(sock, level, optname);
    if (err) goto out_put;
    // 获取用户空间设置的选项长度
    if (!in_compat_syscall())
        max_optlen = BPF_CGROUP_GETSOCKOPT_MAX_OPTLEN(optlen);

    // `SOL_SOCKET`层级选项获取
    if (level == SOL_SOCKET)
        err = sock_getsockopt(sock, level, optname, optval, optlen);
    else if (unlikely(!sock->ops->getsockopt))
        err = -EOPNOTSUPP;
    else
        // socket的`.getsockopt`接口获取
        err = sock->ops->getsockopt(sock, level, optname, optval, optlen);

    if (!in_compat_syscall())
        // 运行`GETSOCKOPT`BPF程序
        err = BPF_CGROUP_RUN_PROG_GETSOCKOPT(sock->sk, level, optname,
                        optval, optlen, max_optlen, err);
out_put:
    // 释放socket
    fput_light(sock->file, fput_needed);
    return err;
}
```

##### (3) TCP选项的触发过程

ipv4/ipv6的tcp协议设置`.getsockopt`接口为`tcp_getsockopt`, 如下：

```C
// file: net/ipv4/tcp_ipv4.c
struct proto tcp_prot = {
    .name           = "TCP",
    .owner          = THIS_MODULE,
    ...
    .getsockopt     = tcp_getsockopt,
    .bpf_bypass_getsockopt  = tcp_bpf_bypass_getsockopt,
    ...
};
// file: net/ipv4/tcp_ipv4.c
struct proto tcpv6_prot = {
    .name           = "TCPv6",
    .owner          = THIS_MODULE,
    ...
    .getsockopt     = tcp_getsockopt,
    .bpf_bypass_getsockopt  = tcp_bpf_bypass_getsockopt,
    ...
};
```

其实现如下：

```C
// file: net/ipv4/tcp.c
int tcp_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    if (level != SOL_TCP)
        return READ_ONCE(icsk->icsk_af_ops)->getsockopt(sk, level, optname, optval, optlen);
    // TCP选项获取
    return do_tcp_getsockopt(sk, level, optname, USER_SOCKPTR(optval), USER_SOCKPTR(optlen));
}
```

`do_tcp_getsockopt`函数进行具体选项的获取，如下：

```C
// file: net/ipv4/tcp.c
int do_tcp_getsockopt(struct sock *sk, int level, int optname, sockptr_t optval, sockptr_t optlen)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    struct net *net = sock_net(sk);
    int val, len;

    // 复制选项长度
    if (copy_from_sockptr(&len, optlen, sizeof(int))) return -EFAULT;
    // 检查选项的最小长度
    len = min_t(unsigned int, len, sizeof(int));
    if (len < 0) return -EINVAL;
    // 根据选项进行不同的处理
    switch (optname) {
    case TCP_MAXSEG: ... break;
    ....
    case TCP_ZEROCOPY_RECEIVE: {
        struct scm_timestamping_internal tss;
        struct tcp_zerocopy_receive zc = {};
        int err;
        // 复制设置的`zerocopy_receive`值
        if (copy_from_sockptr(&len, optlen, sizeof(int))) return -EFAULT;
        if (len < 0 || len < offsetofend(struct tcp_zerocopy_receive, length)) return -EINVAL;
        if (unlikely(len > sizeof(zc))) {
            err = check_zeroed_sockptr(optval, sizeof(zc), len - sizeof(zc));
            if (err < 1) return err == 0 ? -EINVAL : err;
            len = sizeof(zc);
            if (copy_to_sockptr(optlen, &len, sizeof(int))) return -EFAULT;
        }
        if (copy_from_sockptr(&zc, optval, len)) return -EFAULT;
        if (zc.reserved) return -EINVAL;
        if (zc.msg_flags &  ~(TCP_VALID_ZC_MSG_FLAGS)) return -EINVAL;

        sockopt_lock_sock(sk);
        // zerocopy接收数据
        err = tcp_zerocopy_receive(sk, &zc, &tss);
        // 运行`GETSOCKOPT_KERN`BPF程序
        err = BPF_CGROUP_RUN_PROG_GETSOCKOPT_KERN(sk, level, optname, &zc, &len, err);
        sockopt_release_sock(sk);
        // 检查`zc`更新的字段，进行不同的处理
        if (len >= offsetofend(struct tcp_zerocopy_receive, msg_flags)) 
            goto zerocopy_rcv_cmsg;
        switch (len) {
        case offsetofend(struct tcp_zerocopy_receive, msg_flags):
             goto zerocopy_rcv_cmsg;
        case offsetofend(struct tcp_zerocopy_receive, msg_controllen):
        case offsetofend(struct tcp_zerocopy_receive, msg_control):
        case offsetofend(struct tcp_zerocopy_receive, flags):
        case offsetofend(struct tcp_zerocopy_receive, copybuf_len):
        case offsetofend(struct tcp_zerocopy_receive, copybuf_address):
        case offsetofend(struct tcp_zerocopy_receive, err):
            goto zerocopy_rcv_sk_err;
        case offsetofend(struct tcp_zerocopy_receive, inq):
            goto zerocopy_rcv_inq;
        case offsetofend(struct tcp_zerocopy_receive, length):
        default:
            goto zerocopy_rcv_out;
        }
zerocopy_rcv_cmsg:
        // 获取的接收时间戳
        if (zc.msg_flags & TCP_CMSG_TS) tcp_zc_finalize_rx_tstamp(sk, &zc, &tss);
        else zc.msg_flags = 0;
zerocopy_rcv_sk_err:
        if (!err) zc.err = sock_error(sk);
zerocopy_rcv_inq:
        // 获取接收队列中的字节数
        zc.inq = tcp_inq_hint(sk);
zerocopy_rcv_out:
        // 复制选项值到用户空间
        if (!err && copy_to_sockptr(optval, &zc, len)) err = -EFAULT;
        return err;
    }
    default:
        return -ENOPROTOOPT;
    }
    // 复制选项值和长度到用户空间
    if (copy_to_sockptr(optlen, &len, sizeof(int))) return -EFAULT;
    if (copy_to_sockptr(optval, &val, len)) return -EFAULT;
    return 0;
}
```

`.bpf_bypass_getsockopt`接口优化`getsockopt`实现，避免`TCP_ZEROCOPY_RECEIVE`选项时额外的锁定。设置为  `tcp_bpf_bypass_getsockopt` 函数，实现如下：

```C
// file: net/ipv4/tcp.c
bool tcp_bpf_bypass_getsockopt(int level, int optname)
{
    if (level == SOL_TCP && optname == TCP_ZEROCOPY_RECEIVE) 
        return true;
    return false;
}
```

#### 18 `CGROUP_SETSOCKOPT`

##### (1) 实现过程

`CGROUP_SETSOCKOPT`在设置socket选项信息(`setsockopt`系统调用)时调用，通过 `BPF_CGROUP_RUN_PROG_SETSOCKOPT` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_SETSOCKOPT(sock, level, optname, optval, optlen,    \
                        kernel_optval)                                          \
({                                                                              \
    int __ret = 0;                                                              \
    if (cgroup_bpf_enabled(CGROUP_SETSOCKOPT) &&                                \
        cgroup_bpf_sock_enabled(sock, CGROUP_SETSOCKOPT))                       \
        __ret = __cgroup_bpf_run_filter_setsockopt(sock, level,                 \
                            optname, optval, optlen, kernel_optval);            \
    __ret;                                                                      \
})
```

在设置了`CGROUP_SETSOCKOPT` BPF程序并且sk附加了`CGROUP_SETSOCKOPT` BPF程序的情况下，调用 `__cgroup_bpf_run_filter_setsockopt` 函数进行选项的设置，其实现如下：

```C
// file: kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_setsockopt(struct sock *sk, int *level, int *optname, 
                    char __user *optval, int *optlen, char **kernel_optval)
{
    // 获取cgroup
    struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    struct bpf_sockopt_buf buf = {};
    // 设置运行上下文的参数
    struct bpf_sockopt_kern ctx = {
        .sk = sk, .level = *level, .optname = *optname,
    };
    int ret, max_optlen;

    // 分配选项空间。分配比用户初始化的空间要多些，适应`TCP_CONGESTION(nv)`到`TCP_CONGESTION(cubic)`的覆盖
    max_optlen = max_t(int, 16, *optlen);
    max_optlen = sockopt_alloc_buf(&ctx, max_optlen, &buf);
    if (max_optlen < 0) return max_optlen;
    
    // 复制选项值和选项长度
    ctx.optlen = *optlen;
    if (copy_from_user(ctx.optval, optval, min(*optlen, max_optlen)) != 0) { ... }

    lock_sock(sk);
    // 运行`CGROUP_SETSOCKOPT`BPF程序
    ret = bpf_prog_run_array_cg(&cgrp->bpf, CGROUP_SETSOCKOPT, &ctx, bpf_prog_run, 0, NULL);
    release_sock(sk);
    // 出现错误时返回
    if (ret) goto out;

    if (ctx.optlen == -1) {
        // 选项长度设置为`-1`，绕过内核空间
        ret = 1;
    } else if (ctx.optlen > max_optlen || ctx.optlen < -1) {
        // 选项长度超出范围，返回错误
        ret = -EFAULT;
    } else {
        // 选项长度在范围内，进行内核处理
        ret = 0;
        // 导出任何可能的修改
        *level = ctx.level;
        *optname = ctx.optname;
        // 选项长度为0，表示使用原来用户空间设置的值
        if (ctx.optlen != 0) {
            *optlen = ctx.optlen;
            // 设置内核空间的选项值，使用栈上内存时分配内存空间
            if (!sockopt_buf_allocated(&ctx, &buf)) {
                void *p = kmalloc(ctx.optlen, GFP_USER);
                if (!p) { ret = -ENOMEM; goto out; }
                memcpy(p, ctx.optval, ctx.optlen);
                *kernel_optval = p;
            } else {
                *kernel_optval = ctx.optval;
            }
            // 导出并且不释放sockopt缓冲区
            return 0;
        }
    }
out:
    // 退出时释放内存空间
    sockopt_free_buf(&ctx, &buf);
    return ret;
}
```

##### (2) 触发过程

`setsockopt`系统调用设置socket选项，如下：

```C
// file: net/socket.c
SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname,
        char __user *, optval, int, optlen)
{
    return __sys_setsockopt(fd, level, optname, optval, optlen);
}
```

`__sys_setsockopt` 函数进行具体的设置操作，实现如下：

```C
// file: net/socket.c
int __sys_setsockopt(int fd, int level, int optname, char __user *user_optval, int optlen)
{
    sockptr_t optval = USER_SOCKPTR(user_optval);
    char *kernel_optval = NULL;
    int err, fput_needed;
    struct socket *sock;

    if (optlen < 0) return -EINVAL;
    // 查找fd对应的socket
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (!sock) return err;
    // LSM安全检查
    err = security_socket_setsockopt(sock, level, optname);
    if (err) goto out_put;

    if (!in_compat_syscall())
        // 运行`SETSOCKOPT`BPF程序
        err = BPF_CGROUP_RUN_PROG_SETSOCKOPT(sock->sk, &level, &optname, 
                                user_optval, &optlen, &kernel_optval);
    // 检查错误信息
    if (err < 0) goto out_put;
    if (err > 0) { err = 0; goto out_put; }

    // 存在内核选项时，设置选项值
    if (kernel_optval) optval = KERNEL_SOCKPTR(kernel_optval);
	
    // `SOL_SOCKET`层级选项设置
    if (level == SOL_SOCKET && !sock_use_custom_sol_socket(sock))
        err = sock_setsockopt(sock, level, optname, optval, optlen);
    else if (unlikely(!sock->ops->setsockopt))
        err = -EOPNOTSUPP;
    else
        // socket的`.setsockopt`接口设置
        err = sock->ops->setsockopt(sock, level, optname, optval, optlen);
    // 释放内核选项值
    kfree(kernel_optval);
out_put:
    fput_light(sock->file, fput_needed);
    return err;
}
```

#### 19 `CGROUP_INET4_GETPEERNAME`

##### (1) 实现过程

`CGROUP_INET4_GETPEERNAME`在获取ipv4的socket的对端地址时(`getpeername`系统调用)时调用，通过 `BPF_CGROUP_RUN_SA_PROG` 宏实现。

##### (2) 触发过程

`getpeername`系统调用获取socket的对端地址，如下：

```C
// file: net/socket.c
SYSCALL_DEFINE3(getpeername, int, fd, struct sockaddr __user *, usockaddr,
        int __user *, usockaddr_len)
{
    return __sys_getpeername(fd, usockaddr, usockaddr_len);
}
```

`__sys_getpeername` 函数进行实际的获取过程，实现如下：

```C
// file: net/socket.c
int __sys_getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
    struct socket *sock;
    struct sockaddr_storage address;
    int err, fput_needed;
    // 查找fd对应的socket
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (sock != NULL) {
        // LSM安全检查
        err = security_socket_getpeername(sock);
        if (err) { fput_light(sock->file, fput_needed); return err; }
        // 调用`.getname`接口
        err = sock->ops->getname(sock, (struct sockaddr *)&address, 1);
        if (err >= 0)
             // 复制地址信息，返回值表示地址的长度
			err = move_addr_to_user(&address, err, usockaddr, usockaddr_len);
        fput_light(sock->file, fput_needed);
    }
    return err;
}
```

ipv4下TCP、UDP、RAW类型的socket在Linux内核中的`.getname`接口都设置为`inet_getname`，如下：

```C
// file: net/ipv4/af_inet.c
// TCP
const struct proto_ops inet_stream_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    ...
    .getname        = inet_getname,
    ...
};
// UDP
const struct proto_ops inet_dgram_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    ...
    .getname        = inet_getname,
    ...
};
// RAW
static const struct proto_ops inet_sockraw_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    ...
    .getname        = inet_getname,
    ...
};
```

`inet_getname`函数获取本地和对端的网络地址，其实现如下：

```C
// file: net/ipv4/af_inet.c
int inet_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
    struct sock *sk = sock->sk;
    struct inet_sock *inet  = inet_sk(sk);
    DECLARE_SOCKADDR(struct sockaddr_in *, sin, uaddr);

    sin->sin_family = AF_INET;
    lock_sock(sk);
    if (peer) {
        // 获取对端地址
        if (!inet->inet_dport || 
            (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) && peer == 1)) {
            // 目的端口为0、或者sk未连接状态返回错误
            release_sock(sk);
            return -ENOTCONN;
        }
        // 设置目的地址和端口
        sin->sin_port = inet->inet_dport;
        sin->sin_addr.s_addr = inet->inet_daddr;
        // 运行`INET4_GETPEERNAME`BPF程序
        BPF_CGROUP_RUN_SA_PROG(sk, (struct sockaddr *)sin, CGROUP_INET4_GETPEERNAME);
    } else {
        // 获取本地地址
        __be32 addr = inet->inet_rcv_saddr;
        if (!addr) addr = inet->inet_saddr;
        // 设置本地端口和地址
        sin->sin_port = inet->inet_sport;
        sin->sin_addr.s_addr = addr;
        // 运行`INET4_GETSOCKNAME`BPF程序
        BPF_CGROUP_RUN_SA_PROG(sk, (struct sockaddr *)sin, CGROUP_INET4_GETSOCKNAME);
    }
    release_sock(sk);
    // 设置未使用的内存
    memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
    return sizeof(*sin);
}
```

#### 20 `CGROUP_INET6_GETPEERNAME`

##### (1) 实现过程

`CGROUP_INET6_GETPEERNAME`在获取ipv6的socket的对端地址时(`getpeername`系统调用)时调用，通过 `BPF_CGROUP_RUN_SA_PROG` 宏实现。

##### (2) 触发过程

ipv6下TCP、UDP、RAW类型的socket在Linux内核中的`.getname`接口都设置为`inet_getname`，如下：

```C
// file: net/ipv6/af_inet6.c
// TCP
const struct proto_ops inet6_stream_ops = {
    .family         = PF_INET6,
    .owner          = THIS_MODULE,
    ...
    .getname        = inet6_getname,
    ...
};
// UDP
const struct proto_ops inet6_dgram_ops = {
    .family         = PF_INET6,
    .owner          = THIS_MODULE,
    ...
    .getname        = inet6_getname,
    ...
};
// file: net/ipv6/raw.c
// RAW
const struct proto_ops inet6_sockraw_ops = {
    .family         = PF_INET6,
    .owner          = THIS_MODULE,
    ...
    .getname        = inet6_getname,
    ...
};
```

`inet6_getname`函数获取本地和对端的网络地址，其实现如下：

```C
// file: net/ipv6/af_inet6.c
int inet6_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
    struct sockaddr_in6 *sin = (struct sockaddr_in6 *)uaddr;
    struct sock *sk = sock->sk;
    struct inet_sock *inet = inet_sk(sk);
    struct ipv6_pinfo *np = inet6_sk(sk);
    // 设置地址基础信息
    sin->sin6_family = AF_INET6;
    sin->sin6_flowinfo = 0;
    sin->sin6_scope_id = 0;
    lock_sock(sk);
    if (peer) {
        // 获取对端地址
        if (!inet->inet_dport ||
            (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) && peer == 1)) {
            // 目的端口为0、或者sk未连接状态返回错误
            release_sock(sk);
            return -ENOTCONN;
        }
        // 设置目的地址和端口
        sin->sin6_port = inet->inet_dport;
        sin->sin6_addr = sk->sk_v6_daddr;
        if (np->sndflow) sin->sin6_flowinfo = np->flow_label;
        // 运行`INET6_GETPEERNAME`BPF程序
        BPF_CGROUP_RUN_SA_PROG(sk, (struct sockaddr *)sin, CGROUP_INET6_GETPEERNAME);
    } else {
        // 获取本地地址
        if (ipv6_addr_any(&sk->sk_v6_rcv_saddr))
            sin->sin6_addr = np->saddr;
        else
            sin->sin6_addr = sk->sk_v6_rcv_saddr;
        sin->sin6_port = inet->inet_sport;
        // 运行`INET6_GETSOCKNAME`BPF程序
        BPF_CGROUP_RUN_SA_PROG(sk, (struct sockaddr *)sin, CGROUP_INET6_GETSOCKNAME);
    }
    // 获取scope_id
    sin->sin6_scope_id = ipv6_iface_scope_id(&sin->sin6_addr, sk->sk_bound_dev_if);
    release_sock(sk);
    return sizeof(*sin);
}
```

#### 21 `CGROUP_INET4_GETSOCKNAME`

##### (1) 实现过程

`CGROUP_INET4_GETSOCKNAME`在获取ipv4的socket的本地地址时(`getsockname`系统调用)时调用，通过 `BPF_CGROUP_RUN_SA_PROG` 宏实现。

##### (2) 触发过程

`getsockname`系统调用获取socket的本地地址，如下：

```C
// file: net/socket.c
SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr,
        int __user *, usockaddr_len)
{
    return __sys_getsockname(fd, usockaddr, usockaddr_len);
}
```

`__sys_getsockname` 函数进行实际的获取过程，实现如下：

```C
// file: net/socket.c
int __sys_getsockname(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
    struct socket *sock;
    struct sockaddr_storage address;
    int err, fput_needed;
    // 查找fd对应的socket
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (!sock) goto out;
    // LSM安全检查
    err = security_socket_getsockname(sock);
    if (err) goto out_put;
    // 调用`.getname`接口
    err = sock->ops->getname(sock, (struct sockaddr *)&address, 0);
    if (err < 0) goto out_put;
    // 复制地址信息，返回值表示地址的长度
    err = move_addr_to_user(&address, err, usockaddr, usockaddr_len);
out_put:
    fput_light(sock->file, fput_needed);
out:
    return err;
}
```

通用调用`.getname`接口，其实现过程见`CGROUP_INET4_GETPEERNAME`。

#### 22 `CGROUP_INET6_GETSOCKNAME`

##### (1) 实现过程

`CGROUP_INET6_GETSOCKNAME`在获取ipv6的socket的本地地址时(`getsockname`系统调用)时调用，通过 `BPF_CGROUP_RUN_SA_PROG` 宏实现。

##### (2) 触发过程

通用调用`.getname`接口，其实现过程见`CGROUP_INET6_GETPEERNAME`。

#### 23 `CGROUP_INET_SOCK_RELEASE`

##### (1) 实现过程

`CGROUP_INET_SOCK_RELEASE`在关闭socket时(`close`系统调用)时调用，通过 `BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE` 宏实现，如下：

```C
// file: include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE(sk)               \
    BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET_SOCK_RELEASE)
```

`close`系统调用时调用文件的`.release`接口，创建socket时关联文件设置的`.release`接口为`sock_close`。如下：

```C
// file: net/socket.c
static const struct file_operations socket_file_ops = {
    ...
    .release    =   sock_close,
    ...
};
```

其实现如下：

```C
// file: net/socket.c
static int sock_close(struct inode *inode, struct file *filp)
{
    __sock_release(SOCKET_I(inode), inode);
    return 0;
}
```

`__sock_release`进行实际的释放操作，如下：

```C
// file: net/socket.c
static void __sock_release(struct socket *sock, struct inode *inode)
{
    if (sock->ops) {
        struct module *owner = sock->ops->owner;
        if (inode) inode_lock(inode);
        // `ops->release`接口调用
        sock->ops->release(sock);
        // 清空sk和ops接口
        sock->sk = NULL;
        if (inode) inode_unlock(inode);
        sock->ops = NULL;
        module_put(owner);
    }
    // fasync列表检查
    if (sock->wq.fasync_list) pr_err("%s: fasync list not empty!\n", __func__);
    // 释放关联的文件
    if (!sock->file) { iput(SOCK_INODE(sock)); return; }
    sock->file = NULL;
}
```

##### (2) IPV4的触发过程

ipv4下TCP、UDP、RAW类型的socket在Linux内核中的`.release`接口都设置为`inet_release`，如下：

```C
// file: net/ipv4/af_inet.c
// TCP
const struct proto_ops inet_stream_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    .release        = inet_release,
    ...
};
// UDP
const struct proto_ops inet_dgram_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    .release        = inet_release,
    .release        = inet_release,
    ...
};
// RAW
static const struct proto_ops inet_sockraw_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    .release        = inet_release,
    ...
};
```

其实现如下：

```C
// file: net/ipv4/af_inet.c
int inet_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    if (sk) {
        long timeout; 
        // 用户空间创建的socket，运行`INET_SOCK_RELEASE`BPF程序
        if (!sk->sk_kern_sock)
            BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE(sk);
        // 离开组播组
        ip_mc_drop_socket(sk);
        // 设置`LINGER`时，设置等待时间
        timeout = 0;
        if (sock_flag(sk, SOCK_LINGER) && !(current->flags & PF_EXITING))
            timeout = sk->sk_lingertime;
        sk->sk_prot->close(sk, timeout);
        sock->sk = NULL;
    }
    return 0;
}
```

##### (3) IPV6的触发过程

ipv6下TCP、UDP、RAW类型的socket在Linux内核中的`.release`接口都设置为`inet6_release`，如下：

```C
// file: net/ipv6/af_inet6.c
// TCP
const struct proto_ops inet6_stream_ops = {
    .family         = PF_INET6,
    .owner          = THIS_MODULE,
    .release        = inet6_release,
    ...
};
// UDP
const struct proto_ops inet6_dgram_ops = {
    .family         = PF_INET6,
    .owner          = THIS_MODULE,
    .release        = inet6_release,
    ...
};
// file: net/ipv6/raw.c
// RAW
const struct proto_ops inet6_sockraw_ops = {
    .family         = PF_INET6,
    .owner          = THIS_MODULE,
    .release        = inet6_release,
    ...
};
```

其实现如下：

```C
// file: net/ipv6/af_inet6.c
int inet6_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    if (!sk) return -EINVAL;
    // 释放组播列表()
    ipv6_sock_mc_close(sk);
    // 释放任播列表(anycast)
    ipv6_sock_ac_close(sk);
    // ipv4方式释放socket
    return inet_release(sock);
}
```

#### 24 `CGROUP_LSM`

##### (1) 实现过程

在附加BPF程序时，通过BPF trampoline设置调用函数。`bpf_lsm_find_cgroup_shim` 函数获取BPF的执行函数，根据LSM HOOK函数函数原型进行获取，如下：

```C
// file: kernel/bpf/bpf_lsm.c
void bpf_lsm_find_cgroup_shim(const struct bpf_prog *prog, bpf_func_t *bpf_func)
{
    const struct btf_param *args __maybe_unused;
    // LSM HOOK函数没有参数，或者在`bpf_lsm_current_hooks`中，使用`__cgroup_bpf_run_lsm_current`
    if (btf_type_vlen(prog->aux->attach_func_proto) < 1 || 
        btf_id_set_contains(&bpf_lsm_current_hooks, prog->aux->attach_btf_id)) {
        *bpf_func = __cgroup_bpf_run_lsm_current;
        return;
    }
    // 获取函数参数
    args = btf_params(prog->aux->attach_func_proto);

    if (args[0].type == btf_sock_ids[BTF_SOCK_TYPE_SOCKET])
        // 第一个参数是`socket`类型，使用`__cgroup_bpf_run_lsm_socket`
        *bpf_func = __cgroup_bpf_run_lsm_socket;
    else if (args[0].type == btf_sock_ids[BTF_SOCK_TYPE_SOCK])
        // 第一个参数是`sock`类型，使用`__cgroup_bpf_run_lsm_sock`
        *bpf_func = __cgroup_bpf_run_lsm_sock;
    else
        // 默认使用`__cgroup_bpf_run_lsm_current`
        *bpf_func = __cgroup_bpf_run_lsm_current;
}
```

`__cgroup_bpf_run_lsm_current` 函数是 在不带参数的LSM函数 或者 处于当前的hooks时，设置的实现接口。实现如下：

```C
// file: kernel/bpf/cgroup.c
unsigned int __cgroup_bpf_run_lsm_current(const void *ctx, const struct bpf_insn *insn)
{
    const struct bpf_prog *shim_prog;
    struct cgroup *cgrp;
    int ret = 0;
    // 获取bpf程序
    shim_prog = (const struct bpf_prog *)((void *)insn - offsetof(struct bpf_prog, insnsi));
    // 获取cgroup后，运行BPF程序
    cgrp = task_dfl_cgroup(current);
    if (likely(cgrp))
        ret = bpf_prog_run_array_cg(&cgrp->bpf, shim_prog->aux->cgroup_atype, ctx, bpf_prog_run, 0, NULL);
    return ret;
}
```

`__cgroup_bpf_run_lsm_socket` 函数是在第一个参数时`socket`类型时设置的实现接口。实现如下：

```C
// file: kernel/bpf/cgroup.c
unsigned int __cgroup_bpf_run_lsm_socket(const void *ctx, const struct bpf_insn *insn)
{
    const struct bpf_prog *shim_prog;
    struct socket *sock;
    struct cgroup *cgrp;
    int ret = 0;
    u64 *args;

    // 获取参数和bpf程序
    args = (u64 *)ctx;
    sock = (void *)(unsigned long)args[0];
    shim_prog = (const struct bpf_prog *)((void *)insn - offsetof(struct bpf_prog, insnsi));

    // 获取cgroup后，运行BPF程序
    cgrp = sock_cgroup_ptr(&sock->sk->sk_cgrp_data);
    if (likely(cgrp))
        ret = bpf_prog_run_array_cg(&cgrp->bpf, shim_prog->aux->cgroup_atype, ctx, bpf_prog_run, 0, NULL);
    return ret;
}
```

`__cgroup_bpf_run_lsm_sock` 函数是在第一个参数时`sock`类型时设置的实现接口。实现如下：

```C
// file: kernel/bpf/cgroup.c
unsigned int __cgroup_bpf_run_lsm_sock(const void *ctx, const struct bpf_insn *insn)
{
    const struct bpf_prog *shim_prog;
    struct sock *sk;
    struct cgroup *cgrp;
    int ret = 0;
    u64 *args;

    // 获取参数和bpf程序
    args = (u64 *)ctx;
    sk = (void *)(unsigned long)args[0];
    shim_prog = (const struct bpf_prog *)((void *)insn - offsetof(struct bpf_prog, insnsi));

    // 获取cgroup后，运行BPF程序
    cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    if (likely(cgrp))
        ret = bpf_prog_run_array_cg(&cgrp->bpf, shim_prog->aux->cgroup_atype, ctx, bpf_prog_run, 0, NULL);
    return ret;
}
```

##### (2) 触发过程

在调用LSM函数时触发的，其触发过程参见[BPF LSM的内核实现](./11-bpf%20lsm.md)章节。

## 5 总结

本文通过内核中的`cgroup_link`示例程序分析了Linux内核使用BPF程序在cgroup级别对进程、socket和设备文件(devfile)进行动态控制。

此外，Linux内核中还提供了丰富的cgroup测试程序，如下：

```bash
$ cd tools/testing/selftests/bpf/progs
$ ls -l *cgroup*
-rw-r--r-- 1 root root  764  2月 20  2023 cgroup_getset_retval_getsockopt.c
-rw-r--r-- 1 root root  355  2月 20  2023 cgroup_getset_retval_hooks.c
-rw-r--r-- 1 root root  862  2月 20  2023 cgroup_getset_retval_setsockopt.c
-rw-r--r-- 1 root root 4079  2月 20  2023 cgroup_hierarchical_stats.c
-rw-r--r-- 1 root root  781  2月 20  2023 cgroup_iter.c
-rw-r--r-- 1 root root 2243  2月 20  2023 cgroup_skb_sk_lookup_kern.c
-rw-r--r-- 1 root root 2086  2月 20  2023 cgrp_ls_attach_cgroup.c
-rw-r--r-- 1 root root 1184  2月 20  2023 dev_cgroup.c
-rw-r--r-- 1 root root  806  2月 20  2023 get_cgroup_id_kern.c
-rw-r--r-- 1 root root 4279  2月 20  2023 lsm_cgroup.c
-rw-r--r-- 1 root root  347  2月 20  2023 lsm_cgroup_nonvoid.c
-rw-r--r-- 1 root root  422  2月 20  2023 test_cgroup_link.c
```

## 参考资料

* [Linux Kernel Selftests](https://www.kernel.org/doc/html/latest/dev-tools/kselftest.html)
* [BPF_PROG_TYPE_CGROUP_SOCKOPT](https://www.kernel.org/doc/html/latest/bpf/prog_cgroup_sockopt.html)
* [BPF_PROG_TYPE_CGROUP_SYSCTL](https://www.kernel.org/doc/html/latest/bpf/prog_cgroup_sysctl.html)
* [cgroupv2 权威指南](https://arthurchiao.art/blog/cgroupv2-zh/)
* [BPF 进阶笔记（一）：BPF 程序（BPF Prog）类型详解](https://arthurchiao.art/blog/bpf-advanced-notes-1-zh/)