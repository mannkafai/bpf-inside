# BPF_ITER的内核实现

## 0 前言

今天我们借助`bpf_iter`示例程序分析从用户空间来灵活有效地遍历内核数据的实现过程。

## 1 简介

现有少数方法可以将内核数据复制到到用户空间。最流行是通过 `/proc`系统，例如可通过 "cat /proc/net/tcp6" 或者 "cat /proc/net/netlink" 命令打印系统中所有的 tcp6 或 netlink 套接字信息。然而，这种方式输出格式往往是固定的，如果用户想获得关于这些套接字的更多信息，就必须通过给内核打补丁的方式实现，这将涉及到上游和发布，往往需要很长的时间。

BPF 迭代器通过为每个内核数据对象调用BPF程序，灵活地收集哪些数据（例如，任务、bpf_maps等），从而解决了上述问题。

## 2 `bpf_iter`示例程序

### 2.1 BPF程序

BPF程序源码参见[bpf_iter.bpf.c](../src/bpf_iter.bpf.c)，主要内容如下：

```C
SEC("iter/task")
int dump_task_stack(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    long i, retlen;
    // task为NULL，表示结束
    if (task == (void *)0) return 0;
    // 获取内核栈信息
    retlen = bpf_get_task_stack(task, entries, MAX_STACK_TRACE_DEPTH * SIZE_OF_ULONG, 0);
    if (retlen < 0) return 0;
    // 打印栈信息
    BPF_SEQ_PRINTF(seq, "pid: %8u num_entries: %8u\n", task->pid, retlen / SIZE_OF_ULONG);
    for (i = 0; i < MAX_STACK_TRACE_DEPTH; i++) {
        if (retlen > i * SIZE_OF_ULONG)
            BPF_SEQ_PRINTF(seq, "[<0>] %pB\n", (void *)entries[i]);
    }
    BPF_SEQ_PRINTF(seq, "\n");
    return 0;
}

SEC("iter/bpf_map")
int dump_bpf_map(struct bpf_iter__bpf_map *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    __u64 seq_num = ctx->meta->seq_num;
    struct bpf_map *map = ctx->map;
    // map为NULL时，表示结束
    if (map == (void *)0) {
        BPF_SEQ_PRINTF(seq, "      %%%%%% END %%%%%%\n");
        return 0;
    }
    // seq_num为0时，打印表头
    if (seq_num == 0)
        BPF_SEQ_PRINTF(seq, "      id   refcnt  usercnt  locked_vm\n");
    // 打印map信息
    BPF_SEQ_PRINTF(seq, "%8u %8ld %8ld %10lu\n", map->id, map->refcnt.counter, map->usercnt.counter, 0LLU);
    return 0;
}
```

该程序包括多个BPF程序，都使用 `iter` 前缀。

### 2.2 用户程序

用户程序源码参见[bpf_iter.c](../src/bpf_iter.c)，主要内容如下：

#### 1 附加BPF程序

```C
int main(int argc, char **argv)
{
    struct bpf_iter_bpf *skel;
    LIBBPF_OPTS(bpf_iter_attach_opts, opts);
    union bpf_iter_link_info linfo;
    int err;

    // 设置 libbpf 调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);
    // 打开并加载BPF程序
    skel = bpf_iter_bpf__open_and_load();
    if (!skel) { ... }

    // 打印当前进程的PID
    printf("PID %d\n", getpid());
    // 筛选当前进程的内核栈信息
    memset(&linfo, 0, sizeof(linfo));
    linfo.task.tid = getpid();
    opts.link_info = &linfo;
    opts.link_info_len = sizeof(linfo);
    do_dummy_read_opts(skel->progs.dump_task_stack, &opts);

    // 读取内核的BPF map信息
    do_dummy_read(skel->progs.dump_bpf_map);

cleanup:
    // 销毁BPF程序
    bpf_iter_bpf__destroy(skel);
    return -err;
}

static void do_dummy_read_opts(struct bpf_program *prog, struct bpf_iter_attach_opts *opts)
{
    char buf[256] = {};
    int iter_fd, len;
    struct bpf_link *link;
    // 手动附加BPF迭代器
    link = bpf_program__attach_iter(prog, opts);
    if (link == NULL) { ... }
    // 创建`bpf_iter`，获取`iter_fd`
    iter_fd = bpf_iter_create(bpf_link__fd(link));
    if (iter_fd < 0) { ... }
    // 读取文件内容
    while ((len = read(iter_fd, buf, sizeof(buf) - 1)) > 0)
    {
        buf[len] = 0;
        fprintf(stderr, "%s", buf);
    }
    printf("\n");
    // 关闭`iter_fd`
    close(iter_fd);
free_link:
    bpf_link__destroy(link);
}
static void do_dummy_read(struct bpf_program *prog)
{
    do_dummy_read_opts(prog, NULL);
}
```

#### 2 读取数据过程

`bpf_iter`程序通过用户空间程序读取内核空间内容。

### 2.3 编译运行

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make bpf_iter 
$ sudo ./bpf_iter 
libbpf: loading object 'bpf_iter_bpf' from buffer
...
PID 2345
pid:     2345 num_entries:       11
[<0>] __bpf_get_stack+0x1fe/0x240
[<0>] bpf_get_task_stack+0x74/0xc0
[<0>] bpf_prog_3def68e2a01a9209_dump_task_stack+0x4a/0x135
[<0>] bpf_iter_run_prog+0x10b/0x200
[<0>] task_seq_show+0x4e/0x80
[<0>] bpf_seq_read+0x9a/0x430
[<0>] vfs_read+0xa8/0x2f0
[<0>] ksys_read+0x67/0xf0
[<0>] __x64_sys_read+0x19/0x30
[<0>] do_syscall_64+0x5c/0x90
[<0>] entry_SYSCALL_64_after_hwframe+0x72/0xdc


      id   refcnt  usercnt  locked_vm
       1        3        1          0
       2        3        1          0
      95        4        1          0
      96        5        1          0
      %%% END %%%
```

## 3 bpf_iter附加BPF的过程

`bpf_iter.bpf.c`文件中BPF程序的SEC名称分别为 `SEC("iter/task")`和 `SEC("iter/bpf_map")`，`iter` 前缀在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("iter+", TRACING, BPF_TRACE_ITER, SEC_ATTACH_BTF, attach_iter),
    SEC_DEF("iter.s+", TRACING, BPF_TRACE_ITER, SEC_ATTACH_BTF | SEC_SLEEPABLE, attach_iter),
    ...
};
```

`iter` 和 `iter.s` 都是可以通过 `attach_iter` 函数进行附加的。

### 3.1 确定BTF_ID的过程

`iter`前缀需要BTF支持，在加载BPF程序时，需要确定BTF信息。使用BTF的前缀为`bpf_iter_`, 类别为函数，即： `iter/task` 对应 `bpf_iter_task` 的函数类型。如下：

```C
// file: libbpf/src/libbpf.c
#define BTF_ITER_PREFIX "bpf_iter_"
#define BTF_MAX_NAME_SIZE 128

void btf_get_kernel_prefix_kind(enum bpf_attach_type attach_type, const char **prefix, int *kind)
{
    switch (attach_type) {
    ...
    case BPF_TRACE_ITER:
        *prefix = BTF_ITER_PREFIX;
        *kind = BTF_KIND_FUNC;
        break;
    default:
        *prefix = "";
        *kind = BTF_KIND_FUNC;
    }
}
```

### 3.2 附加和分离的过程

`attach_iter`函数是对 `bpf_program__attach_iter` 函数的调用封装。实现过程如下：

```C
// file: libbpf/src/libbpf.c
static int attach_iter(const struct bpf_program *prog, long cookie, struct bpf_link **link)
{
    *link = bpf_program__attach_iter(prog, NULL);
    return libbpf_get_error(*link);
}
// file: libbpf/src/libbpf.c
struct bpf_link * bpf_program__attach_iter(const struct bpf_program *prog,
                    const struct bpf_iter_attach_opts *opts)
{
    DECLARE_LIBBPF_OPTS(bpf_link_create_opts, link_create_opts);
    char errmsg[STRERR_BUFSIZE];
    struct bpf_link *link;
    int prog_fd, link_fd;
    __u32 target_fd = 0;

    if (!OPTS_VALID(opts, bpf_iter_attach_opts)) return libbpf_err_ptr(-EINVAL);
    
    // 获取opts设置的参数
    link_create_opts.iter_info = OPTS_GET(opts, link_info, (void *)0);
    link_create_opts.iter_info_len = OPTS_GET(opts, link_info_len, 0);

    // 获取bpf程序fd
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) { ... }

    // 创建link，设置分离接口
    link = calloc(1, sizeof(*link));
    if (!link) return libbpf_err_ptr(-ENOMEM);
    link->detach = &bpf_link__detach_fd;

    // 创建link
    link_fd = bpf_link_create(prog_fd, target_fd, BPF_TRACE_ITER, &link_create_opts);
    if (link_fd < 0)  { ... }
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
    case BPF_TRACE_ITER:
        // 设置`iter_info`属性
        attr.link_create.iter_info = ptr_to_u64(OPTS_GET(opts, iter_info, (void *)0));
        attr.link_create.iter_info_len = iter_info_len;
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

### 3.3 创建和关闭迭代器的过程

在读取迭代器数据时，首先需要获取迭代器的文件句柄，`bpf_iter_create`函数完成该项工作，其实现如下：

```C
// file: libbpf/src/bpf.c
int bpf_iter_create(int link_fd)
{
    const size_t attr_sz = offsetofend(union bpf_attr, iter_create);
    union bpf_attr attr;
    int fd;
    // 设置link_fd
    memset(&attr, 0, attr_sz);
    attr.iter_create.link_fd = link_fd;
    // BPF系统调用，使用`BPF_ITER_CREATE`指令
    fd = sys_bpf_fd(BPF_ITER_CREATE, &attr, attr_sz);
    return libbpf_err_errno(fd);
}
```

`close`函数实现迭代器的关闭.

## 4 内核实现

### 4.1 迭代器的注册和注销过程

#### 1 迭代器目标的介绍

内核中支持的BPF迭代器类型叫做迭代器目标(`iter_target`)，使用`struct bpf_iter_target_info`结构表示，其定义如下：

```C
// file: kernel/bpf/bpf_iter.c
struct bpf_iter_target_info {
    struct list_head list;
    const struct bpf_iter_reg *reg_info;
    u32 btf_id; /* cached value */
};
```

`.btf_id`字段表示`iter_target`对应的`btf`的ID。

`.reg_info`字段表示`iter_target`对应迭代器的注册接口，在内核中使用 `struct bpf_iter_reg` 表示，其定义如下：

```C
// file: include/linux/bpf.h
#define BPF_ITER_CTX_ARG_MAX 2
struct bpf_iter_reg {
    const char *target;
    bpf_iter_attach_target_t attach_target;
    bpf_iter_detach_target_t detach_target;
    bpf_iter_show_fdinfo_t show_fdinfo;
    bpf_iter_fill_link_info_t fill_link_info;
    bpf_iter_get_func_proto_t get_func_proto;
    u32 ctx_arg_info_size;
    u32 feature;
    struct bpf_ctx_arg_aux ctx_arg_info[BPF_ITER_CTX_ARG_MAX];
    const struct bpf_iter_seq_info *seq_info;
};
```

* `.target`字段表示BPF迭代器的名称;
* `.attach_target`和`.detach_target`用于注册和注销迭代器的特殊处理操作;
* `.show_fdinfo`和`.fill_link_info`用于用户获取迭代器相关信息时调用，调用时填充迭代器的具体信息;
* `.get_func_proto`用于获取迭代器的BPF辅助函数;
* `.ctx_arg_info_size`和`.ctx_arg_info`指定BPF程序参数信息;
* `.feature`指定BPF迭代器支持的功能，目前只支持`BPF_ITER_RESCHED`;
* `.seq_info`表示BPF迭代器的序列化操作接口，可以初始化/清理对应的私有数据;

`iter_target`的BTF信息通过 `DEFINE_BPF_ITER_FUNC` 宏定义的，其定义如下：

```C
// file: include/linux/bpf.h
#define BPF_ITER_FUNC_PREFIX "bpf_iter_"
#define DEFINE_BPF_ITER_FUNC(target, args...)           \
    extern int bpf_iter_ ## target(args);               \
    int __init bpf_iter_ ## target(args) { return 0; }
```

Linux内核(v6.2)支持多种BPF迭代器，如下：

```C
// file: kernel/kallsyms.c
// 遍历内核`ksym`符号信息
DEFINE_BPF_ITER_FUNC(ksym, struct bpf_iter_meta *meta, struct kallsym_iter *ksym)

// file: kernel/bpf/cgroup_iter.c
// 遍历内核中的cgroup结构信息
DEFINE_BPF_ITER_FUNC(cgroup, struct bpf_iter_meta *meta, struct cgroup *cgroup)

// file: kernel/bpf/link_iter.c
// 遍历内核中的BPF Link结构信息
DEFINE_BPF_ITER_FUNC(bpf_link, struct bpf_iter_meta *meta, struct bpf_link *link)

// file: kernel/bpf/map_iter.c
// 遍历内核中的BPF Map结构信息
DEFINE_BPF_ITER_FUNC(bpf_map, struct bpf_iter_meta *meta, struct bpf_map *map)

// file: kernel/bpf/map_iter.c
// 遍历内核中的BPF Map中元素信息
DEFINE_BPF_ITER_FUNC(bpf_map_elem, struct bpf_iter_meta *meta, 
                struct bpf_map *map, void *key, void *value)

// file: kernel/bpf/prog_iter.c
// 遍历内核中的BPF程序
DEFINE_BPF_ITER_FUNC(bpf_prog, struct bpf_iter_meta *meta, struct bpf_prog *prog)

// file: kernel/bpf/task_iter.c
// 遍历内核中的task信息
DEFINE_BPF_ITER_FUNC(task, struct bpf_iter_meta *meta, struct task_struct *task)

// file: kernel/bpf/task_iter.c
// 遍历task中的文件信息
DEFINE_BPF_ITER_FUNC(task_file, struct bpf_iter_meta *meta, 
                struct task_struct *task, u32 fd, struct file *file)

// file: kernel/bpf/task_iter.c
// 遍历task中的内存分布
DEFINE_BPF_ITER_FUNC(task_vma, struct bpf_iter_meta *meta,
                struct task_struct *task, struct vm_area_struct *vma)

// file: net/core/bpf_sk_storage.c
// 遍历内核中的BPF SK 本地存储信息
DEFINE_BPF_ITER_FUNC(bpf_sk_storage_map, struct bpf_iter_meta *meta,
                struct bpf_map *map, struct sock *sk, void *value)

// file: net/core/sock_map.c
// 遍历内核中的BPF Sockmap中元素
DEFINE_BPF_ITER_FUNC(sockmap, struct bpf_iter_meta *meta,
                struct bpf_map *map, void *key, struct sock *sk)

// file: net/ipv4/tcp_ipv4.c
// 遍历内核中的TCP连接信息
DEFINE_BPF_ITER_FUNC(tcp, struct bpf_iter_meta *meta, 
                struct sock_common *sk_common, uid_t uid)

// file: net/ipv4/udp.c
// 遍历内核中的UDP连接信息
DEFINE_BPF_ITER_FUNC(udp, struct bpf_iter_meta *meta, 
                struct udp_sock *udp_sk, uid_t uid, int bucket)

// file: net/ipv6/route.c
// 遍历内核中的ipv6路由信息
DEFINE_BPF_ITER_FUNC(ipv6_route, struct bpf_iter_meta *meta, struct fib6_info *rt)

// file: net/netlink/af_netlink.c
// 遍历内核中的Netllink信息
DEFINE_BPF_ITER_FUNC(netlink, struct bpf_iter_meta *meta, struct netlink_sock *sk)

// file: net/unix/af_unix.c
// 遍历内核中的Unix 域信息
DEFINE_BPF_ITER_FUNC(unix, struct bpf_iter_meta *meta, 
                struct unix_sock *unix_sk, uid_t uid)
```

#### 2 BPF迭代器的注册/注销过程

BPF迭代器通过`bpf_iter_reg_target`注册到内核中，实现如下：

```C
// file: kernel/bpf/bpf_iter.c
int bpf_iter_reg_target(const struct bpf_iter_reg *reg_info)
{
    struct bpf_iter_target_info *tinfo;
    // 分配内存空间
    tinfo = kzalloc(sizeof(*tinfo), GFP_KERNEL);
    if (!tinfo) return -ENOMEM;

    // 设置target的注册信息
    tinfo->reg_info = reg_info;
    INIT_LIST_HEAD(&tinfo->list);

    mutex_lock(&targets_mutex);
    // 添加到targets链表中
    list_add(&tinfo->list, &targets);
    mutex_unlock(&targets_mutex);
    return 0;
}
```

通过`bpf_iter_unreg_target`函数从内核中注销，实现如下：

```C
// file: kernel/bpf/bpf_iter.c
void bpf_iter_unreg_target(const struct bpf_iter_reg *reg_info)
{
    struct bpf_iter_target_info *tinfo;
    bool found = false;

    mutex_lock(&targets_mutex);
    // 遍历targets链表
    list_for_each_entry(tinfo, &targets, list) {
        if (reg_info == tinfo->reg_info) {
            // 找到reg_info对应的target后删除
            list_del(&tinfo->list);
            kfree(tinfo);
            found = true;
            break;
        }
    }
    mutex_unlock(&targets_mutex);
    WARN_ON(found == false);
}
```

#### 3 BPF迭代器确定BTF_ID

在加载BPF程序时需要验证附加的BTF_ID，对于`BPF_TRACE_ITER`类型的程序，需要BPF程序是否支持迭代器，如下：

```C
// file: kernel/bpf/verifier.c
static int check_attach_btf_id(struct bpf_verifier_env *env)
{
    ...
    else if (prog->expected_attach_type == BPF_TRACE_ITER) {
        if (!bpf_iter_prog_supported(prog))
            return -EINVAL;
        return 0;
    }
    ...
}
```

`bpf_iter_prog_supported`函数检查BPF程序是否支持迭代器，如下：

```C
// file: kernel/bpf/bpf_iter.c
bool bpf_iter_prog_supported(struct bpf_prog *prog)
{
    // BPF附加名称
    const char *attach_fname = prog->aux->attach_func_name;
    struct bpf_iter_target_info *tinfo = NULL, *iter;
    u32 prog_btf_id = prog->aux->attach_btf_id;
    const char *prefix = BPF_ITER_FUNC_PREFIX;
    int prefix_len = strlen(prefix);

    // 检查前缀是否符合，即：是否以`bpf_iter_`开始
    if (strncmp(attach_fname, prefix, prefix_len)) return false;

    mutex_lock(&targets_mutex);
    list_for_each_entry(iter, &targets, list) {
        // btf_id相同时，表示获取到`iter_target`
        if (iter->btf_id && iter->btf_id == prog_btf_id) {
            tinfo = iter;
            break;
        }
        // 去掉前缀后，比较`target`名称，相同时表示获取`iter_target`
        if (!strcmp(attach_fname + prefix_len, iter->reg_info->target)) {
            // 设置`iter_target`的btf_id，即：prog->aux->attach_btf_id
            cache_btf_id(iter, prog);
            tinfo = iter;
            break;
        }
    }
    mutex_unlock(&targets_mutex);
    // 获取到`iter_target`后，设置上下文参数信息
    if (tinfo) {
        prog->aux->ctx_arg_info_size = tinfo->reg_info->ctx_arg_info_size;
        prog->aux->ctx_arg_info = tinfo->reg_info->ctx_arg_info;
    }
    return tinfo != NULL;
}
```

### 4.2 附加BPF程序的过程

#### 1 BPF系统调用

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

#### 2 `BPF_LINK_CREATE`

`link_create` 在检查BFP程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 `iter`前缀的程序类型为`BPF_PROG_TYPE_TRACING`, 附加类型为`BPF_TRACE_ITER`, 对应 `bpf_iter_link_attach` 处理函数。如下：

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
    case BPF_PROG_TYPE_LSM:
    case BPF_PROG_TYPE_TRACING:
            ...
        else if (prog->expected_attach_type == BPF_TRACE_ITER)
            ret = bpf_iter_link_attach(attr, uattr, prog);
        else 
            ...
        break;
    ...
    }
    ...
}
```

#### 3 `bpf_iter_link_attach`

`bpf_iter_link_attach` 函数检查用户输入的参数信息，获取对应的`iter_target`后，设置 `iter_link` 的信息后，附加BPF程序。如下：

```C
// file: kernel/bpf/bpf_iter.c
int bpf_iter_link_attach(const union bpf_attr *attr, bpfptr_t uattr, struct bpf_prog *prog)
{
    struct bpf_iter_target_info *tinfo = NULL, *iter;
    struct bpf_link_primer link_primer;
    union bpf_iter_link_info linfo;
    struct bpf_iter_link *link;
    u32 prog_btf_id, linfo_len;
    bpfptr_t ulinfo;
    int err;

    // 检查用户输入的参数信息，不能设置`target_fd`和`flags`参数
    if (attr->link_create.target_fd || attr->link_create.flags) return -EINVAL;

    memset(&linfo, 0, sizeof(union bpf_iter_link_info));

    // 获取并检查用户输入的`iter_info`
    ulinfo = make_bpfptr(attr->link_create.iter_info, uattr.is_kernel);
    linfo_len = attr->link_create.iter_info_len;
    if (bpfptr_is_null(ulinfo) ^ !linfo_len) return -EINVAL;

    // 复制用户空间输入的`iter_info`
    if (!bpfptr_is_null(ulinfo)) {
        err = bpf_check_uarg_tail_zero(ulinfo, sizeof(linfo), linfo_len);
        if (err) return err;
        linfo_len = min_t(u32, linfo_len, sizeof(linfo));
        if (copy_from_bpfptr(&linfo, ulinfo, linfo_len)) return -EFAULT;
    }

    // 获取btf_id后，获取`iter_target`
    prog_btf_id = prog->aux->attach_btf_id;
    mutex_lock(&targets_mutex);
    list_for_each_entry(iter, &targets, list) {
        if (iter->btf_id == prog_btf_id) { 
            tinfo = iter;
            break;
        }
    }
    mutex_unlock(&targets_mutex);
    // `iter_target`不存在时，返回错误
    if (!tinfo) return -ENOENT;

    // 只允许`sleepable`BPF程序支持重新调度
    if (prog->aux->sleepable && !bpf_iter_target_support_resched(tinfo))
        return -EINVAL;

    // 创建 link
    link = kzalloc(sizeof(*link), GFP_USER | __GFP_NOWARN);
    if (!link) return -ENOMEM;

    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_ITER, &bpf_iter_link_lops, prog);
    link->tinfo = tinfo;
    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    if (err) { ... }

    // `iter_target`支持附加时，调用`.attach_target`接口
    if (tinfo->reg_info->attach_target) {
        err = tinfo->reg_info->attach_target(prog, &linfo, &link->aux);
        if (err) { ... }
    }
    // fd 和 file 进行关联
    return bpf_link_settle(&link_primer);
}
```

### 4.3 注销BPF程序的过程

#### 1 `bpf_iter_link_lops`接口

在附加`bpf_iter_link_attach`过程中，设置了用户空间操作`bpf_link`的文件接口，如下：

```C
// file: kernel/bpf/bpf_iter.c
int bpf_iter_link_attach(const union bpf_attr *attr, bpfptr_t uattr, struct bpf_prog *prog)
{
    ...
    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_ITER, &bpf_iter_link_lops, prog);
    link->tinfo = tinfo;
    ...
    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    ...
}
```

`bpf_iter_link_lops` 是设置的文件操作接口，定义如下：

```C
// file: kernel/bpf/bpf_iter.c
static const struct bpf_link_ops bpf_iter_link_lops = {
    .release = bpf_iter_link_release,
    .dealloc = bpf_iter_link_dealloc,
    .update_prog = bpf_iter_link_replace,
    .show_fdinfo = bpf_iter_link_show_fdinfo,
    .fill_link_info = bpf_iter_link_fill_link_info,
};
```

#### 2 更新bpf程序

`.update_prog`更新接口，更新当前设置的bpf程序，设置为`bpf_iter_link_replace`。实现如下:

```C
// file: kernel/bpf/bpf_iter.c
static int bpf_iter_link_replace(struct bpf_link *link,
            struct bpf_prog *new_prog, struct bpf_prog *old_prog)
{
    int ret = 0;

    mutex_lock(&link_mutex);
    // 不能替换同一个程序
    if (old_prog && link->prog != old_prog) {
        ret = -EPERM;
        goto out_unlock;
    }
    // 检查程序类型、附加类型、BTF是否一致
    if (link->prog->type != new_prog->type ||
        link->prog->expected_attach_type != new_prog->expected_attach_type ||
        link->prog->aux->attach_btf_id != new_prog->aux->attach_btf_id) {
        ret = -EINVAL;
        goto out_unlock;
    }
    // 替换程序
    old_prog = xchg(&link->prog, new_prog);
    bpf_prog_put(old_prog);

out_unlock:
    mutex_unlock(&link_mutex);
    return ret;
}
```

#### 3 注销接口

`.release`接口释放`iter_link`关联的程序，设置为`bpf_iter_link_release` 。实现如下:

```C
// file: kernel/bpf/bpf_iter.c
static void bpf_iter_link_release(struct bpf_link *link)
{
    struct bpf_iter_link *iter_link = container_of(link, struct bpf_iter_link, link);
    // `iter_target`支持分离时，调用`.detach_target`接口
    if (iter_link->tinfo->reg_info->detach_target)
        iter_link->tinfo->reg_info->detach_target(&iter_link->aux);
}
```

`.dealloc`接口释放`iter_link`内存资源，设置为`bpf_iter_link_dealloc` 。实现如下:

```C
// file: kernel/bpf/bpf_iter.c
static void bpf_iter_link_dealloc(struct bpf_link *link)
{
    struct bpf_iter_link *iter_link = container_of(link, struct bpf_iter_link, link);
    // 释放`iter_link`
    kfree(iter_link);
}
```

### 4.4 迭代器读取数据的实现

#### 1 打开迭代器

##### (1) BPF系统调用

使用`BPF_ITER_CREATE` BPF系统调用，如下：

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
    case BPF_ITER_CREATE: err = bpf_iter_create(&attr); break;
    ...
    }
    return err;
}
```

##### (2) `bpf_iter_create`

`bpf_iter_create`函数创建迭代器的文件描述符，获取`bpf_link`后创建文件描述符，如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_iter_create(union bpf_attr *attr)
{
    struct bpf_link *link;
    int err;
    // `attr`检查
    if (CHECK_ATTR(BPF_ITER_CREATE)) return -EINVAL;
    // `iter_create`不支持flag设置
    if (attr->iter_create.flags) return -EINVAL;

    // 获取`bpf_link`
    link = bpf_link_get_from_fd(attr->iter_create.link_fd);
    if (IS_ERR(link)) return PTR_ERR(link);

    // 创建`iter_fd`
    err = bpf_iter_new_fd(link);
    bpf_link_put(link);
    return err;
}
```

`bpf_link_get_from_fd`函数根据`fd`获取`bpf_link`，实现如下：

```C
// file: kernel/bpf/syscall.c
struct bpf_link *bpf_link_get_from_fd(u32 ufd)
{
    // 根据fd获取文件信息
    struct fd f = fdget(ufd);
    struct bpf_link *link;

    // 文件不存在、`.f_op`接口不匹配时，返回错误 
    if (!f.file) return ERR_PTR(-EBADF);
    if (f.file->f_op != &bpf_link_fops) {
        fdput(f);
        return ERR_PTR(-EINVAL);
    }
    // 文件的私有数据即`bpf_link`
    link = f.file->private_data;
    bpf_link_inc(link);
    fdput(f);
    return link;
}
```

##### (3) 创建用户空间FD

`bpf_iter_new_fd`函数根据`bpf_link`创建用户空间使用的文件描述符，实现如下：

```C
// file: kernel/bpf/bpf_iter.c
int bpf_iter_new_fd(struct bpf_link *link)
{
    struct bpf_iter_link *iter_link;
    struct file *file;
    unsigned int flags;
    int err, fd;

    // `.ops`不是`bpf_iter_link_lops`时，返回错误
    if (link->ops != &bpf_iter_link_lops) return -EINVAL;

    // 获取未使用的`fd`, 设置为只读
    flags = O_RDONLY | O_CLOEXEC;
    fd = get_unused_fd_flags(flags);
    if (fd < 0) return fd;

    // 创建匿名节点文件
    file = anon_inode_getfile("bpf_iter", &bpf_iter_fops, NULL, flags);
    if (IS_ERR(file)) { err = PTR_ERR(file); goto free_fd; }

    // 获取`iter_link`
    iter_link = container_of(link, struct bpf_iter_link, link);
    // 准备`seq`文件
    err = prepare_seq_file(file, iter_link, __get_seq_info(iter_link));
    if (err) goto free_file;

    // 文件关联fd
    fd_install(fd, file);
    return fd;
free_file:
    fput(file);
free_fd:
    put_unused_fd(fd);
    return err;
}
```

`__get_seq_info`函数获取`iter_link`的文件读取操作接口(`seq_info`)，实现如下：

```C
// file: kernel/bpf/bpf_iter.c
static const struct bpf_iter_seq_info * __get_seq_info(struct bpf_iter_link *link)
{
    const struct bpf_iter_seq_info *seq_info;

    if (link->aux.map) {
        // `link`存在辅助的map时，获取`map->ops->iter_seq_info`
        seq_info = link->aux.map->ops->iter_seq_info;
        if (seq_info) return seq_info;
    }
    // 默认使用`reg_info->seq_info`
    return link->tinfo->reg_info->seq_info;
}
```

`prepare_seq_file`函数准备seq文件，实现如下：

```C
// file: kernel/bpf/bpf_iter.c
static int prepare_seq_file(struct file *file, struct bpf_iter_link *link, 
                const struct bpf_iter_seq_info *seq_info)
{
    struct bpf_iter_priv_data *priv_data;
    struct bpf_iter_target_info *tinfo;
    struct bpf_prog *prog;
    u32 total_priv_dsize;
    struct seq_file *seq;
    int err = 0;

    // 获取`iter_link`关联的BPF程序
    mutex_lock(&link_mutex);
    prog = link->link.prog;
    bpf_prog_inc(prog);
    mutex_unlock(&link_mutex);

    tinfo = link->tinfo;
    // 计算BPF迭代器的私有数据大小
    total_priv_dsize = offsetof(struct bpf_iter_priv_data, target_private) + seq_info->seq_priv_size;
    // 分配私有数据空间，并打开`seq`文件
    priv_data = __seq_open_private(file, seq_info->seq_ops, total_priv_dsize);
    if (!priv_data) { err = -ENOMEM; goto release_prog; }

    // `.init_seq_private`接口存在时，初始化迭代器目标的私有数据
    if (seq_info->init_seq_private) {
        err = seq_info->init_seq_private(priv_data->target_private, &link->aux);
        if (err) goto release_seq_file;
    }
    // 初始化私有数据的元信息
    init_seq_meta(priv_data, tinfo, seq_info, prog);
    // 设置seq的私有数据为BPF迭代器的私有数据
    seq = file->private_data;
    seq->private = priv_data->target_private;

    return 0;
    // 失败时，清理资源
release_seq_file:
    seq_release_private(file->f_inode, file);
    file->private_data = NULL;
release_prog:
    bpf_prog_put(prog);
    return err;
}
```

`init_seq_meta`函数初始化BPF迭代器的元信息，如下：

```C
// file: kernel/bpf/bpf_iter.c
static void init_seq_meta(struct bpf_iter_priv_data *priv_data, struct bpf_iter_target_info *tinfo, 
            const struct bpf_iter_seq_info *seq_info, struct bpf_prog *prog)
{
    priv_data->tinfo = tinfo;
    priv_data->seq_info = seq_info;
    priv_data->prog = prog;
    priv_data->session_id = atomic64_inc_return(&session_id);
    // 重置seq序号、结束标志
    priv_data->seq_num = 0;
    priv_data->done_stop = false;
}
```

#### 2 关闭迭代器

在打开迭代器时设置的文件操作接口为`bpf_iter_fops`，定义如下：

```C
// file: kernel/bpf/bpf_iter.c
const struct file_operations bpf_iter_fops = {
    .open       = iter_open,
    .llseek     = no_llseek,
    .read       = bpf_seq_read,
    .release    = iter_release,
};
```

`.release`接口在关闭文件时调用，设置为`iter_release`，实现如下：

```C
// file: kernel/bpf/bpf_iter.c
static int iter_release(struct inode *inode, struct file *file)
{
    struct bpf_iter_priv_data *iter_priv;
    struct seq_file *seq;
    
    // 获取`seq`文件，不存在时返回
    seq = file->private_data;
    if (!seq) return 0;
    // 获取BPF迭代器使用数据
    iter_priv = container_of(seq->private, struct bpf_iter_priv_data, target_private);

    // `.fini_seq_private`接口存在时，清理迭代器目标的私有数据
    if (iter_priv->seq_info->fini_seq_private)
        iter_priv->seq_info->fini_seq_private(seq->private);

    bpf_prog_put(iter_priv->prog);
    // 修改`seq`文件的私有数据
    seq->private = iter_priv;
    // 释放私有数据，并关闭`seq`文件
    return seq_release_private(inode, file);
}
```

#### 3 读取迭代器的数据

`.read`接口在读取数据时调用，设置为`bpf_seq_read`，实现如下：

```C
// file: kernel/bpf/bpf_iter.c
static ssize_t bpf_seq_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
    struct seq_file *seq = file->private_data;
    size_t n, offs, copied = 0;
    int err = 0, num_objs = 0;
    bool can_resched;
    void *p;

    mutex_lock(&seq->lock);

    // seq缓冲区不存在时
    if (!seq->buf) {
        // 分配8个页的内存当做缓冲区
        seq->size = PAGE_SIZE << 3;
        seq->buf = kvmalloc(seq->size, GFP_KERNEL);
        if (!seq->buf) { err = -ENOMEM; goto done; }
    }
    // 存在缓存数据时，从缓冲区中读取
    if (seq->count) {
        n = min(seq->count, size);
        err = copy_to_user(buf, seq->buf + seq->from, n);
        if (err) { err = -EFAULT; goto done; }
        seq->count -= n;
        seq->from += n;
        copied = n;
        goto done;
    }
    // 设置缓冲区的起始位置
    seq->from = 0;

    // 开始读取数据项
    p = seq->op->start(seq, &seq->index);
    // 数据项不存在时，停止读取
    if (!p) goto stop;
    // 获取数据项失败时，结束读取
    if (IS_ERR(p)) { err = PTR_ERR(p); seq->op->stop(seq, p); seq->count = 0; goto done; }
    
    // 打印数据项到缓冲区中
    err = seq->op->show(seq, p);
    // 跳过数据项时，下一个有效数据项可以重复使用`seq_num`
	if (err > 0) { bpf_iter_dec_seq_num(seq); seq->count = 0;
    } else if (err < 0 || seq_has_overflowed(seq)) {
        // 打印出错、缓冲区溢出时，结束读取
        if (!err) err = -E2BIG; seq->op->stop(seq, p); seq->count = 0; goto done;
    }

    // 检查是否支持重新调度
    can_resched = bpf_iter_support_resched(seq);

    // 获取下一个数据项的处理
    while (1) {
        loff_t pos = seq->index;
        num_objs++;
        offs = seq->count;
        
        // 获取下一个数据项
        p = seq->op->next(seq, p, &seq->index);
        if (pos == seq->index) { seq->index++; }
        // 数据项为空时，退出获取过程
        if (IS_ERR_OR_NULL(p)) break;
        // 获取到有效的数据项，增加`seq_num`
        bpf_iter_inc_seq_num(seq);
        // 缓冲区不足时，退出读取过程
        if (seq->count >= size) break;
        
        // 读取数量超过限制(`1000000`)时，退出获取过程
        if (num_objs >= MAX_ITER_OBJECTS) {
            // 缓冲区为空时，结束读取
            if (offs == 0) { err = -EAGAIN; seq->op->stop(seq, p); goto done; }
            break;
        }
        // 打印数据项到缓冲区中
        err = seq->op->show(seq, p);

        // 跳过数据项时，下一个有效数据项可以重复使用`seq_num`
        if (err > 0) { bpf_iter_dec_seq_num(seq); seq->count = offs;
        } else if (err < 0 || seq_has_overflowed(seq)) {
            seq->count = offs;
            // 缓冲区为空时，结束读取
            if (offs == 0) { if (!err) err = -E2BIG; seq->op->stop(seq, p); goto done; }
            // 打印出错、缓冲区溢出时，退出获取过程
            break;
        }
        // 支持重新调度时，重新调度
        if (can_resched) cond_resched();
    }
stop:
    offs = seq->count;
    // 读取出错时，结束读取
    if (IS_ERR(p)) { seq->op->stop(seq, NULL); err = PTR_ERR(p); goto done; }
    // 停止读取
    seq->op->stop(seq, p);
    // 读取结束时
    if (!p) {
        // 缓冲区未溢出，修改`.done_stop = true`
        if (!seq_has_overflowed(seq)) { bpf_iter_done_stop(seq); 
        } else {
            seq->count = offs;
            // 缓冲区为空时，结束读取
            if (offs == 0) { err = -E2BIG; goto done; }
        }
    }
    // 复制读取内容到用户缓冲区
    n = min(seq->count, size);
    err = copy_to_user(buf, seq->buf, n);
    if (err) { err = -EFAULT; goto done; }
    copied = n;
    seq->count -= n;
    seq->from = n;
done:
    // 设置返回值，读取的数据量或者错误码
    if (!copied) copied = err;
    else *ppos += copied;
    mutex_unlock(&seq->lock);
    return copied;
}
```

整个读取过程中通过控制`seq->op`操作接口，实现读取过程。

`bpf_iter_inc_seq_num`和`bpf_iter_dec_seq_num`函数增加/减少读取的seq_num，实现如下：

```C
// file: kernel/bpf/bpf_iter.c
static void bpf_iter_inc_seq_num(struct seq_file *seq)
{
    struct bpf_iter_priv_data *iter_priv;
    iter_priv = container_of(seq->private, struct bpf_iter_priv_data, target_private);
    iter_priv->seq_num++;
}
// file: kernel/bpf/bpf_iter.c
static void bpf_iter_dec_seq_num(struct seq_file *seq)
{
    struct bpf_iter_priv_data *iter_priv;
    iter_priv = container_of(seq->private, struct bpf_iter_priv_data, target_private);
    iter_priv->seq_num--;
}
```

### 4.5 `bpf_map`迭代器的实现

#### 1 注册过程

`bpf_map`迭代器的注册信息在内核中使用`bpf_map_reg_info`表示，定义如下：

```C
// file: kernel/bpf/map_iter.c
static struct bpf_iter_reg bpf_map_reg_info = {
    .target     = "bpf_map",
    .ctx_arg_info_size  = 1,
    .ctx_arg_info   = {
        { offsetof(struct bpf_iter__bpf_map, map), PTR_TO_BTF_ID_OR_NULL },
    },
    .seq_info = &bpf_map_seq_info,
};
```

在`initcall`阶段注册到内核中，如下：

```C
// file: kernel/bpf/map_iter.c
static int __init bpf_map_iter_init(void)
{
    int ret;
    // 设置第一个参数的BTF_ID后，注册`bpf_map`迭代器
    bpf_map_reg_info.ctx_arg_info[0].btf_id = *btf_bpf_map_id;
    ret = bpf_iter_reg_target(&bpf_map_reg_info);
    if (ret) return ret;
    // 注册`pf_map_elem`迭代器
    return bpf_iter_reg_target(&bpf_map_elem_reg_info);
}
late_initcall(bpf_map_iter_init);
```

#### 2 迭代器的操作接口

`bpf_map`迭代器获取内核中所有的BPF MAP，不需要额外的操作接口。

#### 3 `seq_info`的操作接口

`bpf_map`迭代器的`.seq_info`字段设置为`bpf_map_seq_info`，定义如下：

```C
// file: kernel/bpf/map_iter.c
static const struct bpf_iter_seq_info bpf_map_seq_info = {
    .seq_ops            = &bpf_map_seq_ops,
    .init_seq_private   = NULL,
    .fini_seq_private   = NULL,
    .seq_priv_size      = sizeof(struct bpf_iter_seq_map_info),
};
```

`bpf_map_seq_info`的私有数据是`struct bpf_iter_seq_map_info`类型的结构, 定义如下：

```C
// file: kernel/bpf/map_iter.c
struct bpf_iter_seq_map_info {
    u32 map_id;
};
```

私有数据不需要额外的初始化和清理。

#### 4 `seq_ops`的操作接口

`bpf_map`迭代器的`.seq_ops`接口设置为`bpf_map_seq_ops`, 定义如下：

```C
// file: kernel/bpf/map_iter.c
static const struct seq_operations bpf_map_seq_ops = {
    .start  = bpf_map_seq_start,
    .next   = bpf_map_seq_next,
    .stop   = bpf_map_seq_stop,
    .show   = bpf_map_seq_show,
};
```

##### `.start`接口

`.start`接口在开始获取迭代目标时调用，设置为`bpf_map_seq_start`，实现如下：

```C
// file: kernel/bpf/map_iter.c
static void *bpf_map_seq_start(struct seq_file *seq, loff_t *pos)
{
    struct bpf_iter_seq_map_info *info = seq->private;
    struct bpf_map *map;
    // 获取当前或下一个迭代目标
    map = bpf_map_get_curr_or_next(&info->map_id);
    if (!map) return NULL;
    // 起始时，增加pos计数
    if (*pos == 0) ++*pos;
    return map;
}
```

##### `.next`接口

`.next`接口在获取下一个迭代目标时调用，设置为`bpf_map_seq_next`，实现如下：

```C
// file: kernel/bpf/map_iter.c
static void *bpf_map_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
    struct bpf_iter_seq_map_info *info = seq->private;
    // 增加`pos`和`map_id`
    ++*pos;
    ++info->map_id;
    // 释放上一个map的占用
    bpf_map_put((struct bpf_map *)v);
    // 获取当前或下一个迭代目标
    return bpf_map_get_curr_or_next(&info->map_id);
}
```

##### `.stop`接口

`.stop`接口在停止获取时调用，设置为`bpf_map_seq_stop`，实现如下：

```C
// file: kernel/bpf/map_iter.c
static void bpf_map_seq_stop(struct seq_file *seq, void *v)
{
    // `v`为空，表示读取完毕，否则释放map的占用
    if (!v)
        (void)__bpf_map_seq_show(seq, v, true);
    else
        bpf_map_put((struct bpf_map *)v);
}
```

##### `.show`接口

`.show`接口在将获取的目标打印到缓冲区时调用，设置为`bpf_map_seq_show`，实现如下：

```C
// file: kernel/bpf/map_iter.c
static int bpf_map_seq_show(struct seq_file *seq, void *v)
{
    return __bpf_map_seq_show(seq, v, false);
}
```

`bpf_map_seq_show`函数是对`__bpf_map_seq_show`的调用封装，后者实现如下：

```C
// file: kernel/bpf/map_iter.c
static int __bpf_map_seq_show(struct seq_file *seq, void *v, bool in_stop)
{
    struct bpf_iter__bpf_map ctx;
    struct bpf_iter_meta meta;
    struct bpf_prog *prog;
    int ret = 0;
    // 设置BPF迭代器上下文
    ctx.meta = &meta;
    ctx.map = v;
    meta.seq = seq;

    // 获取BPF程序
    prog = bpf_iter_get_info(&meta, in_stop);
    // 运行BPF迭代器程序
    if (prog) ret = bpf_iter_run_prog(prog, &ctx);
    return ret;
}
```

BPF_MAP迭代器的上下文用`struct bpf_iter__bpf_map`表示，定义如下：

```C
// file: kernel/bpf/map_iter.c
struct bpf_iter__bpf_map {
    __bpf_md_ptr(struct bpf_iter_meta *, meta);
    __bpf_md_ptr(struct bpf_map *, map);
};
```

#### 5 BPF迭代器程序的运行过程

`bpf_iter_get_info`函数获取BPF迭代器程序，实现如下：

```C
// file: kernel/bpf/bpf_iter.c
struct bpf_prog *bpf_iter_get_info(struct bpf_iter_meta *meta, bool in_stop)
{
    struct bpf_iter_priv_data *iter_priv;
    struct seq_file *seq;
    void *seq_priv;

    seq = meta->seq;
    // 不是BPF迭代器时，返回NULL
    if (seq->file->f_op != &bpf_iter_fops) return NULL;

    // 获取BPF迭代器的私有数据
    seq_priv = seq->private;
    iter_priv = container_of(seq_priv, struct bpf_iter_priv_data, target_private);

    // stop状态时，返回NULL
    if (in_stop && iter_priv->done_stop) return NULL;

    // 设置迭代器的元数据后，返回BPF程序
    meta->session_id = iter_priv->session_id;
    meta->seq_num = iter_priv->seq_num;
    return iter_priv->prog;
}
```

`bpf_iter_run_prog`函数运行BPF迭代器程序，实现如下：

```C
// file: kernel/bpf/bpf_iter.c
int bpf_iter_run_prog(struct bpf_prog *prog, void *ctx)
{
    struct bpf_run_ctx run_ctx, *old_run_ctx;
    int ret;

    if (prog->aux->sleepable) {
        rcu_read_lock_trace();
        migrate_disable();
        might_fault();
        // 设置BPF程序运行上下文后，运行BPF程序
        old_run_ctx = bpf_set_run_ctx(&run_ctx);
        ret = bpf_prog_run(prog, ctx);
        bpf_reset_run_ctx(old_run_ctx);
        migrate_enable();
        rcu_read_unlock_trace();
    } else {
        rcu_read_lock();
        migrate_disable();
        // 设置BPF程序运行上下文后，运行BPF程序
        old_run_ctx = bpf_set_run_ctx(&run_ctx);
        ret = bpf_prog_run(prog, ctx);
        bpf_reset_run_ctx(old_run_ctx);
        migrate_enable();
        rcu_read_unlock();
    }
    // 返回BPF程序运行结果，0表示运行成功，1表示重新获取目标
    return ret == 0 ? 0 : -EAGAIN;
}
```

### 4.6 `bpf_map_elem`迭代器的实现

#### 1 注册过程

`bpf_map_elem`迭代器的注册信息在内核中使用`bpf_map_elem_reg_info`表示，定义如下：

```C
// file: kernel/bpf/map_iter.c
static const struct bpf_iter_reg bpf_map_elem_reg_info = {
    .target     = "bpf_map_elem",
    .attach_target      = bpf_iter_attach_map,
    .detach_target      = bpf_iter_detach_map,
    .show_fdinfo        = bpf_iter_map_show_fdinfo,
    .fill_link_info     = bpf_iter_map_fill_link_info,
    .ctx_arg_info_size  = 2,
    .ctx_arg_info       = {
        { offsetof(struct bpf_iter__bpf_map_elem, key),
            PTR_TO_BUF | PTR_MAYBE_NULL | MEM_RDONLY },
        { offsetof(struct bpf_iter__bpf_map_elem, value),
            PTR_TO_BUF | PTR_MAYBE_NULL },
    },
};
```

在`initcall`阶段注册到内核中，如下：

```C
// file: kernel/bpf/map_iter.c
static int __init bpf_map_iter_init(void)
{
    ...
    // 注册`bpf_map_elem`迭代器目标
    return bpf_iter_reg_target(&bpf_map_elem_reg_info);
}
late_initcall(bpf_map_iter_init);
```

#### 2 迭代器的操作接口

`bpf_map_elem`迭代器获取指定BPF MAP中的元素，需要额外的操作接口。

##### (1) 附加目标

`.attach_target`接口在创建BPF迭代器时调用，用于设置附加的目标，设置为`bpf_iter_attach_map`, 实现如下：

```C
// file: kernel/bpf/map_iter.c
static int bpf_iter_attach_map(struct bpf_prog *prog,
            union bpf_iter_link_info *linfo, struct bpf_iter_aux_info *aux)
{
    u32 key_acc_size, value_acc_size, key_size, value_size;
    struct bpf_map *map;
    bool is_percpu = false;
    int err = -EINVAL;

    // `bpf_map_elem`迭代器需要指定BPF MAP
    if (!linfo->map.map_fd) return -EBADF;
    // 获取BPF MAP
    map = bpf_map_get_with_uref(linfo->map.map_fd);
    if (IS_ERR(map)) return PTR_ERR(map);

    if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
        map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
        map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
        // `PERCPU_HASH`,`LRU_PERCPU_HASH`,`PERCPU_ARRAY`类型是PERCPU类型
        is_percpu = true;
    else if (map->map_type != BPF_MAP_TYPE_HASH &&
        map->map_type != BPF_MAP_TYPE_LRU_HASH &&
        map->map_type != BPF_MAP_TYPE_ARRAY)
        // 不支持`HASH`,`LRU_HASH`,`ARRAY`类型
        goto put_map;

    key_acc_size = prog->aux->max_rdonly_access;
    value_acc_size = prog->aux->max_rdwr_access;
    // 获取key,value的占用大小
    key_size = map->key_size;
    if (!is_percpu)
        value_size = map->value_size;
    else
        value_size = round_up(map->value_size, 8) * num_possible_cpus();
    // 检查key,value的占用大小是否超过BPF程序的`max_rdonly_access`和`max_rdwr_access`
    if (key_acc_size > key_size || value_acc_size > value_size) {
        err = -EACCES;
        goto put_map;
    }
    // 辅助信息设置`map`
    aux->map = map;
    return 0;

put_map:
    bpf_map_put_with_uref(map);
    return err;
}
```

##### (2) 分离目标

`.detach_target`接口在关闭BPF迭代器时调用，用于分离附加的目标，设置为`bpf_iter_detach_map`, 实现如下：

```C
// file: kernel/bpf/map_iter.c
static void bpf_iter_detach_map(struct bpf_iter_aux_info *aux)
{
    // 释放占用的map
    bpf_map_put_with_uref(aux->map);
}
```

##### (3) 查看FD信息

`.show_fdinfo`接口在`procfs`文件系统中获取FD信息时调用，设置为`bpf_iter_map_show_fdinfo`, 实现如下：

```C
// file: kernel/bpf/map_iter.c
void bpf_iter_map_show_fdinfo(const struct bpf_iter_aux_info *aux, struct seq_file *seq)
{   
    // 打印当前的`map_id`
    seq_printf(seq, "map_id:\t%u\n", aux->map->id);
}
```

##### (4) 填充Link信息

`.fill_link_info`接口在用户空间获取BPF对象信息时(`BPF_OBJ_GET_INFO_BY_FD`命令)调用，设置为`bpf_iter_map_fill_link_info`, 实现如下：

```C
// file: kernel/bpf/map_iter.c
int bpf_iter_map_fill_link_info(const struct bpf_iter_aux_info *aux, struct bpf_link_info *info)
{
    // 填充`map_id`
    info->iter.map.map_id = aux->map->id;
    return 0;
}
```

#### 3 ARRAY_MAP迭代器的实现过程

`bpf_map_elem`迭代器没有设置`.seq_info`字段，`seq_info`信息需要从map设置中获取。

##### (1) `seq_info`的操作接口

以 `BPF_MAP_TYPE_ARRAY` 类型的map为例，设置为`iter_seq_info`，如下：

```C
// file: kernel/bpf/arraymap.c
const struct bpf_map_ops array_map_ops = {
    ...
    .iter_seq_info = &iter_seq_info,
};
```

`iter_seq_info`的定义如下：

```C
// file: kernel/bpf/arraymap.c
static const struct bpf_iter_seq_info iter_seq_info = {
    .seq_ops            = &bpf_array_map_seq_ops,
    .init_seq_private   = bpf_iter_init_array_map,
    .fini_seq_private   = bpf_iter_fini_array_map,
    .seq_priv_size      = sizeof(struct bpf_iter_seq_array_map_info),
};
```

`iter_seq_info`的私有数据是 `struct bpf_iter_seq_array_map_info` 类型的结构, 定义如下：

```C
// file: kernel/bpf/arraymap.c
struct bpf_iter_seq_array_map_info {
    struct bpf_map *map;
    void *percpu_value_buf;
    u32 index;
};
```

私有数据需要额外的初始化和清理。

###### 初始化私有数据

`.init_seq_private`接口在打开`seq`文件时调用，设置为`bpf_iter_init_array_map`，用于初始化私有数据，实现如下：

```C
// file: kernel/bpf/arraymap.c
static int bpf_iter_init_array_map(void *priv_data, struct bpf_iter_aux_info *aux)
{
    // 私有数据即`struct bpf_iter_seq_array_map_info`类型的结构
    struct bpf_iter_seq_array_map_info *seq_info = priv_data;
    struct bpf_map *map = aux->map;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    void *value_buf;
    u32 buf_size;

    // `PERCPU_ARRAY`类型的MAP，按照CPU数量分配内存空间
    if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
        buf_size = array->elem_size * num_possible_cpus();
        value_buf = kmalloc(buf_size, GFP_USER | __GFP_NOWARN);
        if (!value_buf) return -ENOMEM;

        seq_info->percpu_value_buf = value_buf;
    }
    // 增加map的使用计数，避免在迭代前或迭代中释放map
    bpf_map_inc_with_uref(map);
    seq_info->map = map;
    return 0;
}
```

###### 清理私有数据

`.fini_seq_private`接口在关闭`seq`文件时调用，设置为`bpf_iter_fini_array_map`，用于清理私有数据，实现如下：

```C
// file: kernel/bpf/arraymap.c
static void bpf_iter_fini_array_map(void *priv_data)
{
    struct bpf_iter_seq_array_map_info *seq_info = priv_data;
    // 减少使用计数，释放percpu值的内存空间
    bpf_map_put_with_uref(seq_info->map);
    kfree(seq_info->percpu_value_buf);
}
```

##### (2) `seq_ops`的操作接口

`ARRAY`类型的map迭代器的`.seq_ops`接口设置为`bpf_array_map_seq_ops`, 定义如下：

```C
// file: kernel/bpf/arraymap.c
static const struct seq_operations bpf_array_map_seq_ops = {
    .start  = bpf_array_map_seq_start,
    .next   = bpf_array_map_seq_next,
    .stop   = bpf_array_map_seq_stop,
    .show   = bpf_array_map_seq_show,
};
```

###### `.start`接口

`.start`接口在开始获取迭代目标时调用，设置为`bpf_array_map_seq_start`，实现如下：

```C
// file: kernel/bpf/arraymap.c
static void *bpf_array_map_seq_start(struct seq_file *seq, loff_t *pos)
{
    struct bpf_iter_seq_array_map_info *info = seq->private;
    struct bpf_map *map = info->map;
    struct bpf_array *array;
    u32 index;
    // `index`索引超出map的最大限制时，返回NULL
    if (info->index >= map->max_entries) return NULL;
    // 起始时，增加pos计数
    if (*pos == 0) ++*pos;

    // 获取`bpf_array`，计算索引
    array = container_of(map, struct bpf_array, map);
    index = info->index & array->index_mask;
    // `PERCPU`类型时，直接返回对应的值
    if (info->percpu_value_buf) return array->pptrs[index];
    // 非`PERCPU`类型时，返回数值中指定索引的值
    return array_map_elem_ptr(array, index);
}
```

`array_map_elem_ptr`函数获取数组中指定索引的值，实现如下：

```C
// file: kernel/bpf/arraymap.c
static void *array_map_elem_ptr(struct bpf_array* array, u32 index)
{
    return array->value + (u64)array->elem_size * index;
}
```

###### `.next`接口

`.next`接口在获取下一个迭代目标时调用，设置为`bpf_array_map_seq_next`，实现如下：

```C
// file: kernel/bpf/arraymap.c
static void *bpf_array_map_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
    struct bpf_iter_seq_array_map_info *info = seq->private;
    struct bpf_map *map = info->map;
    struct bpf_array *array;
    u32 index;
    // 增加`pos`和`index`
    ++*pos;
    ++info->index;
    // `index`索引超出map的最大限制时，返回NULL
    if (info->index >= map->max_entries) return NULL;

    // 获取`bpf_array`，计算索引
    array = container_of(map, struct bpf_array, map);
    index = info->index & array->index_mask;
    // 获取`array`中指定索引的值
    if (info->percpu_value_buf) return array->pptrs[index];
    return array_map_elem_ptr(array, index);
}
```

###### `.stop`接口

`.stop`接口在停止获取时调用，设置为`bpf_map_seq_stop`，实现如下：

```C
// file: kernel/bpf/arraymap.c
static void bpf_array_map_seq_stop(struct seq_file *seq, void *v)
{   
    // v为空表示结束，打印结束
    if (!v) (void)__bpf_array_map_seq_show(seq, NULL);
}
```

###### `.show`接口

`.show`接口在将获取的目标打印到缓冲区时调用，设置为`bpf_array_map_seq_show`，实现如下：

```C
// file: kernel/bpf/arraymap.c
static int bpf_array_map_seq_show(struct seq_file *seq, void *v)
{
    return __bpf_array_map_seq_show(seq, v);
}
```

`bpf_array_map_seq_show`函数是对`__bpf_array_map_seq_show`的调用封装，后者实现如下：

```C
// file: kernel/bpf/arraymap.c
static int __bpf_array_map_seq_show(struct seq_file *seq, void *v)
{
    struct bpf_iter_seq_array_map_info *info = seq->private;
    struct bpf_iter__bpf_map_elem ctx = {};
    struct bpf_map *map = info->map;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    struct bpf_iter_meta meta;
    struct bpf_prog *prog;
    int off = 0, cpu = 0;
    void __percpu **pptr;
    u32 size;
    
    // 初始化meta信息后，获取BPF程序
    meta.seq = seq;
    prog = bpf_iter_get_info(&meta, v == NULL);
    if (!prog) return 0;

    ctx.meta = &meta;
    ctx.map = info->map;
    if (v) {
        // 设置上下文的key和value
        ctx.key = &info->index;
        if (!info->percpu_value_buf) {
            ctx.value = v;
        } else {
            // percpu类型时，获取每个CPU的值
            pptr = v;
            size = array->elem_size;
            for_each_possible_cpu(cpu) {
                copy_map_value_long(map, info->percpu_value_buf + off, per_cpu_ptr(pptr, cpu));
                check_and_init_map_value(map, info->percpu_value_buf + off);
                off += size;
            }
            ctx.value = info->percpu_value_buf;
        }
    }
    // 运行BPF迭代器程序
    return bpf_iter_run_prog(prog, &ctx);
}
```

ARRAY_MAP迭代器的上下文用`struct bpf_iter__bpf_map_elem`表示，定义如下：

```C
// file: include/linux/bpf.h
struct bpf_iter__bpf_map_elem {
    __bpf_md_ptr(struct bpf_iter_meta *, meta);
    __bpf_md_ptr(struct bpf_map *, map);
    __bpf_md_ptr(void *, key);
    __bpf_md_ptr(void *, value);
};
```

#### 4 HASH_MAP迭代器的实现过程

##### (1) `seq_info`的操作接口

以 `BPF_MAP_TYPE_HASH` 类型的map为例，设置为`iter_seq_info`，如下：

```C
// file: kernel/bpf/hashtab.c
const struct bpf_map_ops htab_map_ops = {
    ...
    .iter_seq_info = &iter_seq_info,
};
```

`iter_seq_info`的定义如下：

```C
// file: kernel/bpf/hashtab.c
static const struct bpf_iter_seq_info iter_seq_info = {
    .seq_ops            = &bpf_hash_map_seq_ops,
    .init_seq_private   = bpf_iter_init_hash_map,
    .fini_seq_private   = bpf_iter_fini_hash_map,
    .seq_priv_size      = sizeof(struct bpf_iter_seq_hash_map_info),
};
```

`iter_seq_info`的私有数据是 `struct bpf_iter_seq_hash_map_info` 类型的结构, 定义如下：

```C
// file: kernel/bpf/hashtab.c
struct bpf_iter_seq_hash_map_info {
    struct bpf_map *map;
    struct bpf_htab *htab;
    void *percpu_value_buf; // non-zero means percpu hash
    u32 bucket_id;
    u32 skip_elems;
};
```

私有数据需要额外的初始化和清理。

###### 初始化私有数据

`.init_seq_private`接口在打开`seq`文件时调用，设置为`bpf_iter_init_hash_map`，用于初始化私有数据，实现如下：

```C
// file: kernel/bpf/hashtab.c
static int bpf_iter_init_hash_map(void *priv_data, struct bpf_iter_aux_info *aux)
{
    struct bpf_iter_seq_hash_map_info *seq_info = priv_data;
    struct bpf_map *map = aux->map;
    void *value_buf;
    u32 buf_size;

    // `PERCPU_HASH`或`LRU_PERCPU_HASH`类型的MAP，按照CPU数量分配内存空间
    if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
        map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {
        buf_size = round_up(map->value_size, 8) * num_possible_cpus();
        value_buf = kmalloc(buf_size, GFP_USER | __GFP_NOWARN);
        if (!value_buf) return -ENOMEM;

        seq_info->percpu_value_buf = value_buf;
    }

    // 增加map的使用计数，避免在迭代前或迭代中释放map
    bpf_map_inc_with_uref(map);
    // 设置seq信息，包含map和htab
    seq_info->map = map;
    seq_info->htab = container_of(map, struct bpf_htab, map);
    return 0;
}
```

###### 清理私有数据

`.fini_seq_private`接口在关闭`seq`文件时调用，设置为`bpf_iter_fini_hash_map`，用于清理私有数据，实现如下：

```C
// file: kernel/bpf/hashtab.c
static void bpf_iter_fini_hash_map(void *priv_data)
{
    struct bpf_iter_seq_hash_map_info *seq_info = priv_data;
    // 减少使用计数，释放percpu值的内存空间
    bpf_map_put_with_uref(seq_info->map);
    kfree(seq_info->percpu_value_buf);
}
```

##### (2) `seq_ops`的操作接口

`HASH`类型的map迭代器的`.seq_ops`接口设置为`bpf_hash_map_seq_ops`, 定义如下：

```C
// file: kernel/bpf/hashtab.c
static const struct seq_operations bpf_hash_map_seq_ops = {
    .start  = bpf_hash_map_seq_start,
    .next   = bpf_hash_map_seq_next,
    .stop   = bpf_hash_map_seq_stop,
    .show   = bpf_hash_map_seq_show,
};
```

###### `.start`接口

`.start`接口在开始获取迭代目标时调用，设置为`bpf_hash_map_seq_start`，实现如下：

```C
// file: kernel/bpf/hashtab.c
static void *bpf_hash_map_seq_start(struct seq_file *seq, loff_t *pos)
{
    struct bpf_iter_seq_hash_map_info *info = seq->private;
    struct htab_elem *elem;
    // 获取hash_map的中的下一个元素
    elem = bpf_hash_map_seq_find_next(info, NULL);
    if (!elem) return NULL;
    // 起始时，增加pos计数
    if (*pos == 0) ++*pos;
    return elem;
}
```

`bpf_hash_map_seq_find_next`函数获取hash_map中的下一个元素，实现如下：

```C
// file: kernel/bpf/hashtab.c
static struct htab_elem * bpf_hash_map_seq_find_next(struct bpf_iter_seq_hash_map_info *info,
                            struct htab_elem *prev_elem)
{
    const struct bpf_htab *htab = info->htab;
    u32 skip_elems = info->skip_elems;
    u32 bucket_id = info->bucket_id;
    struct hlist_nulls_head *head;
    struct hlist_nulls_node *n;
    struct htab_elem *elem;
    struct bucket *b;
    u32 i, count;
    
    // bucket超过hash数量时，返回NULL
    if (bucket_id >= htab->n_buckets) return NULL;

    if (prev_elem) {
        // 从同一个bucket中获取下一个元素
        n = rcu_dereference_raw(hlist_nulls_next_rcu(&prev_elem->hash_node));
        elem = hlist_nulls_entry_safe(n, struct htab_elem, hash_node);
        if (elem) return elem;

        // 未找到时，从下一个bucket中获取
        b = &htab->buckets[bucket_id++];
        rcu_read_unlock();
        skip_elems = 0;
    }
    // 从指定的bucket遍历
    for (i = bucket_id; i < htab->n_buckets; i++) {
        b = &htab->buckets[i];
        rcu_read_lock();
        count = 0;
        head = &b->head;
        hlist_nulls_for_each_entry_rcu(elem, n, head, hash_node) {
            if (count >= skip_elems) {
                // 获取到元素
                info->bucket_id = i;
                info->skip_elems = count;
                return elem;
            }
            count++;
        }
        rcu_read_unlock();
        skip_elems = 0;
    }
    // 未找到时，记录位置，返回NULL
    info->bucket_id = i;
    info->skip_elems = 0;
    return NULL;
}
```

###### `.next`接口

`.next`接口在获取下一个迭代目标时调用，设置为`bpf_hash_map_seq_next`，实现如下：

```C
// file: kernel/bpf/hashtab.c
static void *bpf_hash_map_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
    struct bpf_iter_seq_hash_map_info *info = seq->private;
    // 增加`pos`和`skip_elems`计数
    ++*pos;
    ++info->skip_elems;
    // 获取hash_map的下一个元素
    return bpf_hash_map_seq_find_next(info, v);
}
```

###### `.stop`接口

`.stop`接口在停止获取时调用，设置为`bpf_hash_map_seq_stop`，实现如下：

```C
// file: kernel/bpf/hashtab.c
static void bpf_hash_map_seq_stop(struct seq_file *seq, void *v)
{
    // v为空表示结束，打印结束
    if (!v) 
        (void)__bpf_hash_map_seq_show(seq, NULL);
    else 
        rcu_read_unlock();
}
```

###### `.show`接口

`.show`接口在将获取的目标打印到缓冲区时调用，设置为`bpf_hash_map_seq_show`，实现如下：

```C
// file: kernel/bpf/hashtab.c
static int bpf_hash_map_seq_show(struct seq_file *seq, void *v)
{
    return __bpf_hash_map_seq_show(seq, v);
}
```

`bpf_hash_map_seq_show`函数是对`__bpf_hash_map_seq_show`的调用封装，后者实现如下：

```C
// file: kernel/bpf/hashtab.c
static int __bpf_hash_map_seq_show(struct seq_file *seq, struct htab_elem *elem)
{
    struct bpf_iter_seq_hash_map_info *info = seq->private;
    u32 roundup_key_size, roundup_value_size;
    struct bpf_iter__bpf_map_elem ctx = {};
    struct bpf_map *map = info->map;
    struct bpf_iter_meta meta;
    int ret = 0, off = 0, cpu;
    struct bpf_prog *prog;
    void __percpu *pptr;

    // 初始化meta信息后，获取BPF程序
    meta.seq = seq;
    prog = bpf_iter_get_info(&meta, elem == NULL);

    if (prog) {
        ctx.meta = &meta;
        ctx.map = info->map;
        if (elem) {
            // 计算key的占用大小，按8字节对齐
            roundup_key_size = round_up(map->key_size, 8);
            // 设置key
            ctx.key = elem->key;
            // 设置value
            if (!info->percpu_value_buf) {
                ctx.value = elem->key + roundup_key_size;
            } else {
                // percpu类型时，获取每个CPU的值
                roundup_value_size = round_up(map->value_size, 8);
                pptr = htab_elem_get_ptr(elem, map->key_size);
                for_each_possible_cpu(cpu) {
                    bpf_long_memcpy(info->percpu_value_buf + off, 
                        per_cpu_ptr(pptr, cpu), roundup_value_size);
                    off += roundup_value_size;
                }
                ctx.value = info->percpu_value_buf;
            }
        }
        // 运行BPF迭代器程序
        ret = bpf_iter_run_prog(prog, &ctx);
    }
    return ret;
}
```

HASH_MAP迭代器的上下文用`struct bpf_iter__bpf_map_elem`表示，定义如下：

```C
// file: include/linux/bpf.h
struct bpf_iter__bpf_map_elem {
    __bpf_md_ptr(struct bpf_iter_meta *, meta);
    __bpf_md_ptr(struct bpf_map *, map);
    __bpf_md_ptr(void *, key);
    __bpf_md_ptr(void *, value);
};
```

#### 5 其他类型的迭代器

除此之外，`SOCKMAP`和`SOCKHASH`类型的MAP也是通过类似的方式实现的，其定义如下，略过分析过程。

```C
// file: net/core/sock_map.c
static const struct bpf_iter_seq_info sock_map_iter_seq_info = {
    .seq_ops            = &sock_map_seq_ops,
    .init_seq_private   = sock_map_init_seq_private,
    .fini_seq_private   = sock_map_fini_seq_private,
    .seq_priv_size      = sizeof(struct sock_map_seq_info),
};
const struct bpf_map_ops sock_map_ops = {
    ...
    .iter_seq_info  = &sock_map_iter_seq_info,
};

// file: net/core/sock_map.c
static const struct bpf_iter_seq_info sock_hash_iter_seq_info = {
    .seq_ops            = &sock_hash_seq_ops,
    .init_seq_private   = sock_hash_init_seq_private,
    .fini_seq_private   = sock_hash_fini_seq_private,
    .seq_priv_size      = sizeof(struct sock_hash_seq_info),
};
const struct bpf_map_ops sock_hash_ops = {
    ...
    .iter_seq_info  = &sock_hash_iter_seq_info,
};
```

### 4.7 `task`迭代器的实现

#### 1 注册过程

`task`迭代器的注册信息在内核中使用`task_reg_info`表示，定义如下：

```C
// file: kernel/bpf/task_iter.c
static struct bpf_iter_reg task_reg_info = {
    .target             = "task",
    .attach_target      = bpf_iter_attach_task,
    .feature            = BPF_ITER_RESCHED,
    .ctx_arg_info_size  = 1,
    .ctx_arg_info       = {
        { offsetof(struct bpf_iter__task, task), PTR_TO_BTF_ID_OR_NULL },
    },
    .seq_info       = &task_seq_info,
    .fill_link_info = bpf_iter_fill_link_info,
    .show_fdinfo    = bpf_iter_task_show_fdinfo,
};
```

在`initcall`阶段注册到内核中，如下：

```C
// file: kernel/bpf/task_iter.c
static int __init task_iter_init(void)
{
    struct mmap_unlock_irq_work *work;
    int ret, cpu;

    for_each_possible_cpu(cpu) {
        work = per_cpu_ptr(&mmap_unlock_work, cpu);
        init_irq_work(&work->irq_work, do_mmap_read_unlock);
    }
    // 注册`task`迭代器目标
    task_reg_info.ctx_arg_info[0].btf_id = btf_tracing_ids[BTF_TRACING_TYPE_TASK];
    ret = bpf_iter_reg_target(&task_reg_info);
    if (ret) return ret;

    // 注册`task_file`迭代器目标
    task_file_reg_info.ctx_arg_info[0].btf_id = btf_tracing_ids[BTF_TRACING_TYPE_TASK];
    task_file_reg_info.ctx_arg_info[1].btf_id = btf_tracing_ids[BTF_TRACING_TYPE_FILE];
    ret =  bpf_iter_reg_target(&task_file_reg_info);
    if (ret) return ret;

    // 注册`task_vma`迭代器目标
    task_vma_reg_info.ctx_arg_info[0].btf_id = btf_tracing_ids[BTF_TRACING_TYPE_TASK];
    task_vma_reg_info.ctx_arg_info[1].btf_id = btf_tracing_ids[BTF_TRACING_TYPE_VMA];
    return bpf_iter_reg_target(&task_vma_reg_info);
}
late_initcall(task_iter_init);
```

#### 2 迭代器的操作接口

`task`迭代器获取内核中所有的任务信息，用户可以指定筛选条件。

##### (1) 附加目标

`.attach_target`接口在创建BPF迭代器时调用，用于设置附加的目标，设置为`bpf_iter_attach_task`, 实现如下：

```C
// file: kernel/bpf/task_iter.c
static int bpf_iter_attach_task(struct bpf_prog *prog,
            union bpf_iter_link_info *linfo, struct bpf_iter_aux_info *aux)
{
    unsigned int flags;
    struct pid *pid;
    pid_t tgid;
    // `tid`,`pid`,`pid_fd`最多指定一个
    if ((!!linfo->task.tid + !!linfo->task.pid + !!linfo->task.pid_fd) > 1)
        return -EINVAL;
    
    // 默认筛选全部的任务
    aux->task.type = BPF_TASK_ITER_ALL;
    
    // 指定tid时，按tid筛选
    if (linfo->task.tid != 0) {
        aux->task.type = BPF_TASK_ITER_TID;
        aux->task.pid = linfo->task.tid;
    }
    // 指定pid时，按pid筛选
    if (linfo->task.pid != 0) {
        aux->task.type = BPF_TASK_ITER_TGID;
        aux->task.pid = linfo->task.pid;
    }
    // 指定pid_fd时，按tgid筛选
    if (linfo->task.pid_fd != 0) {
        aux->task.type = BPF_TASK_ITER_TGID;
        pid = pidfd_get_pid(linfo->task.pid_fd, &flags);
        if (IS_ERR(pid)) return PTR_ERR(pid);
        tgid = pid_nr_ns(pid, task_active_pid_ns(current));
        aux->task.pid = tgid;
        put_pid(pid);
    }
    return 0;
}
```

##### (2) 查看FD信息

`.show_fdinfo`接口在`procfs`文件系统中获取FD信息时调用，设置为`bpf_iter_task_show_fdinfo`, 实现如下：

```C
// file: kernel/bpf/task_iter.c
static void bpf_iter_task_show_fdinfo(const struct bpf_iter_aux_info *aux, struct seq_file *seq)
{
    // 打印筛选类型
    seq_printf(seq, "task_type:\t%s\n", iter_task_type_names[aux->task.type]);
    // 打印tid或者pid
    if (aux->task.type == BPF_TASK_ITER_TID)
        seq_printf(seq, "tid:\t%u\n", aux->task.pid);
    else if (aux->task.type == BPF_TASK_ITER_TGID)
        seq_printf(seq, "pid:\t%u\n", aux->task.pid);
}
```

##### (3) 填充Link信息

`.fill_link_info`接口在用户空间获取BPF对象信息时(`BPF_OBJ_GET_INFO_BY_FD`命令)调用，设置为`bpf_iter_fill_link_info`, 实现如下：

```C
// file: kernel/bpf/task_iter.c
static int bpf_iter_fill_link_info(const struct bpf_iter_aux_info *aux, struct bpf_link_info *info)
{
    // 设置tid或者pid
    switch (aux->task.type) {
    case BPF_TASK_ITER_TID: info->iter.task.tid = aux->task.pid; break;
    case BPF_TASK_ITER_TGID: info->iter.task.pid = aux->task.pid; break;
    default: break;
    }
    return 0;
}
```

#### 3 `seq_info`的操作接口

`task`迭代器的`.seq_info`字段设置为`task_seq_info`，定义如下：

```C
// file: kernel/bpf/task_iter.c
static const struct bpf_iter_seq_info task_seq_info = {
    .seq_ops            = &task_seq_ops,
    .init_seq_private   = init_seq_pidns,
    .fini_seq_private   = fini_seq_pidns,
    .seq_priv_size      = sizeof(struct bpf_iter_seq_task_info),
};
```

`task_seq_info`的私有数据是`struct bpf_iter_seq_task_info`类型的结构, 定义如下：

```C
// file: kernel/bpf/task_iter.c
struct bpf_iter_seq_task_info {
    struct bpf_iter_seq_task_common common;
    u32 tid;
};
```

私有数据需要额外的初始化和清理。

##### 初始化私有数据

`.init_seq_private`接口在打开`seq`文件时调用，设置为`init_seq_pidns`，用于初始化命名空间，实现如下：

```C
// file: kernel/bpf/task_iter.c
static int init_seq_pidns(void *priv_data, struct bpf_iter_aux_info *aux)
{
    struct bpf_iter_seq_task_common *common = priv_data;
    // 获取pid的命名空间，设置筛选类型和id
    common->ns = get_pid_ns(task_active_pid_ns(current));
    common->type = aux->task.type;
    common->pid = aux->task.pid;
    return 0;
}
```

##### 清理私有数据

`.fini_seq_private`接口在关闭`seq`文件时调用，设置为`fini_seq_pidns`，用于释放命名空间，实现如下：

```C
// file: kernel/bpf/task_iter.c
static void fini_seq_pidns(void *priv_data)
{
    struct bpf_iter_seq_task_common *common = priv_data;
    // 释放pid的命名空间
    put_pid_ns(common->ns);
}
```

#### 4 `seq_ops`的操作接口

`task`迭代器的`.seq_ops`接口设置为`task_seq_ops`, 定义如下：

```C
// file: kernel/bpf/task_iter.c
static const struct seq_operations task_seq_ops = {
    .start  = task_seq_start,
    .next   = task_seq_next,
    .stop   = task_seq_stop,
    .show   = task_seq_show,
};
```

##### `.start`接口

`.start`接口在开始获取迭代目标时调用，设置为`task_seq_start`，实现如下：

```C
// file: kernel/bpf/task_iter.c
static void *task_seq_start(struct seq_file *seq, loff_t *pos)
{
    struct bpf_iter_seq_task_info *info = seq->private;
    struct task_struct *task;
    // 获取下一个`task`
    task = task_seq_get_next(&info->common, &info->tid, false);
    if (!task) return NULL;

    // 起始时，增加pos计数
    if (*pos == 0) ++*pos;
    return task;
}
```

`task_seq_get_next`函数根据筛选信息获取下一个`task`，实现如下：

```C
// file: kernel/bpf/task_iter.c
static struct task_struct *task_seq_get_next(struct bpf_iter_seq_task_common *common,
                u32 *tid, bool skip_if_dup_files)
{
    struct task_struct *task = NULL;
    struct pid *pid;

    // 按照`TID`筛选
    if (common->type == BPF_TASK_ITER_TID) {
        // `tid`不是上一个查询的pid时，返回NULL
        if (*tid && *tid != common->pid) return NULL;
        rcu_read_lock();
        // 从命名空间中获取下一个pid
        pid = find_pid_ns(common->pid, common->ns);
        if (pid) {
            // 存在pid时，获取`task`结构，设置查询的pid
            task = get_pid_task(pid, PIDTYPE_TGID);
            *tid = common->pid;
        }
        rcu_read_unlock();
        return task;
    }
    // 按照`TGID`筛选
    if (common->type == BPF_TASK_ITER_TGID) {
        rcu_read_lock();
        // 按照组获取下一个`task`
        task = task_group_seq_get_next(common, tid, skip_if_dup_files);
        rcu_read_unlock();
        return task;
    }
    // 未设置筛选条件时，获取所有的任务
    rcu_read_lock();
retry:
    // 从命名空间中获取下一个pid
    pid = find_ge_pid(*tid, common->ns);
    if (pid) {
        // 获取`tid`和`task`
        *tid = pid_nr_ns(pid, common->ns);
        task = get_pid_task(pid, PIDTYPE_PID);
        if (!task) {
            // 获取失败时，增加`tid`后重新获取
            ++*tid;
            goto retry;
        } else if (skip_if_dup_files && !thread_group_leader(task) &&
                task->files == task->group_leader->files) {
            // 不是进程时，重新获取
            put_task_struct(task);
            task = NULL;
            ++*tid;
            goto retry;
        }
    }
    rcu_read_unlock();
    // 返回`task`信息
    return task;
}
```

##### `.next`接口

`.next`接口在获取下一个迭代目标时调用，设置为`task_seq_next`，实现如下：

```C
// file: kernel/bpf/task_iter.c
static void *task_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
    struct bpf_iter_seq_task_info *info = seq->private;
    struct task_struct *task;
    // 增加`pos`和`tid`
    ++*pos;
    ++info->tid;
    // 释放上一个`task`的占用
    put_task_struct((struct task_struct *)v);
    // 获取下一个`task`
    task = task_seq_get_next(&info->common, &info->tid, false);
    if (!task) return NULL;
    return task;
}
```

##### `.stop`接口

`.stop`接口在停止获取时调用，设置为`task_seq_stop`，实现如下：

```C
// file: kernel/bpf/task_iter.c
static void task_seq_stop(struct seq_file *seq, void *v)
{
    // `v`为空，表示读取完毕，否则释放task的占用
    if (!v) 
        (void)__task_seq_show(seq, v, true);
    else 
        put_task_struct((struct task_struct *)v);
}
```

##### `.show`接口

`.show`接口在将获取的目标打印到缓冲区时调用，设置为`task_seq_show`，实现如下：

```C
// file: kernel/bpf/task_iter.c
static int task_seq_show(struct seq_file *seq, void *v)
{
    return __task_seq_show(seq, v, false);
}
```

`task_seq_show`函数是对`__task_seq_show`的调用封装，后者实现如下：

```C
// file: kernel/bpf/task_iter.c
static int __task_seq_show(struct seq_file *seq, struct task_struct *task, bool in_stop)
{
    struct bpf_iter_meta meta;
    struct bpf_iter__task ctx;
    struct bpf_prog *prog;

    meta.seq = seq;
    // 获取BPF程序
    prog = bpf_iter_get_info(&meta, in_stop);
    if (!prog) return 0;

    // 设置BPF迭代器上下文
    ctx.meta = &meta;
    ctx.task = task;
    // 运行BPF迭代器程序
    return bpf_iter_run_prog(prog, &ctx);
}
```

`task`迭代器的上下文用`struct bpf_iter__task`表示，定义如下：

```C
// file: kernel/bpf/task_iter.c
struct bpf_iter__task {
    __bpf_md_ptr(struct bpf_iter_meta *, meta);
    __bpf_md_ptr(struct task_struct *, task);
};
```

### 4.8 其他迭代器的实现

其他类型的迭代器实现过程和`task`迭代器类似，略过分析过程。

## 5 总结

本文通过`bpf_iter`示例程序分析了`bpf_map`,`bpf_map_elem`,`task`等BPF迭代器的内核实现过程。通过BPF迭代器可以从用户空间灵活的遍历内核数据，自定义内核数据的输出格式。

## 参考资料

* [BPF Iterators](https://docs.kernel.org/bpf/bpf_iterators.html)
* [BPF 迭代器：以灵活和高效的方式检索内核数据结构](https://www.ebpf.top/post/bpf-iterator-retrieving-kernel-data-with-flexibility-and-efficiency/)