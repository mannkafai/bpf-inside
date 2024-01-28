# UPROBE.MULTI的内核实现

## 0 前言

在[UPROBE的内核实现](./07-uprobe.md)，我们分析了`uprobes`和`usdt`的实现过程，实现对用户空间的程序进行追踪，一次追踪使用对应一个BPF程序，在对多个同类型函数追踪时使用同样的BPF程序功能时，需要创建多个Link。现在借助`UPROBE.MULTI`可以实现追踪多个函数时使用同一个BPF_LINK。我们基于`uprobe_multi`程序分析`UPROBE.MULTI`的实现过程。

## 1 简介

`u[ret]probe.multi` 支持在单个系统调用中附加多个uprobe，提升了附加多个uprobes的速度。

## 2 `uprobe_multi`示例程序

### 2.1 BPF程序

BPF程序源码参见[uprobe_multi.bpf.c](../src/uprobe_multi.bpf.c)，主要内容如下：

```C
SEC("uprobe.multi//proc/self/exe:uprobe_multi_func_*")
int uprobe(struct pt_regs *ctx)
{
    uprobe_multi_check(ctx, false, false);
    return 0;
}
SEC("uretprobe.multi//proc/self/exe:uprobe_multi_func_*")
int uretprobe(struct pt_regs *ctx)
{
    uprobe_multi_check(ctx, true, false);
    return 0;
}
SEC("uprobe.multi.s//proc/self/exe:uprobe_multi_func_*")
int uprobe_sleep(struct pt_regs *ctx)
{
    uprobe_multi_check(ctx, false, true);
    return 0;
}
SEC("uretprobe.multi.s//proc/self/exe:uprobe_multi_func_*")
int uretprobe_sleep(struct pt_regs *ctx)
{
    uprobe_multi_check(ctx, true, true);
    return 0;
}
```

该程序包括多个BPF程序，使用 `uprobe.multi` 和 `uretprobe.multi` 前缀。

### 2.2 用户程序

用户程序源码参见[uprobe_multi.c](../src/uprobe_multi.c)，主要内容如下：

#### 1 附加BPF程序

```C
static void
test_attach_api(const char *binary, const char *pattern, struct bpf_uprobe_multi_opts *opts, struct child *child)
{
    pid_t pid = child ? child->pid : -1;
    struct uprobe_multi_bpf *skel = NULL;
    // 打开并加载BPF程序
    skel = uprobe_multi_bpf__open_and_load();
    if (!ASSERT_OK_PTR(skel, "uprobe_multi_bpf__open_and_load")) goto cleanup;
    // 手动附加BPF程序
    opts->retprobe = false;
    skel->links.uprobe = bpf_program__attach_uprobe_multi(skel->progs.uprobe, pid, binary, pattern, opts);
    if (!ASSERT_OK_PTR(skel->links.uprobe, "bpf_program__attach_uprobe_multi")) goto cleanup;
    opts->retprobe = true;
    skel->links.uretprobe = bpf_program__attach_uprobe_multi(skel->progs.uretprobe, pid, binary, pattern, opts);
    if (!ASSERT_OK_PTR(skel->links.uretprobe, "bpf_program__attach_uprobe_multi")) goto cleanup;
    ...

    // 执行用户空间程序触发
    uprobe_multi_test_run(skel, child);
cleanup:
    // 销毁BPF程序
    uprobe_multi_bpf__destroy(skel);
}

int main(int argc, char **argv)
{
    // 设置 libbpf 调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);
    LIBBPF_OPTS(bpf_uprobe_multi_opts, opts);
    const char *syms[3] = {
        "uprobe_multi_func_1",
        "uprobe_multi_func_2",
        "uprobe_multi_func_3",
    };
    // 设置附加`uprobe.multi`的选项
    opts.syms = syms;
    opts.cnt = ARRAY_SIZE(syms);
    test_attach_api("/proc/self/exe", NULL, &opts, NULL);
    return 0;
}
```

#### 2 读取数据过程

BPF程序将采集的数据通过全局变量输出。

### 2.3 编译运行

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make uprobe_multi 
$ sudo ./uprobe_multi 
libbpf: loading object 'uprobe_multi_bpf' from buffer
...
libbpf: map '.rodata.str1.1': created successfully, fd=4
libbpf: prog 'uprobe': failed to attach multi-uprobe: Invalid argument
...
```

由于`uprobe.multi`在Linux v6.6内核中添加的，目前使用的是Linux v6.5，因此运行失败。

## 3 uprobe_multi附加BPF的过程

`uprobe_multi.bpf.c`文件中BPF程序的SEC名称分别为 `SEC("uprobe.multi/")` 和 `SEC("uretprobe.multi/")`, 在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("uprobe.multi+", KPROBE, BPF_TRACE_UPROBE_MULTI, SEC_NONE, attach_uprobe_multi),
    SEC_DEF("uretprobe.multi+", KPROBE, BPF_TRACE_UPROBE_MULTI, SEC_NONE, attach_uprobe_multi),
    SEC_DEF("uprobe.multi.s+", KPROBE, BPF_TRACE_UPROBE_MULTI, SEC_SLEEPABLE, attach_uprobe_multi),
    SEC_DEF("uretprobe.multi.s+", KPROBE, BPF_TRACE_UPROBE_MULTI, SEC_SLEEPABLE, attach_uprobe_multi),
    ...
};
```

`uprobe.multi` 和 `uretprobe.multi` 都是通过 `attach_uprobe_multi` 函数进行附加的。用户可通过 `bpf_program__attach_uprobe_multi` 手动附加。

`attach_uprobe_multi` 在解析SEC名称中`pattern`后，调用 `bpf_program__attach_uprobe_multi` 函数完成剩余的工作。实现过程如下：

```C
// file: libbpf/src/libbpf.c
static int attach_uprobe_multi(const struct bpf_program *prog, long cookie, struct bpf_link **link)
{
    char *probe_type = NULL, *binary_path = NULL, *func_name = NULL;
    LIBBPF_OPTS(bpf_uprobe_multi_opts, opts);
    int n, ret = -EINVAL;

    *link = NULL;
    // 解析`sec`名称对应的`probe_type`,`binary_path`,`func_name`字段
    n = sscanf(prog->sec_name, "%m[^/]/%m[^:]:%m[^\n]", &probe_type, &binary_path, &func_name);
    switch (n) {
    case 1:
        // 处理 SEC("u[ret]probe.multi")，格式正确，但不支持自动附加BPF程序
        ret = 0;
        break;
    case 3:
        // 格式正确，自动附加BPF程序
        opts.retprobe = strcmp(probe_type, "uretprobe.multi") == 0;
        *link = bpf_program__attach_uprobe_multi(prog, -1, binary_path, func_name, &opts);
        ret = libbpf_get_error(*link);
        break;
    default:
        // 格式不正确
        pr_warn("prog '%s': invalid format of section definition '%s'\n", prog->name, prog->sec_name);
        break;
    }
    free(probe_type);
    free(binary_path);
    free(func_name);
    return ret;
}
```

`bpf_program__attach_uprobe_multi` 函数检查opts参数和`pattern`的兼容性，存在`pattern`时解析符号在用户空间中的地址，设置link属性后，调用`bpf_link_create`函数进行实际的创建，如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link *
bpf_program__attach_uprobe_multi(const struct bpf_program *prog, pid_t pid, const char *path, 
    const char *func_pattern, const struct bpf_uprobe_multi_opts *opts)
{
    const unsigned long *ref_ctr_offsets = NULL, *offsets = NULL;
    LIBBPF_OPTS(bpf_link_create_opts, lopts);
    ...

    if (!OPTS_VALID(opts, bpf_uprobe_multi_opts)) return libbpf_err_ptr(-EINVAL);

    // 获取opts设置的参数
    syms = OPTS_GET(opts, syms, NULL);
    offsets = OPTS_GET(opts, offsets, NULL);
    ref_ctr_offsets = OPTS_GET(opts, ref_ctr_offsets, NULL);
    cookies = OPTS_GET(opts, cookies, NULL);
    cnt = OPTS_GET(opts, cnt, 0);

    // opts参数和pattern兼容性检查
    if (!path) return libbpf_err_ptr(-EINVAL);
    if (!func_pattern && cnt == 0) return libbpf_err_ptr(-EINVAL);
    if (func_pattern) {
        if (syms || offsets || ref_ctr_offsets || cookies || cnt)
            return libbpf_err_ptr(-EINVAL);
    } else {
        if (!!syms == !!offsets) return libbpf_err_ptr(-EINVAL);
    }

    if (func_pattern) {
        // 路径中不存在`/`时，解析全路径
        if (!strchr(path, '/')) {
            err = resolve_full_path(path, full_path, sizeof(full_path));
            if (err) { ... }
            path = full_path;
        }
        // 根据函数通配符解析偏移量
        err = elf_resolve_pattern_offsets(path, func_pattern, &resolved_offsets, &cnt);
        if (err < 0) return libbpf_err_ptr(err);
        offsets = resolved_offsets;
    } else if (syms) {
        // 根据设置的函数名称解析偏移量
        err = elf_resolve_syms_offsets(path, cnt, syms, &resolved_offsets, STT_FUNC);
        if (err < 0) return libbpf_err_ptr(err);
        offsets = resolved_offsets;
    }

    // 设置`uprobe_multi`属性
    lopts.uprobe_multi.path = path;
    lopts.uprobe_multi.offsets = offsets;
    lopts.uprobe_multi.ref_ctr_offsets = ref_ctr_offsets;
    lopts.uprobe_multi.cookies = cookies;
    lopts.uprobe_multi.cnt = cnt;
    lopts.uprobe_multi.flags = OPTS_GET(opts, retprobe, false) ? BPF_F_UPROBE_MULTI_RETURN : 0;

    // pid设置
    if (pid == 0) pid = getpid();
    if (pid > 0) lopts.uprobe_multi.pid = pid;

    // 创建link，设置分离接口
    link = calloc(1, sizeof(*link));
    if (!link) { ... }
    link->detach = &bpf_link__detach_fd;

    // 获取bpf程序fd后，创建link
    prog_fd = bpf_program__fd(prog);
    link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &lopts);
    if (link_fd < 0) { ... }
    link->fd = link_fd;
    // 释放解析的地址信息
    free(resolved_offsets);
    return link;

error:
    // 错误时清理
    free(resolved_offsets);
    free(link);
    return libbpf_err_ptr(err);
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
    case BPF_TRACE_UPROBE_MULTI:
        // 设置`uprobe_multi`属性
        attr.link_create.uprobe_multi.flags = OPTS_GET(opts, uprobe_multi.flags, 0);
        attr.link_create.uprobe_multi.cnt = OPTS_GET(opts, uprobe_multi.cnt, 0);
        attr.link_create.uprobe_multi.path = ptr_to_u64(OPTS_GET(opts, uprobe_multi.path, 0));
        attr.link_create.uprobe_multi.offsets = ptr_to_u64(OPTS_GET(opts, uprobe_multi.offsets, 0));
        attr.link_create.uprobe_multi.ref_ctr_offsets = ptr_to_u64(OPTS_GET(opts, uprobe_multi.ref_ctr_offsets, 0));
        attr.link_create.uprobe_multi.cookies = ptr_to_u64(OPTS_GET(opts, uprobe_multi.cookies, 0));
        attr.link_create.uprobe_multi.pid = OPTS_GET(opts, uprobe_multi.pid, 0);
        if (!OPTS_ZEROED(opts, uprobe_multi)) return libbpf_err(-EINVAL);
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

`link_create` 在检查BFP程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 `uprobe.multi` 和 `uretprobe.multi` 设置的程序类型为`BPF_PROG_TYPE_KPROBE`, 附加类型为`BPF_TRACE_UPROBE_MULTI`, 对应 `bpf_uprobe_multi_link_attach` 处理函数。如下：

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
    case BPF_PROG_TYPE_KPROBE:
        if (attr->link_create.attach_type == BPF_PERF_EVENT)
            ret = bpf_perf_link_attach(attr, prog);
        else if (attr->link_create.attach_type == BPF_TRACE_KPROBE_MULTI)
            ret = bpf_kprobe_multi_link_attach(attr, prog);
        else if (attr->link_create.attach_type == BPF_TRACE_UPROBE_MULTI)
            // uprobe_multi_link处理
            ret = bpf_uprobe_multi_link_attach(attr, prog);
        break;
    ...
    }
    ...
}
```

#### 3 `bpf_uprobe_multi_link_attach`

`bpf_uprobe_multi_link_attach` 函数检查用户输入的参数信息，使用输入的地址设置 `multi_link` 的信息后，逐个注册`uprobe`探测事件。如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_uprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    struct bpf_uprobe_multi_link *link = NULL;
    unsigned long __user *uref_ctr_offsets;
    unsigned long *ref_ctr_offsets = NULL;
    struct bpf_link_primer link_primer;
    struct bpf_uprobe *uprobes = NULL;
    ...

    // `uprobe_multi` 不支持32位系统
    if (sizeof(u64) != sizeof(void *)) return -EOPNOTSUPP;

    if (prog->expected_attach_type != BPF_TRACE_UPROBE_MULTI) return -EINVAL;

    // 用户参数检查，只支持 `UPROBE_MULTI_RETURN` 标记设置
    flags = attr->link_create.uprobe_multi.flags;
    if (flags & ~BPF_F_UPROBE_MULTI_RETURN) return -EINVAL;

    // 用户参数参数检查，`upath`和`uoffsets`必须设置，数量必须 > 0
    upath = u64_to_user_ptr(attr->link_create.uprobe_multi.path);
    uoffsets = u64_to_user_ptr(attr->link_create.uprobe_multi.offsets);
    cnt = attr->link_create.uprobe_multi.cnt;
    if (!upath || !uoffsets || !cnt) return -EINVAL;
    // `ref_ctr_offsets`和`cookies`参数
    uref_ctr_offsets = u64_to_user_ptr(attr->link_create.uprobe_multi.ref_ctr_offsets);
    ucookies = u64_to_user_ptr(attr->link_create.uprobe_multi.cookies);

    // 查找用户空间设置的文件路径
    name = strndup_user(upath, PATH_MAX);
    if (IS_ERR(name)) { ... }
    err = kern_path(name, LOOKUP_FOLLOW, &path);
    kfree(name);
    if (err) return err;
    // 文件类型确定是普通文件
    if (!d_is_reg(path.dentry)) { ... }

    // 指定`pid`时，获取`pid`对应的task
    pid = attr->link_create.uprobe_multi.pid;
    if (pid) {
        rcu_read_lock();
        task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
        rcu_read_unlock();
        if (!task) { ... }
    }

    err = -ENOMEM;
    // 创建 link
    link = kzalloc(sizeof(*link), GFP_KERNEL);
    // 创建 `uprobes`
    uprobes = kvcalloc(cnt, sizeof(*uprobes), GFP_KERNEL);
    if (!uprobes || !link) goto error_free;

    // 复制`ref_ctr_offsets`信息到内核空间
    if (uref_ctr_offsets) {
        ref_ctr_offsets = kvcalloc(cnt, sizeof(*ref_ctr_offsets), GFP_KERNEL);
        if (!ref_ctr_offsets) goto error_free;
    }

    for (i = 0; i < cnt; i++) {
        // 设置`uprobes[i]`的`cookie`,`offset`等属性
        if (ucookies && __get_user(uprobes[i].cookie, ucookies + i)) { ...	}
        if (uref_ctr_offsets && __get_user(ref_ctr_offsets[i], uref_ctr_offsets + i)) { ...	}
        if (__get_user(uprobes[i].offset, uoffsets + i)) { ...	}
        // 设置`link`
        uprobes[i].link = link;

        // 设置`uprobes[i]`的`handler`,`filter`等处理接口
        if (flags & BPF_F_UPROBE_MULTI_RETURN)
            uprobes[i].consumer.ret_handler = uprobe_multi_link_ret_handler;
        else
            uprobes[i].consumer.handler = uprobe_multi_link_handler;
        if (pid)
            uprobes[i].consumer.filter = uprobe_multi_link_filter;
    }
    // 设置`link`属性
    link->cnt = cnt;
    link->uprobes = uprobes;
    link->path = path;
    link->task = task;

    bpf_link_init(&link->link, BPF_LINK_TYPE_UPROBE_MULTI, &bpf_uprobe_multi_link_lops, prog);

    for (i = 0; i < cnt; i++) {
        // 逐个注册`uprobe`
        err = uprobe_register_refctr(d_real_inode(link->path.dentry), uprobes[i].offset,
                            ref_ctr_offsets ? ref_ctr_offsets[i] : 0, &uprobes[i].consumer);
        if (err) {
            bpf_uprobe_unregister(&path, uprobes, i);
            goto error_free;
        }
    }

    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    if (err) goto error_free;

    kvfree(ref_ctr_offsets);
    // fd 和 file 进行关联
    return bpf_link_settle(&link_primer);
    // 失败时的清理
error_free:
    kvfree(ref_ctr_offsets);
    kvfree(uprobes);
    kfree(link);
    if (task) put_task_struct(task);
error_path_put:
    path_put(&path);
    return err;
}
```

`uprobe_register_refctr`函数注册`uprobe`，其实现过程参见[UPROBE的内核实现](./07-uprobe.md#1-注册过程)中注册过程章节。

### 4.2 注销BPF程序的过程

#### 1 `bpf_uprobe_multi_link_lops`接口

在`bpf_uprobe_multi_link_attach`函数附加link过程中，设置了用户空间操作`bpf_link`的文件接口，如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_uprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_UPROBE_MULTI, &bpf_uprobe_multi_link_lops, prog);
    ...
    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    ...
}
```

`bpf_uprobe_multi_link_lops` 是设置的文件操作接口，定义如下：

```C
// file: kernel/trace/bpf_trace.c
static const struct bpf_link_ops bpf_uprobe_multi_link_lops = {
    .release = bpf_uprobe_multi_link_release,
    .dealloc = bpf_uprobe_multi_link_dealloc,
};
```

#### 2 注销接口

`.release`接口释放`bpf_link`关联的程序。`bpf_uprobe_multi_link_release`注销`uprobes`，如下：

```C
// file: kernel/trace/bpf_trace.c
static void bpf_uprobe_multi_link_release(struct bpf_link *link)
{
    struct bpf_uprobe_multi_link *umulti_link;

    umulti_link = container_of(link, struct bpf_uprobe_multi_link, link);
    bpf_uprobe_unregister(&umulti_link->path, umulti_link->uprobes, umulti_link->cnt);
}
```

`bpf_uprobe_unregister`函数注销`umulti_link`设置的`uprobes`，如下：

```C
// file: kernel/trace/bpf_trace.c
static void bpf_uprobe_unregister(struct path *path, struct bpf_uprobe *uprobes, u32 cnt)
{
    u32 i;
    for (i = 0; i < cnt; i++) {
        uprobe_unregister(d_real_inode(path->dentry), uprobes[i].offset, &uprobes[i].consumer);
    }
}
```

`uprobe_unregister`函数注销`uprobe`，其实现过程参见[UPROBE的内核实现](./07-uprobe.md#2-注销过程)中注销过程章节。

#### 3 释放接口

`.dealloc`接口释放`bpf_link`。`bpf_uprobe_multi_link_dealloc`释放`umulti_link`，如下：

```C
// file: kernel/trace/bpf_trace.c
static void bpf_uprobe_multi_link_dealloc(struct bpf_link *link)
{
    struct bpf_uprobe_multi_link *umulti_link;
    umulti_link = container_of(link, struct bpf_uprobe_multi_link, link);
    // 释放`umulti_link`的`task`,`path`,`uprobes`后，释放`umulti_link`
    if (umulti_link->task)
        put_task_struct(umulti_link->task);
    path_put(&umulti_link->path);
    kvfree(umulti_link->uprobes);
    kfree(umulti_link);
}
```

### 4.3 BPF调用过程

#### 1 UPROBE的触发过程

UPROBE通过设置断点的方式触发中断，在`x86`架构下通过`INT3`中断实现。具体的实现过程参见[UPROBE的内核实现](./07-uprobe.md#45-uprobe的触发过程)中触发过程章节。

#### 2 `uprobe_multi`的执行过程

UPROBE通过响应INT3中断的方式实现。具体的实现过程参见[UPROBE的内核实现](./07-uprobe.md#2-uprobe的执行过程)中`uprobe的执行过程`章节。

`handler_chain` 函数调用UPROBE设置的处理函数，实现如下：

```C
// file: kernel/events/uprobes.c
static void handler_chain(struct uprobe *uprobe, struct pt_regs *regs)
{
    ...
    down_read(&uprobe->register_rwsem);
    for (uc = uprobe->consumers; uc; uc = uc->next) {
        int rc = 0;
        // 入口点
        if (uc->handler) {
            rc = uc->handler(uc, regs);
            WARN(rc & ~UPROBE_HANDLER_MASK, "bad rc=0x%x from %ps()\n", rc, uc->handler);
        }
        // uretprobe处理接口
        if (uc->ret_handler)
            need_prep = true;
	    remove &= rc;
    }

    if (need_prep && !remove)
        // 在返回位置设置断点
        prepare_uretprobe(uprobe, regs); /* put bp at return */

    if (remove && uprobe->consumers) {
        WARN_ON(!uprobe_is_active(uprobe));
        // 删除断点
        unapply_uprobe(uprobe, current->mm);
    }
    up_read(&uprobe->register_rwsem);
}
```

`uprobe_multi`类型的程序不能同时`uprobe.multi`和`uretprobe.multi`，即，不能同时设置`handler`和`ret_handler`，如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_uprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
	for (i = 0; i < cnt; i++) {
        ...
        if (flags & BPF_F_UPROBE_MULTI_RETURN)
            uprobes[i].consumer.ret_handler = uprobe_multi_link_ret_handler;
        else
            uprobes[i].consumer.handler = uprobe_multi_link_handler;

        if (pid)
            uprobes[i].consumer.filter = uprobe_multi_link_filter;
    }
}
```

`consumer.filter`接口过滤符合条件的`uprobe`，设置为`uprobe_multi_link_filter`,  实现如下：

```C
// file: kernel/trace/bpf_trace.c
static bool
uprobe_multi_link_filter(struct uprobe_consumer *con, enum uprobe_filter_ctx ctx, struct mm_struct *mm)
{
    struct bpf_uprobe *uprobe;
    uprobe = container_of(con, struct bpf_uprobe, consumer);
    // 判断内存区域和`task`的内存区域是否相同
    return uprobe->link->task->mm == mm;
}
```

`consumer.handler`接口是`uprobe`的处理接口，设置为`uprobe_multi_link_handler`,  实现如下：

```C
// file: kernel/trace/bpf_trace.c
static int uprobe_multi_link_handler(struct uprobe_consumer *con, struct pt_regs *regs)
{
    struct bpf_uprobe *uprobe;
    // 获取`bpf_uprobe`后，运行BPF程序
    uprobe = container_of(con, struct bpf_uprobe, consumer);
    return uprobe_prog_run(uprobe, instruction_pointer(regs), regs);
}
```

`uprobe_prog_run`函数运行`bpf_uprobe`程序，如下：

```C
// file: kernel/trace/bpf_trace.c
static int uprobe_prog_run(struct bpf_uprobe *uprobe, unsigned long entry_ip, struct pt_regs *regs)
{
    struct bpf_uprobe_multi_link *link = uprobe->link;
    // `uprobe_multi`运行上下文
    struct bpf_uprobe_multi_run_ctx run_ctx = {
        .entry_ip = entry_ip,
        .uprobe = uprobe,
    };
    struct bpf_prog *prog = link->link.prog;
    bool sleepable = prog->aux->sleepable;
    struct bpf_run_ctx *old_run_ctx;
    int err = 0;

    // 不是当前运行的任务，返回
    if (link->task && current != link->task) return 0;

    if (sleepable)
        rcu_read_lock_trace();
    else
        rcu_read_lock();
    migrate_disable();

    // 设置运行上下文
    old_run_ctx = bpf_set_run_ctx(&run_ctx.run_ctx);
    // 运行BPF程序
    err = bpf_prog_run(link->link.prog, regs);
    bpf_reset_run_ctx(old_run_ctx);

    migrate_enable();
    if (sleepable)
        rcu_read_unlock_trace();
    else
        rcu_read_unlock();
    return err;
}
```

#### 3 `uretprobe_multi`的执行过程

URETPROBE通过设置trampoline的方式实现。具体的实现过程参见[UPROBE的内核实现](./07-uprobe.md#3-uretprobe的执行过程)中`uretprobe的执行过程`章节。

`handle_uretprobe_chain` 函数调用URETPROBE设置的处理函数，实现如下：

```C
// file: kernel/events/uprobes.c
static void handle_uretprobe_chain(struct return_instance *ri, struct pt_regs *regs)
{
    struct uprobe *uprobe = ri->uprobe;
    struct uprobe_consumer *uc;

    down_read(&uprobe->register_rwsem);
    for (uc = uprobe->consumers; uc; uc = uc->next) {
        if (uc->ret_handler)
            uc->ret_handler(uc, ri->func, regs);
    }
    up_read(&uprobe->register_rwsem);
}
```

`consumer.ret_handler`接口是`uretprobe`的处理接口，设置为`uprobe_multi_link_ret_handler`,  实现如下：

```C
// file: kernel/trace/bpf_trace.c
static int
uprobe_multi_link_ret_handler(struct uprobe_consumer *con, unsigned long func, struct pt_regs *regs)
{
    struct bpf_uprobe *uprobe;
    // 获取`bpf_uprobe`后，运行BPF程序
    uprobe = container_of(con, struct bpf_uprobe, consumer);
    return uprobe_prog_run(uprobe, func, regs);
}
```

### 4.4 USDT使用`uprobe_multi`

在内核支持`UPROBE_MULTI_LINK`的特性下，USDT使用`UPROBE_MULTI`方式附加，主要改动如下：

在libbpf中修改附加类型，如下：

```C
// file: libbpf/src/libbpf.c
static int libbpf_prepare_prog_load(struct bpf_program *prog, struct bpf_prog_load_opts *opts, long cookie)
{
    ...
    // USDT在内核支持`UPROBE_MULTI`时，修改附加类型
    if ((def & SEC_USDT) && kernel_supports(prog->obj, FEAT_UPROBE_MULTI_LINK))
        prog->expected_attach_type = BPF_TRACE_UPROBE_MULTI;
    ...
}
```

`usdt_manager`检查是否支持`uprobe_multi`，如下：

```C
// file: libbpf/src/usdt.c
struct usdt_manager *usdt_manager_new(struct bpf_object *obj)
{
    static const char *ref_ctr_sysfs_path = "/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset";
    struct usdt_manager *man;
    ...
    // 检测内核是否支持`uprobe multi`
    man->has_uprobe_multi = kernel_supports(obj, FEAT_UPROBE_MULTI_LINK);
    return man;
}
```

使用`uprobe_multi`附加USDT，如下：

```C
// file: libbpf/src/usdt.c
struct bpf_link *usdt_manager_attach_usdt(struct usdt_manager *man, const struct bpf_program *prog, pid_t pid, 
                    const char *path, const char *usdt_provider, const char *usdt_name, __u64 usdt_cookie)
{
    ...
    if (man->has_uprobe_multi) {
        // 支持`uprobe_multi`时，分配`offsets`,`cookies`,`ref_ctr_offsets`
        offsets = calloc(target_cnt, sizeof(*offsets));
        cookies = calloc(target_cnt, sizeof(*cookies));
        ref_ctr_offsets = calloc(target_cnt, sizeof(*ref_ctr_offsets));
        if (!offsets || !ref_ctr_offsets || !cookies) { err = -ENOMEM; goto err_out; }
    } else {
        // 不支持`uprobe_multi`时，分配多个`uprobe`
        link->uprobes = calloc(target_cnt, sizeof(*link->uprobes));
        if (!link->uprobes) { err = -ENOMEM; goto err_out; }
    }

    for (i = 0; i < target_cnt; i++) {
        struct usdt_target *target = &targets[i];
        struct bpf_link *uprobe_link;
        ...

        if (man->has_uprobe_multi) {
            // 支持`uprobe_multi`时, 设置`offsets`,`cookies`,`ref_ctr_offsets`
            offsets[i] = target->rel_ip;
            ref_ctr_offsets[i] = target->sema_off;
            cookies[i] = spec_id;
        } else {
            // 不支持`uprobe_multi`时，附加`uprobe`
            opts.ref_ctr_offset = target->sema_off;
            opts.bpf_cookie = man->has_bpf_cookie ? spec_id : 0;
            uprobe_link = bpf_program__attach_uprobe_opts(prog, pid, path, target->rel_ip, &opts);
            err = libbpf_get_error(uprobe_link);
            if (err) { ... }

            link->uprobes[i].link = uprobe_link;
            link->uprobes[i].abs_ip = target->abs_ip;
            link->uprobe_cnt++;
        }
    }

    if (man->has_uprobe_multi) {
        // 支持`uprobe_multi`时, 通过`uprobe_multi`方式附加
        LIBBPF_OPTS(bpf_uprobe_multi_opts, opts_multi,
            .ref_ctr_offsets = ref_ctr_offsets, .offsets = offsets,
            .cookies = cookies, .cnt = target_cnt,
        );
        link->multi_link = bpf_program__attach_uprobe_multi(prog, pid, path, NULL, &opts_multi);
        if (!link->multi_link) { ... }
        // 释放`offsets`,`cookies`,`ref_ctr_offsets`
        free(offsets);
        free(ref_ctr_offsets);
        free(cookies);
    }

    // 清理工作
    free(targets);
    hashmap__free(specs_hash);
    elf_close(&elf_fd);
    return &link->link;

err_out:
    ...
}
```

分离时释放`multi_link`， 如下：

```C
// file: libbpf/src/usdt.c
static int bpf_link_usdt_detach(struct bpf_link *link)
{
    struct bpf_link_usdt *usdt_link = container_of(link, struct bpf_link_usdt, link);
    struct usdt_manager *man = usdt_link->usdt_man;
    int i;
    // 销毁`multi_link`
    bpf_link__destroy(usdt_link->multi_link);

    // 销毁`uprobes`
    for (i = 0; i < usdt_link->uprobe_cnt; i++) {
        // 销毁`uprobes_link`
        bpf_link__destroy(usdt_link->uprobes[i].link);
        if (!man->has_bpf_cookie) {
            (void)bpf_map_delete_elem(bpf_map__fd(man->ip_to_spec_id_map), &usdt_link->uprobes[i].abs_ip);
        }
    }
    ...
}
```

## 5 总结

本文通过`uprobe_multi`示例程序分析了`u[ret]probe.multi`的内核实现过程。

`u[ret]probe.multi` 支持在单个系统调用中附加多个uprobe，提升了附加多个uprobes的速度。`u[ret]probe.multi` 通过Link的方式实现多个`uprobe`。

## 参考资料

* [uprobe multi link](http://vger.kernel.org/bpfconf2023_material/uprobe_multi.pdf)
* [bpf: Add multi uprobe link](https://lwn.net/Articles/939802/)
