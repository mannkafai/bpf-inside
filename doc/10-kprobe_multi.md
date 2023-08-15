# KPROBE.MULTI的内核实现

## 0 前言

在第六篇中我们分析了Kprobe的内核实现，第九篇中分析了fentry的内核实现，都是对Linux内核函数的入口和出口处进行追踪。一次追踪使用对应一个BPF程序，在对多个同类型函数追踪时使用同样的BPF程序功能时，需要创建多个BPF程序。现在借助`KPROBE.MULTI`可以实现追踪多个函数时使用同一个BPF程序。我们基于`kprobe_multi`程序分析`KPROBE.MULTI`的实现过程。

## 1 简介

`k[ret]probe.multi` 支持在单个系统调用中附加多个kprobe，提升了附加多个kprobes的速度。

## 2 `kprobe_multi`示例程序

### 2.1 BPF程序

BPF程序源码参见[kprobe_multi.bpf.c](../src/kprobe_multi.bpf.c)，主要内容如下：

```C
SEC("kprobe.multi/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	pid_t pid;
	const char *filename;
	pid = bpf_get_current_pid_tgid() >> 32;
	filename = BPF_CORE_READ(name, name);
	bpf_printk("KPROBE.MULTI ENTRY pid = %d, filename = %s\n", pid, filename);
	return 0;
}

SEC("kretprobe.multi/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE.MULTI EXIT: pid = %d, ret = %ld\n", pid, ret);
	return 0;
}
```

该程序包括2个BPF程序 `do_unlinkat` 和 `do_unlinkat_exit` ，使用 `kprobe.multi` 和 `kretprobe.multi` 前缀。`BPF_KPROBE`宏和`BPF_KRETPROBE`宏展开过程参见 [KPROBE的内核实现](./06-kprobe%20pmu.md) 章节。

### 2.2 用户程序

用户程序源码参见[kprobe_multi.c](../src/kprobe_multi.c)，主要内容如下：

#### 1 附加BPF程序

```C
int main(int argc, char **argv)
{
    struct kprobe_multi_bpf *skel;
    ...
    // 设置 libbpf 调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);
    // 打开并加载BPF程序
    skel = kprobe_multi_bpf__open_and_load();
    if (!skel) { ... }
    // 附加BPF程序
    err = kprobe_multi_bpf__attach(skel);
    if (err) { ... }
    // 设置`INT`处理函数
    if (signal(SIGINT, sig_int) == SIG_ERR) { ... }
    
    while (!stop) {
        fprintf(stderr, ".");
        sleep(1);
    }
cleanup:
    // 销毁BPF程序
    kprobe_multi_bpf__destroy(skel);
    return -err;
}
```

#### 2 读取数据过程

`do_unlinkat` 和 `do_unlinkat_exit` BPF程序将采集的数据通过 `bpf_printk` 输出到 `/sys/kernel/debug/tracing/trace_pipe` 文件中。

### 2.3 编译运行

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make kprobe_multi 
$ sudo ./kprobe_multi 
libbpf: loading object 'kprobe_multi_bpf' from buffer
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

在`kprobe_multi`程序运行的过程中打开另一个bash窗口查看输出结果，如下：

```bash
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
 systemd-journal-311     [001] d..41 294944.073638: bpf_trace_printk: KPROBE.MULTI ENTRY pid = 311, filename = /run/systemd/journal/streams/8:5860097
 systemd-journal-311     [001] d..31 294944.073679: bpf_trace_printk: KPROBE.MULTI EXIT: pid = 311, ret = 0
...
```

## 3 kprobe_multi附加BPF的过程

`kprobe_multi.bpf.c`文件中BPF程序的SEC名称分别为 `SEC("kprobe.multi/do_unlinkat")` 和 `SEC("kretprobe.multi/do_unlinkat")` , `kprobe.multi` 和 `kretprobe.multi` 前缀在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("kprobe.multi+",	KPROBE,	BPF_TRACE_KPROBE_MULTI, SEC_NONE, attach_kprobe_multi),
    SEC_DEF("kretprobe.multi+",	KPROBE,	BPF_TRACE_KPROBE_MULTI, SEC_NONE, attach_kprobe_multi),
    ...
};
```

`kprobe.multi` 和 `kretprobe.multi` 都是通过 `attach_kprobe_multi` 函数进行附加的。

`attach_kprobe_multi` 在解析SEC名称中`pattern`后，调用 `bpf_program__attach_kprobe_multi_opts` 函数完成剩余的工作。实现过程如下：

```C
// file: libbpf/src/libbpf.c
static int attach_kprobe_multi(const struct bpf_program *prog, long cookie, struct bpf_link **link)
{
    LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
    const char *spec;
    char *pattern;
    int n;

    *link = NULL;

    // SEC("kprobe.multi") 和 SEC("kretprobe.multi") 时，不自动附加
    if (strcmp(prog->sec_name, "kprobe.multi") == 0 || strcmp(prog->sec_name, "kretprobe.multi") == 0)
        return 0;

    // 获取 retprobe 和 spec 
    opts.retprobe = str_has_pfx(prog->sec_name, "kretprobe.multi/");
    if (opts.retprobe)
        spec = prog->sec_name + sizeof("kretprobe.multi/") - 1;
    else
        spec = prog->sec_name + sizeof("kprobe.multi/") - 1;

    // 获取解析的pattern，支持`*`--匹配多个字符，`?`--匹配单个字符
    n = sscanf(spec, "%m[a-zA-Z0-9_.*?]", &pattern);
    if (n < 1) { ... }

    *link = bpf_program__attach_kprobe_multi_opts(prog, pattern, &opts);
    free(pattern);
    return libbpf_get_error(*link);
}
```

`bpf_program__attach_kprobe_multi_opts` 函数检查opts参数和`pattern`的兼容性，存在`pattern`时解析符号在内核中的地址，设置link属性后，调用`bpf_link_create`函数进行实际的创建，如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link * bpf_program__attach_kprobe_multi_opts(const struct bpf_program *prog,
                        const char *pattern, const struct bpf_kprobe_multi_opts *opts)
{
    LIBBPF_OPTS(bpf_link_create_opts, lopts);
    struct kprobe_multi_resolve res = {
        .pattern = pattern,
    };
    struct bpf_link *link = NULL;
    ...

    if (!OPTS_VALID(opts, bpf_kprobe_multi_opts))
        return libbpf_err_ptr(-EINVAL);

    // 获取opts设置的参数
    syms    = OPTS_GET(opts, syms, false);
    addrs   = OPTS_GET(opts, addrs, false);
    cnt     = OPTS_GET(opts, cnt, false);
    cookies = OPTS_GET(opts, cookies, false);

    // opts参数和pattern兼容性检查
    if (!pattern && !addrs && !syms) return libbpf_err_ptr(-EINVAL);
    if (pattern && (addrs || syms || cookies || cnt)) return libbpf_err_ptr(-EINVAL);
    if (!pattern && !cnt) return libbpf_err_ptr(-EINVAL);
    if (addrs && syms) return libbpf_err_ptr(-EINVAL);

    if (pattern) {
        // 解析符号，从`/proc/kallsyms`文件中解析
        err = libbpf_kallsyms_parse(resolve_kprobe_multi_cb, &res);
        if (err) goto error;
        if (!res.cnt) { ... }
        // 设置解析的结果
        addrs = res.addrs;
        cnt = res.cnt;
    }

    // 设置`kprobe_multi`属性
    retprobe = OPTS_GET(opts, retprobe, false);
    lopts.kprobe_multi.syms = syms;
    lopts.kprobe_multi.addrs = addrs;
    lopts.kprobe_multi.cookies = cookies;
    lopts.kprobe_multi.cnt = cnt;
    lopts.kprobe_multi.flags = retprobe ? BPF_F_KPROBE_MULTI_RETURN : 0;

    // 创建link，设置分离接口
    link = calloc(1, sizeof(*link));
    if (!link) { ... }
    link->detach = &bpf_link__detach_fd;

    // 获取bpf程序fd后，创建link
    prog_fd = bpf_program__fd(prog);
    link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_KPROBE_MULTI, &lopts);
    if (link_fd < 0) { ... }
    link->fd = link_fd;
    // 释放解析的地址信息
    free(res.addrs);
    return link;

error:
    // 错误时清理
    free(link);
    free(res.addrs);
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
    case BPF_TRACE_KPROBE_MULTI:
        // 设置`kprobe_multi`属性
        attr.link_create.kprobe_multi.flags = OPTS_GET(opts, kprobe_multi.flags, 0);
        attr.link_create.kprobe_multi.cnt = OPTS_GET(opts, kprobe_multi.cnt, 0);
        attr.link_create.kprobe_multi.syms = ptr_to_u64(OPTS_GET(opts, kprobe_multi.syms, 0));
        attr.link_create.kprobe_multi.addrs = ptr_to_u64(OPTS_GET(opts, kprobe_multi.addrs, 0));
        attr.link_create.kprobe_multi.cookies = ptr_to_u64(OPTS_GET(opts, kprobe_multi.cookies, 0));
        if (!OPTS_ZEROED(opts, kprobe_multi)) return libbpf_err(-EINVAL);
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

`link_create` 在检查BFP程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 `kprobe.multi` 和 `kretprobe.multi` 设置的程序类型为`BPF_PROG_TYPE_KPROBE`, 附加类型为`BPF_TRACE_KPROBE_MULTI`, 对应 `bpf_kprobe_multi_link_attach` 处理函数。如下：

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
        else
            // multi_link处理
            ret = bpf_kprobe_multi_link_attach(attr, prog);
        break;
    ...
    }
    ...
}
```

#### 2 `bpf_kprobe_multi_link_attach`

`bpf_kprobe_multi_link_attach` 函数检查用户输入的参数信息，使用输入的地址或解析输入符号对应的地址后，设置 `multi_link` 的信息后，注册 `fprobe` 探测事件。如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_kprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    struct bpf_kprobe_multi_link *link = NULL;
    struct bpf_link_primer link_primer;
    void __user *ucookies;
    unsigned long *addrs;
    u32 flags, cnt, size;
    void __user *uaddrs;
    u64 *cookies = NULL;
    void __user *usyms;
    int err;

    // `kprobe_multi` 不支持32位系统
    if (sizeof(u64) != sizeof(void *)) return -EOPNOTSUPP;

    if (prog->expected_attach_type != BPF_TRACE_KPROBE_MULTI) return -EINVAL;

    // 用户参数检查，只支持 `KPROBE_MULTI_RETURN` 标记设置
    flags = attr->link_create.kprobe_multi.flags;
    if (flags & ~BPF_F_KPROBE_MULTI_RETURN) return -EINVAL;

    // 用户参数参数检查，`addrs`和`syms` 至少设置一个，数量必须 > 0
    uaddrs = u64_to_user_ptr(attr->link_create.kprobe_multi.addrs);
    usyms = u64_to_user_ptr(attr->link_create.kprobe_multi.syms);
    if (!!uaddrs == !!usyms) return -EINVAL;
    cnt = attr->link_create.kprobe_multi.cnt;
    if (!cnt) return -EINVAL;

    size = cnt * sizeof(*addrs);
    addrs = kvmalloc_array(cnt, sizeof(*addrs), GFP_KERNEL);
    if (!addrs) return -ENOMEM;

    // 用户设置`cookies`参数时，复制到内核空间
    ucookies = u64_to_user_ptr(attr->link_create.kprobe_multi.cookies);
    if (ucookies) {
        cookies = kvmalloc_array(cnt, sizeof(*addrs), GFP_KERNEL);
        if (!cookies) { ... }
        if (copy_from_user(cookies, ucookies, size)) { ... }
    }

    // 用户设置`addrs`参数时，复制到内核空间
    if (uaddrs) {
        if (copy_from_user(addrs, uaddrs, size)) { ... }
    } else {
        // 用户设置`syms`参数时，解析符号对应的地址
        struct multi_symbols_sort data = {
            .cookies = cookies,
        };
        struct user_syms us;

        err = copy_user_syms(&us, usyms, cnt);
        if (err) goto error;
        if (cookies) data.funcs = us.syms;
        sort_r(us.syms, cnt, sizeof(*us.syms), symbols_cmp_r, symbols_swap_r, &data);
        // 解析符号对应的地址
        err = ftrace_lookup_symbols(us.syms, cnt, addrs);
        free_user_syms(&us);
        if (err) goto error;
    }

    // 创建 link
    link = kzalloc(sizeof(*link), GFP_KERNEL);
    if (!link) { ... }
    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_KPROBE_MULTI,
            &bpf_kprobe_multi_link_lops, prog);
    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    if (err) { ... }

    // 设置 `entry_handler` 或 `exit_handler`
    if (flags & BPF_F_KPROBE_MULTI_RETURN)
        link->fp.exit_handler = kprobe_multi_link_handler;
    else
        link->fp.entry_handler = kprobe_multi_link_handler;

    // link属性设置
    link->addrs = addrs;
    link->cookies = cookies;
    link->cnt = cnt;

    if (cookies) {
        // 对`addrs`排序，在排序的同时对`cookies`进行排序。
        // `bpf_get_attach_cookie` 可以通过`address`查找对应的`cookie`
        sort_r(addrs, cnt, sizeof(*addrs), bpf_kprobe_multi_cookie_cmp,
            bpf_kprobe_multi_cookie_swap, link);
    }

    // 获取 `addrs` 对应的 `modules`
    err = get_modules_for_addrs(&link->mods, addrs, cnt);
    if (err < 0) { ... }
    link->mods_cnt = err;

    // 注册 `kprobe_multi`
    err = register_fprobe_ips(&link->fp, addrs, cnt);
    if (err) { ... }
    // fd 和 file 进行关联
    return bpf_link_settle(&link_primer);

error:
    kfree(link);
    kvfree(addrs);
    kvfree(cookies);
    return err;
}
```

### 4.2 注册`kprobe_multi`

#### 1 获取探测地址

在用户设置的`kprobe_multi`属性中，如果设置了`uaddrs`使用设置的`uaddrs`；否则，需要解析设置的`usyms`对应的地址。如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_kprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{   
    ...
    if (uaddrs) {
        if (copy_from_user(addrs, uaddrs, size)) { ... }
    } else {
        // 用户设置`syms`参数时，解析符号对应的地址
        struct multi_symbols_sort data = {
            .cookies = cookies,
        };
        struct user_syms us;
        err = copy_user_syms(&us, usyms, cnt);
        if (err) goto error;

        if (cookies) data.funcs = us.syms;
        
        sort_r(us.syms, cnt, sizeof(*us.syms), symbols_cmp_r, symbols_swap_r, &data);
        // 解析符号对应的地址
        err = ftrace_lookup_symbols(us.syms, cnt, addrs);
        free_user_syms(&us);
        if (err) goto error;
    }
    ...
}
```

#### 2 注册探测地址

在获取探测地址后，`register_fprobe_ips` 函数实现探测地址的的注册。在设置`fprobe`和`rethook`后，通过注册 `ftrace_ops` 方式注册探测事件。如下：

```C
// file: kernel/trace/fprobe.c
int register_fprobe_ips(struct fprobe *fp, unsigned long *addrs, int num)
{
    int ret;
    if (!fp || !addrs || num <= 0) return -EINVAL;

    // `fprobe` 初始化设置
    fprobe_init(fp);
    // 查找`addrs`对应的`dyn_event`到`filter_hash`中 
    ret = ftrace_set_filter_ips(&fp->ops, addrs, num, 0, 0);
    if (ret) return ret;
    // 设置`rethook`
    ret = fprobe_init_rethook(fp, num);
    // 注册`ftrace_ops`
    if (!ret) ret = register_ftrace_function(&fp->ops);
    // 错误时清理
    if (ret) fprobe_fail_cleanup(fp);
    return ret;
}
```

`fprobe_init` 函数设置`fprobe`信息，将`nmissed`置零后，设置 `ftrace_ops` 属性。如下：

```C
// file: kernel/trace/fprobe.c
static void fprobe_init(struct fprobe *fp)
{
    fp->nmissed = 0;
    if (fprobe_shared_with_kprobes(fp))
        fp->ops.func = fprobe_kprobe_handler;
    else
        fp->ops.func = fprobe_handler;
    fp->ops.flags |= FTRACE_OPS_FL_SAVE_REGS;
}
```

#### 3 设置`rethook`

`KPROBE_MULTI_RETURN` 类型的事件需要在函数执行完成后执行设置的BPF程序，通过设置`rethook`实现该功能。在注册 `ftrace_ops` 前，`fprobe_init_rethook` 函数实现`rethook`的设置，如下：

```C
// file: kernel/trace/fprobe.c
static int fprobe_init_rethook(struct fprobe *fp, int num)
{
    if (num < 0) return -EINVAL;
    // `KPROBE_MULTI`不需要`rethook` 
    if (!fp->exit_handler) {
        fp->rethook = NULL;
        return 0;
    }
    size = num * num_possible_cpus() * 2;
    if (size < 0) return -E2BIG;
    // 创建`rethook`
    fp->rethook = rethook_alloc((void *)fp, fprobe_exit_handler);
    if (!fp->rethook) return -ENOMEM;
    // rethook_node 设置
    for (i = 0; i < size; i++) {
        struct fprobe_rethook_node *node;
        node = kzalloc(sizeof(*node), GFP_KERNEL);
        if (!node) { ... }
        rethook_add_node(fp->rethook, &node->node);
    }
    return 0;
}
```

### 4.3 注销`kprobe_multi`

#### 1 `bpf_link_fops`接口

在附加`bpf_kprobe_multi_link_attach`过程中，设置了用户空间操作`bpf_link`的文件接口，如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_kprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    err = bpf_link_prime(&link->link, &link_primer);
    ...
}

// file: kernel/bpf/syscall.c
int bpf_link_prime(struct bpf_link *link, struct bpf_link_primer *primer)
{
    ...
    file = anon_inode_getfile("bpf_link", &bpf_link_fops, link, O_CLOEXEC);
    ...
}
```

`bpf_link_fops` 是设置的文件操作接口，定义如下：

```C
// file: kernel/bpf/syscall.c
static const struct file_operations bpf_link_fops = {
#ifdef CONFIG_PROC_FS
    .show_fdinfo    = bpf_link_show_fdinfo,
#endif
    .release    = bpf_link_release,
    .read       = bpf_dummy_read,
    .write      = bpf_dummy_write,
};
```

`bpf_link_release` 函数释放link资源，通过`bpf_link_put` 函数最终调用 `bpf_link_free` 函数。 如下：

```C
// file：kernel/bpf/syscall.c
static int bpf_link_release(struct inode *inode, struct file *filp)
    --> struct bpf_link *link = filp->private_data;
    --> bpf_link_put(link);
        --> bpf_link_free(link);

// file: kernel/bpf/syscall.c
static void bpf_link_free(struct bpf_link *link)
{
    bpf_link_free_id(link->id);
    if (link->prog) {
        // 分离BPF程序，清理使用的资源
        link->ops->release(link);
        bpf_prog_put(link->prog);
    }
    // 释放 bpf_link 和其包含的资源
    link->ops->dealloc(link);
}
```

#### 2 `bpf_kprobe_multi_link_lops`接口

`bpf_kprobe_multi_link_lops` 是我们设置的`link->ops`，如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_kprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_KPROBE_MULTI,
            &bpf_kprobe_multi_link_lops, prog);
    ...
}
```

定义如下：

```C
// file: kernel/trace/bpf_trace.c
static const struct bpf_link_ops bpf_kprobe_multi_link_lops = {
    .release = bpf_kprobe_multi_link_release,
    .dealloc = bpf_kprobe_multi_link_dealloc,
};
```

`.release`接口释放`bpf_link`关联的程序。`bpf_kprobe_multi_link_release` 释放`kmulti_link`，如下：

```C
// file: kernel/trace/bpf_trace.c
static void bpf_kprobe_multi_link_release(struct bpf_link *link)
{
    struct bpf_kprobe_multi_link *kmulti_link;
    kmulti_link = container_of(link, struct bpf_kprobe_multi_link, link);
    // 注销`fprobe`
    unregister_fprobe(&kmulti_link->fp);
    // 释放`kprobe_multi`资源
    kprobe_multi_put_modules(kmulti_link->mods, kmulti_link->mods_cnt);
}
```

`unregister_fprobe` 函数释放`rethook`、注销`ftrace_ops` 和释放`ftrace_ops`中的`filter`，如下：

```C
// file: kernel/trace/fprobe.c
int unregister_fprobe(struct fprobe *fp)
{
    if (!fp || (fp->ops.saved_func != fprobe_handler &&
                fp->ops.saved_func != fprobe_kprobe_handler))
        return -EINVAL;

    // `rethook_free()`开始禁用`rethook`，`rethook` 处理函数可能还在其他处理器上运行。
    // 确保所有的`rethook`都运行完成后调用`unregister_ftrace_function`。
    if (fp->rethook)
        rethook_free(fp->rethook);
    // 注销`ftrace_ops`
    ret = unregister_ftrace_function(&fp->ops);
    if (ret < 0) return ret;
    // 释放`ftrace_ops`中所有的`filter`
    ftrace_free_filter(&fp->ops);
    return ret;
}
```

### 4.4 BPF调用过程

#### 1 触发`ftrace_ops_list_func`

`kprobe_multi`类型的程序不能同时`kprobe.multi`和`kretprobe.multi`，即，不能同时设置`entry_handler`和`exit_handler`，如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_kprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    if (flags & BPF_F_KPROBE_MULTI_RETURN)
        link->fp.exit_handler = kprobe_multi_link_handler;
    else
        link->fp.entry_handler = kprobe_multi_link_handler;
}
```

因此，追踪同一个函数的入口和出口位置时，需要使用两个`kprobe_multi`类型的程序。意味着，在同一个动态事件中注册两个`ftrace_ops`，在注册第二个`ftrace_ops`时，`dyn_event` 的调用信息设置为 `FTRACE_REGS_ADDR` 或者 `FTRACE_ADDR`。实现如下：

```C
// file: kernel/trace/ftrace.c
unsigned long ftrace_get_addr_new(struct dyn_ftrace *rec)
{
    struct ftrace_ops *ops;
    unsigned long addr;

    // 直接调用时，获取地址
    if ((rec->flags & FTRACE_FL_DIRECT) && (ftrace_rec_count(rec) == 1)) {
        addr = ftrace_find_rec_direct(rec->ip);
        if (addr) return addr;
        WARN_ON_ONCE(1);
    }

    // 获取`trampoline`地址。在`ftrace_rec_count(rec) == 1`时设置
    if (rec->flags & FTRACE_FL_TRAMP) {
        ops = ftrace_find_tramp_ops_new(rec);
        if (FTRACE_WARN_ON(!ops || !ops->trampoline)) { ... }
        return ops->trampoline;
    }

    // 默认地址
    if (rec->flags & FTRACE_FL_REGS)
        return (unsigned long)FTRACE_REGS_ADDR;
    else
        return (unsigned long)FTRACE_ADDR;
}
```

在注册`ftrace_ops`过程中修改全局的追踪函数，设置为`ftrace_ops_list_func`, 如下：

```C
// file: kernel/trace/ftrace.c
void ftrace_modify_all_code(int command)
{
    int update = command & FTRACE_UPDATE_TRACE_FUNC;
    ...
    if (update) {
        err = update_ftrace_func(ftrace_ops_list_func);
        if (FTRACE_WARN_ON(err)) return;
    }
    ...
}
```

`ftrace_ops_list_func` 设置为 `arch_ftrace_ops_list_func` 函数，如下：

```C
// file: include/asm-generic/vmlinux.lds.h
#ifdef CONFIG_FTRACE_MCOUNT_RECORD
#define MCOUNT_REC()	. = ALIGN(8);				\
            ...
            FTRACE_STUB_HACK			\
            ftrace_ops_list_func = arch_ftrace_ops_list_func;
#else
# ifdef CONFIG_FUNCTION_TRACER
#  define MCOUNT_REC()	FTRACE_STUB_HACK			\
            ftrace_ops_list_func = arch_ftrace_ops_list_func;
# else
#  define MCOUNT_REC()
# endif
#endif
```

`arch_ftrace_ops_list_func` 函数调用`__ftrace_ops_list_func`, 后者遍历 `ftrace_ops_list` 列表逐个调用 `ftrace_ops` 设置的 `func`。如下：

```C
// file: kernel/trace/ftrace.c
void arch_ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
            struct ftrace_ops *op, struct ftrace_regs *fregs)
{
    __ftrace_ops_list_func(ip, parent_ip, NULL, fregs);
}

// file: kernel/trace/ftrace.c
static nokprobe_inline void
__ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
            struct ftrace_ops *ignored, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_ops *op;
    int bit;
    // 检查并设置递归调用标记
    bit = trace_test_and_set_recursion(ip, parent_ip, TRACE_LIST_START);
    if (bit < 0) return;

    do_for_each_ftrace_op(op, ftrace_ops_list) {
        // 桩函数时不执行
        if (op->flags & FTRACE_OPS_FL_STUB) continue;
        // 检查RCU标志，`ftrace_ops_test` 检查`ip`是否在ops过滤器中
        if ((!(op->flags & FTRACE_OPS_FL_RCU) || rcu_is_watching()) && 
                ftrace_ops_test(op, ip, regs)) {
            if (FTRACE_WARN_ON(!op->func)) { ... }
            // 调用 `ftrace_ops` 的函数
            op->func(ip, parent_ip, op, fregs);
        }
    } while_for_each_ftrace_op(op);
out:
    // 清除递归调用标记
    trace_clear_recursion(bit);
}
```

#### 2 触发`fprobe_handler`

在内核调用我们探测的函数时，调用`FTRACE_REGS_ADDR`(`ftrace_regs_caller`函数) 或者 进入设置的蹦床中执行，最终调用 `ftrace_ops->func` 。`ftrace_ops` 的 `ops.func` 设置为 `fprobe_kprobe_handler` 或 `fprobe_handler` 。 `fprobe_kprobe_handler` 是对 `fprobe_handler` 进行的封装。如下：

```C
// file: kernel/trace/fprobe.c
static void fprobe_kprobe_handler(unsigned long ip, unsigned long parent_ip,
                struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct fprobe *fp = container_of(ops, struct fprobe, ops);

    // 当前CPU有kprobe在运行时，增加nmissed计数
    if (unlikely(kprobe_running())) {
        fp->nmissed++;
        return;
    }
    kprobe_busy_begin();
    fprobe_handler(ip, parent_ip, ops, fregs);
    kprobe_busy_end();
}
```

`fprobe_handler` 函数执行`fprobe`设置的`entry_handler`(存在时)，在`exit_handler`存在时设置`rethook`，如下：

```C
// file: kernel/trace/fprobe.c
static void fprobe_handler(unsigned long ip, unsigned long parent_ip,
                struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct fprobe_rethook_node *fpr;
    struct rethook_node *rh;
    struct fprobe *fp;
    int bit;

    fp = container_of(ops, struct fprobe, ops);
    // fp禁用时返回
    if (fprobe_disabled(fp)) return;

    // 检查并设置递归调用标记
    bit = ftrace_test_recursion_trylock(ip, parent_ip);
    if (bit < 0) { fp->nmissed++; return; }

    // `KPROBE_MULTI`执行`entry_handler`
    if (fp->entry_handler)
        fp->entry_handler(fp, ip, ftrace_get_regs(fregs));

    // `KPROBE_MULTI_RETURN`设置`rethook`
    if (fp->exit_handler) {
        // 获取rethook，失败时增加`missed`计数
        rh = rethook_try_get(fp->rethook);
        if (!rh) { fp->nmissed++; goto out; }
        fpr = container_of(rh, struct fprobe_rethook_node, node);
        fpr->entry_ip = ip;
        // 设置rethook
        rethook_hook(rh, ftrace_get_regs(fregs), true);
    }

out:
    // 清除递归调用标记
    ftrace_test_recursion_unlock(bit);
}
```

#### 3 `kprobe_multi`的执行过程

在附加`kprobe_multi`的过程中 `entry_handler` 设置为 `kprobe_multi_link_handler`， 如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_kprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    if (flags & BPF_F_KPROBE_MULTI_RETURN)
        link->fp.exit_handler = kprobe_multi_link_handler;
    else
        link->fp.entry_handler = kprobe_multi_link_handler;
}
```

`kprobe_multi_link_handler` 函数获取`link`后，调用 `kprobe_multi_link_prog_run` 函数，后者设置运行上下文后运行BPF程序。如下：

```C
// file: kernel/trace/bpf_trace.c
static void kprobe_multi_link_handler(struct fprobe *fp, unsigned long fentry_ip, 
                struct pt_regs *regs)
{
    struct bpf_kprobe_multi_link *link;
    link = container_of(fp, struct bpf_kprobe_multi_link, fp);
    kprobe_multi_link_prog_run(link, get_entry_ip(fentry_ip), regs);
}

// file: kernel/trace/bpf_trace.c
static int kprobe_multi_link_prog_run(struct bpf_kprobe_multi_link *link,
                unsigned long entry_ip, struct pt_regs *regs)
{
    struct bpf_kprobe_multi_run_ctx run_ctx = {
        .link = link,
        .entry_ip = entry_ip,
    };
    struct bpf_run_ctx *old_run_ctx;
    int err;

    // 增加引用计数，失败时退出
    if (unlikely(__this_cpu_inc_return(bpf_prog_active) != 1)) { ... }

    migrate_disable();
    rcu_read_lock();
    // 设置 `run_ctx`
    old_run_ctx = bpf_set_run_ctx(&run_ctx.run_ctx);
    // 运行BPF程序
    err = bpf_prog_run(link->link.prog, regs);
    // 重置 `run_ctx`
    bpf_reset_run_ctx(old_run_ctx);
    rcu_read_unlock();
    migrate_enable();

 out:
    __this_cpu_dec(bpf_prog_active);
    return err;
}
```

#### 4 `kretprobe_multi`的执行过程

在附加`kretprobe_multi`的过程中 `exit_handler` 设置为 `kprobe_multi_link_handler`， 如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_kprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    if (flags & BPF_F_KPROBE_MULTI_RETURN)
        link->fp.exit_handler = kprobe_multi_link_handler;
    else
        link->fp.entry_handler = kprobe_multi_link_handler;
}
```

和 `rethook` 设置：

```C
// file: kernel/trace/fprobe.c
static int fprobe_init_rethook(struct fprobe *fp, int num)
{
    ...
    fp->rethook = rethook_alloc((void *)fp, fprobe_exit_handler);
    ...
}
```

##### （1）设置rethook

`rethook_hook` 函数修改当前函数的调用流程，通过修改栈返回信息，设置在函数返回时调用`rethook`。实现如下：

```C
// file: kernel/trace/rethook.c
void rethook_hook(struct rethook_node *node, struct pt_regs *regs, bool mcount)
{
    arch_rethook_prepare(node, regs, mcount);
    __llist_add(&node->llist, &current->rethooks);
}

// file: arch/x86/kernel/rethook.c
void arch_rethook_prepare(struct rethook_node *rh, struct pt_regs *regs, bool mcount)
{
    unsigned long *stack = (unsigned long *)regs->sp;
    rh->ret_addr = stack[0];
    rh->frame = regs->sp;

    // 用`trampoline`地址替换返回地址
    stack[0] = (unsigned long) arch_rethook_trampoline;
}
```

##### （2）执行`rethook_trampoline`

函数执行完成后，调用`ret`指令返回上一个函数继续执行，此时返回`rethook`设置的地址，即 `arch_rethook_trampoline`，该函数通过汇编编写的，如下：

```C
// file: arch/x86/kernel/rethook.c
asm(
    ".text\n"
    ".global arch_rethook_trampoline\n"
    ".type arch_rethook_trampoline, @function\n"
    "arch_rethook_trampoline:\n"
#ifdef CONFIG_X86_64
    ANNOTATE_NOENDBR	/* This is only jumped from ret instruction */
    /* Push a fake return address to tell the unwinder it's a rethook. */
    "	pushq $arch_rethook_trampoline\n"
    UNWIND_HINT_FUNC
    "       pushq $" __stringify(__KERNEL_DS) "\n"
    /* Save the 'sp - 16', this will be fixed later. */
    "	pushq %rsp\n"
    "	pushfq\n"
    SAVE_REGS_STRING
    "	movq %rsp, %rdi\n"
    "	call arch_rethook_trampoline_callback\n"
    RESTORE_REGS_STRING
    /* In the callback function, 'regs->flags' is copied to 'regs->ss'. */
    "	addq $16, %rsp\n"
    "	popfq\n"
#else
    ...
#endif
    ASM_RET
    ".size arch_rethook_trampoline, .-arch_rethook_trampoline\n"
);
```

`arch_rethook_trampoline` 函数组主要的功能是调用 `arch_rethook_trampoline_callback` 函数，进而调用`rethook` 。 `arch_rethook_trampoline_callback` 函数实现如下：

```C
// file: arch/x86/kernel/rethook.c
__used __visible void arch_rethook_trampoline_callback(struct pt_regs *regs)
{
    unsigned long *frame_pointer;

    // 寄存器设置
    regs->cs = __KERNEL_CS;
#ifdef CONFIG_X86_32
    regs->gs = 0;
#endif
    regs->ip = (unsigned long)&arch_rethook_trampoline;
    regs->orig_ax = ~0UL;
    regs->sp += 2*sizeof(long);
    frame_pointer = (long *)(regs + 1);

    // rethook蹦床处理
    rethook_trampoline_handler(regs, (unsigned long)frame_pointer);

    // 拷贝FLGS，`arch_rethook_trapmoline`在执行`popfq`后执行`RET`
    *(unsigned long *)&regs->ss = regs->flags;
}
```

`rethook_trampoline_handler` 函数实现`rethook`的调用，实现如下：

```C
// file: kernel/trace/rethook.c
unsigned long rethook_trampoline_handler(struct pt_regs *regs, unsigned long frame)
{
    ...
    // 获取ret_addr, 即前面设置 `rh->ret_addr = stack[0];` 地址
    correct_ret_addr = __rethook_find_ret_addr(current, &node);
    ...

    instruction_pointer_set(regs, correct_ret_addr);
    ...
    first = current->rethooks.first;
    while (first) {
        rhn = container_of(first, struct rethook_node, llist);
        if (WARN_ON_ONCE(rhn->frame != frame)) break;
        // 执行`rethook`的处理函数
        handler = READ_ONCE(rhn->rethook->handler);
        if (handler) handler(rhn, rhn->rethook->data, regs);
        
        if (first == node) break;
        // 继续下一个
        first = first->next;
    }
    // 修正返回地址
    arch_rethook_fixup_return(regs, correct_ret_addr);

    // 标记执行的rethook，设置未执行的rethook
    first = current->rethooks.first;
    current->rethooks.first = node->next;
    node->next = NULL;

    // 释放rethook
    while (first) {
        rhn = container_of(first, struct rethook_node, llist);
        first = first->next;
        rethook_recycle(rhn);
    }
}
```

`kretprobe_multi`设置`rethook`的处理函数为`fprobe_exit_handler`，实现过程如下：

```C
// file: kernel/trace/fprobe.c
static void fprobe_exit_handler(struct rethook_node *rh, void *data, struct pt_regs *regs)
{
    struct fprobe *fp = (struct fprobe *)data;
    struct fprobe_rethook_node *fpr;

    // `fp`禁用时，直接返回
    if (!fp || fprobe_disabled(fp)) return;

    fpr = container_of(rh, struct fprobe_rethook_node, node);
    // 调用`exit_handler`
    fp->exit_handler(fp, fpr->entry_ip, regs);
}
```

##### （3）执行`exit_handler`

`exit_handler` 同样设置为 `kprobe_multi_link_handler`，在`kprobe_multi_link_handler` 中调用BPF程序。 如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_kprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    if (flags & BPF_F_KPROBE_MULTI_RETURN)
        link->fp.exit_handler = kprobe_multi_link_handler;
    else
        link->fp.entry_handler = kprobe_multi_link_handler;
}
```

### 4.5 GDB调试验证

#### 1 附加BPF程序前

Linux系统启动后，通过`Ctrl-C`中断，查看如下：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	nopl   0x0(%rax,%rax,1)
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
```

`do_unlinkat` 函数的前5个字节为nop指令。

#### 2 附加BPF程序

在qemu系统中编译并运行BPF程序，如下：

```bash
$ cd build
$ cmake ../src
$ make kprobe_multi 
$ sudo ./kprobe_multi 
libbpf: loading object 'kprobe_multi_bpf' from buffer
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

##### (1) `kprobe.multi`/`kretprobe.multi`同时存在的情况

附加BPF程序后查看`do_unlinkat`函数反汇编代码：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	call   0xffffffff810a99f0 <ftrace_regs_caller>
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
(gdb) disassemble ftrace_regs_caller
Dump of assembler code for function ftrace_regs_caller:
   0xffffffff810a99f0 <+0>:	pushf  
   0xffffffff810a99f1 <+1>:	push   %rbp
   0xffffffff810a99f2 <+2>:	push   0x18(%rsp)
   0xffffffff810a99f6 <+6>:	push   %rbp
   ...
   0xffffffff810a9a42 <+82>:	mov    0xe0(%rsp),%rsi
   0xffffffff810a9a4a <+90>:	mov    0xd8(%rsp),%rdi
   0xffffffff810a9a52 <+98>:	mov    %rdi,0x80(%rsp)
   0xffffffff810a9a5a <+106>:	sub    $0x5,%rdi
   0xffffffff810a9a5e <+110>:	nopl   0x0(%rax,%rax,1)
   0xffffffff810a9a66 <+118>:	xchg   %ax,%ax
   0xffffffff810a9a68 <+120>:	mov    0x2557d51(%rip),%rdx        # 0xffffffff836017c0 <function_trace_op>
   ...
   0xffffffff810a9ae2 <+242>:	call   0xffffffff812516e0 <arch_ftrace_ops_list_func>
   ...
   0xffffffff810a9b31 <+321>:	test   %rax,%rax
   0xffffffff810a9b34 <+324>:	jne    0xffffffff810a9b6b <ftrace_regs_caller+379>
   0xffffffff810a9b36 <+326>:	mov    0x20(%rsp),%rbp
   ...
   0xffffffff810a9b59 <+361>:	mov    0x50(%rsp),%rax
   0xffffffff810a9b5e <+366>:	add    $0xd0,%rsp
   0xffffffff810a9b65 <+373>:	popf   
   0xffffffff810a9b66 <+374>:	ret  
```

##### (2) `kprobe.multi`/`kretprobe.multi`只存在一个的情况

附加BPF程序后查看`do_unlinkat`函数反汇编代码：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	call   0xffffffffc0227000
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
(gdb) x/100i 0xffffffffc0227000
   0xffffffffc0227000:	pushf  
   0xffffffffc0227001:	push   %rbp
   0xffffffffc0227002:	push   0x18(%rsp)
   0xffffffffc0227006:	push   %rbp
   ...
   0xffffffffc02270df:	lea    0x1(%rsp),%rbp
   0xffffffffc02270e4:	lea    (%rsp),%rcx
   0xffffffffc02270e8:	nopl   0x0(%rax,%rax,1)
   0xffffffffc02270f0:	xchg   %ax,%ax
   0xffffffffc02270f2:	call   0xffffffff812bb8d0 <fprobe_handler>
   ...
   0xffffffffc0227169:	mov    0x50(%rsp),%rax
   0xffffffffc022716e:	add    $0xd0,%rsp
   0xffffffffc0227175:	popf   
   0xffffffffc0227176:	ret    
   0xffffffffc0227177:	int3   
   ...
```

##### (3) `kprobe.multi`附加多个函数的情况

修改`kprobe_multi.bpf.c`文件，只保留`do_unlinkat`程序，同时修改前缀。如下：

```C
SEC("kprobe.multi/do_*linkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    ...
}
```

在附加BPF程序时，使用模板方式查找所有的符号，支持`*`和`?`方式匹配。

符合`do_*linkat`格式的符号有 `do_unlinkat` 和 `do_linkat`。`do_unlinkat` 和 `do_linkat` 函数开始位置指向同一个调用地址。如下：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	call   0xffffffffc0227000
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
(gdb) disassemble do_linkat 
Dump of assembler code for function do_linkat:
   0xffffffff81493da0 <+0>:	call   0xffffffffc0227000
   0xffffffff81493da5 <+5>:	push   %rbp
   0xffffffff81493da6 <+6>:	mov    %rsp,%rbp
   ...
(gdb) x/100i 0xffffffffc0227000
   0xffffffffc0227000:	pushf  
   0xffffffffc0227001:	push   %rbp
   0xffffffffc0227002:	push   0x18(%rsp)
   0xffffffffc0227006:	push   %rbp
   ...
   0xffffffffc02270df:	lea    0x1(%rsp),%rbp
   0xffffffffc02270e4:	lea    (%rsp),%rcx
   0xffffffffc02270e8:	nopl   0x0(%rax,%rax,1)
   0xffffffffc02270f0:	xchg   %ax,%ax
   0xffffffffc02270f2:	call   0xffffffff812bb8d0 <fprobe_handler>
   ...
   0xffffffffc0227169:	mov    0x50(%rsp),%rax
   0xffffffffc022716e:	add    $0xd0,%rsp
   0xffffffffc0227175:	popf   
   0xffffffffc0227176:	ret    
   0xffffffffc0227177:	int3   
   ...
```

#### 3 清理BPF程序后

在qemu中退出`kprobe_multi`程序后，查看`do_unlinkat` 的反汇编代码，重新设置为nop指令，如下：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	nopl   0x0(%rax,%rax,1)
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
```

## 5 总结

本文通过`kprobe_multi`示例程序分析了`k[ret]probe.multi`的内核实现过程。

`k[ret]probe.multi` 支持在单个系统调用中附加多个kprobe，提示了附加多个kprobes的速度。`k[ret]probe.multi` 基于ftrace实现的，只允许在函数的入口位置使用 kprobes 和 kretprobes。

## 参考资料

* [bpf: Add kprobe multi link](https://lwn.net/Articles/885811/)
* [kprobe/bpf: Add support to attach multiple kprobes](https://lwn.net/Articles/880337/)
