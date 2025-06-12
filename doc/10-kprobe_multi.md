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

SEC("kprobe.session/do_unlinkat")
int BPF_KPROBE(session_unlinkat, int dfd, struct filename *name)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	const char *filename = BPF_CORE_READ(name, name);
	bool is_return = bpf_session_is_return();
	bpf_printk("KPROBE.SESSION %s pid = %d, filename = %s\n", is_return ? "EXIT" : "ENTRY",  pid, filename);
	return 0;
}
```

该程序包括多个BPF程序 `do_unlinkat`, `do_unlinkat_exit` 和 `session_unlinkat`。使用 `kprobe.multi`， `kretprobe.multi` 和 `kprobe.session` 前缀。`BPF_KPROBE`宏和`BPF_KRETPROBE`宏展开过程参见 [KPROBE的内核实现](./06-kprobe%20pmu.md) 章节。

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

`kprobe_multi.bpf.c`文件中BPF程序的SEC名称包括 `SEC("kprobe.multi/do_unlinkat")`, `SEC("kretprobe.multi/do_unlinkat")` 和 `SEC("kprobe.session/do_unlinkat")` , 这些前缀在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("kprobe.multi+",	KPROBE,	BPF_TRACE_KPROBE_MULTI, SEC_NONE, attach_kprobe_multi),
    SEC_DEF("kretprobe.multi+",	KPROBE,	BPF_TRACE_KPROBE_MULTI, SEC_NONE, attach_kprobe_multi),
    SEC_DEF("kprobe.session+",	KPROBE,	BPF_TRACE_KPROBE_SESSION, SEC_NONE, attach_kprobe_session),
    ...
};
```

`kprobe.multi` 和 `kretprobe.multi` 都是通过 `attach_kprobe_multi` 函数进行附加的。`kprobe.session` 是通过 `attach_kprobe_session` 函数进行附加的。

`attach_kprobe_multi` 在解析SEC名称中`pattern`后，调用 `bpf_program__attach_kprobe_multi_opts` 函数完成剩余的工作, `attach_kprobe_session` 同样在解析SEC名称中`pattern`后，调用 `bpf_program__attach_kprobe_multi_opts` 函数。实现过程如下：

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

```C
// file: libbpf/src/libbpf.c
static int attach_kprobe_session(const struct bpf_program *prog, long cookie, struct bpf_link **link)
{
    // 设置默认参数，session为true
    LIBBPF_OPTS(bpf_kprobe_multi_opts, opts, .session = true);
    const char *spec;
    char *pattern;
    int n;

    *link = NULL;

    // SEC("kprobe.session")时，不自动附加
    if (strcmp(prog->sec_name, "kprobe.session") == 0)
        return 0;

    // 获取 pattern
    spec = prog->sec_name + sizeof("kprobe.session/") - 1;
    n = sscanf(spec, "%m[a-zA-Z0-9_.*?]", &pattern);
    if (n < 1) { ... }

    *link = bpf_program__attach_kprobe_multi_opts(prog, pattern, &opts);
    free(pattern);
    return *link ? 0 : -errno;
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

    // 获取bpf程序的fd
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) { ... }

    // 获取opts设置的参数
    syms    = OPTS_GET(opts, syms, false);
    addrs   = OPTS_GET(opts, addrs, false);
    cnt     = OPTS_GET(opts, cnt, false);
    cookies = OPTS_GET(opts, cookies, false);
    unique_match = OPTS_GET(opts, unique_match, false);

    // opts参数和pattern兼容性检查
    if (!pattern && !addrs && !syms) return libbpf_err_ptr(-EINVAL);
    if (pattern && (addrs || syms || cookies || cnt)) return libbpf_err_ptr(-EINVAL);
    if (!pattern && !cnt) return libbpf_err_ptr(-EINVAL);
    if (!pattern && unique_match) return libbpf_err_ptr(-EINVAL);
    if (addrs && syms) return libbpf_err_ptr(-EINVAL);

    if (pattern) {
        // 解析符号，从`DEBUGFS"/available_filter_functions"`
        // 或者`DEBUGFS"/available_filter_functions_addrs"`文件中解析
        if (has_available_filter_functions_addrs())
            err = libbpf_available_kprobes_parse(&res);
        else
            err = libbpf_available_kallsyms_parse(&res);
        if (err) goto error;
        if (unique_match && res.cnt != 1) { ... }
        // 设置解析的结果
        addrs = res.addrs;
        cnt = res.cnt;
    }

    retprobe = OPTS_GET(opts, retprobe, false);
    session  = OPTS_GET(opts, session, false);
    // 不能同时设置为`retprobe`和`session`
    if (retprobe && session) return libbpf_err_ptr(-EINVAL);

    // 确定附加类型
    attach_type = session ? BPF_TRACE_KPROBE_SESSION : BPF_TRACE_KPROBE_MULTI;

    // 设置`kprobe_multi`属性
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
    case BPF_TRACE_KPROBE_SESSION:
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

`link_create` 在检查BFP程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 `kprobe.multi` 和 `kretprobe.multi` 设置的程序类型为`BPF_PROG_TYPE_KPROBE`, 附加类型为`BPF_TRACE_KPROBE_MULTI`。 `kprobe.session` 设置的程序类型为`BPF_PROG_TYPE_KPROBE`, 附加类型为`BPF_TRACE_KPROBE_SESSION`, 这两种附加类型都对应 `bpf_kprobe_multi_link_attach` 处理函数。如下：

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
        ...
        else if (attr->link_create.attach_type == BPF_TRACE_KPROBE_MULTI ||
             attr->link_create.attach_type == BPF_TRACE_KPROBE_SESSION)
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
    // 不支持create时设置flags
    if (attr->link_create.flags) return -EINVAL;
    // 检查 prog 是否为 `kprobe_multi` 类型，即：`BPF_TRACE_KPROBE_MULTI` 或者 `BPF_TRACE_KPROBE_SESSION`
    if (!is_kprobe_multi(prog)) return -EINVAL;

    // 用户参数检查，只支持 `KPROBE_MULTI_RETURN` 标记设置
    flags = attr->link_create.kprobe_multi.flags;
    if (flags & ~BPF_F_KPROBE_MULTI_RETURN) return -EINVAL;

    // 用户参数参数检查，`addrs`和`syms` 至少设置一个，数量必须 > 0
    uaddrs = u64_to_user_ptr(attr->link_create.kprobe_multi.addrs);
    usyms = u64_to_user_ptr(attr->link_create.kprobe_multi.syms);
    if (!!uaddrs == !!usyms) return -EINVAL;
    cnt = attr->link_create.kprobe_multi.cnt;
    if (!cnt) return -EINVAL;
    if (cnt > MAX_KPROBE_MULTI_CNT) return -E2BIG;

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
    // 检查 `addrs` 是否支持 'override'
    if (prog->kprobe_override && addrs_check_error_injection_list(addrs, cnt)) { ... }

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
    if (!(flags & BPF_F_KPROBE_MULTI_RETURN))
        link->fp.entry_handler = kprobe_multi_link_handler;
    if ((flags & BPF_F_KPROBE_MULTI_RETURN) || is_kprobe_session(prog))
        link->fp.exit_handler = kprobe_multi_link_exit_handler;
    // `KPROBE_SESSION` 类型时，设置 `entry_data_size`, 用于传递 `cookie` 信息
    if (is_kprobe_session(prog))
        link->fp.entry_data_size = sizeof(u64);

    // link属性设置
    link->addrs = addrs;
    link->cookies = cookies;
    link->cnt = cnt;
    link->flags = flags;

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

在获取探测地址后，`register_fprobe_ips` 函数实现探测地址的的注册。在初始化设置`fprobe`后，通过`fprobe_graph`添加地址的方式实现注册探测事件。如下：

```C
// file: kernel/trace/fprobe.c
int register_fprobe_ips(struct fprobe *fp, unsigned long *addrs, int num)
{
    struct fprobe_hlist *hlist_array;
    int ret, i;

    // 初始化`fprobe`数据结构，创建并初始化`hlist_array`
    ret = fprobe_init(fp, addrs, num);
    if (ret) return ret;

    mutex_lock(&fprobe_mutex);

    hlist_array = fp->hlist_array;
    // `fprobe_graph`添加探测地址
    ret = fprobe_graph_add_ips(addrs, num);
    if (!ret) {
        // 将`fprobe`添加到`fprobe_table`中
        add_fprobe_hash(fp);
        for (i = 0; i < hlist_array->size; i++)
            // 将`hlist_array`添加到`fprobe_ip_table`中
            insert_fprobe_node(&hlist_array->array[i]);
    }
    mutex_unlock(&fprobe_mutex);
    // 错误时，清理
    if (ret) fprobe_fail_cleanup(fp);

    return ret;
}
```

`fprobe_graph_add_ips` 函数将地址列表添加到`fprobe_graph_ops`中，并在必要时注册`fprobe_graph`。如下：

```C
// file: kernel/trace/fprobe.c
static int fprobe_graph_add_ips(unsigned long *addrs, int num)
{
    int ret;

    lockdep_assert_held(&fprobe_mutex);
    // 将地址列表添加到`fprobe_graph_ops.ops`中，`fprobe_graph_ops`启用时，修改addr的入口地址
    ret = ftrace_set_filter_ips(&fprobe_graph_ops.ops, addrs, num, 0, 0);
    if (ret) return ret;

    if (!fprobe_graph_active) {
        // `fprobe_graph`没有启用时注册
        ret = register_ftrace_graph(&fprobe_graph_ops);
        if (WARN_ON_ONCE(ret)) {
            // 注册失败时，清理筛选信息
            ftrace_free_filter(&fprobe_graph_ops.ops);
            return ret;
        }
    }
    fprobe_graph_active++;
    return 0;
}
```

`register_ftrace_graph` 函数注册`fprobe_graph`，通过添加`fgraph_array`和注册`graph_ops`实现。如下：

```C
// file: kernel/trace/fgraph.c
int register_ftrace_graph(struct fgraph_ops *gops)
{
    static bool fgraph_initialized;
    int command = 0;
    ...

    if (!fgraph_array[0]) {
        // 初始化`fgraph_array`
        fgraph_array[0] = &fgraph_stub;
        for (i = 0; i < FGRAPH_ARRAY_SIZE; i++)
            fgraph_array[i] = &fgraph_stub;
        fgraph_lru_init();
    }

    i = fgraph_lru_alloc_index();
    if (i < 0 || WARN_ON_ONCE(fgraph_array[i] != &fgraph_stub)) return -ENOSPC;
    gops->idx = i;

    ftrace_graph_active++;

    if (ftrace_graph_active == 2)
        ftrace_graph_disable_direct(true);

    if (ftrace_graph_active == 1) {
        ftrace_graph_enable_direct(false, gops);
        register_pm_notifier(&ftrace_suspend_notifier);
        // 开始跟踪，分配返回栈空间
        ret = start_graph_tracing();
        if (ret) goto error;

        // 设置默认的`entry`和`return`函数
        ftrace_graph_return = return_run;
        ftrace_graph_entry = entry_run;
        command = FTRACE_START_FUNC_RET;
    } else {
        init_task_vars(gops->idx);
    }
    // 设置`gops`
    gops->saved_func = gops->entryfunc;
    gops->ops.flags |= FTRACE_OPS_FL_GRAPH;

    // 设置`gops->ops`由`graph_ops`管理，并注册`graph_ops`
    ret = ftrace_startup_subops(&graph_ops, &gops->ops, command);
    // 添加`fgraph_array`
    if (!ret) fgraph_array[i] = gops;

error:
    // 错误时，清理
    if (ret) {
        ftrace_graph_active--;
        gops->saved_func = NULL;
        fgraph_lru_release_index(i);
    }
    return ret;
}
```

`graph_ops`是一种`ftrace_ops`, 在启用`ftrace_graph`时，将观测函数的入口地址修改为`graph_ops.func`，其定义如下：

```C
// file: kernel/trace/fgraph.c
static struct ftrace_ops graph_ops = {
    .func           = ftrace_graph_func,
    .flags          = FTRACE_OPS_GRAPH_STUB,
#ifdef FTRACE_GRAPH_TRAMP_ADDR
    .trampoline     = FTRACE_GRAPH_TRAMP_ADDR,
#endif
};
```

#### 3 设置`return_hooker`

`kretprobe.multi` 或者 `kprobe.session` 类型的事件需要在函数执行完成后执行设置的BPF程序，通过在调用`ftrace_graph_func`函数过程中修改栈上返回地址实现， 在x86_64架构下实现如下：

```C
// file: arch/x86/kernel/ftrace.c
void ftrace_graph_func(unsigned long ip, unsigned long parent_ip,
            struct ftrace_ops *op, struct ftrace_regs *fregs)
{
    // 获取pt_regs
    struct pt_regs *regs = &arch_ftrace_regs(fregs)->regs;
    // 获取栈顶地址
    unsigned long *stack = (unsigned long *)kernel_stack_pointer(regs);
    // 获取返回地址，即`return_to_handler`
    unsigned long return_hooker = (unsigned long)&return_to_handler;
    unsigned long *parent = (unsigned long *)stack;

    if (unlikely(skip_ftrace_return())) return;

    // 进入`function_graph`
    if (!function_graph_enter_regs(*parent, ip, 0, parent, fregs))
        // 设置返回的函数地址为`return_to_handler`
        *parent = return_hooker;
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

`unregister_fprobe` 函数注销`ftrace_ops` 和释放`ftrace_ops`中的`filter`，如下：

```C
// file: kernel/trace/fprobe.c
int unregister_fprobe(struct fprobe *fp)
{
    struct fprobe_hlist *hlist_array;
    unsigned long *addrs = NULL;
    int ret = 0, i, count;

    mutex_lock(&fprobe_mutex);
    if (!fp || !is_fprobe_still_exist(fp)) { ... }

    hlist_array = fp->hlist_array;
    addrs = kcalloc(hlist_array->size, sizeof(unsigned long), GFP_KERNEL);
    if (!addrs) { ... }

    // 从`hlist_array`和`fprobe_table`中删除`fprobe`
    count = 0;
    for (i = 0; i < hlist_array->size; i++) {
        if (!delete_fprobe_node(&hlist_array->array[i]))
            addrs[count++] = hlist_array->array[i].addr;
    }
    del_fprobe_hash(fp);

    // 从`fprobe_graph`中删除`addrs`
    fprobe_graph_remove_ips(addrs, count);

    kfree_rcu(hlist_array, rcu);
    fp->hlist_array = NULL;

out:
    mutex_unlock(&fprobe_mutex);
    kfree(addrs);
    return ret;
}
```

`fprobe_graph_remove_ips` 函数从`fprobe_graph`中删除`addrs`，如下：

```C
// file: kernel/trace/fprobe.c
static void fprobe_graph_remove_ips(unsigned long *addrs, int num)
{
    lockdep_assert_held(&fprobe_mutex);

    fprobe_graph_active--;
    // `fprobe_graph`没有启用时，注销`fprobe_graph`
    if (!fprobe_graph_active)
        unregister_ftrace_graph(&fprobe_graph_ops);

    // 从`fprobe_graph_ops.ops`中删除`addrs`
    if (num) ftrace_set_filter_ips(&fprobe_graph_ops.ops, addrs, num, 1, 0);
}
```

### 4.4 BPF调用过程

#### 1 触发`ftrace_graph_func`

在同一个动态事件中注册多个`ftrace_ops`时，在注册第二个`ftrace_ops`时，`dyn_event` 的调用信息设置为 `FTRACE_REGS_ADDR` 或者 `FTRACE_ADDR`。实现如下：

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

在内核调用我们探测的函数时，调用`FTRACE_REGS_ADDR`(`ftrace_regs_caller`函数) 或者 进入设置的蹦床中执行，最终调用 `ftrace_ops->func` 。`graph_ops` 的 `ops.func` 设置为 `ftrace_graph_func`，如下：

```C
// file: arch/x86/kernel/ftrace.c
void ftrace_graph_func(unsigned long ip, unsigned long parent_ip,
            struct ftrace_ops *op, struct ftrace_regs *fregs)
{
    // 获取pt_regs
    struct pt_regs *regs = &arch_ftrace_regs(fregs)->regs;
    // 获取栈顶地址
    unsigned long *stack = (unsigned long *)kernel_stack_pointer(regs);
    // 获取返回地址，即`return_to_handler`
    unsigned long return_hooker = (unsigned long)&return_to_handler;
    unsigned long *parent = (unsigned long *)stack;

    if (unlikely(skip_ftrace_return())) return;

    // 进入`function_graph`
    if (!function_graph_enter_regs(*parent, ip, 0, parent, fregs))
        // 设置返回的函数地址为`return_to_handler`
        *parent = return_hooker;
}
```

#### 2 `kprobe_multi`的执行过程

##### (1) 触发`fprobe_entry`

`function_graph_enter_regs` 函数记录调用函数前的操作，如下：

```C
// file: kernel/trace/fgraph.c
int function_graph_enter_regs(unsigned long ret, unsigned long func,
                    unsigned long frame_pointer, unsigned long *retp,
                    struct ftrace_regs *fregs)
{
    struct ftrace_graph_ent trace;
    unsigned long bitmap = 0;
    int offset;
    int bit;
    int i;

    // 检查是否可以递归调用
    bit = ftrace_test_recursion_trylock(func, ret);
    if (bit < 0) return -EBUSY;

    trace.func = func;
    trace.depth = ++current->curr_ret_depth;

    // 在栈上记录返回地址
    offset = ftrace_push_return_trace(ret, func, frame_pointer, retp, 0);
    if (offset < 0) goto out;

#ifdef CONFIG_HAVE_STATIC_CALL
    if (static_branch_likely(&fgraph_do_direct)) {
        int save_curr_ret_stack = current->curr_ret_stack;
        // 调用`fgraph_func`
        if (static_call(fgraph_func)(&trace, fgraph_direct_gops, fregs))
            bitmap |= BIT(fgraph_direct_gops->idx);
        else
            /* Clear out any saved storage */
            current->curr_ret_stack = save_curr_ret_stack;
    } else
#endif
    {
        for_each_set_bit(i, &fgraph_array_bitmask, sizeof(fgraph_array_bitmask) * BITS_PER_BYTE) {
            // 获取`fgraph_ops`
            struct fgraph_ops *gops = READ_ONCE(fgraph_array[i]);
            int save_curr_ret_stack;

            if (gops == &fgraph_stub) continue;

            save_curr_ret_stack = current->curr_ret_stack;
            // 调用`gops->entryfunc`
            if (ftrace_ops_test(&gops->ops, func, NULL) &&
                gops->entryfunc(&trace, gops, fregs))
                bitmap |= BIT(i);
            else
                /* Clear out any saved storage */
                current->curr_ret_stack = save_curr_ret_stack;
        }
    }

    if (!bitmap) goto out_ret;

    // 设置`bitmap`
    set_bitmap(current, offset, bitmap | BIT(0));
    // 清除递归调用标记
    ftrace_test_recursion_unlock(bit);
    return 0;
 out_ret:
    current->curr_ret_stack -= FGRAPH_FRAME_OFFSET + 1;
 out:
    current->curr_ret_depth--;
    ftrace_test_recursion_unlock(bit);
    return -EBUSY;
}
```

在注册`kprobe_multi`时，我们通过注册`fprobe_graph_ops`来实现，如下：

```C
// file: kernel/trace/fprobe.c
static int fprobe_graph_add_ips(unsigned long *addrs, int num)
{
    ...
    if (!fprobe_graph_active) {
        ret = register_ftrace_graph(&fprobe_graph_ops);
        ...
    }
    ...
    fprobe_graph_active++;
    return 0;
}
```

`fprobe_graph_ops`定义如下：

```C
// file: kernel/trace/fprobe.c
static struct fgraph_ops fprobe_graph_ops = {
    .entryfunc  = fprobe_entry,
    .retfunc    = fprobe_return,
};
```

其`.entryfunc` 设置为 `fprobe_entry` 函数，如下：

```C
// file: kernel/trace/fprobe.c
static int fprobe_entry(struct ftrace_graph_ent *trace, struct fgraph_ops *gops, struct ftrace_regs *fregs)
{
    struct fprobe_hlist_node *node, *first;
    unsigned long *fgraph_data = NULL;
    unsigned long func = trace->func;
    unsigned long ret_ip;
    int reserved_words;
    struct fprobe *fp;
    int used, ret;

    if (WARN_ON_ONCE(!fregs)) return 0;

    first = node = find_first_fprobe_node(func);
    if (unlikely(!first)) return 0;

    reserved_words = 0;
    // 计算需要预留的空间
    hlist_for_each_entry_from_rcu(node, hlist) {
        if (node->addr != func) break;
        fp = READ_ONCE(node->fp);
        if (!fp || !fp->exit_handler) continue;

        reserved_words += FPROBE_HEADER_SIZE_IN_LONG + SIZE_IN_LONG(fp->entry_data_size);
    }
    node = first;
    if (reserved_words) {
        // 预留空间
        graph_data = fgraph_reserve_data(gops->idx, reserved_words * sizeof(long));
        if (unlikely(!fgraph_data)) { ... }
    }

    // 获取返回地址
    ret_ip = ftrace_regs_get_return_address(fregs);
    used = 0;
    hlist_for_each_entry_from_rcu(node, hlist) {
        int data_size;
        void *data;

        if (node->addr != func) break;
        fp = READ_ONCE(node->fp);
        // `fp`不存在或禁用时跳过
        if (!fp || fprobe_disabled(fp)) continue;

        // 获取`fprobe`数据
        data_size = fp->entry_data_size;
        if (data_size && fp->exit_handler)
            data = fgraph_data + used + FPROBE_HEADER_SIZE_IN_LONG;
        else
            data = NULL;

        // 调用`fprobe_handler`
        if (fprobe_shared_with_kprobes(fp))
            ret = __fprobe_kprobe_handler(func, ret_ip, fp, fregs, data);
        else
            ret = __fprobe_handler(func, ret_ip, fp, fregs, data);

        // `entry_handler`返回非0时，不计数`missed`，跳过`exit_handler`
        if (!ret && fp->exit_handler) {
            int size_words = SIZE_IN_LONG(data_size);
            // 写入`fprobe`数据，在执行`exit_handler`时使用
            if (write_fprobe_header(&fgraph_data[used], fp, size_words))
                used += FPROBE_HEADER_SIZE_IN_LONG + size_words;
        }
    }
    if (used < reserved_words) memset(fgraph_data + used, 0, reserved_words - used);

    /* If any exit_handler is set, data must be used. */
    return used != 0;
}
```

##### (2) 触发`__fprobe_handler`

`fprobe_entry` 函数遍历`fprobe_hlist`列表，调用`__fprobe_kprobe_handler` 或者 `__fprobe_handler` 函数。`__fprobe_kprobe_handler` 是对 `__fprobe_handler` 进行的封装。如下：

```C
// file: kernel/trace/fprobe.c
static inline int __fprobe_kprobe_handler(unsigned long ip, unsigned long parent_ip,
                        struct fprobe *fp, struct ftrace_regs *fregs, void *data)
{
    int ret;

    // 当前CPU有kprobe在运行时，增加nmissed计数
    if (unlikely(kprobe_running())) {
        fp->nmissed++;
        return 0;
    }
    kprobe_busy_begin();
    ret = __fprobe_handler(ip, parent_ip, fp, fregs, data);
    kprobe_busy_end();
    return ret;
}
```

`__fprobe_handler` 函数执行`fprobe`设置的`entry_handler`(存在时)，如下：

```C
// file: kernel/trace/fprobe.c
static inline int __fprobe_handler(unsigned long ip, unsigned long parent_ip,
                struct fprobe *fp, struct ftrace_regs *fregs, void *data)
{
    if (!fp->entry_handler) return 0;

    return fp->entry_handler(fp, ip, parent_ip, fregs, data);
}
```

##### (3) 触发`kprobe_multi_link_handler`

在附加`kprobe_multi`的过程中 `entry_handler` 设置为 `kprobe_multi_link_handler`， 如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_kprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    // 设置 `entry_handler` 或 `exit_handler`
    if (!(flags & BPF_F_KPROBE_MULTI_RETURN))
        link->fp.entry_handler = kprobe_multi_link_handler;
    ...
}
```

`kprobe_multi_link_handler` 函数获取`link`后，调用 `kprobe_multi_link_prog_run` 函数，后者设置运行上下文后运行BPF程序。如下：

```C
// file: kernel/trace/bpf_trace.c
static int kprobe_multi_link_handler(struct fprobe *fp, unsigned long fentry_ip,
                unsigned long ret_ip, struct ftrace_regs *fregs, void *data)
{
    struct bpf_kprobe_multi_link *link;
    int err;

    link = container_of(fp, struct bpf_kprobe_multi_link, fp);
    // 运行BPF程序
    err = kprobe_multi_link_prog_run(link, ftrace_get_entry_ip(fentry_ip), fregs, false, data);
    return is_kprobe_session(link->link.prog) ? err : 0;
}

// file: kernel/trace/bpf_trace.c
static int kprobe_multi_link_prog_run(struct bpf_kprobe_multi_link *link,
            unsigned long entry_ip, struct ftrace_regs *fregs, bool is_return, void *data)
{
    struct bpf_kprobe_multi_run_ctx run_ctx = {
        .session_ctx = {
            .is_return = is_return,
            .data = data,
        },
        .link = link,
        .entry_ip = entry_ip,
    };
    struct bpf_run_ctx *old_run_ctx;
    struct pt_regs *regs;
    int err;

    // 增加引用计数，失败时退出
    if (unlikely(__this_cpu_inc_return(bpf_prog_active) != 1)) {
        bpf_prog_inc_misses_counter(link->link.prog);
        err = 1;
        goto out;
    }

    migrate_disable();
    rcu_read_lock();
    // 获取`pt_regs`
    regs = ftrace_partial_regs(fregs, bpf_kprobe_multi_pt_regs_ptr());
    // 设置 `run_ctx`
    old_run_ctx = bpf_set_run_ctx(&run_ctx.session_ctx.run_ctx);
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

#### 3 `kretprobe_multi`的执行过程

##### （1）设置`return_hooker`

在调用函数前进入`ftrace`时，即`ftrace_graph_func`函数中，设置`return_hooker`，如下：

```C
// file: arch/x86/kernel/ftrace.c
void ftrace_graph_func(unsigned long ip, unsigned long parent_ip,
            struct ftrace_ops *op, struct ftrace_regs *fregs)
{
    // 获取pt_regs
    struct pt_regs *regs = &arch_ftrace_regs(fregs)->regs;
    // 获取栈顶地址
    unsigned long *stack = (unsigned long *)kernel_stack_pointer(regs);
    // 获取返回地址，即`return_to_handler`
    unsigned long return_hooker = (unsigned long)&return_to_handler;
    unsigned long *parent = (unsigned long *)stack;

    if (unlikely(skip_ftrace_return())) return;

    // 进入`function_graph`
    if (!function_graph_enter_regs(*parent, ip, 0, parent, fregs))
        // 设置返回的函数地址为`return_to_handler`
        *parent = return_hooker;
}
```

通过修改栈返回信息，设置在函数返回时调用`return_hooker`， 即：`return_to_handler`函数。

##### （2）执行`return_to_handler`

函数执行完成后，调用`ret`指令返回上一个函数继续执行，此时返回`return_hooker`设置的地址，即 `return_to_handler`，在x86_64架构下，该函数通过汇编编写的，如下：

```C
// file: arch/x86/kernel/ftrace_64.S
SYM_CODE_START(return_to_handler)
    UNWIND_HINT_UNDEFINED
    ANNOTATE_NOENDBR

    // 保存`ftrace_regs`
    subq $(FRAME_SIZE), %rsp

    movq %rax, RAX(%rsp)
    movq %rdx, RDX(%rsp)
    movq %rbp, RBP(%rsp)
    movq %rsp, %rdi

    // 调用`ftrace_return_to_handler`
    call ftrace_return_to_handler

    movq %rax, %rdi
    movq RDX(%rsp), %rdx
    movq RAX(%rsp), %rax

    // 释放`ftrace_regs`
    addq $(FRAME_SIZE), %rsp
    ...
SYM_CODE_END(return_to_handler)
```

`return_to_handler` 函数组主要的功能是调用 `ftrace_return_to_handler` 函数。 `ftrace_return_to_handler` 函数实现如下：

```C
// file: kernel/trace/fgraph.c
unsigned long ftrace_return_to_handler(struct ftrace_regs *fregs)
{
    return __ftrace_return_to_handler(fregs, ftrace_regs_get_frame_pointer(fregs));
}
```

##### (3) 触发`fprobe_return`

`__ftrace_return_to_handler` 函数进行函数返回前的操作，如下：

```C
// file: kernel/trace/fgraph.c
static inline unsigned long
__ftrace_return_to_handler(struct ftrace_regs *fregs, unsigned long frame_pointer)
{
    struct ftrace_ret_stack *ret_stack;
    struct ftrace_graph_ret trace;
    unsigned long bitmap;
    unsigned long ret;
    int offset;
    int i;

    // 获取`ret_stack`
    ret_stack = ftrace_pop_return_trace(&trace, &ret, frame_pointer, &offset);

    if (unlikely(!ret_stack)) {
        // `ret_stack`不存在时，打印错误信息
        ftrace_graph_stop();
        WARN_ON(1);
        /* Might as well panic. What else to do? */
        return (unsigned long)panic;
    }

    // 设置ip寄存器地址
    if (fregs) ftrace_regs_set_instruction_pointer(fregs, ret);

#ifdef CONFIG_FUNCTION_GRAPH_RETVAL
    // 记录`retval`
    trace.retval = ftrace_regs_get_return_value(fregs);
#endif

    bitmap = get_bitmap_bits(current, offset);

#ifdef CONFIG_HAVE_STATIC_CALL
    if (static_branch_likely(&fgraph_do_direct)) {
        if (test_bit(fgraph_direct_gops->idx, &bitmap))
            // 调用`fgraph_retfunc`
            static_call(fgraph_retfunc)(&trace, fgraph_direct_gops, fregs);
    } else
#endif
    {
        for_each_set_bit(i, &bitmap, sizeof(bitmap) * BITS_PER_BYTE) {
            // 获取`fgraph_ops`
            struct fgraph_ops *gops = READ_ONCE(fgraph_array[i]);
            if (gops == &fgraph_stub) continue;
            // 调用`gops->retfunc`
            gops->retfunc(&trace, gops, fregs);
        }
    }
    barrier();
    // 设置`curr_ret_stack`
    current->curr_ret_stack = offset - FGRAPH_FRAME_OFFSET;
    current->curr_ret_depth--;
    return ret;
}
```

在注册`kprobe_multi`时，我们通过注册`fprobe_graph_ops`来实现的, 如下：

```C
// file: kernel/trace/fprobe.c
static struct fgraph_ops fprobe_graph_ops = {
    .entryfunc  = fprobe_entry,
    .retfunc    = fprobe_return,
};
```

其`.retfunc` 设置为 `fprobe_return` 函数，如下：

```C
// file: kernel/trace/fprobe.c
static void fprobe_return(struct ftrace_graph_ret *trace, struct fgraph_ops *gops, struct ftrace_regs *fregs)
{
    unsigned long *fgraph_data = NULL;
    unsigned long ret_ip;
    struct fprobe *fp;
    int size, curr;
    int size_words;

    // 获取`fprobe`数据
    fgraph_data = (unsigned long *)fgraph_retrieve_data(gops->idx, &size);
    if (WARN_ON_ONCE(!fgraph_data)) return;

    size_words = SIZE_IN_LONG(size);
    // 获取`ret_ip`
    ret_ip = ftrace_regs_get_instruction_pointer(fregs);

    preempt_disable();

    curr = 0;
    while (size_words > curr) {
        // 获取`fprobe`
        read_fprobe_header(&fgraph_data[curr], &fp, &size);
        if (!fp) break;
        
        curr += FPROBE_HEADER_SIZE_IN_LONG;
        if (is_fprobe_still_exist(fp) && !fprobe_disabled(fp)) {
            if (WARN_ON_ONCE(curr + size > size_words)) break;
            // 调用`exit_handler`
            fp->exit_handler(fp, trace->func, ret_ip, fregs,
                size ? fgraph_data + curr : NULL);
        }
        curr += size;
    }
    preempt_enable();
}
```

##### (4) 执行`exit_handler`

`exit_handler` 设置为 `kprobe_multi_link_exit_handler`。 如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_kprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    if ((flags & BPF_F_KPROBE_MULTI_RETURN) || is_kprobe_session(prog))
        link->fp.exit_handler = kprobe_multi_link_exit_handler;
    // `KPROBE_SESSION` 类型时，设置 `entry_data_size`, 用于传递 `cookie` 信息
    if (is_kprobe_session(prog))
        link->fp.entry_data_size = sizeof(u64);
    ...
}
```

`kprobe_multi_link_exit_handler` 在获取`link`后，调用 `kprobe_multi_link_prog_run` 函数，后者设置运行上下文后运行BPF程序。如下：

```C
// file: kernel/trace/bpf_trace.c
static void
kprobe_multi_link_exit_handler(struct fprobe *fp, unsigned long fentry_ip,
                unsigned long ret_ip, struct ftrace_regs *fregs, void *data)
{
    struct bpf_kprobe_multi_link *link;

    link = container_of(fp, struct bpf_kprobe_multi_link, fp);
    // 运行BPF程序
    kprobe_multi_link_prog_run(link, ftrace_get_entry_ip(fentry_ip), fregs, true, data);
}
```

### 4.5 GDB调试验证

#### 1 附加BPF程序前

Linux系统启动后，通过`Ctrl-C`中断，查看如下：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff81644d60 <+0>:     nopw   (%rax)
   0xffffffff81644d64 <+4>:     nopl   0x0(%rax,%rax,1)
   0xffffffff81644d69 <+9>:     push   %r15
   0xffffffff81644d6b <+11>:    push   %r14
   0xffffffff81644d6d <+13>:    push   %r13
   ...
```

`do_unlinkat` 函数的前9个字节为nop指令。

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
   0xffffffff81644d60 <+0>:     nopw   (%rax)
   0xffffffff81644d64 <+4>:     call   0xffffffffc0402000
   0xffffffff81644d69 <+9>:     push   %r15
   0xffffffff81644d6b <+11>:    push   %r14
   0xffffffff81644d6d <+13>:    push   %r13
   ...
(gdb) x/100i 0xffffffffc0402000
   0xffffffffc0402000:  sub    $0xa8,%rsp
   0xffffffffc0402007:  mov    %rax,0x50(%rsp)
   0xffffffffc040200c:  mov    %rcx,0x58(%rsp)
   0xffffffffc0402011:  mov    %rdx,0x60(%rsp)
   0xffffffffc0402016:  mov    %rsi,0x68(%rsp)
   ...
   0xffffffffc040207b:  movq   $0x0,0x88(%rsp)
   0xffffffffc0402087:  cs nopl 0x0(%rax,%rax,1)
   0xffffffffc0402090:  call   0xffffffff8126c890 <ftrace_graph_func>
   0xffffffffc0402095:  mov    0x80(%rsp),%rax
   0xffffffffc040209d:  mov    %rax,0xa8(%rsp)
   0xffffffffc04020a5:  mov    0x20(%rsp),%rbp
   ...
   0xffffffffc04020cd:  add    $0xa8,%rsp
   0xffffffffc04020d4:  jmp    0xffffffff81f5c860 <its_return_thunk>  
   0xffffffffc04020d9:  add    %cl,%dl
   0xffffffffc04020db:  sbb    -0x1(%rbx),%eax
   0xffffffffc04020e1:  add    %al,(%rax)
   0xffffffffc04020e3:  add    %al,(%rax)
   ...
```

##### (2) `kprobe.multi`/`kretprobe.multi`只存在一个的情况

附加BPF程序后查看`do_unlinkat`函数反汇编代码：

```bash
(gdb) disassemble do_unlinkat
Dump of assembler code for function do_unlinkat:
   0xffffffff81644d60 <+0>:     nopw   (%rax)
   0xffffffff81644d64 <+4>:     call   0xffffffffc0402000
   0xffffffff81644d69 <+9>:     push   %r15
   0xffffffff81644d6b <+11>:    push   %r14
   0xffffffff81644d6d <+13>:    push   %r13
   ...
(gdb) x/100i 0xffffffffc0402000
   0xffffffffc0402000:  sub    $0xa8,%rsp
   0xffffffffc0402007:  mov    %rax,0x50(%rsp)
   0xffffffffc040200c:  mov    %rcx,0x58(%rsp)
   0xffffffffc0402011:  mov    %rdx,0x60(%rsp)
   0xffffffffc0402016:  mov    %rsi,0x68(%rsp)
   ...
   0xffffffffc040207b:  movq   $0x0,0x88(%rsp)
   0xffffffffc0402087:  cs nopl 0x0(%rax,%rax,1)
   0xffffffffc0402090:  call   0xffffffff8126c890 <ftrace_graph_func>
   0xffffffffc0402095:  mov    0x80(%rsp),%rax
   0xffffffffc040209d:  mov    %rax,0xa8(%rsp)
   0xffffffffc04020a5:  mov    0x20(%rsp),%rbp
   ...
   0xffffffffc04020cd:  add    $0xa8,%rsp
   0xffffffffc04020d4:  jmp    0xffffffff81f5c860 <its_return_thunk>  
   0xffffffffc04020d9:  add    %cl,%dl
   0xffffffffc04020db:  sbb    -0x1(%rbx),%eax
   0xffffffffc04020e1:  add    %al,(%rax)
   0xffffffffc04020e3:  add    %al,(%rax)
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
   0xffffffff81644d60 <+0>:     nopw   (%rax)
   0xffffffff81644d64 <+4>:     call   0xffffffffc0402000
   0xffffffff81644d69 <+9>:     push   %r15
   0xffffffff81644d6b <+11>:    push   %r14
   0xffffffff81644d6d <+13>:    push   %r13
   ...
(gdb) disassemble do_linkat
Dump of assembler code for function do_linkat:
   0xffffffff81645360 <+0>:     nopw   (%rax)
   0xffffffff81645364 <+4>:     call   0xffffffffc0402000
   0xffffffff81645369 <+9>:     push   %r15
   0xffffffff8164536b <+11>:    push   %r14
   0xffffffff8164536d <+13>:    push   %r13
   ...
(gdb) x/100i 0xffffffffc0402000
   0xffffffffc0402000:  sub    $0xa8,%rsp
   0xffffffffc0402007:  mov    %rax,0x50(%rsp)
   0xffffffffc040200c:  mov    %rcx,0x58(%rsp)
   0xffffffffc0402011:  mov    %rdx,0x60(%rsp)
   0xffffffffc0402016:  mov    %rsi,0x68(%rsp)
   ...
   0xffffffffc040207b:  movq   $0x0,0x88(%rsp)
   0xffffffffc0402087:  cs nopl 0x0(%rax,%rax,1)
   0xffffffffc0402090:  call   0xffffffff8126c890 <ftrace_graph_func>
   0xffffffffc0402095:  mov    0x80(%rsp),%rax
   0xffffffffc040209d:  mov    %rax,0xa8(%rsp)
   0xffffffffc04020a5:  mov    0x20(%rsp),%rbp
   ...
   0xffffffffc04020cd:  add    $0xa8,%rsp
   0xffffffffc04020d4:  jmp    0xffffffff81f5c860 <its_return_thunk>  
   0xffffffffc04020d9:  add    %cl,%dl
   0xffffffffc04020db:  sbb    -0x1(%rbx),%eax
   0xffffffffc04020e1:  add    %al,(%rax)
   0xffffffffc04020e3:  add    %al,(%rax)
   ...
```

#### 3 清理BPF程序后

在qemu中退出`kprobe_multi`程序后，查看`do_unlinkat` 的反汇编代码，重新设置为nop指令，如下：

```bash
(gdb) disassemble do_unlinkat
Dump of assembler code for function do_unlinkat:
   0xffffffff81644d60 <+0>:     nopw   (%rax)
   0xffffffff81644d64 <+4>:     nopl   0x0(%rax,%rax,1)
   0xffffffff81644d69 <+9>:     push   %r15
   0xffffffff81644d6b <+11>:    push   %r14
   0xffffffff81644d6d <+13>:    push   %r13
   ...
```

可以看到，`kprobe_multi`使用`trace_graph`后，在附加多个`k[ret]probe.multi`时，只使用一个`ftrace_ops`，减少了`ftrace_ops`调用次数。

## 5 总结

本文通过`kprobe_multi`示例程序分析了`k[ret]probe.multi`和`kprobe.session`的内核实现过程。

`kprobe.session` 支持在同一个BPF程序在`kprobe` 和 `kretprobe`时同时执行, 通过 `bpf_session_is_return()` kfunc 判断是否在函数返回时执行。

`k[ret]probe.multi` 支持在单个系统调用中附加多个kprobe，提示了附加多个kprobes的速度。`k[ret]probe.multi` 基于ftrace实现的，只允许在函数的入口位置使用 kprobes 和 kretprobes。

## 参考资料

* [bpf: Add kprobe multi link](https://lwn.net/Articles/885811/)
* [kprobe/bpf: Add support to attach multiple kprobes](https://lwn.net/Articles/880337/)
* [bpf: Introduce kprobe_multi session attach](https://lwn.net/Articles/970725/)
* [Program type BPF_PROG_TYPE_KPROBE](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/)