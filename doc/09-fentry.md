# fentry的内核实现

## 0 前言

在第六篇中我们分析了Kprobe的内核实现，借助Kprobe PMU对Linux内核函数的入口和出口处插入断点进行追踪。`fentry/fexit`类型程序实现相同的功能，今天我们基于`fentry`程序分析`fentry/fexit`的实现过程。

## 1 简介

fentry（function entry）和 fexit（function exit）是 eBPF 中的两种探针类型，用于在Linux内核函数的入口和退出处进行跟踪。

## 2 `fentry`示例程序

### 2.1 BPF程序

BPF程序源码参见[fentry.bpf.c](../src/fentry.bpf.c)，主要内容如下：

```C
SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fentry: pid = %d, filename = %s/n", pid, name->name);
    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fexit: pid = %d, filename = %s, ret = %ld/n", pid, name->name, ret);
    return 0;
}
```

该程序包括2个BPF程序 `do_unlinkat` 和 `do_unlinkat_exit` ，分别使用`fentry`和`fexit`前缀。`BPF_PROG`展开过程参见前一篇 [RAW TRACEPOINT的内核实现](./08-raw%20tracepoint.md) 章节。

### 2.2 用户程序

用户程序源码参见[fentry.c](../src/fentry.c)，主要内容如下：

#### 1 附加BPF程序

```C
int main(int argc, char **argv)
{
    struct fentry_bpf *skel;
    ...
    // 设置 libbpf 调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);
    // 打开并加载BPF程序
    skel = fentry_bpf__open_and_load();
    if (!skel) { ... }
    // 附加BPF程序
    err = fentry_bpf__attach(skel);
    if (err) { ... }
    // 设置`INT`处理函数
    if (signal(SIGINT, sig_int) == SIG_ERR) { ... }
    
    while (!stop) {
        fprintf(stderr, ".");
        sleep(1);
    }
cleanup:
    // 销毁BPF程序
    fentry_bpf__destroy(skel);
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
$ make fentry 
$ sudo ./fentry 
libbpf: loading object 'fentry_bpf' from buffer
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

在`fentry`程序运行的过程中打开另一个bash窗口查看输出结果，如下：

```bash
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
 systemd-journal-311     [002] d..21 284889.787069: bpf_trace_printk: fentry: pid = 311, filename = /run/systemd/journal/streams/8:5484072
 systemd-journal-311     [002] d..21 284889.787099: bpf_trace_printk: fexit: pid = 311, filename = /run/systemd/journal/streams/8:5484072, ret = 0
...
```

## 3 fentry附加BPF的过程

`fentry.bpf.c`文件中BPF程序的 `SEC("fentry/do_unlinkat")` 和 `SEC("fexit/do_unlinkat")` , 使用`fentry` 和 `fexit` 前缀，除此之外，`fmod_ret` 和 `freplace` 也使用同样的附加方式。在libbpf中对应的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("fentry+",      TRACING, BPF_TRACE_FENTRY, SEC_ATTACH_BTF, attach_trace),
    SEC_DEF("fmod_ret+",    TRACING, BPF_MODIFY_RETURN, SEC_ATTACH_BTF, attach_trace),
    SEC_DEF("fexit+",       TRACING, BPF_TRACE_FEXIT, SEC_ATTACH_BTF, attach_trace),
    SEC_DEF("fentry.s+",    TRACING, BPF_TRACE_FENTRY, SEC_ATTACH_BTF | SEC_SLEEPABLE, attach_trace),
    SEC_DEF("fmod_ret.s+",  TRACING, BPF_MODIFY_RETURN, SEC_ATTACH_BTF | SEC_SLEEPABLE, attach_trace),
    SEC_DEF("fexit.s+",	    TRACING, BPF_TRACE_FEXIT, SEC_ATTACH_BTF | SEC_SLEEPABLE, attach_trace),
    SEC_DEF("freplace+",    EXT, 0, SEC_ATTACH_BTF, attach_trace),
    ...
};
```

`fentry`,`fexit`,`fmod_ret`,`freplace` 这些`SEC`使用 `SEC_ATTACH_BTF` 标记，表示需要BTF支持。`SEC_DEF` 宏设置了 `prog_prepare_load_fn` 接口函数，libbpf在加载BPF程序阶段调用，调用过程参见 [RAW TRACEPOINT的内核实现](./08-raw%20tracepoint.md) 章节。

### 3.1 加载阶段

在获取BTF ID时，使用默认前缀和类别，即：前缀为空，类别为`FUNC`。如下：

```C
// file: libbpf/src/libbpf.c
void btf_get_kernel_prefix_kind(enum bpf_attach_type attach_type, const char **prefix, int *kind)
{
    switch (attach_type) {
    case BPF_TRACE_RAW_TP:
        *prefix = BTF_TRACE_PREFIX;
        *kind = BTF_KIND_TYPEDEF;
        break;
    case BPF_LSM_MAC:
    case BPF_LSM_CGROUP:
        *prefix = BTF_LSM_PREFIX;
        *kind = BTF_KIND_FUNC;
        break;
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

### 3.2 附加阶段

`attach_trace` 函数是对`bpf_program__attach_trace` 函数的简单封装，最终调用`bpf_program__attach_btf_id`，如下：

```C
// file: libbpf/src/libbpf.c
static int attach_trace(const struct bpf_program *prog, long cookie, struct bpf_link **link)
    --> *link = bpf_program__attach_trace(prog);
        --> bpf_program__attach_btf_id(prog, NULL);
```

`bpf_program__attach_btf_id` 函数设置link属性后，调用`bpf_link_create`进行实际的创建，如下：

```C
// file: libbpf/src/bpf.c
static struct bpf_link *bpf_program__attach_btf_id(const struct bpf_program *prog,
                            const struct bpf_trace_opts *opts)
{
    LIBBPF_OPTS(bpf_link_create_opts, link_opts);
    struct bpf_link *link;
    ...
    // 获取BPF程序fd
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) { ... }

    // 分配link，并设置detach接口
    link = calloc(1, sizeof(*link));
    if (!link) return libbpf_err_ptr(-ENOMEM);
    link->detach = &bpf_link__detach_fd;

    link_opts.tracing.cookie = OPTS_GET(opts, cookie, 0);
    // 创建link
    pfd = bpf_link_create(prog_fd, 0, bpf_program__expected_attach_type(prog), &link_opts);
    if (pfd < 0) { ... }
    // 设置link->fd
    link->fd = pfd;
    return link;
}
```

`bpf_link_create` 在设置和检查`bpf_attr`属性后，使用 `BPF_LINK_CREATE` 指令进行BPF系统调用。在旧内核不支持时，对`tracing`类型的程序使用 `BPF_RAW_TRACEPOINT_OPEN` 指令再次附加，如下：

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
    case BPF_TRACE_FENTRY:
    case BPF_TRACE_FEXIT:
    case BPF_MODIFY_RETURN:
    case BPF_LSM_MAC:
        // 设置 `tracing` 属性
        attr.link_create.tracing.cookie = OPTS_GET(opts, tracing.cookie, 0);
        if (!OPTS_ZEROED(opts, tracing)) return libbpf_err(-EINVAL);
        break;
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

    // 使用 `BPF_RAW_TRACEPOINT_OPEN` 指令参数检查
    if (attr.link_create.target_fd || attr.link_create.target_btf_id)
        return libbpf_err(err);
    if (!OPTS_ZEROED(opts, sz)) return libbpf_err(err);

    // 回退到旧内核支持的 `BPF_RAW_TRACEPOINT_OPEN` 指令附加BPF程序  
    switch (attach_type) {
    case BPF_TRACE_RAW_TP:
    case BPF_LSM_MAC:
    case BPF_TRACE_FENTRY:
    case BPF_TRACE_FEXIT:
    case BPF_MODIFY_RETURN:
        return bpf_raw_tracepoint_open(NULL, prog_fd);
    default:
        return libbpf_err(err);
    }
}
```

使用`BPF_LINK_CREATE`指令创建失败时（`EINVAL`错误情况下），回退到旧内核支持的 `BPF_RAW_TRACEPOINT_OPEN` 指令附加BPF程序。如下：

```C
// file: libbpf/src/bpf.c
int bpf_raw_tracepoint_open(const char *name, int prog_fd)
{
    const size_t attr_sz = offsetofend(union bpf_attr, raw_tracepoint);
    union bpf_attr attr;
    int fd;

    // attr属性设置
    memset(&attr, 0, attr_sz);
    attr.raw_tracepoint.name = ptr_to_u64(name);
    attr.raw_tracepoint.prog_fd = prog_fd;

    // BPF系统调用，使用`BPF_RAW_TRACEPOINT_OPEN`指令
    fd = sys_bpf_fd(BPF_RAW_TRACEPOINT_OPEN, &attr, attr_sz);
    return libbpf_err_errno(fd);
}
```

## 4 内核实现

### 4.1 BPF系统调用

`BPF_RAW_TRACEPOINT_OPEN` 和 `BPF_LINK_CREATE` 都是BPF系统调用，如下：

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
    case BPF_RAW_TRACEPOINT_OPEN: err = bpf_raw_tracepoint_open(&attr); break;
    ...
    case BPF_LINK_CREATE: err = link_create(&attr, uattr); break;
    ...
    }
    return err;
}
```

#### 1 `BPF_LINK_CREATE`

`link_create` 在检查BFP程序类型和`attr`属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。`freplace`设置的程序类型为`BPF_PROG_TYPE_EXT`；`fentry`,`fexit`,`fmod_ret`设置的程序类型为`BPF_PROG_TYPE_TRACING`，这4个前缀都对应 `bpf_tracing_prog_attach` 处理函数。如下：

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
    case BPF_PROG_TYPE_EXT:
        // EXT类型程序
        ret = bpf_tracing_prog_attach(prog, attr->link_create.target_fd,
                        attr->link_create.target_btf_id, attr->link_create.tracing.cookie);
        break;
    case BPF_PROG_TYPE_LSM:
    case BPF_PROG_TYPE_TRACING:
        // 检查 attach_type 和 expected_attach_type 是否匹配
        if (attr->link_create.attach_type != prog->expected_attach_type) { ... }

        if (prog->expected_attach_type == BPF_TRACE_RAW_TP)
            ret = bpf_raw_tp_link_attach(prog, NULL);
        else if (prog->expected_attach_type == BPF_TRACE_ITER)
            ret = bpf_iter_link_attach(attr, uattr, prog);
        else if (prog->expected_attach_type == BPF_LSM_CGROUP)
            ret = cgroup_bpf_link_attach(attr, prog);
        else
            // TENTRY, FMOD_RET, FEXIT, LSM_MAC 类型
            ret = bpf_tracing_prog_attach(prog, attr->link_create.target_fd,
                            attr->link_create.target_btf_id, attr->link_create.tracing.cookie);
        break;
        ...
    }
    ...
}
```

#### 2 `BPF_RAW_TRACEPOINT_OPEN`

`bpf_raw_tracepoint_open` 在获取设置的属性中追踪点名称后，调用 `bpf_raw_tp_link_attach` 函数，在其中检查BPF程序类型和附加类型，`freplace`,`fentry`,`fexit`,`fmod_ret`这4个前缀设置的附加类型都不是`RAW_TP`类型，最终调用 `bpf_tracing_prog_attach` 函数。如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_raw_tracepoint_open(const union bpf_attr *attr)
{
    ...
    prog = bpf_prog_get(attr->raw_tracepoint.prog_fd);
    if (IS_ERR(prog)) return PTR_ERR(prog);

    fd = bpf_raw_tp_link_attach(prog, u64_to_user_ptr(attr->raw_tracepoint.name));
    if (fd < 0) bpf_prog_put(prog);
    return fd;
}

// file: kernel/bpf/syscall.c
static int bpf_raw_tp_link_attach(struct bpf_prog *prog,  const char __user *user_tp_name)
{
    ...
    switch (prog->type) {
    case BPF_PROG_TYPE_TRACING:
    case BPF_PROG_TYPE_EXT:
    case BPF_PROG_TYPE_LSM:
        // 用户传入的名称必须为空
        if (user_tp_name) return -EINVAL;
        // RAW_TP 类型获取 tracepoint 名称
        if (prog->type == BPF_PROG_TYPE_TRACING &&
            prog->expected_attach_type == BPF_TRACE_RAW_TP) {
            tp_name = prog->aux->attach_func_name;
            break;
        }
        return bpf_tracing_prog_attach(prog, 0, 0, 0);
    }
    ...
}
```

#### 3 `bpf_tracing_prog_attach`

`bpf_tracing_prog_attach` 在获取btf_id对应的蹦床(trampoline)后，注册蹦床到挂载点。如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_tracing_prog_attach(struct bpf_prog *prog,
                    int tgt_prog_fd, u32 btf_id, u64 bpf_cookie)
{
    // prog->type 和 prog->expected_attach_type 匹配性检查
    switch (prog->type) { ... }

    // 指定 tgt_prog_fd 情况下
    if (tgt_prog_fd) {
        // 目前只支持 `BPF_PROG_TYPE_EXT` 
        if (prog->type != BPF_PROG_TYPE_EXT) { ... }

        tgt_prog = bpf_prog_get(tgt_prog_fd);
        if (IS_ERR(tgt_prog)) { ... }
        // 重新计算key
        key = bpf_trampoline_compute_key(tgt_prog, NULL, btf_id);
    }

    // 分配 link，设置相关属性 
    link = kzalloc(sizeof(*link), GFP_USER);
    if (!link) { ... }
    bpf_link_init(&link->link.link, BPF_LINK_TYPE_TRACING, &bpf_tracing_link_lops, prog);
    link->attach_type = prog->expected_attach_type;
    link->link.cookie = bpf_cookie;

    // prog->aux->dst_trampoline 存在，表示只加载了BPF程序，没有附加
    // prog->aux->dst_trampoline 为空，表示附加了BPF程序
    // tgt_prog 存在，表示使用 `link_create` 方式指定了 tgt_prog_fd, target_btf_id 参数
    // tgt_prog 为空，表示使用`raw_tracepoint_open` 方式，我们使用 `prog->aux-dst_prog`
    // prog->aux->dst_trampoline 和 tgt_prog 都为空，表示BPF程序已分离（detached），现在需要重新附加（re-attach）
    
    // 两者都为空的情况，重新附加状态 
    if (!prog->aux->dst_trampoline && !tgt_prog) {
        // 目前只支持 TRACING 和 LSM 类型BPF程序重新附加
        if (prog->type != BPF_PROG_TYPE_TRACING &&
            prog->type != BPF_PROG_TYPE_LSM) { ...  }
        
        btf_id = prog->aux->attach_btf_id;
        key = bpf_trampoline_compute_key(NULL, prog->aux->attach_btf, btf_id);
    }

    if (!prog->aux->dst_trampoline || (key && key != prog->aux->dst_trampoline->key)) {
        // 不存在保存的信息 或 指定的目标和加载阶段不同 时，创建新的trampoline
        struct bpf_attach_target_info tgt_info = {};
        // 检查附加目标
        err = bpf_check_attach_target(NULL, prog, tgt_prog, btf_id, &tgt_info);
        if (err) goto out_unlock;
        // 获取新的trampoline
        tr = bpf_trampoline_get(key, &tgt_info);
        if (!tr) { ... }
    } else {
        // 没有指定目标 或 同一个目标时，使用加载阶段的trampoline。
        // 只有在加载时候使用一次，`prog->aux`信息在后面清空
        tr = prog->aux->dst_trampoline;
        tgt_prog = prog->aux->dst_prog;
    }

    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link.link, &link_primer);
    if (err) goto out_unlock;

    // bpf_trampoline 关联 prog
    err = bpf_trampoline_link_prog(&link->link, tr);
    if (err) { ... }

    // link 属性设置
    link->tgt_prog = tgt_prog;
    link->trampoline = tr;

    ...
    // 清空 `prog->aux` 保存的 `trampoline` 和 `prog` 
    prog->aux->dst_prog = NULL;
    prog->aux->dst_trampoline = NULL;

    // fd 和 file 进行关联
    return bpf_link_settle(&link_primer);
    ...
}
```

### 4.2 `bpf_trampoline`的创建

#### 1 加载阶段创建的`trampoline`

在`bpf_tracing_prog_attach`函数中，我们需要检查 `prog->aux->dst_trampoline` 的状态来决定是否创建新的trampoline。`prog->aux` 保存了加载阶段的 `trampoline` 和 `prog` 信息，这些信息创建过程如下：

```C
// file: kernel/bpf/syscall.c
static int __sys_bpf(int cmd, bpfptr_t uattr, unsigned int size)
{
    ...
    switch (cmd) {
    ...
    case BPF_PROG_LOAD: err = bpf_prog_load(&attr, uattr); break;
    ...
    }
    return err;
}
```

在加载BPF程序过程中，需要验证BPF程序，在验证`BTF_ID`时，创建trampoline。如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_prog_load(union bpf_attr *attr, bpfptr_t uattr)
        // BPF程序验证
    --> err = bpf_check(&prog, attr, uattr);
            // 验证btf_id
        --> ret = check_attach_btf_id(env);
            --> struct bpf_prog *prog = env->prog;
            --> struct bpf_prog *tgt_prog = prog->aux->dst_prog;
            --> u32 btf_id = prog->aux->attach_btf_id;
                // 检查附加目标
            --> ret = bpf_check_attach_target(&env->log, prog, tgt_prog, btf_id, &tgt_info);
                // 计算key
            --> key = bpf_trampoline_compute_key(tgt_prog, prog->aux->attach_btf, btf_id);
                // 获取trampoline
            --> tr = bpf_trampoline_get(key, &tgt_info);
            --> prog->aux->dst_trampoline = tr;
```

#### 2 `trampoline`的创建过程

创建 `bpf_trampoline` 需要三个步骤：检查附加目标、计算key、获取trampoline。每个步骤对应一个函数，如下：

`bpf_check_attach_target` 函数检查附加目标，经过一系列检查后，最终得到附加目标。这其中最主要的是通过BTF信息获取名称后，确定对应的addr。如下：

```C
// file: kernel/bpf/verifier.c
int bpf_check_attach_target(struct bpf_verifier_log *log, const struct bpf_prog *prog,
        const struct bpf_prog *tgt_prog, u32 btf_id, struct bpf_attach_target_info *tgt_info)
{
    bool prog_extension = prog->type == BPF_PROG_TYPE_EXT;
    const char prefix[] = "btf_trace_";
    const struct btf_type *t;
    struct btf *btf;
    long addr = 0;
    ...

    // btf_id 必须存在
    if (!btf_id) { ... }
    // 获取 btf 信息
    btf = tgt_prog ? tgt_prog->aux->btf : prog->aux->attach_btf;
    if (!btf) { ... }
    // 获取 btf_id 对应的 btf_type 信息
    t = btf_type_by_id(btf, btf_id);
    if (!t) { ... }
    // 获取 btf_name 
    tname = btf_name_by_offset(btf, t->name_off);
    if (!tname) { ... }

    // 指定 prog 时，匹配性检查 
    if (tgt_prog) { ... }

    switch (prog->expected_attach_type) {
    ...
    case BPF_MODIFY_RETURN:
    case BPF_LSM_MAC:
    case BPF_LSM_CGROUP:
    case BPF_TRACE_FENTRY:
    case BPF_TRACE_FEXIT:
        // btf_type 必须是 函数（function）类型
        if (!btf_type_is_func(t)) { ... }
        // EXT类型BPF程序时需要检查BTF是否匹配
        if (prog_extension && btf_check_type_match(log, prog, btf, t)) { ... }
        // 检查 btf_type 原型，必须为函数原型（FUNC_PROTO）
        t = btf_type_by_id(btf, t->type);
        if (!btf_type_is_func_proto(t)) { ... }
        ...
        // 获取函数原型，参数个数、参数类型、返回参数类型
        ret = btf_distill_func_proto(log, btf, t, tname, &tgt_info->fmodel);
        if (ret < 0) return ret;

        // 获取`addr`信息
        if (tgt_prog) {
            if (subprog == 0)
                addr = (long) tgt_prog->bpf_func;
            else
                addr = (long) tgt_prog->aux->func[subprog]->bpf_func;
        } else {
            // 从 kallsyms 中获取符号名称对应的地址
            addr = kallsyms_lookup_name(tname);
            if (!addr) { ... }
        }

        // sleepable 检查
        if (prog->aux->sleepable) { ... }
        // MODIFY_RETURN 检查
        else if (prog->expected_attach_type == BPF_MODIFY_RETURN) { ... }

        break;
    }
    // 设置获取的目标属性
    tgt_info->tgt_addr = addr;
    tgt_info->tgt_name = tname;
    tgt_info->tgt_type = t;
    return 0;
}
```

`bpf_trampoline_compute_key` 计算trampoline的key，如下：

```C
// file: include/linux/bpf_verifier.h
static inline u64 bpf_trampoline_compute_key(const struct bpf_prog *tgt_prog,
                        struct btf *btf, u32 btf_id)
{
    if (tgt_prog)
        return ((u64)tgt_prog->aux->id << 32) | btf_id;
    else
        return ((u64)btf_obj_id(btf) << 32) | 0x80000000 | btf_id;
}
```

`bpf_trampoline_get` 函数根据key获取trampoline后，更新函数信息，如下：

```C
// file: kernel/bpf/trampoline.c
struct bpf_trampoline *bpf_trampoline_get(u64 key, struct bpf_attach_target_info *tgt_info)
{
    struct bpf_trampoline *tr;
    // 获取trampoline
    tr = bpf_trampoline_lookup(key);
    if (!tr) return NULL;

    mutex_lock(&tr->mutex);
    if (tr->func.addr) goto out;
    
    // 更新函数信息
    memcpy(&tr->func.model, &tgt_info->fmodel, sizeof(tgt_info->fmodel));
    tr->func.addr = (void *)tgt_info->tgt_addr;
out:
    mutex_unlock(&tr->mutex);
    return tr;
}
```

`bpf_trampoline_lookup` 首先从`trampoline_table`获取，存在相同的key表示该trampoline已存在，直接复用即可；否则，创建新的trampoline。如下：

```C
// file: kernel/bpf/trampoline.c
static struct bpf_trampoline *bpf_trampoline_lookup(u64 key)
{
    struct bpf_trampoline *tr;
    ...

    mutex_lock(&trampoline_mutex);
    head = &trampoline_table[hash_64(key, TRAMPOLINE_HASH_BITS)];
    hlist_for_each_entry(tr, head, hlist) {
        // 存在相同的key，说明trampoline已存在，增加引用计数即可
        if (tr->key == key) { refcount_inc(&tr->refcnt); goto out; }
    }

    // 创建trampoline
    tr = kzalloc(sizeof(*tr), GFP_KERNEL);
    if (!tr) goto out;
#ifdef CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
    tr->fops = kzalloc(sizeof(struct ftrace_ops), GFP_KERNEL);
    if (!tr->fops) { ...}
    tr->fops->private = tr;
    tr->fops->ops_func = bpf_tramp_ftrace_ops_func;
#endif

    tr->key = key;
    INIT_HLIST_NODE(&tr->hlist);
    // 添加到`trampoline_table`中
    hlist_add_head(&tr->hlist, head);
    refcount_set(&tr->refcnt, 1);
    mutex_init(&tr->mutex);
    for (i = 0; i < BPF_TRAMP_MAX; i++)
        INIT_HLIST_HEAD(&tr->progs_hlist[i]);
out:
    mutex_unlock(&trampoline_mutex);
    return tr;
}
```

Linux中定义了1K个hashtable，如下：

```C
// file: kernel/bpf/trampoline.c
#define TRAMPOLINE_HASH_BITS 10
#define TRAMPOLINE_TABLE_SIZE (1 << TRAMPOLINE_HASH_BITS)
static struct hlist_head trampoline_table[TRAMPOLINE_TABLE_SIZE];
```

`trampoline_table` 在`initcall`阶段初始化的，如下：

```C
// file: kernel/bpf/trampoline.c
static int __init init_trampolines(void)
{
    int i;
    for (i = 0; i < TRAMPOLINE_TABLE_SIZE; i++)
        INIT_HLIST_HEAD(&trampoline_table[i]);
    return 0;
}
late_initcall(init_trampolines);
```

### 4.3 关联BPF程序

#### 1 关联BPF程序接口

`bpf_trampoline_link_prog` 函数对 `__bpf_trampoline_link_prog` 进行了调用封装，后者实现如下：

```C
// file: kernel/bpf/trampoline.c
static int __bpf_trampoline_link_prog(struct bpf_tramp_link *link, struct bpf_trampoline *tr)
{
    enum bpf_tramp_prog_type kind;
    struct bpf_tramp_link *link_exiting;

    // 获取 trampoline 的类型，`FENTRY`,`MODIFY_RETURN`,`FEXIT`，`REPLACE` 中的一种
    kind = bpf_attach_type_to_tramp(link->link.prog);
    // 存在扩展的程序时直接退出
    if (tr->extension_prog) { ... }

    // 计算 trampoline 程序总量 
    for (i = 0; i < BPF_TRAMP_MAX; i++)
        cnt += tr->progs_cnt[i];
    
    // REPLACE 类型处理，设置扩展程序
    if (kind == BPF_TRAMP_REPLACE) {
        // `fentry/fexit` 使用时，不能附加扩展程序 
        if (cnt) return -EBUSY;
        tr->extension_prog = link->link.prog;
        // 直接修改调用
        return bpf_arch_text_poke(tr->func.addr, BPF_MOD_JUMP, NULL, link->link.prog->bpf_func);
    }
    // 检查数量限制，不能超过38个（s390x架构下为27个）
    if (cnt >= BPF_MAX_TRAMP_LINKS) return -E2BIG;

    // 检查 prog 是否已经链接，已链接时退出
    if (!hlist_unhashed(&link->tramp_hlist)) return -EBUSY;
    hlist_for_each_entry(link_exiting, &tr->progs_hlist[kind], tramp_hlist) { ... }
    
    // 添加到 progs_hlist 中
    hlist_add_head(&link->tramp_hlist, &tr->progs_hlist[kind]);
    tr->progs_cnt[kind]++;
    // 更新 trampoline
    err = bpf_trampoline_update(tr, true /* lock_direct_mutex */);
    ...
}
```

`bpf_attach_type_to_tramp` 函数获取`bpf`程序使用的`trampoline`类型，如下：

```C
// file: kernel/bpf/trampoline.c
static enum bpf_tramp_prog_type bpf_attach_type_to_tramp(struct bpf_prog *prog)
{
    switch (prog->expected_attach_type) {
    case BPF_TRACE_FENTRY: return BPF_TRAMP_FENTRY;
    case BPF_MODIFY_RETURN: return BPF_TRAMP_MODIFY_RETURN;
    case BPF_TRACE_FEXIT: return BPF_TRAMP_FEXIT;
    case BPF_LSM_MAC:
        if (!prog->aux->attach_func_proto->type) 
            return BPF_TRAMP_FEXIT;
        else
            return BPF_TRAMP_MODIFY_RETURN;
    default: return BPF_TRAMP_REPLACE;
    }
}
```

`bpf_trampoline`包含4中类型，使用`bpf_tramp_prog_type` 枚举表示，类型定义如下：

```C
// file: include/linux/bpf.h
enum bpf_tramp_prog_type {
    BPF_TRAMP_FENTRY,
    BPF_TRAMP_FEXIT,
    BPF_TRAMP_MODIFY_RETURN,
    BPF_TRAMP_MAX,
    BPF_TRAMP_REPLACE, /* more than MAX */
};
```

`bpf_trampoline` 结构中只使用前三种类型，如下：

```C
// file: include/linux/bpf.h
struct bpf_trampoline {
    ...
    struct hlist_head progs_hlist[BPF_TRAMP_MAX];
    int progs_cnt[BPF_TRAMP_MAX];
    ...
};
```

即，只有`FENTRY`,`FEXIT`,`MODIFY_RETURN`这三种类型才能设置BPF程序，`REPLACE`类型替换当前的调用程序。

#### 2 `REPLACE`方式修改跳转指令

`BPF_PROG_TYPE_EXT`类型的程序对应`BPF_TRAMP_REPLACE`类型，直接修改跳转指令。如下：

```C
// file: kernel/bpf/trampoline.c
static int __bpf_trampoline_link_prog(struct bpf_tramp_link *link, struct bpf_trampoline *tr)
{
    ....
    if (kind == BPF_TRAMP_REPLACE) {
        // `fentry/fexit` 使用时，不能附加扩展程序 
        if (cnt) return -EBUSY;
        tr->extension_prog = link->link.prog;
        // 直接修改调用
        return bpf_arch_text_poke(tr->func.addr, BPF_MOD_JUMP, NULL, link->link.prog->bpf_func);
    }
    ...
}
```

`bpf_arch_text_poke` 函数对调用地址进行检查后，调用 `__bpf_arch_text_poke` 进行修改，如下：

```C
// file: arch/x86/net/bpf_jit_comp.c
int bpf_arch_text_poke(void *ip, enum bpf_text_poke_type t, void *old_addr, void *new_addr)
{
    // 检查`ip`是否在内核中，不支持module调用修改
    if (!is_kernel_text((long)ip) && !is_bpf_text_address((long)ip))
        return -EINVAL;
    // 跳过`ENDBR`指令，ENDBR:分支结束指令
    if (is_endbr(*(u32 *)ip)) ip += ENDBR_INSN_SIZE;
    return __bpf_arch_text_poke(ip, t, old_addr, new_addr);
}
```

`__bpf_arch_text_poke` 函数生成调用指令后替换，支持`call`和`jump`两种类型指令的修改，如下：

```C
// file: arch/x86/net/bpf_jit_comp.c
static int __bpf_arch_text_poke(void *ip, enum bpf_text_poke_type t, 
                void *old_addr, void *new_addr)
{
    const u8 *nop_insn = x86_nops[5];
    u8 old_insn[X86_PATCH_SIZE];
    u8 new_insn[X86_PATCH_SIZE];
    u8 *prog;
    int ret;

    // 生成旧的调用指令
    memcpy(old_insn, nop_insn, X86_PATCH_SIZE);
    if (old_addr) {
        prog = old_insn;
        ret = t == BPF_MOD_CALL ? 
            emit_call(&prog, old_addr, ip) : emit_jump(&prog, old_addr, ip);
        if (ret) return ret;
    }

    // 生成新的调用指令
    memcpy(new_insn, nop_insn, X86_PATCH_SIZE);
    if (new_addr) { 
        prog = new_insn;
        ret = t == BPF_MOD_CALL ?
            emit_call(&prog, new_addr, ip) : emit_jump(&prog, new_addr, ip);
        if (ret) return ret;
    }

    ret = -EBUSY;
    mutex_lock(&text_mutex);
    // 当前指令内容和旧指令内容不同时退出
    if (memcmp(ip, old_insn, X86_PATCH_SIZE)) goto out;
    ret = 1;
    // 当前指令内容和新指令内容不同时替换
    if (memcmp(ip, new_insn, X86_PATCH_SIZE)) {
        // 替换为新的调用指令
        text_poke_bp(ip, new_insn, X86_PATCH_SIZE, NULL);
        ret = 0;
    }
out:
    mutex_unlock(&text_mutex);
    return ret;
}
```

#### 3 更新`bpf_trampoline`

`FENTRY`,`FEXIT`,`MODIFY_RETURN`使用`bpf_trampoline`。`bpf_trampoline`关联的BPF程序有变化时，需要更新trampoline，`bpf_trampoline_update` 函数实现该功能，该函数包含注册和注销两个过程，我们目前关注注册过程。如下：

```C
// file: kernel/bpf/trampoline.c
static int bpf_trampoline_update(struct bpf_trampoline *tr, bool lock_direct_mutex)
{
    struct bpf_tramp_image *im;
    struct bpf_tramp_links *tlinks;
    u32 orig_flags = tr->flags;
    
    // 获取 trampoline 中 prog数量、tramp_links 信息
    tlinks = bpf_trampoline_get_progs(tr, &total, &ip_arg);
    if (IS_ERR(tlinks)) return PTR_ERR(tlinks);

    // prog数量为0时，释放trampoline
    if (total == 0) {
        err = unregister_fentry(tr, tr->cur_image->image);
        bpf_tramp_image_put(tr->cur_image);
        tr->cur_image = NULL;
        tr->selector = 0;
        goto out;
    }

    // 分配 tramp_image
    im = bpf_tramp_image_alloc(tr->key, tr->selector);
    if (IS_ERR(im)) { ... }

    // 仅保留 SHARE_IPMODIFY 标志
    tr->flags &= BPF_TRAMP_F_SHARE_IPMODIFY;

    // RESTORE_REGS 标志表示 从trampoline中恢复，继续执行原来的函数。只适用于只有 `fentry` 的情况。
    // CALL_ORIG 标志表示 在`fentry`之后，`fexit`之前，调用原始的函数
    // SKIP_FRAME 标志表示 跳过当前的函数栈直接返回到上一级调用。只适用于 `fentry/fexit` 类型
    if (tlinks[BPF_TRAMP_FEXIT].nr_links ||
        tlinks[BPF_TRAMP_MODIFY_RETURN].nr_links) {
        tr->flags |= BPF_TRAMP_F_CALL_ORIG | BPF_TRAMP_F_SKIP_FRAME;
    } else {
        tr->flags |= BPF_TRAMP_F_RESTORE_REGS;
    }

    // 设置`IP_ARG`标志，保留调用者ip地址
    if (ip_arg)
        tr->flags |= BPF_TRAMP_F_IP_ARG;

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
again:
    // 设置 `ORIG_STACK`标志， fexit/fmod_ret 程序类型时，可以从栈中获取原始的函数地址，替换默认的直接地址方式
    if ((tr->flags & BPF_TRAMP_F_SHARE_IPMODIFY) &&
        (tr->flags & BPF_TRAMP_F_CALL_ORIG))
        tr->flags |= BPF_TRAMP_F_ORIG_STACK;
#endif

    // 生成 bpf_trampoline 代码  
    err = arch_prepare_bpf_trampoline(im, im->image, im->image + PAGE_SIZE,
                    &tr->func.model, tr->flags, tlinks, tr->func.addr);
    if (err < 0) goto out;

    // 设置 trampoline 镜像权限，读和执行权限
    set_memory_rox((long)im->image, 1);

    if (tr->cur_image)
        // 当前地址有程序运行时，修改`fentry`
        err = modify_fentry(tr, tr->cur_image->image, im->image, lock_direct_mutex);
    else
        // 第一次运行时，注册`fentry`
        err = register_fentry(tr, im->image);

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
    // bpf_tramp_ftrace_ops_func 调用出错时，重新注册trampoline
    if (err == -EAGAIN) {
        // 重置 fops->func 和 fops->trampoline 
        tr->fops->func = NULL;
        tr->fops->trampoline = 0;
        // 重置 im->image 属性
        set_memory_nx((long)im->image, 1);
        set_memory_rw((long)im->image, 1);
        goto again;
    }
#endif

    // 释放并设置当前的image
    if (tr->cur_image) bpf_tramp_image_put(tr->cur_image);
    tr->cur_image = im;
    tr->selector++;

out:
    // 出现错误时，恢复之前的标志
    if (err) tr->flags = orig_flags;
    kfree(tlinks);
    return err;
}
```

`bpf_tramp_image_alloc` 函数创建存放`trampoline`的内存空间，如下：

```C
// file: kernel/bpf/trampoline.c
static struct bpf_tramp_image *bpf_tramp_image_alloc(u64 key, u32 idx)
{
    struct bpf_tramp_image *im;
    struct bpf_ksym *ksym;
    void *image;
    int err = -ENOMEM;

`   // 创建`tramp_image`结构
    im = kzalloc(sizeof(*im), GFP_KERNEL);
    if (!im) goto out;

    // 检查`jit`使用配额限制
    err = bpf_jit_charge_modmem(PAGE_SIZE);
    if (err) goto out_free_im;

    err = -ENOMEM;
    // 创建image使用的内存页
    im->image = image = bpf_jit_alloc_exec(PAGE_SIZE);
    if (!image) goto out_uncharge;
    set_vm_flush_reset_perms(image);

    // 设置`tramp_image`释放接口
    err = percpu_ref_init(&im->pcref, __bpf_tramp_image_release, 0, GFP_KERNEL);
    if (err) goto out_free_image;

    // 设置`image`符号，并添加到系统中
    ksym = &im->ksym;
    INIT_LIST_HEAD_RCU(&ksym->lnode);
    snprintf(ksym->name, KSYM_NAME_LEN, "bpf_trampoline_%llu_%u", key, idx);
    bpf_image_ksym_add(image, ksym);
    return im;
    ...
}
```

#### 4 生成`bpf_trampoline`代码

`arch_prepare_bpf_trampoline`函数生成`trampoline`的执行代码。将 `FENTRY`, `FEXIT`, `MODIFY_RETURN` 三种类型的BPF程序和原始调用的程序按照调用关系生成对应的汇编代码，如下：

```C
// file: arch/x86/net/bpf_jit_comp.c
int arch_prepare_bpf_trampoline(struct bpf_tramp_image *im, void *image, void *image_end,
                const struct btf_func_model *m, u32 flags,
                struct bpf_tramp_links *tlinks, void *func_addr)
{
    int i, ret, nr_regs = m->nr_args, stack_size = 0;
    int regs_off, nregs_off, ip_off, run_ctx_off;
    struct bpf_tramp_links *fentry = &tlinks[BPF_TRAMP_FENTRY];
    struct bpf_tramp_links *fexit = &tlinks[BPF_TRAMP_FEXIT];
    struct bpf_tramp_links *fmod_ret = &tlinks[BPF_TRAMP_MODIFY_RETURN];
    void *orig_call = func_addr;
    u8 **branches = NULL;
    u8 *prog;
    bool save_ret;

    // struct 结构使用额外的寄存器数量
    for (i = 0; i < m->nr_args; i++)
        if (m->arg_flags[i] & BTF_FMODEL_STRUCT_ARG)
            nr_regs += (m->arg_size[i] + 7) / 8 - 1;

    // x86_64架构通过寄存器最多传递6个参数值
    if (nr_regs > 6) return -ENOTSUPP;

    // 预留 `fentry` 或 `orig_call` 返回值
    save_ret = flags & (BPF_TRAMP_F_CALL_ORIG | BPF_TRAMP_F_RET_FENTRY_RET);
    if (save_ret) 
        stack_size += 8;
    
    stack_size += nr_regs * 8;
    regs_off = stack_size;

    // 参数值占用的大小
    stack_size += 8;
    nregs_off = stack_size;

    // 预留IP寄存器空间
    if (flags & BPF_TRAMP_F_IP_ARG)
        stack_size += 8; 

    ip_off = stack_size;

    stack_size += (sizeof(struct bpf_tramp_run_ctx) + 7) & ~0x7;
    run_ctx_off = stack_size;

    // orig_call 的实际地址
    if (flags & BPF_TRAMP_F_SKIP_FRAME) {
        if (is_endbr(*(u32 *)orig_call))
            orig_call += ENDBR_INSN_SIZE;
        orig_call += X86_PATCH_SIZE;
    }

    prog = image;

    EMIT_ENDBR();
    // 直接调用的trampoline，需要 `__fentry__` 调用
    x86_call_depth_emit_accounting(&prog, NULL);
    EMIT1(0x55);    /* push rbp */
    EMIT3(0x48, 0x89, 0xE5); /* mov rbp, rsp */
    EMIT4(0x48, 0x83, 0xEC, stack_size); /* sub rsp, stack_size */
    EMIT1(0x53);    /* push rbx */

    // 保存追踪函数的参数计数器数量，对应汇编如下：
    //  mov rax, nr_regs
    //  mov QWORD PTR [rbp - nregs_off], rax
    emit_mov_imm64(&prog, BPF_REG_0, 0, (u32) nr_regs);
    emit_stx(&prog, BPF_DW, BPF_REG_FP, BPF_REG_0, -nregs_off);

    // 保存追踪函数的执行位置，
    if (flags & BPF_TRAMP_F_IP_ARG) {
        // movabsq rax, func_addr
        // mov QWORD PTR [rbp - ip_off], rax
        emit_mov_imm64(&prog, BPF_REG_0, (long) func_addr >> 32, (u32) (long) func_addr);
        emit_stx(&prog, BPF_DW, BPF_REG_FP, BPF_REG_0, -ip_off);
    }

    // 保存传递的参数信息
    save_regs(m, &prog, nr_regs, regs_off);

    // 调用原始函数时，开始阶段调用 `__bpf_tramp_enter`
    if (flags & BPF_TRAMP_F_CALL_ORIG) {
        // `__bpf_tramp_enter`，只需要一个参数 arg1: mov rdi, im
        emit_mov_imm64(&prog, BPF_REG_1, (long) im >> 32, (u32) (long) im);
        if (emit_rsb_call(&prog, __bpf_tramp_enter, prog)) {
            ret = -EINVAL;
            goto cleanup;
        }
    }
    
    // fentry BPF函数调用
    if (fentry->nr_links)
        // `invoke_bpf`对每个prog调用`invoke_bpf_prog`生成调用代码， 生成类似下面的代码：
        // call __bpf_prog_enter
        // call addr_of_jited_FENTRY_prog
        // call __bpf_prog_exit
        if (invoke_bpf(m, &prog, fentry, regs_off, run_ctx_off,
                    flags & BPF_TRAMP_F_RET_FENTRY_RET))
        return -EINVAL;

    // fmod_ret BPF函数调用
    if (fmod_ret->nr_links) {
        branches = kcalloc(fmod_ret->nr_links, sizeof(u8 *), GFP_KERNEL);
        if (!branches) return -ENOMEM;
        // branches 记录返回值判断的地址，生成类似下面的代码：
        // call __bpf_prog_enter
        // call addr_of_jited_FMED_RET_prog
        // call __bpf_prog_exit
        // if (*(u64 *)(rbp - 8) !=  0)
        //    goto do_fexit;
        if (invoke_bpf_mod_ret(m, &prog, fmod_ret, regs_off, run_ctx_off, branches)) {
            ret = -EINVAL;
            goto cleanup;
        }
    }

    // 原始函数调用
    if (flags & BPF_TRAMP_F_CALL_ORIG) {
        restore_regs(m, &prog, nr_regs, regs_off);

        if (flags & BPF_TRAMP_F_ORIG_STACK) {
            // 从栈上获取函数地址，存放到 rax 寄存器中
            emit_ldx(&prog, BPF_DW, BPF_REG_0, BPF_REG_FP, 8);
            EMIT2(0xff, 0xd0); /* call *rax */
        } else {
            // 调用原来的函数
            if (emit_rsb_call(&prog, orig_call, prog)) {
                ret = -EINVAL;
                goto cleanup;
            }
        }
        // 保存返回值到栈上，bpf程序能够访问
        emit_stx(&prog, BPF_DW, BPF_REG_FP, BPF_REG_0, -8);
        im->ip_after_call = prog;
        memcpy(prog, x86_nops[5], X86_PATCH_SIZE);
        prog += X86_PATCH_SIZE;
    }

    // fmod_ret 分支判断代码生成
    if (fmod_ret->nr_links) {
        emit_align(&prog, 16);
        // 更新记录 invoke_bpf_mod_ret 保存的分支信息
        for (i = 0; i < fmod_ret->nr_links; i++)
            emit_cond_near_jump(&branches[i], prog, branches[i], X86_JNE);
    }

    // fexit BPF函数调用
    if (fexit->nr_links)
        if (invoke_bpf(m, &prog, fexit, regs_off, run_ctx_off, false)) {
            ret = -EINVAL;
            goto cleanup;
        }
    
    // 恢复寄存器值 
    if (flags & BPF_TRAMP_F_RESTORE_REGS)
        restore_regs(m, &prog, nr_regs, regs_off);

    // 调用原始函数时，结束阶段调用 `__bpf_tramp_exit`
    if (flags & BPF_TRAMP_F_CALL_ORIG) {
        im->ip_epilogue = prog;
        emit_mov_imm64(&prog, BPF_REG_1, (long) im >> 32, (u32) (long) im);
        if (emit_rsb_call(&prog, __bpf_tramp_exit, prog)) {
            ret = -EINVAL;
            goto cleanup;
        }
    }
    
    // 恢复`fentry` 或 `orig_call` 返回值
    if (save_ret)
        emit_ldx(&prog, BPF_DW, BPF_REG_0, BPF_REG_FP, -8);

    EMIT1(0x5B); /* pop rbx */
    EMIT1(0xC9); /* leave */
    // 跳过返回地址，直接返回到上一级调用
    if (flags & BPF_TRAMP_F_SKIP_FRAME)
        EMIT4(0x48, 0x83, 0xC4, 8); /* add rsp, 8 */
    emit_return(&prog, prog);
    // 确保 trampoline 生成的代码不会溢出
    if (WARN_ON_ONCE(prog > (u8 *)image_end - BPF_INSN_SAFETY)) {
        ret = -EFAULT;
        goto cleanup;
    }
    ret = prog - (u8 *)image;

cleanup:
    kfree(branches);
    return ret;
}
```

#### 5 注册`fentry`

在`bpf_trampoline`第一次使用时，进行注册。`register_fentry`函数实现该功能，在获取`addr`对应的动态事件(`dyn_event`)的函数地址后，通过注册`ftrace_ops`直接调用方式修改调用指令，如下：

```C
// file: kernel/bpf/trampoline.c
static int register_fentry(struct bpf_trampoline *tr, void *new_addr)
{
    void *ip = tr->func.addr;
    unsigned long faddr;
    int ret;

    // 获取`dyn_event`的地址
    faddr = ftrace_location((unsigned long)ip);
    if (faddr) {
        if (!tr->fops)
            return -ENOTSUPP;
        tr->func.ftrace_managed = true;
    }
    // 检查`tr->func.addr`对应的module是否能够访问
    if (bpf_trampoline_module_get(tr))
        return -ENOENT;

    if (tr->func.ftrace_managed) {
        // ftrace_ops 方式修改直接调用 
        ftrace_set_filter_ip(tr->fops, (unsigned long)ip, 0, 1);
        ret = register_ftrace_direct_multi(tr->fops, (long)new_addr);
    } else {
        ret = bpf_arch_text_poke(ip, BPF_MOD_CALL, NULL, new_addr);
    }
    // 失败时释放资源
    if (ret) bpf_trampoline_module_put(tr);
    return ret;
}
```

我们需要将BPF程序挂载到动态事件下，`ftrace_set_filter_ip` 函数获取动态事件到`filter_hash`中后。 `register_ftrace_direct_multi` 函数注册直接调用事件，修改动态事件调用指令，如下：

```C
// file: kernel/trace/ftrace.c
int register_ftrace_direct_multi(struct ftrace_ops *ops, unsigned long addr)
{
    ...
    hash = ops->func_hash->filter_hash;

    // 确保`filter_hash`中的`dyn_event`未注册
    size = 1 << hash->size_bits;
    for (i = 0; i < size; i++) {
        hlist_for_each_entry(entry, &hash->buckets[i], hlist) {
            if (ftrace_find_rec_direct(entry->ip))
                goto out_unlock;
        }
    }
    // 添加到 `direct_functions` 中
    err = -ENOMEM;
    for (i = 0; i < size; i++) {
        hlist_for_each_entry(entry, &hash->buckets[i], hlist) {
            new = ftrace_add_rec_direct(entry->ip, addr, &free_hash);
            if (!new) goto out_remove;
            entry->direct = addr;
        }
    }

    // ops 属性设置
    ops->func = call_direct_funcs;
    ops->flags = MULTI_FLAGS;
    ops->trampoline = FTRACE_REGS_ADDR;

    // 注册 ftrace_ops
    err = register_ftrace_function_nolock(ops);
    ...
}
```

#### 6 修改`fentry`

在`bpf_trampoline`已经使用时，需要修改已注册的动态事件的调用指令，`modify_fentry` 函数实现该功能。如下：

```C
// file: kernel/bpf/trampoline.c
static int modify_fentry(struct bpf_trampoline *tr, void *old_addr, void *new_addr,
        bool lock_direct_mutex)
{
    void *ip = tr->func.addr;
    int ret;

    if (tr->func.ftrace_managed) {
        if (lock_direct_mutex)
            ret = modify_ftrace_direct_multi(tr->fops, (long)new_addr);
        else
            ret = modify_ftrace_direct_multi_nolock(tr->fops, (long)new_addr);
    } else {
        ret = bpf_arch_text_poke(ip, BPF_MOD_CALL, old_addr, new_addr);
    }
    return ret;
}
```

`modify_ftrace_direct_multi` 和 `modify_ftrace_direct_multi_nolock` 函数是对 `__modify_ftrace_direct_multi` 进行不同的封装，`__modify_ftrace_direct_multi` 函数实现如下：

```C
// file: kernel/trace/ftrace.c
static int __modify_ftrace_direct_multi(struct ftrace_ops *ops, unsigned long addr)
{
    struct ftrace_hash *hash;
    struct ftrace_func_entry *entry, *iter;
    static struct ftrace_ops tmp_ops = {
        .func   = ftrace_stub,
        .flags  = FTRACE_OPS_FL_STUB,
    };
    
    lockdep_assert_held_once(&direct_mutex);

    // tmp_ops 和 ops 有同样的函数
    ftrace_ops_init(&tmp_ops);
    tmp_ops.func_hash = ops->func_hash;

    // 注册 tmp_ops，注册成功后，ops 中直接调用的函数，将调用目标修改为 `ftrace_ops_list_func()`
    err = register_ftrace_function_nolock(&tmp_ops);
    if (err) return err;

    mutex_lock(&ftrace_lock);

    // 修改直接调用地址
    hash = ops->func_hash->filter_hash;
    size = 1 << hash->size_bits;
    for (i = 0; i < size; i++) {
        hlist_for_each_entry(iter, &hash->buckets[i], hlist) {
            entry = __ftrace_lookup_ip(direct_functions, iter->ip);
            if (!entry) continue;
            entry->direct = addr;
        }
    }

    mutex_unlock(&ftrace_lock);

    // 注销 tmp_ops，更新直接调用的函数
    unregister_ftrace_function(&tmp_ops);
    return err;
}
```

#### 7 动态事件调用变化情况

`ftrace_ops` 在注册( `register_ftrace_function_nolock` ) 和 注销( `unregister_ftrace_function` ) 过程中调用 `ftrace_replace_code` 函数更新 `dyn_event` 的调用信息，通过 `ftrace_get_addr_new()` 函数获取新的调用地址，实现如下：

```C
// file: kernel/trace/ftrace.c
unsigned long ftrace_get_addr_new(struct dyn_ftrace *rec)
{
    struct ftrace_ops *ops;
    unsigned long addr;

    // 直接调用时，获取地址。在`register_fentry`或`modify_fentry`中注销`tmp_ops`时使用
    if ((rec->flags & FTRACE_FL_DIRECT) && (ftrace_rec_count(rec) == 1)) {
        addr = ftrace_find_rec_direct(rec->ip);
        if (addr) return addr;
        WARN_ON_ONCE(1);
    }

    // 获取`trampoline`地址。在`modify_fentry`中注册`tmp_ops`时使用
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

### 4.4 分离BPF程序

#### 1 `bpf_link_fops`接口

在附加BPF程序过程中，设置了用户控件操作`bpf_link`的文件接口，如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_tracing_prog_attach(struct bpf_prog *prog,
                int tgt_prog_fd, u32 btf_id, u64 bpf_cookie)
{
    ...
    err = bpf_link_prime(&link->link.link, &link_primer);
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

`bpf_link_release` 函数释放`link`资源，通过 `bpf_link_put` 函数最终调用`bpf_link_free` 函数。`bpf_link_free` 实现如下：

```C
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

#### 2 `bpf_tracing_link_lops`接口

`bpf_tracing_link_lops` 是我们设置的`link->ops`，如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_tracing_prog_attach(struct bpf_prog *prog,
                int tgt_prog_fd, u32 btf_id, u64 bpf_cookie)
{
    ...
    bpf_link_init(&link->link.link, BPF_LINK_TYPE_TRACING, &bpf_tracing_link_lops, prog);
    link->attach_type = prog->expected_attach_type;
    link->link.cookie = bpf_cookie;
    ...
}
```

定义如下：

```C
// file: kernel/bpf/syscall.c
static const struct bpf_link_ops bpf_tracing_link_lops = {
    .release = bpf_tracing_link_release,
    .dealloc = bpf_tracing_link_dealloc,
    .show_fdinfo = bpf_tracing_link_show_fdinfo,
    .fill_link_info = bpf_tracing_link_fill_link_info,
};
```

`.release`接口释放`bpf_link`关联的程序。`bpf_tracing_link_release` 函数释放`tr_link`, 如下：

```C
// file: kernel/bpf/syscall.c
static void bpf_tracing_link_release(struct bpf_link *link)
{
    struct bpf_tracing_link *tr_link = container_of(link, struct bpf_tracing_link, link.link);
    // unlink prog
    WARN_ON_ONCE(bpf_trampoline_unlink_prog(&tr_link->link, tr_link->trampoline));
    // 释放 trampoline
    bpf_trampoline_put(tr_link->trampoline);
    // 释放 tgt_prog
    if (tr_link->tgt_prog) bpf_prog_put(tr_link->tgt_prog);
}
```

#### 3 分离BPF程序

`bpf_trampoline_unlink_prog` 函数是对 `__bpf_trampoline_unlink_prog` 的调用封装，后者实现如下：

```C
// file: kernel/bpf/trampoline.c
static int __bpf_trampoline_unlink_prog(struct bpf_tramp_link *link, struct bpf_trampoline *tr)
{
    enum bpf_tramp_prog_type kind;
    int err;

    kind = bpf_attach_type_to_tramp(link->link.prog);
    
    // REPLACE类型时，替换BPF调用
    if (kind == BPF_TRAMP_REPLACE) {
        WARN_ON_ONCE(!tr->extension_prog);
        err = bpf_arch_text_poke(tr->func.addr, BPF_MOD_JUMP, tr->extension_prog->bpf_func, NULL);
        tr->extension_prog = NULL;
        return err;
    }
    // 从hash中删除link，减少计数后更新trampoline
    hlist_del_init(&link->tramp_hlist);
    tr->progs_cnt[kind]--;
    return bpf_trampoline_update(tr, true /* lock_direct_mutex */);
}
```

`REPLACE`类型的程序同样使用 `bpf_arch_text_poke` 函数直接修改调用内容。其他类型的程序，在从`bpf_trampoline`中删除和修改程序计数之后，调用 `bpf_trampoline_update` 函数更新调用代码。我们现在关注释放过程，如下：

```C
// file: kernel/bpf/trampoline.c
static int bpf_trampoline_update(struct bpf_trampoline *tr, bool lock_direct_mutex)
{
    // 获取 trampoline 中 prog数量、tramp_links 信息
    tlinks = bpf_trampoline_get_progs(tr, &total, &ip_arg);
    if (IS_ERR(tlinks)) return PTR_ERR(tlinks);

    // prog数量为0时，释放trampoline
    if (total == 0) {
        err = unregister_fentry(tr, tr->cur_image->image);
        bpf_tramp_image_put(tr->cur_image);
        tr->cur_image = NULL;
        tr->selector = 0;
        goto out;
    }
    ...
}
```

#### 4 注销`fentry`

`unregister_fentry` 函数注销调用`bpf_trampoline`使用者，如下：

```C
// file: kernel/bpf/trampoline.c
static int unregister_fentry(struct bpf_trampoline *tr, void *old_addr)
{
    void *ip = tr->func.addr;
    int ret;

    if (tr->func.ftrace_managed)
        ret = unregister_ftrace_direct_multi(tr->fops, (long)old_addr);
    else
        ret = bpf_arch_text_poke(ip, BPF_MOD_CALL, old_addr, NULL);

    if (!ret) bpf_trampoline_module_put(tr);
    return ret;
}
```

`unregister_ftrace_direct_multi` 函数注销`ftrace_ops`后，从 `direct_functions` 中删除直接调用。实现如下：

```C
// file: kernel/trace/ftrace.c
int unregister_ftrace_direct_multi(struct ftrace_ops *ops, unsigned long addr)
{
    struct ftrace_hash *hash = ops->func_hash->filter_hash;
    ...

    mutex_lock(&direct_mutex);
    // 注销`ftrace_ops`, `filter_hash`中的`dyn_event`将调用修改为nop
    err = unregister_ftrace_function(ops);
    // 从`direct_functions`中移除
    remove_direct_functions_hash(hash, addr);
    mutex_unlock(&direct_mutex);

    // 清理设置，后续可能使用
    ops->func = NULL;
    ops->trampoline = 0;
    return err;
}
```

#### 5 释放`tramp_image`

在注销调用`bpf_trampoline`使用者后，释放tramp_image。`bpf_tramp_image_put` 函数实现该功能，如下：

```C
// file: kernel/bpf/trampoline.c
static void bpf_tramp_image_put(struct bpf_tramp_image *im)
{
    if (im->ip_after_call) {
        int err = bpf_arch_text_poke(im->ip_after_call, BPF_MOD_JUMP, NULL, im->ip_epilogue);
        WARN_ON(err);
        if (IS_ENABLED(CONFIG_PREEMPTION))
            call_rcu_tasks(&im->rcu, __bpf_tramp_image_put_rcu_tasks);
        else
            percpu_ref_kill(&im->pcref);
        return;
    }
    call_rcu_tasks_trace(&im->rcu, __bpf_tramp_image_put_rcu_tasks);
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
$ make fentry 
$ sudo ./fentry 
libbpf: loading object 'fentry_bpf' from buffer
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

##### (1) fentry/fexit同时存在的情况

附加BPF程序后查看`do_unlinkat`函数反汇编代码：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	call   0xffffffffc0229000
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
```


此时，将nop指令替换为`call 0xffffffffc0229000` 指令。`0xffffffffc0229000` 即 `bpf_trampoline` 地址。

在gdb中通过`x/i`查看对应的汇编代码，如下：

```bash
(gdb) x/100i 0xffffffffc0229000
   0xffffffffc0229000:	push   %rbp
   0xffffffffc0229001:	mov    %rsp,%rbp
   0xffffffffc0229004:	sub    $0x30,%rsp
   0xffffffffc0229008:	push   %rbx
   ...
   0xffffffffc0229023:	call   0xffffffff81309b70 <__bpf_tramp_enter>
   ...
   0xffffffffc022903c:	call   0xffffffff81309050 <__bpf_prog_enter_recur>
   ...
   0xffffffffc022904d:	call   0xffffffffc000ee0c // fentry
   ...
   0xffffffffc0229063:	call   0xffffffff81309320 <__bpf_prog_exit_recur>
   0xffffffffc0229068:	mov    -0x18(%rbp),%edi
   0xffffffffc022906b:	mov    -0x10(%rbp),%rsi
   0xffffffffc022906f:	call   0xffffffff814935b5 <do_unlinkat+5>
   ...
   0xffffffffc0229091:	call   0xffffffff81309050 <__bpf_prog_enter_recur>
   ...
   0xffffffffc02290a2:	call   0xffffffffc000ef68 // fexit
   ...
   0xffffffffc02290b8:	call   0xffffffff81309320 <__bpf_prog_exit_recur>
   ...
   0xffffffffc02290c7:	call   0xffffffff81309bd0 <__bpf_tramp_exit>
   ...
   0xffffffffc02290d2:	add    $0x8,%rsp
   0xffffffffc02290d6:	ret    
   0xffffffffc02290d7:	int3
   ...  
```

可以看到，在 `fentry`BPF程序 和 `fexit`BPF程序之间调用 `<do_unlinkat+5>` 函数，在执行`ret`指令之前修改`%rsp`寄存器位置。

##### (2) 只存在fentry的情况

修改`fentry.bpf.c`文件，只保留`do_unlinkat`BPF程序，重新编译后运行，查看反汇编情况如下：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	call   0xffffffffc0227000
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
(gdb) x/100i 0xffffffffc0227000
   0xffffffffc0227000:	push   %rbp
   0xffffffffc0227001:	mov    %rsp,%rbp
   0xffffffffc0227004:	sub    $0x28,%rsp
   0xffffffffc0227008:	push   %rbx
   ...
   0xffffffffc022702d:	call   0xffffffff81309050 <__bpf_prog_enter_recur>
   ...
   0xffffffffc022703e:	call   0xffffffffc000ee94
   ...
   0xffffffffc0227054:	call   0xffffffff81309320 <__bpf_prog_exit_recur>
   ...
   0xffffffffc0227060:	pop    %rbx
   0xffffffffc0227061:	leave  
   0xffffffffc0227062:	ret    
   0xffffffffc0227063:	int3
   ...   
```

可以看到，在`fentry`BPF程序执行完成后调用`ret`指令，返回之前的位置（`<do_unlinkat+5>`）继续执行。

##### (3) 只存在fexit的情况

修改`fentry.bpf.c`文件，只保留`do_unlinkat_exit`BPF程序，重新编译后运行，查看反汇编情况如下：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	call   0xffffffffc0229000
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
(gdb) x/100i 0xffffffffc0229000
   0xffffffffc0229000:	push   %rbp
   0xffffffffc0229001:	mov    %rsp,%rbp
   0xffffffffc0229004:	sub    $0x30,%rsp
   0xffffffffc0229008:	push   %rbx
   ...
   0xffffffffc0229023:	call   0xffffffff81309b70 <__bpf_tramp_enter>
   0xffffffffc0229028:	mov    -0x18(%rbp),%edi
   0xffffffffc022902b:	mov    -0x10(%rbp),%rsi
   0xffffffffc022902f:	call   0xffffffff814935b5 <do_unlinkat+5>
   ...
   0xffffffffc0229051:	call   0xffffffff81309050 <__bpf_prog_enter_recur>
   ...
   0xffffffffc0229062:	call   0xffffffffc000ef58
   ...
   0xffffffffc0229078:	call   0xffffffff81309320 <__bpf_prog_exit_recur>
   0xffffffffc022907d:	movabs $0xffff888109951000,%rdi
   0xffffffffc0229087:	call   0xffffffff81309bd0 <__bpf_tramp_exit>
   0xffffffffc022908c:	mov    -0x8(%rbp),%rax
   0xffffffffc0229090:	pop    %rbx
   0xffffffffc0229091:	leave  
   0xffffffffc0229092:	add    $0x8,%rsp
   0xffffffffc0229096:	ret    
   0xffffffffc0229097:	int3   
   ...
```

可以看到，在执行 `<do_unlinkat+5>` 函数后，执行`fexit`BPF程序，在执行`ret`指令之前修改`%rsp`寄存器位置。

#### 3 清理BPF程序后

在qemu中退出`fentry`程序后，查看`do_unlinkat` 的反汇编代码，重新设置为nop指令，如下：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	nopl   0x0(%rax,%rax,1)
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
```

## 5 总结

本文通过`fentry`示例程序分析了`fentry/fexit`的内核实现过程。

`fentry/fexit` 和 `kprobe/kretprobe` 程序一样，用于在`Linux`内核函数的入口和退出处进行跟踪。与`kprobe/kretprobe`相比，`fentry/fexit` 程序有更高的性能和可用性。`fentry/fexit`程序可以直接访问函数的参数，而不需要使用读取帮助程序，`fexit` 程序可以访问函数的输入参数和返回值，而`kretprobe`只能访问返回值。

剩余两种类型前缀，`freplace`前缀用于BPF程序之间替换，`fmod_ret`前缀用来修改函数返回值，用于LSM模块。

## 参考资料

* [Introduce BPF trampoline](https://lwn.net/Articles/804112/)
* [Sleepable BPF programs](https://lwn.net/Articles/825415/)
* [Introduce BPF_MODIFY_RET tracing progs](https://lwn.net/Articles/813724/)