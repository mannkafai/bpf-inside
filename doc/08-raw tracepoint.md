# RAW TRACEPOINT的内核实现

## 0 前言

在第三篇中我们分析了Tracepoint的内核实现，借助Tracepoint PMU对Linux内核中静态定义的调试点进行追踪。今天我们基于`softirqs`程序分析Tracepoint的另一种使用方式 -- Raw Tracepoint。

## 1 简介

Raw Tracepoint和Tracepoint PMU类似，都是对Linux内核中静态定义的调试点进行追踪，两者在使用方式有所不同。

## 2 `softirqs`示例程序

### 2.1 BPF程序

BPF程序源码参见[softirqs.bpf.c](../src/softirqs.bpf.c)，主要内容如下：

```C
SEC("tp_btf/softirq_entry")
int BPF_PROG(softirq_entry_btf, unsigned int vec_nr)
{
    return handle_entry(vec_nr);
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(softirq_exit_btf, unsigned int vec_nr)
{
    return handle_exit(vec_nr);
}

SEC("raw_tp/softirq_entry")
int BPF_PROG(softirq_entry, unsigned int vec_nr)
{
    return handle_entry(vec_nr);
}

SEC("raw_tp/softirq_exit")
int BPF_PROG(softirq_exit, unsigned int vec_nr)
{
    return handle_exit(vec_nr);
}
```

该程序包括4个BPF程序 `softirq_entry_btf` 和 `softirq_exit_btf` 使用`tp_btf`前缀，`softirq_entry` 和 `softirq_exit` 使用`raw_tp` 前缀 。


####  `BPF_PROG`展开过程

这4个BPF程序都使用`BPF_PROG`宏，`BPF_PROG` 宏在 [bpf_tracing.h](../libbpf/src/bpf_tracing.h) 中定义的，如下：

```C
// file: libbpf/src/bpf_tracing.h
#define BPF_PROG(name, args...)						    \
name(unsigned long long *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(unsigned long long *ctx, ##args);				    \
typeof(name(0)) name(unsigned long long *ctx)				    \
{									    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(___bpf_ctx_cast(args));			    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(unsigned long long *ctx, ##args)
```

`___bpf_ctx_cast(args)` 宏在同一个文件中定义，展开 `args` 的参数，如下：

```C
// file: libbpf/src/bpf_tracing.h
#define ___bpf_ctx_cast0()            ctx
#define ___bpf_ctx_cast1(x)           ___bpf_ctx_cast0(), (void *)ctx[0]
#define ___bpf_ctx_cast2(x, args...)  ___bpf_ctx_cast1(args), (void *)ctx[1]
...
#define ___bpf_ctx_cast12(x, args...) ___bpf_ctx_cast11(args), (void *)ctx[11]
#define ___bpf_ctx_cast(args...)      ___bpf_apply(___bpf_ctx_cast, ___bpf_narg(args))(args)
```

使用`___bpf_ctx_castn(ctx)` 宏获取`ctx`的第n个参数，最多获取12个参数。

`int BPF_PROG(softirq_entry_btf, unsigned int vec_nr)` 宏展开后内如如下：

```C
int softirq_entry_btf(unsigned long long *ctx); 
static inline __attribute__((always_inline)) typeof(softirq_entry_btf(0)) 
____softirq_entry_btf(unsigned long long *ctx,unsigned int vec_nr); 
typeof(softirq_entry_btf(0)) softirq_entry_btf(unsigned long long *ctx) { 
    _Pragma("GCC diagnostic push") 
    _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") 
    return ____softirq_entry_btf(ctx, (void *)ctx[0]); 
    _Pragma("GCC diagnostic pop") 
} 
static inline __attribute__((always_inline)) typeof(softirq_entry_btf(0)) 
____softirq_entry_btf(unsigned long long *ctx,unsigned int vec_nr)
```

### 2.2 用户程序

用户程序源码参见[softirqs.c](../src/softirqs.c)，主要内容如下：

#### 1 附加BPF过程

```C
int main(int argc, char **argv)
{
    struct softirqs_bpf *obj;
    ...
    // 解析命令行参数
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    ...
    // 设置 libbpf 调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);
    // 打开BPF程序
    obj = softirqs_bpf__open();
    if (!obj) { ... }
    
    // 选择`raw_tp`和`tp_btf`加载方式，优先使用`tp_btf`方式
    if (probe_tp_btf("softirq_entry")) {
        bpf_program__set_autoload(obj->progs.softirq_entry, false);
        bpf_program__set_autoload(obj->progs.softirq_exit, false);
    } else {
        bpf_program__set_autoload(obj->progs.softirq_entry_btf, false);
        bpf_program__set_autoload(obj->progs.softirq_exit_btf, false);
    }
    // 初始化全局变量，设置过滤选项
    obj->rodata->targ_dist = env.distributed;
    obj->rodata->targ_ns = env.nanoseconds;

    // 加载BPF程序
    err = softirqs_bpf__load(obj);
    if (err) { ... }
    // 附加BPF程序
    err = softirqs_bpf__attach(skel);
    if (err) { ... }
    // 设置`SIGINT`处理函数
    signal(SIGINT, sig_handler);
    
    while (1) {
        sleep(env.interval);
        printf("\n");
        // 打印时间
        if (env.timestamp) { ... }
        // 打印结果
        if (!env.distributed)
            err = print_count(obj->bss);
        else
            err = print_hist(obj->bss);
        
        // 出现错误时退出、手动退出、到时间时退出
        if (err) break;
        if (exiting || --env.times == 0) break;
    }

cleanup:
    // 销毁BPF程序
    softirqs_bpf__destroy(obj);
    return err != 0;
}
```

#### 2 读取数据过程

`handle_entry()` 和 `handle_exit()` BPF函数将采集的数据更新到全局变量中，用户空间程序通过`print_count()` 或 `print_hist()` 打印输出。

### 2.3 编译运行

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make softirqs
$ sudo ./softirqs 
Tracing soft irq event time... Hit Ctrl-C to end.
^C
SOFTIRQ          TOTAL_usecs             
timer                   5972
net_rx                  8802
block                     74
tasklet                   41
sched                  22168
rcu                     6070
```

## 3 raw_tp附加BPF的方式

### 3.1 libbpf附加raw_tp的前缀

`softirqs.bpf.c`文件中BPF程序的SEC名称有两类，以`softirq_entry`为例，包括：`SEC("tp_btf/softirq_entry")` 和 `SEC("raw_tp/softirq_entry")` 。 `tp_btf` 和 `raw_tp` 在libbpf中对应的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
	SEC_DEF("raw_tracepoint+",	RAW_TRACEPOINT, 0, SEC_NONE, attach_raw_tp),
	SEC_DEF("raw_tp+",		RAW_TRACEPOINT, 0, SEC_NONE, attach_raw_tp),
	SEC_DEF("raw_tracepoint.w+",	RAW_TRACEPOINT_WRITABLE, 0, SEC_NONE, attach_raw_tp),
	SEC_DEF("raw_tp.w+",		RAW_TRACEPOINT_WRITABLE, 0, SEC_NONE, attach_raw_tp),
	SEC_DEF("tp_btf+",		TRACING, BPF_TRACE_RAW_TP, SEC_ATTACH_BTF, attach_trace),
    ...
};
```

### 3.2 `raw_tp`方式附加BPF程序

`raw_tp` 和 `raw_tracepoint` 前缀使用`attach_raw_tp`方式加载BPF程序，实现如下：

```C
// file: libbpf/src/libbpf.c
static int attach_raw_tp(const struct bpf_program *prog, long cookie, struct bpf_link **link)
{
    // raw_tp 使用的前缀
    static const char *const prefixes[] = {
        "raw_tp",
        "raw_tracepoint",
        "raw_tp.w",
        "raw_tracepoint.w",
    };
    const char *tp_name = NULL;
    *link = NULL;

    for (i = 0; i < ARRAY_SIZE(prefixes); i++) {
        size_t pfx_len;
        if (!str_has_pfx(prog->sec_name, prefixes[i])) continue;
        pfx_len = strlen(prefixes[i]);

        // `SEC`名称只有前缀时，表示不用自动附加BPF程序
        if (prog->sec_name[pfx_len] == '\0') return 0;
        // `SEC`名称格式不正确
        if (prog->sec_name[pfx_len] != '/') continue;
        // 解析`tp_name`
        tp_name = prog->sec_name + pfx_len + 1;
        break;
    }
    if (!tp_name) { ... }

    *link = bpf_program__attach_raw_tracepoint(prog, tp_name);
    return libbpf_get_error(*link);
}
```

在解析`SEC`名称中`tp_name`后，调用 `bpf_program__attach_raw_tracepoint` 函数完成剩余的工作，如下： 

```C
// file: libbpf/src/libbpf.c
struct bpf_link *bpf_program__attach_raw_tracepoint(const struct bpf_program *prog, const char *tp_name)
{
    struct bpf_link *link;
    int prog_fd, pfd;

    // 获取 prog_fd
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) { ... }

    // 创建link，设置分离接口
    link = calloc(1, sizeof(*link));
    if (!link) return libbpf_err_ptr(-ENOMEM);
    link->detach = &bpf_link__detach_fd;

    // 打开 raw_tracepoint
    pfd = bpf_raw_tracepoint_open(tp_name, prog_fd);
    if (pfd < 0) { ... }
    link->fd = pfd;
    return link;
}
```

`bpf_raw_tracepoint_open` 设置`bpf_attr`属性后，使用 `BPF_RAW_TRACEPOINT_OPEN` 指令进行BPF系统调用，如下： 

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

### 3.3 `tp_btf`方式附加BPF程序

`tp_btf` 使用 `SEC_ATTACH_BTF` 标记，表示需要BTF支持。

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
	SEC_DEF("tp_btf+",		TRACING, BPF_TRACE_RAW_TP, SEC_ATTACH_BTF, attach_trace),
    ...
};
```

`SEC` 宏定义如下：

```C
// file: libbpf/src/libbpf.c
#define SEC_DEF(sec_pfx, ptype, atype, flags, ...) {			    \
	.sec = (char *)sec_pfx,						    \
	.prog_type = BPF_PROG_TYPE_##ptype,				    \
	.expected_attach_type = atype,					    \
	.cookie = (long)(flags),					    \
	.prog_prepare_load_fn = libbpf_prepare_prog_load,		    \
	__VA_ARGS__							    \
}
```

#### 1 加载阶段

* preload回调函数

`SEC_DEF` 宏设置了 `prog_prepare_load_fn` 接口函数，libbpf在加载BPF程序阶段调用，如下：

```C
// file: libbpf/src/libbpf.c
static int bpf_object_load_prog(struct bpf_object *obj, struct bpf_program *prog,
                struct bpf_insn *insns, int insns_cnt,
                const char *license, __u32 kern_version, int *prog_fd)
{
    ...
    // 检查BTF支持情况，支持`BTF_FUNC`的情况下，设置相关属性
    btf_fd = bpf_object__btf_fd(obj);
    if (btf_fd >= 0 && kernel_supports(obj, FEAT_BTF_FUNC)) { ... }

    // 加载BPF程序前（preload）的回调函数
    if (prog->sec_def && prog->sec_def->prog_prepare_load_fn) {
        err = prog->sec_def->prog_prepare_load_fn(prog, &load_attr, prog->sec_def->cookie);
        if (err < 0) { ... }
        insns = prog->insns;
        insns_cnt = prog->insns_cnt;
    }
    ...
    // 加载BPF程序
    ret = bpf_prog_load(prog->type, prog_name, license, insns, insns_cnt, &load_attr);
    ...
}
```

`libbpf_prepare_prog_load` 函数是libbpf默认设置的preload回调函数，实现如下：

```C
// file: libbpf/src/libbpf.c
static int libbpf_prepare_prog_load(struct bpf_program *prog,
                    struct bpf_prog_load_opts *opts, long cookie)
{
    enum sec_def_flags def = cookie;
    ...
    if ((def & SEC_ATTACH_BTF) && !prog->attach_btf_id) {
        // 获取附加名称
        attach_name = strchr(prog->sec_name, '/');
        if (!attach_name) { ... }
        attach_name++; /* skip over / */

        // 获取 BPF 信息
        err = libbpf_find_attach_btf_id(prog, attach_name, &btf_obj_fd, &btf_type_id);
        if (err) return err;

        // 缓存解析的 BTF_FD 和 BTF_type_ID
        prog->attach_btf_obj_fd = btf_obj_fd;
        prog->attach_btf_id = btf_type_id;
        // opts 设置
        opts->attach_btf_obj_fd = btf_obj_fd;
        opts->attach_btf_id = btf_type_id;
    }
}
```

* 获取BTF ID

`libbpf_find_attach_btf_id` 函数可以通过通过BPF程序、内核、module三种方式获取BTF信息，如下：

```C
// file: libbpf/src/libbpf.c
static int libbpf_find_attach_btf_id(struct bpf_program *prog, const char *attach_name, 
                    int *btf_obj_fd, int *btf_type_id)
{
    enum bpf_attach_type attach_type = prog->expected_attach_type;
    __u32 attach_prog_fd = prog->attach_prog_fd;

    // 获取BPF程序的BTF信息
    if (prog->type == BPF_PROG_TYPE_EXT || attach_prog_fd) {
        if (!attach_prog_fd) { ...}
        // 获取prog的BTF ID
        err = libbpf_find_prog_btf_id(attach_name, attach_prog_fd);
        if (err < 0) { ... }
        *btf_obj_fd = 0;
        *btf_type_id = err;
        return 0;
    }

    if (prog->obj->gen_loader) {
        // 从gen_loader中获取BTF ID
        bpf_gen__record_attach_target(prog->obj->gen_loader, attach_name, attach_type);
        *btf_obj_fd = 0;
        *btf_type_id = 1;
    } else {
        // 从内核中获取BTF ID
        err = find_kernel_btf_id(prog->obj, attach_name, attach_type, btf_obj_fd, btf_type_id);
    }
    ...
}
```

我们只关注中内核中获取BTF ID，`find_kernel_btf_id` 实现如下：

```C
// file: libbpf/src/libbpf.c
static int find_kernel_btf_id(struct bpf_object *obj, const char *attach_name,
            enum bpf_attach_type attach_type, int *btf_obj_fd, int *btf_type_id)
{
    ...
    ret = find_attach_btf_id(obj->btf_vmlinux, attach_name, attach_type);
    if (ret > 0) {
        *btf_obj_fd = 0; /* vmlinux BTF */
        *btf_type_id = ret;
        return 0;
    }
    if (ret != -ENOENT) return ret;

    // 加载module
    ret = load_module_btfs(obj);
    if (ret) return ret;
    // 从module中获取BTF ID
    for (i = 0; i < obj->btf_module_cnt; i++) {
        const struct module_btf *mod = &obj->btf_modules[i];
        ret = find_attach_btf_id(mod->btf, attach_name, attach_type);
        ...
    }
    return -ESRCH;
}
```

`find_attach_btf_id` 函数获取附加类型对应的前缀(prefix)和类别(kind)后，解析BTF数据格式，获取指定名称和类型的BTF ID，实现如下：

```C
// file: libbpf/src/libbpf.c
static inline int find_attach_btf_id(struct btf *btf, const char *name,
                    enum bpf_attach_type attach_type)
{
    const char *prefix;
    int kind;
    
    btf_get_kernel_prefix_kind(attach_type, &prefix, &kind);
    return find_btf_by_prefix_kind(btf, prefix, name, kind);
}
```

`btf_get_kernel_prefix_kind` 函数获取附加类型对应的前缀(prefix)和类别(kind)，对应关系如下：

```C
// file: libbpf/src/libbpf.c
#define BTF_TRACE_PREFIX "btf_trace_"
#define BTF_LSM_PREFIX "bpf_lsm_"
#define BTF_ITER_PREFIX "bpf_iter_"
#define BTF_MAX_NAME_SIZE 128

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

在获取前缀和类别后，`find_btf_by_prefix_kind` 根据将前缀和名称组成内核使用的BTF类型名称后，获取BTF ID，实现如下：

```C
// file: libbpf/src/libbpf.c
static int find_btf_by_prefix_kind(const struct btf *btf, const char *prefix, const char *name, __u32 kind)
{
    char btf_type_name[BTF_MAX_NAME_SIZE];
    ...
    ret = snprintf(btf_type_name, sizeof(btf_type_name), "%s%s", prefix, name);
    if (ret < 0 || ret >= sizeof(btf_type_name))
        return -ENAMETOOLONG;
    return btf__find_by_name_kind(btf, btf_type_name, kind);
}
```

`btf__find_by_name_kind` 从BTF文件中获取对应的名称和类别，这里略过实现过程。BTF格式参见[BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html)。

* 内核BTF信息

`btf_vmlinux` 通过 `btf__load_vmlinux_btf` 函数加载的，从众所周知的路径中加载。实现如下：

```C
// file：libbpf/src/btf.c
struct btf *btf__load_vmlinux_btf(void)
{
    const char *locations[] = {
        /* try canonical vmlinux BTF through sysfs first */
        "/sys/kernel/btf/vmlinux",
        /* fall back to trying to find vmlinux on disk otherwise */
        "/boot/vmlinux-%1$s",
        "/lib/modules/%1$s/vmlinux-%1$s",
        "/lib/modules/%1$s/build/vmlinux",
        "/usr/lib/modules/%1$s/kernel/vmlinux",
        "/usr/lib/debug/boot/vmlinux-%1$s",
        "/usr/lib/debug/boot/vmlinux-%1$s.debug",
        "/usr/lib/debug/lib/modules/%1$s/vmlinux",
    };
    char path[PATH_MAX + 1];
    struct utsname buf;
    struct btf *btf;

    // 获取 uname 
    uname(&buf);

    for (i = 0; i < ARRAY_SIZE(locations); i++) {
        // 路径中添加`release`信息
        snprintf(path, PATH_MAX, locations[i], buf.release);

        if (faccessat(AT_FDCWD, path, R_OK, AT_EACCESS)) continue;
        // 解析 btf 
        btf = btf__parse(path, NULL);
        err = libbpf_get_error(btf);
        if (err) continue;
        // 解析成功后返回
        return btf;
    }
    ...
    return libbpf_err_ptr(-ESRCH);
}
```

#### 2 附加阶段

`tp_btf`前缀使用`attach_trace`方式加载BPF程序，`attach_trace` 函数是对`bpf_program__attach_trace` 函数的简单封装，最终调用`bpf_program__attach_btf_id`，如下：

```C
// file: libbpf/src/libbpf.c
static int attach_trace(const struct bpf_program *prog, long cookie, struct bpf_link **link)
    --> *link = bpf_program__attach_trace(prog);
        --> bpf_program__attach_btf_id(prog, NULL);
```

`bpf_program__attach_btf_id` 函数设置link属性后，调用`bpf_link_create`函数进行实际的创建，如下：

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

    // 创建link，设置分离接口
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
    // 根据附加类型设置opts属性
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

`bpf_link_create` 对不同附加类型的BPF程序设置不同的属性。`tp_btf`设置的附加类型为`BPF_TRACE_RAW_TP`，只需要默认设置即可。

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

`link_create` 在检查BFP程序类型和`attr`属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。`tp_btf`设置的程序类型为`BPF_PROG_TYPE_TRACING`, 附加类型为`BPF_TRACE_RAW_TP`, 对应`bpf_raw_tp_link_attach` 处理。如下：

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
        // 检查 attach_type 和 expected_attach_type 是否匹配
        if (attr->link_create.attach_type != prog->expected_attach_type) { ... }
        // BPF_TRACE_RAW_TP 类型
        if (prog->expected_attach_type == BPF_TRACE_RAW_TP)
            ret = bpf_raw_tp_link_attach(prog, NULL);
        ...
        break;
    ...
    }
    ...
}
```

#### 2 `BPF_RAW_TRACEPOINT_OPEN`

`bpf_raw_tracepoint_open` 在获取设置的属性中追踪点名称后，调用 `bpf_raw_tp_link_attach` 。如下：

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
```

#### 3 `bpf_raw_tp_link_attach`

`bpf_raw_tp_link_attach` 获取追踪点名称(`tp_name`)后，注册相应名称的追踪点。如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_raw_tp_link_attach(struct bpf_prog *prog,  const char __user *user_tp_name)
{
    struct bpf_link_primer link_primer;
    struct bpf_raw_tp_link *link;
    struct bpf_raw_event_map *btp;
    const char *tp_name;
    char buf[128];

    // 获取`tp_name`
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
    case BPF_PROG_TYPE_RAW_TRACEPOINT:
    case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
        // 用户设置的tp_name
        if (strncpy_from_user(buf, user_tp_name, sizeof(buf) - 1) < 0) return -EFAULT;
        buf[sizeof(buf) - 1] = 0;
        tp_name = buf;
        break;
    default:
        return -EINVAL;
    }

    // 获取`raw_tracepoint`
    btp = bpf_get_raw_tracepoint(tp_name);
    if (!btp) return -ENOENT;

    // 创建 link
    link = kzalloc(sizeof(*link), GFP_USER);
    if (!link) { ... }
    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_RAW_TRACEPOINT, 
                &bpf_raw_tp_link_lops, prog);
    link->btp = btp;
    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    if (err) { ... }

    // 注册`raw_tracepoint`
    err = bpf_probe_register(link->btp, prog);
    if (err) { ... }
    // fd 和 file 进行关联
    return bpf_link_settle(&link_primer);

out_put_btp:
    bpf_put_raw_tracepoint(btp);
    return err;
    ...
}
```

### 4.2 注册原始追踪点

#### 1 获取原始追踪点

`bpf_get_raw_tracepoint` 函数获取指定名称的追踪点，如下：

```C
// file: kernel/trace/bpf_trace.c
struct bpf_raw_event_map *bpf_get_raw_tracepoint(const char *name)
{
    struct bpf_raw_event_map *btp = __start__bpf_raw_tp;
    for (; btp < __stop__bpf_raw_tp; btp++) {
        if (!strcmp(btp->tp->name, name))
            return btp;
    }
    return bpf_get_raw_tracepoint_module(name);
}
```

遍历 `__section("__bpf_raw_tp")` 段内容，逐项比较名称后获取 `bpf_raw_event_map` 。 `__bpf_raw_tp` 的定义如下： 

```C
// file: include/asm-generic\vmlinux.lds.h
#ifdef CONFIG_BPF_EVENTS
#define BPF_RAW_TP() STRUCT_ALIGN();				\
	BOUNDED_SECTION_BY(__bpf_raw_tp_map, __bpf_raw_tp)
#else
#define BPF_RAW_TP()
#endif
```

`__bpf_raw_tp` 和 `__bpf_raw_tp_map` 段名称进行关联，实际存放 `__bpf_raw_tp_map` 段的内容，其定义如下：

```C
// file: include/trace/bpf_probe.h
#define __DEFINE_EVENT(template, call, proto, args, size)		\
static inline void bpf_test_probe_##call(void)				\
{									\
	check_trace_callback_type_##call(__bpf_trace_##template);	\
}									\
typedef void (*btf_trace_##call)(void *__data, proto);			\
static union {								\
	struct bpf_raw_event_map event;					\
	btf_trace_##call handler;					\
} __bpf_trace_tp_map_##call __used					\
__section("__bpf_raw_tp_map") = {					\
	.event = {							\
		.tp		= &__tracepoint_##call,			\
		.bpf_func	= __bpf_trace_##template,		\
		.num_args	= COUNT_ARGS(args),			\
		.writable_size	= size,					\
	},								\
};
```

在`TRACE_EVENT`展开过程的第十二阶段("bpf_probe定义阶段")中展开的。其中 `typedef void (*btf_trace_##call)(void *__data, proto);` 和获取BTF前缀和类别对应，如下：

```C
// file: libbpf/src/libbpf.c
#define BTF_TRACE_PREFIX "btf_trace_"

// file: libbpf/src/libbpf.c
void btf_get_kernel_prefix_kind(enum bpf_attach_type attach_type, const char **prefix, int *kind)
{
    switch (attach_type) {
    case BPF_TRACE_RAW_TP:
        *prefix = BTF_TRACE_PREFIX;
        *kind = BTF_KIND_TYPEDEF;
        break;
    ...
    }
}
```

`.tp`字段设置为`&__tracepoint_##call`，在`TRACE_EVENT`展开过程的第二阶段("定义阶段")中展开的，定义如下：

```C
// file: include/linux/tracepoint.h
#define DEFINE_TRACE_FN(_name, _reg, _unreg, proto, args)		\
	static const char __tpstrtab_##_name[]				\
	__section("__tracepoints_strings") = #_name;			\
    ...
	struct tracepoint __tracepoint_##_name	__used			\
	__section("__tracepoints") = {					\
		.name = __tpstrtab_##_name,				\
    ...
```

`.bpf_func`字段设置为`__bpf_trace_##template`, 定义如下：

```C
// file: include/trace/bpf_probe.h
#define __BPF_DECLARE_TRACE(call, proto, args)				\
static notrace void							\
__bpf_trace_##call(void *__data, proto)					\
{									\
	struct bpf_prog *prog = __data;					\
	CONCATENATE(bpf_trace_run, COUNT_ARGS(args))(prog, CAST_TO_U64(args));	\
}
```

#### 2 注册原始追踪点

在获取追踪点后，`bpf_probe_register` 函数实现追踪点的注册。如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_probe_register(struct bpf_raw_event_map *btp, struct bpf_prog *prog)
{
    return __bpf_probe_register(btp, prog);
}

// file: kernel/trace/bpf_trace.c
static int __bpf_probe_register(struct bpf_raw_event_map *btp, struct bpf_prog *prog)
{
    struct tracepoint *tp = btp->tp;
    // 检查BPF程序访问的参数是否超过tracepoint的参数范围
    if (prog->aux->max_ctx_offset > btp->num_args * sizeof(u64))
        return -EINVAL;
    if (prog->aux->max_tp_access > btp->writable_size)
        return -EINVAL;
    // 注册`tracepoint`探测接口
    return tracepoint_probe_register_may_exist(tp, (void *)btp->bpf_func, prog);
}
```

和`TRACEPOINT-PMU`方式不同，原始追踪点通过添加探测函数的方式注册多个BPF程序。如下：

```C
// file: include/linux/tracepoint.h
static inline int tracepoint_probe_register_may_exist(struct tracepoint *tp, void *probe, void *data)
{
    return tracepoint_probe_register_prio_may_exist(tp, probe, data, TRACEPOINT_DEFAULT_PRIO);
}

// file：kernel/tracepoint.c
int tracepoint_probe_register_prio_may_exist(struct tracepoint *tp, void *probe, void *data, int prio)
{
    struct tracepoint_func tp_func;
    int ret;
    mutex_lock(&tracepoints_mutex);
    tp_func.func = probe;
    tp_func.data = data;
    tp_func.prio = prio;
    ret = tracepoint_add_func(tp, &tp_func, prio, false);
    mutex_unlock(&tracepoints_mutex);
    return ret;
}
```

### 4.3 注销原始追踪点

#### 1 `bpf_link_fops`接口

在附加`bpf_raw_tp_link`过程中，设置了用户空间操作`bpf_link`的文件接口，如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_raw_tp_link_attach(struct bpf_prog *prog,  const char __user *user_tp_name)
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

`bpf_link_release` 函数释放`link`资源，通过 `bpf_link_put` 函数最终调用`bpf_link_free` 函数。`bpf_link_free` 实现如下：

```C
// file：kernel/bpf/syscall.c
static int bpf_link_release(struct inode *inode, struct file *filp)
{
    struct bpf_link *link = filp->private_data;
    bpf_link_put(link);
    return 0;
}

// file：kernel/bpf/syscall.c
void bpf_link_put(struct bpf_link *link)
{
    if (!atomic64_dec_and_test(&link->refcnt))
        return;

    if (in_atomic()) {
        // 工作队列(workqueue)方式释放
        INIT_WORK(&link->work, bpf_link_put_deferred);
        schedule_work(&link->work);
    } else {
        bpf_link_free(link);
    }
}

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

#### 2 `bpf_raw_tp_link_lops`接口

`bpf_raw_tp_link_lops` 是我们设置的`link->ops`，如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_raw_tp_link_attach(struct bpf_prog *prog,  const char __user *user_tp_name)
{
    ...
    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_RAW_TRACEPOINT, 
                &bpf_raw_tp_link_lops, prog);
    link->btp = btp;
    ...
}
```

定义如下：

```C
// file: kernel/bpf/syscall.c
static const struct bpf_link_ops bpf_raw_tp_link_lops = {
    .release = bpf_raw_tp_link_release,
    .dealloc = bpf_raw_tp_link_dealloc,
    .show_fdinfo = bpf_raw_tp_link_show_fdinfo,
    .fill_link_info = bpf_raw_tp_link_fill_link_info,
};
```

`.release`接口释放`bpf_link`关联的程序。`bpf_raw_tp_link_release` 释放`raw_tp`，如下：

```C
// file: kernel/bpf/syscall.c
static void bpf_raw_tp_link_release(struct bpf_link *link)
{
    struct bpf_raw_tp_link *raw_tp = container_of(link, struct bpf_raw_tp_link, link);
    // 注销`bpf`程序
    bpf_probe_unregister(raw_tp->btp, raw_tp->link.prog);
    // 释放`raw_tracepoint`资源
    bpf_put_raw_tracepoint(raw_tp->btp);
}
```

`bpf_probe_unregister` 函数注销追踪点中对应的BPF程序，如下：

```C
// file: kernel/trace/bpf_trace.c
int bpf_probe_unregister(struct bpf_raw_event_map *btp, struct bpf_prog *prog)
{
    return tracepoint_probe_unregister(btp->tp, (void *)btp->bpf_func, prog);
}
```

`tracepoint_probe_unregister` 移除追踪点中指定的探测函数，如下：

```C
// file：kernel/tracepoint.c
int tracepoint_probe_unregister(struct tracepoint *tp, void *probe, void *data)
{
    struct tracepoint_func tp_func;
    int ret;
    mutex_lock(&tracepoints_mutex);
    tp_func.func = probe;
    tp_func.data = data;
    ret = tracepoint_remove_func(tp, &tp_func);
    mutex_unlock(&tracepoints_mutex);
    return ret;
}
```

### 4.4 BPF调用过程

在 `TRACE_EVENT` 展开过程的第一个阶段("声明阶段")和第二个阶段(`定义阶段`)，我们知道调用 `trace_##name` 函数时，逐个调用Tracepoint设置的函数列表中设置的函数。在注册原始追踪点过程中，我们将`btp->bpf_func`添加到追踪点的探测函数列表中。`.bpf_func` 设置为 `__bpf_trace_##template` , 定义如下：

```C
// file: include/trace/bpf_probe.h
#define __BPF_DECLARE_TRACE(call, proto, args)				\
static notrace void							\
__bpf_trace_##call(void *__data, proto)					\
{									\
	struct bpf_prog *prog = __data;					\
	CONCATENATE(bpf_trace_run, COUNT_ARGS(args))(prog, CAST_TO_U64(args));	\
}
```

`COUNT_ARGS(args)` 宏表示`args`参数的数量，`CONCATENATE`将连接字符。 `CONCATENATE(bpf_trace_run, COUNT_ARGS(args))` 宏展开后，为 `bpf_trace_run1`, `bpf_trace_run2`, ... 之类的函数。

Linux定义了 `bpf_trace_run1` ~ `bpf_trace_run12` 函数，如下：

```C
// file: include/linux/trace_events.h
void bpf_trace_run1(struct bpf_prog *prog, u64 arg1);
void bpf_trace_run2(struct bpf_prog *prog, u64 arg1, u64 arg2);
...
void bpf_trace_run12(struct bpf_prog *prog, u64 arg1, u64 arg2,
                u64 arg3, u64 arg4, u64 arg5, u64 arg6, u64 arg7,
                u64 arg8, u64 arg9, u64 arg10, u64 arg11, u64 arg12);
```

`bpf_trace_run##x` 的实现如下：

```C
// file: kernel/trace/bpf_trace.c
#define BPF_TRACE_DEFN_x(x)						\
	void bpf_trace_run##x(struct bpf_prog *prog,			\
			      REPEAT(x, SARG, __DL_COM, __SEQ_0_11))	\
	{								\
		u64 args[x];						\
		REPEAT(x, COPY, __DL_SEM, __SEQ_0_11);			\
		__bpf_trace_run(prog, args);				\
	}								\
	EXPORT_SYMBOL_GPL(bpf_trace_run##x)
BPF_TRACE_DEFN_x(1);
BPF_TRACE_DEFN_x(2);
...
BPF_TRACE_DEFN_x(12);
```

`bpf_trace_run##x` 函数组织`args`参数后，调用 `__bpf_trace_run` 函数。后者调用BPF程序，如下：

```C
// file: kernel/trace/bpf_trace.c
static __always_inline void __bpf_trace_run(struct bpf_prog *prog, u64 *args)
{
    cant_sleep();
    if (unlikely(this_cpu_inc_return(*(prog->active)) != 1)) {
        bpf_prog_inc_misses_counter(prog);
        goto out;
    }
    rcu_read_lock();
    // 运行BPF程序
    (void) bpf_prog_run(prog, args);
    rcu_read_unlock();
out:
    this_cpu_dec(*(prog->active));
}
```

## 5 总结

本文通过`softirqs`示例程序分析了Raw Tracepoint的内核实现过程。

Raw Tracepoint 和 Tracepoint-PMU 以不同的方式使用系统中定义的tracepoint。Raw Tracepoint 不会像 Tracepoint-PMU 那样预先处理好事件参数，Raw Tracepoint 访问的都是事件的原始参数。因此，在性能上会更好一些。

## 参考资料

* [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html)、
* [bpf, tracing: introduce bpf raw tracepoints](https://lwn.net/Articles/750569/)