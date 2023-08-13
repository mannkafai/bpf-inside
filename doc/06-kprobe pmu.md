# KPROBE的内核实现

## 0 前言

在上一章节我们分析了SOFTWARE-PMU的实现，今天我们基于`kprobe`程序分析KPROBE的实现过程。

## 1 简介

Kprobe是一个在Linux内核中用于调试和跟踪内核函数的工具。它可以用来在内核函数的入口和出口处插入断点，以便在运行时观察函数的参数、返回值和执行路径。

## 2 kprobe示例程序

### 2.1 BPF程序

BPF程序的源码参见[kprobe.bpf.c](../src/kprobe.bpf.c)，主要内容如下：

```C
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;
    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
```

该程序包括两个BPF程序 `do_unlinkat` 和 `do_unlinkat_exit` 。

#### 1 `BPF_KPROBE`展开过程

`do_unlinkat` 使用 `BPF_KPROBE` 宏，有两个参数 `dfd` 和 `name`。`BPF_KPROBE` 宏在 [bpf_tracing.h](../libbpf/src/bpf_tracing.h) 中定义的，如下：

```C
// file: libbpf/src/bpf_tracing.h
#define BPF_KPROBE(name, args...)					    \
name(struct pt_regs *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args);				    \
typeof(name(0)) name(struct pt_regs *ctx)				    \
{									    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(___bpf_kprobe_args(args));			    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args)
```

`___bpf_kprobe_args(args)` 宏在同一个文件中定义，展开 `args` 的参数，如下：

```C
// file: libbpf/src/bpf_tracing.h
#define ___bpf_kprobe_args0()           ctx
#define ___bpf_kprobe_args1(x)          ___bpf_kprobe_args0(), (void *)PT_REGS_PARM1(ctx)
#define ___bpf_kprobe_args2(x, args...) ___bpf_kprobe_args1(args), (void *)PT_REGS_PARM2(ctx)
...
#define ___bpf_kprobe_args8(x, args...) ___bpf_kprobe_args7(args), (void *)PT_REGS_PARM8(ctx)
#define ___bpf_kprobe_args(args...)     ___bpf_apply(___bpf_kprobe_args, ___bpf_narg(args))(args)
```

`PT_REGS_PARMn(ctx)` 宏获取`ctx`的第n个参数。根据`x86_64`架构的调用约定，`PT_REGS_PARM1` ~ `PT_REGS_PARM6` 为 `di`,`si`,`dx`,`cx`,`r8`,`r9` 寄存器。

`int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)` 宏展开后如下：

```C
int do_unlinkat(struct pt_regs *ctx); 
static inline __attribute__((always_inline)) typeof(do_unlinkat(0)) 
____do_unlinkat(struct pt_regs *ctx,int dfd, struct filename *name); 
typeof(do_unlinkat(0)) do_unlinkat(struct pt_regs *ctx) { 
    _Pragma("GCC diagnostic push") 
    _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") 
    return ____do_unlinkat(ctx, (void *)((ctx)->di), (void *)((ctx)->si));
    _Pragma("GCC diagnostic pop") 
}
static inline __attribute__((always_inline)) typeof(do_unlinkat(0)) 
____do_unlinkat(struct pt_regs *ctx,int dfd, struct filename *name)
```

#### 2 `BPF_KRETPROBE`展开过程
  
`BPF_KRETPROBE` 宏同 `BPF_KPROBE` 类似，展开后获取返回值，在`x86_64`架构下为 `ax` 寄存器。

`int BPF_KRETPROBE(do_unlinkat_exit, long ret)` 宏展开后如下：

```C
int do_unlinkat_exit(struct pt_regs *ctx); 
static inline __attribute__((always_inline)) typeof(do_unlinkat_exit(0)) 
____do_unlinkat_exit(struct pt_regs *ctx,long ret); 
typeof(do_unlinkat_exit(0)) do_unlinkat_exit(struct pt_regs *ctx) {
    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") 
    return ____do_unlinkat_exit(ctx, (void *)((ctx)->ax)); 
    _Pragma("GCC diagnostic pop") 
} 
static inline __attribute__((always_inline)) typeof(do_unlinkat_exit(0)) 
____do_unlinkat_exit(struct pt_regs *ctx,long ret)
```

### 2.2 用户程序

用户程序的源码参见[kprobe.c](../src/kprobe.c)，主要功能如下：

#### 1 附加BPF过程

```C
int main(int argc, char **argv)
{
    struct kprobe_bpf *skel;
    ...
    // 打开和加载BPF程序
    skel = kprobe_bpf__open_and_load();
    ...
    // 附加BPF程序
    err = kprobe_bpf__attach(skel);
    ...
    // 设置中断信号处理函数
    if (signal(SIGINT, sig_int) == SIG_ERR) { ... }
    ...
    while (!stop) {
        fprintf(stderr, ".");
        sleep(1);
    }
cleanup:
    // 卸载BPF程序
    kprobe_bpf__destroy(skel);
    return -err;
}
```

#### 2 读取数据过程

`do_unlinkat` 和 `do_unlinkat_exit` 将采集的数据通过 `bpf_printk` 输出到 `/sys/kernel/debug/tracing/trace_pipe` 文件中。


### 2.3 编译运行程序

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make kprobe
$ sudo ./kprobe 
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

在`kprobe`程序运行的过程中打开另一个bash窗口查看输出结果，如下：

```bash
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
 systemd-journal-313     [007] d..31 111831.229464: bpf_trace_printk: KPROBE ENTRY pid = 313, filename = /run/systemd/journal/streams/8:1626886
 systemd-journal-313     [007] d..31 111831.229492: bpf_trace_printk: KPROBE EXIT: pid = 313, ret = 0
         systemd-1       [004] d..31 111831.230293: bpf_trace_printk: KPROBE ENTRY pid = 1, filename = /run/systemd/units/invocation:kubelet.service
         systemd-1       [004] d..31 111831.230303: bpf_trace_printk: KPROBE EXIT: pid = 1, ret = 0
...
```

## 3 kprobe附加BPF的方式

### 3.1 libbpf附加kprobe的过程

`kprobe.bpf.c` 文件中BPF程序的SEC名称分别为 `SEC("kprobe/do_unlinkat")` 和 `SEC("kretprobe/do_unlinkat")` 。在第一篇中，我们分析了libbpf在附加阶段通过`SEC`名称进行附加的。`kprobe` 和 `kretprobe` 对应的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("kprobe+", KPROBE, 0, SEC_NONE, attach_kprobe),
    ...
    SEC_DEF("kretprobe+", KPROBE, 0, SEC_NONE, attach_kprobe),
    ...
};
```

`kprobe` 和 `kretprobe` 都是通过 `attach_kprobe` 函数进行附加的。`attach_kprobe` 的实现过程如下：

```C
// file: libbpf/src/libbpf.c
static int attach_kprobe(const struct bpf_program *prog, long cookie, struct bpf_link **link)
{
    DECLARE_LIBBPF_OPTS(bpf_kprobe_opts, opts);
    ...
    // 检查SEC名称，只附加 SEC("kprobe") 和 SEC("kretprobe") 
    if (strcmp(prog->sec_name, "kprobe") == 0 || strcmp(prog->sec_name, "kretprobe") == 0)
        return 0;
    // 检查是否是retprobe
    opts.retprobe = str_has_pfx(prog->sec_name, "kretprobe/");
    // 获取func_name
    if (opts.retprobe)
        func_name = prog->sec_name + sizeof("kretprobe/") - 1;
    else
        func_name = prog->sec_name + sizeof("kprobe/") - 1;
    // 获取func, offset
    n = sscanf(func_name, "%m[a-zA-Z0-9_.]+%li", &func, &offset);
    if (n < 1) { ... return -EINVAL;}
    // kretprobe的偏移必须为0，即：函数入口点
    if (opts.retprobe && offset != 0) { ... return -EINVAL; }

    opts.offset = offset;
    // 附加 kprobe
    *link = bpf_program__attach_kprobe_opts(prog, func, &opts);
    free(func);
    return libbpf_get_error(*link);
}
```

`bpf_program__attach_kprobe_opts` 函数附加BPF程序到kprobe，实现如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link *
bpf_program__attach_kprobe_opts(const struct bpf_program *prog,
                const char *func_name, const struct bpf_kprobe_opts *opts)
{
    DECLARE_LIBBPF_OPTS(bpf_perf_event_opts, pe_opts);
    ...
    // 默认附加设置
    attach_mode = OPTS_GET(opts, attach_mode, PROBE_ATTACH_MODE_DEFAULT);
    retprobe = OPTS_GET(opts, retprobe, false);
    offset = OPTS_GET(opts, offset, 0);
    pe_opts.bpf_cookie = OPTS_GET(opts, bpf_cookie, 0);

    // 检查是否使用传统附加方式
    legacy = determine_kprobe_perf_type() < 0;
    // 附加方式匹配性设置
    switch (attach_mode) {
    case PROBE_ATTACH_MODE_LEGACY:
        legacy = true;
        pe_opts.force_ioctl_attach = true;
        break;
    case PROBE_ATTACH_MODE_PERF:
        if (legacy) return libbpf_err_ptr(-ENOTSUP);
        pe_opts.force_ioctl_attach = true;
        break;
        ...
    }

    if (!legacy) {
        // 打开kprobe
        pfd = perf_event_open_probe(false /* uprobe */, retprobe,
                    func_name, offset, -1 /* pid */, 0 /* ref_ctr_off */);
    } else {
        char probe_name[256];
        // 获取传统kprobe事件名称
        gen_kprobe_legacy_event_name(probe_name, sizeof(probe_name), func_name, offset);
        legacy_probe = strdup(probe_name);
        if (!legacy_probe) return libbpf_err_ptr(-ENOMEM);
        // 传统方式打开kprobe
        pfd = perf_event_kprobe_open_legacy(legacy_probe, retprobe, func_name, offset, -1 /* pid */);
    }
    ...
    link = bpf_program__attach_perf_event_opts(prog, pfd, &pe_opts);
    if (legacy) {
        struct bpf_link_perf *perf_link = container_of(link, struct bpf_link_perf, link);
        perf_link->legacy_probe_name = legacy_probe;
        perf_link->legacy_is_kprobe = true;
        perf_link->legacy_is_retprobe = retprobe;
    }
    return link;
    ...
}
```

可以看到kprobe有两种方式加载BPF程序，传统方式和现代方式。这两种方式打开perf_event（打开事件的方式不同）后，附加到perf_event事件。通过 `determine_kprobe_perf_type` 函数判断是否使用传统附加方式，实现如下：

```C
// file: libbpf/src/libbpf.c
static int determine_kprobe_perf_type(void)
{
    const char *file = "/sys/bus/event_source/devices/kprobe/type";
    return parse_uint_from_file(file, "%d\n");
}
```

在第二篇PMU初始化过程中，系统注册的PMU在 `/sys/bus/event_source/` 目录下。 `/sys/bus/event_source/devices/kprobe/type` 表示名称为`kprobe`的PMU，注册如下：

```C
// file: kernel/events/core.c
void __init perf_event_init(void)
    --> perf_tp_register()
        --> perf_pmu_register(&perf_kprobe, "kprobe", -1);
```

即，`determine_kprobe_perf_type` 函数判断 KPROBE-PMU 是否注册。


### 3.2 现代方式--KPROBE-PMU

在 KPROBE-PMU注册后，使用现代方式，调用 `perf_event_open_probe` 函数，实现如下：

```C
// file: libbpf/src/libbpf.c
static int perf_event_open_probe(bool uprobe, bool retprobe, const char *name,
            uint64_t offset, int pid, size_t ref_ctr_off)
{
    const size_t attr_sz = sizeof(struct perf_event_attr);
    struct perf_event_attr attr;
    ...
    memset(&attr, 0, attr_sz);
    // 获取kprobe或uprobe类型
    type = uprobe ? determine_uprobe_perf_type() : determine_kprobe_perf_type();
    ...
    // retprobe时，获取retprobe配置
    if (retprobe) {
        int bit = uprobe ? determine_uprobe_retprobe_bit()
                        : determine_kprobe_retprobe_bit();
        if(bit < 0) { ... }
        attr.config |= 1 << bit;
    }
    // attr设置，使用kprobe或uprobe类型
    attr.size = attr_sz;
    attr.type = type;
    attr.config |= (__u64)ref_ctr_off << PERF_UPROBE_REF_CTR_OFFSET_SHIFT;
    attr.config1 = ptr_to_u64(name); /* kprobe_func or uprobe_path */
    attr.config2 = offset;		 /* kprobe_addr or probe_offset */
    // perf_event_open系统调用
    pfd = syscall(__NR_perf_event_open, &attr, pid < 0 ? -1 : pid /* pid */,
                pid == -1 ? 0 : -1 /* cpu */, -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
    return pfd >= 0 ? pfd : -errno;
}
```

### 3.3 传统方式--TRACEPOINT-PMU

没有注册`KPROBE-PMU`时或强制使用传统方式时，实现如下

```C
// file: libbpf/src/libbpf.c
char probe_name[256];
// 获取kprobe名称
gen_kprobe_legacy_event_name(probe_name, sizeof(probe_name), func_name, offset);
legacy_probe = strdup(probe_name);
// 使用传统方式打开事件
pfd = perf_event_kprobe_open_legacy(legacy_probe, retprobe, func_name, offset, -1 /* pid */);
```

`perf_event_kprobe_open_legacy` 函数实现如下：

```C
// file: libbpf/src/libbpf.c
static int perf_event_kprobe_open_legacy(const char *probe_name, bool retprobe,
                const char *kfunc_name, size_t offset, int pid)
{
    const size_t attr_sz = sizeof(struct perf_event_attr);
    struct perf_event_attr attr;
    // 传统方式添加kprobe
    err = add_kprobe_event_legacy(probe_name, retprobe, kfunc_name, offset);
    ...
    // 获取kprobe_perf类型
    type = determine_kprobe_perf_type_legacy(probe_name, retprobe);
    // attr设置，使用TRACEPOINT
    memset(&attr, 0, attr_sz);
    attr.size = attr_sz;
    attr.config = type;
    attr.type = PERF_TYPE_TRACEPOINT;
    // perf_event_open系统调用
    pfd = syscall(__NR_perf_event_open, &attr, pid < 0 ? -1 : pid, /* pid */
    	      pid == -1 ? 0 : -1, /* cpu */ -1 /* group_fd */,  PERF_FLAG_FD_CLOEXEC);
    if (pfd < 0) { ... }
    return pfd;
}
```

`add_kprobe_event_legacy` 函数添加kprobe事件，实现如下：

```C
// file: libbpf/src/libbpf.c
static int add_kprobe_event_legacy(const char *probe_name, bool retprobe,
                    const char *kfunc_name, size_t offset)
{
    return append_to_file(tracefs_kprobe_events(), "%c:%s/%s %s+0x%zx",
                retprobe ? 'r' : 'p',
                retprobe ? "kretprobes" : "kprobes",
                probe_name, kfunc_name, offset);
}
```

按照kprobe事件格式添加到 `kprobe_events` 文件中（通过 `tracefs_kprobe_events()` 函数获取）。`kprobe_events` 文件路径为 `/sys/kernel/debug/tracing/kprobe_events` 或 `/sys/kernel/debug/kprobe_events`。

在添加kprobe事件后，`determine_kprobe_perf_type_legacy` 函数获取添加kprobe的类型。实现如下：

```C
// file: libbpf/src/libbpf.c
static int determine_kprobe_perf_type_legacy(const char *probe_name, bool retprobe)
{
    char file[256];
    snprintf(file, sizeof(file), "%s/events/%s/%s/id",
        tracefs_path(), retprobe ? "kretprobes" : "kprobes", probe_name);
    return parse_uint_from_file(file, "%d\n");
}
```

看着比较熟悉？在第三篇中`ftrace_events`事件就注册在该路径下。传统方式添加kprobe的事件注册到 `/sys/kernel/debug/tracing/events/k[ret]probes/<probe_name>/` 目录下。


## 4 内核实现

### 4.1 kprobes初始化过程

`kprobes`的初始化过程分为两个步骤，在`start_kernel`函数中初始化和通过`initcall`机制初始化。

#### 1 `start_kernel` 阶段-- `ftrace`初始化

`kprobes` 是基于 ftrace 实现的。ftrace 是一个内部跟踪器，旨在帮助系统开发人员和设计人员查找内核内部发生的情况，最常见的用途之一是事件跟踪。整个内核中有数百个静态事件点，可以通过 tracefs 文件系统启用这些事件点，以查看内核某些部分发生的情况。

在 `start_kernel` 阶段进行 `ftrace` 初始化，如下：

```C
// file: init/main.c
start_kernel(void)
    --> ftrace_init()
```

`ftrace_init` 函数实现如下：

```C
// file: kernel/trace/ftrace.c
void __init ftrace_init(void)
{
    extern unsigned long __start_mcount_loc[];
    extern unsigned long __stop_mcount_loc[];
    unsigned long count, flags;
    ...
    count = __stop_mcount_loc - __start_mcount_loc;
    ret = ftrace_process_locs(NULL, __start_mcount_loc, __stop_mcount_loc);
    last_ftrace_enabled = ftrace_enabled = 1;
}
```

`__start_mcount_loc` 和 `__stop_mcount_loc` 在 `vmlinux.lds.h` 中定义，在内核开启 `CONFIG_FTRACE_MCOUNT_RECORD` 编译选项的情况下，通过`MCOUNT_REC()` 记录，最终放到 `.init.data`段中。如下：

```C
// file: include/asm-generic/vmlinux.lds.h
#ifdef CONFIG_FTRACE_MCOUNT_RECORD
#define MCOUNT_REC()	. = ALIGN(8);				\
			__start_mcount_loc = .;			\
			KEEP(*(__mcount_loc))			\
			KEEP_PATCHABLE				\
			__stop_mcount_loc = .;			\
			FTRACE_STUB_HACK			\
			ftrace_ops_list_func = arch_ftrace_ops_list_func;
#else
...

// file: include/asm-generic/vmlinux.lds.h
#define INIT_DATA							\
	...								\
	KERNEL_CTORS()							\
	MCOUNT_REC()
	...								\
```

`ftrace_init` 函数收集 `__mcount_loc` 段数据。`ftrace` 利用`gcc -pg`编译选项，在每个函数的开始位置增加桩函数(stub)。在x86架构下使用 `gcc -pg -mfentry` 编译选项，在函数的开始位置增加 `call __fentry__` 指令。在 `CONFIG_FUNCTION_TRACER` 编译选项打开时，编译时会增加`-pg`编译选项。

`scripts/recordmcount.pl` 脚本文件处理编译后的`.o`文件，经过处理后`.o`文件中新增了一个`__mcount_loc`段，里面记录了所有`mcount/fentry`的函数地址。

`ftrace_process_locs` 函数实现具体的工作，将 `__start_mcount_loc` 和 `__stop_mcount_loc` 之间的每个地址都创建一个 `struct dyn_ftrace` 结构，其中`ip`字段记录着函数开始的stub地址。这些 `dyn_ftrace` 存放在 `struct ftrace_page` 结构中， 这两个结构定义如下：

```C
// file: include/linux/ftrace.h
struct dyn_ftrace {
    unsigned long		ip; /* address of mcount call-site */
    unsigned long		flags;
    struct dyn_arch_ftrace	arch;
};

// file: kernel/trace/ftrace.c
struct ftrace_page {
	struct ftrace_page	*next;
	struct dyn_ftrace	*records;
	int			index;
	int			order;
};

#define ENTRY_SIZE sizeof(struct dyn_ftrace)
#define ENTRIES_PER_PAGE (PAGE_SIZE / ENTRY_SIZE)
```

`ftrace_process_locs` 实现如下：

```C
// file: kernel/trace/ftrace.c
static int ftrace_process_locs(struct module *mod, unsigned long *start, unsigned long *end)
{
    struct ftrace_page *start_pg;
    struct ftrace_page *pg;
    struct dyn_ftrace *rec;
    unsigned long count;
    ...
    count = end - start;
    // 分配ftrace的页
    start_pg = ftrace_allocate_pages(count);

    if (!mod) {
        // 初次调用时，设置 `ftrace_pages_start` 
        ftrace_pages = ftrace_pages_start = start_pg;
    } else { ... }

    // 设置每个ftrace的stub地址
    p = start;
    pg = start_pg;
    while (p < end) {
        unsigned long end_offset;
        // 调整函数地址，x86架构不调整
        addr = ftrace_call_adjust(*p++);
        if (!addr) continue;
        // 超过当前页时，切换到下一页
        end_offset = (pg->index+1) * sizeof(pg->records[0]);
        if (end_offset > PAGE_SIZE << pg->order) {
            if (WARN_ON(!pg->next)) break;
            pg = pg->next;
        }
        // 设置rec的stub地址
        rec = &pg->records[pg->index++];
        rec->ip = addr;
    }
    ...
    // 优化指令
    ftrace_update_code(mod, start_pg);
    ...
}
```

`gcc -pg -mfentry` 编译选项在函数开始位置增加了一条`call`指令，`__fentry__/mcount` 函数返回时调用`retq`指令。这两条指令有性能开销，Linux使用nop指令进行优化，`ftrace_update_code` 函数完成此项工作，实现如下：

```C
// file: kernel/trace/ftrace.c
static int ftrace_update_code(struct module *mod, struct ftrace_page *new_pgs)
{
    struct ftrace_page *pg;
    struct dyn_ftrace *p;
    ...
    for (pg = new_pgs; pg; pg = pg->next) {
        for (i = 0; i < pg->index; i++) {
            p = &pg->records[i];
            p->flags = rec_flags;
            // 单个`dyn_ftrace` nop指令优化
            if (init_nop && !ftrace_nop_initialize(mod, p))
                break;
            update_cnt++;
        }
    }
}
```

`ftrace_nop_initialize` 函数对单个 `dyn_ftrace` 进行nop指令优化，实现如下：

```C
// file: kernel/trace/ftrace.c
static int
ftrace_nop_initialize(struct module *mod, struct dyn_ftrace *rec)
    --> ftrace_init_nop(mod, rec);
            // file: arch/x86/kernel/ftrace.c
            // 优化为nop
        --> ftrace_make_nop(mod, rec, MCOUNT_ADDR);
            --> unsigned long ip = rec->ip;
            --> old = ftrace_call_replace(ip, addr);
            --> new = ftrace_nop_replace(); // x86_nops[5];
            --> if (addr == MCOUNT_ADDR)
                    // 更新调用信息，直接修改
                --> ftrace_modify_code_direct(ip, old, new);
                    --> text_poke_early((void *)ip, new_code, MCOUNT_INSN_SIZE);
                            // 直接修改内容
                        --> memcpy(addr, opcode, len);
```

x86_64架构下，Linux系统的`call`指令占用5个字节。如下：

```C
// file: arch/x86/include/asm/ftrace.h
#define MCOUNT_ADDR		((unsigned long)(__fentry__))
#define MCOUNT_INSN_SIZE	5 /* sizeof mcount call */
```

`ftrace_nop_replace` 函数返回`x86_nops[5]`，`x86_nops` 定义如下：

```C
// file: arch/x86/include/asm/ftrace.h
static const unsigned char x86nops[] =
{
    BYTES_NOP1, BYTES_NOP2, BYTES_NOP3, BYTES_NOP4,
    BYTES_NOP5, BYTES_NOP6, BYTES_NOP7, BYTES_NOP8,
};

// file: arch/x86/include/asm/ftrace.h
const unsigned char * const x86_nops[ASM_NOP_MAX+1] = 
{
    NULL,
    x86nops,
    x86nops + 1,
    x86nops + 1 + 2,
    x86nops + 1 + 2 + 3,
    x86nops + 1 + 2 + 3 + 4,
    x86nops + 1 + 2 + 3 + 4 + 5,
    x86nops + 1 + 2 + 3 + 4 + 5 + 6,
    x86nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
}；
```

`x86_nops` 数组存放nops的优化指令，对应 `BYTES_NOP1` ~ `BYTES_NOP8` 指令。在x86-64架构下优化指令如下：

```C
// file: arch/x86/include/asm/nops.h
/*
 * Generic 64bit nops from GAS:
 *
 * 1: nop
 * 2: osp nop
 * 3: nopl (%eax)
 * 4: nopl 0x00(%eax)
 * 5: nopl 0x00(%eax,%eax,1)
 * 6: osp nopl 0x00(%eax,%eax,1)
 * 7: nopl 0x00000000(%eax)
 * 8: nopl 0x00000000(%eax,%eax,1)
 */
#define BYTES_NOP1	0x90
#define BYTES_NOP2	0x66,BYTES_NOP1
#define BYTES_NOP3	0x0f,0x1f,0x00
#define BYTES_NOP4	0x0f,0x1f,0x40,0x00
#define BYTES_NOP5	0x0f,0x1f,0x44,0x00,0x00
#define BYTES_NOP6	0x66,BYTES_NOP5
#define BYTES_NOP7	0x0f,0x1f,0x80,0x00,0x00,0x00,0x00
#define BYTES_NOP8	0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00
```

#### 2 `initcall` 阶段-- `kprobe_trace`初始化

这个阶段进行`kprobe_trace`初始化，主要有：

* `core_initcall(init_kprobe_trace_early)`

`init_kprobe_trace_early` 注册 `trace_kprobe_ops` 到 `dyn_event_ops_list` 中，这样内核在 `postcore_initcall` 阶段没有加载 `tracefs` 时，可以设置kprobe事件。实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static __init int init_kprobe_trace_early(void)
{
    // 注册动态事件
    ret = dyn_event_register(&trace_kprobe_ops);
    ...    
}
core_initcall(init_kprobe_trace_early);
```

* `fs_initcall(init_kprobe_trace)`

`init_kprobe_trace` 创建 `kprobe_trace` 需要的 `kprobe_events` 和 `kprobe_profile` 文件。实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static __init int init_kprobe_trace(void)
{
    int ret;
    // `tracing` 目录
    ret = tracing_init_dentry();
    if (ret) return 0;
    // kprobe_events 文件
    trace_create_file("kprobe_events", TRACE_MODE_WRITE, NULL, NULL, &kprobe_events_ops);
    // kprobe_profile 文件
    trace_create_file("kprobe_profile", TRACE_MODE_READ, NULL, NULL, &kprobe_profile_ops);
    // 命令行 `kprobe_event=` 设置的kprobe事件
    setup_boot_kprobe_events();
    return 0;
}
fs_initcall(init_kprobe_trace);
```

* `late_initcall(debugfs_kprobe_init);`

`debugfs_kprobe_init` 创建 `kprobes` 的调试文件，`list` 、`enabled` 和 `blacklist` 三个文件。实现如下：

```C
// file: kernel/kprobes.c
static int __init debugfs_kprobe_init(void)
{
    struct dentry *dir;
    dir = debugfs_create_dir("kprobes", NULL);
    debugfs_create_file("list", 0400, dir, NULL, &kprobes_fops);
    debugfs_create_file("enabled", 0600, dir, NULL, &fops_kp);
    debugfs_create_file("blacklist", 0400, dir, NULL, &kprobe_blacklist_fops);
    return 0;
}
late_initcall(debugfs_kprobe_init);
```

### 4.2 KPROBE-PMU的内核实现

通过perf_event打开`kprobe`操作的pmu为`perf_kprobe`，注册过程如下：

```C
// file: kernel/events/core.c
static inline void perf_tp_register(void)
{
    ...
#ifdef CONFIG_KPROBE_EVENTS
    perf_pmu_register(&perf_kprobe, "kprobe", -1);
#endif
    ...
}
```

`perf_kprobe` 的定义如下：

```C
// file: kernel/events/core.c
static struct pmu perf_kprobe = {
	.task_ctx_nr	= perf_sw_context,
	.event_init	= perf_kprobe_event_init,
	.add		= perf_trace_add,
	.del		= perf_trace_del,
	.start		= perf_swevent_start,
	.stop		= perf_swevent_stop,
	.read		= perf_swevent_read,
	.attr_groups	= kprobe_attr_groups,
};
```

`perf_kprobe`提供了初始化、开启/停止、添加/删除、读取等基本的操作接口。

#### 1 初始化 -- `perf_kprobe_event_init`

perf_kprobe的初始化接口设置为 `.event_init = perf_kprobe_event_init`，实现过程如下：

##### (1) perf_kprobe初始化接口

```C
// file：kernel/events/core.c
static int perf_kprobe_event_init(struct perf_event *event)
{
    ...
    // 检查类型是否匹配
    if (event->attr.type != perf_kprobe.type) return -ENOENT;
    //  检查权限，
    if (!perfmon_capable()) return -EACCES;
    // 不支持分支采样
    if (has_branch_stack(event)) return -EOPNOTSUPP;
    // 是否为retprobe
    is_retprobe = event->attr.config & PERF_PROBE_CONFIG_IS_RETPROBE;
    // kprobe初始化
    err = perf_kprobe_init(event, is_retprobe);
    if (err) return err;
    // 设置销毁函数
    event->destroy = perf_kprobe_destroy;
    return 0;
}
```

`perf_kprobe_init`函数创建kprobe类型的perf_event追踪事件后，初始化perf_event。实现如下：

```C
// file: kernel/trace/trace_event_perf.c
int perf_kprobe_init(struct perf_event *p_event, bool is_retprobe)
{
    struct trace_event_call *tp_event;
    // 设置了func名称，复制到内核
    if (p_event->attr.kprobe_func) {
        func = strndup_user(u64_to_user_ptr(p_event->attr.kprobe_func), KSYM_NAME_LEN);
        ...
    }
    // 创建kprobe的追踪事件
    tp_event = create_local_trace_kprobe(
        func, (void *)(unsigned long)(p_event->attr.kprobe_addr),
        p_event->attr.probe_offset, is_retprobe);
    ...
    mutex_lock(&event_mutex);
    // perf_trace事件初始化
    ret = perf_trace_event_init(tp_event, p_event);
    mutex_unlock(&event_mutex);
}
```

##### (2) 创建kprobe追踪事件

`create_local_trace_kprobe` 函数创建kprobe追踪事件，创建`perf_event` 需要的 `trace_event_call` 。实现如下：

```C
// file: kernel/trace/trace_kprobe.c
struct trace_event_call *
create_local_trace_kprobe(char *func, void *addr, unsigned long offs, bool is_return)
{
    enum probe_print_type ptype;
    struct trace_kprobe *tk;
    ...
    // 设置event名称
    event = func ? func : "DUMMY_EVENT";
    // 创建并初始化kprobe
    tk = alloc_trace_kprobe(KPROBE_EVENT_SYSTEM, event, (void *)addr, func, offs, 
                    0 /* maxactive */, 0 /* nargs */, is_return);
    ...
    // 初始化
    init_trace_event_call(tk);
    // 获取kprobe事件打印类型，并设置print_fmt
    ptype = trace_kprobe_is_return(tk) ? PROBE_PRINT_RETURN : PROBE_PRINT_NORMAL;
    if (traceprobe_set_print_fmt(&tk->tp, ptype) < 0) { ... }
    // 注册kprobe事件
    ret = __register_trace_kprobe(tk);
    if (ret < 0) goto error;
    // 返回event_call
    return trace_probe_event_call(&tk->tp);
error:
    free_trace_kprobe(tk);
    return ERR_PTR(ret);
}
```

`alloc_trace_kprobe` 函数创建`trace_kprobe`结构，设置探针的地址、kprobe和kretprobe处理函数。如下：

```C
// file: kernel/trace/trace_kprobe.c
static struct trace_kprobe *
alloc_trace_kprobe(const char *group, const char *event,
                void *addr, const char *symbol, unsigned long offs, 
                int maxactive, int nargs, bool is_return)
{
    struct trace_kprobe *tk;
    tk = kzalloc(struct_size(tk, tp.args, nargs), GFP_KERNEL);
    tk->nhit = alloc_percpu(unsigned long);

    // 通过函数名称设置，设置名称和偏移量
    if (symbol) {
        tk->symbol = kstrdup(symbol, GFP_KERNEL);
        if (!tk->symbol) goto error;
        tk->rp.kp.symbol_name = tk->symbol;
        tk->rp.kp.offset = offs;
    } else
        // 通过地址设置，设置地址
        tk->rp.kp.addr = addr;

    // 设置kprobe和kretprobe处理函数
    if (is_return)
        tk->rp.handler = kretprobe_dispatcher;
    else
        tk->rp.kp.pre_handler = kprobe_dispatcher;

    tk->rp.maxactive = maxactive;
    // 分配trace_probe_event
    ret = trace_probe_init(&tk->tp, event, group, false);
    // 动态事件初始化
    dyn_event_init(&tk->devent, &trace_kprobe_ops);
    return tk;
}
```

`init_trace_event_call` 函数设置`trace_kprobe`结构中的`trace_event` 和 `trace_event->class` 的属性，这里设置了 `class->reg` 操作接口。如下：

```C
// file: kernel/trace/trace_kprobe.c
static inline void init_trace_event_call(struct trace_kprobe *tk)
{
    struct trace_event_call *call = trace_probe_event_call(&tk->tp);
    // 设置event函数
    if (trace_kprobe_is_return(tk)) {
        call->event.funcs = &kretprobe_funcs;
        call->class->fields_array = kretprobe_fields_array;
    } else {
        call->event.funcs = &kprobe_funcs;
        call->class->fields_array = kprobe_fields_array;
    }
    // 设置KPROBE标志和注册函数
    call->flags = TRACE_EVENT_FL_KPROBE;
    call->class->reg = kprobe_register;
}
```

##### (3) perf_trace事件初始化

在创建kprobe追踪事件后，调用 `perf_trace_event_init(tp_event, p_event);` 函数进行初始化。初始化的实现过程参见`第三篇`相关内容。初始化过程实现 `TRACE_REG_PERF_REGISTER` 和 `TRACE_REG_PERF_OPEN` 指令。

kprobe的注册函数设置为 `kprobe_register`，如下：

```C
// file: kernel/trace/trace_kprobe.c
static inline void init_trace_event_call(struct trace_kprobe *tk)
{
    ...
    call->class->reg = kprobe_register;
}
```

实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static int kprobe_register(struct trace_event_call *event,
			   enum trace_reg type, void *data)
{
    struct trace_event_file *file = data;
    switch (type) {
    case TRACE_REG_REGISTER: 
        return enable_trace_kprobe(event, file);
    case TRACE_REG_UNREGISTER: 
        return disable_trace_kprobe(event, file);

#ifdef CONFIG_PERF_EVENTS
    case TRACE_REG_PERF_REGISTER:
        return enable_trace_kprobe(event, NULL);
    case TRACE_REG_PERF_UNREGISTER:
        return disable_trace_kprobe(event, NULL);
    case TRACE_REG_PERF_OPEN:
    case TRACE_REG_PERF_CLOSE:
    case TRACE_REG_PERF_ADD:
    case TRACE_REG_PERF_DEL:
        return 0;
#endif
    }
    return 0;
}
```

可以看到，kprobe事件只关注 `REGISTER` 和 `UNREGISTER` 操作。

#### 2 添加 -- `perf_trace_add`

perf_kprobe的添加接口设置为 `.add = perf_trace_add`，实现过程如下：

```C
// file: kernel/trace/trace_event_perf.c
int perf_trace_add(struct perf_event *p_event, int flags)
    --> tp_event->class->reg(tp_event, TRACE_REG_PERF_ADD, p_event)
```

#### 3 删除 -- `perf_trace_del`

perf_kprobe的添加接口设置为 `.del = perf_trace_del`，实现过程如下：

```C
// file: kernel/trace/trace_event_perf.c
void perf_trace_del(struct perf_event *p_event, int flags)
    --> tp_event->class->reg(tp_event, TRACE_REG_PERF_DEL, p_event)
```

#### 4 开始 -- `perf_swevent_start`

perf_kprobe的开始接口设置为 `.start = perf_swevent_start`，实现过程如下：

```C
//file: kernel/events/core.c
static void perf_swevent_start(struct perf_event *event, int flags)
    --> event->hw.state = 0;
```

设置 `event->hw` 的状态为0。

#### 5 停止 -- `perf_swevent_stop`

perf_kprobe的停止接口设置为 `.stop = perf_swevent_stop`，实现过程如下：

```C
//file: kernel/events/core.c
static void perf_swevent_stop(struct perf_event *event, int flags)
    --> event->hw.state = PERF_HES_STOPPED;
```

设置 `event->hw` 的状态为停止状态。

#### 6 销毁 -- `perf_kprobe_destroy`

`perf_kprobe_destroy` 进行清理工作和释放资源，实现如下：

```C
//file: kernel/trace/trace_event_perf.c
void perf_kprobe_destroy(struct perf_event *p_event)
    --> perf_trace_event_close(p_event);
        --> tp_event->class->reg(tp_event, TRACE_REG_PERF_CLOSE, p_event);
    --> perf_trace_event_unreg(p_event);
        --> if (--tp_event->perf_refcount > 0) return;
            // 引用计数为0时，进行注销
        --> tp_event->class->reg(tp_event, TRACE_REG_PERF_UNREGISTER, NULL);
        --> free_percpu(tp_event->perf_events);
            // 缓冲区引用计数为0时，删除缓冲区
        --> if (!--total_ref_count) 
            --> for (i = 0; i < PERF_NR_CONTEXTS; i++) 
                --> free_percpu(perf_trace_buf[i]);
            	--> perf_trace_buf[i] = NULL;
	--> trace_event_put_ref(p_event->tp_event);
        // 销毁`trace_kprobe`
    --> destroy_local_trace_kprobe(p_event->tp_event);
            // 注销`trace_kprobe`
        --> __unregister_trace_kprobe(tk);
            // 释放`trace_kprobe`
        --> free_trace_kprobe(tk);
```

通过 `tp_event->class->reg` 进行关闭和注销，在必要时释放分配的缓冲区。最后销毁创建的`trace_kprobe`。

### 4.3 TRACEPOINT-PMU的内核实现

传统方式通过写入 `/sys/kernel/debug/tracing/kprobe_events` 或 `/sys/kernel/debug/kprobe_events` 文件的方式创建 `kprobes` 事件。

#### 1 `kprobe_events`文件操作接口

`kprobe_events` 文件的定义如下：

```C
// file: kernel/trace/trace_kprobe.c
static __init int init_kprobe_trace(void)
{
    ...
    trace_create_file("kprobe_events", TRACE_MODE_WRITE,
                NULL, NULL, &kprobe_events_ops);
    ...
}

// file: kernel/trace/trace_kprobe.c
static const struct file_operations kprobe_events_ops = {
	.owner          = THIS_MODULE,
	.open           = probes_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
	.write		= probes_write,
};
```

`kprobe_events` 文件的操作接口为 `kprobe_events_ops` 。 我们只关注写操作，即 `probes_write` 函数，实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static ssize_t probes_write(struct file *file, const char __user *buffer, 
                    size_t count, loff_t *ppos)
{
    return trace_parse_run_command(file, buffer, count, ppos, 
                    create_or_delete_trace_kprobe);
}
```

`trace_parse_run_command` 函数按行解析文件内容后，逐行调用`createfn`。 实现如下：

```C
// file: kernel/trace/trace.c
ssize_t trace_parse_run_command(struct file *file, const char __user *buffer,
                size_t count, loff_t *ppos, int (*createfn)(const char *))
{
    char *kbuf, *buf, *tmp;
    ...
    // 分配内核缓冲区
    kbuf = kmalloc(WRITE_BUFSIZE, GFP_KERNEL);

    while (done < count) {
        size = count - done;
        if (size >= WRITE_BUFSIZE) size = WRITE_BUFSIZE - 1;
        // 拷贝用户空间内存
        if (copy_from_user(kbuf, buffer + done, size)) { ret = -EFAULT; goto out; }

        kbuf[size] = '\0';
        buf = kbuf;
        do {
            // 截取换行符
            tmp = strchr(buf, '\n');
            ...
            done += size;
            // 截取注释符号
            tmp = strchr(buf, '#');
            if (tmp) *tmp = '\0';
            // 调用回调函数
            ret = createfn(buf);
            buf += size;
        } while (done < count);
    }
    ret = done;
 out:
    kfree(kbuf);
    return ret;   
}
```

`create_or_delete_trace_kprobe` 函数处理输入的行内容，实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static int create_or_delete_trace_kprobe(const char *raw_command)
{
    int ret;
    // 以`-`开始，释放`dyn_event`
    if (raw_command[0] == '-')
        return dyn_event_release(raw_command, &trace_kprobe_ops);
    // 创建 `trace_kprobe`
    ret = trace_kprobe_create(raw_command);
    return ret == -ECANCELED ? -EINVAL : ret;
}
```

#### 2 创建`trace_kprobe`

当每行内容（`raw_command`）不是以 `-` 开始时，调用 `trace_kprobe_create` 创建 `trace_kprobe`。实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static int trace_kprobe_create(const char *raw_command)
{
    return trace_probe_create(raw_command, __trace_kprobe_create);
}

// file: kernel/trace/trace_probe.c
int trace_probe_create(const char *raw_command, int (*createfn)(int, const char **))
{
    int argc = 0, ret = 0;
    char **argv;
    // 分割参数
    argv = argv_split(GFP_KERNEL, raw_command, &argc);
    if (!argv) return -ENOMEM;
    // 调用回调函数
    if (argc) 
        ret = createfn(argc, (const char **)argv);

    argv_free(argv);
    return ret;
}
```

`__trace_kprobe_create` 函数实现具体的创建工作，支持的解析格式如下：

```text
// kprobe 格式
p[:[GRP/][EVENT]] [MOD:]KSYM[+OFFS]|KADDR [FETCHARGS]
// kretprobe 格式
r[MAXACTIVE][:[GRP/][EVENT]] [MOD:]KSYM[+0] [FETCHARGS]
p[:[GRP/][EVENT]] [MOD:]KSYM[+0]%return [FETCHARGS]
```

实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static int __trace_kprobe_create(int argc, const char *argv[])
{
    // 默认group名称(`kprobes`)
    group = KPROBE_EVENT_SYSTEM; 
    ...
    // 解析第一个参数的第一个字节，判断是否为 kprobe 或者 kretprobe
    switch (argv[0][0]) {
    case 'r': is_return = true; break;
    case 'p': break;
    default: return -ECANCELED;
    }
    // 解析第一参数中 `event` 名称
    event = strchr(&argv[0][1], ':');
    if (event) event++;

    // 解析第一个参数，解析 `maxactive` 值
    if (isdigit(argv[0][1])) { ... }

    // 解析第二个参数， 解析 `addr` 或者 `symbol`,`offset`,`is_return`
    if (kstrtoul(argv[1], 0, (unsigned long *)&addr)) { ... }
    
    // 解析event名称
    if (event) {
        ret = traceprobe_parse_event_name(&event, &group, gbuf, event - argv[0]);
        if (ret) goto parse_error;
    }
    // 创建 `trace_kprobe`
    tk = alloc_trace_kprobe(group, event, addr, symbol, offset, maxactive, 
                    argc - 2, is_return);

    // probe args 参数
    argc -= 2; argv += 2;
    for (i = 0; i < argc && i < MAX_TRACE_ARGS; i++) {
        ...
        ret = traceprobe_parse_probe_arg(&tk->tp, i, argv[i], flags);
        if (ret)goto error;	/* This can be -ENOMEM */
    }

    // 设置打印格式
    ptype = is_return ? PROBE_PRINT_RETURN : PROBE_PRINT_NORMAL;
    ret = traceprobe_set_print_fmt(&tk->tp, ptype);
    if (ret < 0) goto error;

    // 注册 `trace_kprobe`
    ret = register_trace_kprobe(tk);
    ...
}
```

`register_trace_kprobe` 实现`trace_kprobe` 的注册，实现过程如下：

```C
// file: kernel/trace/trace_kprobe.c
static int register_trace_kprobe(struct trace_kprobe *tk)
        // 查找是否存在相同的组和名称的 `trace_kprobe`
    --> old_tk = find_trace_kprobe(trace_probe_name(&tk->tp), trace_probe_group_name(&tk->tp));
    --> if (old_tk) 
            // 类型的相同的情况下添加到 old_tk 中后，退出
        --> append_trace_kprobe(tk, old_tk);
                // 添加到 `old_tk` 的列表中
            --> ret = trace_probe_append(&tk->tp, &to->tp);
                    // 释放 tk
                --> list_del_init(&tp->list);
                --> trace_probe_event_free(tp->event);
                --> tp->event = to->event;
                    // 添加到 to 列表中
                --> list_add_tail(&tp->list, trace_probe_probe_list(to));
            // 注册 tk 
        -->  __register_trace_kprobe(tk);
            // 添加到动态事件列表中（`dyn_event_list`）
        --> dyn_event_add(&tk->devent, trace_probe_event_call(&tk->tp));
            --> list_add_tail(&ev->list, &dyn_event_list);
        // 注册kprobe_event
    --> ret = register_kprobe_event(tk);
        --> init_trace_event_call(tk);
            --> call->class->reg = kprobe_register;
        --> trace_probe_register_event_call(&tk->tp);
                // 注册 `trace_event`
            --> register_trace_event(&call->event);
                    // 分配type值
                --> event->type = alloc_trace_event_type();
            --> trace_add_event_call(call);
                    // 注册 trace事件
                --> __register_event(call, NULL);
                    --> event_init(call);
                    --> list_add(&call->list, &ftrace_events);
                --> __add_event_to_tracers(call);
                    --> list_for_each_entry(tr, &ftrace_trace_arrays, list)
                            // 添加新事件
                        --> __trace_add_new_event(call, tr);
                                // 事件的文件
                            --> file = trace_create_new_event(call, tr);
                                // 创建事件的文件
                            --> event_create_dir(tr->event_dir, file);
                                    // 创建`group`文件夹
                                --> d_events = event_subsystem_dir(tr, call->class->system, file, parent);
                                    // 创建`name`文件夹
                                --> file->dir = tracefs_create_dir(name, d_events);
                                    // 创建`id`文件
                                --> trace_create_file("id", TRACE_MODE_READ, file->dir, 
                                    (void *)(long)call->event.type, &ftrace_event_id_fops);
        // 注册`trace_kprobe``
    -->  __register_trace_kprobe(tk);
        // 添加`dyn_event`到动态事件列表中（`dyn_event_list`）
    --> dyn_event_add(&tk->devent, trace_probe_event_call(&tk->tp));
```

在注册过程中，`trace_probe_register_event_call` 函数将 `trace_kprobe` 注册到 `tracefs` 文件系统中，这样我们通过 `Tracepoint` 实现 kprobe事件的分析。具体实现过程参见 [Tracepoint的内核实现](doc/03-tracepoint%20inside.md)。

#### 3 销毁`trace_kprobe`

当每行内容（`raw_command`）以 `-` 开始时，调用 `dyn_event_release` 销毁 `trace_kprobe`。实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static int create_or_delete_trace_kprobe(const char *raw_command)
{
    if (raw_command[0] == '-')
        return dyn_event_release(raw_command, &trace_kprobe_ops);
    ...
}
```

`dyn_event_release` 函数实现动态事件的销毁，支持格式如下：

```text
-:[GRP/][EVENT]
```

实现如下：

```C
// file: kernel/trace/trace_dynevent.c
int dyn_event_release(const char *raw_command, struct dyn_event_operations *type)
{
    ...
    argv = argv_split(GFP_KERNEL, raw_command, &argc);

    // 格式处理
    if (argv[0][0] == '-') { ... }
    // 解析 `system`,`event`字段
    p = strchr(event, '/');
    if (p) { system = event; event = p + 1; *p = '\0'; }
    ...
    // 遍历 `dyn_event_list` 列表，`for_each_dyn_event_safe` 定义如下：
    // list_for_each_entry_safe(pos, n, &dyn_event_list, list)
    for_each_dyn_event_safe(pos, n) { 
        if (type && type != pos->ops) continue;
            // 检查事件是否匹配
        if (!pos->ops->match(system, event, argc - 1, (const char **)argv + 1, pos))
            continue;
            // 释放事件
        ret = pos->ops->free(pos);
        if (ret) break;
    }
    ...
}
```

`create_or_delete_trace_kprobe` 函数使用 `trace_kprobe_ops` 参数。 `trace_kprobe_ops` 定义了 `kprobe`事件的动态事件接口，定义如下：

```C
// file: kernel/trace/trace_kprobe.c
static struct dyn_event_operations trace_kprobe_ops = {
	.create = trace_kprobe_create,
	.show = trace_kprobe_show,
	.is_busy = trace_kprobe_is_busy,
	.free = trace_kprobe_release,
	.match = trace_kprobe_match,
};
```

`.match` 接口设置为 `trace_kprobe_match`，实现对`event`,`system`,`symbol+offset`/`addr`,`args`等逐级精确匹配。实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static bool trace_kprobe_match(const char *system, const char *event,
			int argc, const char **argv, struct dyn_event *ev)
{
    struct trace_kprobe *tk = to_trace_kprobe(ev);
    return (event[0] == '\0' ||
        strcmp(trace_probe_name(&tk->tp), event) == 0) &&   
        (!system || strcmp(trace_probe_group_name(&tk->tp), system) == 0) &&
        trace_kprobe_match_command_head(tk, argc, argv);
}
```

`.free` 接口设置为 `trace_kprobe_release`，释放动态事件，实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static int trace_kprobe_release(struct dyn_event *ev)
    --> struct trace_kprobe *tk = to_trace_kprobe(ev);
        // 注销 `trace_kprobe`
    --> unregister_trace_kprobe(tk);
            // 注销 `kprobe_event`
        --> unregister_kprobe_event(tk);
            --> trace_probe_unregister_event_call(&tk->tp);
                --> trace_remove_event_call(&tp->event->call);
                    --> probe_remove_event_call(call);
                        --> __trace_remove_event_call(call);
                                // 移除 `event`
                            --> event_remove(call);
                                    // 注销 `trace_event`
                                --> __unregister_trace_event(&call->event);
                                        // 释放`type`
                                    --> free_trace_event_type(event->type);
                                --> remove_event_from_tracers(call);
                                        // 删除 `event` 文件目录
                                    --> remove_event_file_dir(file);
                                        --> tracefs_remove(dir);
                                        --> remove_subsystem(file->system);
                            --> trace_destroy_fields(call);
                            --> free_event_filter(call->filter);
            // 注销 `trace_kprobe`
        --> __unregister_trace_kprobe(tk);
            // 删除 `dyn_event`
        --> dyn_event_remove(&tk->devent);
            --> list_del_init(&ev->list);
        --> trace_probe_unlink(&tk->tp);
        // 释放 `trace_kprobe`
    --> free_trace_kprobe(tk);
```

### 4.4 KPROBE-REG接口的实现

#### 1 注册过程

`__register_trace_kprobe` 函数注册`trace_kprobe`，进行一些列检查后，注册kprobe或kretprobe。实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static int __register_trace_kprobe(struct trace_kprobe *tk)
{
    // 安全检查
    ret = security_locked_down(LOCKDOWN_KPROBES);
    if (ret) return ret;
    // 检查是否注册
    if (trace_kprobe_is_registered(tk)) return -EINVAL;
    // 检查kprobe地址是否可追踪
    if (within_notrace_func(tk)) { ...	}

    // 检查kprobe是否启用，设置相关标记
    if (trace_probe_is_enabled(&tk->tp))
        tk->rp.kp.flags &= ~KPROBE_FLAG_DISABLED;
    else
        tk->rp.kp.flags |= KPROBE_FLAG_DISABLED;

    // 注册kprobe或kretprobe
    if (trace_kprobe_is_return(tk))
        ret = register_kretprobe(&tk->rp);
    else
        ret = register_kprobe(&tk->rp.kp);
}
```

##### （1）kprobe的注册过程

`register_kprobe` 函数实现kprobe的注册，整个过程比较复杂，实现过程如下：

```C
// file: kernel/kprobes.c
int register_kprobe(struct kprobe *p)
        // 获取kprobe地址
    --> addr = _kprobe_addr(p->addr, p->symbol_name, p->offset, &on_func_entry);
            // 获取符号的地址
        --> if (symbol_name)
            --> addr = kprobe_lookup_name(symbol_name, offset);
                --> kallsyms_lookup_name(name)
                    --> kallsyms_lookup_names(name, &i, NULL);
                    --> kallsyms_sym_address(get_symbol_seq(i));
        --> addr = (void *)addr + offset;
            // 获取实际的offset
        --> kallsyms_lookup_size_offset((unsigned long)addr, NULL, &offset)
        --> addr = (void *)addr - offset;
            // 架构平台调整kprobe地址
        --> addr = arch_adjust_kprobe_addr((unsigned long)addr, offset, on_func_entry);
            --> *on_func_entry = !offset;
            --> return (kprobe_opcode_t *)(addr + offset);
        // 设置kprobe地址
    --> p->addr = addr;
        // 检查kprobe是否已经注册
    -- warn_kprobe_rereg(p);
        // 检查kprobe地址是否安全
    --> check_kprobe_address_safe(p, &probed_mod);
        --> check_ftrace_location(p);
                // 如果是`dyn_ftrace`stub地址，设置FTRACE标记
            --> if (ftrace_location(addr) == addr)
                    --> p->flags |= KPROBE_FLAG_FTRACE;
            // 检查kprobe地址范围
            // 地址需要在内核核心代码区域或module代码区域
        --> if (!(core_kernel_text((unsigned long) p->addr) ||
        --> is_module_text_address((unsigned long) p->addr)) ||
            // 中断上下文区域，x86_64架构下为VSYSCALL区域
        --> in_gate_area_no_mm((unsigned long) p->addr) ||
            // kprobe黑名单，`NOKPROBE_SYMBOL`宏函数(`_kprobe_blacklist`段) 和
            // `__kprobes`标记的函数(`.kprobes.text`段)
        --> within_kprobe_blacklist((unsigned long) p->addr) ||
            // jump_label代码区域，`__jump_table`段
        --> jump_label_text_reserved(p->addr, p->addr)  ||
            // static_call代码区域，`static_call_sites`段
        --> static_call_text_reserved(p->addr, p->addr) ||
            // bug代码区域，`__bug_table`段
        --> find_bug((unsigned long) p->addr) ) { ret = -EINVAL; }
            // 检查kprobe是否在module区域
        --> *probed_mod = __module_text_address((unsigned long) p->addr);
        --> if (*probed_mod) { ... }
        // 检查kprobe地址是否已经注册kprobe
    --> old_p = get_kprobe(p->addr);
            // 从`kprobe_table`中查找地址
        --> head = &kprobe_table[hash_ptr(addr, KPROBE_HASH_BITS)];
        --> hlist_for_each_entry_rcu(p, head, hlist, lockdep_is_held(&kprobe_mutex))
            --> if (p->addr == addr) return p;
        // 存在注册的kprobe，注册aggr_kprobe
    --> if (old_p) { ret = register_aggr_kprobe(old_p, p); goto out; }
        // register_aggr_kprobe(struct kprobe *orig_p, struct kprobe *p)
        --> struct kprobe *ap = orig_p;
        --> if (!kprobe_aggrprobe(orig_p))
            --> ap = alloc_aggr_kprobe(orig_p);
            --> init_aggr_kprobe(ap, orig_p);
                    // 复制opcode、ainsn
                --> copy_kprobe(p, ap);
                --> ap->addr = p->addr;
                --> ap->flags = p->flags & ~KPROBE_FLAG_OPTIMIZED;
                    // 设置pre_handler处理函数
                --> ap->pre_handler = aggr_pre_handler;
                    // 设置 post_handler
                --> if (p->post_handler && !kprobe_gone(p))
                    --> ap->post_handler = aggr_post_handler;
                    // 将替换旧的kprobe-`p`添加到新的kprobe-`ap`列表中
                --> list_add_rcu(&p->list, &ap->list);
                    // 使用新的kprobe--ap替换旧的kprobe--p
                --> hlist_replace_rcu(&p->hlist, &ap->hlist);
        --> else if (kprobe_unused(ap))
            --> ret = reuse_unused_kprobe(ap);
        --> copy_kprobe(ap, p);
        --> add_new_kprobe(ap, p);
            --> list_add_rcu(&p->list, &ap->list);
                // 设置 post_handler
            --> if (p->post_handler && !ap->post_handler)
               --> ap->post_handler = aggr_post_handler;
        // 准备kprobe，设置原始指令(ainsn)
    --> prepare_kprobe(p);
        --> if (kprobe_ftrace(p))
            --> return arch_prepare_kprobe_ftrace(p);
                --> p->ainsn.insn = NULL;
                --> p->ainsn.boostable = false;
        --> arch_prepare_kprobe(p);
        // 将kprobe添加到`kprobe_table`中
    --> hlist_add_head_rcu(&p->hlist, &kprobe_table[hash_ptr(p->addr, KPROBE_HASH_BITS)]);
        // kprobes处于启用状态，且kprobe未禁用时，开启kprobe
    --> if (!kprobes_all_disarmed && !kprobe_disabled(p)) 
        --> arm_kprobe(p);
        // 优化kprobe
    --> try_to_optimize_kprobe(p);
        --> if (kprobe_ftrace(p)) return;
        --> ...
```

主要步骤如下：

* 获取kprobe地址。存在符号时，根据symbol和offset获取kallsyms的地址；检查addr是否在函数入口点；
* 检查kprobe地址是否安全。kprobe探针的地址必须在内核地址或module地址中，并且需要避开关键区域；
* kprobe地址已经注册时，注册aggr_kprobe。将同一个地址的kprobe事件形成链表；
* kprobe地址未注册时，准备kprobe，并添加到`kprobe_table`。
* 可能的话，开启kprobe。


##### （2）kretprobe的注册过程

`register_kretprobe` 函数实现kretprobe的注册，实现过程如下：

```C
// file: kernel/kprobes.c
int register_kretprobe(struct kretprobe *rp)
        // 检查kprobe地址是否在函数入口点
    --> kprobe_on_func_entry(rp->kp.addr, rp->kp.symbol_name, rp->kp.offset);
        --> _kprobe_addr(addr, sym, offset, &on_func_entry);
        // 指定kp.addr时，检查kprobe是否注册
    --> if (rp->kp.addr && warn_kprobe_rereg(&rp->kp)) return -EINVAL;
        // 检查kprobe地址是否在kretprobe黑名单中
    --> if (kretprobe_blacklist_size)
        --> addr = kprobe_addr(&rp->kp);
        --> for (i = 0; kretprobe_blacklist[i].name != NULL; i++)
            --> if (kretprobe_blacklist[i].addr == addr) return -EINVAL;
        // 设置kprobe处理函数
    --> rp->kp.pre_handler = pre_handler_kretprobe;
    --> rp->kp.post_handler = NULL;
        // maxactive设置
    --> if (rp->maxactive <= 0) rp->maxactive = max_t(unsigned int, 10, 2*num_possible_cpus());
        // x86架构使用RETHOOK方式设置
    --> rp->rh = rethook_alloc((void *)rp, kretprobe_rethook_handler);
        // maxactive分配
    --> for (i = 0; i < rp->maxactive; i++) 
        --> inst = kzalloc(sizeof(struct kretprobe_instance) + rp->data_size, GFP_KERNEL);
        --> rethook_add_node(rp->rh, &inst->node);
    --> rp->nmissed = 0;
        // 注册kprobe
    --> ret = register_kprobe(&rp->kp);
```

主要步骤如下：

* 检查kprobe地址。获取kprobe地址，kretprobe的探测地址必须在函数入口点；
* 检查kprobe地址是否安全。kretprobe探针的地址需要避开`kretprobe_blacklist`；
* 设置kretprobe的处理参数。如：入口处理函数(`pre_handler`)，maxactive数量；
* 设置kretprobe返回处理。以`RETHOOK`方式设置；
* 注册kprobe。
  

#### 2 注销过程

`__unregister_trace_kprobe` 函数注销`trace_kprobe`，注销kprobe或kretprobe。实现如下：

```C
// file：kernel/trace/trace_kprobe.c
static void __unregister_trace_kprobe(struct trace_kprobe *tk)
{
    if (trace_kprobe_is_registered(tk)) {
        if (trace_kprobe_is_return(tk))
            unregister_kretprobe(&tk->rp);
        else
            unregister_kprobe(&tk->rp.kp);
        // 清理kprobe
        INIT_HLIST_NODE(&tk->rp.kp.hlist);
        INIT_LIST_HEAD(&tk->rp.kp.list);
        if (tk->rp.kp.symbol_name) 
            tk->rp.kp.addr = NULL;
    }
}
```

##### （1）kprobe的注销过程

`unregister_kprobe` 函数实现kprobe的注销过程，实现如下：

```C
// file: kernel/kprobes.c
void unregister_kprobe(struct kprobe *p)
{
    unregister_kprobes(&p, 1);
}

// file: kernel/kprobes.c
void unregister_kprobes(struct kprobe **kps, int num)
{
    if (num <= 0) return;
    mutex_lock(&kprobe_mutex);
    for (i = 0; i < num; i++)
        if (__unregister_kprobe_top(kps[i]) < 0)
            kps[i]->addr = NULL;
    mutex_unlock(&kprobe_mutex);

    synchronize_rcu();
    for (i = 0; i < num; i++)
        if (kps[i]->addr)
            __unregister_kprobe_bottom(kps[i]);
}
```

`unregister_kprobes` 通过 `__unregister_kprobe_top` 和 `__unregister_kprobe_bottom` 方式注销`kprobe`。

`__unregister_kprobe_top` 函数禁用kprobe后，从hash中删除。实现如下：

```C
// file: kernel/kprobes.c
static int __unregister_kprobe_top(struct kprobe *p)
{
    // 禁用kprobe
    ap = __disable_kprobe(p);
    // kprobe是独立的(未优化的)，不是`aggrprobe`时，直接从`hash_list`中删除
    if (ap == p) goto disarmed;
    // 假设`kprobe`是`aggrprobe`的情况
    WARN_ON(!kprobe_aggrprobe(ap));
    // 只有一个kprobe且禁用的状态时，直接从`hash_list`中删除
    if (list_is_singular(&ap->list) && kprobe_disarmed(ap))
        goto disarmed;
    else
        ...

disarmed:
    hlist_del_rcu(&ap->hlist);
}    
```

`__unregister_kprobe_bottom` 函数注销`top`函数不能注销的kprobe。实现如下：

```C
// file: kernel/kprobes.c
static void __unregister_kprobe_bottom(struct kprobe *p)
{
    struct kprobe *ap;
    if (list_empty(&p->list))
        // 独立的kprobe
        arch_remove_kprobe(p);
    else if (list_is_singular(&p->list)) {
        // 最后一个 `aggrprobe`
    	ap = list_entry(p->list.next, struct kprobe, list);
    	list_del(&p->list);
    	free_aggr_kprobe(ap);
    }
}
```

##### （2）kretprobe的注销过程

`unregister_kretprobe` 函数实现kretprobe的注销过程，实现如下：

```C
// file: kernel/kprobes.c
void unregister_kretprobe(struct kretprobe *rp)
{
    unregister_kretprobes(&rp, 1);
}

// file: kernel/kprobes.c
void unregister_kretprobes(struct kretprobe **rps, int num)
{
    if (num <= 0) return;
    mutex_lock(&kprobe_mutex);
    for (i = 0; i < num; i++) {
        if (__unregister_kprobe_top(&rps[i]->kp) < 0)
            rps[i]->kp.addr = NULL;
#ifdef CONFIG_KRETPROBE_ON_RETHOOK
        rethook_free(rps[i]->rh);
#else
        rps[i]->rph->rp = NULL;
#endif
    }
    mutex_unlock(&kprobe_mutex);

    synchronize_rcu();
    for (i = 0; i < num; i++) {
        if (rps[i]->kp.addr) {
            __unregister_kprobe_bottom(&rps[i]->kp);
#ifndef CONFIG_KRETPROBE_ON_RETHOOK
            free_rp_inst(rps[i]);
#endif
        }
    }
}
```

`unregister_kretprobes` 同样通过 `__unregister_kprobe_top` 和 `__unregister_kprobe_bottom` 方式注销`kprobe`，除此之外，释放创建的`rethook`。

#### 3 开启过程

`perf_trace_event_reg` 函数调用了 `TRACE_REG_PERF_REGISTER` 指令，对应 `enable_trace_kprobe` 操作。`enable_trace_kprobe` 函数开启kprobe事件，实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static int enable_trace_kprobe(struct trace_event_call *call,
                struct trace_event_file *file)
{
    struct trace_probe *tp;
    struct trace_kprobe *tk;
    bool enabled;

    // 获取trace_probe事件
    tp = trace_probe_primary_from_call(call);
    enabled = trace_probe_is_enabled(tp);

    // 设置标记信息
    if (file) {
        ret = trace_probe_add_file(tp, file);
        if (ret) return ret;
    } else
        trace_probe_set_flag(tp, TP_FLAG_PROFILE);
    
    // 已经开启时，返回
    if (enabled) return 0;
    // 遍历tp事件中`probes`
    ist_for_each_entry(tk, trace_probe_probe_list(tp), tp.list) {
        if (trace_kprobe_has_gone(tk)) continue;
        // 开启kprobe事件
        ret = __enable_trace_kprobe(tk);
        if (ret) break;
        enabled = true;
    }
    ...
}
```

`__enable_trace_kprobe` 函数检查`trace_kprobe`事件状态，已注册且未删除时，开启kprobe或kretprobe事件，实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static inline int __enable_trace_kprobe(struct trace_kprobe *tk)
{
    int ret = 0;
    if (trace_kprobe_is_registered(tk) && !trace_kprobe_has_gone(tk)) {
        if (trace_kprobe_is_return(tk))
            ret = enable_kretprobe(&tk->rp);
        else
            ret = enable_kprobe(&tk->rp.kp);
    }
    return ret;
}
```

##### （1）kprobe的开启过程

`enable_kprobe` 开启kprobe事件，实现如下：

```C
// file: kernel/kprobes.c
int enable_kprobe(struct kprobe *kp)
{
    struct kprobe *p;
    ...
    // 获取原始的kprobe
    p = __get_valid_kprobe(kp);
    ...
    // 检查事件是否删除
    if (kprobe_gone(kp)) {...}
    // 清除disable标记
    if (p != kp) kp->flags &= ~KPROBE_FLAG_DISABLED;
    // kprobes处于启用状态，且kprobe未禁用时，开启kprobe
    if (!kprobes_all_disarmed && kprobe_disabled(p)) {
        p->flags &= ~KPROBE_FLAG_DISABLED;
        ret = arm_kprobe(p);
        ...
    }
    ...
}
```

`enable_kprobe` 在检查kprobe事件处于开启状态时，调用 `arm_kprobe` 函数实现真正的开启。`arm_kprobe` 实现如下：

```C
// file: kernel/kprobes.c
static int arm_kprobe(struct kprobe *kp)
{
    if (unlikely(kprobe_ftrace(kp)))
        return arm_kprobe_ftrace(kp);

    cpus_read_lock();
    mutex_lock(&text_mutex);
    __arm_kprobe(kp);
    mutex_unlock(&text_mutex);
    cpus_read_unlock();
    return 0;
}
```

`arm_kprobe` 根据`kprobe`是否为`ftrace`进行不同的设置，是`ftrace`时(我们使用的场景)，调用 `arm_kprobe_ftrace` 函数开启`kprobe_ftrace`事件。实现如下：

```C
// file: kernel/kprobes.c
static int arm_kprobe_ftrace(struct kprobe *p)
{
    bool ipmodify = (p->post_handler != NULL);
    return __arm_kprobe_ftrace(p,
        ipmodify ? &kprobe_ipmodify_ops : &kprobe_ftrace_ops,
        ipmodify ? &kprobe_ipmodify_enabled : &kprobe_ftrace_enabled);
}
```

`arm_kprobe_ftrace` 根据 `post_handler` 的设置与否，使用不同的 `ftrace_ops`。这两个 `ftrace_ops` 只是标记不同，调用的函数相同（ `kprobe_ftrace_handler` ），定义如下：

```C
// file: kernel/kprobes.c
static struct ftrace_ops kprobe_ftrace_ops __read_mostly = {
    .func = kprobe_ftrace_handler,
    .flags = FTRACE_OPS_FL_SAVE_REGS,
};

static struct ftrace_ops kprobe_ipmodify_ops __read_mostly = {
    .func = kprobe_ftrace_handler,
    .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,
};
```

`__arm_kprobe_ftrace` 函数将`kprobe`和`ftrace_ops`关联。将`kprobe`的挂载地址对应的`dyn_ftrace`，添加到 `ftrace_ops` 的 `filter_hash` 中；第一次使用时需要注册 `ftrace_ops` 。在更新或注册时，调用 `ftrace_run_update_code` 函数实现`dyn_ftrace`的调用更新。在`x86`架构下，`ftrace_ops` 使用蹦床(trampoline)，将 `dyn_ftrace` 时的入口调用地址设置为`trampoline`，实现控制流程的跳转。`__arm_kprobe_ftrace` 实现过程如下：

```C
// file: kernel/kprobes.c
static int __arm_kprobe_ftrace(struct kprobe *p, struct ftrace_ops *ops, int *cnt)
        // 获取符合添加的`dyn_ftrace`, 这里添加到`filter_hash`中
    --> ftrace_set_filter_ip(ops, (unsigned long)p->addr, 0, 0);
        --> ftrace_ops_init(ops);
        --> ftrace_set_addr(ops, &ip, 1, remove, reset, 1);
            --> ftrace_set_hash(ops, NULL, 0, ips, cnt, remove, reset, enable);
                    // 获取`dyn_ftrace`
                --> ftrace_match_addr(hash, ips, cnt, remove);
                    --> __ftrace_match_addr(hash, ips[i], remove);
                        --> ip = ftrace_location(ip);
                        --> add_hash_entry(hash, ip);
                    // 更新`ftrace_ops`的`filter_hash` 和 `notrace_hash`
                --> ftrace_hash_move_and_update_ops(ops, orig_hash, hash, enable);
                    --> ftrace_hash_move(ops, enable, orig_hash, hash);
                    --> ftrace_ops_update_code(ops, &old_hash_ops);
                            // `ftrace_ops`启用的情况下，更新 `ftrace` 调用
                        --> if (ops->flags & FTRACE_OPS_FL_ENABLED)
                            --> ftrace_run_modify_code(ops, FTRACE_UPDATE_CALLS, old_hash);
                                --> ops->flags |= FTRACE_OPS_FL_MODIFYING;
                                --> ftrace_run_update_code(command);
                                --> ops->flags &= ~FTRACE_OPS_FL_MODIFYING;
        // (*cnt == 0) 时，注册 `ftrace_ops`, ops->func 用于性能分析
    --> register_ftrace_function(ops);
            // 检查直接调用或修改ip是否支持
        --> prepare_direct_functions_for_ipmodify(ops);
        --> register_ftrace_function_nolock(ops);
            --> ftrace_ops_init(ops);
                // `ftrace` 初始设置
            --> ftrace_startup(ops, 0);
                    // 注册 `ftrace_function`
                --> __register_ftrace_function(ops);
                    --> add_ftrace_ops(&ftrace_ops_list, ops);
                    --> ops->saved_func = ops->func;
                        // 更新`ops->trampoline`蹦床
                    --> ftrace_update_trampoline(ops);
                            // file: arch/x86/kernel/ftrace.c
                            // x86架构下更新蹦床
                        --> arch_ftrace_update_trampoline(ops);
                                 // `trampoline` 不存在时，创建蹦床
                            --> if (!ops->trampoline)
                                --> ops->trampoline = create_trampoline(ops, &size);
                                --> ops->trampoline_size = size;
                                --> return;
                                // trampoline 存在的情况下，更新`trampoline`的调用函数
                                // 计算替换指令位置和获取调用函数
                            --> offset = calc_trampoline_call_offset(ops->flags & FTRACE_OPS_FL_SAVE_REGS);
                            --> ip = ops->trampoline + offset;
                            -->	func = ftrace_ops_get_func(ops);
                                // 生成调用指令和替换对应调用代码
                            --> new = ftrace_call_replace(ip, (unsigned long)func);
                            --> text_poke_bp((void *)ip, new, MCOUNT_INSN_SIZE, NULL);
                            // `ftrace_enabled` 开启的情况下，更新系统全局 `ftrace_function`
                        --> if (ftrace_enabled) update_ftrace_function();
                        // 更新ops标志，设置启用和添加状态
                    --> ops->flags |= FTRACE_OPS_FL_ENABLED | FTRACE_OPS_FL_ADDING;
                        // 尝试更新`filter_hash`中`dyn_ftrace`的`IPMODIFY`标记
                    --> ret = ftrace_hash_ipmodify_enable(ops);
                    // 依据`ops`的`filter_hash`和`notrace_hash`确定的范围，更新`dyn_ftrace`的flag
                --> if (ftrace_hash_rec_enable(ops, 1)) command |= FTRACE_UPDATE_CALLS;
                    --> __ftrace_hash_rec_update(ops, filter_hash, 1);
                        --> do_for_each_ftrace_rec(pg, rec)
                            --> rec->flags++;
                                // 设置`dyn_ftrace` 使用蹦床标志
                            --> if (ftrace_rec_count(rec) == 1 && ops->trampoline)
                                --> rec->flags |= FTRACE_FL_TRAMP;
                    // 开启`ftrace_startup`设置
                --> ftrace_startup_enable(command);
                    --> ftrace_run_update_code(command);
                            // 架构平台更新
                        --> arch_ftrace_update_code(command);
                            --> ftrace_modify_all_code(command);
                                    // 设置 `TRACE_FUNC` 标记时，更新`ftrace_call` 和 `ftrace_regs_call` 调用函数
                                --> if (update) update_ftrace_func(ftrace_ops_list_func);
                                    // 设置`UPDATE_CALLS` 标记时，替换`dyn_ftrace`调用信息
                                --> if (command & FTRACE_UPDATE_CALLS)
                                        // file: arch/x86/kernel/ftrace.c
                                    --> ftrace_replace_code(mod_flags | FTRACE_MODIFY_ENABLE_FL);
                                            // 遍历所有的`dyn_ftrace`
                                        --> for_ftrace_rec_iter(iter) 
                                            --> rec = ftrace_rec_iter_record(iter);
                                                // 获取 `dyn_ftrace` 事件的更新方式
                                            --> switch (ftrace_test_record(rec, enable))
                                            --> case FTRACE_UPDATE_MAKE_CALL:
                                            --> case FTRACE_UPDATE_MODIFY_CALL:
                                                    // 生成调用指令
                                                --> new = ftrace_call_replace(rec->ip, ftrace_get_addr_new(rec));
                                            --> case FTRACE_UPDATE_MAKE_NOP:
                                                --> new = ftrace_nop_replace();
                                                // 替换对应调用代码，以队列方式批量更新
                                            --> text_poke_queue((void *)rec->ip, new, MCOUNT_INSN_SIZE, NULL);
                                                // 更新`dyn_ftrace`的标志，更新启用状态信息
                                            --> ftrace_update_record(rec, enable);
                                            // 批量更新调用
                                        --> text_poke_finish();
                    // 更新ops标记，移除添加标记
                --> ops->flags &= ~FTRACE_OPS_FL_ADDING;
```

在 `x86`架构下，`create_trampoline` 函数创建`ftrace_ops` 的`trampoline`, 实现如下：

```C
// file: arch/x86/kernel/ftrace.c
static unsigned long
create_trampoline(struct ftrace_ops *ops, unsigned int *tramp_size)
{
    ...
    unsigned const char op_ref[] = { 0x48, 0x8b, 0x15 };
    unsigned const char retq[] = { RET_INSN_OPCODE, INT3_INSN_OPCODE };
    union ftrace_op_code_union op_ptr;
    // 确定`trampoline`的位置信息
    if (ops->flags & FTRACE_OPS_FL_SAVE_REGS) {
        start_offset = (unsigned long)ftrace_regs_caller;
        end_offset = (unsigned long)ftrace_regs_caller_end;
        op_offset = (unsigned long)ftrace_regs_caller_op_ptr;
        call_offset = (unsigned long)ftrace_regs_call;
        jmp_offset = (unsigned long)ftrace_regs_caller_jmp;
    } else {
        start_offset = (unsigned long)ftrace_caller;
        end_offset = (unsigned long)ftrace_caller_end;
        op_offset = (unsigned long)ftrace_caller_op_ptr;
        call_offset = (unsigned long)ftrace_call;
        jmp_offset = 0;
    }
    size = end_offset - start_offset;
    
    // 分配内存
    trampoline = alloc_tramp(size + RET_SIZE + sizeof(void *));
    if (!trampoline) return 0;
    
    // 确定`trampoline`的大小和占用的页
    *tramp_size = size + RET_SIZE + sizeof(void *);
    npages = DIV_ROUND_UP(*tramp_size, PAGE_SIZE);

    // 复制执行的代码到trampoline
    ret = copy_from_kernel_nofault(trampoline, (void *)start_offset, size);

    // 设置`retq`信息
    ip = trampoline + size;
    if (cpu_feature_enabled(X86_FEATURE_RETHUNK))
        __text_gen_insn(ip, JMP32_INSN_OPCODE, ip, x86_return_thunk, JMP32_INSN_SIZE);
    else
        memcpy(ip, retq, sizeof(retq));

    // 更新`jump`代码
    if (ops->flags & FTRACE_OPS_FL_SAVE_REGS) {
        ip = trampoline + (jmp_offset - start_offset);
        if (WARN_ON(*(char *)ip != 0x75)) goto fail;
        ret = copy_from_kernel_nofault(ip, x86_nops[2], 2);
        if (ret < 0) goto fail;
    }

    // 设置`ops`信息，ptr指向trampoline结束位置
    ptr = (unsigned long *)(trampoline + size + RET_SIZE);
    *ptr = (unsigned long)ops;

    // 复制 `op` 调用信息， 对应 `movq function_trace_op(%rip), %rdx` 汇编代码
    op_offset -= start_offset;
    memcpy(&op_ptr, trampoline + op_offset, OP_REF_SIZE);

    /* Are we pointing to the reference? */
    if (WARN_ON(memcmp(op_ptr.op, op_ref, 3) != 0)) goto fail;

    // 计算 `ptr` 的偏移量，将 `ptr` 内容当做参数 
    offset = (unsigned long)ptr;
    offset -= (unsigned long)trampoline + op_offset + OP_REF_SIZE;

    // 更新 `op` 偏移量后，更新`op`代码
    op_ptr.offset = offset;
    memcpy(trampoline + op_offset, &op_ptr, OP_REF_SIZE);

    // 更新 `call ftrace_stub` 指令
    mutex_lock(&text_mutex);
    call_offset -= start_offset;
    // ops->func 或者 `ftrace_ops_assist_func`
    dest = ftrace_ops_get_func(ops);
    // 替换 `call ftrace_stub` 代码，
    memcpy(trampoline + call_offset,
        text_gen_insn(CALL_INSN_OPCODE, trampoline + call_offset, dest),
        CALL_INSN_SIZE);
    mutex_unlock(&text_mutex);

    // 设置`ALLOC_TRAMP`标志
    ops->flags |= FTRACE_OPS_FL_ALLOC_TRAMP;

    // 设置`trampoline`内存区域只读
    set_memory_rox((unsigned long)trampoline, npages);
    return (unsigned long)trampoline;
    ...
}
```

`trampoline` 基于 `ftrace_regs_caller` 或者 `ftrace_caller` 实现的。在复制对应的代码后，修改相应位置的代码最终实现`ftrace_ops` 的`trampoline`。

`ftrace_regs_caller` 和 `ftrace_caller` 的定义如下：

```C
// file: arch/x86/kernel/ftrace_64.S
SYM_FUNC_START(ftrace_caller)
    save_mcount_regs
    ...
SYM_INNER_LABEL(ftrace_caller_op_ptr, SYM_L_GLOBAL)
    ANNOTATE_NOENDBR
    /* Load the ftrace_ops into the 3rd parameter */
    movq function_trace_op(%rip), %rdx
    ...
SYM_INNER_LABEL(ftrace_call, SYM_L_GLOBAL)
    ANNOTATE_NOENDBR
    call ftrace_stub
SYM_INNER_LABEL(ftrace_caller_end, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	RET
SYM_FUNC_END(ftrace_caller);

// file: arch/x86/kernel/ftrace_64.S
SYM_FUNC_START(ftrace_regs_caller)
    pushfq
    ...
SYM_INNER_LABEL(ftrace_regs_caller_op_ptr, SYM_L_GLOBAL)
    ANNOTATE_NOENDBR
    /* Load the ftrace_ops into the 3rd parameter */
    movq function_trace_op(%rip), %rdx
    ...
SYM_INNER_LABEL(ftrace_regs_call, SYM_L_GLOBAL)
    ANNOTATE_NOENDBR
    call ftrace_stub
    ...
SYM_INNER_LABEL(ftrace_regs_caller_jmp, SYM_L_GLOBAL)
    ANNOTATE_NOENDBR
    jnz	1f
    ...
SYM_INNER_LABEL(ftrace_regs_caller_end, SYM_L_GLOBAL)
    ANNOTATE_NOENDBR
    RET
SYM_FUNC_END(ftrace_regs_caller)
STACK_FRAME_NON_STANDARD_FP(ftrace_regs_caller)
```

##### （2）kretprobe的开启过程

`enable_kretprobe` 函数同样开启`kprobe`, 实现如下：

```C
// file: include/linux/kprobes.h
static inline int enable_kretprobe(struct kretprobe *rp)
{
    return enable_kprobe(&rp->kp);
}
```

#### 4 禁用过程

在销毁`kprobe`过程中，`perf_trace_event_unreg` 函数调用了 `TRACE_REG_PERF_UNREGISTER` 指令，对应 `disable_trace_kprobe` 操作。`disable_trace_kprobe` 函数禁用kprobe事件，实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static int disable_trace_kprobe(struct trace_event_call *call, struct trace_event_file *file)
{
    struct trace_probe *tp;
    tp = trace_probe_primary_from_call(call);
    ...
    // 清除标记
    if (file) {
        if (!trace_probe_get_file_link(tp, file)) return -ENOENT;
        if (!trace_probe_has_single_file(tp))goto out;
        trace_probe_clear_flag(tp, TP_FLAG_TRACE);
    } else
        trace_probe_clear_flag(tp, TP_FLAG_PROFILE);
    // 禁用 `trace_probe`
    if (!trace_probe_is_enabled(tp))
        __disable_trace_kprobe(tp);

 out:
    if (file) trace_probe_remove_file(tp, file);
    return 0;
}
```

`__disable_trace_kprobe` 函数进行禁用操作，遍历`probes`逐个禁用，实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static void __disable_trace_kprobe(struct trace_probe *tp)
{
    struct trace_kprobe *tk;
    list_for_each_entry(tk, trace_probe_probe_list(tp), tp.list) {
        if (!trace_kprobe_is_registered(tk)) continue;
        if (trace_kprobe_is_return(tk))
            disable_kretprobe(&tk->rp);
        else
            disable_kprobe(&tk->rp.kp);
    }
}
```

##### （1）kprobe的禁用过程

`disable_kprobe` 函数禁用`kprobe` 事件，实现如下：

```C
// file: kernel/kprobes.c
int disable_kprobe(struct kprobe *kp)
{
    mutex_lock(&kprobe_mutex);
    p = __disable_kprobe(kp);
    if (IS_ERR(p)) ret = PTR_ERR(p);
    mutex_unlock(&kprobe_mutex);
}

// file: kernel/kprobes.c
static struct kprobe *__disable_kprobe(struct kprobe *p)
{
    struct kprobe *orig_p;
    // 获取原始的kprobe
    orig_p = __get_valid_kprobe(p);
    ...
    if (!kprobe_disabled(p))
    {
        // 子kprobe时，设置`DISABLED`标记即可
        if (p != orig_p) p->flags |= KPROBE_FLAG_DISABLED;
        // 禁用这个或父kprobe
        if (p == orig_p || aggr_kprobe_disabled(orig_p)) {
            if (!kprobes_all_disarmed && !kprobe_disabled(orig_p)) {
                // 禁用kprobe
                ret = disarm_kprobe(orig_p, true);
                if (ret) {... }
            }
            orig_p->flags |= KPROBE_FLAG_DISABLED;
        }
    }
}
```

`__disable_kprobe` 在检查kprobe事件状态后，调用 `disarm_kprobe` 函数实现真正的禁用。`disarm_kprobe` 实现如下：

```C
// file: kernel/kprobes.c
static int disarm_kprobe(struct kprobe *kp, bool reopt)
{
    // 禁用`kprobe_ftrace`
    if (unlikely(kprobe_ftrace(kp)))
        return disarm_kprobe_ftrace(kp);

    cpus_read_lock();
    mutex_lock(&text_mutex);
    __disarm_kprobe(kp, reopt);
    mutex_unlock(&text_mutex);
    cpus_read_unlock();
	return 0;
}
```

和`arm_kprobe`一样，`disarm_kprobe` 根据`kprobe`是否为`ftrace`进行不同的设置，是`ftrace`时(我们使用的场景)，调用 `disarm_kprobe_ftrace` 函数禁用`kprobe_ftrace`事件。实现如下：

```C
// file: kernel/kprobes.c
static int disarm_kprobe_ftrace(struct kprobe *p)
{
    bool ipmodify = (p->post_handler != NULL);
    return __disarm_kprobe_ftrace(p,
        ipmodify ? &kprobe_ipmodify_ops : &kprobe_ftrace_ops,
        ipmodify ? &kprobe_ipmodify_enabled : &kprobe_ftrace_enabled);
}
```

`__disarm_kprobe_ftrace` 函数将`kprobe`和`ftrace_ops`解除关联。首先检查是否需要注销`ftrace_ops`，之后恢复`filter_hash`中的 `dyn_ftrace`的调用信息。`__arm_kprobe_ftrace` 实现过程如下：

```C
// file: kernel/kprobes.c
static int __disarm_kprobe_ftrace(struct kprobe *p, struct ftrace_ops *ops, int *cnt)
        // (*cnt == 1)时，注销`ftrace_ops`
    --> unregister_ftrace_function(ops);
        --> ftrace_shutdown(ops, 0);
                // 注销 `ftrace_function`
            --> __unregister_ftrace_function(ops);
                --> remove_ftrace_ops(&ftrace_ops_list, ops);
                --> if (ftrace_enabled) update_ftrace_function();
                --> ops->func = ops->saved_func;
                // 尝试更新`filter_hash`中`dyn_ftrace`的`IPMODIFY`标记
            --> ftrace_hash_ipmodify_disable(ops);
                // 依据`ops`的`filter_hash`和`notrace_hash`确定的范围，更新`dyn_ftrace`的flag
            --> if (ftrace_hash_rec_disable(ops, 1)) command |= FTRACE_UPDATE_CALLS;
                --> __ftrace_hash_rec_update(ops, filter_hash, 0);
                    --> do_for_each_ftrace_rec(pg, rec)
                        --> rec->flags--;
                            // 清除 `dyn_ftrace` 蹦床标志
                        --> rec->flags &= ~FTRACE_FL_TRAMP;
                // 更新ops标志，清除启用标记和设置删除状态
            --> ops->flags &= ~FTRACE_OPS_FL_ENABLED;
            --> ops->flags |= FTRACE_OPS_FL_REMOVING;
            --> removed_ops = ops;
                // 遍历所有的`dyn_ftrace`, 更新调用信息
            --> ftrace_run_update_code(command);
            --> removed_ops = NULL;
                // 更新ops标志，清除删除状态
            --> ops->flags &= ~FTRACE_OPS_FL_REMOVING;
                // 如果`ops`是动态创建的，删除trampoline
            --> if (ops->flags & FTRACE_OPS_FL_DYNAMIC)
                --> ftrace_trampoline_free(ops);
                    --> arch_ftrace_trampoline_free(ops);
                        --> tramp_free((void *)ops->trampoline);
                        --> ops->trampoline = 0;
            // 注销`IPMODIFY`，清理直接调用
        --> cleanup_direct_functions_after_ipmodify(ops);
         // 获取符合添加的`dyn_ftrace`, 这里从`filter_hash`中删除
    --> ftrace_set_filter_ip(ops, (unsigned long)p->addr, 1, 0);
        --> ftrace_ops_init(ops);
        --> ftrace_set_addr(ops, &ip, 1, remove, reset, 1);
            --> ftrace_set_hash(ops, NULL, 0, ips, cnt, remove, reset, enable);
                    // 获取`dyn_ftrace` 
                --> ftrace_match_addr(hash, ips, cnt, remove);
                    --> __ftrace_match_addr(hash, ips[i], remove);
                        --> ip = ftrace_location(ip);
                        --> free_hash_entry(hash, entry);
                    // 更新`ftrace_ops`的`filter_hash` 和 `notrace_hash`
                --> ftrace_hash_move_and_update_ops(ops, orig_hash, hash, enable);
```

##### （2）kretprobe的禁用过程

`disable_kretprobe` 函数同样禁用`kprobe`, 实现如下：

```C
// file: include/linux/kprobes.h
static inline int disable_kretprobe(struct kretprobe *rp)
{
    return disable_kprobe(&rp->kp);
}
```

#### 5 设置BPF程序

在 `perf_event` 通过`ioctl`方式或`bpf`系统调用（`BPF_LINK_CREATE`）设置BPF程序时，调用 `perf_event_set_bpf_prog` 函数进行设置，如下：

```C
// file: kernel/events/core.c
int perf_event_set_bpf_prog(struct perf_event *event, struct bpf_prog *prog, u64 bpf_cookie)
{
	if (!perf_event_is_tracing(event))
		return perf_event_set_bpf_handler(event, prog, bpf_cookie);
	...
	return perf_event_attach_bpf_prog(event, prog, bpf_cookie);
}

// file: kernel/trace/bpf_trace.c
int perf_event_attach_bpf_prog(struct perf_event *event, struct bpf_prog *prog, u64 bpf_cookie)
{
	struct bpf_prog_array *old_array;
	struct bpf_prog_array *new_array;
	...
	mutex_lock(&bpf_event_mutex);
	if (event->prog)
		goto unlock;
	old_array = bpf_event_rcu_dereference(event->tp_event->prog_array);
	// 添加prog到列表中
	ret = bpf_prog_array_copy(old_array, NULL, prog, bpf_cookie, &new_array);
	event->prog = prog;
	event->bpf_cookie = bpf_cookie;
	rcu_assign_pointer(event->tp_event->prog_array, new_array);
	...
unlock:
	mutex_unlock(&bpf_event_mutex);
	return ret;
}
```

`kprobe`和`Tracepoint`属于`tracing`事件，通过`perf_event_attach_bpf_prog` 添加bpf程序到 `tp_event->prog_array` 列表中。

### 4.5 kprobe的触发过程

#### 1 触发`ftrace_handler`

在内核调用我们探测的函数时，进入设置的蹦床中执行。在蹦床中调用设置的 `kprobe_ftrace_handler` 函数。后者实现如下：

```C
// file: arch/x86/kernel/kprobes/ftrace.c
void kprobe_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct kprobe *p;
    struct kprobe_ctlblk *kcb;
    int bit;

    // 检查并设置递归调用标记
    bit = ftrace_test_recursion_trylock(ip, parent_ip);
    if (bit < 0) return;
    // 获取kprobe，从`kprobe_table`中获取
    p = get_kprobe((kprobe_opcode_t *)ip);
    // kprobe不存在或禁用状态时退出
    if (unlikely(!p) || kprobe_disabled(p)) goto out;

    kcb = get_kprobe_ctlblk();
    if (kprobe_running()) {
        // 有正在运行的kprobe时，增加missed计数
        kprobes_inc_nmissed_count(p);
    } else {
        unsigned long orig_ip = regs->ip;
        // kprobe handler 的断点位置 
        regs->ip = ip + sizeof(kprobe_opcode_t);

        // 设置当前CPU执行的kprobe
        __this_cpu_write(current_kprobe, p);
        kcb->kprobe_status = KPROBE_HIT_ACTIVE;
        // 执行`pre_handler`
        if (!p->pre_handler || !p->pre_handler(p, regs)) {
            // 模拟单步调试
            regs->ip = (unsigned long)p->addr + MCOUNT_INSN_SIZE;
            if (unlikely(p->post_handler)) {
                kcb->kprobe_status = KPROBE_HIT_SSDONE;
                // 执行`post_handler`
                p->post_handler(p, regs, 0);
            }
            regs->ip = orig_ip;
        }
        // 清除当前CPU执行的kprobe
        __this_cpu_write(current_kprobe, NULL);
    }
out:
    // 清除递归调用标记
    ftrace_test_recursion_unlock(bit);
}
```

#### 2 触发`pre_handler`

在同一个地址中添加多个`kprobe`时，创建了`aggr_kprobe`，设置了`pre_handler` 处理函数，如下：

```C
// file: kernel/kprobes.c
static void init_aggr_kprobe(struct kprobe *ap, struct kprobe *p)
{
    ...
    ap->flags = p->flags & ~KPROBE_FLAG_OPTIMIZED;
    ap->pre_handler = aggr_pre_handler;
}
```

`aggr_pre_handler` 函数遍历`kprobe->list`，逐个调用`pre_handler`。实现过程如下：

```C
// file: kernel/kprobes.c
static int aggr_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct kprobe *kp;
    list_for_each_entry_rcu(kp, &p->list, list) {
        if (kp->pre_handler && likely(!kprobe_disabled(kp))) {
            set_kprobe_instance(kp);
            if (kp->pre_handler(kp, regs))
                return 1;
        }
        reset_kprobe_instance();
    }
    return 0;
}
```

#### 3 `kprobe`的执行过程

在注册kprobe过程中设置了`pre_handler`，如下：

```C
// file: kernel/trace/trace_kprobe.c
static struct trace_kprobe *alloc_trace_kprobe(const char *group, ...)
{
    ...
    if (is_return)
        tk->rp.handler = kretprobe_dispatcher;
    else
        tk->rp.kp.pre_handler = kprobe_dispatcher;
}
```

`kprobe_dispatcher` 函数的实现过程如下：

```C
// file: kernel/trace/trace_kprobe.c
static int kprobe_dispatcher(struct kprobe *kp, struct pt_regs *regs)
{
    struct trace_kprobe *tk = container_of(kp, struct trace_kprobe, rp.kp);
    int ret = 0;
    raw_cpu_inc(*tk->nhit);

    if (trace_probe_test_flag(&tk->tp, TP_FLAG_TRACE))
        kprobe_trace_func(tk, regs);
#ifdef CONFIG_PERF_EVENTS
    if (trace_probe_test_flag(&tk->tp, TP_FLAG_PROFILE))
        ret = kprobe_perf_func(tk, regs);
#endif
    return ret;
}
```

`kprobe_dispatcher` 函数检查`TRACE` 和 `PROFILE` 标记，存在对应标记时，调用 `kprobe_trace_func` 和 `kprobe_perf_func` 函数。我们需要调用BPF程序时，在`trace_event`初始化时调用了 `TRACE_REG_PERF_REGISTER` 指令，设置了 `TP_FLAG_PROFILE` 标记，将执行 `kprobe_perf_func` 函数。实现过程如下：

```C
// file: kernel/trace/trace_kprobe.c
static int kprobe_perf_func(struct trace_kprobe *tk, struct pt_regs *regs)
{
    struct trace_event_call *call = trace_probe_event_call(&tk->tp);
    struct kprobe_trace_entry_head *entry;
    ...
    if (bpf_prog_array_valid(call)) {
        // 记录原始执行pc的位置
        unsigned long orig_ip = instruction_pointer(regs);
        // 调用BPF程序
        ret = trace_call_bpf(call, regs);
        // 检查是否修改了pc位置，如果修改了返回1，进行单步处理
        if (orig_ip != instruction_pointer(regs)) return 1;
        if (!ret) return 0;
    }
    // 检查是否存在`perf_events`
    head = this_cpu_ptr(call->perf_events);
    if (hlist_empty(head)) return 0;

    ...
    entry = perf_trace_buf_alloc(size, NULL, &rctx);
    if (!entry) return 0;
    // 获取entry信息
    entry->ip = (unsigned long)tk->rp.kp.addr;
    memset(&entry[1], 0, dsize);
    store_trace_args(&entry[1], &tk->tp, regs, sizeof(*entry), dsize);
    // perf_trace 默认执行操作
    perf_trace_buf_submit(entry, size, rctx, call->event.type, 1, regs, head, NULL);
    return 0;
}
```

`trace_call_bpf` 函数执行BPF程序，实现如下：

```C
// file: kernel/trace/bpf_trace.c
unsigned int trace_call_bpf(struct trace_event_call *call, void *ctx)
{
    ...
    ret = bpf_prog_run_array(rcu_dereference(call->prog_array), ctx, bpf_prog_run);
    ...
}
```

#### 4 `kretprobe`的执行过程

在注册`kretprobe`过程中，设置了`pre_handler` 和 `rethook`，如下：

```C
// file: kernel/kprobes.c
int register_kretprobe(struct kretprobe *rp)
{
    ...
    rp->kp.pre_handler = pre_handler_kretprobe;
    ...
    rp->rh = rethook_alloc((void *)rp, kretprobe_rethook_handler);
}
```

##### （1）设置rethook

`pre_handler_kretprobe` 函数实现`kretprobe`的准备过程，实现如下：

```C
// file: kernel/kprobes.c
static int pre_handler_kretprobe(struct kprobe *p, struct pt_regs *regs)
{
    struct kretprobe *rp = container_of(p, struct kretprobe, kp);
    struct kretprobe_instance *ri;
    struct rethook_node *rhn;

    // 获取rethook
    rhn = rethook_try_get(rp->rh);
    if (!rhn) {	rp->nmissed++; return 0; } 

    ri = container_of(rhn, struct kretprobe_instance, node);
    if (rp->entry_handler && rp->entry_handler(ri, regs))
        rethook_recycle(rhn);
    else
        // 设置rethook
        rethook_hook(rhn, regs, kprobe_ftrace(p));
    return 0;
}
```

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

`kretprobe`设置`rethook`的处理函数为`kretprobe_rethook_handler`，实现过程如下：

```C
// file: kernel/kprobes.c
static void kretprobe_rethook_handler(struct rethook_node *rh, void *data,
                        struct pt_regs *regs)
{
    struct kretprobe *rp = (struct kretprobe *)data;
    ...

    __this_cpu_write(current_kprobe, &rp->kp);
    kcb = get_kprobe_ctlblk();
    kcb->kprobe_status = KPROBE_HIT_ACTIVE;

    ri = container_of(rh, struct kretprobe_instance, node);
    // 调用kretprobe处理函数
    rp->handler(ri, regs);

    __this_cpu_write(current_kprobe, NULL);
}
```

`kretprobe_rethook_handler` 函数执行 `kretprobe` 设置的处理函数（rp->handler）, 设置如下：

```C
// file: kernel/trace/trace_kprobe.c
static struct trace_kprobe *alloc_trace_kprobe(const char *group, ...)
{
    ...
    if (is_return)
        tk->rp.handler = kretprobe_dispatcher;
    ...
}
```

##### （3）执行`kretprobe_dispatcher`

`kretprobe_dispatcher` 函数和`kprobe_dispatcher` 函数类似，判断`TRACE`和`PROFILE`标记后调用相关函数，实现如下：

```C
// file: kernel/trace/trace_kprobe.c
static int kretprobe_dispatcher(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kretprobe *rp = get_kretprobe(ri);
    struct trace_kprobe *tk;

    if (unlikely(!rp)) return 0;

    tk = container_of(rp, struct trace_kprobe, rp);
    raw_cpu_inc(*tk->nhit);

    if (trace_probe_test_flag(&tk->tp, TP_FLAG_TRACE))
        kretprobe_trace_func(tk, ri, regs);
#ifdef CONFIG_PERF_EVENTS
    if (trace_probe_test_flag(&tk->tp, TP_FLAG_PROFILE))
        kretprobe_perf_func(tk, ri, regs);
#endif
    return 0;	/* We don't tweak kernel, so just return 0 */
}
```

我们需要调用BPF程序时，在`trace_event`初始化时调用了 `TRACE_REG_PERF_REGISTER` 指令，设置了 `TP_FLAG_PROFILE` 标记，将执行 `kretprobe_perf_func` 函数。实现过程如下：

```C
// file: kernel/trace/trace_kprobe.c
static void kretprobe_perf_func(struct trace_kprobe *tk, struct kretprobe_instance *ri, 
                struct pt_regs *regs)
{
    struct trace_event_call *call = trace_probe_event_call(&tk->tp);
    struct kretprobe_trace_entry_head *entry;
    ...
    // 设置了BPF程序，通过`trace_call_bpf`函数调用BPF程序
    if (bpf_prog_array_valid(call) && !trace_call_bpf(call, regs))
        return;
    // 检查是否存在`perf_events`
    head = this_cpu_ptr(call->perf_events);
    if (hlist_empty(head)) return 0;

    ...
    entry = perf_trace_buf_alloc(size, NULL, &rctx);
    if (!entry) return 0;
    // 获取entry信息
    entry->func = (unsigned long)tk->rp.kp.addr;
    entry->ret_ip = get_kretprobe_retaddr(ri);
    store_trace_args(&entry[1], &tk->tp, regs, sizeof(*entry), dsize);
    // perf_trace 默认执行操作
    perf_trace_buf_submit(entry, size, rctx, call->event.type, 1, regs, head, NULL);
}
```

### 4.6 GDB调试验证

我们通过qemu搭建Linux内核调试环境后，通过gdb调试内核。搭建过程参见[在macOS下搭建Linux内核调试环境](https://github.com/mannkafai/mkf.github.io/blob/main/debug%20linux%20kernel%20on%20macos.md)。

以`kprobe`程序为例，我们通过gdb查看 `do_unlinkat` 调用的变化。

#### 1 start_kernel前

```bash
(gdb) b start_kernel 
Breakpoint 1 at 0xffffffff836620c0: file /<path>/init/main.c, line 941.
(gdb) c
Continuing.

Thread 1 hit Breakpoint 1, start_kernel () at /<path>/init/main.c:941
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	call   0xffffffff810a98c0 <__fentry__>
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
```

#### 2 start_kernel后

Linux系统启动后，通过`Ctrl-C`中断，查看如下：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	nopl   0x0(%rax,%rax,1)
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
```

`do_unlinkat` 函数的前5个字节替换为nop指令，对应`BYTES_NOP5`。

```C
// 5: nopl 0x00(%eax,%eax,1)
#define BYTES_NOP5	0x0f,0x1f,0x44,0x00,0x00
```

#### 3 附加BPF程序

在qemu系统中编译并运行BPF程序，如下：

```bash
$ cd build
$ cmake ../src
$ make kprobe
$ sudo ./kprobe 
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

附加BPF程序后查看`do_unlinkat`函数反汇编代码：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	call   0xffffffffc0262000
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
```

此时，将`BYTES_NOP5`替换为`call 0xffffffffc0262000` 指令。`0xffffffffc0262000` 即 `kprobe_ftrace_ops` 的trampoline地址。

在gdb中通过`x/i`查看对应的汇编代码，如下：

```C
(gdb) x/100i 0xffffffffc0262000
   0xffffffffc0262000:	pushf  
   0xffffffffc0262001:	push   %rbp
   0xffffffffc0262002:	push   0x18(%rsp)
   ...
   0xffffffffc0262052:	mov    0xe0(%rsp),%rsi
   0xffffffffc026205a:	mov    0xd8(%rsp),%rdi
   0xffffffffc0262062:	mov    %rdi,0x80(%rsp)
   0xffffffffc026206a:	sub    $0x5,%rdi
   0xffffffffc026206e:	nopl   0x0(%rax,%rax,1)
   0xffffffffc0262076:	xchg   %ax,%ax
   0xffffffffc0262078:	mov    0xfc(%rip),%rdx        # 0xffffffffc026217b
   0xffffffffc026207f:	mov    %r15,(%rsp)
   ...
   0xffffffffc02620df:	lea    0x1(%rsp),%rbp
   0xffffffffc02620e4:	lea    (%rsp),%rcx
   0xffffffffc02620e8:	nopl   0x0(%rax,%rax,1)
   0xffffffffc02620f0:	xchg   %ax,%ax
   0xffffffffc02620f2:	call   0xffffffff810b0440 <kprobe_ftrace_handler>
   ...
```

通过汇编代码，我们可以看到`trampoline`修改`%rdi`,`%rsi`,`%rdx`,`%rcx`寄存器值后(对应第1~4个参数)，调用 `kprobe_ftrace_handler` 函数。

#### 4 查看kretprobe执行过程

设置`do_unlinkat`函数入口位置断点，

```bash
// "do_unlinkat"函数入口地址
(gdb) b do_unlinkat 
Breakpoint 16 at 0xffffffff814935b0: file /<path>/fs/namei.c, line 4281.
// "do_unlinkat"函数第二条指令
(gdb) b *0xffffffff814935b5
Breakpoint 17 at 0xffffffff814935b5: file /<path>/fs/namei.c, line 4281.
(gdb) c
Continuing.

Thread 3 hit Breakpoint 16, do_unlinkat (dfd=dfd@entry=-100, name=0xffff88810b3cc000) at /<path>/fs/namei.c:4281
4281	{
// 触发"do_unlinkat"断点，查看rsp寄存器状态
(gdb) i r rsp
rsp            0xffffc90002593ea8  0xffffc90002593ea8
(gdb) x/2a $rsp
0xffffc90002593ea8:	0xffffffff814939e2 <__x64_sys_unlink+66>	0x0 <fixed_percpu_data>

(gdb) c
Continuing.

Thread 3 hit Breakpoint 17, 0xffffffff814935b5 in do_unlinkat (dfd=-100, name=0xffff88810b3cc000) at /<path>/fs/namei.c:4281
4281	{
// 触发"do_unlinkat"函数第二条指令断点，查看rsp寄存器状态
(gdb) i r rsp
rsp            0xffffc90002593ea8  0xffffc90002593ea8
(gdb) x/2a $rsp
0xffffc90002593ea8:	0xffffffff810aa3c0 <arch_rethook_trampoline>	0x0 <fixed_percpu_data>
```

可以看到，执行第一条指令`call   0xffffffffc0262000`前后，`%rsp`寄存器位置的值发送了变化，由 `0xffffffff814939e2 <__x64_sys_unlink+66>` 变成了 `0xffffffff810aa3c0 <arch_rethook_trampoline>`。 `do_unlinkat`函数执行完成后跳转到 `arch_rethook_trampoline` 位置继续执行，对应的反汇编代码如下：

```bash
(gdb) disassemble  arch_rethook_trampoline
Dump of assembler code for function arch_rethook_trampoline:
   0xffffffff810aa3c0 <+0>:	push   $0xffffffff810aa3c0
   0xffffffff810aa3c5 <+5>:	push   $0x18
   0xffffffff810aa3c7 <+7>:	push   %rsp
   ...
   0xffffffff810aa3e9 <+41>:	mov    %rsp,%rdi
   0xffffffff810aa3ec <+44>:	call   0xffffffff810aa4b0 <arch_rethook_trampoline_callback>
   ...
   0xffffffff810aa408 <+72>:	add    $0x18,%rsp
   0xffffffff810aa40c <+76>:	add    $0x10,%rsp
   0xffffffff810aa410 <+80>:	popf   
   0xffffffff810aa411 <+81>:	ret
   0xffffffff810aa412 <+82>:	int3 
   ...  
```

设置`arch_rethook_trampoline`断点为最后一条可执行的指令位置(`ret`指令)，查看寄存器状态，如下

```bash
(gdb) b *0xffffffff810aa411
Breakpoint 19 at 0xffffffff810aa411
(gdb) c
Continuing.

Thread 3 hit Breakpoint 19, 0xffffffff810aa411 in arch_rethook_trampoline ()
(gdb) i r rsp
rsp            0xffffc90002593ea8  0xffffc90002593ea8
(gdb) x/2a $rsp
0xffffc90002593ea8:	0xffffffff814939e2 <__x64_sys_unlink+66>	0x0 <fixed_percpu_data>
```

此时，`%rsp`寄存器和保存的值恢复到调用`do_unlinkat`之前的状态。

#### 5 清理BPF程序后

在qemu中退出`kprobe`程序后，查看`do_unlinkat` 的反汇编代码，重新设置为nop指令，如下：

```bash
(gdb) disassemble do_unlinkat 
Dump of assembler code for function do_unlinkat:
   0xffffffff814935b0 <+0>:	nopl   0x0(%rax,%rax,1)
   0xffffffff814935b5 <+5>:	push   %rbp
   0xffffffff814935b6 <+6>:	mov    %rsp,%rbp
   ...
```

## 5 ksyscall示例程序

libbpf实现了对系统调用函数的`kprobe`探测。

### 5.1 BPF程序

BPF程序的源码参见[ksyscall.bpf.c](../src/ksyscall.bpf.c)，主要内容如下：

```C
SEC("ksyscall/unlinkat")
int BPF_KSYSCALL(unlinkat_entry, int fd, const char *pathname, int flag)
{
	char comm[TASK_COMM_LEN];
	__u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
	
	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk( "PID %d (%s) unlinkat syscall called with fd[%d], pathname[%s] and flag[%d].",
		caller_pid, comm, fd, pathname, flag);
	return 0;
}

SEC("kretsyscall/unlinkat")
int BPF_KRETPROBE(unlinkat_return, int ret)
{
	char comm[TASK_COMM_LEN];
	__u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("PID %d (%s) unlinkat syscall return called  with ret[%d].", caller_pid, comm, ret);
	return 0;
}
```

该程序包括两个BPF程序 `unlinkat_entry` 和 `unlinkat_return` 。

#### `BPF_KSYSCALL`展开过程

`unlinkat_entry` 使用 `BPF_KSYSCALL` 宏，有三个参数 `fd`，`pathname` 和 `flag`。`BPF_KSYSCALL` 宏在 [bpf_tracing.h](../libbpf/src/bpf_tracing.h) 中定义的，如下：

```C
// file: libbpf/src/bpf_tracing.h
#define BPF_KSYSCALL(name, args...)					    \
name(struct pt_regs *ctx);						    \
extern _Bool LINUX_HAS_SYSCALL_WRAPPER __kconfig;			    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args);				    \
typeof(name(0)) name(struct pt_regs *ctx)				    \
{									    \
	struct pt_regs *regs = LINUX_HAS_SYSCALL_WRAPPER		    \
			       ? (struct pt_regs *)PT_REGS_PARM1(ctx)	    \
			       : ctx;					    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	if (LINUX_HAS_SYSCALL_WRAPPER)					    \
		return ____##name(___bpf_syswrap_args(args));		    \
	else								    \
		return ____##name(___bpf_syscall_args(args));		    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args)
```

`BPF_KSYSCALL`宏根据`LINUX_HAS_SYSCALL_WRAPPER`的设置，使用`___bpf_syswrap_args(args)` 或 `___bpf_syscall_args(args)` 获取系统调用的参数。这两种读取参数的顺序一致，`___bpf_syswrap_args(args)` 使用`BPF_CORE_READ`方式读取参数值。 以`___bpf_syscall_args(args)` 为例进行说明，其在同一个文件中定义，展开`args`的参数，如下：

```C
// file: libbpf/src/bpf_tracing.h
#define ___bpf_syscall_args0()           ctx
#define ___bpf_syscall_args1(x)          ___bpf_syscall_args0(), (void *)PT_REGS_PARM1_SYSCALL(regs)
#define ___bpf_syscall_args2(x, args...) ___bpf_syscall_args1(args), (void *)PT_REGS_PARM2_SYSCALL(regs)
#define ___bpf_syscall_args3(x, args...) ___bpf_syscall_args2(args), (void *)PT_REGS_PARM3_SYSCALL(regs)
#define ___bpf_syscall_args4(x, args...) ___bpf_syscall_args3(args), (void *)PT_REGS_PARM4_SYSCALL(regs)
#define ___bpf_syscall_args5(x, args...) ___bpf_syscall_args4(args), (void *)PT_REGS_PARM5_SYSCALL(regs)
#define ___bpf_syscall_args6(x, args...) ___bpf_syscall_args5(args), (void *)PT_REGS_PARM6_SYSCALL(regs)
#define ___bpf_syscall_args7(x, args...) ___bpf_syscall_args6(args), (void *)PT_REGS_PARM7_SYSCALL(regs)
#define ___bpf_syscall_args(args...)     ___bpf_apply(___bpf_syscall_args, ___bpf_narg(args))(args)
```

`PT_REGS_PARMn_SYSCALL(ctx)` 宏获取`ctx`的第n个参数。根据`x86_64`架构的调用约定，系统调用最多支持6个参数，`PT_REGS_PARM1_SYSCALL` ~ `PT_REGS_PARM6_SYSCALL` 为 `di`,`si`,`dx`,`r10`,`r8`,`r9` 寄存器。

`int BPF_KSYSCALL(unlinkat_entry, int fd, const char *pathname, int flag)` 宏展开后如下：

```C
int unlinkat_entry(struct pt_regs *ctx); 
extern _Bool LINUX_HAS_SYSCALL_WRAPPER __attribute__((section(".kconfig"))); 
static inline __attribute__((always_inline)) typeof(unlinkat_entry(0)) 
____unlinkat_entry(struct pt_regs *ctx,int fd, const char *pathname, int flag); 
typeof(unlinkat_entry(0)) unlinkat_entry(struct pt_regs *ctx) {
     struct pt_regs *regs = LINUX_HAS_SYSCALL_WRAPPER ? (struct pt_regs *)((ctx)->di) : ctx; 
     _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") 
    if (LINUX_HAS_SYSCALL_WRAPPER) 
        return ____unlinkat_entry(ctx, 
                (void *)({ typeof(((regs))->di) __r;  ({ 
                            bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), 
                                (const void *)__builtin_preserve_access_index(&((typeof((((regs))))((((regs)))))->di)); 
                            });  __r; }), 
                (void *)({ typeof(((regs))->si) __r; ({ 
                            bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), 
                                (const void *)__builtin_preserve_access_index(&((typeof((((regs)))))((((regs)))))->si)); 
                            }); __r; }), 
                (void *)({ typeof(((regs))->dx) __r; ({ 
                            bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), 
                                (const void *)__builtin_preserve_access_index(&((typeof((((regs)))))((((regs)))))->dx)); 
                            }); __r; })); 
     else 
        return ____unlinkat_entry(ctx, (void *)((regs)->di), (void *)((regs)->si), (void *)((regs)->dx)); 
     _Pragma("GCC diagnostic pop") 
}
static inline __attribute__((always_inline)) typeof(unlinkat_entry(0)) 
____unlinkat_entry(struct pt_regs *ctx,int fd, const char *pathname, int flag)
```

`LINUX_HAS_SYSCALL_WRAPPER` 表示Linux内核是否支持`SYSCALL_WRAPPER`，在加载阶段解析，如下：

```C
// file: bpftool/libbpf/src/libbpf.c
static int bpf_object__resolve_externs(struct bpf_object *obj, const char *extra_kconfig)
{
    ...
    else if (strcmp(ext->name, "LINUX_HAS_SYSCALL_WRAPPER") == 0) {
        value = kernel_supports(obj, FEAT_SYSCALL_WRAPPER);
    }
}
```

### 5.2 用户程序

用户程序的源码参见[ksyscall.c](../src/ksyscall.c)，主要功能如下：

#### 1 附加BPF过程

```C
int main(int argc, char **argv)
{
    struct ksyscall_bpf *skel;
    ...
    // 打开和加载BPF程序
    skel = ksyscall_bpf__open_and_load();
    ...
    // 附加BPF程序
    err = ksyscall_bpf__attach(skel);
    ...
    // 设置中断信号处理函数
    if (signal(SIGINT, sig_int) == SIG_ERR) { ... }
    ...
    while (!stop) {
        fprintf(stderr, ".");
        sleep(1);
    }
cleanup:
    // 卸载BPF程序
    ksyscall_bpf__destroy(skel);
    return -err;
}
```

#### 2 读取数据过程

`unlinkat_entry` 和 `unlinkat_return` 将采集的数据通过 `bpf_printk` 输出到 `/sys/kernel/debug/tracing/trace_pipe` 文件中。

### 5.3 编译运行程序

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make ksyscall 
$ sudo ./ksyscall  
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

在`kprobe`程序运行的过程中打开另一个bash窗口查看输出结果，如下：

```bash
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-811380  [005] d..31 211590.415053: bpf_trace_printk: PID 811380 (rm) unlinkat syscall called with fd[-100], pathname[a.txt] and flag[0].
           <...>-811380  [005] d..31 211590.415115: bpf_trace_printk: PID 811380 (rm) unlinkat syscall return called  with ret[0].
...
```

### 5.4 libbpf附加ksyscall的过程

`ksyscall.bpf.c` 文件中BPF程序的SEC名称分别为 `SEC("ksyscall/unlinkat")` 和 `SEC("kretsyscall/unlinkat")` 。在第一篇中，我们分析了libbpf在附加阶段通过`SEC`名称进行附加的，`ksyscall` 和 `kretsyscall` 对应的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
	SEC_DEF("ksyscall+",		KPROBE,	0, SEC_NONE, attach_ksyscall),
	SEC_DEF("kretsyscall+",		KPROBE, 0, SEC_NONE, attach_ksyscall),
    ...
};
```

`ksyscall` 和 `kretsyscall` 都是通过 `attach_ksyscall` 函数进行附加的。`attach_ksyscall` 的实现过程如下：

```C
// file: libbpf/src/libbpf.c
static int attach_ksyscall(const struct bpf_program *prog, long cookie, struct bpf_link **link)
{
    LIBBPF_OPTS(bpf_ksyscall_opts, opts);
    const char *syscall_name;
    *link = NULL;

    // 只有 SEC("ksyscall") and SEC("kretsyscall") 时不自动加载
    if (strcmp(prog->sec_name, "ksyscall") == 0 || strcmp(prog->sec_name, "kretsyscall") == 0)
        return 0;
    // 获取 `syscall_name` 名称
    opts.retprobe = str_has_pfx(prog->sec_name, "kretsyscall/");
    if (opts.retprobe)
        syscall_name = prog->sec_name + sizeof("kretsyscall/") - 1;
    else
        syscall_name = prog->sec_name + sizeof("ksyscall/") - 1;

    *link = bpf_program__attach_ksyscall(prog, syscall_name, &opts);
    return *link ? 0 : -errno;
}
```

`attach_ksyscall` 获取`SEC`中的系统调用名称，`bpf_program__attach_ksyscall` 获取系统调用的实际函数名称后，通过kprobe方式附加BPF程序。如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link *bpf_program__attach_ksyscall(const struct bpf_program *prog,
                    const char *syscall_name, const struct bpf_ksyscall_opts *opts)
{
    LIBBPF_OPTS(bpf_kprobe_opts, kprobe_opts);
    char func_name[128];

    if (!OPTS_VALID(opts, bpf_ksyscall_opts))
        return libbpf_err_ptr(-EINVAL);
    
    // 获取函数名称
    if (kernel_supports(prog->obj, FEAT_SYSCALL_WRAPPER)) {
        // 在通过`kernel_supports`检查后，获取系统调用的前缀
        snprintf(func_name, sizeof(func_name), "__%s_sys_%s", 
            arch_specific_syscall_pfx() ? : "", syscall_name);
    } else {
        snprintf(func_name, sizeof(func_name), "__se_sys_%s", syscall_name);
    }

    kprobe_opts.retprobe = OPTS_GET(opts, retprobe, false);
    kprobe_opts.bpf_cookie = OPTS_GET(opts, bpf_cookie, 0);
    // 附加kprobe
    return bpf_program__attach_kprobe_opts(prog, func_name, &kprobe_opts);
}
```

## 6 总结

本文通过`kprobe`示例程序分析了KRPOBE-PMU的内核实现过程。 `kprobe`/`kretprobe` 事件基于 `ftrace` 实现的，通过修改函数的入口指令，将入口指令修改调用`trampoline` 程序，从而实现调用BPF程序。

`kprobe`探针能够在任意位置插入探针，`kretprobe`只能在函数入口位置插入探针。本文只分析了最常用的 `kprobe`/`kretprobe` 探针在函数入口位置的情况。

除此之外，分析了kprobe实现的特殊情况--ksyscall。系统调用的参数和实际名称与内核中的其他函数有所区别，libbpf通过`ksyscall`段名称进行了通用化处理。

## 参考资料

* [ftrace - Function Tracer](https://www.kernel.org/doc/html/latest/trace/ftrace.html)
* [Function Tracer Design](https://www.kernel.org/doc/html/latest/trace/ftrace-design.html)
* [Kernel Probes (Kprobes)](https://www.kernel.org/doc/html/latest/trace/kprobes.html)
* [Kprobe-based Event Tracing](https://www.kernel.org/doc/html/latest/trace/kprobetrace.html)
* [Linux内核ftrace原理](https://www.jianshu.com/p/56a96de4e879)
* [在macOS下搭建Linux内核调试环境](https://github.com/mannkafai/mkf.github.io/blob/main/debug%20linux%20kernel%20on%20macos.md)