# UPROBE的内核实现

## 0 前言

在上一章节我们分析了kprobes的内核实现，kprobes可以对内核函数设置探针。今天我们基于`uprobe`和`usdt`程序分析uprobes的实现过程。

## 1 简介

uprobes和kprobes类似，提供了用户态程序的动态插桩。uprobes可以在用户态程序的的函数入口、特定偏移处以及函数返回处位置进行插桩。

用户预定义静态追踪(user-level statically defined tracing，USDT)提供了一个用户空间版的追踪点机制，USDT基于uprobes实现的。

## 2 uprobe示例程序

### 2.1 BPF程序

BPF程序的源码参见[uprobe.bpf.c](../src/uprobe.bpf.c)，主要内容如下：

```C
SEC("uprobe")
int BPF_KPROBE(uprobe_add, int a, int b)
{
    bpf_printk("uprobed_add ENTRY: a = %d, b = %d", a, b);
    return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_add, int ret)
{
    bpf_printk("uprobed_add EXIT: return = %d", ret);
    return 0;
}

SEC("uprobe//proc/self/exe:uprobed_sub")
int BPF_KPROBE(uprobe_sub, int a, int b)
{
    bpf_printk("uprobed_sub ENTRY: a = %d, b = %d", a, b);
    return 0;
}

SEC("uretprobe//proc/self/exe:uprobed_sub")
int BPF_KRETPROBE(uretprobe_sub, int ret)
{
    bpf_printk("uprobed_sub EXIT: return = %d", ret);
    return 0;
}
```

该程序包括4个BPF程序，`uprobe_add`, `uretprobe_add`, `uprobe_sub` 和 `uretprobe_sub` 。 `BPF_KPROBE` 和 `BPF_KRETPROBE` 展开过程参见前一篇 "KPROBE的内核实现" 章节。

### 2.2 用户程序

用户程序的源码参见[uprobe.c](../src/uprobe.c)，主要功能如下：

#### 1 附加BPF程序

```C
int main(int argc, char **argv)
{
    struct uprobe_bpf *skel;
    long uprobe_offset;
    ...
    // 打开和加载BPF程序
    skel = uprobe_bpf__open_and_load();
    // 获取`uprobed_add`函数的偏移地址
    uprobe_offset = get_uprobe_offset(&uprobed_add);

    // 手动方式附加`uprobe_add`BPF程序
    skel->links.uprobe_add =
        bpf_program__attach_uprobe(skel->progs.uprobe_add, false /* not uretprobe */,
                        0 /* self pid */, "/proc/self/exe", uprobe_offset);
    if (!skel->links.uprobe_add) { ... }

    // 手动方式附加`uretprobe_add`BPF程序
    skel->links.uretprobe_add =
        bpf_program__attach_uprobe(skel->progs.uretprobe_add, true /* uretprobe */,
                        -1 /* any pid */, "/proc/self/exe", uprobe_offset);
    if (!skel->links.uretprobe_add) { ... }
    
    // 自动方式附加 `uprobe_sub/uretprobe_sub` BPF程序
    err = uprobe_bpf__attach(skel);
    if(err) { ... }

    for (i = 0;; i++) {
        // 触发BPF程序
        fprintf(stderr, ".");
        uprobed_add(i, i + 1);
        uprobed_sub(i * i, i);
        sleep(1);
    }

cleanup:
    // 卸载BPF程序
    uprobe_bpf__destroy(skel);
    return -err;
}
```

#### 2 读取数据过程

`uprobe_add`, `uretprobe_add`, `uprobe_sub` 和 `uretprobe_sub` 这4个BPF程序将采集的数据通过 `bpf_printk` 输出到 `/sys/kernel/debug/tracing/trace_pipe` 文件中。

### 2.3 编译运行程序

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make uprobe
$ sudo ./uprobe 
libbpf: loading object 'uprobe_bpf' from buffer
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

在`uprobe`程序运行的过程中打开另一个bash窗口查看输出结果，如下：

```bash
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
          uprobe-189688  [000] d..31 108524.598182: bpf_trace_printk: uprobed_add ENTRY: a = 0, b = 1
          uprobe-189688  [000] d..31 108524.598212: bpf_trace_printk: uprobed_add EXIT: return = 1
          uprobe-189688  [000] d..31 108524.598218: bpf_trace_printk: uprobed_sub ENTRY: a = 0, b = 0
          uprobe-189688  [000] d..31 108524.598224: bpf_trace_printk: uprobed_sub EXIT: return = 0
...
```

## 3 uprobes附加BPF的方式

### 3.1 libbpf附加uprobes的过程

`uprobe.bpf.c` 文件中BPF程序的SEC名称分别为 `SEC("uprobe")` , `SEC("uretprobe")`, `SEC("uprobe//proc/self/exe:uprobed_sub")` 和 `SEC("uretprobe//proc/self/exe:uprobed_sub")` 。`uprobe` 和 `uretprobe` 在libbpf中对应的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("uprobe+",		KPROBE,	0, SEC_NONE, attach_uprobe),
    SEC_DEF("uprobe.s+",		KPROBE,	0, SEC_SLEEPABLE, attach_uprobe),
    SEC_DEF("uretprobe+",		KPROBE, 0, SEC_NONE, attach_uprobe),
    SEC_DEF("uretprobe.s+",		KPROBE, 0, SEC_SLEEPABLE, attach_uprobe),
    ...
};
```

#### (1) 自动附加

`attach_uprobe` 函数实现`uprobe/uretprobe` 类型的BPF程序的附加，支持解析的格式如下：

```text
u[ret]probe/binary:function[+offset]
```

实现如下：

```C
// file: libbpf/src/libbpf.c
static int attach_uprobe(const struct bpf_program *prog, long cookie, struct bpf_link **link)
{
    DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts);
    char *probe_type = NULL, *binary_path = NULL, *func_name = NULL;
    int n, ret = -EINVAL;
    long offset = 0;
    ...

    *link = NULL;
    // 解析`probe_type`,`binary_path`,`func_name,`offset`参数
    n = sscanf(prog->sec_name, "%m[^/]/%m[^:]:%m[a-zA-Z0-9_.]+%li",
            &probe_type, &binary_path, &func_name, &offset);
    switch (n) {
    case 1:
        // 处理 SEC("u[ret]probe")，格式正确，但不支持自动附加BPF程序
        ret = 0;
        break;
    case 2:
        // 缺少 ':function[+offset]' 格式，
        pr_warn("prog '%s': section '%s' missing ':function[+offset]' specification\n", prog->name, prog->sec_name);
        break;
    case 3:
    case 4:
        // 格式正确，自动附加BPF程序
        opts.retprobe = strcmp(probe_type, "uretprobe") == 0 ||
                strcmp(probe_type, "uretprobe.s") == 0;
        // uretprobe 格式只支持在函数入口点附加探针
        if (opts.retprobe && offset != 0) {
            pr_warn("prog '%s': uretprobes do not support offset specification\n", prog->name);
            break;
        }
        opts.func_name = func_name;
        *link = bpf_program__attach_uprobe_opts(prog, -1, binary_path, offset, &opts);
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

`bpf_program__attach_uprobe_opts` 函数附加BPF程序到uprobe，实现如下：

```C
LIBBPF_API struct bpf_link *
bpf_program__attach_uprobe_opts(const struct bpf_program *prog, pid_t pid,
                const char *binary_path, size_t func_offset,
                const struct bpf_uprobe_opts *opts)
{
    DECLARE_LIBBPF_OPTS(bpf_perf_event_opts, pe_opts);
    ...
    // 默认附加设置
    attach_mode = OPTS_GET(opts, attach_mode, PROBE_ATTACH_MODE_DEFAULT);
    retprobe = OPTS_GET(opts, retprobe, false);
    ref_ctr_off = OPTS_GET(opts, ref_ctr_offset, 0);
    pe_opts.bpf_cookie = OPTS_GET(opts, bpf_cookie, 0);

    archive_sep = strstr(binary_path, "!/");
    if (archive_sep) {
        // 路径中存在`!/`时，解析归档文件路径(`archive`)和二进制文件路径(`binary`)
        full_path[0] = '\0';
        libbpf_strlcpy(full_path, binary_path,
                    min(sizeof(full_path), (size_t)(archive_sep - binary_path + 1)));
        archive_path = full_path;
        binary_path = archive_sep + 2;
    } else if (!strchr(binary_path, '/')) {
        // 路径中不存在`/`时，解析全路径
        err = resolve_full_path(binary_path, full_path, sizeof(full_path));
        if (err) { ... }
        binary_path = full_path;
    }

    func_name = OPTS_GET(opts, func_name, NULL);
    // 函数名称存在时，解析函数名称的偏移地址
    if (func_name) {
        long sym_off;
        if (archive_path) {
            // 解析归档文件中的偏移地址，解压缩`archive`后，获取`binary`文件内容后（elf格式），获取符号的偏移量
            sym_off = elf_find_func_offset_from_archive(archive_path, binary_path, func_name);
            binary_path = archive_path;
        } else {
            // 解析二进制文件中的偏移地址，打开二进制格式文件(elf格式)，获取符号的偏移量
            sym_off = elf_find_func_offset_from_file(binary_path, func_name);
        }
        if (sym_off < 0) return libbpf_err_ptr(sym_off);
        func_offset += sym_off;
    }

    // 检查是否使用传统附加方式
    legacy = determine_uprobe_perf_type() < 0;
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
        // 现代方式打开uprobe
        pfd = perf_event_open_probe(true /* uprobe */, retprobe, binary_path, func_offset, pid, ref_ctr_off);
    } else {
        char probe_name[PATH_MAX + 64];
        if (ref_ctr_off) return libbpf_err_ptr(-EINVAL);
        // 获取uprobe事件名称
        gen_uprobe_legacy_event_name(probe_name, sizeof(probe_name), binary_path, func_offset);
        legacy_probe = strdup(probe_name);
        if (!legacy_probe) return libbpf_err_ptr(-ENOMEM);
        // 传统方式打开uprobe
        pfd = perf_event_uprobe_open_legacy(legacy_probe, retprobe, binary_path, func_offset, pid);
    }
    ...
    // 附加perf_event
    link = bpf_program__attach_perf_event_opts(prog, pfd, &pe_opts);
    ...
    if (legacy) {
	    struct bpf_link_perf *perf_link = container_of(link, struct bpf_link_perf, link);
	    perf_link->legacy_probe_name = legacy_probe;
	    perf_link->legacy_is_kprobe = false;
	    perf_link->legacy_is_retprobe = retprobe;
	}
	return link;
    ...
}
```

`resolve_full_path` 获取文件全路径时，根据文件的后缀名称设置不同的查找路径。如下：

```C
// file: libbpf/src/libbpf.c
static int resolve_full_path(const char *file, char *result, size_t result_sz)
{
    const char *search_paths[3] = {};
    if (str_has_sfx(file, ".so") || strstr(file, ".so.")) {
        // .so 动态链接库的查找路径
        search_paths[0] = getenv("LD_LIBRARY_PATH");
        search_paths[1] = "/usr/lib64:/usr/lib";
        search_paths[2] = arch_specific_lib_paths();
        perm = R_OK;
    } else {
        // 二进制文件的查找路径
        search_paths[0] = getenv("PATH");
        search_paths[1] = "/usr/bin:/usr/sbin";
        perm = R_OK | X_OK;
    }
    ...
}
```

同kprobe类似，uprobe有两种方式加载BPF程序：传统方式和现代方式。这两种方式打开perf_event（打开事件的方式不同）后，附加到perf_event事件。通过 `determine_uprobe_perf_type` 函数判断是否使用传统附加方式，实现如下：

```C
// file: libbpf/src/libbpf.c
static int determine_uprobe_perf_type(void)
{
    const char *file = "/sys/bus/event_source/devices/uprobe/type";
    return parse_uint_from_file(file, "%d\n");
}
```

在第二篇PMU初始化过程中，系统注册的PMU在 `/sys/bus/event_source/` 目录下。 `/sys/bus/event_source/devices/uprobe/type` 表示名称为`uprobe`的PMU，注册如下：

```C
// file: kernel/events/core.c
void __init perf_event_init(void)
    --> perf_tp_register()
        --> perf_pmu_register(&perf_uprobe, "uprobe", -1);
```

即，`determine_uprobe_perf_type` 函数判断 UPROBE-PMU 是否注册。

#### (2) 手动附加

`attach_uprobe`检测`SEC()`名称，在只有`SEC(uprobe)`或`SEC("uretprobe")`时，需要用户以手动方式附加。`bpf_program__attach_uprobe` 实现该功能，实现如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link *bpf_program__attach_uprobe(const struct bpf_program *prog,
                    bool retprobe, pid_t pid, const char *binary_path, size_t func_offset)
{
    DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts, .retprobe = retprobe);
    return bpf_program__attach_uprobe_opts(prog, pid, binary_path, func_offset, &opts);
}
```

### 3.2 现代方式--UPROBE-PMU

在 UPROBE-PMU注册后，使用现代方式，调用 `perf_event_open_probe` 函数，实现如下：

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

没有注册`UPROBE-PMU`时或强制使用传统方式时，实现如下:

```C
// file: libbpf/src/libbpf.c
char probe_name[PATH_MAX + 64];
// 获取uprobe事件名称
gen_uprobe_legacy_event_name(probe_name, sizeof(probe_name), binary_path, func_offset);
// 传统方式打开uprobe
pfd = perf_event_uprobe_open_legacy(legacy_probe, retprobe, binary_path, func_offset, pid);
```

`perf_event_uprobe_open_legacy` 函数实现具体的工作，实现如下：

```C
// file: libbpf/src/libbpf.c
static int perf_event_uprobe_open_legacy(const char *probe_name, bool retprobe,
                    const char *binary_path, size_t offset, int pid)
{
    const size_t attr_sz = sizeof(struct perf_event_attr);
    struct perf_event_attr attr;
    ...
    // 传统方式添加uprobe
    err = add_uprobe_event_legacy(probe_name, retprobe, binary_path, offset);
    if (err < 0) { ... }
    // 获取uprobe_perf类型
    type = determine_uprobe_perf_type_legacy(probe_name, retprobe);
    if (type < 0) { ... }

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
    ...
}
```

`add_uprobe_event_legacy` 函数添加uprobe事件，实现如下：

```C
// file: libbpf/src/libbpf.c
static inline int add_uprobe_event_legacy(const char *probe_name, bool retprobe,
                        const char *binary_path, size_t offset)
{
    return append_to_file(tracefs_uprobe_events(), "%c:%s/%s %s:0x%zx",
                retprobe ? 'r' : 'p',
                retprobe ? "uretprobes" : "uprobes",
                probe_name, binary_path, offset);
}
```

按照uprobe事件格式添加到 `uprobe_events` 文件中（通过 `tracefs_uprobe_events()` 函数获取）。`uprobe_events` 文件路径为 `/sys/kernel/debug/tracing/uprobe_events` 或 `/sys/kernel/debug/uprobe_events`。

在添加uprobe事件后，`determine_uprobe_perf_type_legacy` 函数获取添加uprobe的类型。实现如下：

```C
// file: libbpf/src/libbpf.c
static int determine_uprobe_perf_type_legacy(const char *probe_name, bool retprobe)
{
    char file[256];
    snprintf(file, sizeof(file), "%s/events/%s/%s/id",
        tracefs_path(), retprobe ? "uretprobes" : "uprobes", probe_name);
    return parse_uint_from_file(file, "%d\n");
}
```

和kprobe一样，传统方式添加uprobe的事件注册到 `/sys/kernel/debug/tracing/events/u[ret]probes/<probe_name>/` 目录下。

## 4 内核实现

### 4.1 uprobes初始化过程

`uprobes`的初始化过程分为两个步骤，在`start_kernel`函数中初始化和通过`initcall`机制初始化。

#### 1 `start_kernel` 阶段-- `uprobes`初始化

在 `start_kernel` 阶段进行 `uprobes` 初始化，如下：

```C
// file: init/main.c
start_kernel(void)
    --> fork_init()
        --> uprobes_init()
```

`uprobes_init` 函数实现如下：

```C
// file: kernel/events/uprobes.c
void __init uprobes_init(void)
{
    int i;
    for (i = 0; i < UPROBES_HASH_SZ; i++)
        mutex_init(&uprobes_mmap_mutex[i]);

    BUG_ON(register_die_notifier(&uprobe_exception_nb));
}
```

`uprobes_init` 函数初始化 `uprobes_mmap_mutex`, 注册 `die_notifier` 通知链。相关定义如下：

```C
// file: kernel/events/uprobes.c
#define UPROBES_HASH_SZ	13
static struct mutex uprobes_mmap_mutex[UPROBES_HASH_SZ];
```

#### 2 `initcall` 阶段-- `uprobe_trace`初始化

这个阶段进行`uprobe_trace`初始化，主要有：

* `fs_initcall(init_uprobe_trace)`

`init_uprobe_trace` 创建 `uprobe_trace` 需要的 `uprobe_events` 和 `uprobe_profile` 文件。实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static __init int init_uprobe_trace(void)
{
    int ret;
    // 注册 uprobe_ops 动态事件
    ret = dyn_event_register(&trace_uprobe_ops);
    if (ret) return ret;
    // `tracing` 目录
    ret = tracing_init_dentry();
    if (ret) return 0;
    // uprobe_events 文件
    trace_create_file("uprobe_events", TRACE_MODE_WRITE, NULL, NULL, &uprobe_events_ops);
    // uprobe_profile 文件
    trace_create_file("uprobe_profile", TRACE_MODE_READ, NULL, NULL, &uprobe_profile_ops);
    return 0;
}
fs_initcall(init_uprobe_trace);
```

### 4.2 UPROBE-PMU的内核实现

通过perf_event打开`uprobe`操作的pmu为`perf_uprobe`，注册过程如下：

```C
// file: kernel/events/core.c
static inline void perf_tp_register(void)
{
    ...
#ifdef CONFIG_UPROBE_EVENTS
    perf_pmu_register(&perf_uprobe, "uprobe", -1);
#endif
}
```

`perf_uprobe` 的定义如下：

```C
// file: kernel/events/core.c
static struct pmu perf_uprobe = {
	.task_ctx_nr	= perf_sw_context,
	.event_init	= perf_uprobe_event_init,
	.add		= perf_trace_add,
	.del		= perf_trace_del,
	.start		= perf_swevent_start,
	.stop		= perf_swevent_stop,
	.read		= perf_swevent_read,
	.attr_groups	= uprobe_attr_groups,
};
```

`perf_uprobe`提供了初始化、开启/停止、添加/删除、读取等基本的操作接口。

#### 1 初始化 -- `perf_uprobe_event_init`

perf_uprobe的初始化接口设置为 `.event_init = perf_uprobe_event_init`，实现过程如下：

##### (1) perf_uprobe初始化接口

```C
// file：kernel/events/core.c
static int perf_uprobe_event_init(struct perf_event *event)
{
    ...
    // 检查类型是否匹配
    if (event->attr.type != perf_uprobe.type) return -ENOENT;
    //  检查权限，
    if (!perfmon_capable()) return -EACCES;
    // 不支持分支采样
    if (has_branch_stack(event)) return -EOPNOTSUPP;
    // 是否为retprobe
    is_retprobe = event->attr.config & PERF_PROBE_CONFIG_IS_RETPROBE;
    ref_ctr_offset = event->attr.config >> PERF_UPROBE_REF_CTR_OFFSET_SHIFT;
    // uprobe初始化
    err = perf_uprobe_init(event, ref_ctr_offset, is_retprobe);
    if (err) return err;
    // 设置销毁函数
    event->destroy = perf_uprobe_destroy;
    return 0;
}
```

`perf_uprobe_init`函数创建uprobe类型的perf_event追踪事件后，初始化perf_event。实现如下：

```C
// file: kernel/trace/trace_event_perf.c
int perf_uprobe_init(struct perf_event *p_event, unsigned long ref_ctr_offset, bool is_retprobe)
{
    struct trace_event_call *tp_event;
    ...
    // uprobe必须设置`uprobe_path`属性
    if (!p_event->attr.uprobe_path) return -EINVAL;
    // 复制 uprobe_path 到内核
    path = strndup_user(u64_to_user_ptr(p_event->attr.uprobe_path), PATH_MAX);

    // 创建uprobe的追踪事件
    tp_event = create_local_trace_uprobe(path, p_event->attr.probe_offset,
                        ref_ctr_offset, is_retprobe);
    ...
    mutex_lock(&event_mutex);
    // perf_trace事件初始化
    ret = perf_trace_event_init(tp_event, p_event);
    mutex_unlock(&event_mutex);
    ...
}
```

##### (2) 创建uprobe追踪事件

`create_local_trace_uprobe` 函数创建uprobe追踪事件，创建`perf_event` 需要的 `trace_event_call` 。实现如下：

```C
// file: kernel/trace/trace_uprobe.c
struct trace_event_call *
create_local_trace_uprobe(char *name, unsigned long offs,
                unsigned long ref_ctr_offset, bool is_return)
{
    enum probe_print_type ptype;
    struct trace_uprobe *tu;
    struct path path;
    ...
    // 获取`PATH`的路径
    ret = kern_path(name, LOOKUP_FOLLOW, &path);
    if (ret) return ERR_PTR(ret);
    // 创建`trace_uprobe`
    tu = alloc_trace_uprobe(UPROBE_EVENT_SYSTEM, "DUMMY_EVENT", 0, is_return);
    if (IS_ERR(tu)) { ... }

    tu->offset = offs;
    tu->path = path;
    tu->ref_ctr_offset = ref_ctr_offset;
    tu->filename = kstrdup(name, GFP_KERNEL);

    // 初始化event_call
    init_trace_event_call(tu);

    // 获取uprobe事件打印类型，并设置print_fmt
    ptype = is_ret_probe(tu) ? PROBE_PRINT_RETURN : PROBE_PRINT_NORMAL;
    if (traceprobe_set_print_fmt(&tu->tp, ptype) < 0) { ...	}

    // 返回event_call
    return trace_probe_event_call(&tu->tp);
}
```

`alloc_trace_uprobe` 函数创建`trace_uprobe`结构，设置uprobe和uretprobe处理函数。如下：

```C
// file: kernel/trace/trace_uprobe.c
static struct trace_uprobe *
alloc_trace_uprobe(const char *group, const char *event, int nargs, bool is_ret)
{
    struct trace_uprobe *tu;
    int ret;
    
    // 分配`trace_uprobe`
    tu = kzalloc(struct_size(tu, tp.args, nargs), GFP_KERNEL);
    if (!tu) return ERR_PTR(-ENOMEM);

    // 分配trace_probe_event
    ret = trace_probe_init(&tu->tp, event, group, true);
    if (ret < 0) goto error;

     // 动态事件初始化
    dyn_event_init(&tu->devent, &trace_uprobe_ops);
    // 设置uprobe和uretprobe处理函数
    tu->consumer.handler = uprobe_dispatcher;
    if (is_ret)
        tu->consumer.ret_handler = uretprobe_dispatcher;
    init_trace_uprobe_filter(tu->tp.event->filter);
    return tu;
    ...
}
```

`init_trace_event_call` 函数设置`trace_uprobe`结构中的`trace_event` 和 `trace_event->class` 的属性，这里设置了 `class->reg` 操作接口。如下：

```C
// file: kernel/trace/trace_uprobe.c
static inline void init_trace_event_call(struct trace_uprobe *tu)
{
    struct trace_event_call *call = trace_probe_event_call(&tu->tp);
    // 设置event函数
    call->event.funcs = &uprobe_funcs;
    call->class->fields_array = uprobe_fields_array;

    // 设置UPROBE标志和注册函数
    call->flags = TRACE_EVENT_FL_UPROBE | TRACE_EVENT_FL_CAP_ANY;
    call->class->reg = trace_uprobe_register;
}
```

##### (3) perf_trace事件初始化

在创建uprobe追踪事件后，调用 `perf_trace_event_init(tp_event, p_event);` 函数进行初始化。初始化的实现过程参见`第三篇`相关内容。初始化过程实现 `TRACE_REG_PERF_REGISTER` 和 `TRACE_REG_PERF_OPEN` 指令。

uprobe的注册函数设置为 `trace_uprobe_register`，如下：

```C
// file: kernel/trace/trace_uprobe.c
static inline void init_trace_event_call(struct trace_uprobe *tu)
{
    ...
    call->class->reg = trace_uprobe_register;
}
```

实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int
trace_uprobe_register(struct trace_event_call *event, enum trace_reg type, void *data)
{
    struct trace_event_file *file = data;
    switch (type) {
    case TRACE_REG_REGISTER:
        return probe_event_enable(event, file, NULL);
    case TRACE_REG_UNREGISTER:
        probe_event_disable(event, file);
        return 0;
#ifdef CONFIG_PERF_EVENTS
    case TRACE_REG_PERF_REGISTER:
        return probe_event_enable(event, NULL, uprobe_perf_filter);
    case TRACE_REG_PERF_UNREGISTER:
        probe_event_disable(event, NULL);
        return 0;
    case TRACE_REG_PERF_OPEN:
        return uprobe_perf_open(event, data);
    case TRACE_REG_PERF_CLOSE:
        return uprobe_perf_close(event, data);
#endif
    default:
        return 0;
    }
}
```

可以看到，uprobe事件关注 `REGISTER`, `UNREGISTER`, `OPEN` 和 `CLOSE` 操作。


#### 2 添加 -- `perf_trace_add`

perf_uprobe的添加接口设置为 `.add = perf_trace_add`，实现过程如下：

```C
// file: kernel/trace/trace_event_perf.c
int perf_trace_add(struct perf_event *p_event, int flags)
    --> tp_event->class->reg(tp_event, TRACE_REG_PERF_ADD, p_event)
```

#### 3 删除 -- `perf_trace_del`

perf_uprobe的添加接口设置为 `.del = perf_trace_del`，实现过程如下：

```C
// file: kernel/trace/trace_event_perf.c
void perf_trace_del(struct perf_event *p_event, int flags)
    --> tp_event->class->reg(tp_event, TRACE_REG_PERF_DEL, p_event)
```

#### 4 开始 -- `perf_swevent_start`

perf_uprobe的开始接口设置为 `.start = perf_swevent_start`，实现过程如下：

```C
//file: kernel/events/core.c
static void perf_swevent_start(struct perf_event *event, int flags)
    --> event->hw.state = 0;
```

设置 `event->hw` 的状态为0。

#### 5 停止 -- `perf_swevent_stop`

perf_uprobe的停止接口设置为 `.stop = perf_swevent_stop`，实现过程如下：

```C
//file: kernel/events/core.c
static void perf_swevent_stop(struct perf_event *event, int flags)
    --> event->hw.state = PERF_HES_STOPPED;
```

设置 `event->hw` 的状态为停止状态。

#### 6 销毁 -- `perf_uprobe_destroy`

`perf_uprobe_destroy` 进行清理工作和释放资源，实现如下：

```C
//file: kernel/trace/trace_event_perf.c
void perf_uprobe_destroy(struct perf_event *p_event)
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
        // 销毁`trace_uprobe`
    --> destroy_local_trace_uprobe(p_event->tp_event);
            // 释放`trace_uprobe`
        --> free_trace_uprobe(tu);
```

通过 `tp_event->class->reg` 进行关闭和注销，在必要时释放分配的缓冲区。最后销毁创建的`trace_uprobe`。

### 4.3 TRACEPOINT-PMU的内核实现

传统方式通过写入 `/sys/kernel/debug/tracing/uprobe_events` 或 `/sys/kernel/debug/uprobe_events` 文件的方式创建 `uprobes` 事件。

#### 1 `uprobe_events`文件操作接口

`uprobe_events` 文件的定义如下：

```C
// file: kernel/trace/trace_uprobe.c
static __init int init_uprobe_trace(void)
{
    ...
    trace_create_file("uprobe_events", TRACE_MODE_WRITE, NULL, NULL, &uprobe_events_ops);
    ...
}

// file: kernel/trace/trace_uprobe.c
static const struct file_operations uprobe_events_ops = {
	.owner		= THIS_MODULE,
	.open		= probes_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
	.write		= probes_write,
};
```

`uprobe_events` 文件的操作接口为 `uprobe_events_ops` 。 我们只关注写操作，即 `probes_write` 函数，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static ssize_t probes_write(struct file *file, const char __user *buffer,
                size_t count, loff_t *ppos)
{
    return trace_parse_run_command(file, buffer, count, ppos, 
                    create_or_delete_trace_uprobe);
}
```

`trace_parse_run_command` 函数按行解析文件内容后，逐行调用`createfn`。  `create_or_delete_trace_uprobe` 函数处理输入的行内容，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int create_or_delete_trace_uprobe(const char *raw_command)
{
    int ret;
    // 以`-`开始，释放`dyn_event`
    if (raw_command[0] == '-')
        return dyn_event_release(raw_command, &trace_uprobe_ops);
    // 创建 `trace_uprobe`
    ret = trace_uprobe_create(raw_command);
    return ret == -ECANCELED ? -EINVAL : ret;
}
```

#### 2 创建`trace_uprobe`

当每行内容（`raw_command`）不是以 `-` 开始时，调用 `trace_uprobe_create` 创建 `trace_uprobe`。实现如下：

```C
// file: kernel/trace/trace_uprobe.c
int trace_uprobe_create(const char *raw_command)
{
    return trace_probe_create(raw_command, __trace_uprobe_create);
}

// file: kernel/trace/trace_probe.c
int trace_probe_create(const char *raw_command, int (*createfn)(int, const char **))
{
    ..
    argv = argv_split(GFP_KERNEL, raw_command, &argc);
    if (!argv) return -ENOMEM;
    // 调用回调函数
    if (argc) ret = createfn(argc, (const char **)argv);

    argv_free(argv);
    return ret;
}
```

`__trace_uprobe_create` 函数实现具体的创建工作，支持的解析格式如下：

```text
p|r[:[GRP/][EVENT]] PATH:OFFSET[%return][(REF)] [FETCHARGS]
```

实现如下：

```C
static int __trace_uprobe_create(int argc, const char **argv)
{
    ...
    // 默认group名称(`uprobes`)
    group = UPROBE_EVENT_SYSTEM;
    ...
    // 解析第一个参数的第一个字节，判断是 uprobe 还是 uretprobe
    switch (argv[0][0]) {
    case 'r': is_return = true;	break;
    case 'p': break;
    default: return -ECANCELED;
    }
    // 获取event参数
    if (argv[0][1] == ':') event = &argv[0][2];
    // 复制第一个参数
    filename = kstrdup(argv[1], GFP_KERNEL);
    // 获取`PATH`参数
    arg = strrchr(filename, ':');
    ...
    // 获取`PATH`的路径
    *arg++ = '\0';
    ret = kern_path(filename, LOOKUP_FOLLOW, &path);
    if (ret) { ... }
    // 确保`PATH`对应的文件是regular文件
    if (!d_is_reg(path.dentry)) { ... }
    ...
    // 解析`REF`引用计数偏移量(reference counter offset)
    rctr = strchr(arg, '(');
    if (rctr) { ... }
    // 解析`%return`参数
    tmp = strchr(arg, '%');
    if (tmp) { ... }
    // 解析`OFFSET`参数
    ret = kstrtoul(arg, 0, &offset);
    // 解析`GRP`/`EVENT`参数
    if (event) {
        ret = traceprobe_parse_event_name(&event, &group, gbuf, event - argv[0]);
        ...
    }
    // 设置默认event名称
    if (!event) { ... }

    argc -= 2;
    argv += 2;

    // 创建`trace_uprobe`
    tu = alloc_trace_uprobe(group, event, argc, is_return);
    if (IS_ERR(tu)) { ... }
    // `trace_uprobe`属性设置
    tu->offset = offset;
    tu->ref_ctr_offset = ref_ctr_offset;
    tu->path = path;
    tu->filename = filename;

    // 解析参数
    for (i = 0; i < argc && i < MAX_TRACE_ARGS; i++) {
        ret = traceprobe_parse_probe_arg(&tu->tp, i, argv[i],
                    (is_return ? TPARG_FL_RETURN : 0) | TPARG_FL_USER);
    }

    // 获取uprobe事件打印类型，并设置print_fmt
    ptype = is_ret_probe(tu) ? PROBE_PRINT_RETURN : PROBE_PRINT_NORMAL;
    ret = traceprobe_set_print_fmt(&tu->tp, ptype);
    if (ret < 0) goto error;

    // 注册`trace_uprobe`
    ret = register_trace_uprobe(tu);
    if (!ret) goto out;
    ...
}
```

`register_trace_uprobe` 实现`trace_uprobe` 的注册，实现过程如下：

```C
// file: kernel/trace/trace_uprobe.c
static int register_trace_uprobe(struct trace_uprobe *tu)
        // 验证`ref_ctr_offset`，uprobe不支持多个reference counter
    --> ret = validate_ref_ctr_offset(tu);
        // 查找是否存在相同的组和名称的 `trace_uprobe`
    --> old_tu = find_probe_event(trace_probe_name(&tu->tp), trace_probe_group_name(&tu->tp));
    --> if (old_tu) 
            // 类型的相同的情况下添加到 old_tu 中后，退出
        --> append_trace_uprobe(tu, old_tu);
                // 添加到 `old_tu` 的列表中
            --> trace_probe_append(&tu->tp, &to->tp);
                    // 释放 tu
                --> list_del_init(&tp->list);
                --> trace_probe_event_free(tp->event);
                --> tp->event = to->event;
                    // 添加到 to 列表中
                --> list_add_tail(&tp->list, trace_probe_probe_list(to));
                // 添加到动态事件列表中（`dyn_event_list`）
            --> dyn_event_add(&tu->devent, trace_probe_event_call(&tu->tp));
                --> call->flags |= TRACE_EVENT_FL_DYNAMIC;
                --> list_add_tail(&ev->list, &dyn_event_list);
        // 注册uprobe_event
    --> ret = register_uprobe_event(tu);
        --> init_trace_event_call(tu);
            --> call->class->reg = trace_uprobe_register;
        --> trace_probe_register_event_call(&tu->tp);
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
        // 添加`dyn_event`到动态事件列表中（`dyn_event_list`）
    --> dyn_event_add(&tu->devent, trace_probe_event_call(&tu->tp));
```

在注册过程中，`trace_probe_register_event_call` 函数将 `trace_uprobe` 注册到 `tracefs` 文件系统中，这样我们通过 `Tracepoint` 实现 uprobe事件的分析。具体实现过程参见 [Tracepoint的内核实现](doc/03-tracepoint%20inside.md)。


#### 3 销毁`trace_uprobe`

当每行内容（`raw_command`）以 `-` 开始时，调用 `dyn_event_release` 销毁 `trace_uprobe`。实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int create_or_delete_trace_uprobe(const char *raw_command)
{
    if (raw_command[0] == '-')
        return dyn_event_release(raw_command, &trace_uprobe_ops);
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

`create_or_delete_trace_uprobe` 函数使用 `trace_uprobe_ops` 参数。 `trace_uprobe_ops` 定义了 `uprobe`事件的动态事件接口，定义如下：

```C
// file: kernel/trace/trace_uprobe.c
static struct dyn_event_operations trace_uprobe_ops = {
	.create = trace_uprobe_create,
	.show = trace_uprobe_show,
	.is_busy = trace_uprobe_is_busy,
	.free = trace_uprobe_release,
	.match = trace_uprobe_match,
};
```

`.match` 接口设置为 `trace_uprobe_match`，实现对`event`,`system`,`filename`,`ref_ctr_offset`,`args`等逐级精确匹配。实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static bool trace_uprobe_match(const char *system, const char *event,
                int argc, const char **argv, struct dyn_event *ev)
{
    struct trace_uprobe *tu = to_trace_uprobe(ev);
    return (event[0] == '\0' ||
        strcmp(trace_probe_name(&tu->tp), event) == 0) &&
        (!system || strcmp(trace_probe_group_name(&tu->tp), system) == 0) &&
        trace_uprobe_match_command_head(tu, argc, argv);
}
```

`.free` 接口设置为 `trace_uprobe_release`，释放动态事件，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int trace_uprobe_release(struct dyn_event *ev)
    --> struct trace_uprobe *tu = to_trace_uprobe(ev);
        // 注销 `trace_uprobe`
    --> unregister_trace_uprobe(tu);
            // 注销 `uprobe_event`
        --> unregister_uprobe_event(tu);
            --> trace_probe_unregister_event_call(&tu->tp);
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
            // 删除 `dyn_event`
        --> dyn_event_remove(&tu->devent);
            --> list_del_init(&ev->list);
        --> trace_probe_unlink(&tu->tp);
        // 释放 `trace_uprobe`
    --> free_trace_uprobe(tu);
```

### 4.4 UPROBE--REG接口的实现

#### 1 注册过程

`perf_trace_event_reg` 函数调用了 `TRACE_REG_PERF_REGISTER` 指令，对应 `probe_event_enable` 操作。`probe_event_enable` 函数开启uprobe事件，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int
trace_uprobe_register(struct trace_event_call *event, enum trace_reg type, void *data)
{
    ...
case TRACE_REG_PERF_REGISTER:
    return probe_event_enable(event, NULL, uprobe_perf_filter);
    ...
}

// file: kernel/trace/trace_uprobe.c
static int probe_event_enable(struct trace_event_call *call,
			struct trace_event_file *file, filter_func_t filter)
{
    ...
    // 获取trace_probe事件
    tp = trace_probe_primary_from_call(call);
    if (WARN_ON_ONCE(!tp)) return -ENODEV;
    enabled = trace_probe_is_enabled(tp);

    // 设置 TRACE 或 PROFILE 标记，不能同时设置
    if (file) {
        if (trace_probe_test_flag(tp, TP_FLAG_PROFILE))
            return -EINTR;
        ret = trace_probe_add_file(tp, file);
        if (ret < 0) return ret;
    } else {
        if (trace_probe_test_flag(tp, TP_FLAG_TRACE))
            return -EINTR;
        trace_probe_set_flag(tp, TP_FLAG_PROFILE);
    }
    ...
    // 已经开启时，返回
    if (enabled) return 0;
    // 检查 uprobe 缓冲区是否启用
    ret = uprobe_buffer_enable();
    if (ret) goto err_flags;
    // 遍历tp事件中`probes`
    list_for_each_entry(tu, trace_probe_probe_list(tp), tp.list) {
        // 开启uprobe事件
        ret = trace_uprobe_enable(tu, filter);
        if (ret) { ... }
    }
    ...
}
```

`uprobe_buffer_enable()` 检查uprobe使用的缓冲区是否可用，在引用计数为0时，分配缓冲区，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int uprobe_buffer_enable(void)
    --> if (uprobe_buffer_refcnt++ == 0)
        --> ret = uprobe_buffer_init();

// file: kernel/trace/trace_uprobe.c
static int uprobe_buffer_init(void)
{
    // per-CPU变量
    uprobe_cpu_buffer = alloc_percpu(struct uprobe_cpu_buffer);
    if (uprobe_cpu_buffer == NULL) return -ENOMEM;

    for_each_possible_cpu(cpu) {
        // 分配页
        struct page *p = alloc_pages_node(cpu_to_node(cpu), GFP_KERNEL, 0);
        if (p == NULL) { ... }
        // per-CPU变量设置
        per_cpu_ptr(uprobe_cpu_buffer, cpu)->buf = page_address(p);
        mutex_init(&per_cpu_ptr(uprobe_cpu_buffer, cpu)->mutex);
    }
    return 0;
    ...
}
```

`trace_uprobe_enable` 函数开启`trace_uprobe`事件，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int trace_uprobe_enable(struct trace_uprobe *tu, filter_func_t filter)
{
    // tu 属性设置
    tu->consumer.filter = filter;
    tu->inode = d_real_inode(tu->path.dentry);

    // 注册uprobe
    if (tu->ref_ctr_offset)
        ret = uprobe_register_refctr(tu->inode, tu->offset, tu->ref_ctr_offset, &tu->consumer);
    else
        ret = uprobe_register(tu->inode, tu->offset, &tu->consumer);

    if (ret) tu->inode = NULL;
    return ret;
}
```

`uprobe_register_refctr` 和 `uprobe_register` 函数都是对 `__uprobe_register` 函数的封装，如下：

```C
// file: kernel/events/uprobes.c
int uprobe_register(struct inode *inode, loff_t offset, struct uprobe_consumer *uc)
    --> return __uprobe_register(inode, offset, 0, uc);

// file: kernel/events/uprobes.c
int uprobe_register_refctr(struct inode *inode, loff_t offset, 
            loff_t ref_ctr_offset, struct uprobe_consumer *uc)
    --> return __uprobe_register(inode, offset, ref_ctr_offset, uc);
```

`__uprobe_register` 实现过程如下：

```C
// file: kernel/events/uprobes.c
static int __uprobe_register(struct inode *inode, loff_t offset,
                loff_t ref_ctr_offset, struct uprobe_consumer *uc)
        // handler 和 ret_handler 至少设置一个
    --> if (!uc->handler && !uc->ret_handler) return -EINVAL;
        // read_mapping_page() 或者 shmem_read_mapping_page() 检查
    --> if (!inode->i_mapping->a_ops->read_folio && !shmem_mapping(inode->i_mapping))
        // 检查 offset
    --> if (offset > i_size_read(inode)) return -EINVAL;
        // 对齐检查，确保后续操作不会跨页
    --> if (!IS_ALIGNED(offset, UPROBE_SWBP_INSN_SIZE)) return -EINVAL;
	--> if (!IS_ALIGNED(ref_ctr_offset, sizeof(short)))	return -EINVAL;
        // retry： 分配 uprobe
    --> uprobe = alloc_uprobe(inode, offset, ref_ctr_offset);
        --> uprobe = kzalloc(sizeof(struct uprobe), GFP_KERNEL);
            // 属性设置
        --> uprobe->inode = inode;
        --> uprobe->offset = offset;
        --> uprobe->ref_ctr_offset = ref_ctr_offset;
            // 添加到 `uprobes_tree` 中，inode:offset 作为key
        --> cur_uprobe = insert_uprobe(uprobe);
            --> __insert_uprobe(uprobe);
                    // 添加到 `uprobes_tree` 红黑树中
                --> node = rb_find_add(&uprobe->rb_node, &uprobes_tree, __uprobe_cmp);
                    // 存在 node 时，返回 node
                --> if (node) return get_uprobe(__node_2_uprobe(node));
                    // 不存在时，设置引用计数，访问+创建 引用
                --> refcount_set(&uprobe->ref, 2); return NULL;
            // 存在 inode:offset 的uprobe时，检查 ref_ctr_offset 是否相同
        --> if (cur_uprobe) { ... }
    --> ret = -EAGAIN;
        // uprobe 活跃时，注册
    --> if (likely(uprobe_is_active(uprobe))) 
            // 添加到 `uprobe->consumers` 列表中
        --> consumer_add(uprobe, uc);
            --> uc->next = uprobe->consumers;
            --> uprobe->consumers = uc;
            // 注册`uprobe`到`vma`中，添加断点
        --> register_for_each_vma(uprobe, uc);
    --> put_uprobe(uprobe);
        // 重新尝试
    --> if (unlikely(ret == -EAGAIN)) goto retry;
```

#### 2 注销过程

`perf_trace_event_unreg` 函数调用了 `TRACE_REG_PERF_UNREGISTER` 指令，对应 `probe_event_disable` 操作。`probe_event_disable` 函数注销uprobe事件，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int
trace_uprobe_register(struct trace_event_call *event, enum trace_reg type, void *data)
{
    ...
case TRACE_REG_PERF_UNREGISTER:
    probe_event_disable(event, NULL);
    return 0;
    ...
}

// file: kernel/trace/trace_uprobe.c
static void probe_event_disable(struct trace_event_call *call, struct trace_event_file *file)
{
    tp = trace_probe_primary_from_call(call);
    // 未启用时退出
    if (!trace_probe_is_enabled(tp)) return;
   
    if (file) {
         // 删除文件, 文件列表为空时，清除 `TRACE` 标记
        if (trace_probe_remove_file(tp, file) < 0) return;
        if (trace_probe_is_enabled(tp)) return;
    } else
        // 清除 `PROFILE` 标记
        trace_probe_clear_flag(tp, TP_FLAG_PROFILE);

    // 禁用 `uprobe_event` 事件
    __probe_event_disable(tp);
    // 禁用uprobe缓冲区，计数为0时，释放分配的内存
    uprobe_buffer_disable();
}
```

`__probe_event_disable` 禁用 `uprobe_event` 事件，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static void __probe_event_disable(struct trace_probe *tp)
{
    struct trace_uprobe *tu;
    tu = container_of(tp, struct trace_uprobe, tp);
    WARN_ON(!uprobe_filter_is_empty(tu->tp.event->filter));

    // 遍历`probes`列表 
    list_for_each_entry(tu, trace_probe_probe_list(tp), tp.list) {
        if (!tu->inode) continue;
        // 注销 `trace_uprobe`
        uprobe_unregister(tu->inode, tu->offset, &tu->consumer);
        tu->inode = NULL;
    }
}
```

`uprobe_unregister` 函数注销已注册的uprobe，移除consumer。实现如下：

```C
// file: kernel/events/uprobes.c
void uprobe_unregister(struct inode *inode, loff_t offset, struct uprobe_consumer *uc)
{
    uprobe = find_uprobe(inode, offset);

    down_write(&uprobe->register_rwsem);
    __uprobe_unregister(uprobe, uc);
    up_write(&uprobe->register_rwsem);
    put_uprobe(uprobe);
}

// file: kernel/events/uprobes.c
static void __uprobe_unregister(struct uprobe *uprobe, struct uprobe_consumer *uc)
{
    // 从 `uprobe->consumers` 列表中删除 uc
    if (WARN_ON(!consumer_del(uprobe, uc))) return;
    // 删除断点
    err = register_for_each_vma(uprobe, NULL);
    // 删除uprobe
    if (!uprobe->consumers && !err)
        delete_uprobe(uprobe);
}
```

#### 3 打开过程

`perf_trace_event_open` 函数调用了 `TRACE_REG_PERF_OPEN` 指令，对应 `uprobe_perf_open` 操作。`uprobe_perf_open` 函数开启uprobe事件，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int
trace_uprobe_register(struct trace_event_call *event, enum trace_reg type, void *data)
{
    ...
case TRACE_REG_PERF_OPEN:
    return uprobe_perf_open(event, data);
    ...
}

// file: kernel/trace/trace_uprobe.c
static int uprobe_perf_open(struct trace_event_call *call, struct perf_event *event)
{
    tp = trace_probe_primary_from_call(call);
    tu = container_of(tp, struct trace_uprobe, tp);
    // 添加 `perf_event` 到 `trace_uprobe_filter` 中
    if (trace_uprobe_filter_add(tu->tp.event->filter, event)) return 0;
    // 遍历`probes`列表逐个添加
    list_for_each_entry(tu, trace_probe_probe_list(tp), tp.list) {
        // 添加断点
        err = uprobe_apply(tu->inode, tu->offset, &tu->consumer, true);
        if (err) { ... }
    }
    return err;
}
```

`trace_uprobe_filter_add` 函数添加 `perf_event` 事件到 `trace_uprobe_filter` 中，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static bool trace_uprobe_filter_add(struct trace_uprobe_filter *filter, struct perf_event *event)
{
    bool done;
    write_lock(&filter->rwlock);
    if (event->hw.target) {
        // event->parent != NULL 表示 `copy_process()`，我们需要避免调用 `uprobe_apply()`
        done = filter->nr_systemwide ||
            event->parent || event->attr.enable_on_exec ||
            trace_uprobe_filter_event(filter, event);
        list_add(&event->hw.tp_list, &filter->perf_events);
    } else {
        // 系统全局
        done = filter->nr_systemwide;
        filter->nr_systemwide++;
    }
    write_unlock(&filter->rwlock);
    return done;
}
```

`uprobe_apply` 函数注销已注册的uprobe，添加/删除断点。实现如下：

```C
// file: kernel/events/uprobes.c
int uprobe_apply(struct inode *inode, loff_t offset, struct uprobe_consumer *uc, bool add)
{
    int ret = -ENOENT;
    // 获取uprobe
    uprobe = find_uprobe(inode, offset);
    if (WARN_ON(!uprobe)) return ret;

    down_write(&uprobe->register_rwsem);
    // 检查 uc 是否在 `consumers` 中
    for (con = uprobe->consumers; con && con != uc ; con = con->next)
        ;
    // 在列表中时，注册`uprobe`到`vma`中，添加/删除 断点
    if (con) ret = register_for_each_vma(uprobe, add ? uc : NULL);
    up_write(&uprobe->register_rwsem);
    put_uprobe(uprobe);
    return err;
}
```

#### 4 关闭过程

`perf_trace_event_close` 函数调用了 `TRACE_REG_PERF_CLOSE` 指令，对应 `uprobe_perf_close` 操作。`uprobe_perf_close` 函数关闭uprobe事件，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int
trace_uprobe_register(struct trace_event_call *event, enum trace_reg type, void *data)
{
    ...
case TRACE_REG_PERF_CLOSE:
    return uprobe_perf_close(event, data);
    ...
}

// file: kernel/trace/trace_uprobe.c
static int uprobe_perf_close(struct trace_event_call *call, struct perf_event *event)
{
    tp = trace_probe_primary_from_call(call);
	tu = container_of(tp, struct trace_uprobe, tp);
	
    // 从 `trace_uprobe_filter` 中移除 `perf_event` 
    if (trace_uprobe_filter_remove(tu->tp.event->filter, event)) return 0;
    // 遍历`probes`列表逐个删除
    list_for_each_entry(tu, trace_probe_probe_list(tp), tp.list) {
        // 删除断点
        ret = uprobe_apply(tu->inode, tu->offset, &tu->consumer, false);
        if (ret) break;
    }
    return ret;
}
```

`trace_uprobe_filter_remove` 和 `trace_uprobe_filter_add` 对应， 从 `trace_uprobe_filter` 中移除 `perf_event` ，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static bool trace_uprobe_filter_remove(struct trace_uprobe_filter *filter, struct perf_event *event)
{
    bool done;  
    write_lock(&filter->rwlock);
    if (event->hw.target) {
        // 从列表中删除
        list_del(&event->hw.tp_list);
        done = filter->nr_systemwide || 
            (event->hw.target->flags & PF_EXITING) ||
            trace_uprobe_filter_event(filter, event);
    } else {
        filter->nr_systemwide--;
        done = filter->nr_systemwide;
    }
    write_unlock(&filter->rwlock);
    return done;
}
```

#### 5 设置/删除断点

在注册/注销，打开/关闭 过程中，都是通过 `register_for_each_vma` 函数实现实现。通过设置 `struct uprobe_consumer *new` 参数进行设置和删除断点，参数值为空时表示删除断点，不为空表示设置断点。`register_for_each_vma` 函数实现如下：

```C
// file: kernel/events/uprobes.c
static int register_for_each_vma(struct uprobe *uprobe, struct uprobe_consumer *new)
{
    // 是否设置断点，new != NULL
    bool is_register = !!new;
    struct map_info *info;
    int err = 0;

    percpu_down_write(&dup_mmap_sem);

    // 构建 `inode->i_mapping` 内存映射关系 
    info = build_map_info(uprobe->inode->i_mapping, uprobe->offset, is_register);
    if (IS_ERR(info)) { ... }

    while (info) {
        struct mm_struct *mm = info->mm;
        struct vm_area_struct *vma;
        // 注册时出现错误，查找下一个内存区域
        if (err && is_register) goto free;

        mmap_write_lock(mm);
        // 查找 `info->vaddr` 对应的 vma
        vma = find_vma(mm, info->vaddr);
        // 检查 vma 区域是否匹配
        if (!vma || !valid_vma(vma, is_register) || file_inode(vma->vm_file) != uprobe->inode)
            goto unlock;
        if (vma->vm_start > info->vaddr || vaddr_to_offset(vma, info->vaddr) != uprobe->offset)
            goto unlock;

        if (is_register) {
            if (consumer_filter(new, UPROBE_FILTER_REGISTER, mm))
                // 插入断点
                err = install_breakpoint(uprobe, mm, vma, info->vaddr);
        } else if (test_bit(MMF_HAS_UPROBES, &mm->flags)) {
            if (!filter_chain(uprobe, UPROBE_FILTER_UNREGISTER, mm))
                // 删除断点 
                err |= remove_breakpoint(uprobe, mm, info->vaddr);
        }
 unlock:
        mmap_write_unlock(mm);
 free:
        mmput(mm);
        // 下一个 `map_info`
        info = free_map_info(info);
    }
 out:
    percpu_up_write(&dup_mmap_sem);
    return err;
}
```

##### （1）设置断点

在设置断点前 `consumer_filter` 函数检查内存区域是否匹配，实现如下：

```C
// file: kernel/events/uprobes.c
static inline bool consumer_filter(struct uprobe_consumer *uc,
            enum uprobe_filter_ctx ctx, struct mm_struct *mm)
{
    return !uc->filter || uc->filter(uc, ctx, mm);
}
```

即，不存在 `filter` 或 `filter(uc，ctx，mm)` 返回值正确时，表示匹配。在注册阶段设置为 `uprobe_perf_filter` 函数，实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static bool uprobe_perf_filter(struct uprobe_consumer *uc, 
                enum uprobe_filter_ctx ctx, struct mm_struct *mm)
{
    tu = container_of(uc, struct trace_uprobe, consumer);
    filter = tu->tp.event->filter;

    read_lock(&filter->rwlock);
    ret = __uprobe_perf_filter(filter, mm);
    read_unlock(&filter->rwlock);
}

// file: kernel/trace/trace_uprobe.c
static bool __uprobe_perf_filter(struct trace_uprobe_filter *filter, struct mm_struct *mm)
{
    struct perf_event *event;
    // 系统全局时，全部有效
    if (filter->nr_systemwide) return true;
    // 检查是否匹配 `perf_events` 
    list_for_each_entry(event, &filter->perf_events, hw.tp_list) {
        if (event->hw.target->mm == mm)
            return true;
    }
    return false;
}
```

`install_breakpoint` 函数在`vaddr`虚拟地址上设置断点，实现如下：

```C
// file: kernel/events/uprobes.c
static int install_breakpoint(struct uprobe *uprobe, struct mm_struct *mm,
                    struct vm_area_struct *vma, unsigned long vaddr)
        // 复制原始指令
    --> ret = prepare_uprobe(uprobe, vma->vm_file, mm, vaddr);
            // uprobe不能重复复制
        --> if (test_bit(UPROBE_COPY_INSN, &uprobe->flags)) goto out;
            // 检查指令是否能够支持探针
        --> if (is_trap_insn((uprobe_opcode_t *)&uprobe->arch.insn)) goto out;
            // 复制原始指令信息，保存到 uprobe->arch.insn
        --> ret = copy_insn(uprobe, file);
            // 平台相关设置
        --> ret = arch_uprobe_analyze_insn(&uprobe->arch, mm, vaddr);
            --> uprobe_init_insn(auprobe, &insn, is_64bit_mm(mm));
                --> insn_decode(insn, auprobe->insn, sizeof(auprobe->insn), m);
                    --> insn_init(insn, kaddr, buf_len, m == INSN_MODE_64);
                    --> insn_get_length(insn);
                    --> insn_complete(insn);
                // uprobe_xol_ops 匹配性设置，按branch, push, default层级选择
            --> branch_setup_xol_ops(auprobe, &insn);
                --> auprobe->ops = &branch_xol_ops;
            --> push_setup_xol_ops(auprobe, &insn);
                --> auprobe->ops = &push_xol_ops;
            --> auprobe->ops = &default_xol_ops;
            // 设置`UPROBE_COPY_INSN`, 表示已经复制
        --> set_bit(UPROBE_COPY_INSN, &uprobe->flags);
        // 第一次使用时，设置 MMF_HAS_UPROBES 标记
    --> if (first_uprobe) set_bit(MMF_HAS_UPROBES, &mm->flags);
        // 设置断点
    --> ret = set_swbp(&uprobe->arch, mm, vaddr);
        --> uprobe_write_opcode(auprobe, mm, vaddr, UPROBE_SWBP_INSN);
        // 失败时，设置`RECALC_UPROBES`标记，表示`MMF_HAS_UPROBES`有误
    --> if (!ret) clear_bit(MMF_RECALC_UPROBES, &mm->flags);
        // 第一次使用时，清除 MMF_HAS_UPROBES 标记
	--> else if (first_uprobe) clear_bit(MMF_HAS_UPROBES, &mm->flags);
```

`uprobe_write_opcode` 函数在指定的虚拟地址上写入`opcode`，通过复制页实现，如下：

```C
// file: kernel/events/uprobes.c
int uprobe_write_opcode(struct arch_uprobe *auprobe, struct mm_struct *mm,
            unsigned long vaddr, uprobe_opcode_t opcode)
{
    is_register = is_swbp_insn(&opcode);
    uprobe = container_of(auprobe, struct uprobe, arch);

    ...
    // 获取旧的内存页
    ret = get_user_pages_remote(mm, vaddr, 1, gup_flags, &old_page, &vma, NULL);
    ... 
    // 分配新的内存页
    new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vaddr);
    ...
    // 复制内存页
    copy_highpage(new_page, old_page);
    // 复制`opcode``
    copy_to_page(new_page, vaddr, &opcode, UPROBE_SWBP_INSN_SIZE);
    ...
    // 替换内存页
    ret = __replace_page(vma, vaddr, old_page, new_page);
    ...
    // 释放旧的内存页
    put_page(old_page);
}
```

设置断点时，在`vaddr`虚拟地址上写入`UPROBE_SWBP_INSN`指令，x86_64下为 `int3` 指令，如下：

```C
// file: arch/x86/include/asm/uprobes.h
#define UPROBE_SWBP_INSN		0xcc
#define UPROBE_SWBP_INSN_SIZE		   1
```

##### （2）删除断点

在删除断点前 `filter_chain` 函数检查内存区域是否匹配，实现如下：

```C
// file: kernel/events/uprobes.c
static bool filter_chain(struct uprobe *uprobe,
                enum uprobe_filter_ctx ctx, struct mm_struct *mm)
{
    struct uprobe_consumer *uc;
    bool ret = false;
    down_read(&uprobe->consumer_rwsem);
    // 遍历所有的 consumers
    for (uc = uprobe->consumers; uc; uc = uc->next) {
        ret = consumer_filter(uc, ctx, mm);
        if (ret) break;
    }
    up_read(&uprobe->consumer_rwsem);
    return ret;
}
```

即，`!filter_chain()`表示 `uprobe`设置的`consumers`任意一个匹配时，不能删除断点。

`remove_breakpoint` 函数在`vaddr`虚拟地址上写入原来的指令，实现删除断点。实现如下：

```C
// file: kernel/events/uprobes.c
static int remove_breakpoint(struct uprobe *uprobe, struct mm_struct *mm, unsigned long vaddr)
        // 设置`RECALC_UPROBES`标记，表示`MMF_HAS_UPROBES`有误
    --> set_bit(MMF_RECALC_UPROBES, &mm->flags);
	--> set_orig_insn(&uprobe->arch, mm, vaddr);
            // 在虚拟地址上写入保存的原始指令
        --> uprobe_write_opcode(auprobe, mm, vaddr, *(uprobe_opcode_t *)&auprobe->insn);
```


#### 6 设置BPF程序

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

`uprobe`和`Tracepoint`属于`tracing`事件，通过`perf_event_attach_bpf_prog` 添加bpf程序到 `tp_event->prog_array` 列表中。

### 4.5 UPROBE的触发过程

#### 1 中断设置

设置断点时，在`vaddr`虚拟地址上写入`UPROBE_SWBP_INSN`指令，在`x86_64`下对应`int3`指令。

##### （1）INT3中断设置

```C
// file: arch/x86/entry/entry_64.S
//idtentry宏定义
.macro idtentry vector asmsym cfunc has_error_code:req
SYM_CODE_START(\asmsym)
    --> ...
    --> call	\cfunc
    --> ...

// int3 中断设置
// file: arch/x86/include/asm/idtentry.h
DECLARE_IDTENTRY_RAW(X86_TRAP_BP,		exc_int3);
```

`X86_TRAP_BP` 中断处理函数为 `asm_exc_int3`， 在其中调用 `exc_int3` C函数。实现如下： 

```C
// file: arch/x86/kernel/traps.c
DEFINE_IDTENTRY_RAW(exc_int3)
{
    if (user_mode(regs)) {
        irqentry_enter_from_user_mode(regs);
        instrumentation_begin();
        // 用户空间`int3`处理
        do_int3_user(regs);
        instrumentation_end();
        // 退出到用户态
        irqentry_exit_to_user_mode(regs);
    } else {
        irqentry_state_t irq_state = irqentry_nmi_enter(regs);
        instrumentation_begin();
        if (!do_int3(regs))
            die("int3", regs, 0);
        instrumentation_end();
        irqentry_nmi_exit(regs, irq_state);
    }
}
```

在 `do_int3_user` 函数中调用 `do_int3` 函数，`do_int3` 函数实现如下：

```C
// file: arch/x86/kernel/traps.c
static void do_int3_user(struct pt_regs *regs)
{
    if (do_int3(regs))
        return;

    cond_local_irq_enable(regs);
    do_trap(X86_TRAP_BP, SIGTRAP, "int3", regs, 0, 0, NULL);
    cond_local_irq_disable(regs);
}

// file: arch/x86/kernel/traps.c
static bool do_int3(struct pt_regs *regs)
{
    int res;
    ...
    res = notify_die(DIE_INT3, "int3", regs, 0, X86_TRAP_BP, SIGTRAP);
    return res == NOTIFY_STOP;
}
```

`notify_die` 通过通知链发送`die`消息，实现如下：

```C
// file: kernel/notifier.c
int notrace notify_die(enum die_val val, const char *str,
        struct pt_regs *regs, long err, int trap, int sig)
{
    struct die_args args = {
        .regs	= regs,
        .str	= str,
        .err	= err,
        .trapnr	= trap,
        .signr	= sig,
    };
    RCU_LOCKDEP_WARN(!rcu_is_watching(), 
        "notify_die called but RCU thinks we're quiescent");
    return atomic_notifier_call_chain(&die_chain, val, &args);
}
```

通知链的实现参见[Notification Chains](https://0xax.gitbook.io/linux-insides/summary/concepts/linux-cpu-4) 。

##### （2）UPROBE通知链

在`start_kernel`初始化阶段，`uprobes_init` 函数注册 `die_notifier` 通知链。如下：

```C
// file: kernel/events/uprobes.c
void __init uprobes_init(void)
{
    ...
    BUG_ON(register_die_notifier(&uprobe_exception_nb));
}
```

`uprobe_exception_nb` 定义如下：

```C
// file: kernel/events/uprobes.c
static struct notifier_block uprobe_exception_nb = {
    .notifier_call  = arch_uprobe_exception_notify,
    .priority       = INT_MAX-1,	/* notified after kprobes, kgdb */
};
```

设置的 `.notifier_call` 接口设置为 `arch_uprobe_exception_notify` ，实现如下：

```C
// file: kernel/events/uprobes.c
int arch_uprobe_exception_notify(struct notifier_block *self, unsigned long val, void *data)
{
    struct die_args *args = data;
    struct pt_regs *regs = args->regs;
    int ret = NOTIFY_DONE;

    // 只关心用户空间的陷阱
    if (regs && !user_mode(regs)) return NOTIFY_DONE;
    switch (val) {
    case DIE_INT3: 
        // uprobe单步执行前通知
        if (uprobe_pre_sstep_notifier(regs)) ret = NOTIFY_STOP;
        break;
    case DIE_DEBUG:
        // uprobe单步执行后通知
        if (uprobe_post_sstep_notifier(regs)) ret = NOTIFY_STOP;
        break;
    default:
        break;
    }
    return ret;
}
```

`uprobe_pre_sstep_notifier` 被中断上下文调用，设置`TIF_UPROBE`标记，表示触发断点。实现如下：

```C
// file: kernel/events/uprobes.c
int uprobe_pre_sstep_notifier(struct pt_regs *regs)
{
    if (!current->mm) return 0;

    if (!test_bit(MMF_HAS_UPROBES, &current->mm->flags) &&
        (!current->utask || !current->utask->return_instances))
        return 0;
    // 设置`TIF_UPROBE`标记
    set_thread_flag(TIF_UPROBE);
    return 1;
}
```

`uprobe_post_sstep_notifier` 被中断上下文调用，设置`TIF_UPROBE`标记，表示完成断点。实现如下：

```C
// file: kernel/events/uprobes.c
int uprobe_pre_sstep_notifier(struct pt_regs *regs)
{
    struct uprobe_task *utask = current->utask;
    // 当前task没有设置uprobe
    if (!current->mm || !utask || !utask->active_uprobe)
        return 0;
    // 设置断点完成标志
    utask->state = UTASK_SSTEP_ACK;
    set_thread_flag(TIF_UPROBE);
    return 1;
}
```

##### （3）触发UPROBE

在断点处理完成后，在退出到用户空间的过程，触发UPROBE。实现过程如下：

```C
// file: kernel/entry/common.c
noinstr void irqentry_exit_to_user_mode(struct pt_regs *regs)
    --> exit_to_user_mode_prepare(regs);
            // 读取线程标记
        --> ti_work = read_thread_flags();
        --> if (unlikely(ti_work & EXIT_TO_USER_MODE_WORK))
            --> ti_work = exit_to_user_mode_loop(regs, ti_work);
                --> while (ti_work & EXIT_TO_USER_MODE_WORK) 
                        // 检查`TIF_UPROBE`标记
                    --> if (ti_work & _TIF_UPROBE)
                        --> uprobe_notify_resume(regs);
                    --> if (ti_work & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL))
                        --> arch_do_signal_or_restart(regs);
```

`uprobe_notify_resume` 函数是触发UPROBE设置的断点后，在返回用户空间过程中UPROBE的处理函数。实现如下：

```C
// file: kernel/events/uprobes.c
void uprobe_notify_resume(struct pt_regs *regs)
{
    struct uprobe_task *utask;
    clear_thread_flag(TIF_UPROBE);
    utask = current->utask;
    if (utask && utask->active_uprobe)
        handle_singlestep(utask, regs);
    else
        handle_swbp(regs);
}
```

`handle_swbp` 函数处理UPROBE，并设置单步调试信息（如：active_uprobe等）；`handle_singlestep` 函数完成对断点的单步调试。单步调试的过程比较复杂，暂时略过。我们现阶段关注UPROBE的处理过程，通过 `handle_swbp` 进行处理的。

`handle_swbp` 函数调用UPROBE的处理接口函数，设置线程处于单步调式状态。这个阶段我们只关注UPROBE处理部分，主要实现如下：

```C
// file: kernel/events/uprobes.c
static void handle_swbp(struct pt_regs *regs)
{
    ...
    // 获取断点指令的虚拟地址，`reg->pc - UPROBE_SWBP_INSN_SIZE`
    bp_vaddr = uprobe_get_swbp_addr(regs);

    // uretprobe设置的`trampoline`
    if (bp_vaddr == get_trampoline_vaddr())
        return handle_trampoline(regs);
    
    // 获取断点指令地址的UPROBE
    uprobe = find_active_uprobe(bp_vaddr, &is_swbp);
    if (!uprobe) { ... }

    // UPROBE设置断点时，设置了 `COPY_INSN` 标记。不存在改标记，直接退出
    if (unlikely(!test_bit(UPROBE_COPY_INSN, &uprobe->flags))) goto out;

    // 和`prepare_uprobe()`中调用`smp_wmb()`对应，确保`UPROBE_COPY_INSN`设置
    smp_rmb();

    // 使用 `utask` 在处理过程中传递信息
    if (!get_utask()) goto out;
    if (arch_uprobe_ignore(&uprobe->arch, regs)) goto out;

    // UPROBE处理
    handler_chain(uprobe, regs);

    if (arch_uprobe_skip_sstep(&uprobe->arch, regs)) goto out;

    // 设置单步调试
    if (!pre_ssout(uprobe, regs, bp_vaddr)) return;

out:
    put_uprobe(uprobe);
}
```

##### （4）设置单步调试

在调用`handler_chain`处理完成UPROBE后，`pre_ssout`函数设置线程单步调试模式，如下：

```C
// file: kernel/events/uprobes.c
static int pre_ssout(struct uprobe *uprobe, struct pt_regs *regs, unsigned long bp_vaddr)
{
    ...
    // 获取 utask 和 xol_vaddr
    utask = get_utask();
    // 获取xol_area中空闲的区域
    xol_vaddr = xol_get_insn_slot(uprobe);

    utask->xol_vaddr = xol_vaddr;
    utask->vaddr = bp_vaddr;

    // 设置单步调试
    err = arch_uprobe_pre_xol(&uprobe->arch, regs);
    if (unlikely(err)) { ... }

    // 设置`active_uprobe`，触发断点时进入单步调试状态
    utask->active_uprobe = uprobe;
    utask->state = UTASK_SSTEP;
    return 0;
}
```

`arch_uprobe_pre_xol` 设置单步调试状态，

```C
// file: arch/x86/kernel/uprobes.c
int arch_uprobe_pre_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
    struct uprobe_task *utask = current->utask;
	if (auprobe->ops->pre_xol) { ... }

    // 修改执行位置
    regs->ip = utask->xol_vaddr;
    utask->autask.saved_trap_nr = current->thread.trap_nr;
    current->thread.trap_nr = UPROBE_TRAP_NR;

    utask->autask.saved_tf = !!(regs->flags & X86_EFLAGS_TF);
    // EFLAGS_TF 开启单步调试模式
    regs->flags |= X86_EFLAGS_TF;
    if (test_tsk_thread_flag(current, TIF_BLOCKSTEP))
        set_task_blockstep(current, false);

    return 0;
}
```

#### 2 `uprobe`的执行过程

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

uprobe在创建阶段设置了`handler`处理函数，如下：

```C
// file: kernel/trace/trace_uprobe.c
static struct trace_uprobe *
alloc_trace_uprobe(const char *group, const char *event, int nargs, bool is_ret)
{
    ...
    tu->consumer.handler = uprobe_dispatcher;
    ...
}
```

`uprobe_dispatcher` 函数实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int uprobe_dispatcher(struct uprobe_consumer *con, struct pt_regs *regs)
{
    ...
    tu = container_of(con, struct trace_uprobe, consumer);
    tu->nhit++;
    ...
    // 获取函数参数值
    ucb = uprobe_buffer_get();
    store_trace_args(ucb->buf, &tu->tp, regs, esize, dsize);

    if (trace_probe_test_flag(&tu->tp, TP_FLAG_TRACE))
        ret |= uprobe_trace_func(tu, regs, ucb, dsize);

#ifdef CONFIG_PERF_EVENTS
    if (trace_probe_test_flag(&tu->tp, TP_FLAG_PROFILE))
        ret |= uprobe_perf_func(tu, regs, ucb, dsize);
#endif
    uprobe_buffer_put(ucb);
    return ret;
}
```

`uprobe_perf_func` 函数检查当前内存区域在关注列表中，且不是`uretprobe`时调用 `__uprobe_perf_func` 。如下：

```C
// file: kernel/trace/trace_uprobe.c
static int uprobe_perf_func(struct trace_uprobe *tu, struct pt_regs *regs, 
                struct uprobe_cpu_buffer *ucb, int dsize)
{
    // 过滤当前内存区域
    if (!uprobe_perf_filter(&tu->consumer, 0, current->mm))
        return UPROBE_HANDLER_REMOVE;
    // 不是uretprobe
    if (!is_ret_probe(tu))
        __uprobe_perf_func(tu, 0, regs, ucb, dsize);
    return 0;
}
```

`__uprobe_perf_func` 函数进行采样数据输出，如下：

```C
// file: kernel/trace/trace_uprobe.c
static void __uprobe_perf_func(struct trace_uprobe *tu, unsigned long func, struct pt_regs *regs,
                struct uprobe_cpu_buffer *ucb, int dsize)
{
    ...
#ifdef CONFIG_BPF_EVENTS
    if (bpf_prog_array_valid(call)) {
        // 运行BPF程序
        ret = bpf_prog_run_array_sleepable(call->prog_array, regs, bpf_prog_run);
        if (!ret) return;
    }
#endif /* CONFIG_BPF_EVENTS */

    ...
    head = this_cpu_ptr(call->perf_events);
    if (hlist_empty(head)) goto out;

    // 参数数据
    entry = perf_trace_buf_alloc(size, NULL, &rctx);
    if (is_ret_probe(tu)) {
        entry->vaddr[0] = func;
        entry->vaddr[1] = instruction_pointer(regs);
        data = DATAOF_TRACE_ENTRY(entry, true);
    } else {
        entry->vaddr[0] = instruction_pointer(regs);
        data = DATAOF_TRACE_ENTRY(entry, false);
    }
    memcpy(data, ucb->buf, tu->tp.size + dsize);
    ...
    // 默认方式采样数据输出
    perf_trace_buf_submit(entry, size, rctx, call->event.type, 1, regs, head, NULL);
}
```

#### 3 `uretprobe`的执行过程

##### （1）设置`uretprobe`断点

`handler_chain` 函数调用UPROBE设置的处理函数中，存在`ret_handler`时，在返回位置上设置断点。`prepare_uretprobe` 实现该功能，如下：

```C
// file: kernel/events/uprobes.c
static void prepare_uretprobe(struct uprobe *uprobe, struct pt_regs *regs)
{
    ...
    // 获取xol区域，trampoline区域
    if (!get_xol_area()) return;
    utask = get_utask();
    if (!utask) return;
    
    // 执行深度检查
    if (utask->depth >= MAX_URETPROBE_DEPTH) { ... }

    ri = kmalloc(sizeof(struct return_instance), GFP_KERNEL);
    ...
    // 获取`trampoline`地址（xol_area->vaddr），将返回地址替换为trampoline地址
    trampoline_vaddr = get_trampoline_vaddr();
    orig_ret_vaddr = arch_uretprobe_hijack_return_addr(trampoline_vaddr, regs);
    ...
    // ret指令设置
    ri->uprobe = get_uprobe(uprobe);
    ri->func = instruction_pointer(regs);
    ri->stack = user_stack_pointer(regs);
    ri->orig_ret_vaddr = orig_ret_vaddr;
    ri->chained = chained;

    utask->depth++;
    ri->next = utask->return_instances;
    utask->return_instances = ri;
}
```

* 获取`xol_area`区域
  
`xol_area` 区域存储行外执行指令。`get_xol_area` 函数获取该区域，不存在时创建，实现如下：

```C
// file: kernel/events/uprobes.c
static struct xol_area *get_xol_area(void)
{
    struct mm_struct *mm = current->mm;
    struct xol_area *area;

    if (!mm->uprobes_state.xol_area)
        __create_xol_area(0);

    area = READ_ONCE(mm->uprobes_state.xol_area);
    return area;
}
```

`__create_xol_area` 函数创建`xol_area`，在该区域设置断点。实现如下：

```C
// file: kernel/events/uprobes.c
static struct xol_area *__create_xol_area(unsigned long vaddr)
{
    struct mm_struct *mm = current->mm;
    uprobe_opcode_t insn = UPROBE_SWBP_INSN;
    struct xol_area *area;
    
    area = kmalloc(sizeof(*area), GFP_KERNEL);
    area->bitmap = kcalloc(BITS_TO_LONGS(UINSNS_PER_PAGE), sizeof(long), GFP_KERNEL);
    // xol_mapping属性设置
    area->xol_mapping.name = "[uprobes]";
    area->xol_mapping.fault = NULL;
    area->xol_mapping.pages = area->pages;
    // 分配一个内存页
    area->pages[0] = alloc_page(GFP_HIGHUSER);
    area->pages[1] = NULL;
    // 虚拟地址设置
    area->vaddr = vaddr;
    // 设置断点指令
    arch_uprobe_copy_ixol(area->pages[0], 0, &insn, UPROBE_SWBP_INSN_SIZE);
    
    // 添加到mm内存区域中
    if (!xol_add_vma(mm, area))
        return area;
    ...
}
```

`xol_add_vma` 实现映射内存区域，如下：

```C
// file: kernel/events/uprobes.c
static int xol_add_vma(struct mm_struct *mm, struct xol_area *area)
{
    ...
    if (!area->vaddr) {
        // 映射内存地址，尽量往高地址上映射
        area->vaddr = get_unmapped_area(NULL, TASK_SIZE - PAGE_SIZE, PAGE_SIZE, 0, 0);
    }
    // 添加内存区域
    vma = _install_special_mapping(mm, area->vaddr, PAGE_SIZE,  
                VM_EXEC|VM_MAYEXEC|VM_DONTCOPY|VM_IO, &area->xol_mapping);
    // 设置`uprobes_state.xol_area` 值
    smp_store_release(&mm->uprobes_state.xol_area, area); 
}
```

* 替换返回地址

`arch_uretprobe_hijack_return_addr` 函数修改用户空间的栈信息，实现执行过程的跳转。实现如下：

```C
// file: arch/x86/kernel/uprobes.c
unsigned long arch_uretprobe_hijack_return_addr(unsigned long trampoline_vaddr, struct pt_regs *regs)
{
    int rasize = sizeof_long(regs), nleft;
    unsigned long orig_ret_vaddr = 0; /* clear high bits for 32-bit apps */

    // 从`sp`寄存器中获取原来的返回地址
    if (copy_from_user(&orig_ret_vaddr, (void __user *)regs->sp, rasize))
        return -1;

    // 检查该地址是否已经修改
    if (orig_ret_vaddr == trampoline_vaddr)
        return orig_ret_vaddr;
        
    // 修改`sp`寄存器，设置用户函数执行完成后跳转到`trampoline`中
    nleft = copy_to_user((void __user *)regs->sp, &trampoline_vaddr, rasize);
    if (likely(!nleft))
        return orig_ret_vaddr;

    // 出现错误时，发送段错误信号
    if (nleft != rasize) {
        pr_err("return address clobbered: pid=%d, %%sp=%#lx, %%ip=%#lx\n", 
                current->pid, regs->sp, regs->ip);
        force_sig(SIGSEGV);
    }
    return -1;
}
```

##### （2）触发`uretprobe`断点

在用户空间函数执行完成后，跳转到`xol_area`的虚拟地址上继续执行，该地址设置了断点指令，进而触发`int3`中断，最终执行 `handle_swbp` 函数。此时是`uretprobe`的`trampoline`触发的断点，如下：

```C
// file: kernel/events/uprobes.c
static void handle_swbp(struct pt_regs *regs)
{
    ...
    // 获取断点指令的虚拟地址，`reg->pc - UPROBE_SWBP_INSN_SIZE`
    bp_vaddr = uprobe_get_swbp_addr(regs);
    // uretprobe设置的`trampoline`
    if (bp_vaddr == get_trampoline_vaddr())
        return handle_trampoline(regs);
    ...
}
```

`handle_trampoline` 函数实现`uretprobe`设置的处理函数，如下：

```C
// file: kernel/events/uprobes.c
static void handle_trampoline(struct pt_regs *regs)
{
    ...
    // 获取utask和ri，不存在时，发送`SIGILL`指令
    utask = current->utask;
    if (!utask) goto sigill;
    ri = utask->return_instances;
    if (!ri) goto sigill;

    do {
        next = find_next_ret_chain(ri);
        valid = !next || arch_uretprobe_is_alive(next, RP_CHECK_RET, regs);
        instruction_pointer_set(regs, ri->orig_ret_vaddr);
        do {
            if (valid)
                // uretprobe处理
                handle_uretprobe_chain(ri, regs);
                // 释放ret指令的同时，释放`uprobe`
            ri = free_ret_instance(ri);
            utask->depth--;
        } while (ri != next);
    } while (!valid);

    utask->return_instances = ri;
    return;

 sigill:
    uprobe_warn(current, "handle uretprobe, sending SIGILL.");
    force_sig(SIGILL);
}
```

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

uprobe在创建阶段设置了`ret_handler`处理函数，如下：

```C
// file: kernel/trace/trace_uprobe.c
static struct trace_uprobe *
alloc_trace_uprobe(const char *group, const char *event, int nargs, bool is_ret)
{
    ...
    if (is_ret)
        tu->consumer.ret_handler = uretprobe_dispatcher;
    ...
}
```

`uretprobe_dispatcher` 函数实现如下：

```C
// file: kernel/trace/trace_uprobe.c
static int uretprobe_dispatcher(struct uprobe_consumer *con, unsigned long func, struct pt_regs *regs)
{

    tu = container_of(con, struct trace_uprobe, consumer);
    ...
    // 获取函数参数值
    ucb = uprobe_buffer_get();
	store_trace_args(ucb->buf, &tu->tp, regs, esize, dsize);
    
    if (trace_probe_test_flag(&tu->tp, TP_FLAG_TRACE))
        uretprobe_trace_func(tu, func, regs, ucb, dsize);

#ifdef CONFIG_PERF_EVENTS
    if (trace_probe_test_flag(&tu->tp, TP_FLAG_PROFILE))
        uretprobe_perf_func(tu, func, regs, ucb, dsize);
#endif
    uprobe_buffer_put(ucb);
    return 0;
}
```

`uretprobe_perf_func` 直接调用 `__uprobe_perf_func` 完成采样数据的输出。如下：

```C
// file: kernel/trace/trace_uprobe.c
static void uretprobe_perf_func(struct trace_uprobe *tu, unsigned long func,
                struct pt_regs *regs, struct uprobe_cpu_buffer *ucb, int dsize)
{
    __uprobe_perf_func(tu, func, regs, ucb, dsize);
}
```

#### 4 断点修正

在中断触发后返回到用户空间的过程中，在触发UPROBE后设置运行线程处于单步调试状态，`handle_singlestep` 处理修正这种情况，如下：

```C
// file： kernel/events/uprobes.c
static void handle_singlestep(struct uprobe_task *utask, struct pt_regs *regs)
{
    ...
    uprobe = utask->active_uprobe;

    if (utask->state == UTASK_SSTEP_ACK)
        // 单步执行后恢复
        err = arch_uprobe_post_xol(&uprobe->arch, regs);
    else if (utask->state == UTASK_SSTEP_TRAPPED)
        // 出现错误时取消`xol`
        arch_uprobe_abort_xol(&uprobe->arch, regs);
    else
        WARN_ON_ONCE(1);

    // 释放UPROBE
    put_uprobe(uprobe);
    // utask状态修改
    utask->active_uprobe = NULL;
    utask->state = UTASK_RUNNING;
    // 释放xol_insl
    xol_free_insn_slot(current);

    spin_lock_irq(&current->sighand->siglock);
    // 撤回等待的信号，清除`TIF_SIGPENDING`标记
    recalc_sigpending(); /* see uprobe_deny_signal() */
    spin_unlock_irq(&current->sighand->siglock);

    if (unlikely(err)) {
        uprobe_warn(current, "execute the probed insn, sending SIGILL.");
        force_sig(SIGILL);
    }
}
```

`arch_uprobe_post_xol` 函数在单步执行后调用，恢复之前的执行状态。如下：

```C
// file: arch/x86/kernel/uprobes.c
int arch_uprobe_post_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
    struct uprobe_task *utask = current->utask;
    bool send_sigtrap = utask->autask.saved_tf;
    ...
    // 恢复`trap_nr`
    WARN_ON_ONCE(current->thread.trap_nr != UPROBE_TRAP_NR);
    current->thread.trap_nr = utask->autask.saved_trap_nr;
    
    if (auprobe->ops->post_xol) { ... }

    // 发送额外的`SIGTRAP`信号
    if (send_sigtrap)
        send_sig(SIGTRAP, current, 0);

    // 清除`arch_uprobe_pre_xol()`设置的TF标记
    if (!utask->autask.saved_tf)
        regs->flags &= ~X86_EFLAGS_TF;

    return err;
}
```

`arch_uprobe_abort_xol` 函数在`XOL`指令被捕获或线程出现致命错误时，将执行指令重置为保存的位置。如下：

```C
// file: arch/x86/kernel/uprobes.c
void arch_uprobe_abort_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
    struct uprobe_task *utask = current->utask;

    if (auprobe->ops->abort)
        auprobe->ops->abort(auprobe, regs);
    // 获取之前的执行位置
    current->thread.trap_nr = utask->autask.saved_trap_nr;
    regs->ip = utask->vaddr;
    // 清除`arch_uprobe_pre_xol()`设置的TF标记
    if (!utask->autask.saved_tf)
        regs->flags &= ~X86_EFLAGS_TF;
}
```

### 4.6 GDB调试验证

我们使用GDB调试`uprobe`执行程序，查看对应的执行情况。如下：

#### (1) 附加BPF程序前

附加BPF程序前，`uprobed_add` 的反汇编代码如下：

```bash
$ sudo gdb ./uprobe 
// 设置main函数断点
(gdb) b main 
(gdb) r
Starting program: /<path>/uprobe 
[Thread debugging using libthread_db enabled]
...
Breakpoint 1, 0x000055555555a4ad in main ()
(gdb) disassemble uprobed_add 
Dump of assembler code for function uprobed_add:
   0x000055555555a477 <+0>:     endbr64 
   0x000055555555a47b <+4>:     push   %rbp
   0x000055555555a47c <+5>:     mov    %rsp,%rbp
   0x000055555555a47f <+8>:     mov    %edi,-0x4(%rbp)
   0x000055555555a482 <+11>:    mov    %esi,-0x8(%rbp)
   0x000055555555a485 <+14>:    mov    -0x4(%rbp),%edx
   0x000055555555a488 <+17>:    mov    -0x8(%rbp),%eax
   0x000055555555a48b <+20>:    add    %edx,%eax
   0x000055555555a48d <+22>:    pop    %rbp
   0x000055555555a48e <+23>:    ret    
End of assembler dump.
```

可以看到，入口位置为`endbr64`指令。

#### (2) 附加BPF程序后

继续运行，在附加BPF程序后通过`Ctrl-C`中断GDB调试后，查看反汇编情况，如下：

```bash
(gdb) c
Continuing.
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
...^C
Program received signal SIGINT, Interrupt.
0x00007ffff7ce57fa in clock_nanosleep () from /lib/x86_64-linux-gnu/libc.so.6

(gdb) disassemble uprobed_add 
Dump of assembler code for function uprobed_add:
   0x000055555555a477 <+0>:     int3   
   0x000055555555a478 <+1>:     nop    %edx
   0x000055555555a47b <+4>:     push   %rbp
   0x000055555555a47c <+5>:     mov    %rsp,%rbp
   0x000055555555a47f <+8>:     mov    %edi,-0x4(%rbp)
   0x000055555555a482 <+11>:    mov    %esi,-0x8(%rbp)
   0x000055555555a485 <+14>:    mov    -0x4(%rbp),%edx
   0x000055555555a488 <+17>:    mov    -0x8(%rbp),%eax
   0x000055555555a48b <+20>:    add    %edx,%eax
   0x000055555555a48d <+22>:    pop    %rbp
   0x000055555555a48e <+23>:    ret    
End of assembler dump.
```

此时入口点位置指令已经替换为`int3`指令。

#### (3) 查看uretprobe执行情况

在调用`uprobed_add`的位置设置断点，

```bash
(gdb) disassemble main 
Dump of assembler code for function main:
   0x000055555555a4a5 <+0>:     endbr64 
   ...
   0x000055555555a666 <+449>:   mov    %edx,%esi
   0x000055555555a668 <+451>:   mov    %eax,%edi
   0x000055555555a66a <+453>:   call   0x55555555a477 <uprobed_add>
   0x000055555555a66f <+458>:   mov    -0x14(%rbp),%eax
   0x000055555555a672 <+461>:   imul   %eax,%eax
   ...

// 在调用`uprobed_add`位置设置断点
(gdb) b *0x000055555555a66a
Breakpoint 2 at 0x55555555a66a
// 逐指令执行
(gdb) si
0x000055555555a477 in uprobed_add ()
// 查看rsp寄存器值
(gdb) x/10a  $rsp
0x7fffffffe3b8: 0x55555555a66f <main+458>       0x7fffffffe508

// 执行一条指令，此时`int3`指令执行完成
(gdb) si
0x000055555555a47b in uprobed_add ()
(gdb) x/10a  $rsp
0x7fffffffe3b8: 0x7ffff7fba000  0x7fffffffe508
```

可以看到，将`%rsp`寄存器中的值从 `0x55555555a66f` 修改为 `0x7ffff7fba000`。`0x7ffff7fba000` 对应`uretprobe`设置的trampoline地址。在gdb中查看内存映射信息，如下：

```bash
(gdb) info proc mappings 
process 1019519
Mapped address spaces:
          Start Addr           End Addr       Size     Offset  Perms  objfile
          ...
      0x7ffff7fba000     0x7ffff7fbb000     0x1000        0x0  --xp   [uprobes]
          ...
```

继续执行，在`uprobed_add`函数执行完成后，跳转到`0x00007ffff7fba000`地址执行，然后返回到`main`函数中继续执行，如下：

```bash
...
(gdb) si
0x000055555555a48e in uprobed_add ()
(gdb) si
0x00007ffff7fba000 in ?? ()
(gdb) si
0x000055555555a672 in main ()
```

## 5 USDT的实现

### 5.1 BPF程序

BPF程序的源码参见[usdt.bpf.c](../src/usdt.bpf.c)，主要内容如下：

```C
SEC("usdt/libc.so.6:libc:setjmp")
int BPF_USDT(usdt_auto_attach, void *arg1, int arg2, void *arg3)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != my_pid)
        return 0;
    bpf_printk("USDT auto attach to libc:setjmp: arg1 = %lx, arg2 = %d, arg3 = %lx", arg1, arg2, arg3);
    return 0;
}

SEC("usdt")
int BPF_USDT(usdt_manual_attach, void *arg1, int arg2, void *arg3)
{
    bpf_printk("USDT manual attach to libc:setjmp: arg1 = %lx, arg2 = %d, arg3 = %lx", arg1, arg2, arg3);
    return 0;
}
```

该程序包括两个BPF程序 `usdt_auto_attach` 和 `usdt_manual_attach` 。

#### `BPF_USDT`展开过程

`usdt_auto_attach` 和 `usdt_manual_attach` 使用 `BPF_USDT` 宏，都有三个参数 `arg1`，`arg2` 和 `arg3`。`BPF_USDT` 宏在 [usdt.bpf.h](../libbpf/src/usdt.bpf.h) 中定义的，如下：

```C
// file: libbpf/src/usdt.bpf.h
#define BPF_USDT(name, args...)						    \
name(struct pt_regs *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args);				    \
typeof(name(0)) name(struct pt_regs *ctx)				    \
{									    \
        _Pragma("GCC diagnostic push")					    \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
        return ____##name(___bpf_usdt_args(args));			    \
        _Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args)
```

`___bpf_usdt_args(args)` 宏在同一个文件中定义，展开 `args` 的参数，如下：

```C
// file: libbpf/src/usdt.bpf.h
#define ___bpf_usdt_args0() ctx
#define ___bpf_usdt_args1(x) ___bpf_usdt_args0(), ({ long _x; bpf_usdt_arg(ctx, 0, &_x); (void *)_x; })
#define ___bpf_usdt_args2(x, args...) ___bpf_usdt_args1(args), ({ long _x; bpf_usdt_arg(ctx, 1, &_x); (void *)_x; })
...
#define ___bpf_usdt_args12(x, args...) ___bpf_usdt_args11(args), ({ long _x; bpf_usdt_arg(ctx, 11, &_x); (void *)_x; })
#define ___bpf_usdt_args(args...) ___bpf_apply(___bpf_usdt_args, ___bpf_narg(args))(args)
```

`___bpf_usdt_argsn(args)` 宏获取`ctx`的第n个参数，通过 `bpf_usdt_arg` 函数获取的，该函数的实现将在后面进行分析。

`int BPF_USDT(usdt_auto_attach, void *arg1, int arg2, void *arg3)` 宏展开后如下：

```C
int usdt_auto_attach(struct pt_regs *ctx); 
static inline __attribute__((always_inline)) typeof(usdt_auto_attach(0)) 
____usdt_auto_attach(struct pt_regs *ctx,void *arg1, int arg2, void *arg3); 
typeof(usdt_auto_attach(0)) usdt_auto_attach(struct pt_regs *ctx) {
     _Pragma("GCC diagnostic push") 
     _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") 
     return ____usdt_auto_attach(ctx, 
                ({ long _x; bpf_usdt_arg(ctx, 0, &_x); (void *)_x; }), 
                ({ long _x; bpf_usdt_arg(ctx, 1, &_x); (void *)_x; }), 
                ({ long _x; bpf_usdt_arg(ctx, 2, &_x); (void *)_x; })); 
     _Pragma("GCC diagnostic pop") 
} 
static inline __attribute__((always_inline)) typeof(usdt_auto_attach(0)) 
____usdt_auto_attach(struct pt_regs *ctx,void *arg1, int arg2, void *arg3)
```

### 5.2 用户程序

用户程序的源码参见[usdt.c](../src/usdt.c)，主要功能如下：

#### 1 附加BPF过程

```C
int main(int argc, char **argv)
{
    struct usdt_bpf *skel;
    ...
    // 打开BPF程序
    skel = usdt_bpf__open();
    // 设置pid过滤
    skel->bss->my_pid = getpid();
    // 加载BPF程序
    err = usdt_bpf__load(skel);

    // 手动方式附加，指定了pid参数，在BPF程序中不需要pid过滤
    skel->links.usdt_manual_attach = bpf_program__attach_usdt(
        skel->progs.usdt_manual_attach, getpid(), "libc.so.6", "libc", "setjmp", NULL);

    // 自动附加BPF程序，libbpf自动附加USDT类型BPF程序时，没有指定pid，因此我们需要从BPF程序过过滤
    err = usdt_bpf__attach(skel);

    // 设置中断信号处理函数
    if (signal(SIGINT, sig_int) == SIG_ERR) { ... }
    ...
    while (!exiting) {
        // 触发BPF程序
        usdt_trigger();
        fprintf(stderr, ".");
        sleep(1);
    }
cleanup:
    usdt_bpf__destroy(skel);
    return -err;
}
```

#### 2 读取数据过程

`usdt_auto_attach` 和 `usdt_manual_attach` 将采集的数据通过 `bpf_printk` 输出到 `/sys/kernel/debug/tracing/trace_pipe` 文件中。

### 5.3 编译运行程序

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make usdt 
$ sudo ./usdt
...  
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

在`uprobe`程序运行的过程中打开另一个bash窗口查看输出结果，如下：

```bash
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            usdt-842601  [000] d..31 215420.038878: bpf_trace_printk: USDT auto attach to libc:setjmp: arg1 = 55653eac9220, arg2 = 0, arg3 = 55653ea82270
            usdt-842601  [000] d..31 215420.038886: bpf_trace_printk: USDT manual attach to libc:setjmp: arg1 = 55653eac9220, arg2 = 0, arg3 = 55653ea82270
            ...
```

### 5.4 libbpf附加USDT的过程

`usdt.bpf.c` 文件中BPF程序的SEC名称分别为 `SEC("usdt/libc.so.6:libc:setjmp")` 和 `SEC("usdt")` 。`usdt` 对应的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("usdt+",		KPROBE,	0, SEC_NONE, attach_usdt),
    ...
};
```

`usdt` 通过 `attach_usdt` 函数进行附加的。`attach_usdt` 支持解析的格式如下：

```text
usdt/<path>:<provider>:<name>
```

实现过程如下：

```C
// file: libbpf/src/libbpf.c
static int attach_usdt(const struct bpf_program *prog, long cookie, struct bpf_link **link)
{
    char *path = NULL, *provider = NULL, *name = NULL;
    ...
    sec_name = bpf_program__section_name(prog);
    // 只有SEC("usdt")时，不自动附加
    if (strcmp(sec_name, "usdt") == 0) { ... }
    // 解析path，provider，name参数
    n = sscanf(sec_name, "usdt/%m[^:]:%m[^:]:%m[^:]", &path, &provider, &name);
    if (n != 3) {
        // 格式不正确时提示并退出
        ...
    } else {
        *link = bpf_program__attach_usdt(prog, -1 /* any process */, path, provider, name, NULL);
        err = libbpf_get_error(*link);
    }
    ...
    return err;
}
```

`attach_usdt` 获取`SEC`中的`<path>:<provider>:<name>`参数后，调用 `bpf_program__attach_usdt` 附加USDT类型的BPF程序。如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link *bpf_program__attach_usdt(const struct bpf_program *prog,
                    pid_t pid, const char *binary_path, const char *usdt_provider, 
                    const char *usdt_name, const struct bpf_usdt_opts *opts)
{
    char resolved_path[512];
    struct bpf_object *obj = prog->obj;
    ...
    if (bpf_program__fd(prog) < 0) { ... }
    // 文件路径必须设置
    if (!binary_path) return libbpf_err_ptr(-EINVAL);

    if (!strchr(binary_path, '/')) {
        // 解析全路径
        err = resolve_full_path(binary_path, resolved_path, sizeof(resolved_path));
        if (err) { ... }
        binary_path = resolved_path;
    }

    // USDT manager 在第一次附加USDT时延时初始化，在`bpf_object__close()`中销毁
    if (IS_ERR(obj->usdt_man)) return libbpf_ptr(obj->usdt_man);
    if (!obj->usdt_man) {
        obj->usdt_man = usdt_manager_new(obj);
        if (IS_ERR(obj->usdt_man)) return libbpf_ptr(obj->usdt_man);
    }

    usdt_cookie = OPTS_GET(opts, usdt_cookie, 0);
    // 附加usdt类型程序
    link = usdt_manager_attach_usdt(obj->usdt_man, prog, pid, binary_path,
                usdt_provider, usdt_name, usdt_cookie);
    ...
    return link;
}
```

#### usdt_manager

在第一次加载USDT类型的BPF程序时，`bpf_object`会创建`usdt_manager`，`usdt_manager_new` 函数实现此功能，如下：

```C
// file: libbpf/src/usdt.c
struct usdt_manager *usdt_manager_new(struct bpf_object *obj)
{
    static const char *ref_ctr_sysfs_path = "/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset";
    struct usdt_manager *man;
    struct bpf_map *specs_map, *ip_to_spec_id_map;

    specs_map = bpf_object__find_map_by_name(obj, "__bpf_usdt_specs");
    ip_to_spec_id_map = bpf_object__find_map_by_name(obj, "__bpf_usdt_ip_to_spec_id");
    // `specs_map` 和 `ip_to_spec_id_map` 必须都存在
    if (!specs_map || !ip_to_spec_id_map) { ...  }

    man = calloc(1, sizeof(*man));
    if (!man) return ERR_PTR(-ENOMEM);

    man->specs_map = specs_map;
    man->ip_to_spec_id_map = ip_to_spec_id_map;

    // 检查内核是否支持 kprobes 的 BPF cookie 设置，支持时不需要`IP-to-ID`映射
    // 通过`probe_kern_bpf_cookie`函数探测，在`KPROBE`程序中调用`BPF_FUNC_get_attach_cookie`检查是否正常加载
    man->has_bpf_cookie = kernel_supports(obj, FEAT_BPF_COOKIE);

    // 检查内核是否支持USDT信号量的自动计数
    man->has_sema_refcnt = faccessat(AT_FDCWD, ref_ctr_sysfs_path, F_OK, AT_EACCESS) == 0;
    return man;
}
```

`__bpf_usdt_spec` 记录usdt的id和规范的映射，`__bpf_usdt_ip_to_spec_id` 记录usdt的指令位置和id的映射。这两个map的定义如下：

```C
// file: libbpf/src/usdt.bpf.h
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BPF_USDT_MAX_SPEC_CNT);
	__type(key, int);
	__type(value, struct __bpf_usdt_spec);
} __bpf_usdt_specs SEC(".maps") __weak;

// file: libbpf/src/usdt.bpf.h
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BPF_USDT_MAX_IP_CNT);
	__type(key, long);
	__type(value, __u32);
} __bpf_usdt_ip_to_spec_id SEC(".maps") __weak;
```

USDT类型的程序需要包含`usdt.bpf.h`头文件，编译时自动添加这两个MAP。`struct __bpf_usdt_spec` 结构定义了USDT的规范，如下：

```C
// file: libbpf/src/usdt.bpf.h
#define BPF_USDT_MAX_ARG_CNT 12
struct __bpf_usdt_spec {
	struct __bpf_usdt_arg_spec args[BPF_USDT_MAX_ARG_CNT];
	__u64 usdt_cookie;
	short arg_cnt;
};
```

每个规范最多包括12个参数。

#### usdt_manager_attach_usdt

`usdt_manager_attach_usdt` 函数完成附加USDT的工作，收集USDT信息后，使用UPROBE方式附加BPF程序，如下：

```C
// file: libbpf/src/usdt.c
struct bpf_link *usdt_manager_attach_usdt(struct usdt_manager *man, const struct bpf_program *prog, pid_t pid,
                    const char *path, const char *usdt_provider, const char *usdt_name, __u64 usdt_cookie)
{
    LIBBPF_OPTS(bpf_uprobe_opts, opts);
    struct hashmap *specs_hash = NULL;
    struct bpf_link_usdt *link = NULL;
    struct usdt_target *targets = NULL;

    spec_map_fd = bpf_map__fd(man->specs_map);
    ip_map_fd = bpf_map__fd(man->ip_to_spec_id_map);

    // 打开文件，解析ELF是否正确
    fd = open(path, O_RDONLY | O_CLOEXEC);
    elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
    // 确保是EXE或DYN类型的ELF文件
    err = sanity_check_usdt_elf(elf, path);

    // PID过滤
    if (pid < 0)  pid = -1;
    else if (pid == 0)  pid = getpid();
    
    // 收集指定文件的USDT信息
    err = collect_usdt_targets(man, elf, path, pid, usdt_provider, usdt_name, 
                usdt_cookie, &targets, &target_cnt);
    // 创建hashmap
    specs_hash = hashmap__new(specs_hash_fn, specs_equal_fn, NULL);

    // 创建map，设置link属性 
    link = calloc(1, sizeof(*link));
    link->usdt_man = man;
    link->link.detach = &bpf_link_usdt_detach;
    link->link.dealloc = &bpf_link_usdt_dealloc;
    // 创建 uprobes
    link->uprobes = calloc(target_cnt, sizeof(*link->uprobes));

    for (i = 0; i < target_cnt; i++) {
        struct usdt_target *target = &targets[i];
        struct bpf_link *uprobe_link;
        bool is_new;
        int spec_id;
        // 获取spec_id，使用已有的spec或分配新的
        err = allocate_spec_id(man, specs_hash, link, target, &spec_id, &is_new);
        // 新分配的，需要填写规范映射信息
        if (is_new && bpf_map_update_elem(spec_map_fd, &spec_id, &target->spec, BPF_ANY)) { ... }
        // 内核不支持bpf_cookie时，使用`ip_map_fd`映射
        if (!man->has_bpf_cookie && bpf_map_update_elem(ip_map_fd, &target->abs_ip, &spec_id, BPF_NOEXIST)) { ... }

        // 设置opts选项后，附加uprobe
        opts.ref_ctr_offset = target->sema_off;
        opts.bpf_cookie = man->has_bpf_cookie ? spec_id : 0;
        uprobe_link = bpf_program__attach_uprobe_opts(prog, pid, path, target->rel_ip, &opts);

        // 设置`link_usdt`对应的uprobes信息
        link->uprobes[i].link = uprobe_link;
        link->uprobes[i].abs_ip = target->abs_ip;
        link->uprobe_cnt++;
    }
    // 清理工作
    free(targets);
    hashmap__free(specs_hash);
    elf_end(elf);
    close(fd);
    return &link->link;

err_out:
    ...
}
```

这其中最主要的功能是收集USDT信息，`collect_usdt_targets` 实现该功能。获取ELF文件中的`.note.stapsdt`信息后逐项解析，如下：

```C
// file: libbpf/src/usdt.c
static int collect_usdt_targets(struct usdt_manager *man, Elf *elf, const char *path, pid_t pid,
                const char *usdt_provider, const char *usdt_name, __u64 usdt_cookie,
                struct usdt_target **out_targets, size_t *out_target_cnt)
{
    *out_targets = NULL;
    *out_target_cnt = 0;
    
    // 获取ELF文件中".note.stapsdt"段信息
    err = find_elf_sec_by_name(elf, USDT_NOTE_SEC, &notes_shdr, &notes_scn);   
    // `notes_shdr`是NOTE类型，必须存在
    if (notes_shdr.sh_type != SHT_NOTE || !gelf_getehdr(elf, &ehdr)) { ... }
    // 获取ELF文件中所有段
    err = parse_elf_segs(elf, path, &segs, &seg_cnt);
    
    // `.stapsdt.base` 是可选段。记录`perlink offset`
    if (find_elf_sec_by_name(elf, USDT_BASE_SEC, &base_shdr, &base_scn) == 0)
        base_addr = base_shdr.sh_addr;
    
    data = elf_getdata(notes_scn, 0);
    off = 0;
    while ((off = gelf_getnote(data, off, &nhdr, &name_off, &desc_off)) > 0) {
        long usdt_abs_ip, usdt_rel_ip, usdt_sema_off = 0;
        struct usdt_note note;
        // 解析 usdt_node
        err = parse_usdt_note(elf, path, &nhdr, data->d_buf, name_off, desc_off, &note);
        // 是否为我们需要的 provider 和 name
        if (strcmp(note.provider, usdt_provider) != 0 || strcmp(note.name, usdt_name) != 0)
            continue;
        
        // usdt绝对地址
        usdt_abs_ip = note.loc_addr;
        if (base_addr)
            usdt_abs_ip += base_addr - note.base_addr;

        // 使用uprobes时，需要指定文件的偏移地址，而不是相对的虚拟地址。
        // 我们需要将相对虚拟地址转换为文件的编译地址
        seg = find_elf_seg(segs, seg_cnt, usdt_abs_ip);
        // seg 必须可执行
        if (!seg->is_exec) { ... }
        // 将虚拟地址转换为文件偏移地址
        usdt_rel_ip = usdt_abs_ip - seg->start + seg->offset;

        if (ehdr.e_type == ET_DYN && !man->has_bpf_cookie) { 
            // 内核不支持BPF cookie，但需要附加动态链接库。我们需要知道附加点的绝对地址，只有指定PID时才能确定。
            // BPF cookie 消除了绝对地址限制，不需要进行此查找。
            // 因此对于支持 BPF cookie 的较新内核，libbpf 支持将 USDT 附加到没有 PID 过滤器的共享库。
            
            // 必须指定PID
            if (pid < 0) { ... }
            if (vma_seg_cnt == 0) {
                // 延时加载vma_segs。解析`/proc/<pid>/maps`文件，获取vma_seg
                err = parse_vma_segs(pid, path, &vma_segs, &vma_seg_cnt);
            }
            // 获取`usdt_rel_ip`所在的vma段
            seg = find_vma_seg(vma_segs, vma_seg_cnt, usdt_rel_ip);
            // 计算绝对位置
            usdt_abs_ip = seg->start - seg->offset + usdt_rel_ip;
        }

        // 将信号地址转换为文件偏移地址
        if (note.sema_addr) { 
            // 需要USDT支持 即："/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset" 可访问
            if (!man->has_sema_refcnt) { ... }

            // 计算信号偏移量
            seg = find_elf_seg(segs, seg_cnt, note.sema_addr);
            if (seg->is_exec) { ... }
            usdt_sema_off = note.sema_addr - seg->start + seg->offset;
        }
        // 记录调整后的地址和偏移量，解析USDT规格
        tmp = libbpf_reallocarray(targets, target_cnt + 1, sizeof(*targets));

        targets = tmp;
	    target = &targets[target_cnt];
	    memset(target, 0, sizeof(*target));

	    target->abs_ip = usdt_abs_ip;
	    target->rel_ip = usdt_rel_ip;
	    target->sema_off = usdt_sema_off;

        // 解析USDT规格信息
        target->spec_str = note.args;
        err = parse_usdt_spec(&target->spec, &note, usdt_cookie);

        target_cnt++;
    }
    // 设置解析结果
    *out_targets = targets;
    *out_target_cnt = target_cnt;
    err = target_cnt;

err_out:
    free(segs);
    free(vma_segs);
    if (err < 0) free(targets);
    return err;
}
```

#### 获取USDT参数

在BPF程序中，我们使用`bpf_usdt_arg`获取参数值，实现如下：

```C
// file: libbpf/src/usdt.bpf.h
__weak __hidden int bpf_usdt_arg(struct pt_regs *ctx, __u64 arg_num, long *res)
{
    *res = 0;
    // 获取规范信息，获取spec_id后，从`__bpf_usdt_specs`获取
    spec_id = __bpf_usdt_spec_id(ctx);
    spec = bpf_map_lookup_elem(&__bpf_usdt_specs, &spec_id);
    ...

    arg_spec = &spec->args[arg_num];
    switch (arg_spec->arg_type) {
    case BPF_USDT_ARG_CONST:
        // 常量值，参数格式为："-4@$-9"
        val = arg_spec->val_off;
        break;
    case BPF_USDT_ARG_REG:
        // 寄存器值，参数格式为："8@%rax" 
        err = bpf_probe_read_kernel(&val, sizeof(val), (void *)ctx + arg_spec->reg_off);
        if (err) return err;
        break;
    case BPF_USDT_ARG_REG_DEREF:
        // 寄存器值保存的值，参数格式为："-4@-1204(%rbp)" 
        err = bpf_probe_read_kernel(&val, sizeof(val), (void *)ctx + arg_spec->reg_off);
        if (err) return err;
        err = bpf_probe_read_user(&val, sizeof(val), (void *)val + arg_spec->val_off);
        if (err) return err;
        // 大端时，处理偏移
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        val >>= arg_spec->arg_bitshift;
#endif
        break;
    default:
        return -EINVAL;
    }

    // 从8字节中获取1,2,4字节值
    val <<= arg_spec->arg_bitshift;
    if (arg_spec->arg_signed)
        val = ((long)val) >> arg_spec->arg_bitshift;
    else
        val = val >> arg_spec->arg_bitshift;
    *res = val;
    return 0;
}
```

`__bpf_usdt_spec_id` 获取sec_id，实现如下：

```C
// file: libbpf/src/usdt.bpf.h
static __always_inline int __bpf_usdt_spec_id(struct pt_regs *ctx)
{
    if (!LINUX_HAS_BPF_COOKIE) {
        long ip = PT_REGS_IP(ctx);
        int *spec_id_ptr;
        // 不支持BPF cookie时，从`__bpf_usdt_ip_to_spec_id`中获取
        spec_id_ptr = bpf_map_lookup_elem(&__bpf_usdt_ip_to_spec_id, &ip);
        return spec_id_ptr ? *spec_id_ptr : -ESRCH;
    }
    return bpf_get_attach_cookie(ctx);
}
```

### 5.5 自定义USDT

#### (1) 查看USDT信息

通过`readelf`工具查看段信息，如下：

```bash
$ readelf -S /lib/x86_64-linux-gnu/libc.so.6 \
There are 66 section headers, starting at offset 0x21c0f0:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
...
  [18] .stapsdt.base     PROGBITS         00000000001e3e28  001e3e28
       0000000000000001  0000000000000000   A       0     0     1
...
  [36] .note.stapsdt     NOTE             0000000000000000  00219888
       0000000000001c6c  0000000000000000           0     0     4
...
```

查看`stapsdt`信息，如下：

```bash
$ readelf -n /lib/x86_64-linux-gnu/libc.so.6 
...
Displaying notes found in: .note.stapsdt
  Owner                Data size        Description
  stapsdt              0x0000003a       NT_STAPSDT (SystemTap probe descriptors)
    Provider: libc
    Name: setjmp
    Location: 0x0000000000042155, Base: 0x00000000001e3e28, Semaphore: 0x0000000000000000
    Arguments: 8@%rdi -4@%esi 8@%rax
  stapsdt              0x0000003b       NT_STAPSDT (SystemTap probe descriptors)
    Provider: libc
    Name: longjmp
    Location: 0x0000000000042301, Base: 0x00000000001e3e28, Semaphore: 0x0000000000000000
    Arguments: 8@%rdi -4@%esi 8@%rdx
  stapsdt              0x00000042       NT_STAPSDT (SystemTap probe descriptors)
...
```

`parse_usdt_note`函数解析`stapsdt`信息；`parse_usdt_spec` 函数解析`Arguments`信息。

#### (2) 在程序中设置USDT

`usdt-hello` 展示了一个简单的USDT示例程序，代码如下：

```C
#include <sys/sdt.h>
int main()
{
    DTRACE_PROBE("hello-usdt", "probe-main");
    int a = 10;
    DTRACE_PROBE1("hello-usdt", "probe-1", &a);
    return 0;
}
```

只需要包含`<sys/sdt.h>`头文件，在代码中通过`DTRACE_PROBE`宏定义USDT即可。USDT依赖`systemtap-sdt-dev`开发库，在Ubuntu系统下通过 `$ sudo apt-get install systemtap-sdt-dev` 命令安装。

编译后查看USDT信息，如下：

```bash
$ gcc usdt-hello.c -o usdt-hello
$ readelf -n usdt-hello
...
Displaying notes found in: .note.stapsdt
  Owner                Data size        Description
  stapsdt              0x00000033       NT_STAPSDT (SystemTap probe descriptors)
    Provider: "hello-usdt"
    Name: "probe-main"
    Location: 0x0000000000001164, Base: 0x0000000000002004, Semaphore: 0x0000000000000000
    Arguments: 
  stapsdt              0x00000036       NT_STAPSDT (SystemTap probe descriptors)
    Provider: "hello-usdt"
    Name: "probe-1"
    Location: 0x0000000000001170, Base: 0x0000000000002004, Semaphore: 0x0000000000000000
    Arguments: 8@%rax
```

## 6 总结

本文通过`uprobe`示例程序分析了URPOBE-PMU的内核实现过程。 `uprobe`事件在目标指令处设置断点指令，通过断点指令将执行转交给uprobes处理函数。当不需要uprobes时，目标指令会恢复成原来的样子。`uretprobes`也是在函数入口位置处使用uprobe进行插桩，在函数返回之前，使用蹦床对函数返回地址进行劫持，从而实现调用BPF程序。

除此之外，借助`usdt`示例程序，分析了USDT的实现过程。USDT是一种特殊的uprobes，通过`.note.stapsdt`段名称确定探测的位置。

## 参考资料

* [Uprobe-tracer: Uprobe-based Event Tracing](https://www.kernel.org/doc/html/latest/trace/uprobetracer.html)
* [Using user-space tracepoints with BPF](https://lwn.net/Articles/753601/)
* [Notification Chains](https://0xax.gitbook.io/linux-insides/summary/concepts/linux-cpu-4) 
* [GDB to LLDB command map](https://lldb.llvm.org/use/map.html)