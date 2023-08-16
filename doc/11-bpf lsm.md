# BPF LSM的内核实现

## 0 前言

在[第九篇](./09-fentry.md)中分析了fentry的内核实现，介绍了`fentry/fexit`, `fmod_ret`, `freplace` 4个前缀的实现过程。`fmod_ret`适用于安全领域，今天我们借助 `lsm_connect` 示例程序分析`fmod_ret`在安全领域的的使用。

## 1 简介

Linux Secrity Module简称LSM，是Linux下的一个安全框架标准，为不同的linux安全模块提供统一标准的接口。我们熟知的selinux就是基于LSM框架实现的。

LSM BPF程序允许特权用户对LSM挂钩进行运行时检测，实现系统范围的 MAC（强制访问控制）和审核策略。

## 2 `lsm_connect`示例程序

### 2.1 BPF程序

BPF程序源码参见[lsm_connect.bpf.c](../src/lsm_connect.bpf.c)，主要内容如下：

```C
SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret != 0)
        return ret;
    if (address->sa_family != AF_INET)
        return 0;

    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    __u32 dest = addr->sin_addr.s_addr;
    bpf_printk("lsm: found connect to %08x", dest);
    if (dest == blockme)
    {
        bpf_printk("lsm: blocking %08x", dest);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/sk_free_security")
void BPF_PROG(sk_free_security, struct socket *sock)
{
    // do nothing
}
```

该程序包含两个BPF程序`restrict_connect` 和 `sk_free_security`，都使用`lsm`前缀。`BPF_PROG`宏通过 `___bpf_ctx_cast(arg)` 获取参数，具体展开过程参见 [RAW TRACEPOINT的内核实现](./08-raw%20tracepoint.md) 章节。

### 2.2 用户程序

#### 1 附加BPF程序

```C
int main(int argc, char **argv)
{
    struct lsm_connect_bpf *skel;
    ...
    // 设置 libbpf 调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);
    // 打开并加载BPF程序
    skel = lsm_connect_bpf__open_and_load();
    if (!skel) { ... }
    // 附加BPF程序
    err = lsm_connect_bpf__attach(skel);
    if (err) { ... }
    // 设置`INT`处理函数
    if (signal(SIGINT, sig_int) == SIG_ERR) { ... }
    
    while (!stop) {
        fprintf(stderr, ".");
        sleep(1);
    }
cleanup:
    // 销毁BPF程序
    lsm_connect_bpf__destroy(skel);
    return -err;
}
```

#### 2 读取数据过程

`restrict_connect` BPF程序检测的网络连接，通过 `bpf_printk` 输出到 `/sys/kernel/debug/tracing/trace_pipe` 文件中。

### 2.3 编译运行

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make lsm_connect 
$ sudo ./lsm_connect 
libbpf: loading object 'lsm_connect_bpf' from buffer
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

在`lsm_connect`程序运行的过程中打开另一个bash窗口尝试访问`1.1.1.1`，如下：

```bash
$ ping 1.1.1.1
ping: connect: Operation not permitted
$ curl 1.1.1.1
curl: (7) Couldn't connect to server
$ wget 1.1.1.1
--2023-08-16 20:46:37--  http://1.1.1.1/
Connecting to 1.1.1.1:80... failed: Operation not permitted.
Retrying.
...
$ ping www.baidu.com
PING www.a.shifen.com (180.101.50.188) 56(84) bytes of data.
64 bytes from 180.101.50.188: icmp_seq=1 ttl=53 time=13.3 ms
64 bytes from 180.101.50.188: icmp_seq=2 ttl=53 time=18.1 ms
...
```

在`lsm_connect`程序运行的过程中打开另一个bash窗口查看输出结果，如下：

```bash
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-1484305 [004] d..21 305917.995820: bpf_trace_printk: lsm: found connect to 01010101
           <...>-1484305 [004] d..21 305917.995826: bpf_trace_printk: lsm: blocking 01010101
           <...>-1484462 [005] d..21 305930.523593: bpf_trace_printk: lsm: found connect to 0100007f
           <...>-1484460 [001] d..21 305931.524540: bpf_trace_printk: lsm: found connect to 0100007f
           <...>-1484508 [004] d..21 305934.733753: bpf_trace_printk: lsm: found connect to 01010101
           <...>-1484508 [004] d..21 305934.733759: bpf_trace_printk: lsm: blocking 01010101
            wget-1484508 [004] d..21 305935.734253: bpf_trace_printk: lsm: found connect to 01010101
            wget-1484508 [004] d..21 305935.734260: bpf_trace_printk: lsm: blocking 01010101
            ping-1520623 [003] d..21 310809.035075: bpf_trace_printk: lsm: found connect to 3500007f
            ping-1520623 [003] d..21 310809.052352: bpf_trace_printk: lsm: found connect to 3500007f
...
```

通过运行结果，可以看到只是限制访问`1.1.1.1`这个IP，其他IP正常访问。

## 3 附加BPF的过程

`lsm_connect.bpf.c`文件中BPF程序的SEC名称为 `SEC("lsm/socket_connect")` 。`lsm`前缀在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("lsm+",     LSM, BPF_LSM_MAC, SEC_ATTACH_BTF, attach_lsm),
    SEC_DEF("lsm.s+",   LSM, BPF_LSM_MAC, SEC_ATTACH_BTF | SEC_SLEEPABLE, attach_lsm),
    ...
};
```

`lsm` 对应的`SEC`使用 `SEC_ATTACH_BTF` 标记，表示需要BTF支持。`SEC_DEF` 宏设置了 `prog_prepare_load_fn` 接口函数，libbpf在加载BPF程序阶段调用，调用过程参见 [RAW TRACEPOINT的内核实现](./08-raw%20tracepoint.md) 章节。

### 3.1 加载阶段

在获取BTF ID时，使用`bpf_lsm_`前缀和`FUNC`类别。如下：

```C
#define BTF_LSM_PREFIX "bpf_lsm_"

// file: libbpf/src/libbpf.c
void btf_get_kernel_prefix_kind(enum bpf_attach_type attach_type, const char **prefix, int *kind)
{
    switch (attach_type) {
    ...
    case BPF_LSM_MAC:
    case BPF_LSM_CGROUP:
        *prefix = BTF_LSM_PREFIX;
        *kind = BTF_KIND_FUNC;
        break;
    ...
    }
}
```

### 3.2 附加阶段

`attach_lsm` 函数是对`bpf_program__attach_lsm` 函数的简单封装，最终调用`bpf_program__attach_btf_id`，如下：

```C
// file: libbpf/src/libbpf.c
static int attach_lsm(const struct bpf_program *prog, long cookie, struct bpf_link **link)
    --> *link = bpf_program__attach_lsm(prog);
        --> bpf_program__attach_btf_id(prog, NULL);
```

`bpf_program__attach_btf_id` 函数的使用 `BPF_LINK_CREATE` 指令或`BPF_RAW_TRACEPOINT_OPEN` 指令进行BPF系统调用，将程序附加到内核中，具体实现过程参见 [fentry的内核实现](./09-fentry.md) 章节。 

## 4 内核实现

### 4.1 security初始化过程

在`start_kernel`阶段进行`security`相关的初始化，如下：

```C
// file: init/main.c
asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
    --> ...
    --> early_security_init();
    --> ...
    --> security_init();
```

#### 1 HOOK函数

Linux内核中设置了许多安全相关的hook点，每个hook点包含一个函数声明,如下：

```C
// file：include/linux/lsm_hooks.h
union security_list_options {
    #define LSM_HOOK(RET, DEFAULT, NAME, ...) RET (*NAME)(__VA_ARGS__);
    #include "lsm_hook_defs.h"
    #undef LSM_HOOK
};
```

单个的hook点以 `struct security_hook_list` 结构表示，这些hook点通过`list`建立链表，使不同的安全引擎能同时工作。如下：

```C
// file：include/linux/lsm_hooks.h
struct security_hook_list {
    struct hlist_node		list;
    struct hlist_head		*head;
    union security_list_options	hook;
    const char			*lsm;
} __randomize_layout;
```

`lsm_hook_defs.h` 文件中定义了内核中的hook点信息，如下：

```C
// file: include/linux/lsm_hook_defs.h
LSM_HOOK(int, 0, binder_set_context_mgr, const struct cred *mgr)
LSM_HOOK(int, 0, binder_transaction, const struct cred *from, const struct cred *to)
...
```

`LSM_HOOK` 宏是LSM模块使用的结构模式，通过复用宏`LSM_HOOK`节省很多重复的代码，如下：

```C
LSM_HOOK(<return_type>, <default_value>, <hook_name>, args...)
```

#### 2 早期初始化

`early_security_init` 函数实现安全模块的早期初始化，允许在`setup_arch` 期间施加安全机制。该函数实现 `security_hook_heads` 的初始化，开启早期阶段的LSM模块。如下：

```C
// file: security/security.c
int __init early_security_init(void)
{
    struct lsm_info *lsm;

#define LSM_HOOK(RET, DEFAULT, NAME, ...) \
    INIT_HLIST_HEAD(&security_hook_heads.NAME);
#include "linux/lsm_hook_defs.h"
#undef LSM_HOOK

    for (lsm = __start_early_lsm_info; lsm < __end_early_lsm_info; lsm++) {
        if (!lsm->enabled)
            lsm->enabled = &lsm_enabled_true;
        // 准备和初始化`lsm`
        prepare_lsm(lsm);
        initialize_lsm(lsm);
    }
    return 0;
}
```

`security_hook_heads` 变量是其同名的结构，定义如下：

```C
// file: security/security.c
struct security_hook_heads security_hook_heads __lsm_ro_after_init;
```

在`vmlinux.lds.h`中定义了 `lsm_info` 和 `_early_lsm_info` 数据区域，`_early_lsm_info` 表示早期初始化阶段使用的LSM，使用 `__section(".early_lsm_info.init")` 定义； `_lsm_info` 表示初始化阶段使用的LSM，使用 `__section(".lsm_info.init")` 定义，如下：

```C
// file: include/asm-generic/vmlinux.lds.h
#ifdef CONFIG_SECURITY
#define LSM_TABLE()					\
    . = ALIGN(8);					\
    BOUNDED_SECTION_PRE_LABEL(.lsm_info.init, _lsm_info, __start, __end)
#define EARLY_LSM_TABLE()						\
    . = ALIGN(8);							\
    BOUNDED_SECTION_PRE_LABEL(.early_lsm_info.init, _early_lsm_info, __start, __end)
#else
#define LSM_TABLE()
#define EARLY_LSM_TABLE()
#endif
```

`DEFINE_EARLY_LSM` 宏定义早期阶段使用的`lsm`，`DEFINE_LSM` 宏定义初始化阶段使用的`lsm`， 如下：

```C
// file：include/linux/lsm_hooks.h
#define DEFINE_LSM(lsm)						\
    static struct lsm_info __lsm_##lsm				\
        __used __section(".lsm_info.init")			\
        __aligned(sizeof(unsigned long))

#define DEFINE_EARLY_LSM(lsm)					\
    static struct lsm_info __early_lsm_##lsm			\
        __used __section(".early_lsm_info.init")		\
        __aligned(sizeof(unsigned long))
```

早期初始化阶段使用的`lsm`只有`lockdown`，如下：

```C
// file: security/lockdown/lockdown.c
#ifdef CONFIG_SECURITY_LOCKDOWN_LSM_EARLY
DEFINE_EARLY_LSM(lockdown) = {
#else
DEFINE_LSM(lockdown) = {
#endif
    .name = "lockdown",
    .init = lockdown_lsm_init,
};
```

#### 3 初始化

`security_init`函数中初始化非早期的LSM模块，如下：

```C
// file: security/security.c
int __init security_init(void)
{
    struct lsm_info *lsm;
    for (lsm = __start_early_lsm_info; lsm < __end_early_lsm_info; lsm++) {
        if (lsm->enabled)
            // 添加到`lsm_names`中
            lsm_append(lsm->name, &lsm_names);
    }
    // 以指定的顺序加载LSM模块
    ordered_lsm_init();
    return 0;
}
```

`ordered_lsm_init` 函数将内核中的LSM模块按照指定的顺序初始化，如下：

```C
// file: security/security.c
static void __init ordered_lsm_init(void)
{
    // 分配内核使用的LSM空间
    ordered_lsms = kcalloc(LSM_COUNT + 1, sizeof(*ordered_lsms), GFP_KERNEL);

    if (chosen_lsm_order) {
        // 设置 `lsm=` 命令行参数时，取消 `security=` 命令行参数
        if (chosen_major_lsm)
            chosen_major_lsm = NULL;
        //根据`lsm=`命令行参数设置的顺序加载LSM模块
        ordered_lsm_parse(chosen_lsm_order, "cmdline");
    } else
        //根据`CONFIG_LSM`编译选项设置的顺序加载LSM模块
        ordered_lsm_parse(builtin_lsm_order, "builtin");

    // 准备LSM
    for (lsm = ordered_lsms; *lsm; lsm++)
        prepare_lsm(*lsm);

    // 打印LSM模块启动顺序
    report_lsm_order();

    // 创建 blobs 使用的 `kmem_caches`
    if (blob_sizes.lbs_file)
        lsm_file_cache = kmem_cache_create("lsm_file_cache", blob_sizes.lbs_file, 0,
                            SLAB_PANIC, NULL);
    if (blob_sizes.lbs_inode)
        lsm_inode_cache = kmem_cache_create("lsm_inode_cache", blob_sizes.lbs_inode, 0,
                            SLAB_PANIC, NULL);

    lsm_early_cred((struct cred *) current->cred);
    lsm_early_task(current);
    // 初始化LSM
    for (lsm = ordered_lsms; *lsm; lsm++)
        initialize_lsm(*lsm);

    kfree(ordered_lsms);
}
```

`LSM_COUNT` 表示`_lsm_info` 区域的大小，即：`DEFINE_LSM` 宏定义的LSM数量。其定义如下：

```C
// file: security/security.c
#define LSM_COUNT (__end_lsm_info - __start_lsm_info)
```

`ordered_lsm_parse` 函数将无序的LSM模块按照指定的配置顺序添加到`ordered_lsms`中，如下：

```C
// file: security/security.c
static void __init ordered_lsm_parse(const char *order, const char *origin)
{
    // LSM_ORDER_FIRST 总是设置在第一个
    for (lsm = __start_lsm_info; lsm < __end_lsm_info; lsm++) {
        if (lsm->order == LSM_ORDER_FIRST)
            append_ordered_lsm(lsm, "  first");
    }
    // 设置 "security=" 命令行参数时，禁用其他"LSM_FLAG_LEGACY_MAJOR"模块
    if (chosen_major_lsm) {
        struct lsm_info *major;
        for (major = __start_lsm_info; major < __end_lsm_info; major++) {
            if ((major->flags & LSM_FLAG_LEGACY_MAJOR) &&
                strcmp(major->name, chosen_major_lsm) != 0) {
                set_enabled(major, false);
            }
        }
    }
    sep = kstrdup(order, GFP_KERNEL);
    next = sep;
    // 变量列表，按名称匹配LSM模块
    while ((name = strsep(&next, ",")) != NULL) {
        bool found = false;
        for (lsm = __start_lsm_info; lsm < __end_lsm_info; lsm++) {
            if (lsm->order == LSM_ORDER_MUTABLE &&
                strcmp(lsm->name, name) == 0) {
                append_ordered_lsm(lsm, origin);
                found = true;
            }
        }
    }
    // "security=" 参数指定的LSM没有加载时，补充添加
    if (chosen_major_lsm) {
        for (lsm = __start_lsm_info; lsm < __end_lsm_info; lsm++) {
            if (exists_ordered_lsm(lsm)) continue;
            if (strcmp(lsm->name, chosen_major_lsm) == 0)
                append_ordered_lsm(lsm, "security=");
        }
    }
    // 禁用不启用的LSM模块
    for (lsm = __start_lsm_info; lsm < __end_lsm_info; lsm++) {
        if (exists_ordered_lsm(lsm)) continue;
        set_enabled(lsm, false);
    }
    kfree(sep);
}
```

#### 4 LSM初始化

LSM的初始化过程包括两个步骤：准备和初始化，每个步骤对应一个函数，如下：

`prepare_lsm` 函数实现LSM目前初始化前的准备工作，检查并设置LSM开启状态，计算blob使用的大小，如下：

```C
// file: security/security.c
static void __init prepare_lsm(struct lsm_info *lsm)
{
    // 检查是否存在独占LSM情形
    int enabled = lsm_allowed(lsm);
    set_enabled(lsm, enabled);

    if (enabled) {
        if ((lsm->flags & LSM_FLAG_EXCLUSIVE) && !exclusive) {
            // 独占LSM设置
            exclusive = lsm;
            init_debug("exclusive chosen:   %s\n", lsm->name);
        }
        // 设置blob大小
        lsm_set_blob_sizes(lsm->blobs);
    }
}
```

系统中 `lockdown`, `yama`, `loadpin` 等LSM为非独占模块，在内核中可以作为必备模块加载；`selinux`, `apparmor`, `smack` 等是独占模块，彼此排斥（即功能重复），只能设置一个。

`initialize_lsm` 函数初始化LSM模块，在开启的情况下，调用 `init` 接口。如下：

```C
// file: security/security.c
static void __init initialize_lsm(struct lsm_info *lsm)
{
    if (is_enabled(lsm)) 
        ret = lsm->init();
}
```

#### 5 计算`blob`大小

在准备LSM的过程中，调用 `lsm_set_blob_sizes` 函数计算LSM模块的偏移量和全局`blob` 大小，如下：

```C
// file: security/security.c
static void __init lsm_set_blob_sizes(struct lsm_blob_sizes *needed)
{
    if (!needed) return;
    // 计数每个参数的偏移量和总量
    lsm_set_blob_size(&needed->lbs_cred, &blob_sizes.lbs_cred);
    lsm_set_blob_size(&needed->lbs_file, &blob_sizes.lbs_file);

    if (needed->lbs_inode && blob_sizes.lbs_inode == 0)
        blob_sizes.lbs_inode = sizeof(struct rcu_head);
    lsm_set_blob_size(&needed->lbs_inode, &blob_sizes.lbs_inode);
    lsm_set_blob_size(&needed->lbs_ipc, &blob_sizes.lbs_ipc);
    lsm_set_blob_size(&needed->lbs_msg_msg, &blob_sizes.lbs_msg_msg);
    lsm_set_blob_size(&needed->lbs_superblock, &blob_sizes.lbs_superblock);
    lsm_set_blob_size(&needed->lbs_task, &blob_sizes.lbs_task);
}
```

`lsm_set_blob_size` 函数计算偏移量和总量，LSM模块中blob使用偏移量，全局设置使用总量。如下

```C
// file: security/security.c
static void __init lsm_set_blob_size(int *need, int *lbs)
{
    int offset;
    if (*need <= 0) 
        return;
    // 偏移位置(need)和总量(lbs)的计算
    offset = ALIGN(*lbs, sizeof(void *));
    *lbs = offset + *need;
    *need = offset;
}
```

在初始化`LSM`过程中，在准备阶段计算blob使用的总量后，按使用的总量分配 `lsm_file_cache` 和 `lsm_inode_cache` 内存区域。如下：

```C
// file: security/security.c
static void __init ordered_lsm_init(void)
{
    ...
    // 准备LSM
    for (lsm = ordered_lsms; *lsm; lsm++)
        prepare_lsm(*lsm);
    ...
    if (blob_sizes.lbs_file)
        lsm_file_cache = kmem_cache_create("lsm_file_cache", 
                            blob_sizes.lbs_file, 0, SLAB_PANIC, NULL);
    if (blob_sizes.lbs_inode)
        lsm_inode_cache = kmem_cache_create("lsm_inode_cache", 
                            blob_sizes.lbs_inode, 0, SLAB_PANIC, NULL);
    ...
    // 初始化LSM
    for (lsm = ordered_lsms; *lsm; lsm++)
        initialize_lsm(*lsm);
}
```

### 4.2 BPF_LSM 初始化

`bpf_lsm`模块的定义如下：

```C
// file: security/bpf/hooks.c
DEFINE_LSM(bpf) = {
    .name = "bpf",
    .init = bpf_lsm_init,
    .blobs = &bpf_lsm_blob_sizes
};
```

`.blobs` 字段表示需要的blob大小，定义如下：

```C
// file: security/bpf/hooks.c
struct lsm_blob_sizes bpf_lsm_blob_sizes __lsm_ro_after_init = {
    .lbs_inode = sizeof(struct bpf_storage_blob),
    .lbs_task = sizeof(struct bpf_storage_blob),
};
```

`.init` 字段设置了初始化函数，`bpf_lsm_init` 函数实现如下： 

```C
// file: security/bpf/hooks.c
static int __init bpf_lsm_init(void)
{
    security_add_hooks(bpf_lsm_hooks, ARRAY_SIZE(bpf_lsm_hooks), "bpf");
    pr_info("LSM support for eBPF active\n");
    return 0;
}
```

`bpf_lsm_hooks` 变量定义了`bpf_lsm`所有的hook信息，如下：

```C
// file: security/bpf/hooks.c
static struct security_hook_list bpf_lsm_hooks[] __lsm_ro_after_init = {
    #define LSM_HOOK(RET, DEFAULT, NAME, ...) \
    LSM_HOOK_INIT(NAME, bpf_lsm_##NAME),
    #include <linux/lsm_hook_defs.h>
    #undef LSM_HOOK
    LSM_HOOK_INIT(inode_free_security, bpf_inode_storage_free),
    LSM_HOOK_INIT(task_free, bpf_task_storage_free),
};
```

`LSM_HOOK_INIT` 宏设置单个hook点信息，设置`.head`和`.hook`字段。宏定义如下：

```C
// file：include/linux/lsm_hooks.h
#define LSM_HOOK_INIT(HEAD, HOOK) \
    { .head = &security_hook_heads.HEAD, .hook = { .HEAD = HOOK } }
```

`.head` 字段设置为hook点列表；`.hook` 字段为挂载点的处理函数。

在`bpf_lsm`中，`.hook` 设置为 `bpf_lsm_##NAME` ，定义如下：

```C
// file: kernel/bpf/bpf_lsm.c
#define LSM_HOOK(RET, DEFAULT, NAME, ...)	\
noinline RET bpf_lsm_##NAME(__VA_ARGS__)	\
{						\
	return DEFAULT;				\
}

#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK
```

`security_add_hooks` 函数将hook点添加到 `security_hook_heads` 结构中，如下：

```C
// file: security/security.c
void __init security_add_hooks(struct security_hook_list *hooks, int count, const char *lsm)
{
    for (i = 0; i < count; i++) {
        hooks[i].lsm = lsm;
        hlist_add_tail_rcu(&hooks[i].list, hooks[i].head);
    }
    if (slab_is_available()) {
        // 添加到`lsm_names`中
        if (lsm_append(lsm, &lsm_names) < 0)
            panic("%s - Cannot get early memory.\n", __func__);
    }
}
```

### 4.3 BPF系统调用

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

`link_create` 在检查BFP程序类型和`attr`属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。`lsm`前缀设置的程序类型为`BPF_PROG_TYPE_LSM` ，附加类型为 `BPF_LSM_MAC`, 对应 `bpf_tracing_prog_attach` 处理函数。如下：

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

`bpf_raw_tracepoint_open` 在获取设置的属性中追踪点名称后，调用 `bpf_raw_tp_link_attach` 函数，在其中检查BPF程序类型和附加类型，`lsm`前缀设置的附加类型为 `BPF_LSM_MAC`，最终调用 `bpf_tracing_prog_attach` 函数。如下：

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

实现和 `fentry` 相同，具体实现过程参见 [fentry的内核实现](./09-fentry.md) 章节。 

### 4.4 关联BPF程序

实现和 `fentry` 相同，具体实现过程参见 [fentry的内核实现](./09-fentry.md) 章节。 

在获取`trampoline`类型有所不同，`bpf_attach_type_to_tramp` 函数获取`bpf`程序使用的`trampoline`类型，如下：

```C
// file: kernel/bpf/trampoline.c
static enum bpf_tramp_prog_type bpf_attach_type_to_tramp(struct bpf_prog *prog)
{
    switch (prog->expected_attach_type) {
    ...
    case BPF_LSM_MAC:
        if (!prog->aux->attach_func_proto->type) 
            return BPF_TRAMP_FEXIT;
        else
            return BPF_TRAMP_MODIFY_RETURN;
    ...
    }
}
```

`LSM_MAC` 类型程序检查函数类型，没有返回值时使用 `TRAMP_FEXIT`，否则使用 `TRAMP_MODIFY_RETURN` 。

### 4.5 分离BPF程序

实现和 `fentry` 相同，具体实现过程参见 [fentry的内核实现](./09-fentry.md) 章节。 

### 4.6 触发过程

#### 1 有返回值的情况

以`socket_connect` 为例，使用 `security_socket_connect` 函数检查是否能够进行网络连接，如下：

```C
// file: security/security.c
int security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
    return call_int_hook(socket_connect, 0, sock, address, addrlen);
}
```

`call_int_hook` 函数遍历 `security_hook_heads.socket_connect` 列表中hook点，逐个执行 `hook.socket_connect(...)` 函数，检查返回值。返回值0，表示安全策略允许通过，继续判断下一个策略；返回值不为0，表示安全策略不允许通过，直接返回结果。如下：

```C
// file: security/security.c
#define call_int_hook(FUNC, IRC, ...) ({			\
	int RC = IRC;						\
	do {							\
		struct security_hook_list *P;			\
								\
		hlist_for_each_entry(P, &security_hook_heads.FUNC, list) { \
			RC = P->hook.FUNC(__VA_ARGS__);		\
			if (RC != 0)				\
				break;				\
		}						\
	} while (0);						\
	RC;							\
})
```

#### 2 无返回值的情况

以`sk_free` 为例，使用 `security_sk_free` 函数通知释放sock，如下：

```C
// file: security/security.c
void security_sk_free(struct sock *sk)
{
    call_void_hook(sk_free_security, sk);
}
```

`call_void_hook` 函数遍历 `security_hook_heads.sk_free_security` 列表中hook点，逐个执行 `hook.sk_free_security(...)` 函数。如下：

```C
// file: security/security.c
#define call_void_hook(FUNC, ...)				\
	do {							\
		struct security_hook_list *P;			\
								\
		hlist_for_each_entry(P, &security_hook_heads.FUNC, list) \
			P->hook.FUNC(__VA_ARGS__);		\
	} while (0)
```

### 4.7 GDB验证过程

#### 1 确认BPF LSM处于开启状态

确认Linux内核版高于5.7，`CONFIG_BPF_LSM`编译选项处于开启状态，如下：

```bash
$ cat /boot/config-$(uname -r) | grep BPF_LSM
CONFIG_BPF_LSM=y
```

在qemu中设置命令行参数 `lsm=ndlock,lockdown,yama,integrity,apparmor,bpf`，开启BPF LSM。

#### 2 有返回值的情况

以`socket_connect` 为例，BPF LSM使用的hook函数为 `bpf_lsm_socket_connect`。

##### （1） 附加BPF程序前

Linux系统启动后，通过`Ctrl-C`中断，查看如下：

```bash
(gdb) disassemble bpf_lsm_socket_connect 
Dump of assembler code for function bpf_lsm_socket_connect:
   0xffffffff81330220 <+0>:	nopl   0x0(%rax,%rax,1)
   0xffffffff81330225 <+5>:	push   %rbp
   0xffffffff81330226 <+6>:	xor    %eax,%eax
   0xffffffff81330228 <+8>:	mov    %rsp,%rbp
   0xffffffff8133022b <+11>:	pop    %rbp
   0xffffffff8133022c <+12>:	ret    
   0xffffffff8133022d <+13>:	int3   
   ...
```

`bpf_lsm_socket_connect` 函数的前5个字节为nop指令。

##### （2） 附加BPF程序后

在qemu系统中编译并运行BPF程序，如下：

```bash
$ cd build
$ cmake ../src
$ make lsm_connect 
$ sudo ./lsm_connect 
libbpf: loading object 'lsm_connect_bpf' from buffer
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
....
```

附加BPF程序后查看`bpf_lsm_socket_connect`函数反汇编代码：

```bash
Dump of assembler code for function bpf_lsm_socket_connect:
   0xffffffff81330220 <+0>:	call   0xffffffffc0230000
   0xffffffff81330225 <+5>:	push   %rbp
   0xffffffff81330226 <+6>:	xor    %eax,%eax
   0xffffffff81330228 <+8>:	mov    %rsp,%rbp
   0xffffffff8133022b <+11>:	pop    %rbp
   0xffffffff8133022c <+12>:	ret    
   0xffffffff8133022d <+13>:	int3   
   ...

(gdb) x/100i 0xffffffffc0230000
   0xffffffffc0230000:	push   %rbp
   0xffffffffc0230001:	mov    %rsp,%rbp
   0xffffffffc0230004:	sub    $0x38,%rsp
   0xffffffffc0230008:	push   %rbx
   ...
   0xffffffffc0230027:	call   0xffffffff81309b70 <__bpf_tramp_enter>
   ...
   0xffffffffc0230046:	call   0xffffffff813096a0 <__bpf_prog_enter>
   ...
   0xffffffffc0230057:	call   0xffffffffc001a768 // fmod_ret
   0xffffffffc023005c:	mov    %rax,-0x8(%rbp)    // 保存返回值，%rax
   ...
   0xffffffffc0230071:	call   0xffffffff813092d0 <__bpf_prog_exit>
   0xffffffffc0230076:	cmpq   $0x0,-0x8(%rbp)    // 判断返回值是否为0
   0xffffffffc023007b:	jne    0xffffffffc02300a0 // 不为0时跳转，否则继续执行
   0xffffffffc0230081:	mov    -0x20(%rbp),%rdi
   0xffffffffc0230085:	mov    -0x18(%rbp),%rsi
   0xffffffffc0230089:	mov    -0x10(%rbp),%edx
   0xffffffffc023008c:	call   0xffffffff81330225 <bpf_lsm_socket_connect+5>
   0xffffffffc0230091:	mov    %rax,-0x8(%rbp)    // 保存返回值，%rax
   0xffffffffc0230095:	nopl   0x0(%rax,%rax,1)
   0xffffffffc023009a:	nopw   0x0(%rax,%rax,1)
   0xffffffffc02300a0:	movabs $0xffff8881092fe400,%rdi
   0xffffffffc02300aa:	call   0xffffffff81309bd0 <__bpf_tramp_exit>
   0xffffffffc02300af:	mov    -0x8(%rbp),%rax    // 恢复返回值，%rax
   0xffffffffc02300b3:	pop    %rbx
   0xffffffffc02300b4:	leave  
   0xffffffffc02300b5:	add    $0x8,%rsp
   0xffffffffc02300b9:	ret    
   0xffffffffc02300ba:	int3
   ...   
```

在 `bpf_lsm_socket_connect` 函数前执行`mod_ret`设置的BPF程序，判断返回值是否为0。为0时，继续执行 `bpf_lsm_socket_connect` 函数，否则跳过。

##### （3） 清理BPF程序后

在qemu中退出`lsm_connect`程序后，查看`bpf_lsm_socket_connect` 的反汇编代码，重新设置为nop指令，如下：

```bash
(gdb) disassemble bpf_lsm_socket_connect 
Dump of assembler code for function bpf_lsm_socket_connect:
   0xffffffff81330220 <+0>:	nopl   0x0(%rax,%rax,1)
   0xffffffff81330225 <+5>:	push   %rbp
   0xffffffff81330226 <+6>:	xor    %eax,%eax
   0xffffffff81330228 <+8>:	mov    %rsp,%rbp
   0xffffffff8133022b <+11>:	pop    %rbp
   0xffffffff8133022c <+12>:	ret    
   0xffffffff8133022d <+13>:	int3   
   ...
```

#### 3 无返回值的情况

以`sk_free` 为例，BPF LSM使用的hook函数为 `bpf_lsm_sk_free_security`。

##### （1） 附加BPF程序前

Linux系统启动后，通过`Ctrl-C`中断，查看如下：

```bash
(gdb) disassemble bpf_lsm_sk_free_security 
Dump of assembler code for function bpf_lsm_sk_free_security:
   0xffffffff813304c0 <+0>:	nopl   0x0(%rax,%rax,1)
   0xffffffff813304c5 <+5>:	push   %rbp
   0xffffffff813304c6 <+6>:	mov    %rsp,%rbp
   0xffffffff813304c9 <+9>:	pop    %rbp
   0xffffffff813304ca <+10>:	ret    
   0xffffffff813304cb <+11>:	int3   
   ...
```

##### （2） 附加BPF程序后

在qemu系统中编译并运行BPF程序。附加BPF程序后查看`bpf_lsm_sk_free_security`函数反汇编代码：

```bash
(gdb) disassemble bpf_lsm_sk_free_security 
Dump of assembler code for function bpf_lsm_sk_free_security:
   0xffffffff813304c0 <+0>:	call   0xffffffffc0232000
   0xffffffff813304c5 <+5>:	push   %rbp
   0xffffffff813304c6 <+6>:	mov    %rsp,%rbp
   0xffffffff813304c9 <+9>:	pop    %rbp
   0xffffffff813304ca <+10>:	ret    
   0xffffffff813304cb <+11>:	int3   
   ...

(gdb) x/100i 0xffffffffc0232000
   0xffffffffc0232000:	push   %rbp
   0xffffffffc0232001:	mov    %rsp,%rbp
   0xffffffffc0232004:	sub    $0x28,%rsp
   0xffffffffc0232008:	push   %rbx
   0xffffffffc0232009:	mov    $0x1,%eax
   ...
   0xffffffffc0232020:	call   0xffffffff81309b70 <__bpf_tramp_enter>
   0xffffffffc0232025:	mov    -0x10(%rbp),%rdi
   0xffffffffc0232029:	call   0xffffffff813304c5 <bpf_lsm_sk_free_security+5>
   0xffffffffc023202e:	mov    %rax,-0x8(%rbp)
   ...
   0xffffffffc023204b:	call   0xffffffff813096a0 <__bpf_prog_enter>
   ...
   0xffffffffc023205c:	call   0xffffffffc001a814 // fexit
   ...
   0xffffffffc0232072:	call   0xffffffff813092d0 <__bpf_prog_exit>
   0xffffffffc0232077:	movabs $0xffff888103266400,%rdi
   0xffffffffc0232081:	call   0xffffffff81309bd0 <__bpf_tramp_exit>
   0xffffffffc0232086:	mov    -0x8(%rbp),%rax
   0xffffffffc023208a:	pop    %rbx
   0xffffffffc023208b:	leave  
   0xffffffffc023208c:	add    $0x8,%rsp
   0xffffffffc0232090:	ret    
   0xffffffffc0232091:	int3    
   ...
```

在 `bpf_lsm_sk_free_security` 函数后执行`fexit`设置的BPF程序。

##### （3） 清理BPF程序后

在qemu中退出`lsm_connect`程序后，查看`bpf_lsm_sk_free_security` 的反汇编代码，重新设置为nop指令，如下：

```bash
(gdb) disassemble bpf_lsm_sk_free_security 
Dump of assembler code for function bpf_lsm_sk_free_security:
   0xffffffff813304c0 <+0>:	nopl   0x0(%rax,%rax,1)
   0xffffffff813304c5 <+5>:	push   %rbp
   0xffffffff813304c6 <+6>:	mov    %rsp,%rbp
   0xffffffff813304c9 <+9>:	pop    %rbp
   0xffffffff813304ca <+10>:	ret    
   0xffffffff813304cb <+11>:	int3  
   ...
```

## 5 总结

本文通过`lsm_connect`示例程序分析了`BPF LSM`的内核实现过程。

在过去，使用LSM主要通过配置已有的安全模块（如 SELinux 和 AppArmor）或编写自己的内核模块。在 Linux 5.7引入BPF LSM后，开发人员可以通过 eBPF 编写自定义的安全策略，并将其动态加载到内核中的LSM挂载点。

## 参考资料

* [Introduce BPF_MODIFY_RET tracing progs.](https://lwn.net/Articles/813724/)
* [MAC and Audit policy using eBPF (KRSI)](https://lwn.net/Articles/807865/)
* [LSM BPF Programs](https://docs.kernel.org/bpf/prog_lsm.html)