# BREAKPOINT-PMU的内核实现

## 0 前言

在[inux性能计数器在内核的实现](02-Performance%20Counters%20for%20Linux.md)中，我们分析了 perf_events 的实现过程，简单介绍了PMU的注册过程。今天我们基于`data_breakpoint`程序分析BREAKPOINT-PMU的实现过程。

## 1 简介

在使用GDB调试程序的过程中，GDB提供了观察点(watchpoint)功能，可以监控程序中变量或表达式的值，只要在运行过程中发生改变，程序就会停止执行，能够实现让bug自动现身的效果。观察点(watchpoint)时基于内核中`BREAKPOINT`实现的。

## 2 data_breakpoint程序

`data_breakpoint`程序基于`profile`程序，BPF程序实现相同，获取调用堆栈。

### 2.1 BPF程序

BPF程序的源码参见[data_breakpoint.bpf.c](../src/data_breakpoint.bpf.c)，主要内容如下：

```C
// file: src/data_breakpoint.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("perf_event")
int profile(void *ctx)
{
    struct stacktrace_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 1;

    event->pid = bpf_get_current_pid_tgid() >> 32;;
    event->cpu_id = bpf_get_smp_processor_id();;
    if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
        event->comm[0] = 0;
    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);
    event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

该程序包含了一个名称为`events`的map（类型为`BPF_MAP_TYPE_RINGBUF`，大小256KiB）和 名称为`profile`的BPF程序（节名称为"perf_event"）。`profile` 程序采集pid、cpu_id、程序名称（comm）、内核栈和用户栈信息后提交到 `events` 的map中。

### 2.2 用户程序

用户程序的源码参见[data_breakpoint.c](../src/data_breakpoint.c)，主要功能如下：

#### 1 附加BPF过程

```C
int main(int argc, char *const argv[])
{
    const char *online_cpus_file = "/sys/devices/system/cpu/online";
    int pid = -1, cpu, bp_len = 1, bp_type = HW_BREAKPOINT_W;
	uint64_t bp_addr = 0;
    int num_cpus, num_online_cpus;
    bool *online_mask = NULL;
    
    // 获取在线的CPU信息
    err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
    // 获取CPU数量
    num_cpus = libbpf_num_possible_cpus();
    // 打开并加载bpf程序
    skel = data_breakpoint_bpf__open_and_load();

    // 设置计数器属性--断点事件
    links = calloc(num_cpus, sizeof(struct bpf_link *));
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.pinned = 1;
    attr.sample_period = 1;
    attr.bp_addr = bp_addr;
    attr.bp_len = bp_len;
    attr.bp_type = bp_type;

    for (cpu = 0; cpu < num_cpus; cpu++) {
        // 跳过离线的CPU
        if (cpu >= num_online_cpus || !online_mask[cpu])
            continue;
        // 在CPU上设置性能计数器
        pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        ...
        pefds[cpu] = pefd;
        // 附加BPF程序到CPU上
        links[cpu] = bpf_program__attach_perf_event(skel->progs.profile, pefd);
    	...
    }
    ...
}
```

用户空间程序在每个在线的CPU上都开启了性能计数器，并附加了BPF程序。perf_event设置断点的地址、长度和类型。

#### 2 读取map数据过程

```C
int main(int argc, char *const argv[])
{
    struct ring_buffer *ring_buf = NULL;
    ...
    // 创建ring_buffer
    ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);
    ...
    // 使用poll读取数据
    while (ring_buffer__poll(ring_buf, -1) >= 0) {
    }
    ...
}

static int event_handler(void *_ctx, void *data, size_t size)
{
    struct stacktrace_event *event = data;
    if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
        return 1;
    printf("Time:%ld, COMM: %s (pid=%d) @ CPU %d\n", time(NULL), event->comm, event->pid, event->cpu_id);
    if (event->kstack_sz > 0) {
        printf("Kernel:\n");
        show_stack_trace(event->kstack, event->kstack_sz / sizeof(__u64), 0);
    } else {
        printf("No Kernel Stack\n");
    }
    if (event->ustack_sz > 0) {
        printf("Userspace:\n");
        show_stack_trace(event->ustack, event->ustack_sz / sizeof(__u64), event->pid);
    } else {
        printf("No Userspace Stack\n");
    }
    printf("\n");
    return 0;
}
```

创建`ring_buffer`时关联map和回调函数。在附加BPF程序后，通过poll方式检查`ring_buffer`是否有数据。有数据时调用回调函数 `event_handler` 打印程序名称、pid、CPU、内核栈、用户栈信息。

### 2.3 编译运行程序

在内核执行`do_unlinkat`时触发，首先获取`do_unlinkat`的函数地址，如下：

```bash
sudo cat /proc/kallsyms | grep do_unlinkat
ffffffffa6496d40 T __pfx_do_unlinkat
ffffffffa6496d50 T do_unlinkat
```

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make data_breakpoint
$ sudo ./data_breakpoint -a ffffffffa6496d50 -l 8 -t 4
addr:0XFFFFFFFFA6496D50, len:8, type:X
libbpf: loading object 'data_breakpoint_bpf' from buffer
...
Time:1705763457, COMM: systemd-journal (pid=266) @ CPU 2
Kernel:
  0 [<ffffffffa6496d50>] do_unlinkat+0x0
  1 [<ffffffffa70921ac>] do_syscall_64+0x5c
  2 [<ffffffffa72000eb>] entry_SYSCALL_64_after_hwframe+0x73
Userspace:
  0 [<00007fbe78d15ebb>] unlink+0x7fbe78c0000b
  1 [<0000003700000007>]
  2 [<0000000300000006>]
...
```

在内核修改`jiffies`变量时触发，获取`jiffies`的变量地址，如下：

```bash
sudo cat /proc/kallsyms | grep jiffies
...
ffffffffa82079c0 D jiffies
ffffffffa82079c0 D jiffies_64
...
```

运行程序，如下：

```bash
$ sudo ./data_breakpoint -a ffffffffa82079c0 
addr:0XFFFFFFFFA82079C0, len:1, type:W
libbpf: loading object 'data_breakpoint_bpf' from buffer
...
Time:1705764152, COMM: swapper/0 (pid=0) @ CPU 0
Kernel:
  0 [<ffffffffa61eee20>] tick_do_update_jiffies64+0x70
  1 [<ffffffffa61eefcb>] tick_sched_do_timer+0x9b
  2 [<ffffffffa61ef00d>] tick_sched_timer+0x2d
  3 [<ffffffffa61d8287>] __hrtimer_run_queues+0x107
  4 [<ffffffffa61d8e21>] hrtimer_interrupt+0x101
  5 [<ffffffffa609cd74>] __sysvec_apic_timer_interrupt+0x64
  6 [<ffffffffa7096bf1>] sysvec_apic_timer_interrupt+0x91
  7 [<ffffffffa7200f0b>] asm_sysvec_apic_timer_interrupt+0x1b
  8 [<ffffffffa6d1b32e>] cpuidle_enter_state+0xde
  9 [<ffffffffa6d1b9be>] cpuidle_enter+0x2e
  10 [<ffffffffa615c4cf>] cpuidle_idle_call+0x14f
  11 [<ffffffffa615c5f2>] do_idle+0x82
  12 [<ffffffffa615c890>] cpu_startup_entry+0x20
  13 [<ffffffffa70983a5>] rest_init+0xe5
  14 [<ffffffffa866300e>] arch_call_rest_init+0xe
  15 [<ffffffffa8663455>] start_kernel+0x3b5
  16 [<ffffffffa86618b2>] x86_64_start_kernel+0x102
  17 [<ffffffffa600015a>] secondary_startup_64_no_verify+0xe5
No Userspace Stack
...
```

## 3 内核实现

### 3.1 PMU注册过程

Linux内核中断点长度支持1~8字节，支持在读取、写入、执行时触发，如下

```C
// file: include/uapi/linux/hw_breakpoint.h
enum {
	HW_BREAKPOINT_LEN_1 = 1,
	HW_BREAKPOINT_LEN_2 = 2,
	HW_BREAKPOINT_LEN_3 = 3,
	HW_BREAKPOINT_LEN_4 = 4,
	HW_BREAKPOINT_LEN_5 = 5,
	HW_BREAKPOINT_LEN_6 = 6,
	HW_BREAKPOINT_LEN_7 = 7,
	HW_BREAKPOINT_LEN_8 = 8,
};
enum {
	HW_BREAKPOINT_EMPTY	= 0,
	HW_BREAKPOINT_R		= 1,
	HW_BREAKPOINT_W		= 2,
	HW_BREAKPOINT_RW	= HW_BREAKPOINT_R | HW_BREAKPOINT_W,
	HW_BREAKPOINT_X		= 4,
	HW_BREAKPOINT_INVALID   = HW_BREAKPOINT_RW | HW_BREAKPOINT_X,
};
```

断点的pmu中在初始化过程中注册，如下：

```C
// file: kernel/events/core.c
void __init perf_event_init(void)
    // 初始化断点
    --> ret = init_hw_breakpoint();
```

`init_hw_breakpoint`函数初始化断点相关的操作，如下：

```C
// file: kernel/events/hw_breakpoint.c
int __init init_hw_breakpoint(void)
{
    int ret;
    // 初始化约束表(hashlist)
    ret = rhltable_init(&task_bps_ht, &task_bps_ht_params);
    if (ret) return ret;
    // 初始化动态断点槽
    ret = init_breakpoint_slots();
    if (ret) return ret;

    constraints_initialized = true;
    // 注册PMU
    perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
    // 注册断点通知链
    return register_die_notifier(&hw_breakpoint_exceptions_nb);
}
```

断点分为指令(`INST`)和数据(`DATA`)两种类型，如下：

```C
// file: include/uapi/linux/hw_breakpoint.h
enum bp_type_idx {
	TYPE_INST 	= 0,
#ifdef CONFIG_HAVE_MIXED_BREAKPOINTS_REGS
	TYPE_DATA	= 0,
#else
	TYPE_DATA	= 1,
#endif
	TYPE_MAX
};
```

`__nr_bp_slots`变量存放这两种类型的数量，如下：

```C
// file: kernel/events/hw_breakpoint.c
static int __nr_bp_slots[TYPE_MAX] __ro_after_init;
```

在`init_breakpoint_slots`中初始化，如下：

```C
// file: kernel/events/hw_breakpoint.c
static __init int init_breakpoint_slots(void)
{
    int i, cpu, err_cpu;
    for (i = 0; i < TYPE_MAX; i++)
        __nr_bp_slots[i] = hw_breakpoint_slots(i);

    for_each_possible_cpu(cpu) {
        // 初始化per-CPU断点数量
        for (i = 0; i < TYPE_MAX; i++) {
            struct bp_cpuinfo *info = get_bp_info(cpu, i);
            if (!bp_slots_histogram_alloc(&info->tsk_pinned, i)) goto err;
        }
    }
    for (i = 0; i < TYPE_MAX; i++) {
        // 初始化关联全局CPU的断点数量
        if (!bp_slots_histogram_alloc(&cpu_pinned[i], i)) goto err;
        // 初始化与CPU无关的固定任务断点数
        if (!bp_slots_histogram_alloc(&tsk_pinned_all[i], i)) goto err;
    }
    return 0;
err:
    ...
}
```

`hw_breakpoint_slots`表示断点的数量，`x86`架构支持4个断点，如下：

```C
// file: arch/x86/include/asm/hw_breakpoint.h
/* Total number of available HW breakpoint registers */
#define HBP_NUM 4
#define hw_breakpoint_slots(type) (HBP_NUM)
```

在`x86`架构下，`DR0 - DR3`这4个寄存器表示断点的地址；`DR6`寄存器表示调试寄存器的状态；`DR7`寄存器用于选择性地启用四个地址断点条件并指定四个断点中每个断点的类型和大小。

### 3.2 BREAKPOINT-PMU的操作接口

断点的PUM结构定义为`perf_breakpoint` ，如下：

```C
// file: kernel/events/hw_breakpoint.c
static struct pmu perf_breakpoint = {
    .task_ctx_nr    = perf_sw_context, /* could eventually get its own */
    .event_init	= hw_breakpoint_event_init,
    .add        = hw_breakpoint_add,
    .del        = hw_breakpoint_del,
    .start      = hw_breakpoint_start,
    .stop       = hw_breakpoint_stop,
    .read       = hw_breakpoint_pmu_read,
};
```

`perf_breakpoint` 只提供了初始化、开启/停止、添加/删除、读取等基本的操作接口。


#### 1 初始化 -- `hw_breakpoint_event_init`

`perf_breakpoint`的初始化接口(`.event_init`)设置为 `hw_breakpoint_event_init`，实现过程如下：

```C
// file: kernel/events/hw_breakpoint.c
static int hw_breakpoint_event_init(struct perf_event *bp)
{
    int err;
    // 类型检查
    if (bp->attr.type != PERF_TYPE_BREAKPOINT)  return -ENOENT;
    // 不支持分支栈采样
    if (has_branch_stack(bp)) return -EOPNOTSUPP;
    // 注册断点
    err = register_perf_hw_breakpoint(bp);
    if (err) return err;
    // 设置销毁接口
    bp->destroy = bp_perf_event_destroy;
    return 0;
}
```

`register_perf_hw_breakpoint` 函数注册断点，实现过程如下：

```C
// file: kernel/events/hw_breakpoint.c
int register_perf_hw_breakpoint(struct perf_event *bp)
{
    struct arch_hw_breakpoint hw = { };
    int err;
    // 预留断点槽
    err = reserve_bp_slot(bp);
    if (err) return err;
    // 解析断点
    err = hw_breakpoint_parse(bp, &bp->attr, &hw);
    if (err) {
        release_bp_slot(bp);
        return err;
    }
    bp->hw.info = hw;
    return 0;
}
```

##### (1) 断点约束检查

`reserve_bp_slot`函数时对`__reserve_bp_slot`函数的封装，后者对注册的断点计数器约束检查，主要检查断点的数量。如下：

```C
// file: kernel/events/hw_breakpoint.c
int reserve_bp_slot(struct perf_event *bp)
{
    // 获取互斥锁
    struct mutex *mtx = bp_constraints_lock(bp);
    int ret = __reserve_bp_slot(bp, bp->attr.bp_type);
    bp_constraints_unlock(mtx);
    return ret;
}
static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
{
    enum bp_type_idx type;
    int max_pinned_slots;
    int weight;
    int ret;
    // 在启动阶段未能初始化断点约束条件时，返回错误
    if (!constraints_initialized) return -ENOMEM;
    // 基本的类型检查
    if (bp_type == HW_BREAKPOINT_EMPTY || bp_type == HW_BREAKPOINT_INVALID)
        return -EINVAL;
    // 断点类型， RW时表示DATA，其他为INST
    type = find_slot_idx(bp_type);
    weight = hw_breakpoint_weight(bp);
    // 检查指定的CPU(cpu > -1)或所有的CPU(cpu = -1)的关联的断点槽
    max_pinned_slots = max_bp_pinned_slots(bp, type) + weight;
    // 超过断点槽限制时，返回错误
    if (max_pinned_slots > hw_breakpoint_slots_cached(type))
        return -ENOSPC;
    // CPU架构相关
    ret = arch_reserve_bp_slot(bp);
    if (ret) return ret;
    // 添加断点到约束表中
    return toggle_bp_slot(bp, true, type, weight);
}
```

##### (2) 验证断点

`hw_breakpoint_parse` 函数解析设置的断点信息，检查断点的长度和类型，如下：

```C
// file: kernel/events/hw_breakpoint.c
static int hw_breakpoint_parse(struct perf_event *bp, 
            const struct perf_event_attr *attr, struct arch_hw_breakpoint *hw)
{
    int err;
    // 验证断点
    err = hw_breakpoint_arch_parse(bp, attr, hw);
    if (err) return err;
    // 内核空间断点检查
    if (arch_check_bp_in_kernelspace(hw)) {
        if (attr->exclude_kernel) return -EINVAL;
        if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    }
    return 0;
}
```

在`x86`架构下，`hw_breakpoint_arch_parse`定义如下：

```C
// file: arch/x86/kernel/hw_breakpoint.c
int hw_breakpoint_arch_parse(struct perf_event *bp,
        const struct perf_event_attr *attr, struct arch_hw_breakpoint *hw)
{
    unsigned int align;
    int ret;
    ret = arch_build_bp_info(bp, attr, hw);
    if (ret) return ret;

    // 获取对齐
    switch (hw->len) {
    case X86_BREAKPOINT_LEN_1: align = 0; if (hw->mask) align = hw->mask; break;
    case X86_BREAKPOINT_LEN_2: align = 1; break;
    case X86_BREAKPOINT_LEN_4: align = 3; break;
#ifdef CONFIG_X86_64
    case X86_BREAKPOINT_LEN_8: align = 7; break;
#endif
    default: WARN_ON_ONCE(1); return -EINVAL;
    }
    // 检查地址的低位是否和`len`对齐
    if (hw->address & align) return -EINVAL;
    return 0;
}
```

`arch_build_bp_info`函数构建断点信息，转换为平台相关的断点信息，如下：

```C
// file: arch/x86/kernel/hw_breakpoint.c
static int arch_build_bp_info(struct perf_event *bp,
            const struct perf_event_attr *attr, struct arch_hw_breakpoint *hw)
{
    unsigned long bp_end;
    // 检查断点地址的结束位置
    bp_end = attr->bp_addr + attr->bp_len - 1;
    if (bp_end < attr->bp_addr) return -EINVAL;
    // 不能在CPU入口区域和数据区域设置断点
    if (within_cpu_entry(attr->bp_addr, bp_end)) return -EINVAL;
    // 设置到hw结构中
    hw->address = attr->bp_addr;
    hw->mask = 0;
    // 断点类型装换
    switch (attr->bp_type) {
    case HW_BREAKPOINT_W: hw->type = X86_BREAKPOINT_WRITE; break;
    case HW_BREAKPOINT_W | HW_BREAKPOINT_R: hw->type = X86_BREAKPOINT_RW; break;
    case HW_BREAKPOINT_X:
        // 地址为内核空间时，不能在kprobe的黑名单上设置断点
        if (attr->bp_addr >= TASK_SIZE_MAX) {
            if (within_kprobe_blacklist(attr->bp_addr)) return -EINVAL;
        }
        // 执行类型设置
        hw->type = X86_BREAKPOINT_EXECUTE;
        // 设置长度为long时，转换为`X86_BREAKPOINT_LEN_X`
        if (attr->bp_len == sizeof(long)) {
            hw->len = X86_BREAKPOINT_LEN_X;
            return 0;
        }
        fallthrough;
    default:
        return -EINVAL;
    }
    // 长度转换
    switch (attr->bp_len) {
    case HW_BREAKPOINT_LEN_1: hw->len = X86_BREAKPOINT_LEN_1; break;
    case HW_BREAKPOINT_LEN_2: hw->len = X86_BREAKPOINT_LEN_2; break;
    case HW_BREAKPOINT_LEN_4: hw->len = X86_BREAKPOINT_LEN_4; break;
#ifdef CONFIG_X86_64
    case HW_BREAKPOINT_LEN_8: hw->len = X86_BREAKPOINT_LEN_8; break;
#endif
    default:
        // AMD支持断点范围设置
        if (!is_power_of_2(attr->bp_len)) return -EINVAL;
        if (attr->bp_addr & (attr->bp_len - 1)) return -EINVAL;
        if (!boot_cpu_has(X86_FEATURE_BPEXT)) return -EOPNOTSUPP;
        // 其他长度通过掩码设置
        hw->mask = attr->bp_len - 1;
        hw->len = X86_BREAKPOINT_LEN_1;
    }
    return 0;
}
```

`arch_check_bp_in_kernelspace`函数检查断点地址是否为内核空间，实现如下：

```C
// file: arch/x86/kernel/hw_breakpoint.c
int arch_check_bp_in_kernelspace(struct arch_hw_breakpoint *hw)
{
    unsigned long va;
    int len;
    va = hw->address;
    len = arch_bp_generic_len(hw->len);
    WARN_ON_ONCE(len < 0);
    // 判读断点区域是否在内核空间
    return (va >= TASK_SIZE_MAX) || ((va + len - 1) >= TASK_SIZE_MAX);
}
```

`TASK_SIZE_MAX`表示用户空间大小，定义如下：

```C
// file: arch/x86/include/asm/page_64_types.h
#define TASK_SIZE_MAX		task_size_max()

#ifdef CONFIG_X86_5LEVEL
#define __VIRTUAL_MASK_SHIFT	(pgtable_l5_enabled() ? 56 : 47)
/* See task_size_max() in <asm/page_64.h> */
#else
#define __VIRTUAL_MASK_SHIFT	47
#define task_size_max()		((_AC(1,UL) << __VIRTUAL_MASK_SHIFT) - PAGE_SIZE)
#endif
```

`task_size_max()`表示能够访问的虚拟空间大小。

#### 2 添加 -- `hw_breakpoint_add`

`perf_breakpoint`的添加接口(`.add`)设置为 `perf_swevent_add`，实现过程如下：

```C
// file: kernel/events/hw_breakpoint.c
static int hw_breakpoint_add(struct perf_event *bp, int flags)
{
    // 没有设置开启(START)标志时，设置为停止状态
    if (!(flags & PERF_EF_START)) bp->hw.state = PERF_HES_STOPPED;
    // 周期采样时设置事件的采样周期
    if (is_sampling_event(bp)) {
        bp->hw.last_period = bp->hw.sample_period;
        perf_swevent_set_period(bp);
    }
    // 平台安装断点
    return arch_install_hw_breakpoint(bp);
}
```

在`x86`架构下实现如下：

```C
// file: arch/x86/kernel/hw_breakpoint.c
int arch_install_hw_breakpoint(struct perf_event *bp)
{
    // 获取平台相关的断点
    struct arch_hw_breakpoint *info = counter_arch_bp(bp);
    unsigned long *dr7;
    int i;

    lockdep_assert_irqs_disabled();
    // 遍历`bp_per_reg`列表，查找空闲区域
    for (i = 0; i < HBP_NUM; i++) {
        struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
        if (!*slot) { *slot = bp; break; }
    }
    // 无可用的断点槽时，提示错误
    if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
        return -EBUSY;
    // 设置断点地址
    set_debugreg(info->address, i);
    __this_cpu_write(cpu_debugreg[i], info->address);
    // 设置dr7寄存器的值
    dr7 = this_cpu_ptr(&cpu_dr7);
    *dr7 |= encode_dr7(i, info->len, info->type);

    barrier();
    // 设置dr7寄存器
    set_debugreg(*dr7, 7);
    // AMD设置地址掩码
    if (info->mask) amd_set_dr_addr_mask(info->mask, i);
    return 0;
}
```

`encode_dr7`函数对特定断点的长度、类型、启用位进行编码，实现如下：

```C
// file: arch/x86/kernel/hw_breakpoint.c
unsigned long encode_dr7(int drnum, unsigned int len, unsigned int type)
{
    return __encode_dr7(drnum, len, type) | DR_GLOBAL_SLOWDOWN;
}
static inline unsigned long
__encode_dr7(int drnum, unsigned int len, unsigned int type)
{
    unsigned long bp_info;
    bp_info = (len | type) & 0xf;
    bp_info <<= (DR_CONTROL_SHIFT + drnum * DR_CONTROL_SIZE);
    bp_info |= (DR_GLOBAL_ENABLE << (drnum * DR_ENABLE_SIZE));
    return bp_info;
}
```

#### 3 删除 -- `hw_breakpoint_del`

`perf_breakpoint`的删除接口(`.del`)设置为 `hw_breakpoint_del`，实现过程如下：

```C
// file: kernel/events/core.c
static void hw_breakpoint_del(struct perf_event *bp, int flags)
{
    // 平台卸载断点
    arch_uninstall_hw_breakpoint(bp);
}
```

在`x86`架构下实现如下：

```C
// file: arch/x86/kernel/hw_breakpoint.c
void arch_uninstall_hw_breakpoint(struct perf_event *bp)
{
    struct arch_hw_breakpoint *info = counter_arch_bp(bp);
    unsigned long dr7;
    int i;

    lockdep_assert_irqs_disabled();
    // 遍历`bp_per_reg`列表，查找指定的bp
    for (i = 0; i < HBP_NUM; i++) {
        struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
        if (*slot == bp) { *slot = NULL; break; }
    }
    // 不存在时提示错误
    if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot")) return;

    // 读取`%dr7`寄存器之后，清除标记
    dr7 = this_cpu_read(cpu_dr7);
    dr7 &= ~__encode_dr7(i, info->len, info->type);
    // 设置dr7寄存器
    set_debugreg(dr7, 7);
    if (info->mask) amd_set_dr_addr_mask(0, i);

    barrier();
    // 当前CPU设置`dr7`值
    this_cpu_write(cpu_dr7, dr7);
}
```

#### 4 开始 -- `hw_breakpoint_start`

`perf_breakpoint`的删除接口(`.start`)设置为 `hw_breakpoint_start`，实现过程如下：

```C
// file: kernel/events/hw_breakpoint.c
static void hw_breakpoint_start(struct perf_event *event, int flags)
{
    // 设置开始状态
    bp->hw.state = 0;
}
```

#### 5 停止 -- `hw_breakpoint_stop`

`perf_breakpoint`的删除接口(`.start`)设置为 `hw_breakpoint_stop`，实现过程如下：

```C
// file: kernel/events/hw_breakpoint.c
static void hw_breakpoint_stop(struct perf_event *bp, int flags)
{
    // 设置停止状态
    bp->hw.state = PERF_HES_STOPPED;
}
```

#### 6 销毁 -- `bp_perf_event_destroy`

`perf_breakpoint`的销毁接口设置为 `bp->destroy = bp_perf_event_destroy`，实现过程如下：

```C
// file: kernel/events/hw_breakpoint.c
static void bp_perf_event_destroy(struct perf_event *event)
{
    release_bp_slot(event);
}
```

`release_bp_slot`函数释放断点槽，如下：

```C
// file: kernel/events/hw_breakpoint.c
void release_bp_slot(struct perf_event *bp)
{
    struct mutex *mtx = bp_constraints_lock(bp);
    // 平台注销断点
    arch_unregister_hw_breakpoint(bp);
    // 释放断点槽
    __release_bp_slot(bp, bp->attr.bp_type);
    bp_constraints_unlock(mtx);
}
```

`__release_bp_slot`函数释放断点槽，如下

```C
// file: kernel/events/hw_breakpoint.c
static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
{
    enum bp_type_idx type;
    int weight;
    arch_release_bp_slot(bp);
    // 获取类型和权重
    type = find_slot_idx(bp_type);
    weight = hw_breakpoint_weight(bp);
    // 从约束表中删除断点
    WARN_ON(toggle_bp_slot(bp, false, type, weight));
}
```

### 3.3 事件触发的方式

#### 1 DB中断

CPU在触发断点地址时触发DB中断，设置如下：

```C
// file: arch/x86/kernel/idt.c
static const __initconst struct idt_data def_idts[] = {
    ...
    // DB陷阱门设置
    ISTG(X86_TRAP_DB,   asm_exc_debug, IST_INDEX_DB),
    ...
};
```

`DECLARE_IDTENTRY_DEBUG`宏声明定义`exc_debug`，如下：

```C
// file: arch/x86/include/asm/idtentry.h
#ifdef CONFIG_X86_64
DECLARE_IDTENTRY_DEBUG(X86_TRAP_DB,	exc_debug);
#else
DECLARE_IDTENTRY_RAW(X86_TRAP_DB,	exc_debug);
#endif
```

以`x86-64`为例，`DECLARE_IDTENTRY_DEBUG`宏定义如下：

```C
# define DECLARE_IDTENTRY_DEBUG(vector, func)				\
	idtentry_mce_db vector asm_##func func
```

`idtentry_mce_db`宏定义MEC和DB的中断处理函数，如下：

```C
// file: arch/x86/entry/entry_64.S
.macro idtentry_mce_db vector asmsym cfunc
SYM_CODE_START(\asmsym)
    --> ...
    --> call    \cfunc
    --> ...
```

`exc_debug`函数定义如下：

```C
// file: arch/x86/kernel/traps.c
/* IST stack entry */
DEFINE_IDTENTRY_DEBUG(exc_debug)
{
    exc_debug_kernel(regs, debug_read_clear_dr6());
}
/* User entry, runs on regular task stack */
DEFINE_IDTENTRY_DEBUG_USER(exc_debug)
{
    exc_debug_user(regs, debug_read_clear_dr6());
}
```

内核空间调试中断处理程序实现如下：

```C
// file: arch/x86/kernel/traps.c
static __always_inline void exc_debug_kernel(struct pt_regs *regs, unsigned long dr6)
{
    // 获取`%dr7`寄存器
    unsigned long dr7 = local_db_save();
    irqentry_state_t irq_state = irqentry_nmi_enter(regs);
    instrumentation_begin();
    // 用户空间地址时提示
    WARN_ON_ONCE(user_mode(regs));

    if (test_thread_flag(TIF_BLOCKSTEP)) {
        // 重置分支下单步状态
        unsigned long debugctl;
        rdmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
        debugctl |= DEBUGCTLMSR_BTF;
        wrmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
    }
    // 清除单步调试状态
    if ((dr6 & DR_STEP) && is_sysenter_singlestep(regs))
        dr6 &= ~DR_STEP;
    if (!dr6) goto out;
    // 通知调试状态
    if (notify_debug(regs, &dr6)) goto out;
    // 清除`TF`状态(Trap Flag)
    if (WARN_ON_ONCE(dr6 & DR_STEP))
        regs->flags &= ~X86_EFLAGS_TF;
out:
    instrumentation_end();
    irqentry_nmi_exit(regs, irq_state);
    // 恢复`dr7`寄存器
    local_db_restore(dr7);
}
```

用户空间调试中断处理程序实现如下：

```C
// file: arch/x86/kernel/traps.c
static __always_inline void exc_debug_user(struct pt_regs *regs, unsigned long dr6)
{
    bool icebp;
    // 内核空间地址时提示
    WARN_ON_ONCE(!user_mode(regs));
    irqentry_enter_from_user_mode(regs);
    instrumentation_begin();

    // 获取`dr6`
    current->thread.virtual_dr6 = (dr6 & DR_STEP);
    // 清除`TIF_BLOCKSTEP`标记
    clear_thread_flag(TIF_BLOCKSTEP);

    icebp = !dr6;
    // 通知调试状态
    if (notify_debug(regs, &dr6)) goto out;

    local_irq_enable();
    // 8086模式下处理trap
    if (v8086_mode(regs)) {
        handle_vm86_trap((struct kernel_vm86_regs *)regs, 0, X86_TRAP_DB);
        goto out_irq;
    }
    // 触发`BUS_LOCK`
    if (dr6 & DR_BUS_LOCK) handle_bus_lock(regs);
    // 发送trap信号
    dr6 |= current->thread.virtual_dr6;
    if (dr6 & (DR_STEP | DR_TRAP_BITS) || icebp)
        send_sigtrap(regs, 0, get_si_code(dr6));

out_irq:
    local_irq_disable();
out:
    instrumentation_end();
    irqentry_exit_to_user_mode(regs);
}
```

#### 2 DB通知链

`notify_debug`函数发送`DIE_DEBUG`通知信号，如下：

```C
// file: arch/x86/kernel/traps.c
static bool notify_debug(struct pt_regs *regs, unsigned long *dr6)
{
    // 通知`DIE_DEBUG`
    if (notify_die(DIE_DEBUG, "debug", regs, (long)dr6, 0, SIGTRAP) == NOTIFY_STOP)
        return true;

    return false;
}
```

在初始化过程中注册 `hw_breakpoint_exceptions_nb` 通知链，如下：

```C
// file: kernel/events/hw_breakpoint.c
int __init init_hw_breakpoint(void)
{
    ...
    return register_die_notifier(&hw_breakpoint_exceptions_nb);
}
```

`hw_breakpoint_exceptions_nb`定义如下：

```C
// file: kernel/events/hw_breakpoint.c
static struct notifier_block hw_breakpoint_exceptions_nb = {
    .notifier_call = hw_breakpoint_exceptions_notify,
    /* we need to be notified first */
    .priority = 0x7fffffff
};
```

`x86`架构下 `hw_breakpoint_exceptions_notify` 实现如下：

```C
// file: arch/x86/kernel/hw_breakpoint.c
int hw_breakpoint_exceptions_notify(struct notifier_block *unused, unsigned long val, void *data)
{
    // 只支持`DIE_DEBUG`类型
    if (val != DIE_DEBUG) return NOTIFY_DONE;
    // 断点处理接口
    return hw_breakpoint_handler(data);
}
```

`hw_breakpoint_handler`函数实现如下：

```C
// file: arch/x86/kernel/hw_breakpoint.c
static int hw_breakpoint_handler(struct die_args *args)
{
    int i, rc = NOTIFY_STOP;
    struct perf_event *bp;
    unsigned long *dr6_p;
    unsigned long dr6;
    bool bpx;
    // 获取`%dr6`寄存器指针及值
    dr6_p = (unsigned long *)ERR_PTR(args->err);
    dr6 = *dr6_p;
    // `%DR6`寄存器未设置`TRAP`时返回
    if ((dr6 & DR_TRAP_BITS) == 0) return NOTIFY_DONE;

    // 处理所有触发的断点
    for (i = 0; i < HBP_NUM; ++i) {
        // 未触发时继续下一个
        if (likely(!(dr6 & (DR_TRAP0 << i)))) continue;
        bp = this_cpu_read(bp_per_reg[i]);
        if (!bp) continue;
        // 是否为执行断点
        bpx = bp->hw.info.type == X86_BREAKPOINT_EXECUTE;
        if (bpx && (dr6 & DR_STEP)) continue;
        // 完成中断处理后重置`i`th TRAP位
        (*dr6_p) &= ~(DR_TRAP0 << i);
        // 断点事件输出
        perf_bp_event(bp, args->regs);
        // 设置`resume flag`标记避免断点递归
        if (bpx) args->regs->flags |= X86_EFLAGS_RF;
    }
    // 当前任务的`dr6`存在`TRAP`位或`dr6`不存在`TRAP`位时，返回`NOTIFY_DONE`
    if ((current->thread.virtual_dr6 & DR_TRAP_BITS) || (dr6 & (~DR_TRAP_BITS)))
        rc = NOTIFY_DONE;
    return rc;
}
```

#### 3 DB事件输出

`perf_bp_event`函数实现断点事件的采样输出，实现如下:

```C
// file: kernel/events/core.c
void perf_bp_event(struct perf_event *bp, void *data)
{
    struct perf_sample_data sample;
    struct pt_regs *regs = data;
    // 初始化采样数据
    perf_sample_data_init(&sample, bp->attr.bp_addr, 0);
    // 采样数据输出
    if (!bp->hw.state && !perf_exclude_event(bp, regs))
        perf_swevent_event(bp, 1, &sample, regs);
}
```

`perf_swevent_event` 函数实现软件事件的采样输出，其实现过程如下：

```C
// file: kernel/events/core.c
static void perf_swevent_event(struct perf_event *event, u64 nr,
                struct perf_sample_data *data, struct pt_regs *regs)
{
    struct hw_perf_event *hwc = &event->hw;
    // 触发次数修改
    local64_add(nr, &event->count);
    if (!regs) return;
    // 采样周期为0
    if (!is_sampling_event(event)) return;

    // 多种方式计算溢出次数后，采样输出
    if ((event->attr.sample_type & PERF_SAMPLE_PERIOD) && !event->attr.freq) {
        data->period = nr;
        return perf_swevent_overflow(event, 1, data, regs);
    } else
        data->period = event->hw.last_period;

    if (nr == 1 && hwc->sample_period == 1 && !event->attr.freq)
        return perf_swevent_overflow(event, 1, data, regs);

    if (local64_add_negative(nr, &hwc->period_left))
        return;
    perf_swevent_overflow(event, 0, data, regs);
}
```

`perf_swevent_overflow`函数实现软件事件的采样输出，实现如下：

```C
// file: kernel/events/core.c
static void perf_swevent_overflow(struct perf_event *event, u64 overflow,
                struct perf_sample_data *data, struct pt_regs *regs)
{
    struct hw_perf_event *hwc = &event->hw;
    int throttle = 0;
    // 计算溢出次数
    if (!overflow) 
        overflow = perf_swevent_set_period(event);

    if (hwc->interrupts == MAX_INTERRUPTS)
    	return;
    
    for (; overflow; overflow--) {
        // 采样数据输出
        if (__perf_event_overflow(event, throttle, data, regs)) { break; }
        throttle = 1;
    }
}
```

`__perf_event_overflow` 调用 `event->overflow_handler` 进行输出，实现过程如下：

```C
// file: kernel/events/core.c
static int __perf_event_overflow(struct perf_event *event, int throttle, 
                    struct perf_sample_data *data, struct pt_regs *regs)
    --> __perf_event_account_interrupt(event, throttle);
            // 设置了周期性采样
        --> if (event->attr.freq)
            --> if (delta > 0 && delta < 2*TICK_NSEC)
                --> perf_adjust_period(event, delta, hwc->last_period, true);
                        // 超过8个采样周期时，重启事件
                    --> if (local64_read(&hwc->period_left) > 8*sample_period)
                        --> if (disable) event->pmu->stop(event, PERF_EF_UPDATE);
                        --> local64_set(&hwc->period_left, 0);
                        --> if (disable) event->pmu->start(event, PERF_EF_RELOAD);
    --> event->pending_kill = POLL_IN;
    --> ...
    --> READ_ONCE(event->overflow_handler)(event, data, regs);
    --> ...
```

### 3.4 BPF程序调用的过程

#### 1 设置BPF程序

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
// file: kernel/events/core.c
static int perf_event_set_bpf_handler(struct perf_event *event, struct bpf_prog *prog, u64 bpf_cookie)
{
    ...
    event->prog = prog;
    event->bpf_cookie = bpf_cookie;
    event->orig_overflow_handler = READ_ONCE(event->overflow_handler);
    WRITE_ONCE(event->overflow_handler, bpf_overflow_handler);
}
```

断点事件不属于追踪事件，通过 `perf_event_set_bpf_handler` 设置bpf程序到 `event->prog` 中。

#### 2 调用BPF程序

在事件设置BPF程序后，溢出处理函数为 `bpf_overflow_handler`，实现如下：

```C
// file: kernel/events/core.c
static void bpf_overflow_handler(struct perf_event *event, struct perf_sample_data *data, struct pt_regs *regs)
{
    struct bpf_perf_event_data_kern ctx = {
        .data = data,
        .event = event,
    };
    ...
    // 获取寄存器值
    ctx.regs = perf_arch_bpf_user_pt_regs(regs);
    if (unlikely(__this_cpu_inc_return(bpf_prog_active) != 1))
        goto out;
    prog = READ_ONCE(event->prog);
    if (prog) {
        // 根据 event->attr.sample_type, 获取采样数据
        perf_prepare_sample(data, event, regs);
        // 运行bpf程序
        ret = bpf_prog_run(prog, &ctx);
    }

out:
    __this_cpu_dec(bpf_prog_active);
    if (!ret) return;
    // 默认溢出处理
    event->orig_overflow_handler(event, data, regs);
}
```

## 4 总结

本文通过`data_breakpoint`示例程序分析了BREAKPOINT-PMU的内核实现过程。`data_breakpoint` 程序将BPF程序挂载到所有的CPU上，通过设置断点触发挂载的BPF程序。

## 参考资料

* [Hw-breakpoint: shared debugging registers](https://lwn.net/Articles/353050/)
* [Interrupt handlers](https://0xax.gitbook.io/linux-insides/summary/interrupts/linux-interrupts-3)