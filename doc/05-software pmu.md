# SOFTWARE-PMU的内核实现

## 0 前言

在上一章节我们分析了CPU-PMU的实现，今天我们基于`runqlen`程序分析SOFTWARE-PMU的实现过程。

## 1 简介

Linux系统在CPU硬件PMU之外提供了软件PMU，在硬件不支持性能计数器的情况下我们可以借助软件PMU实现性能数据的采集。

## 2 runqlen程序

### 2.1 BPF程序

BPF程序的源码参见[runqlen.bpf.c](../src/runqlen.bpf.c)，主要内容如下：

```C
// file: src/runqlen.h
#define MAX_CPU_NR	128
#define MAX_SLOTS	32
struct hist {
	__u32 slots[MAX_SLOTS];
};

// file: src/runqlen.bpf.c
const volatile bool targ_per_cpu = false;
const volatile bool targ_host = false;
struct hist hists[MAX_CPU_NR] = {};

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
    struct task_struct *task;
    struct hist *hist;
    u64 slot, cpu = 0;
    // 获取当前任务
    task = (void*)bpf_get_current_task();
    // 获取队列长度
    if (targ_host)
        slot = BPF_CORE_READ(task, se.cfs_rq, rq, nr_running);
	else
        slot = BPF_CORE_READ(task, se.cfs_rq, nr_running);

    if (slot > 0)
        slot--;
    // 获取运行的CPU
    if (targ_per_cpu) {
        cpu = bpf_get_smp_processor_id();
        if (cpu >= MAX_CPU_NR)
            return 0;
    }
    hist = &hists[cpu];
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;
    // 增加采样次数
	if (targ_per_cpu)
        hist->slots[slot]++;
    else
        __sync_fetch_and_add(&hist->slots[slot], 1);
    return 0;
}
```

该程序包含了名称为`hists`的全局变量 和 名称为`do_sample`的BPF程序（节名称为"perf_event"）。`do_sample` 程序采集当前task的运行队列（cfs_rq）的长度, 更新到对应CPU的hist统计信息中。

### 2.2 用户程序

用户程序的源码参见[runqlen.c](../src/runqlen.c)，主要功能如下：

#### 1 附加BPF过程

```C
static int nr_cpus;

int main(int argc, char *const argv[])
{
    ...
    struct bpf_link *links[MAX_CPU_NR] = {};
    // 获取CPU数量
    nr_cpus = libbpf_num_possible_cpus();

    // 打开BPF程序
    err = ensure_core_btf(&open_opts);
    obj = runqlen_bpf__open_opts(&open_opts);

    // 初始化全局变量
    obj->rodata->targ_per_cpu = env.per_cpu;
    obj->rodata->targ_host = env.host;
    // 加载BPF程序
    err = runqlen_bpf__load(obj);

    // 附加BPF程序
    err = open_and_attach_perf_event(env.freq, obj->progs.do_sample, links);
    ...
}

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
                struct bpf_link *links[])
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .freq = 1,
        .sample_period = freq,
        .config = PERF_COUNT_SW_CPU_CLOCK,
    };
    for (i = 0; i < nr_cpus; i++) {
        fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
        ...
        links[i] = bpf_program__attach_perf_event(prog, fd);
        ...
    }
    return 0;
}
```

用户空间程序在所有的CPU上开启了性能计数器，并附加了BPF程序。性能计数器周期性采集`SW_CPU_CLOCK`计数器，该计数器用于测量程序执行的软件CPU时钟周期数。

#### 2 读取数据过程

```C
int main(int argc, char *const argv[])
{
    ...
    // 设置中断信号处理函数
    signal(SIGINT, sig_handler);

    while (1) {
        sleep(env.interval);
        printf("\n");
        // 打印时间, 通过"-T"选项开启
        if (env.timestamp) {
            time(&t);
            tm = localtime(&t);
            strftime(ts, sizeof(ts), "%H:%M:%S", tm);
            printf("%-8s\n", ts);
        }
        if (env.runqocc)
            // 统计结果以比例方式显示，通过"-O"选项开启
            print_runq_occupancy(obj->bss);
        else
            // 统计结果以线性方式显示
            print_linear_hists(obj->bss);

        if (exiting || --env.times == 0)
            break;
    }
    ...
}
```

用户通过 `Ctrl-C` 停止程序或设置统计间隔结束时，通过 `print_runq_occupancy` 或 `print_linear_hists` 读取 `obj->bss->hists[i]` 采样结果显示。

### 2.3 编译运行程序

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make runqlen
$ sudo ./runqlen 
Sampling run queue length... Hit Ctrl-C to end.
^C
     runqlen       : count     distribution
        0          : 5592     |****************************************|

$ sudo ./runqlen  -C -O
Sampling run queue length... Hit Ctrl-C to end.
^C
runqocc, CPU 0     0.00%
runqocc, CPU 1     0.00%
runqocc, CPU 2     0.00%
runqocc, CPU 3     0.00%
runqocc, CPU 4     0.00%
runqocc, CPU 5     0.00%
runqocc, CPU 6     0.00%
runqocc, CPU 7     0.00%
```

## 3 内核实现

### 3.1 PMU注册过程

Linux内核提供了12种软件事件，通过这些事件我们可以测量大量的硬件和软件事件。软件事件的类型如下：

```C
// file: include/uapi/linux/perf_event.h
enum perf_sw_ids {
	PERF_COUNT_SW_CPU_CLOCK			= 0,
	PERF_COUNT_SW_TASK_CLOCK		= 1,
	PERF_COUNT_SW_PAGE_FAULTS		= 2,
	PERF_COUNT_SW_CONTEXT_SWITCHES		= 3,
	PERF_COUNT_SW_CPU_MIGRATIONS		= 4,
	PERF_COUNT_SW_PAGE_FAULTS_MIN		= 5,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ		= 6,
	PERF_COUNT_SW_ALIGNMENT_FAULTS		= 7,
	PERF_COUNT_SW_EMULATION_FAULTS		= 8,
	PERF_COUNT_SW_DUMMY			= 9,
	PERF_COUNT_SW_BPF_OUTPUT		= 10,
	PERF_COUNT_SW_CGROUP_SWITCHES		= 11,

	PERF_COUNT_SW_MAX,			/* non-ABI */
};
```

这些软件事件注册到3个不同的pmu中，如下：

```C
// file: kernel/events/core.c
void __init perf_event_init(void)
    // 除 PERF_COUNT_SW_CPU_CLOCK 和 PERF_COUNT_SW_TASK_CLOCK 外的其他事件
    --> perf_pmu_register(&perf_swevent, "software", PERF_TYPE_SOFTWARE);
    // PERF_COUNT_SW_CPU_CLOCK 事件
    --> perf_pmu_register(&perf_cpu_clock, NULL, -1);
    // PERF_COUNT_SW_TASK_CLOCK 事件
    --> perf_pmu_register(&perf_task_clock, NULL, -1);
```

### 3.2 SOFTWARE-PMU的操作接口

首先，我们分析 `perf_swevent` 的实现过程，定义如下：

```C
// file: kernel/events/core.c
static struct pmu perf_swevent = {
	.task_ctx_nr	= perf_sw_context,
	.capabilities	= PERF_PMU_CAP_NO_NMI,
	.event_init	= perf_swevent_init,
	.add		= perf_swevent_add,
	.del		= perf_swevent_del,
	.start		= perf_swevent_start,
	.stop		= perf_swevent_stop,
	.read		= perf_swevent_read,
};
```

`perf_swevent` 只提供了初始化、开启/停止、添加/删除、读取等基本的操作接口。


#### 1 初始化 -- `perf_swevent_init`

perf_swevent的初始化接口设置为 `.event_init = perf_swevent_init`，实现过程如下：

```C
// file: kernel/events/core.c
static int perf_swevent_init(struct perf_event *event)
{
    u64 event_id = event->attr.config;
    // 类型检查
    if (event->attr.type != PERF_TYPE_SOFTWARE)
        return -ENOENT;
    // 软件事件不支持分支栈采样
    if (has_branch_stack(event))
        return -EOPNOTSUPP;
    // config检查
    switch (event_id) {
    case PERF_COUNT_SW_CPU_CLOCK:
    case PERF_COUNT_SW_TASK_CLOCK:
        return -ENOENT;
    default:
        break;
    }
    if (event_id >= PERF_COUNT_SW_MAX)
        return -ENOENT;
    // 事件没有设置parent
    if (!event->parent) {
        int err;
        // 获取软件事件hashlist
        err = swevent_hlist_get();
        ...
        // 增加static_key计数
        static_key_slow_inc(&perf_swevent_enabled[event_id]);
        event->destroy = sw_perf_event_destroy;
    }
    return 0;
}
```

`swevent_hlist_get` 获取软件事件的hashlist，实现过程如下：

```C
// file: kernel/events/core.c
static int swevent_hlist_get(void)
    --> for_each_possible_cpu(cpu)
        --> swevent_hlist_get_cpu(cpu);
            --> struct swevent_htable *swhash = &per_cpu(swevent_htable, cpu);
            --> if(!swevent_hlist_deref(swhash))
                // 分配hlist
                --> hlist = kzalloc(sizeof(*hlist), GFP_KERNEL);
                --> rcu_assign_pointer(swhash->swevent_hlist, hlist);
            --> swhash->hlist_refcount++;
```

`perf_swevent_enabled` 记录每个软件事件的开启情况，定义如下：

```C
// file: kernel/events/core.c
struct static_key perf_swevent_enabled[PERF_COUNT_SW_MAX];
```

#### 2 添加 -- `perf_swevent_add`

perf_swevent的添加接口设置为 `.add = perf_swevent_add`，实现过程如下：

```C
// file: kernel/events/core.c
static int perf_swevent_add(struct perf_event *event, int flags)
{
    struct swevent_htable *swhash = this_cpu_ptr(&swevent_htable);
    struct hw_perf_event *hwc = &event->hw;
    struct hlist_head *head;

    // 检查采样周期
    if (is_sampling_event(event)) {
        hwc->last_period = hwc->sample_period;
        // 设置事件的采样周期
        perf_swevent_set_period(event);
    }   
    hwc->state = !(flags & PERF_EF_START);
    // 获取hashlist
    head = find_swevent_head(swhash, event);
    if (WARN_ON_ONCE(!head))
        return -EINVAL;
    // 添加到hashlist中
    hlist_add_head_rcu(&event->hlist_entry, head);
    // 更新用户页信息
    perf_event_update_userpage(event);
    return 0;
}
```

#### 3 删除 -- `perf_swevent_del`

perf_swevent的删除接口设置为 `.del = perf_swevent_del`，实现过程如下：

```C
// file: kernel/events/core.c
static void perf_swevent_del(struct perf_event *event, int flags)
{
    // 从hashlist中移除
    hlist_del_rcu(&event->hlist_entry);
}
```

#### 4 开始 -- `perf_swevent_start`

perf_swevent的开始接口设置为 `.start = perf_swevent_start`，实现过程如下：

```C
// file: kernel/events/core.c
static void perf_swevent_start(struct perf_event *event, int flags)
{
    // 设置开始状态
    event->hw.state = 0;
}
```

#### 5 停止 -- `perf_swevent_stop`

perf_swevent的停止接口设置为 `.stop = perf_swevent_stop`，实现过程如下：

```C
// file: kernel/events/core.c
static void perf_swevent_stop(struct perf_event *event, int flags)
{
    // 设置停止状态
    event->hw.state = PERF_HES_STOPPED;
}
```

#### 6 销毁 -- `sw_perf_event_destroy`

perf_swevent的销毁接口设置为 `event->destroy = sw_perf_event_destroy`，实现过程如下：

```C
// file: kernel/events/core.c
static void sw_perf_event_destroy(struct perf_event *event)
{
    u64 event_id = event->attr.config;
    WARN_ON(event->parent);
    // 减少static_key计数
    static_key_slow_dec(&perf_swevent_enabled[event_id]);
    // 释放hashlist
    swevent_hlist_put();
}
```

### 3.3 SW_CPU_CLOCK-PMU的操作接口

接下来，我们分析 `perf_cpu_clock` 的实现过程，定义如下：

```C
// file: kernel/events/core.c
static struct pmu perf_cpu_clock = {
	.task_ctx_nr	= perf_sw_context,
	.capabilities	= PERF_PMU_CAP_NO_NMI,
	.event_init	= cpu_clock_event_init,
	.add		= cpu_clock_event_add,
	.del		= cpu_clock_event_del,
	.start		= cpu_clock_event_start,
	.stop		= cpu_clock_event_stop,
	.read		= cpu_clock_event_read,
};
```

和`perf_swevent`一样，`perf_cpu_clock` 也只提供了初始化、开启/停止、添加/删除、读取等基本的操作接口。

#### 1 初始化 -- `cpu_clock_event_init`

perf_cpu_clock的初始化接口设置为 `.event_init = cpu_clock_event_init`，实现过程如下：

```C
// file: kernel/events/core.c
static int cpu_clock_event_init(struct perf_event *event)
{
    // type和config检查
    if (event->attr.type != PERF_TYPE_SOFTWARE)
        return -ENOENT;
    if (event->attr.config != PERF_COUNT_SW_CPU_CLOCK)
        return -ENOENT;
    // 同样不支持分支栈信息获取
    if (has_branch_stack(event))
        return -EOPNOTSUPP;
    // 初始化定时器
    perf_swevent_init_hrtimer(event);
    return 0;
}
```

`perf_swevent_init_hrtimer` 设置软件事件的定时器，实现过程如下：

```C
// file: kernel/events/core.c
static void perf_swevent_init_hrtimer(struct perf_event *event)
{
    struct hw_perf_event *hwc = &event->hw;
    if (!is_sampling_event(event))
        return;
    // 初始化定时器
    hrtimer_init(&hwc->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_HARD);
    hwc->hrtimer.function = perf_swevent_hrtimer;

    // 将采样频率调整为采样周期
    if (event->attr.freq) {
        long freq = event->attr.sample_freq;
        event->attr.sample_period = NSEC_PER_SEC / freq;
        hwc->sample_period = event->attr.sample_period;
        local64_set(&hwc->period_left, hwc->sample_period);
        hwc->last_period = hwc->sample_period;
        event->attr.freq = 0;
    }
}
```

#### 2 添加 -- `cpu_clock_event_add`

perf_cpu_clock的添加接口设置为 `.add = cpu_clock_event_add`，实现过程如下：

```C
// file: kernel/events/core.c
static int cpu_clock_event_add(struct perf_event *event, int flags)
{
    // 设置开始标志的情况下，开启事件
    if (flags & PERF_EF_START)
        cpu_clock_event_start(event, flags);
    // 更新用户页信息
    perf_event_update_userpage(event);
    return 0;
}
```

#### 3 删除 -- `cpu_clock_event_del`

perf_cpu_clock的删除接口设置为 `.add = cpu_clock_event_del`，实现过程如下：

```C
// file: kernel/events/core.c
static void cpu_clock_event_del(struct perf_event *event, int flags)
{
    // 停止事件
    cpu_clock_event_stop(event, flags);
}
```

#### 4 开始 -- `cpu_clock_event_start`

perf_cpu_clock的开始接口设置为 `.add = cpu_clock_event_start`，实现过程如下：

```C
// file: kernel/events/core.c
static void cpu_clock_event_start(struct perf_event *event, int flags)
{
    // 设置开始时间
    local64_set(&event->hw.prev_count, local_clock());
    // 开启定时器
    perf_swevent_start_hrtimer(event);
}

// file: kernel/events/core.c
static void perf_swevent_start_hrtimer(struct perf_event *event)
{
    struct hw_perf_event *hwc = &event->hw;
    s64 period;
    if (!is_sampling_event(event))
        return;
    // 计算定时器周期
    period = local64_read(&hwc->period_left);
    if (period) {
        if (period < 0) period = 10000;
        local64_set(&hwc->period_left, 0);
    } else {
        period = max_t(u64, 10000, hwc->sample_period);
    }
    // 开始定时器
    hrtimer_start(&hwc->hrtimer, ns_to_ktime(period), HRTIMER_MODE_REL_PINNED_HARD);
}
```

#### 5 停止 -- `cpu_clock_event_stop`

perf_cpu_clock的停止接口设置为 `.add = cpu_clock_event_stop`，实现过程如下：

```C
// file: kernel/events/core.c
static void cpu_clock_event_stop(struct perf_event *event, int flags)
{
    // 取消定时器
    perf_swevent_cancel_hrtimer(event);
    // 更新计数信息
    cpu_clock_event_update(event);
}

// file: kernel/events/core.c
static void perf_swevent_cancel_hrtimer(struct perf_event *event)
{
    struct hw_perf_event *hwc = &event->hw;
    if (is_sampling_event(event)) {
        ktime_t remaining = hrtimer_get_remaining(&hwc->hrtimer);
        local64_set(&hwc->period_left, ktime_to_ns(remaining));
        // 取消定时器
        hrtimer_cancel(&hwc->hrtimer);
    }
}
```

#### 6 读取 -- `cpu_clock_event_read`

perf_cpu_clock的读取接口设置为 `.read = cpu_clock_event_read`，实现过程如下：

```C
// file: kernel/events/core.c
static void cpu_clock_event_read(struct perf_event *event)
{
    cpu_clock_event_update(event);
}

// file: kernel/events/core.c
static void cpu_clock_event_update(struct perf_event *event)
{
    s64 prev;
    u64 now;
    // 计算时间
    now = local_clock();
    prev = local64_xchg(&event->hw.prev_count, now);
    local64_add(now - prev, &event->count);
}
```

### 3.4 SW_TASK_CLOCK-PMU的操作接口

接下来，我们分析 `perf_task_clock` 的实现过程，定义如下：

```C
// file: kernel/events/core.c
static struct pmu perf_task_clock = {
	.task_ctx_nr	= perf_sw_context,
	.capabilities	= PERF_PMU_CAP_NO_NMI,
	.event_init	= task_clock_event_init,
	.add		= task_clock_event_add,
	.del		= task_clock_event_del,
	.start		= task_clock_event_start,
	.stop		= task_clock_event_stop,
	.read		= task_clock_event_read,
};
```

`perf_task_clock` 和 `perf_cpu_clock` 的实现过程一致，通过设置定时器开始/停止事件，事件的类型和读取不同。该事件统计任务的时间。

### 3.5 事件触发的方式

#### 1 调度切换时触发

在[Linux性能计数器在内核的实现](doc/02-Performance%20Counters%20for%20Linux.md) 中 `perf事件的调度过程` 中触发三个软件事件，如下：

```C
// file: kernel/sched/core.c
asmlinkage __visible void __sched schedule(void)
    --> __schedule(SM_NONE);
        --> next = pick_next_task(rq, prev, &rf); //struct task_struct *
        --> rq = context_switch(rq, prev, next, &rf);
            --> prepare_task_switch(rq, prev, next);
                --> perf_event_task_sched_out(prev, next);
                    --> __perf_sw_event_sched(PERF_COUNT_SW_CONTEXT_SWITCHES, 1, 0);
                    --> __perf_sw_event_sched(PERF_COUNT_SW_CGROUP_SWITCHES, 1, 0);
            --> switch_to(prev, next, prev);
            --> finish_task_switch(prev);
                --> perf_event_task_sched_in(prev, current);
                    --> __perf_sw_event_sched(PERF_COUNT_SW_CPU_MIGRATIONS, 1, 0);
```

`PERF_COUNT_SW_CONTEXT_SWITCHES`, `PERF_COUNT_SW_CGROUP_SWITCHES`, `PERF_COUNT_SW_CPU_MIGRATIONS` 这三个事件在调度切换过程中通过 `__perf_sw_event_sched` 触发。实现过程如下：

```C
// file: include/linux/perf_event.h
static __always_inline void __perf_sw_event_sched(u32 event_id, u64 nr, u64 addr)
    --> struct pt_regs *regs = this_cpu_ptr(&__perf_regs[0]);
        // 获取调用者寄存器
    --> perf_fetch_caller_regs(regs);
        // file: kernel/events/core.c
    --> ___perf_sw_event(event_id, nr, regs, addr);
        // 采样数据初始化
        --> perf_sample_data_init(&data, addr, 0);
        --> do_perf_sw_event(PERF_TYPE_SOFTWARE, event_id, nr, &data, regs);
            --> struct swevent_htable *swhash = this_cpu_ptr(&swevent_htable);
            // 获取采样事件hashlist
            --> head = find_swevent_head_rcu(swhash, type, event_id);
            --> hlist_for_each_entry_rcu(event, head, hlist_entry)
                // 采样事件匹配性检查
                --> if (perf_swevent_match(event, type, event_id, data, regs))
                    // 软件采样事件输出
			        --> perf_swevent_event(event, nr, data, regs);
```

`perf_swevent_event` 的实现过程如下：

```C
// file: kernel/events/core.c
static void perf_swevent_event(struct perf_event *event, u64 nr,
			       struct perf_sample_data *data,
			       struct pt_regs *regs)
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

// file: kernel/events/core.c
static void perf_swevent_overflow(struct perf_event *event, u64 overflow,
				    struct perf_sample_data *data,
				    struct pt_regs *regs)
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
        if (__perf_event_overflow(event, throttle, data, regs)) 
            { break; }
        throttle = 1;
    }
}
```

`__perf_event_overflow` 调用 `event->overflow_handler` 进行输出，实现过程如下：

```C
// file: kernel/events/core.c
static int __perf_event_overflow(struct perf_event *event,
                int throttle, struct perf_sample_data *data,
                struct pt_regs *regs)
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

#### 2 调用`perf_sw_event`时触发

`PERF_COUNT_SW_PAGE_FAULTS`, `PERF_COUNT_SW_PAGE_FAULTS_MAJ`, `PERF_COUNT_SW_PAGE_FAULTS_MIN`, `PERF_COUNT_SW_ALIGNMENT_FAULTS`, `PERF_COUNT_SW_EMULATION_FAULTS` 这些事件通过调用 `perf_sw_event` 函数触发。如 `mm_account_fault` 函数，触发过程如下：

```C
// file: mm/memory.c
static inline void mm_account_fault(struct pt_regs *regs,
        unsigned long address, unsigned int flags, vm_fault_t ret)
{
    ...
    if (major)
        perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, regs, address);
    else
        perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, regs, address);
}
```

`perf_sw_event` 函数检查事件是否开启，开启时触发。实现过程如下：

```C
// file: include/linux/perf_event.h
static __always_inline void
perf_sw_event(u32 event_id, u64 nr, struct pt_regs *regs, u64 addr)
{
    if (static_key_false(&perf_swevent_enabled[event_id]))
        __perf_sw_event(event_id, nr, regs, addr);
}
```

#### 3 调用`perf_event_output`时触发

`PERF_COUNT_SW_BPF_OUTPUT` 事件调用 `perf_event_output` 函数输出。调用过程如下：

```C
// file: kernel/trace/bpf_trace.c
static __always_inline u64
__bpf_perf_event_output(struct pt_regs *regs, struct bpf_map *map,
            u64 flags, struct perf_sample_data *sd)
{
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    unsigned int cpu = smp_processor_id();
    ...
    ee = READ_ONCE(array->ptrs[index]);
    event = ee->event;
    if (unlikely(event->attr.type != PERF_TYPE_SOFTWARE ||
            event->attr.config != PERF_COUNT_SW_BPF_OUTPUT))
        return -EINVAL;
    if (unlikely(event->oncpu != cpu))
        return -EOPNOTSUPP;
    return perf_event_output(event, sd, regs);
}

// file: kernel/events/core.c
int perf_event_output(struct perf_event *event,
            struct perf_sample_data *data, struct pt_regs *regs)
{
    // 输出到事件的缓冲区中
    return __perf_event_output(event, data, regs, perf_output_begin);
}
```

#### 4 定时器触发

`PERF_COUNT_SW_CPU_CLOCK` 和 `PERF_COUNT_SW_TASK_CLOCK`  通过定时器触发，在初始化过程设置了定时器的触发函数 `hwc->hrtimer.function = perf_swevent_hrtimer` 。`perf_swevent_hrtimer` 的实现如下：

```C
// file: kernel/events/core.c
static enum hrtimer_restart perf_swevent_hrtimer(struct hrtimer *hrtimer)
{
    enum hrtimer_restart ret = HRTIMER_RESTART;
    ...
    // 获取事件
    event = container_of(hrtimer, struct perf_event, hw.hrtimer);
    if (event->state != PERF_EVENT_STATE_ACTIVE)
        return HRTIMER_NORESTART;
    // 事件读取数据
    event->pmu->read(event);
    //采样数据初始化
    perf_sample_data_init(&data, 0, event->hw.last_period);
    regs = get_irq_regs();

    if (regs && !perf_exclude_event(event, regs)) {
        if (!(event->attr.exclude_idle && is_idle_task(current)))
            // 采样数据输出
            if (__perf_event_overflow(event, 1, &data, regs))
                ret = HRTIMER_NORESTART;
    }
    // 重新设置采样周期
    period = max_t(u64, 10000, event->hw.sample_period);
    hrtimer_forward_now(hrtimer, ns_to_ktime(period));
    return ret;
}
```

### 3.6 BPF程序调用的过程

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

软件事件采样事件不属于追踪事件，通过 `perf_event_set_bpf_handler` 设置bpf程序到 `event->prog` 中。

#### 2 调用BPF程序

在事件设置BPF程序后，溢出处理函数为 `bpf_overflow_handler`，实现如下：

```C
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

本文通过`runqlen`示例程序分析了SOFTWARE-PMU的内核实现过程。`runqlen` 程序将BPF程序挂载到所有的CPU上，通过定时器触发挂载的BPF程序。

软件事件提供了多种触发方式，触发方式根据类型的不同而异。
