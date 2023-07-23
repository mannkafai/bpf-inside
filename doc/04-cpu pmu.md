# CPU-PMU的内核实现

## 0 前言

在[inux性能计数器在内核的实现](02-01-Performance%20Counters%20for%20Linux.md)中，我们分析了 perf_events 的实现过程，简单介绍了PMU的注册过程。今天我们基于`profile`程序分析CPU-PMU的实现过程。

## 1 简介

在Linux操作系统中，PMU（Performance Monitoring Unit）是一种硬件组件，用于测量系统的性能和执行情况。PMU提供了一组计数器和事件选择器，可以用于收集和分析各种性能指标，如CPU周期数、缓存命中率、指令执行数等。

## 2 profile程序

### 2.1 BPF程序

BPF程序的源码参见[profile.bpf.c](../src/profile.bpf.c)，主要内容如下：

```C
// file: src/profile.bpf.c
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

用户程序的源码参见[profile.c](../src/profile.c)，主要功能如下：

#### 1 附加BPF过程

```C
int main(int argc, char *const argv[])
{
    const char *online_cpus_file = "/sys/devices/system/cpu/online";
    int num_cpus, num_online_cpus;
    bool *online_mask = NULL;
    
    // 获取在线的CPU信息
    err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
    // 获取CPU数量
    num_cpus = libbpf_num_possible_cpus();
    // 打开并加载bpf程序
    skel = profile_bpf__open_and_load();

    // 设置计数器属性--周期性采集硬件事件
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.sample_freq = freq;
    attr.freq = 1;

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

用户空间程序在每个在线的CPU上都开启了性能计数器，并附加了BPF程序。性能计数器周期性采集`HW_CPU_CYCLES`计数器，该计数器用于测量程序执行的CPU时钟周期数。

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
    printf("COMM: %s (pid=%d) @ CPU %d\n", event->comm, event->pid, event->cpu_id);
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

#### 3 ring_buffer的内部原理

在上节中我们创建了`ring_buffer`, 通过poll方式检查是否有数据。其内部使用epoll机制实现的，如下：

```C
// file: libbpf/src/ringbuf.c
struct ring_buffer *
ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx,
        const struct ring_buffer_opts *opts)
    --> struct ring_buffer *rb;
    --> rb = calloc(1, sizeof(*rb));
    --> rb->page_size = getpagesize();
    // 创建epool
    --> rb->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    // ring_buffer添加fd
    --> ring_buffer__add(rb, map_fd, sample_cb, ctx);
        --> struct bpf_map_info info;
        --> bpf_map_get_info_by_fd(map_fd, &info, &len);
        // 重新分配rings和events
        --> libbpf_reallocarray(rb->rings, rb->ring_cnt + 1, sizeof(*rb->rings));
        --> libbpf_reallocarray(rb->events, rb->ring_cnt + 1, sizeof(*rb->events));
        // 设置ring
        --> r = &rb->rings[rb->ring_cnt]; // struct ring *r;
        --> r->map_fd = map_fd;
        --> r->sample_cb = sample_cb;
        --> r->ctx = ctx;
        --> r->mask = info.max_entries - 1;
        // 映射内存
        --> tmp = mmap(NULL, rb->page_size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        --> r->consumer_pos = tmp;
        --> mmap_sz = rb->page_size + 2 * (__u64)info.max_entries;
        --> tmp = mmap(NULL, (size_t)mmap_sz, PROT_READ, MAP_SHARED, map_fd, rb->page_size);
        --> r->producer_pos = tmp;
        --> r->data = tmp + rb->page_size; 
        // 设置event
        --> e = &rb->events[rb->ring_cnt]; // struct epoll_event *e;
        --> e->events = EPOLLIN;
        --> e->data.fd = rb->ring_cnt;
        // 添加epoll事件
        --> epoll_ctl(rb->epoll_fd, EPOLL_CTL_ADD, map_fd, e)
        --> rb->ring_cnt++;

// file: libbpf/src/ringbuf.c
int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms)
    // epoll获取事件状态
    --> cnt = epoll_wait(rb->epoll_fd, rb->events, rb->ring_cnt, timeout_ms);
    --> for (i = 0; i < cnt; i++)
        --> __u32 ring_id = rb->events[i].data.fd;
        --> struct ring *ring = &rb->rings[ring_id];
        // 处理ring
        --> ringbuf_process_ring(ring);
            --> cons_pos = smp_load_acquire(r->consumer_pos);
            --> prod_pos = smp_load_acquire(r->producer_pos);
            --> while (cons_pos < prod_pos)
                --> len_ptr = r->data + (cons_pos & r->mask);
                --> len = smp_load_acquire(len_ptr);
                --> cons_pos += roundup_len(len);
                // 获取采样数据
                --> sample = (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
                // 触发回调函数
                -->  r->sample_cb(r->ctx, sample, len);
```

### 2.3 编译运行程序

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make profile
$ sudo ./profile 
COMM: swapper/0 (pid=0) @ CPU 0
Kernel:
  0 [<ffffffffaa41d4d8>] mwait_idle_with_hints.constprop.0+0x48
  1 [<ffffffffaa79e6da>] cpuidle_enter_state+0x9a
  2 [<ffffffffaa79ecde>] cpuidle_enter+0x2e
  3 [<ffffffffa9d2e043>] call_cpuidle+0x23
  4 [<ffffffffa9d32399>] cpuidle_idle_call+0x119
  5 [<ffffffffa9d32492>] do_idle+0x82
  6 [<ffffffffa9d32700>] cpu_startup_entry+0x20
  7 [<ffffffffaab18a35>] rest_init+0xe5
  8 [<ffffffffac04f8eb>] arch_call_rest_init+0xe
  9 [<ffffffffac04fdda>] start_kernel+0x4b3
  10 [<ffffffffac04e66b>] x86_64_start_reservations+0x24
  11 [<ffffffffac04e7a1>] x86_64_start_kernel+0xee
  12 [<ffffffffa9c0015a>] secondary_startup_64_no_verify+0xe5
No Userspace Stack
...
```

## 3 内核实现

### 3.1 PMU初始化过程

#### 1 x86架构PMU初始化

x86架构下通过 `early_initcall(init_hw_perf_events)` 实现硬件计数器事件的初始化，`init_hw_perf_events` 实现如下：

```C
// file: arch\x86\events\core.c
static int __init init_hw_perf_events(void)
{
    // 设备厂商PMU初始化
    switch (boot_cpu_data.x86_vendor) {
    case X86_VENDOR_INTEL: err = intel_pmu_init(); break;
    case X86_VENDOR_AMD: err = amd_pmu_init(); break;
    case X86_VENDOR_HYGON: err = amd_pmu_init(); x86_pmu.name = "HYGON"; break;
    case X86_VENDOR_ZHAOXIN:
    case X86_VENDOR_CENTAUR: err = zhaoxin_pmu_init(); break;
    default: err = -ENOTSUPP;}

    // x86_pmu 初始化回调函数
    for (quirk = x86_pmu.quirks; quirk; quirk = quirk->next)
        quirk->func();
    ...
    // 注册NMI处理函数
    register_nmi_handler(NMI_LOCAL, perf_event_nmi_handler, 0, "PMI");
    // 约束条件结束标志 
    unconstrained = (struct event_constraint)
        __EVENT_CONSTRAINT(0, (1ULL << x86_pmu.num_counters) - 1, 0, x86_pmu.num_counters, 0, 0);

    // attr相关设置
    x86_pmu_format_group.attrs = x86_pmu.format_attrs;
    if (!x86_pmu.events_sysfs_show) x86_pmu_events_group.attrs = &empty_attrs;
    pmu.attr_update = x86_pmu.attr_update;

    // 打印PMU信息（非混合架构CPU）
    if (!is_hybrid())
        x86_pmu_show_pmu_cap(x86_pmu.num_counters, x86_pmu.num_counters_fixed, x86_pmu.intel_ctrl);

    // 默认函数设置
    if (!x86_pmu.read) x86_pmu.read = _x86_pmu_read;
    if (!x86_pmu.guest_get_msrs) x86_pmu.guest_get_msrs = (void *)&__static_call_return0;
    if (!x86_pmu.set_period) x86_pmu.set_period = x86_perf_event_set_period;
    if (!x86_pmu.update) x86_pmu.update = x86_perf_event_update;

    // x86_pmu静态调用函数更新
    x86_pmu_static_call_update();
    ...

    // 注册PMU
    if (!is_hybrid()) {
        err = perf_pmu_register(&pmu, "cpu", PERF_TYPE_RAW);
        if (err) goto out2;
    } else {
        struct x86_hybrid_pmu *hybrid_pmu;
        for (i = 0; i < x86_pmu.num_hybrid_pmus; i++) {
            hybrid_pmu = &x86_pmu.hybrid_pmu[i];
            hybrid_pmu->pmu = pmu;
            ...  
            //混合架构CPU注册PMU，区分大小核
            err = perf_pmu_register(&hybrid_pmu->pmu, hybrid_pmu->name,
                        (hybrid_pmu->cpu_type == hybrid_big) ? PERF_TYPE_RAW : -1);
            if (err) break;
        }
        ...
    }
    return 0;
    ...
}
```

主要的步骤如下：

* 初始化`x86_pmu`。根据不同设备厂商对`x86_pmu`初始化；
* 注册NMI处理函数，通过NMI中断检查CPU计数器的采样；
* 函数设置，检查`x86_pmu`默认函数，更新静态调用函数
* 注册cpu-pmu，在混合CPU架构的情况下，注册多个。

我们可以通过 `sudo dmesg` 查看pmu状态信息，如下：

```bash
$ sudo dmesg 
...
[    0.159262] Performance Events: PEBS fmt1+, IvyBridge events, 16-deep LBR, full-width counters, Intel PMU driver.
[    0.159284] ... version:                3
[    0.159285] ... bit width:              48
[    0.159286] ... generic registers:      4
[    0.159287] ... value mask:             0000ffffffffffff
[    0.159289] ... max period:             00007fffffffffff
[    0.159290] ... fixed-purpose events:   3
[    0.159291] ... event mask:             000000070000000f
...
```

通过信息可以知道同时支持4个采样事件和3个特定目的的采样事件。


#### 2 x86_pmu初始化

以功能最丰富的Intel CPU为例进行分析，AMD、兆芯CPU在实现上类似。Intel CPU的初始化过程如下：

```C
// file: arch\x86\events\intel\core.c
__init int intel_pmu_init(void)
{
    ...
    // 获取CPU信息
    cpuid(10, &eax.full, &ebx.full, &fixed_mask, &edx.full);
    if (eax.split.mask_length < ARCH_PERFMON_EVENTS_COUNT)
        return -ENODEV;
    // 根据版本设置x86_pmu
    version = eax.split.version_id;
    if (version < 2)
        x86_pmu = core_pmu;
    else
        x86_pmu = intel_pmu;
    
    // x86_pmu属性设置
    x86_pmu.version         = version;
    x86_pmu.num_counters    = eax.split.num_counters;
    ...

    // 检查是否支持LBR (上次分支记录)
    if (boot_cpu_has(X86_FEATURE_ARCH_LBR))
        intel_pmu_arch_lbr_init();
    
    //BTS (分支追踪存储), PEBS（精确事件采样）支持性检查，设置PEBS采样方式、缓冲区大小
    intel_ds_init();

    x86_add_quirk(intel_arch_events_quirk);

    // 根据cpu型号适配处理
    switch (boot_cpu_data.x86_model) {
    case INTEL_FAM6_CORE_YONAH:
        pr_cont("Core events, ");
        name = "core";
        break;
    ...
    // 以 ivybridge 型号为例，其他型号类似
    case INTEL_FAM6_IVYBRIDGE:
    case INTEL_FAM6_IVYBRIDGE_X:
        x86_add_quirk(intel_ht_bug);
        // hw_cache事件ID
        memcpy(hw_cache_event_ids, snb_hw_cache_event_ids, sizeof(hw_cache_event_ids));
        hw_cache_event_ids[C(DTLB)][C(OP_READ)][C(RESULT_MISS)] = 0x8108;
        //hw_cache额外寄存器
        memcpy(hw_cache_extra_regs, snb_hw_cache_extra_regs, sizeof(hw_cache_extra_regs));

        //初始化lbr，设置lbr数量、起止地址、mask、map信息
        intel_pmu_lbr_init_snb();

        //x86_pmu相关属性更新
        x86_pmu.event_constraints = intel_ivb_event_constraints;
        x86_pmu.pebs_constraints = intel_ivb_pebs_event_constraints;
        x86_pmu.pebs_aliases = intel_pebs_aliases_ivb;
        x86_pmu.pebs_prec_dist = true;
        if (boot_cpu_data.x86_model == INTEL_FAM6_IVYBRIDGE_X)
            x86_pmu.extra_regs = intel_snbep_extra_regs;
        else
            x86_pmu.extra_regs = intel_snb_extra_regs;
        x86_pmu.flags |= PMU_FL_HAS_RSP_1;
        x86_pmu.flags |= PMU_FL_NO_HT_SHARING;
        
        td_attr  = snb_events_attrs;
        mem_attr = snb_mem_events_attrs;

        //事件对应map更新
        intel_perfmon_event_map[PERF_COUNT_HW_STALLED_CYCLES_FRONTEND] =
            X86_CONFIG(.event=0x0e, .umask=0x01, .inv=1, .cmask=1);

        extra_attr = nhm_format_attr;

        pr_cont("IvyBridge events, ");
        name = "ivybridge";
        break;
    ...
    ...
    default:
        //默认处理
        switch (x86_pmu.version) {
            case 1:
                ...
        }
    }

    //attr属性
    if (!is_hybrid()) {
        group_events_td.attrs  = td_attr;
        ...
        x86_pmu.attr_update = attr_update;
    } else {
        hybrid_group_events_td.attrs  = td_attr;
        ...
        x86_pmu.attr_update = hybrid_attr_update;
    }

    // 检查计数器数量
    intel_pmu_check_num_counters(&x86_pmu.num_counters, &x86_pmu.num_counters_fixed, 
                                &x86_pmu.intel_ctrl, (u64)fixed_mask);
    // 检查CPU计数器事件约束
    intel_pmu_check_event_constraints(x86_pmu.event_constraints, x86_pmu.num_counters, 
                                x86_pmu.num_counters_fixed, x86_pmu.intel_ctrl);
    
    //LBR检查，检查LBR寄存器是否能够访问
    if (x86_pmu.lbr_tos && !check_msr(x86_pmu.lbr_tos, 0x3UL))
        x86_pmu.lbr_nr = 0;
    ...
    // LBR初始化
    if (x86_pmu.lbr_nr) {
        intel_pmu_lbr_init();
        pr_cont("%d-deep LBR, ", x86_pmu.lbr_nr);
        if (x86_pmu.disable_all == intel_pmu_disable_all) {
            // 分支栈信息获取函数更新
            if (boot_cpu_has(X86_FEATURE_ARCH_LBR)) {
                static_call_update(perf_snapshot_branch_stack, intel_pmu_snapshot_arch_branch_stack);
            } else {
                static_call_update(perf_snapshot_branch_stack, intel_pmu_snapshot_branch_stack);
            }
        }
    }

    // 额外寄存器检查，通过 check_msr(er->msr, 0x11UL)检查
    intel_pmu_check_extra_regs(x86_pmu.extra_regs);

    // 最大周期设置
    if (x86_pmu.intel_cap.full_width_write) {
        x86_pmu.max_period = x86_pmu.cntval_mask >> 1;
        x86_pmu.perfctr = MSR_IA32_PMC0;
        pr_cont("full-width counters, ");
    }

    if (!is_hybrid() && x86_pmu.intel_cap.perf_metrics)
        x86_pmu.intel_ctrl |= 1ULL << GLOBAL_CTRL_EN_PERF_METRICS;
    ...
}
```

其中主要的步骤包括：

* 设置`x86_pmu`。在通过 `cpuid(10,...)` 获取CPU信息后，根据CPU设置`x86_pmu`；
* 根据CPU型号设置对应属性。由于Intel CPU型号众多，以`ivybridge`为例，设置 `hw_cache_event_ids` 和 `hw_cache_extra_regs` 这两个关键参数；
* 检查计数器数量和约束条件；
* LBR, BTS, PEBS 支持性检查和初始化。 

### 3.2 PMU的操作接口

在上一节中，我们通过 `perf_pmu_register(&pmu, "cpu", PERF_TYPE_RAW);` 实现了CPU pmu的注册，pmu的定义如下：

```C
// file: arch/x86/events/core.c
static struct pmu pmu = {
	.pmu_enable		= x86_pmu_enable,
	.pmu_disable		= x86_pmu_disable,
	.attr_groups		= x86_pmu_attr_groups,

	.event_init		= x86_pmu_event_init,

	.event_mapped		= x86_pmu_event_mapped,
	.event_unmapped		= x86_pmu_event_unmapped,

	.add			= x86_pmu_add,
	.del			= x86_pmu_del,
	.start			= x86_pmu_start,
	.stop			= x86_pmu_stop,
	.read			= x86_pmu_read,

	.start_txn		= x86_pmu_start_txn,
	.cancel_txn		= x86_pmu_cancel_txn,
	.commit_txn		= x86_pmu_commit_txn,

	.event_idx		= x86_pmu_event_idx,
	.sched_task		= x86_pmu_sched_task,
	.swap_task_ctx		= x86_pmu_swap_task_ctx,
	.check_period		= x86_pmu_check_period,

	.aux_output_match	= x86_pmu_aux_output_match,

	.filter			= x86_pmu_filter,
};
```

#### 1 初始化 -- `x86_pmu_event_init`

PMU的初始化接口设置为 `.event_init = x86_pmu_event_init`，实现过程如下：

```C
// file: arch/x86/events/core.c
static int x86_pmu_event_init(struct perf_event *event)
    // 类型检查，必须为 RAW、HARDWARE、HW_CACHE 
    --> if ((event->attr.type != event->pmu->type) &&
            (event->attr.type != PERF_TYPE_HARDWARE) &&
            (event->attr.type != PERF_TYPE_HW_CACHE))
            return -ENOENT;
    --> __x86_pmu_event_init(event);
        // 预留硬件需要的缓冲区
        --> x86_reserve_hardware();
            // pmc_refcount为0时，预留硬件信息
            --> if (atomic_read(&pmc_refcount) == 0)
                // 预留pmc信息
                --> reserve_pmc_hardware();
                    --> num_counters = get_possible_num_counters();
                    --> for (i = 0; i < num_counters; i++)
                        --> reserve_perfctr_nmi(x86_pmu_event_addr(i));
                            --> counter = nmi_perfctr_msr_to_bit(msr);
                            --> test_and_set_bit(counter, perfctr_nmi_owner);
                    --> for (i = 0; i < num_counters; i++)
                        --> reserve_evntsel_nmi(x86_pmu_config_addr(i));
                            --> counter = nmi_evntsel_msr_to_bit(msr);
                            --> test_and_set_bit(counter, evntsel_nmi_owner);
                // 预留调试存储信息
                --> reserve_ds_buffers();
                    --> for_each_possible_cpu(cpu)
                        --> alloc_ds_buffer(cpu);
                            --> struct debug_store *ds = &get_cpu_entry_area(cpu)->cpu_debug_store;
                            --> memset(ds, 0, sizeof(*ds));
                            --> per_cpu(cpu_hw_events, cpu).ds = ds;
                        --> alloc_bts_buffer(cpu);
                            --> buffer = dsalloc_pages(BTS_BUFFER_SIZE, GFP_KERNEL | __GFP_NOWARN, cpu);
                            --> hwev->ds_bts_vaddr = buffer; // hwev = per_cpu_ptr(&cpu_hw_events, cpu);
                        --> alloc_pebs_buffer(cpu);
                            --> size_t bsiz = x86_pmu.pebs_buffer_size;
                            --> buffer = dsalloc_pages(bsiz, GFP_KERNEL, cpu);
                            --> hwev->ds_pebs_vaddr = buffer; // hwev = per_cpu_ptr(&cpu_hw_events, cpu);
                // 预留lbr缓冲区
                --> reserve_lbr_buffers();
                    --> for_each_possible_cpu(cpu)
                        --> cpuc = per_cpu_ptr(&cpu_hw_events, cpu);
                        --> kmem_cache = x86_get_pmu(cpu)->task_ctx_cache;
                        --> cpuc->lbr_xsave = kmem_cache_alloc_node(kmem_cache, GFP_KERNEL | __GFP_ZERO, cpu_to_node(cpu));
            --> atomic_inc(&pmc_refcount);
    // 设置destroy函数
    --> event->destroy = hw_perf_event_destroy;
    // hw事件初始设置
    --> event->hw.idx = -1;
    --> ...
    --> x86_pmu.hw_config(event); 
        // .hw_config = intel_pmu_hw_config,
        // 滑移量检查
        --> if (event->attr.precise_ip) { ... }
        --> if (event->attr.precise_ip > 1 && x86_pmu.intel_cap.pebs_format < 2) { ... }
        --> ...
        // event->hw.config设置
        --> event->hw.config = ARCH_PERFMON_EVENTSEL_INT;
        --> if (!event->attr.exclude_user)
            --> event->hw.config |= ARCH_PERFMON_EVENTSEL_USR;
        --> if (!event->attr.exclude_kernel)
            --> event->hw.config |= ARCH_PERFMON_EVENTSEL_OS;
        --> if (event->attr.type == event->pmu->type)
            --> event->hw.config |= event->attr.config & X86_RAW_EVENT_MASK;
        // 采样周期检查
        --> if (event->attr.sample_period && x86_pmu.limit_period) { ... }
        // 采样寄存器检查，不支持 XMM 寄存器
        --> if (unlikely(event->attr.sample_regs_user & PERF_REG_EXTENDED_MASK)) return -EINVAL;
        --> x86_setup_perfctr(event);
            // 默认采样周期设置
            --> if (!is_sampling_event(event))
                --> hwc->sample_period = x86_pmu.max_period;
                --> ...
            // RAW 事件
            --> if (attr->type == event->pmu->type)
                --> return x86_pmu_extra_regs(event->attr.config, event);
                    --> reg = &event->hw.extra_reg;
                    // x86_pmu.extra_regs中遍历确定符合的寄存器, 通过config和config1确定
                    --> reg->idx = er->idx;
                    --> reg->config = event->attr.config1;
                    --> reg->reg = er->msr;
            // HW_CACHE 事件 
            --> if (attr->type == PERF_TYPE_HW_CACHE)
                --> return set_ext_hw_attr(hwc, event);
                    --> config = attr->config;
                    --> cache_type = (config >> 0) & 0xff;
                    --> cache_op = (config >>  8) & 0xff;
                    --> cache_result = (config >> 16) & 0xff;
                    // 获取 hw_cache_event_ids[][][] 对应的值
                    --> val = hybrid_var(event->pmu, hw_cache_event_ids)[cache_type][cache_op][cache_result];
                    --> hwc->config |= val;
                    --> attr->config1 = hybrid_var(event->pmu, hw_cache_extra_regs)[cache_type][cache_op][cache_result];
                    --> x86_pmu_extra_regs(val, event);
            // HARDWARE 事件
            --> config = x86_pmu.event_map(attr->config); 
                // x86_pmu.event_map = intel_pmu_event_map,
                // 获取map中对应的值
                --> intel_perfmon_event_map[hw_event];
            --> hwc->config |= config;
        // bts 设置
        --> intel_pmu_bts_config(event);
            // 检查是否存在bts事件，bts约束条件：bts_active(存在)，exclude_kernel(用户空间)，!precise_ip(非滑移)
            --> if (unlikely(intel_pmu_has_bts(event)))
                --> x86_add_exclusive(x86_lbr_exclusive_lbr);
                --> event->destroy = hw_perf_lbr_event_destroy;
        // 滑移量检查和设置
        --> if (event->attr.precise_ip) { ... }
        --> if (needs_branch_stack(event))
            // 分支记录采样设置
            --> intel_pmu_setup_lbr_filter(event);
                // 设置分支采样信息
                --> intel_pmu_setup_sw_lbr_filter(event);
                    --> u64 br_type = event->attr.branch_sample_type;
                    --> if (br_type & PERF_SAMPLE_BRANCH_USER) mask |= X86_BR_USER;
                    --> ...
                    --> event->hw.branch_reg.reg = mask;
            // lbr 过滤设置
            --> intel_pmu_setup_hw_lbr_filter(event);
                --> reg = &event->hw.branch_reg;
	            --> reg->idx = EXTRA_REG_LBR;
                --> reg->config = mask;
                --> reg->reg |= X86_BR_TYPE_SAVE;
        // RAW 事件检查
        --> if (intel_pmu_has_cap(event, PERF_CAP_METRICS_IDX) && is_topdown_event(event)) { ... }
    // 验证事件
    --> if (event->group_leader != event)
        // 当前事件不是组长时，验证组事件
        --> validate_group(event);
            --> fake_cpuc = allocate_fake_cpuc(event->pmu);
            // 收集事件，组事件
            --> collect_events(fake_cpuc, leader, true);
                --> collect_event(cpuc, leader, max_count, n);
                    // 验证事件数量是否超出范围
                    --> if (n >= max_count + cpuc->n_metric) return -EINVAL;
                    --> cpuc->event_list[n] = event;
                --> for_each_sibling_event(event, leader)
                    --> collect_event(cpuc, event, max_count, n);
            // 收集事件，自身事件
            --> collect_events(fake_cpuc, leader, false);
            // 调度所有的事件，获取指派信息
            --> x86_pmu.schedule_events(fake_cpuc, n, NULL);
                // .schedule_events	= x86_schedule_events,
                --> static_call_cond(x86_pmu_start_scheduling)(cpuc);
                --> for (i = 0, wmin = X86_PMC_IDX_MAX, wmax = 0; i < n; i++)
                    --> c = cpuc->event_constraint[i];
                    // 重新获取约束
                    --> if (!c || (c->flags & PERF_X86_EVENT_DYNAMIC))
                        --> c = static_call(x86_pmu_get_event_constraints)(cpuc, i, cpuc->event_list[i]);
                        --> cpuc->event_constraint[i] = c;
                // 快速方式，使用之前的寄存器
                --> for (i = 0; i < n; i++)
                    --> hwc = &cpuc->event_list[i]->hw;
                    --> if (hwc->idx == -1) break;
                    --> if (assign) assign[i] = hwc->idx;
                // 慢路径
                --> if (i != n)
                    --> perf_assign_events(cpuc->event_constraint, n, wmin, wmax, gpmax, assign);
                        --> perf_sched_init(&sched, constraints, n, wmin, wmax, gpmax);
                        --> do {
                            --> perf_sched_find_counter(&sched)
                            --> if (assign) assign[sched.state.event] = sched.state.counter;
                        --> } while (perf_sched_next_event(&sched));
                --> if (!unsched && assign)
                    // 提交assign
                    --> for (i = 0; i < n; i++)
                        --> static_call_cond(x86_pmu_commit_scheduling)(cpuc, i, assign[i]);
                --> else
                    // 释放约束信息
                    --> for (i = n0; i < n; i++) {
			            --> e = cpuc->event_list[i];
			            --> static_call_cond(x86_pmu_put_event_constraints)(cpuc, e);
			            --> cpuc->event_constraint[i] = NULL;
                --> static_call_cond(x86_pmu_stop_scheduling)(cpuc);
            --> free_fake_cpuc(fake_cpuc);
    --> else
        // 验证本事件
        --> validate_event(event);
            --> fake_cpuc = allocate_fake_cpuc(event->pmu);
            // 获取约束信息
            --> x86_pmu.get_event_constraints(fake_cpuc, 0, event); 
                //.get_event_constraints = intel_get_event_constraints,
                --> c1 = cpuc->event_constraint[idx];
                --> c2 = __intel_get_event_constraints(cpuc, idx, event);
                    --> c = intel_vlbr_constraints(event); if(c) return c;
                    --> c = intel_bts_constraints(event); if(c) return c;
                    --> c = intel_shared_regs_constraints(cpuc, event); if(c) return c;
                    --> c = intel_pebs_constraints(event); if(c) return c;
                    --> return x86_get_event_constraints(cpuc, idx, event);
                //拷贝c2到c1
                --> bitmap_copy(c1->idxmsk, c2->idxmsk, X86_PMC_IDX_MAX);
                --> c1->weight = c2->weight;
                --> if (cpuc->excl_cntrs) intel_get_excl_constraints(cpuc, event, idx, c2);
            // 释放约束信息
            --> x86_pmu.put_event_constraints(fake_cpuc, event);
                // .put_event_constraints	= intel_put_event_constraints,
                --> intel_put_shared_regs_event_constraints(cpuc, event);
                    // 额外寄存器
                    --> reg = &event->hw.extra_reg; 
                    --> if (reg->idx != EXTRA_REG_NONE) __intel_shared_reg_put_constraints(cpuc, reg);
                    // 分支寄存器
                    --> reg = &event->hw.branch_reg;
                    --> if (reg->idx != EXTRA_REG_NONE) __intel_shared_reg_put_constraints(cpuc, reg);
                --> if (cpuc->excl_cntrs) intel_put_excl_constraints(cpuc, event);
            --> free_fake_cpuc(fake_cpuc);
```

主要步骤如下：

* 类型检查阶段，检查pmu的类型是否匹配。只支持 RAW，HW-CACHE，HARDWARE 三种类型。
* x86_pmu事件初始化阶段。包括：初次使用时，预留缓冲区；设置事件属性信息，如：销毁函数、hw信息等；
* 硬件采集事件配置阶段。在输入参数（如：滑移量、采样周期等）检查后，对RAW，HW-CACHE，HARDWARE三种类型的事件进行对应设置；
* 验证事件阶段。验证组事件或本事件，验证事件数量、约束条件是否正确。
  
##### RAW 事件的初始化

RAW事件用来采集原始计数器，初始化的过程如下：

```C
// file: arch/x86/events/core.c
if (attr->type == event->pmu->type)
    return x86_pmu_extra_regs(event->attr.config, event);
```

查找 `x86_pmu.extra_regs` 中的寄存器，通过 `event->attr.config` 确定。

```C
// file: arch/x86/events/intel/core.c
x86_pmu.extra_regs = intel_snb_extra_regs;

// file: arch/x86/events/intel/core.c
static struct extra_reg intel_snb_extra_regs[] __read_mostly = {
    INTEL_UEVENT_EXTRA_REG(0x01b7, MSR_OFFCORE_RSP_0, 0x3f807f8fffull, RSP_0),
    INTEL_UEVENT_EXTRA_REG(0x01bb, MSR_OFFCORE_RSP_1, 0x3f807f8fffull, RSP_1),
    INTEL_UEVENT_PEBS_LDLAT_EXTRA_REG(0x01cd),
    EVENT_EXTRA_END
};
```

##### HW_CACHE 事件的初始化

HW_CACHE事件用来采集硬件缓存信息，如：L1缓存、L2缓存或LLC（Last Level Cache）缓存等。初始化过程如下：

```C
// file: arch/x86/events/core.c
if (attr->type == PERF_TYPE_HW_CACHE)
    return set_ext_hw_attr(hwc, event);

// file: arch/x86/events/core.c
static inline int
set_ext_hw_attr(struct hw_perf_event *hwc, struct perf_event *event)
{
    ...
    config = attr->config;
    // 通过 config 获取 type、op、result
    cache_type = (config >> 0) & 0xff;
    cache_op = (config >>  8) & 0xff;
    cache_result = (config >> 16) & 0xff;
    ...
    // 获取 hw_cache_event_ids[][][] 中对应的值
    val = hybrid_var(event->pmu, hw_cache_event_ids)[cache_type][cache_op][cache_result];
    hwc->config |= val;
    // 获取 hw_cache_extra_regs[][][] 中对应的值
    attr->config1 = hybrid_var(event->pmu, hw_cache_extra_regs)[cache_type][cache_op][cache_result];
    return x86_pmu_extra_regs(val, event);
}
```

HW_CACHE事件获取 `hw_cache_event_ids[][][]` 中对应的值，该字段定义如下：

```C
// file: arch/x86/events/core.c
u64 __read_mostly hw_cache_event_ids
                [PERF_COUNT_HW_CACHE_MAX]
                [PERF_COUNT_HW_CACHE_OP_MAX]
                [PERF_COUNT_HW_CACHE_RESULT_MAX];
u64 __read_mostly hw_cache_extra_regs
                [PERF_COUNT_HW_CACHE_MAX]
                [PERF_COUNT_HW_CACHE_OP_MAX]
                [PERF_COUNT_HW_CACHE_RESULT_MAX];
```

```C
// file: include/uapi/linux/perf_event.h
enum perf_hw_cache_id {
	PERF_COUNT_HW_CACHE_L1D			= 0,
	PERF_COUNT_HW_CACHE_L1I			= 1,
	PERF_COUNT_HW_CACHE_LL			= 2,
	PERF_COUNT_HW_CACHE_DTLB		= 3,
	PERF_COUNT_HW_CACHE_ITLB		= 4,
	PERF_COUNT_HW_CACHE_BPU			= 5,
	PERF_COUNT_HW_CACHE_NODE		= 6,

	PERF_COUNT_HW_CACHE_MAX,		/* non-ABI */
};

enum perf_hw_cache_op_id {
	PERF_COUNT_HW_CACHE_OP_READ		= 0,
	PERF_COUNT_HW_CACHE_OP_WRITE		= 1,
	PERF_COUNT_HW_CACHE_OP_PREFETCH		= 2,

	PERF_COUNT_HW_CACHE_OP_MAX,		/* non-ABI */
};

enum perf_hw_cache_op_result_id {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS	= 0,
	PERF_COUNT_HW_CACHE_RESULT_MISS		= 1,

	PERF_COUNT_HW_CACHE_RESULT_MAX,		/* non-ABI */
};
```

`hw_cache_event_ids` 是个三维数组，能够采集的硬件缓存事件包括：

```C
 { L1-D, L1-I, LLC, ITLB, DTLB, BPU, NODE } x
 { read, write, prefetch } x
 { accesses, misses }
```

在初始化过程中，不同的型号的CPU进行对应的初始化，如下：

```C
// file: arch/x86/events/intel/core.c
    memcpy(hw_cache_event_ids, snb_hw_cache_event_ids, sizeof(hw_cache_event_ids));
    /* dTLB-load-misses on IVB is different than SNB */
    /* DTLB_LOAD_MISSES.DEMAND_LD_MISS_CAUSES_A_WALK */
    hw_cache_event_ids[C(DTLB)][C(OP_READ)][C(RESULT_MISS)] = 0x8108; 
    memcpy(hw_cache_extra_regs, snb_hw_cache_extra_regs, sizeof(hw_cache_extra_regs));
```

##### HARDWARE 事件的初始化

HARDWARE事件用来采集硬件信息，如：CPU周期、缓存未命中数量、分支指令数量等，初始化过程如下：

```C
// file: arch/x86/events/core.c
config = x86_pmu.event_map(attr->config);
hwc->config |= config;

// file: arch/x86/events/intel/core.c
.event_map		= intel_pmu_event_map,

static u64 intel_pmu_event_map(int hw_event)
{
    return intel_perfmon_event_map[hw_event];
}
```

直接获取 `intel_perfmon_event_map[]` 中对应的值，该变量定义如下：

```C
// file: arch/x86/events/intel/core.c
static u64 intel_perfmon_event_map[PERF_COUNT_HW_MAX] __read_mostly =
{
	[PERF_COUNT_HW_CPU_CYCLES]		= 0x003c,
	[PERF_COUNT_HW_INSTRUCTIONS]		= 0x00c0,
	[PERF_COUNT_HW_CACHE_REFERENCES]	= 0x4f2e,
	[PERF_COUNT_HW_CACHE_MISSES]		= 0x412e,
	[PERF_COUNT_HW_BRANCH_INSTRUCTIONS]	= 0x00c4,
	[PERF_COUNT_HW_BRANCH_MISSES]		= 0x00c5,
	[PERF_COUNT_HW_BUS_CYCLES]		= 0x013c,
	[PERF_COUNT_HW_REF_CPU_CYCLES]		= 0x0300, /* pseudo-encoding */
};
```

`PERF_COUNT_HW_MAX` 的定义如下：

```C
// file: include/uapi/linux/perf_event.h
enum perf_hw_id {
	PERF_COUNT_HW_CPU_CYCLES		= 0,
	PERF_COUNT_HW_INSTRUCTIONS		= 1,
	PERF_COUNT_HW_CACHE_REFERENCES		= 2,
	PERF_COUNT_HW_CACHE_MISSES		= 3,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS	= 4,
	PERF_COUNT_HW_BRANCH_MISSES		= 5,
	PERF_COUNT_HW_BUS_CYCLES		= 6,
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND	= 7,
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND	= 8,
	PERF_COUNT_HW_REF_CPU_CYCLES		= 9,

	PERF_COUNT_HW_MAX,			/* non-ABI */
};
```

HARDWARE支持上述类型的事件（在CPU支持的情况下）。


#### 2 添加 -- `x86_pmu_add`

PMU的添加接口设置为 `.add = x86_pmu_add`，实现过程如下：

```C
// file: arch/x86/events/core.c
static int x86_pmu_add(struct perf_event *event, int flags)
    --> struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
    --> n0 = cpuc->n_events;
    // 收集事件信息，添加到 cpuc->events[]中
    --> ret = n = collect_events(cpuc, event, false);
    // 获取指派信息
    --> static_call(x86_pmu_schedule_events)(cpuc, n, assign); 
        // static_call_update(x86_pmu_schedule_events, x86_pmu.schedule_events);  
    --> memcpy(cpuc->assign, assign, n*sizeof(int));
    // 更新计数信息
    --> cpuc->n_events = n; cpuc->n_added += n - n0; cpuc->n_txn += n - n0;
    --> static_call_cond(x86_pmu_add)(event);
        // static_call_update(x86_pmu_add, x86_pmu.add);
        // x86_pmu.add = intel_pmu_add_event
        // 滑移量
        --> if (event->attr.precise_ip) 
            // pebs 寄存器添加
            --> intel_pmu_pebs_add(event);
                --> struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
                --> cpuc->n_pebs++;
                --> if (hwc->flags & PERF_X86_EVENT_LARGE_PEBS) cpuc->n_large_pebs++;
                --> if (hwc->flags & PERF_X86_EVENT_PEBS_VIA_PT) cpuc->n_pebs_via_pt++;
                --> pebs_update_state(needed_cb, cpuc, event, true);
                    --> if (!needed_cb)
                        // 添加到pmu_txt回调列表
                        --> perf_sched_cb_inc(pmu);
                            --> struct perf_cpu_pmu_context *cpc = this_cpu_ptr(pmu->cpu_pmu_context);
                            --> if (!cpc->sched_cb_usage++)
                                --> list_add(&cpc->sched_cb_entry, this_cpu_ptr(&sched_cb_list));
                            --> this_cpu_inc(perf_sched_cb_usages);
                    --> else
                        // 从pmu_ctx回调列表中删除
                        --> perf_sched_cb_dec(pmu);
                            --> this_cpu_dec(perf_sched_cb_usages);
                            --> if (!--cpc->sched_cb_usage)
                                --> list_del(&cpc->sched_cb_entry);
                    // 添加时更新pebs配置信息
                    --> if (x86_pmu.intel_cap.pebs_baseline && add) 
                        --> pebs_data_cfg = pebs_update_adaptive_cfg(event); 
                        --> cpuc->pebs_data_cfg |= pebs_data_cfg | PEBS_UPDATE_DS_SW;
        --> if (needs_branch_stack(event))
            // lbr 寄存器添加
            --> intel_pmu_lbr_add(event);
                --> cpuc->br_sel = event->hw.branch_reg.reg;
                --> cpuc->lbr_pebs_users++;
                --> perf_sched_cb_inc(event->pmu);
                // 初次添加时重置lbr
                --> if (!cpuc->lbr_users++ && !event->total_time_running) 
                    --> intel_pmu_lbr_reset();
                        --> x86_pmu.lbr_reset();
                        --> wrmsrl(MSR_LBR_SELECT, 0);
```

主要步骤如下：

* 添加阶段，将该事件添加到 `cpuc->event_list[]` 中。
* 重新获取指派信息。
* 添加事件，事件存在滑移量时添加PEBS信息，存在分支寄存器时添加LBR信息。

#### 3 删除 -- `x86_pmu_del`

PMU的删除接口设置为 `.del = x86_pmu_del`，实现过程如下：

```C
// file: arch/x86/events/core.c
static void x86_pmu_del(struct perf_event *event, int flags)
    --> struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
    --> __set_bit(event->hw.idx, cpuc->dirty);
    // 停止事件
    --> x86_pmu_stop(event, PERF_EF_UPDATE);
    // 释放约束信息
    --> static_call_cond(x86_pmu_put_event_constraints)(cpuc, event);
    // 删除列表中事件、约束信息
    --> while (++i < cpuc->n_events) 
        --> cpuc->event_list[i-1] = cpuc->event_list[i];
        --> cpuc->event_constraint[i-1] = cpuc->event_constraint[i];
    // 最后一个约束置空
    --> cpuc->event_constraint[i-1] = NULL;
    --> --cpuc->n_events;
    // 更新指标计数
    --> if (intel_cap.perf_metrics)	del_nr_metric_event(cpuc, event);
    // 更新用户映射页面
    --> perf_event_update_userpage(event);
    // 删除事件
    --> static_call_cond(x86_pmu_del)(event);
        // static_call_update(x86_pmu_del, x86_pmu.del);
        // x86_pmu.del = intel_pmu_del_event
        --> if (needs_branch_stack(event))
            --> intel_pmu_lbr_del(event);
                --> if (event->hw.flags & PERF_X86_EVENT_LBR_SELECT) cpuc->lbr_select = 0;
                --> cpuc->lbr_users--;
                --> perf_sched_cb_dec(event->pmu);
                    --> this_cpu_dec(perf_sched_cb_usages);
                    --> if (!--cpc->sched_cb_usage) list_del(&cpc->sched_cb_entry);
        --> if (event->attr.precise_ip)
            --> intel_pmu_pebs_del(event);
                --> cpuc->n_pebs--;
                --> if (hwc->flags & PERF_X86_EVENT_LARGE_PEBS)	cpuc->n_large_pebs--;
                --> if (hwc->flags & PERF_X86_EVENT_PEBS_VIA_PT) cpuc->n_pebs_via_pt--;
                --> pebs_update_state(needed_cb, cpuc, event, false);

```

主要步骤如下：

* 停止事件，事件运行时停止该事件。
* 释放约束信息、从 `cpuc->event_list[]` 中移除。
* 删除事件，清除LBR和PEBS设置。

#### 4 启用 -- `x86_pmu_enable`

PMU的启用接口设置为 `.pmu_enable = x86_pmu_enable`，实现过程如下：

```C
// file: arch/x86/events/core.c
static void x86_pmu_enable(struct pmu *pmu)
    --> struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
    // 开启标志
    --> if (cpuc->enabled) return;
    // 存在新添加的事件
    --> if (cpuc->n_added)
        --> int n_running = cpuc->n_events - cpuc->n_added;
        // 检查运行的事件
        --> for (i = 0; i < n_running; i++) 
            --> event = cpuc->event_list[i];
            --> hwc = &event->hw;
            // 检查事件，跳过上次指派事件，避免重复停止后开启。
            --> if (hwc->idx == -1 || atch_prev_assignment(hwc, cpuc, i)) continue;
            // 停止事件
            --> x86_pmu_stop(event, PERF_EF_UPDATE);
        // 检查所有事件
        --> for (i = 0; i < cpuc->n_events; i++) 
            --> event = cpuc->event_list[i];
            --> hwc = &event->hw;
            --> if (!match_prev_assignment(hwc, cpuc, i))
                // 指派事件
                --> x86_assign_hw_event(event, cpuc, i);
                    --> hwc->idx = cpuc->assign[i];
                    --> hwc->last_cpu = smp_processor_id();
                    --> hwc->last_tag = ++cpuc->tags[i];
                    --> static_call_cond(x86_pmu_assign)(event, idx);
                    // 根据idx 设置 config_base, event_base
                    --> switch (hwc->idx) {
                        --> case INTEL_PMC_IDX_FIXED_BTS:
                        --> case INTEL_PMC_IDX_FIXED_VLBR:
                            --> hwc->config_base = 0;
                            --> hwc->event_base	= 0;
                            --> break;
                        --> ...
                        --> default:
                            --> hwc->config_base = x86_pmu_config_addr(hwc->idx);
                            --> hwc->event_base  = x86_pmu_event_addr(hwc->idx);
                            --> hwc->event_base_rdpmc = x86_pmu_rdpmc_index(hwc->idx);
                            --> break;
            --> else if (i < n_running) continue;
            // 开启事件
            --> x86_pmu_start(event, PERF_EF_RELOAD);
        --> cpuc->n_added = 0;
    --> cpuc->enabled = 1;
    // 启用所有的事件
    --> static_call(x86_pmu_enable_all)(added);
        // static_call_update(x86_pmu_enable_all, x86_pmu.enable_all);
        // x86_pmu.enable_all = intel_pmu_enable_all,
        --> intel_pmu_pebs_enable_all();
            // 启用 pebs 
            --> if (cpuc->pebs_enabled) wrmsrl(MSR_IA32_PEBS_ENABLE, cpuc->pebs_enabled);
        --> __intel_pmu_enable_all(added, false);
            --> intel_pmu_lbr_enable_all(pmi);
                // 启用 lbr 
                --> __intel_pmu_lbr_enable(pmi);
                    --> wrmsrl(MSR_LBR_SELECT, lbr_select);
                    --> wrmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
                    --> wrmsrl(MSR_ARCH_LBR_CTL, lbr_select | ARCH_LBR_CTL_LBREN);
                // 启用 pmu
                --> wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, intel_ctrl & ~cpuc->intel_ctrl_guest_mask);
                // 启用 bts
                --> if (test_bit(INTEL_PMC_IDX_FIXED_BTS, cpuc->active_mask))
                    --> struct perf_event *event = cpuc->events[INTEL_PMC_IDX_FIXED_BTS];
                    --> intel_pmu_enable_bts(event->hw.config);
```


主要步骤如下：

* 检查新增事件阶段。停止正在运行的事件，重新指派事件后开启。通过指派信息确定事件采集基址。
* 启用所有的采集事件，修改msr寄存器，开启采集事件。

#### 5 禁用 -- `x86_pmu_disable`

PMU的禁用接口设置为 `.pmu_disable = x86_pmu_disable`，实现过程如下：

```C
// file: arch/x86/events/core.c
static void x86_pmu_disable(struct pmu *pmu)
    // 开启标志检查
    --> if (!cpuc->enabled) return;
    // 标志设置
    --> cpuc->n_added = 0; cpuc->enabled = 0;
    // 禁用所有的事件
    --> static_call(x86_pmu_disable_all)();
        // static_call_update(x86_pmu_disable_all, x86_pmu.disable_all);
        // x86_pmu.disable_all = intel_pmu_disable_all,
        --> __intel_pmu_disable_all(true);
            // 禁用 pmu
            --> wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, 0);
            --> if (bts && test_bit(INTEL_PMC_IDX_FIXED_BTS, cpuc->active_mask))
                // 禁用 bts
                --> intel_pmu_disable_bts();
        --> intel_pmu_pebs_disable_all();
            --> if (cpuc->pebs_enabled) __intel_pmu_pebs_disable_all();
                // 禁用 pebs
                --> wrmsrl(MSR_IA32_PEBS_ENABLE, 0);
        --> intel_pmu_lbr_disable_all();
            --> __intel_pmu_arch_lbr_disable();
                // 禁用 lbr
                --> wrmsrl(MSR_ARCH_LBR_CTL, 0);
```

主要步骤如下：

* 禁用所有的采集事件，修改msr寄存器，停止采集事件。

#### 6 开始 -- `x86_pmu_start`

PMU的开始接口设置为 `.start = x86_pmu_start`，实现过程如下：

```C
// file: arch/x86/events/core.c
static void x86_pmu_start(struct perf_event *event, int flags)
    --> struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
    --> int idx = event->hw.idx;
    // 检查事件是否停止
    --> if (WARN_ON_ONCE(!(event->hw.state & PERF_HES_STOPPED))) return;
    // 检查事件是否指派
    --> if (WARN_ON_ONCE(idx == -1)) return;
    // 重新加载时，设置采样周期
    --> if (flags & PERF_EF_RELOAD)
        --> static_call(x86_pmu_set_period)(event);
        // static_call_update(x86_pmu_set_period, x86_pmu.set_period);
        // x86_pmu.set_period = intel_pmu_set_period
        --> x86_perf_event_set_period(event);
            // 计算采样时间
            --> s64 left = local64_read(&hwc->period_left);
            --> static_call_cond(x86_pmu_limit_period)(event, &left);
            --> this_cpu_write(pmc_prev_left[idx], left);
            --> local64_set(&hwc->prev_count, (u64)-left);
            // 更新采样时间
            --> wrmsrl(hwc->event_base, (u64)(-left) & x86_pmu.cntval_mask);
            --> if (is_counter_pair(hwc)) wrmsrl(x86_pmu_event_addr(idx + 1), 0xffff);
            --> perf_event_update_userpage(event);
    // 设置事件状态、cpuc状态
    --> event->hw.state = 0;
    --> cpuc->events[idx] = event;
    --> __set_bit(idx, cpuc->active_mask);
    // 启用事件
    --> static_call(x86_pmu_enable)(event);
        // static_call_update(x86_pmu_enable, x86_pmu.enable);
        // x86_pmu.enable = intel_pmu_enable_event
        // 滑移量
        --> if (unlikely(event->attr.precise_ip)) 
                // 启用 pebs 
            --> intel_pmu_pebs_enable(event);
                --> wrmsrl(MSR_PEBS_DATA_CFG, pebs_data_cfg);
                --> intel_pmu_pebs_via_pt_enable(event);
                    --> wrmsrl(base + idx, value);
        // 启用指派的事件
        --> switch (idx) 
        --> case 0 ... INTEL_PMC_IDX_FIXED - 1:
            --> intel_set_masks(event, idx);
            --> __x86_pmu_enable_event(hwc, ARCH_PERFMON_EVENTSEL_ENABLE);
                    // 修改msr寄存器，开启采样
                --> if (hwc->extra_reg.reg) wrmsrl(hwc->extra_reg.reg, hwc->extra_reg.config);
                --> if (is_counter_pair(hwc)) wrmsrl(x86_pmu_config_addr(hwc->idx + 1), x86_pmu.perf_ctr_pair_en);
                --> wrmsrl(hwc->config_base, (hwc->config | enable_mask) & ~disable_mask);
            --> break;
        --> ...
        --> case INTEL_PMC_IDX_FIXED_BTS:
            --> intel_pmu_enable_bts(hwc->config);
            --> break;
        --> ...
```

主要步骤如下：

* 采样周期设置。重新加载事件时计算采样时间，修改msr寄存器中对应时间；
* 启用事件。修改msr寄存器，开启对应事件。

#### 7 停止 -- `x86_pmu_stop`

PMU的停止接口设置为 `.stop = x86_pmu_stop`，实现过程如下：

```C
// file: arch/x86/events/core.c
void x86_pmu_stop(struct perf_event *event, int flags)
    // 已启用事件
    --> if (test_bit(hwc->idx, cpuc->active_mask))
        // 禁用事件
        --> static_call(x86_pmu_disable)(event);
            // static_call_update(x86_pmu_disable, x86_pmu.disable);
            // x86_pmu.disable = intel_pmu_disable_event
            // 禁用指派的事件
            --> switch (idx) 
            --> case 0 ... INTEL_PMC_IDX_FIXED - 1:
                --> intel_clear_masks(event, idx);
                --> x86_pmu_disable_event(event);
                    --> wrmsrl(hwc->config_base, hwc->config & ~disable_mask);
                    --> if (is_counter_pair(hwc)) wrmsrl(x86_pmu_config_addr(hwc->idx + 1), 0);
                --> break;
            --> ...
            --> case INTEL_PMC_IDX_FIXED_BTS:
                --> intel_pmu_disable_bts();
                --> intel_pmu_drain_bts_buffer();
                --> return;
            --> ...
            // 滑移量
            --> if (unlikely(event->attr.precise_ip))
                // 禁用pebs事件
                --> intel_pmu_pebs_disable(event);
                    --> intel_pmu_drain_large_pebs(cpuc);
                        // pebs缓冲区处理
                        --> intel_pmu_drain_pebs_buffer();
                            --> x86_pmu.drain_pebs(NULL, &data);
                                --> __intel_pmu_pebs_event(event, iregs, data, ...);
                                    // 获取pebs采样数据
                                    --> setup_sample(event, iregs, at, data, regs);
                                    // 输出采样结果
                                    --> perf_event_output(event, data, regs);
                                    // 溢出采样结果
                                    --> perf_event_overflow(event, data, regs);
                    --> intel_pmu_pebs_via_pt_disable(event);
                    --> if (cpuc->enabled) wrmsrl(MSR_IA32_PEBS_ENABLE, cpuc->pebs_enabled);
        // 更新cpuc状态、事件状态
        --> __clear_bit(hwc->idx, cpuc->active_mask);
		--> cpuc->events[hwc->idx] = NULL;
        --> hwc->state |= PERF_HES_STOPPED;
        // 检查更新标志
        --> if ((flags & PERF_EF_UPDATE) && !(hwc->state & PERF_HES_UPTODATE))
            --> static_call(x86_pmu_update)(event);
                // static_call_update(x86_pmu_update, x86_pmu.update);
                // x86_pmu.update = intel_pmu_update
                // 更新事件计数、剩余采样周期
                --> x86_perf_event_update(event);
                    --> rdpmcl(hwc->event_base_rdpmc, new_raw_count);
                    --> local64_add(delta, &event->count);
                    --> local64_sub(delta, &hwc->period_left);
            --> hwc->state |= PERF_HES_UPTODATE;
```

主要步骤如下：

* 禁用事件。修改msr寄存器，禁用对应事件。在停止过程中，当存在滑移量时检查PEBS缓冲区，获取pebs采样数据后输出。
* 采样事件更新。更新采样剩余采样时间。

#### 8 销毁 -- `hw_perf_event_destroy`

采样事件的销毁接口设置为 `event->destroy = hw_perf_event_destroy`，实现过程如下：

```C
// file: arch/x86/events/core.c
static void hw_perf_event_destroy(struct perf_event *event)
    --> x86_release_hardware();
        --> if (atomic_dec_and_mutex_lock(&pmc_refcount, ...))
            // 释放资源
            --> release_pmc_hardware();
                --> num_counters = get_possible_num_counters();
                --> for (i = 0; i < num_counters; i++) 
                    --> release_perfctr_nmi(x86_pmu_event_addr(i));
                    --> release_evntsel_nmi(x86_pmu_config_addr(i));
            --> release_ds_buffers();
                --> for_each_possible_cpu(cpu)
                    --> release_ds_buffer(cpu);
                --> for_each_possible_cpu(cpu)
                    --> fini_debug_store_on_cpu(cpu);
                --> for_each_possible_cpu(cpu)
                    --> release_pebs_buffer(cpu);
                    --> release_bts_buffer(cpu);
            --> release_lbr_buffers();
                --> cpuc = per_cpu_ptr(&cpu_hw_events, cpu);
                --> kmem_cache = x86_get_pmu(cpu)->task_ctx_cache;
                --> kmem_cache_free(kmem_cache, cpuc->lbr_xsave);
                --> cpuc->lbr_xsave = NULL;
    --> atomic_dec(&active_events);
```

### 3.3 触发过程

在CPU-pmu初始化过程中，我们设置总是使用NMI，如下：

```C
// file: arch/x86/events/core.c
void perf_events_lapic_init(void)
{
    if (!x86_pmu.apic || !x86_pmu_initialized())
        return;
    apic_write(APIC_LVTPC, APIC_DM_NMI);
}
```

关于 NMI 的相关信息可以参考 [Handling Non-Maskable interrupts](https://0xax.gitbook.io/linux-insides/summary/interrupts/linux-interrupts-6).

#### 1 NMI中断

```C
// file: arch/x86/kernel/idt.c
// NMI 陷阱门设置
ISTG(X86_TRAP_NMI,		asm_exc_nmi, IST_INDEX_NMI),

// file: arch/x86/entry/entry_64.S
//NMI 处理入口
SYM_CODE_START(asm_exc_nmi)
    --> ...
    --> call	exc_nmi
    --> ...

// file: arch/x86/kernel/nmi.c
// NMI 处理实现
DEFINE_IDTENTRY_RAW(exc_nmi)
    --> ...
    --> default_do_nmi(regs);
        // 本地NMI处理
        --> handled = nmi_handle(NMI_LOCAL, regs);
            --> struct nmi_desc *desc = nmi_to_desc(type);
            --> list_for_each_entry_rcu(a, &desc->head, list)
                --> thishandled = a->handler(type, regs);
    --> ...
```

#### 2 本地NMI处理

在CPU-pmu初始化过程中，我们注册了本地NMI处理接口，如下：

```C
// file: arch/x86/events/core.c
register_nmi_handler(NMI_LOCAL, perf_event_nmi_handler, 0, "PMI");
```

实现过程如下：

```C
// file: arch/x86/events/core.c
static int perf_event_nmi_handler(unsigned int cmd, struct pt_regs *regs)
    --> static_call(x86_pmu_handle_irq)(regs);
        // static_call_update(x86_pmu_handle_irq, x86_pmu.handle_irq);
        // x86_pmu.handle_irq = intel_pmu_handle_irq,
        --> struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
        --> bool late_ack = hybrid_bit(cpuc->pmu, late_ack);
        --> bool mid_ack = hybrid_bit(cpuc->pmu, mid_ack);
        // early ack
        --> if (!late_ack && !mid_ack) apic_write(APIC_LVTPC, APIC_DM_NMI);
        // 1. 开始阶段
        // 禁用本地bts
        --> intel_bts_disable_local();
            --> struct bts_ctx *bts = this_cpu_ptr(&bts_ctx);
            --> if (bts->handle.event) 
                --> __bts_event_stop(bts->handle.event, BTS_STATE_INACTIVE);
                    --> WRITE_ONCE(bts->state, state);
                    --> intel_pmu_disable_bts();
        // 禁用所有采样事件
        --> __intel_pmu_disable_all(true);
        // bts采样记录输出
        --> handled = intel_pmu_drain_bts_buffer();
            --> base = (struct bts_record *)(unsigned long)ds->bts_buffer_base;
            --> top  = (struct bts_record *)(unsigned long)ds->bts_index;
            --> for (at = base; at < top; at++)
                --> perf_output_sample(&handle, &header, &data, event);
            --> event->hw.interrupts++;
            --> event->pending_kill = POLL_IN;
        // bts中断采样输出
        --> handled += intel_bts_interrupt();
            --> buf = perf_get_aux(&bts->handle);
            --> bts_update(bts);
            --> perf_aux_output_end(&bts->handle, local_xchg(&buf->data_size, 0));
        --> status = intel_pmu_get_status();
            --> rdmsrl(MSR_CORE_PERF_GLOBAL_STATUS, status);
        // 采集失败时，进入结束阶段
        --> if (!status) goto done;
        // again： 2. 采集数据阶段
        // 采集lbr数据
        --> intel_pmu_lbr_read();
            --> x86_pmu.lbr_read(cpuc);
                // x86_pmu.lbr_read	= intel_pmu_lbr_read_64,
                --> int num = x86_pmu.lbr_nr;
                --> for (i = 0; i < num; i++)
                    --> from = rdlbr_from(lbr_idx, NULL);
                        --> rdmsrl(x86_pmu.lbr_from + idx, val);
                    --> to   = rdlbr_to(lbr_idx, NULL);
                        --> rdmsrl(x86_pmu.lbr_to + idx, val);
                    --> br[out].from = from;
                    --> br[out].to	 = to;
                    --> ...
                --> cpuc->lbr_stack.nr = out;
	            --> cpuc->lbr_stack.hw_idx = tos;
            --> intel_pmu_lbr_filter(cpuc);
                --> for (i = 0; i < cpuc->lbr_stack.nr; i++) { ... }
        --> intel_pmu_ack_status(status);
            --> wrmsrl(MSR_CORE_PERF_GLOBAL_OVF_CTRL, ack);
        // 超过100次数时，退出
        --> if (++loops > 100)
            --> if (!warned) perf_event_print_debug();
            --> intel_pmu_reset();
            --> goto done;
        // 采样处理
        --> handled += handle_pmi_common(regs, status);
            // PEBS 采样数据处理
            --> if (__test_and_clear_bit(GLOBAL_STATUS_BUFFER_OVF_BIT, (unsigned long *)&status))
                --> x86_pmu_handle_guest_pebs(regs, &data);
                    --> for_each_set_bit(bit, (unsigned long *)&guest_pebs_idxs, ...)
                        --> event = cpuc->events[bit];
                        --> perf_sample_data_init(data, 0, event->hw.last_period);
                        --> if (perf_event_overflow(event, data, regs))
			                --> x86_pmu_stop(event, 0);
                --> x86_pmu.drain_pebs(regs, &data);
            // intel PT 采样数据处理
            --> if (__test_and_clear_bit(GLOBAL_STATUS_TRACE_TOPAPMI_BIT, (unsigned long *)&status))
                --> if (!perf_guest_handle_intel_pt_intr())
                    --> intel_pt_interrupt();
            // Intel Perf metrics
            --> if (__test_and_clear_bit(GLOBAL_STATUS_PERF_METRICS_OVF_BIT, (unsigned long *)&status))
                --> static_call(intel_pmu_update_topdown_event)(NULL);
                    // DEFINE_STATIC_CALL(intel_pmu_update_topdown_event, x86_perf_event_update);
            // 事件采样输出
            --> for_each_set_bit(bit, (unsigned long *)&status, X86_PMC_IDX_MAX)
                --> struct perf_event *event = cpuc->events[bit];
                --> if (!intel_pmu_save_and_restart(event)) continue;
                    // 事件更新
                    --> static_call(x86_pmu_update)(event);
                    --> if (unlikely(event_is_checkpointed(event)))
                        --> wrmsrl(event->hw.event_base, 0);
                        --> local64_set(&event->hw.prev_count, 0);
                    // 采样周期更新
                    --> static_call(x86_pmu_set_period)(event);
                // 采样数据初始化
                --> perf_sample_data_init(&data, 0, event->hw.last_period);
                --> if (has_branch_stack(event))
                    // lbr栈信息更新
                    --> perf_sample_save_brstack(&data, event, &cpuc->lbr_stack)
                // 采样事件输出
                --> if (perf_event_overflow(event, &data, regs))
                    --> x86_pmu_stop(event, 0);
            --> status = intel_pmu_get_status();
            // 一直采样
            --> if (status) goto again;
        // done：3. 结束阶段
        --> if (mid_ack) apic_write(APIC_LVTPC, APIC_DM_NMI);
        --> cpuc->enabled = pmu_enabled;
        // 开启所有事件
        --> if (pmu_enabled) __intel_pmu_enable_all(0, true);
        // 启用本地bts
        --> intel_bts_enable_local();
            --> if (bts->handle.event)
                --> __bts_event_start(bts->handle.event);
                    --> bts_config_buffer(buf);
                    --> WRITE_ONCE(bts->state, BTS_STATE_ACTIVE);
                    --> intel_pmu_enable_bts(config);
        --> if (late_ack) apic_write(APIC_LVTPC, APIC_DM_NMI);
    // 采样周期统计
    --> perf_sample_event_took(finish_clock - start_clock);
```

主要步骤如下：

* 开始阶段。该阶段禁用本地bts、禁用所有的采样事件、bts采样数据输出；
* 采样输出阶段。该阶段逐项检查PEBS、PT、METRICS、采样事件，对PEBS、采样事件进行采样输出。
* 结束阶段。该阶段开启所有的采样事件、开启本地bts.

#### 3 采样数据输出

```C
// file: kernel/events/core.c
int perf_event_overflow(struct perf_event *event, struct perf_sample_data *data, struct pt_regs *regs)
    --> __perf_event_overflow(event, 1, data, regs);
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

#### 4 设置BPF程序

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

static int perf_event_set_bpf_handler(struct perf_event *event, struct bpf_prog *prog, u64 bpf_cookie)
{
    ...
    event->prog = prog;
    event->bpf_cookie = bpf_cookie;
    event->orig_overflow_handler = READ_ONCE(event->overflow_handler);
    WRITE_ONCE(event->overflow_handler, bpf_overflow_handler);
}
```

CPU采样事件不属于追踪事件，通过 `perf_event_set_bpf_handler` 设置bpf程序到 `event->prog` 中。

#### 5 调用BPF程序

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

### 3.4 BTS-PMU

在使用CPU-pmu事件过程中，我们看到BTS相关信息。Intel BTS的性能分析器来识别和解决性能瓶颈，可以帮助找出代码中的热点，了解函数调用和内存使用情况。注册过程如下：

```C
// file: arch/x86/events/intel/bts.c
static __init int bts_init(void)
{
    if (!boot_cpu_has(X86_FEATURE_DTES64) || !x86_pmu.bts)
        return -ENODEV;
    if (boot_cpu_has(X86_FEATURE_PTI))
        return -ENODEV;

    bts_pmu.capabilities	= PERF_PMU_CAP_AUX_NO_SG | PERF_PMU_CAP_ITRACE |
                PERF_PMU_CAP_EXCLUSIVE;
    bts_pmu.task_ctx_nr	= perf_sw_context;
    bts_pmu.event_init	= bts_event_init;
    bts_pmu.add		= bts_event_add;
    bts_pmu.del		= bts_event_del;
    bts_pmu.start		= bts_event_start;
    bts_pmu.stop		= bts_event_stop;
    bts_pmu.read		= bts_event_read;
    bts_pmu.setup_aux	= bts_buffer_setup_aux;
    bts_pmu.free_aux	= bts_buffer_free_aux;

    return perf_pmu_register(&bts_pmu, "intel_bts", -1);
}
arch_initcall(bts_init);
```

`bts_pmu` 通过设置 `INTEL_PMC_IDX_FIXED_BTS` 标志位开启/停止BTS采样事件，采样结果存放到bts缓冲区中。`bts_pmu` 具体的实现过程暂时略过。

## 4 总结

本文通过`profile`示例程序分析了CPU-PMU的内核实现过程。`profile` 程序将BPF程序挂载到所有在线的CPU上，通过NMI触发挂载的BPF程序。

## 参考资料

[Handling Non-Maskable interrupts](https://0xax.gitbook.io/linux-insides/summary/interrupts/linux-interrupts-6)