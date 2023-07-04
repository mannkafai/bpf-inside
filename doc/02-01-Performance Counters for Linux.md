# Linux性能计数器在内核的实现

## 0 前言

在上篇中，我们借助libbpf实现了一个简单的BPF程序，借助 `perf_event_open` 系统调用将BPF程序挂载在 `syscalls/sys_enter_write` 事件下，今天我们将分析 `perf_event_open` 在内核中的实现过程。

## 1 PCL简介

性能计数器是大多数现代CPU上可用的特殊硬件寄存器。这些寄存器对某些类型的硬件事件的数量进行计数（例如：执行的指令、缓存未命中或错误预测的分支）而不会减慢内核或应用程序的速度。当事件数量达到阈值时，这些寄存器还可以触发中断，因此可以用于分析在该 CPU 上运行的代码。

Linux性能计数器(PCL，Performance Counters for Linux)子系统提供了这些硬件功能的抽象，它提供每个任务和每个 CPU 计数器、计数器组，并在此基础上提供事件功能。除此之外，还可以测量软件事件，如：页面错误和上下文切换等。

Linux性能计数器作为收集和分析性能数据的框架，提供性能测量功能有：

* 硬件和软件事件计数
* 事件采样/跟踪
* 各种计数器调度和工作负载测量功能（每个任务、每个CPU、每个子层次结构等）
* 自我和远程测量
* CPU-硬件和软件事件的独立抽象/枚举

性能计数器通过性能监测单元(PMU, Performance Monitor Unit) 实现数据的采集。通过 `perf_event_open` 创建文件描述符，基于文件描述符进行常用的VFS系统调用，如：`read()` 读取计数器，`fcntl()` 可以用来设置阻塞模式。多个计数器可以同时保持打开状态，使用 `poll()` 进行管理。

## 2 获取perf事件

我们通过 `perf_event_open` 系统调用来获取性能计数器的fd，[perf_event_open](https://elixir.bootlin.com/linux/v6.2/source/kernel/events/core.c#L12296) 的函数定义如下：

```C
SYSCALL_DEFINE5(perf_event_open,
		struct perf_event_attr __user *, attr_uptr,
		pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
{
    ...
}
```

### 2.1 参数介绍

`perf_event_open` 系统调用有5个参数，如下：

* 第一个参数：`struct perf_event_attr* attr_uptr`
  
我们来看第一个参数 `attr_uptr`, 是 [perf_event_attr](https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/perf_event.h#L384) 类型的结构，该参数比较复杂，它确定了性能计数器的数据来源、采样设置、采样数据输出类型和方式。定义如下：

```C
struct perf_event_attr {
    __u32   type;       /* Major type: hardware/software/tracepoint/etc. */
    __u32   size;       /* Size of the attr structure, for fwd/bwd compat. */
    __u64   config;     /* Type specific configuration information. */
    union {
        __u64   sample_period;
        __u64   sample_freq;
    };
    __u64   sample_type;
    __u64   read_format;

    __u64   disabled       :  1, /* off by default        */
            inherit        :  1, /* children inherit it   */
            pinned	       :  1, /* must always be on PMU */
            exclusive      :  1, /* only group on PMU     */
            exclude_user   :  1, /* don't count user      */
            exclude_kernel :  1, /* ditto kernel          */
            exclude_hv     :  1, /* ditto hypervisor      */
            exclude_idle   :  1, /* don't count when idle */
            mmap           :  1, /* include mmap data     */
            comm	       :  1, /* include comm data     */
            freq           :  1, /* use freq, not period  */
            ...
            ...
            __reserved_1   : 26;

    union {
        __u32       wakeup_events;      /* wakeup every n events */
        __u32       wakeup_watermark;   /* bytes before wakeup   */
    };

    __u32           bp_type;
    union {
        __u64       bp_addr;
        __u64       kprobe_func; /* for perf_kprobe */
        __u64       uprobe_path; /* for perf_uprobe */
        __u64       config1; /* extension of config */
    };
    union {
        __u64       bp_len;
        __u64       kprobe_addr; /* when kprobe_func == NULL */
        __u64       probe_offset; /* for perf_[k,u]probe */
        __u64       config2; /* extension of config1 */
    };
    __u64   branch_sample_type; /* enum perf_branch_sample_type */

    __u64   sample_regs_user; /*  Defines set of user regs to dump on samples. */
    __u32   sample_stack_user; /* Defines size of the user stack to dump on samples. */

    __s32   clockid;
    __u64   sample_regs_intr;

    __u32   aux_watermark;
    __u16   sample_max_stack;
    __u16   __reserved_2;
    __u32   aux_sample_size;
    __u32   __reserved_3;

    __u64   sig_data;
};
```

`type` 字段表示PMU类型，支持以下类型:

```C
enum perf_type_id {
	PERF_TYPE_HARDWARE			= 0,
	PERF_TYPE_SOFTWARE			= 1,
	PERF_TYPE_TRACEPOINT			= 2,
	PERF_TYPE_HW_CACHE			= 3,
	PERF_TYPE_RAW				= 4,
	PERF_TYPE_BREAKPOINT			= 5,

	PERF_TYPE_MAX,				/* non-ABI */
};
```

Linux支持动态PMU，可以在类型中使用内核导出的值来指示使用的PMU。每个PMU在 `/sys/bus/event_source/devices/` 下都有一个子目录。在每个子目录下都有一个 `type` 的文件，其内容表示在该字段使用的整数。

`size` 字段表示整个 `perf_event_attr` 结构的大小，

`config` 字段表示指定 `pmu` 配置信息，不同类型的pmu有不同的配置。`config1` 和 `config2` 是改字段的扩展。

`sample_period` 和 `sample_freq` 表示 `周期/频率`采样的值，`freq:1` 字段确定是周期采样还是频率采样；

`sample_type` 表示在采样数据时，保存在样本中的值，如下：

```C
enum perf_event_sample_format {
	PERF_SAMPLE_IP				= 1U << 0,
	PERF_SAMPLE_TID				= 1U << 1,
	PERF_SAMPLE_TIME			= 1U << 2,
	...
	...
	PERF_SAMPLE_MAX = 1U << 25,		/* non-ABI */
};
```

`read_format` 字段表示读取 `counter` 数据时，读取的格式。如下：

```C
enum perf_event_read_format {
	PERF_FORMAT_TOTAL_TIME_ENABLED		= 1U << 0,
	PERF_FORMAT_TOTAL_TIME_RUNNING		= 1U << 1,
	PERF_FORMAT_ID				= 1U << 2,
	PERF_FORMAT_GROUP			= 1U << 3,
	PERF_FORMAT_LOST			= 1U << 4,

	PERF_FORMAT_MAX = 1U << 5,		/* non-ABI */
};
```

`disabled:1`，`inherit:1` 等bit标志位，表示一些设置信息。如： `disabled` 设置初始状态；`inherit` 表示是否统计计数器进程对应的子孙后代进程（仅限于新的后代）；`pinned` 表示计数器应始终位于CPU上, 仅适用于硬件计数器并且仅适用于组长；`exclusive` 表示当前计数器组在CPU上时，它应该是唯一使用CPU计数器的组；`exclude_user`，  `exclude_kernel` 和 `exclude_hv` 提供了将事件计数限制为CPU 处于用户、内核或管理程序模式时的时间方法；...

`wakeup_events`， `wakeup_watermark` 表示发生溢出信号前的采样数 (wakeup_events) 或 字节数 (wakeup_watermark)，通过 `watermark:1` 标志来区分。 

`bp_type` 表示断点类型， `bp_addr` 表示断点地址，`bp_len` 表示断点长度。

`branch_sample_type` 表示在启用 `PERF_SAMPLE_BRANCH_STACK` 时, 指定在分支记录中包括哪些分支。

`sample_regs_user` 表示在样本上转存的用户空间CPU寄存器的集合。

`sample_stack_user` 表示在启用 `PERF_SAMPLE_STACK_USER` 时, 转存的用户空间栈大小。

`clockid` 表示使用的指定的时钟。

* 第二参数：`pid_t pid`
  
该参数从进程维度确定event的来源, 有三种情况：
pid == 0 : event绑定到当前进程；
pid > 0 : event绑定到指定进程；
pid < 0 : event绑定到所有进程；

* 第三个参数：`int cpu`

该参数从CPU维度确定event的来源，有两种情况：
cpu >= 0 : event绑定到指定的CPU；
cpu < 0 : event绑定到所有的CPU；

**不支持pid == -1 && cpu == -1 的情形**，即绑定所有CPU的所有进程的情况。

* 第四个参数：`int group_fd`

该参数确定event的组长（group leader）。
group_fd = -1 : 创建一个新的group leader；
group_fd > 0 : 加入到之前创建的group leader中；

* 第五个参数：`unsigned long flags`

创建该event的FD标志信息，如下：

```C
#define PERF_FLAG_FD_NO_GROUP		(1UL << 0)
#define PERF_FLAG_FD_OUTPUT		(1UL << 1)
#define PERF_FLAG_PID_CGROUP		(1UL << 2) /* pid=cgroup id, per-cpu mode only */
#define PERF_FLAG_FD_CLOEXEC		(1UL << 3) /* O_CLOEXEC */
```

### 2.2 主要实现过程

`perf_event_open` 的主要实现过程如下：

```C
SYSCALL_DEFINE5(perf_event_open, ..)
    --> err = security_perf_event_open(&attr, PERF_SECURITY_OPEN);
    --> event_fd = get_unused_fd_flags(f_flags);
    --> err = perf_fget_light(group_fd, &group);
    --> task = find_lively_task_by_vpid(pid);
    --> event = perf_event_alloc(&attr, cpu, task, group_leader, NULL, NULL, NULL, cgroup_fd);
        --> event = kmem_cache_alloc_node(perf_event_cache, GFP_KERNEL | __GFP_ZERO, node);
        --> init_irq_work(&event->pending_irq, perf_pending_irq);
        --> init_task_work(&event->pending_task, perf_pending_task);
        --> event->hw.target = get_task_struct(task);
        --> event->overflow_handler = perf_event_output_forward;
        --> pmu = perf_init_event(event);
            --> pmu = idr_find(&pmu_idr, type); // or pmus
            --> ret = perf_try_init_event(pmu, event);
                --> event->pmu = pmu;
                --> ret = pmu->event_init(event);
        --> err = perf_cgroup_connect(cgroup_fd, event, attr, group_leader);
        --> err = exclusive_event_init(event);
        --> account_event(event);
    --> ctx = find_get_context(task, event);
        --> !task // CPU维度
            --> cpuctx = per_cpu_ptr(&perf_cpu_context, event->cpu);
            --> ctx = &cpuctx->ctx;
        --> task != null
            --> ctx = perf_lock_task_context(task, &flags);
                --> ctx = rcu_dereference(task->perf_event_ctxp);
            --> !ctx
                --> ctx = alloc_perf_context(task); 
                    --> ctx = kzalloc(sizeof(struct perf_event_context), GFP_KERNEL);
                --> rcu_assign_pointer(task->perf_event_ctxp, ctx);
    --> pmu_ctx = find_get_pmu_context(pmu, ctx, event); //perf_event_pmu_context
        --> !ctx->task // CPU维度
            --> cpc = per_cpu_ptr(pmu->cpu_pmu_context, event->cpu);
		    --> epc = &cpc->epc;
            --> list_add(&epc->pmu_ctx_entry, &ctx->pmu_ctx_list); //first add
        --> new = kzalloc(sizeof(*epc), GFP_KERNEL); 
        --> list_add(&epc->pmu_ctx_entry, &ctx->pmu_ctx_list); //epc = new
	    --> epc->ctx = ctx;
    --> event->pmu_ctx = pmu_ctx;
    --> err = perf_event_set_output(event, output_event);  // output_event not null
        --> rb = ring_buffer_get(output_event);
        --> ring_buffer_attach(event, rb);
    --> perf_event_validate_size(event);
        --> __perf_event_read_size(event, event->group_leader->nr_siblings + 1);
        --> __perf_event_header_size(event, event->attr.sample_type & ~PERF_SAMPLE_READ);
        --> perf_event__id_header_size(event);
        --> event->read_size + event->header_size + event->id_header_size + 
            sizeof(struct perf_event_header) >= 16*1024
    --> perf_get_aux_event(event, group_leader);
    --> exclusive_event_installable(event, ctx);
        --> exclusive_event_match(iter_event, event);
    --> event_file = anon_inode_getfile("[perf_event]", &perf_fops, event, f_flags);
    --> move_group
    --> perf_event__header_size(event);
    --> perf_event__id_header_size(event);
    --> perf_install_in_context(ctx, event, event->cpu);
        --> add_event_to_ctx(event, ctx);
            --> list_add_event(event, ctx);
                --> list_add_rcu(&event->event_entry, &ctx->event_list);
            --> perf_group_attach(event);
                --> list_add_tail(&event->sibling_list, &group_leader->sibling_list);
    --> list_add_tail(&event->owner_entry, &current->perf_event_list);
    --> fd_install(event_fd, event_file);
        --> rcu_assign_pointer(fdt->fd[fd], file);
```

主要过程如下：

* 必要的参数检查和权限检查
  
检查是否运行访问、是否有足够的权限、采用频率/周期是否允许、采样数据是否运行 等等。

* 获取 `event_fd`, group leader, task
 
调用 `get_unused_fd_flags` 函数获取 `event_fd`。根据 `group_fd`、`pid` 获取对应的 group leader 和 task, 检查 `inherit` 是否匹配。

* 创建 `event` -- `perf_event_alloc`

通过 `perf_event_alloc` 函数创建 `event`, 在分配内存后，对其属性进行初始化和设置。主要的属性如下：

- `cpu` : 设置的cpu；
- `group_leader` : 事件组长；
- `ns` : 命名空间;
- `id` : 事件id；
- `state` : 状态；
- `clock` : 时钟，默认：local_clock;
- `overflow_handler` : 溢出事件处理函数；
- `overflow_handler_context` : 溢出事件处理函数上下文；
- `pmu` : 性能管理单元, 从`parent`继承，或通过`type`字段从`pmu_idr` (或 `pmus` )中获取。

* 获取上下文 -- `find_get_context`
  
通过 `find_get_context` 获取上下文。绑定CPU时，获取 `perf_cpu_context` 的 per-CPU 变量即可；绑定任务时，获取 `task->perf_event_ctxp` 变量。

* 检查事件组
  
在指定 `group_leader` 的情况下，检查相关检查。检查是否需要移动事件组，pmu是否匹配等。

* 获取pmu上下文 -- `find_get_pmu_context`

通过 `find_get_pmu_context` 获取。绑定CPU时，获取 `pmu->cpu_pmu_context` 的 per-CPU变量；绑定任务时，创建新的上下文。获取之后，添加到pmu上下文列表中。

* 设置事件输出 -- `perf_event_set_output`

在 `output_event` 存在的情况下( `group_fd != -1` 并且设置了 `PERF_FLAG_FD_OUTPUT` )， 将输出信息设置为 `group_leader` 的输出，通过 `ring_buffer_attach`  实现。

* 检查事件空间是否足够
  
通过 `perf_event_validate_size` 验证事件空间是否足够。所有的事件需要的内存不能超过 16KB。

* 设置辅助事件 -- `perf_get_aux_event`

在需要辅助事件时，`perf_get_aux_event` 检查并设置辅助事件。

* 检查event是否重复

通过 `exclusive_event_installable` 检查在同一个ctx下是否存在重复的事件。

* 分配事件文件 -- `anon_inode_getfile`

通过 `anon_inode_getfile` 创建了事件文件，设置该文件的 `ops` 为 `perf_fops`。如下：

```C
static const struct file_operations perf_fops = {
	.llseek			= no_llseek,
	.release		= perf_release,
	.read			= perf_read,
	.poll			= perf_poll,
	.unlocked_ioctl		= perf_ioctl,
	.compat_ioctl		= perf_compat_ioctl,
	.mmap			= perf_mmap,
	.fasync			= perf_fasync,
};
```

* 移动group

在需要移动group的情况，移动group。

* 重新计算大小
  
通过 `perf_event__header_size` 和 `perf_event__id_header_size` 计算实现头部和id头部大小。

* 添加事件到上下文中 -- `perf_install_in_context`

`perf_install_in_context` 函数通过直接调用、`cpu_function_call`, `task_function_call`等多种途径调用 `add_event_to_ctx` ，实现事件的添加。

* 添加事件到当前进程中

通过 `list_add_tail` 函数将event添加到 `current->perf_event_list` 中。

* 关联文件 -- `fd_install`

通过 `fd_install` 关联 event_fd 和 event_file。

以上就是 `perf_event_open` 实现的主要过程。在事件创建完成后，我们可以通过返回的文件fd进行 `read`，`poll`, `ioctl`, `mmap`, `fasync` 等操作。

## 3 perf事件的调度过程

在CPU调度过程中，在进行任务上下文切换perf事件。在切换任务前调用 `perf_event_task_sched_out` , 在切换任务后调用 `perf_event_task_sched_in` 。主要的实现过程如下：

```C
schedule()
    --> __schedule(SM_NONE);
        --> next = pick_next_task(rq, prev, &rf); //struct task_struct *
        --> rq = context_switch(rq, prev, next, &rf);
            --> prepare_task_switch(rq, prev, next);
                --> perf_event_task_sched_out(prev, next);
                    --> __perf_sw_event_sched(PERF_COUNT_SW_CONTEXT_SWITCHES, 1, 0);
                    --> __perf_sw_event_sched(PERF_COUNT_SW_CGROUP_SWITCHES, 1, 0);
                    --> __perf_event_task_sched_out(prev, next);
                        --> perf_pmu_sched_task(task, next, false); // perf_sched_cb_usages > 0
                            --> __perf_pmu_sched_task(cpc, sched_in); //sched_cb_list
                                --> perf_pmu_disable(pmu);
                                    --> pmu->pmu_disable(pmu);
                                --> pmu->sched_task(cpc->task_epc, sched_in);
                                --> perf_pmu_enable(pmu);
                                    --> pmu->pmu_enable(pmu);
                        --> perf_event_switch(task, next, false); // nr_switch_events > 0
                            --> perf_iterate_sb(perf_event_switch_output, &switch_event, NULL);
                                --> perf_iterate_ctx(task_ctx, output, data, false); // task_ctx 
                                    --> output(event, data); //perf_event_switch_output  ctx->event_list 
                                        --> perf_event_header__init_id(&se->event_id.header, &sample, event);
                                        --> ret = perf_output_begin(&handle, &sample, event, se->event_id.header.size);
                                        --> perf_output_put(&handle, se->event_id.header);
                                        --> perf_event__output_id_sample(event, &handle, &sample);
                                        --> perf_output_end(&handle);
                                --> perf_iterate_sb_cpu(output, data); // this_cpu_ptr(&pmu_sb_events)->list
                                    --> output(event, data); // perf_event_switch_output 
                                --> perf_iterate_ctx(ctx, output, data, false); // current->perf_event_ctxp
                        --> perf_event_context_sched_out(task, next);
                            --> perf_ctx_disable(ctx);
                                --> perf_pmu_disable(pmu_ctx->pmu); //ctx->pmu_ctx_list
                            --> perf_ctx_sched_task_cb(ctx, false);
                                --> pmu_ctx->pmu->sched_task(pmu_ctx, sched_in);
                            --> perf_event_swap_task_ctx_data(ctx, next_ctx); // same ctx or same parent
                                --> prev_epc->pmu->swap_task_ctx(prev_epc, next_epc);
                            --> task_ctx_sched_out(ctx, EVENT_ALL); // different ctx
                                --> ctx_sched_out(ctx, event_type);
                                    --> __pmu_ctx_sched_out(pmu_ctx, is_active);
                                        --> perf_pmu_disable(pmu);
                                        --> group_sched_out(event, ctx); //pmu_ctx->pinned_active
                                            --> event_sched_out(group_event, ctx);
                                                --> list_del_init(&event->active_list);
                                                --> perf_pmu_disable(event->pmu);
                                                --> event->pmu->del(event, 0);
                                                --> perf_pmu_enable(event->pmu);
                                            --> event_sched_out(event, ctx); //sibling_list
                                        --> group_sched_out(event, ctx); //pmu_ctx->flexible_active
                                        --> perf_pmu_enable(pmu);
                            --> perf_ctx_enable(ctx);
                                --> perf_pmu_enable(pmu_ctx->pmu); //ctx->pmu_ctx_list
                        --> perf_cgroup_switch(next);
                            --> cgrp = perf_cgroup_from_task(task, NULL);
                            --> perf_ctx_disable(&cpuctx->ctx);
                            --> ctx_sched_out(&cpuctx->ctx, EVENT_ALL);
                            --> cpuctx->cgrp = cgrp;
                            --> ctx_sched_in(&cpuctx->ctx, EVENT_ALL);
                            --> perf_ctx_enable(&cpuctx->ctx);
            --> switch_to(prev, next, prev);
            --> finish_task_switch(prev);
                --> perf_event_task_sched_in(prev, current);
                    --> __perf_event_task_sched_in(prev, task);
                        --> perf_event_context_sched_in(task);
                            --> perf_ctx_disable(ctx);
                            --> perf_ctx_disable(&cpuctx->ctx);
                            --> ctx_sched_out(&cpuctx->ctx, EVENT_FLEXIBLE);
                            --> perf_event_sched_in(cpuctx, ctx);
                                --> ctx_sched_in(&cpuctx->ctx, EVENT_PINNED);
                                    --> ctx_pinned_sched_in(ctx, NULL);
                                        --> visit_groups_merge(ctx, &ctx->pinned_groups, ...);
                                            --> ret = func(*evt, data); // merge_sched_in
                                                --> event_filter_match(event);
                                                --> group_sched_in(event, ctx);
                                                    --> pmu->start_txn(pmu, PERF_PMU_TXN_ADD);
                                                    --> event_sched_in(group_event, ctx);
                                                        --> perf_event_set_state(event, PERF_EVENT_STATE_ACTIVE);
                                                        --> perf_log_throttle(event, 1);
                                                        --> perf_pmu_disable(event->pmu);
                                                        --> perf_log_itrace_start(event);
                                                        --> event->pmu->add(event, PERF_EF_START)
                                                        --> perf_pmu_enable(event->pmu);
                                                    --> event_sched_in(event, ctx); // sibling_list
                                                    --> pmu->commit_txn(pmu);
                                                --> list_add_tail(&event->active_list, get_event_list(event));
                                                --> cpc = this_cpu_ptr(event->pmu_ctx->pmu->cpu_pmu_context);
                                                --> perf_mux_hrtimer_restart(cpc);
                                                --> group_update_userpage(event);
                                    --> ctx_flexible_sched_in(ctx, NULL);
                                        --> visit_groups_merge(ctx, &ctx->flexible_groups, ...);
                                --> ctx_sched_in(ctx, EVENT_PINNED);
                                --> ctx_sched_in(&cpuctx->ctx, EVENT_FLEXIBLE);
                                --> ctx_sched_in(ctx, EVENT_FLEXIBLE);
                            --> perf_ctx_sched_task_cb(cpuctx->task_ctx, true);
                            --> perf_ctx_enable(&cpuctx->ctx);
                            --> perf_ctx_enable(ctx);
                        --> perf_event_switch(task, prev, true);
                        --> perf_pmu_sched_task(prev, task, true);
                    --> __perf_sw_event_sched(PERF_COUNT_SW_CPU_MIGRATIONS, 1, 0);
```

`perf_event_task_sched_out` 主要执行过程如下：

* 软件事件调度（切出事件）
  
在软件事件开启的情况下，调用 `__perf_sw_event_sched` 进行软件事件处理，处理过程将在后续介绍。这里进行 `PERF_COUNT_SW_CONTEXT_SWITCHES` 和 `PERF_COUNT_SW_CGROUP_SWITCHES` 事件处理。

* PMU上下文切换（切出事件）-- `perf_pmu_sched_task`

存在 `perf_sched_cb_usages` 时，遍历当前CPU中的 `sched_cb_list` 列表，通知PMU切出事件， 通过`pmu->sched_task` 函数实现。

* event切换事件（切出事件） -- `perf_event_switch`

存在 `nr_switch_events` 时，即，需要统计切换事件时。`perf_event_switch` 函数记录切换采样数据，通过 `perf_event_switch_output` 函数采样并记录。参与记录的上下文包括：`task_ctx`, 当前CPU的 `pmu_sb_events`，当前任务的 `perf_event_ctxp` 。

* event上下文切出 -- `perf_event_context_sched_out`

`perf_event_context_sched_out` 完成perf事件上下文的切出。在当前任务和待运行任务间有关联关系时，通过 `pmu->swap_task_ctx(prev_epc, next_epc)` 切换任务上下文即可。否则，调用 `task_ctx_sched_out` 将当前任务上下文中所有的event切出。`event_sched_out` 函数通过 `event->pmu->del(event, 0)` 实现event的删除。

* cgroup上下文切换 -- `perf_cgroup_switch`

在 `cgroup` 事件存在时进行cgroup切换。将当前cpu上的所有事件切出后，设置`cgrp`后，在切入。


`perf_event_task_sched_in` 的执行过程与 `perf_event_task_sched_out` 相反。主要执行过程如下：

* event上下文切入 -- `perf_event_context_sched_in`

`perf_event_context_sched_in` 完成perf事件上下文的切入。 将 当前CPU、当前任务事件上下文中 `EVENT_PINNED`, `EVENT_FLEXIBLE` 事件切入。 `event_sched_in` 函数通过 `event->pmu->add(event, PERF_EF_START)` 实现event的添加。

* event切换事件（切入事件） -- `perf_event_switch`

调用 `perf_event_switch` 记录切入事件。

* PMU上下文切换（切入事件）-- `perf_pmu_sched_task`

调用 `perf_pmu_sched_task` 通知PMU切入事件。

* 软件事件调度（切入事件）
  
在软件事件开启的情况下，进行 `PERF_COUNT_SW_CPU_MIGRATIONS` 事件处理。

## 4 perf事件的ioctl控制

在创建perf_file时，设置了文件的 `ops` 接口，如下：

```C
static const struct file_operations perf_fops = {
	.llseek			= no_llseek,
	.release		= perf_release,
	.read			= perf_read,
	.poll			= perf_poll,
	.unlocked_ioctl		= perf_ioctl,
	.compat_ioctl		= perf_compat_ioctl,
	.mmap			= perf_mmap,
	.fasync			= perf_fasync,
};
```

我们可以通过 `ioctl` 系统调用实现对perf事件的控制，可控制的操作如下：

```C
#define PERF_EVENT_IOC_ENABLE			_IO ('$', 0)
#define PERF_EVENT_IOC_DISABLE			_IO ('$', 1)
#define PERF_EVENT_IOC_REFRESH			_IO ('$', 2)
#define PERF_EVENT_IOC_RESET			_IO ('$', 3)
#define PERF_EVENT_IOC_PERIOD			_IOW('$', 4, __u64)
#define PERF_EVENT_IOC_SET_OUTPUT		_IO ('$', 5)
#define PERF_EVENT_IOC_SET_FILTER		_IOW('$', 6, char *)
#define PERF_EVENT_IOC_ID			_IOR('$', 7, __u64 *)
#define PERF_EVENT_IOC_SET_BPF			_IOW('$', 8, __u32)
#define PERF_EVENT_IOC_PAUSE_OUTPUT		_IOW('$', 9, __u32)
#define PERF_EVENT_IOC_QUERY_BPF		_IOWR('$', 10, struct perf_event_query_bpf *)
#define PERF_EVENT_IOC_MODIFY_ATTRIBUTES	_IOW('$', 11, struct perf_event_attr *)
```

可以看到支持的功能比较丰富，我们只关注其中的 `ENABLE`, `DISABLE`, `RESET`, `REFRESH`, `SET_BPF` 这几个操作。

* PERF_EVENT_IOC_ENABLE

该指令开启perf事件，实现如下：

```C
	case PERF_EVENT_IOC_ENABLE:
		func = _perf_event_enable;
		break;
	...
	if (flags & PERF_IOC_FLAG_GROUP)
		perf_event_for_each(event, func); //all group
	else
		perf_event_for_each_child(event, func); // event and child
```

`perf_event_for_each` 从group_leader开始，处理整个group的事件，过程中调用 `perf_event_for_each_child` 。 `perf_event_for_each_child` 处理本事件及其子事件。

`_perf_event_enable` 实现过程如下：

```C
static void _perf_event_enable(struct perf_event *event)
    --> event_function_call(event, __perf_event_enable, NULL);
        --> cpu_function_call(event->cpu, event_function, &efs); //ctx->task is null
            --> event_function(info);
                --> efs->func(event, cpuctx, ctx, efs->data); // __perf_event_enable
        --> task_function_call(task, event_function, &efs); // cpu is off
            --> event_function(info);
                --> efs->func(event, cpuctx, ctx, efs->data); // __perf_event_enable
        --> func(event, NULL, ctx, data); // __perf_event_enable

static void __perf_event_enable(struct perf_event *event, struct perf_cpu_context *cpuctx,
                struct perf_event_context *ctx, void *info)
    -->	ctx_sched_out(ctx, EVENT_TIME); // if (ctx->is_active)
    --> perf_event_set_state(event, PERF_EVENT_STATE_INACTIVE);
    --> perf_cgroup_event_enable(event, ctx);
        --> cpuctx->cgrp = perf_cgroup_from_task(current, ctx);
    --> ctx_sched_in(ctx, EVENT_TIME); 
    --> ctx_resched(cpuctx, task_ctx, get_event_type(event));
        --> perf_ctx_disable(&cpuctx->ctx);
        --> perf_ctx_disable(task_ctx);
        --> task_ctx_sched_out(task_ctx, event_type);
        --> ctx_sched_out(&cpuctx->ctx, event_type); // ctx_sched_out(&cpuctx->ctx, EVENT_FLEXIBLE);
        --> perf_event_sched_in(cpuctx, task_ctx);
        --> perf_ctx_enable(&cpuctx->ctx);
        --> perf_ctx_enable(task_ctx);
```

`_perf_event_enable` 通过 `event_function_call` 调用 `__perf_event_enable` 函数。`event_function_call` 通过 `cpu_function_call` , `task_function_call` 和直接调用方式调用指定的函数。`__perf_event_enable` 通过 `ctx_sched_out`，`ctx_sched_in`，`ctx_resched` 实现事件的开启。

* PERF_EVENT_IOC_DISABLE

该指令关闭perf事件，实现如下：

```C
	case PERF_EVENT_IOC_DISABLE:
		func = _perf_event_disable;
		break;
	...
	if (flags & PERF_IOC_FLAG_GROUP)
		perf_event_for_each(event, func); //all group
	else
		perf_event_for_each_child(event, func); // event and child
```

`_perf_event_disable` 实现过程如下：

```C
static void _perf_event_disable(struct perf_event *event)
    --> event_function_call(event, __perf_event_disable, NULL);

static void __perf_event_disable(struct perf_event *event, struct perf_cpu_context *cpuctx,
                struct perf_event_context *ctx, void *info)
    -->	perf_pmu_disable(event->pmu_ctx->pmu);
    --> group_sched_out(event, ctx); // if (event == event->group_leader)
    --> event_sched_out(event, ctx); // if (event != event->group_leader)
    --> perf_event_set_state(event, PERF_EVENT_STATE_OFF);
    --> perf_cgroup_event_disable(event, ctx);
        --> cpuctx->cgrp = NULL;
    --> perf_pmu_enable(event->pmu_ctx->pmu);
```

`_perf_event_disable` 通过 `event_function_call` 方式调用 `__perf_event_enable` 函数。`__perf_event_disable` 通过 `group_sched_out`，`event_sched_out` 实现事件的停止。

* PERF_EVENT_IOC_RESET

该指令重置perf事件，实现如下：

```C
	case PERF_EVENT_IOC_RESET:
		func = _perf_event_reset;
		break;
	...
	if (flags & PERF_IOC_FLAG_GROUP)
		perf_event_for_each(event, func); //all group
	else
		perf_event_for_each_child(event, func); // event and child
```

`_perf_event_reset` 实现过程如下：

```C
static void _perf_event_reset(struct perf_event *event)
    --> (void)perf_event_read(event, false);
        --> smp_call_function_single(event_cpu, __perf_event_read, &data, 1); // PERF_EVENT_STATE_ACTIVE
            --> __perf_event_read(void* info)
                --> if !data->group
                    --> pmu->read(event); // !data->group
                --> else
                    --> pmu->start_txn(pmu, PERF_PMU_TXN_READ); //read group
                    --> pmu->read(event);
                    --> sub->pmu->read(sub);
                    --> data->ret = pmu->commit_txn(pmu);
        --> perf_event_update_time(event); // PERF_EVENT_STATE_INACTIVE
    --> local64_set(&event->count, 0);
    --> perf_event_update_userpage(event);
        --> calc_timer_values(event, &now, &enabled, &running);
        --> userpg = rb->user_page;
        --> userpg->index = perf_event_index(event);
            --> event->pmu->event_idx(event);
        --> userpg->offset = perf_event_count(event);
        --> userpg->index = perf_event_index(event);
        --> userpg->time_enabled = enabled + atomic64_read(&event->child_total_time_enabled);
        --> userpg->time_running = running + atomic64_read(&event->child_total_time_running);
```

`_perf_event_reset` 首先通过 `perf_event_read` 读取pmu数据，然后设置事件计数为0，最后更新用户页信息。在事件处于启动状态时，调用 `pmu->read(event)` 读取数据；未开启状态时仅更新时间。

* PERF_EVENT_IOC_REFRESH

该指令修改perf_event的并发执行的数量，实现如下：

```C
	case PERF_EVENT_IOC_REFRESH:
		return _perf_event_refresh(event, arg);
```

`_perf_event_refresh` 实现如下：

```C
static int _perf_event_refresh(struct perf_event *event, int refresh)
	--> atomic_add(refresh, &event->event_limit);
	--> _perf_event_enable(event);
```

在修改 `event_limit` 后，调用 `_perf_event_enable` 开启事件。

* PERF_EVENT_IOC_PERIOD

该指令修改perf_event的采用周期/频率，实现如下：

```C
	case PERF_EVENT_IOC_PERIOD:
	{
		u64 value;
		if (copy_from_user(&value, (u64 __user *)arg, sizeof(value)))
			return -EFAULT;
		return _perf_event_period(event, value);
	}
```

`_perf_event_period` 实现如下：

```C
static int _perf_event_period(struct perf_event *event, u64 value)
    --> perf_event_check_period(event, value)
        --> event->pmu->check_period(event, value);
    --> event_function_call(event, __perf_event_period, &value);

static void __perf_event_period(struct perf_event *event, struct perf_cpu_context *cpuctx,
                struct perf_event_context *ctx, void *info)
    --> event->attr.sample_freq = value; // event->attr.freq
        --> event->attr.sample_period = value; // !event->attr.freq
        --> event->hw.sample_period = value;
    --> perf_pmu_disable(event->pmu);
    --> perf_log_throttle(event, 1); //event->hw.interrupts == MAX_INTERRUPTS
    --> event->pmu->stop(event, PERF_EF_UPDATE);
    --> local64_set(&event->hw.period_left, 0);
    --> event->pmu->start(event, PERF_EF_RELOAD);
    --> perf_pmu_enable(event->pmu);
```

`_perf_event_period` 在检查参数正确后，通过 `event_function_call` 方式调用 `__perf_event_period` 进行采用周期设置。`__perf_event_period` 设置相关参数，在事件开启的情况下，停止后再开启PMU。

* PERF_EVENT_IOC_SET_BPF

该指令设置perf_event关联BPF程序，实现如下：

```C
	case PERF_EVENT_IOC_SET_BPF:
	{
		struct bpf_prog *prog;
		int err;
		prog = bpf_prog_get(arg);
		if (IS_ERR(prog)) return PTR_ERR(prog);
		err = perf_event_set_bpf_prog(event, prog, 0);
		if (err) { bpf_prog_put(prog); return err; }
		return 0;
	}
```

`perf_event_set_bpf_prog` 函数的主要调用过程如下：

```C
int perf_event_set_bpf_prog(struct perf_event *event, struct bpf_prog *prog, u64 bpf_cookie)
    --> perf_event_set_bpf_handler(event, prog, bpf_cookie); //!perf_event_is_tracing(event)
        --> event->prog = prog;
        --> event->bpf_cookie = bpf_cookie;
        --> event->orig_overflow_handler = READ_ONCE(event->overflow_handler);
        --> WRITE_ONCE(event->overflow_handler, bpf_overflow_handler);
    --> perf_event_attach_bpf_prog(event, prog, bpf_cookie); // perf_event_is_tracing(event)
        --> bpf_prog_array_copy(old_array, NULL, prog, bpf_cookie, &new_array);
        --> event->prog = prog;
        --> event->bpf_cookie = bpf_cookie;
        --> rcu_assign_pointer(event->tp_event->prog_array, new_array);
```

当perf_event是追踪事件时，将bpf程序添加到prog数组中；否则，设置event有关bpf相关的属性（ `prog`, `bpf_cookie`, `orig_overflow_handler` ），修改 `overflow_handler` 为 `bpf_overflow_handler`。

## 5 PMU的注册和卸载

### 5.1 PMU注册过程 -- `perf_pmu_register`

我们在 `perf_event_open` 函数中通过 `perf_init_event(event)` 确定对应的PMU，通过查找 `pmu_idr` 或 `pmus` 确定。这些 `pmus` 通过 `perf_pmu_register` 函数进行注册的。实现过程如下：

```C
int perf_pmu_register(struct pmu *pmu, const char *name, int type)
    --> pmu->pmu_disable_count = alloc_percpu(int);
    --> pmu->name = name;
    --> ret = idr_alloc(&pmu_idr, pmu, max, 0, GFP_KERNEL);  // type != PERF_TYPE_SOFTWARE
    --> pmu->type = type;
    --> pmu_dev_alloc(pmu); // if pmu_bus_running
    --> pmu->cpu_pmu_context = alloc_percpu(struct perf_cpu_pmu_context);
    --> for_each_possible_cpu(cpu)
        -->	cpc = per_cpu_ptr(pmu->cpu_pmu_context, cpu);
		--> __perf_init_event_pmu_context(&cpc->epc, pmu);
		--> __perf_mux_hrtimer_init(cpc, cpu);
            --> interval = pmu->hrtimer_interval_ms; // or PERF_CPU_HRTIMER = 1ms
            --> cpc->hrtimer_interval = ns_to_ktime(NSEC_PER_MSEC * interval); 
            --> hrtimer_init(timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED_HARD);
            --> timer->function = perf_mux_hrtimer_handler;
    --> pmu->start_txn  = perf_pmu_start_txn; // if (!pmu->start_txn)
    --> ...
    --> pmu->event_idx = perf_event_idx_default; //if (!pmu->event_idx)
    --> list_add_rcu(&pmu->entry, &pmus);  // if (type == PERF_TYPE_SOFTWARE || !name)
    --> list_add_tail_rcu(&pmu->entry, &pmus); // otherwise
    --> atomic_set(&pmu->exclusive_cnt, 0);
```

`perf_pmu_register` 将PMU注册到系统中。主要过程如下：

* 分配`pmu_disable_count` per-cpu变量；
* 对非software类型添加到 `pmu_idr`；
* 设置名称的PMU分配dev，通过dev注册到系统中；
* 初始化每个CPU的`pmu_context`, 设置高精度定时器；
* 设置默认处理函数，如: `start_txn`, `commit_txn`, `pmu_enable` ...
* 添加到 `pmus` 中，software类型添加到前面，减少遍历次数。
  
### 5.2 PMU卸载过程 -- `perf_pmu_unregister`

`perf_pmu_unregister` 函数实现PMU的卸载。实现如下：

```C
void perf_pmu_unregister(struct pmu *pmu)
    --> list_del_rcu(&pmu->entry);
    --> free_percpu(pmu->pmu_disable_count);
    --> idr_remove(&pmu_idr, pmu->type); // if (pmu->type != PERF_TYPE_SOFTWARE)
    --> device_remove_file(pmu->dev, &dev_attr_nr_addr_filters);
    --> device_del(pmu->dev);
    --> put_device(pmu->dev);
    --> free_pmu_context(pmu);
```

`perf_pmu_register` 释放注册时分配的系统资源。

### 5.3 PMU初始化过程

在内核启动阶段 (`start_kernel`) 通过函数调用和 `initcal`方式实现PMU的初始化。

* 系统启动阶段

系统启动阶段说明参见 [Kernel initialization. Part 10.](https://0xax.gitbook.io/linux-insides/summary/initialization/linux-initialization-10) 或 [Linux内核初始化（第六部分）](https://github.com/mannkafai/linux-insides-zh/blob/main/02-initialization/02-initialization-6.md) 

系统启动阶段和perf_event相关的初始化如下：

```C
// init/main.c
asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
    // kernel/events/core.c
    --> perf_event_init();
        --> idr_init(&pmu_idr);
        --> perf_event_init_all_cpus();
            --> for_each_possible_cpu(cpu) 
                --> swhash = &per_cpu(swevent_htable, cpu);
                --> cpuctx = per_cpu_ptr(&perf_cpu_context, cpu);
        --> init_srcu_struct(&pmus_srcu);
        --> perf_pmu_register(&perf_swevent, "software", PERF_TYPE_SOFTWARE);
        --> perf_pmu_register(&perf_cpu_clock, NULL, -1);
        --> perf_pmu_register(&perf_task_clock, NULL, -1);
        --> perf_tp_register();
            --> perf_pmu_register(&perf_tracepoint, "tracepoint", PERF_TYPE_TRACEPOINT);
            --> perf_pmu_register(&perf_kprobe, "kprobe", -1);
            --> perf_pmu_register(&perf_uprobe, "uprobe", -1);
        --> perf_event_init_cpu(smp_processor_id());
            --> perf_swevent_init_cpu(cpu);
        --> register_reboot_notifier(&perf_reboot_notifier);
        --> init_hw_breakpoint();
            --> rhltable_init(&task_bps_ht, &task_bps_ht_params);
            --> init_breakpoint_slots();
            --> perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
            --> register_die_notifier(&hw_breakpoint_exceptions_nb)
        --> perf_event_cache = KMEM_CACHE(perf_event, SLAB_PANIC);
```

`perf_event_init` 初始化`pmu_idr`, 初始化每个CPU上下文，注册通用的PMU, 创建perf_event缓存。注册的PMU包括: `software`, `tracepoint`, `kprobe`, `uprobe`, `breakpoint` 等。

* `initcal` 方式

`initcal` 说明参见 [The initcall mechanism](https://0xax.gitbook.io/linux-insides/summary/concepts/linux-cpu-3) 或 [initcall 机制](https://github.com/mannkafai/linux-insides-zh/blob/main/09-concepts/09-concepts-03.md) 。

通过 `initcal` 方式注册PMU和perf相关的初始化包括：

```C
early_initcall(init_hw_perf_events);
arch_initcall(bts_init);
arch_initcall(pt_init);
device_initcall(perf_event_sysfs_init);
device_initcall(msr_init);
module_init(rapl_pmu_init);
module_init(intel_uncore_init);
module_init(cstate_pmu_init);
...
```

和PMU相关的内容我们在下一节进行分析，这里我们只分析 `perf_event_sysfs_init` 。 实现如下：

```C
static int pmu_bus_running;
static struct bus_type pmu_bus = {
	.name		= "event_source",
	.dev_groups	= pmu_dev_groups,
};
// kernel/events/core.c
static int __init perf_event_sysfs_init(void)
    --> ret = bus_register(&pmu_bus);
        --> priv = kzalloc(sizeof(struct subsys_private), GFP_KERNEL);
        --> priv->bus = bus;
        --> retval = kobject_set_name(bus_kobj, "%s", bus->name);
        --> retval = kset_register(&priv->subsys);
        --> priv->devices_kset = kset_create_and_add("devices", NULL, bus_kobj);
        --> priv->drivers_kset = kset_create_and_add("drivers", NULL, bus_kobj);
        --> retval = add_probe_files(bus);
            --> retval = bus_create_file(bus, &bus_attr_drivers_probe);
            --> retval = bus_create_file(bus, &bus_attr_drivers_autoprobe);
        --> retval = sysfs_create_groups(bus_kobj, bus->bus_groups);
    --> list_for_each_entry(pmu, &pmus, entry)
        --> ret = pmu_dev_alloc(pmu); // if (pmu->name && pmu->type >= 0)
            --> pmu->dev = kzalloc(sizeof(struct device), GFP_KERNEL);
            --> pmu->dev->groups = pmu->attr_groups;
            --> device_initialize(pmu->dev);
            --> dev_set_name(pmu->dev, "%s", pmu->name);
            --> device_add(pmu->dev);
            --> device_create_file(pmu->dev, &dev_attr_nr_addr_filters); // if (pmu->nr_addr_filters) 
            --> sysfs_update_groups(&pmu->dev->kobj, pmu->attr_update);
    --> pmu_bus_running = 1;
```

`perf_event_sysfs_init` 函数实现perf_event相关sysfs的初始化, 主要实现 `pmu_bus` 的注册和 `pmu` 对应设备的创建。

系统注册的PMU在 `/sys/bus/event_source/` 目录下。如下：

```bash
$ tree /sys/bus/event_source/
/sys/bus/event_source/
├── devices
│   ├── breakpoint -> ../../../devices/breakpoint
│   ├── cpu -> ../../../devices/cpu
│   ├── cstate_core -> ../../../devices/cstate_core
│   ├── cstate_pkg -> ../../../devices/cstate_pkg
│   ├── i915 -> ../../../devices/i915
│   ├── kprobe -> ../../../devices/kprobe
│   ├── msr -> ../../../devices/msr
│   ├── power -> ../../../devices/power
│   ├── software -> ../../../devices/software
│   ├── tracepoint -> ../../../devices/tracepoint
│   ├── uncore_arb -> ../../../devices/uncore_arb
│   ├── uncore_cbox_0 -> ../../../devices/uncore_cbox_0
│   ├── uncore_cbox_1 -> ../../../devices/uncore_cbox_1
│   ├── uncore_cbox_2 -> ../../../devices/uncore_cbox_2
│   ├── uncore_cbox_3 -> ../../../devices/uncore_cbox_3
│   ├── uncore_imc -> ../../../devices/uncore_imc
│   └── uprobe -> ../../../devices/uprobe
├── drivers
├── drivers_autoprobe
├── drivers_probe
└── uevent

19 directories, 3 files
```

## 6 perf事件用户内存映射

略。

## 参考资料

* [Linux perf 1.1、perf_event内核框架](https://blog.csdn.net/pwl999/article/details/81200439)
* [Linux内核 eBPF基础：perf（1）：perf_event在内核中的初始化](https://rtoax.blog.csdn.net/article/details/116982544)
* [Linux内核 eBPF基础：perf（4）perf_event_open系统调用与用户手册详解](https://blog.csdn.net/Rong_Toa/article/details/117040529)
* [Kernel initialization. Part 10.](https://0xax.gitbook.io/linux-insides/summary/initialization/linux-initialization-10) 
* [Linux内核初始化（第六部分）](https://github.com/mannkafai/linux-insides-zh/blob/main/02-initialization/02-initialization-6.md) 
* [The initcall mechanism](https://0xax.gitbook.io/linux-insides/summary/concepts/linux-cpu-3) 
* [initcall 机制](https://github.com/mannkafai/linux-insides-zh/blob/main/09-concepts/09-concepts-03.md) 