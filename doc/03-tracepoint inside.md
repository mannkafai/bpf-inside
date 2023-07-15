# Tracepoint的内核实现

## 0 前言

在第一篇中，我们借助libbpf实现了一个简单的BPF程序，借助 `perf_event_open` 系统调用将BPF程序挂载在 `syscalls/sys_enter_write` 事件下。上一篇中我们分析了 `perf_event_open` 的实现过程，在这篇中我们将继续分析BPF程序是如何挂载到该事件下，以及时如何触发的。

## 1 简介

Tracepoint是Linux内核中静态定义的调试点，提供了一个钩子来调用在运行时提供的函数（探针）。跟踪点处于“打开”（有探针连接到它）或“关闭”（没有连接探针）状态。当跟踪点处于“关闭”状态时，它没有任何效果，除了微小的时间损失（检查分支的条件）和空间损失。当跟踪点处于“打开”状态时，每次执行跟踪点时，都会在调用方的执行上下文中调用提供的函数，当提供的函数结束执行时，它返回到调用者继续执行。

## 2 Tracepoint的PMU操作接口

在开始之前，我们先看下 libbpf 中 `attach_tp` 在调用 `perf_event_open` 时传入的参数。我们的示例中 `tp_category` 和 `tp_name` 值为 `syscalls`和`sys_enter_write`。

```C
//file: libbpf/src/libbpf.c
static int perf_event_open_tracepoint(const char *tp_category, const char *tp_name)
{
    const size_t attr_sz = sizeof(struct perf_event_attr);
    struct perf_event_attr attr;
    int tp_id, pfd, err;
    
    tp_id = determine_tracepoint_id(tp_category, tp_name);

    memset(&attr, 0, attr_sz);
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = attr_sz;
    attr.config = tp_id;
    pfd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    ...
}
```

`tp_id` 通过读取 `/sys/kernel/debug/tracing/events/syscalls/sys_enter_write/id` 或 `/sys/kernel/tracing/events/syscalls/sys_enter_write/id` 文件获取。

可以看到，第一个参数 `attr` 只填了 `type`, `size`, `config` 三个字段。在上一篇中，我们知道 `type` 字段表示选择的PMU类型，对应的是PMU为 `tracepoint`。剩余参数表示该事件运行范围在cpu0上的所有进程，并且设置了 `O_CLOEXEC` 选项。对应类型的PMU定义如下：

```C
//file: kernel/events/core.c
perf_pmu_register(&perf_tracepoint, "tracepoint", PERF_TYPE_TRACEPOINT);

static struct pmu perf_tracepoint = {
    .task_ctx_nr    = perf_sw_context,
    .event_init     = perf_tp_event_init,
    .add            = perf_trace_add,
    .del            = perf_trace_del,
    .start          = perf_swevent_start,
    .stop           = perf_swevent_stop,
    .read           = perf_swevent_read,
};
```

### 2.1 初始化 -- `perf_tp_event_init`

* `perf_tp_event_init`

`perf_tracepoint` 的初始化函数为 `perf_tp_event_init` , 实现如下

```C
//file: kernel/events/core.c
static int perf_tp_event_init(struct perf_event *event)
{
    int err;
    if (event->attr.type != PERF_TYPE_TRACEPOINT) return -ENOENT;
    if (has_branch_stack(event)) return -EOPNOTSUPP;
    err = perf_trace_init(event);
    if (err) return err;
    event->destroy = tp_perf_event_destroy;
    return 0;
}
```

实现过程非常简单，首先进行类型字段检查和分支栈检查，在检查成功后，调用 `perf_trace_init` 进行初始化。在初始化完成后设置 `destroy` 的调用函数。

* `perf_trace_init`

`perf_trace_init` 函数实现如下：

```C
//file: kernel/trace/trace_event_perf.c
int perf_trace_init(struct perf_event *p_event)
{
    struct trace_event_call *tp_event;
    u64 event_id = p_event->attr.config;
    int ret = -EINVAL;
    mutex_lock(&event_mutex);
    list_for_each_entry(tp_event, &ftrace_events, list) {
        if (tp_event->event.type == event_id &&
            tp_event->class && tp_event->class->reg &&
            trace_event_try_get_ref(tp_event)) {
            ret = perf_trace_event_init(tp_event, p_event);
            if (ret) trace_event_put_ref(tp_event);
            break;
        }
    }
    mutex_unlock(&event_mutex);
    return ret;
}
```

实现过程也非常简单，遍历 `ftrace_events` 列表，选择类型匹配的 `tp_event` 后，调用 `perf_trace_event_init` 函数。在确定 `tp_event` 时，需要我们传入的 `config` 字段。我们先看下 `perf_trace_event_init` 的实现过程，如下：

```C
//file: kernel/trace/trace_event_perf.c
static int perf_trace_event_init(struct trace_event_call *tp_event, struct perf_event *p_event)
    //权限检查
    --> perf_trace_event_perm(tp_event, p_event);
	    //自定义权限检查，需要设置perf_perm
        --> tp_event->perf_perm(tp_event, p_event);  // if (tp_event->perf_perm)
	    // 需要root权限时，权限检查
        --> if (ftrace_event_is_function(tp_event)) // only for root
            --> perf_allow_tracepoint(&p_event->attr);
	    // 普通权限检查
        --> perf_allow_tracepoint(&p_event->attr);
    //tp_event注册
    --> perf_trace_event_reg(tp_event, p_event);
        --> p_event->tp_event = tp_event;
        --> if (tp_event->perf_refcount++ > 0) return 0;
        // 第一次注册
        --> list = alloc_percpu(struct hlist_head);
        --> for_each_possible_cpu(cpu)
            -->INIT_HLIST_HEAD(per_cpu_ptr(list, cpu));
        --> tp_event->perf_events = list;
        // 第一次分配缓存区。每个CPU分配4个(task, softirq, hardirq, nmi),
        // 单个缓冲区大小:PERF_MAX_TRACE_SIZE(8KB)
        --> if (!total_ref_count) 
            --> for (i = 0; i < PERF_NR_CONTEXTS; i++) {
                --> buf = (char __percpu *)alloc_percpu(perf_trace_t);
                --> perf_trace_buf[i] = buf;
        --> tp_event->class->reg(tp_event, TRACE_REG_PERF_REGISTER, NULL);
    //tp_event打开
    --> perf_trace_event_open(p_event);
        --> p_event->tp_event->class->reg(tp_event, TRACE_REG_PERF_OPEN, p_event);
```

可以看到，主要是依赖 `tp_event` 和 `tp_event->class` 进行操作的。在进行权限检查后，通过 `tp_event->class->reg` 进行注册和打开。在注册时，只有在第一次注册时才进行实际注册，同时检查是否分配缓冲区，需要时进行分配。

### 2.2 添加 -- `perf_trace_add`

`perf_trace_add` 函数的实现过程如下：

```C
//file: kernel/trace/trace_event_perf.c
int perf_trace_add(struct perf_event *p_event, int flags)
    --> if (!(flags & PERF_EF_START))
        --> p_event->hw.state = PERF_HES_STOPPED;
    --> if (!tp_event->class->reg(tp_event, TRACE_REG_PERF_ADD, p_event))
        --> pcpu_list = tp_event->perf_events;
        --> list = this_cpu_ptr(pcpu_list);
        --> hlist_add_head_rcu(&p_event->hlist_entry, list);
```

实现过程也非常简单，主要通过 `tp_event->class->reg` 进行添加。如果不能正常添加，使用默认方式添加。

### 2.3 删除 -- `perf_trace_del`

`perf_trace_del` 函数的实现过程如下：

```C
//file: kernel/trace/trace_event_perf.c
void perf_trace_del(struct perf_event *p_event, int flags)
    --> if (!tp_event->class->reg(tp_event, TRACE_REG_PERF_DEL, p_event))
        --> hlist_del_rcu(&p_event->hlist_entry);
```

实现过程也非常简单，通过 `tp_event->class->reg` 进行删除。如果不能正常删除，通过默认方式删除，即：从 per-cpu变量的hlist中删除。

### 2.4 开始 -- `perf_swevent_start`

`perf_swevent_start` 函数的实现如下：

```C
//file: kernel/events/core.c
static void perf_swevent_start(struct perf_event *event, int flags)
    --> event->hw.state = 0;
```

设置 `event->hw` 的状态为0。

### 2.5 停止 -- `perf_swevent_stop`

`perf_swevent_stop` 函数的实现如下：

```C
//file: kernel/events/core.c
static void perf_swevent_stop(struct perf_event *event, int flags)
    --> event->hw.state = PERF_HES_STOPPED;
```

设置 `event->hw` 的状态为停止状态。

### 2.6 销毁 -- `tp_perf_event_destroy`

`tp_perf_event_destroy` 进行清理工作和释放资源，实现如下：

```C
//file: kernel/events/core.c
static void tp_perf_event_destroy(struct perf_event *event)
    --> perf_trace_destroy(event);
        // file: kernel/trace/trace_event_perf.c
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
```

通过 `tp_event->class->reg` 进行关闭和注销。在必要时释放分配的缓冲区。只有在引用计数为0时才注销。


## 3 Tracepoint的内核实现

### 3.1 Tracepoint相关结构定义

上一节，我们分析了Tracepoint的PMU操作接口部分，可以看到 `perf_event` 通过 `tp_event` 和 `tp_event->class` 进行操作的。我们看下其定义：

```C
//file: include/linux/perf_event.h
struct perf_event {
    ...
#ifdef CONFIG_EVENT_TRACING
    struct trace_event_call *tp_event;
    struct event_filter	    *filter;
#ifdef CONFIG_FUNCTION_TRACER
    struct ftrace_ops       ftrace_ops;
#endif
#endif
    ...
};

//file: include/linux/trace_events.h
struct trace_event_call {
    struct list_head    list;
    struct trace_event_class *class;
    union {
        char                *name;
        struct tracepoint   *tp;
    };
    struct trace_event	event;
    ...
    int         flags; /* static flags of different events */

#ifdef CONFIG_PERF_EVENTS
    int             perf_refcount;
    struct hlist_head __percpu	*perf_events;
    struct bpf_prog_array __rcu	*prog_array;
    int	(*perf_perm)(struct trace_event_call *, struct perf_event *);
#endif
};

//file: include/linux/trace_events.h
struct trace_event_class {
	const char		*system;
	void			*probe;
#ifdef CONFIG_PERF_EVENTS
	void			*perf_probe;
#endif
	int			(*reg)(struct trace_event_call *event, enum trace_reg type, void *data);
	...
	int			(*raw_init)(struct trace_event_call *);
};

//file: include/linux/trace_events.h
struct trace_event {
	struct hlist_node               node;
	int                             type;
	struct trace_event_functions    *funcs;
};

//file: include/linux/tracepoint-defs.h
struct tracepoint_func {
	void *func;
	void *data;
	int prio;
};

//file: include/linux/tracepoint-defs.h
struct tracepoint {
	const char *name;		/* Tracepoint name */
	struct static_key key;
	struct static_call_key *static_call_key;
	void *static_call_tramp;
	void *iterator;
	int (*regfunc)(void);
	void (*unregfunc)(void);
	struct tracepoint_func __rcu *funcs;
};
```

通过上面类型的定义及PMU的操作接口，我们可以看到 `ftrace_events` 是由 `struct trace_event_call` 的集合。

### 3.2 ftrace_events的定义

通过搜索，`ftrace_events` 的定义如下：

```C
//file: kernel/trace/trace_events.c
LIST_HEAD(ftrace_events);
```

在搜索过程中，我们看到在对 `ftrace_events` 的添加操作有两处，分别为：

* 动态添加事件调用

```C
//file: kernel/trace/trace_events.c
static int __register_event(struct trace_event_call *call, struct module *mod)
{
	int ret;
	ret = event_init(call);
	if (ret < 0) return ret;
	list_add(&call->list, &ftrace_events);
	...
	return 0;
}

// file: kernel/trace/trace_events.c
/* Add an additional event_call dynamically */
int trace_add_event_call(struct trace_event_call *call)
{
    ...
    ret = __register_event(call, NULL);
    if (ret >= 0) __add_event_to_tracers(call);
    ...
}
```

通过 `trace_add_event_call` 函数注释，我们可以看到该函数实现动态添加事件调用。接下来，我们看第二处，如下：

* 初始化时添加事件调用

```C
//file: kernel/trace/trace_events.c
static __init int event_trace_enable(void)
{
	...
	for_each_event(iter, __start_ftrace_events, __stop_ftrace_events) {
		call = *iter;
		ret = event_init(call);
		if (!ret)
			list_add(&call->list, &ftrace_events);
	}
	...
}
```

函数中通过 `__start_ftrace_events` 和 `__stop_ftrace_events` ，结合 `vmlinux.lds.h` 文件，可以判断 `ftrace_events` 的内容由 `__section("_ftrace_events")` 组成的。

```C
//file: include/asm-generic/vmlinux.lds.h
#ifdef CONFIG_EVENT_TRACING
#define FTRACE_EVENTS()							\
	. = ALIGN(8);							\
	BOUNDED_SECTION(_ftrace_events)					\
	BOUNDED_SECTION_BY(_ftrace_eval_map, _ftrace_eval_maps)
#else
#define FTRACE_EVENTS()
#endif
```

`__section("_ftrace_events")`  在三个文件定义，如下：

```C
// file：include/linux/syscalls.h
#define SYSCALL_TRACE_ENTER_EVENT(sname)				\
	...								\
	static struct trace_event_call __used				\
	  __section("_ftrace_events")					\
	 *__event_enter_##sname = &event_enter_##sname;

#define SYSCALL_TRACE_EXIT_EVENT(sname)					\
	...								\
	static struct trace_event_call __used				\
	  __section("_ftrace_events")					\
	*__event_exit_##sname = &event_exit_##sname;
```

```C
// file: include/trace/trace_events.h
#undef DEFINE_EVENT
#define DEFINE_EVENT(template, call, proto, args)			\
...									\
static struct trace_event_call __used					\
__section("_ftrace_events") *__event_##call = &event_##call

#undef DEFINE_EVENT_PRINT
#define DEFINE_EVENT_PRINT(template, call, proto, args, print)		\
...									\
static struct trace_event_call __used					\
__section("_ftrace_events") *__event_##call = &event_##call
```

```C
// file： include/trace/trace_custom_events.h
#undef DEFINE_CUSTOM_EVENT
#define DEFINE_CUSTOM_EVENT(template, call, proto, args)		\
...									\
static struct trace_event_call __used					\
__section("_ftrace_events") *__custom_event_##call = &custom_event_##call
```

### 3.3 TRACE_EVENT宏展开过程

在我们继续之前，我们需要分析下 `TRACE_EVENT` 的展开过程，以 `include/trace/events/sched.h` 文件为例。文件内容如下：

```C
// file: include/trace/events/sched.h
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sched

#if !defined(_TRACE_SCHED_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SCHED_H

#include <linux/kthread.h>
#include <linux/sched/numa_balancing.h>
#include <linux/tracepoint.h>
#include <linux/binfmts.h>

TRACE_EVENT(sched_kthread_stop,
...
);

...
DECLARE_EVENT_CLASS(sched_numa_pair_template,
...
);

DEFINE_EVENT(sched_numa_pair_template, sched_stick_numa,
...
);

...
DECLARE_TRACE(pelt_cfs_tp,
	TP_PROTO(struct cfs_rq *cfs_rq),
	TP_ARGS(cfs_rq));
...
#endif /* _TRACE_SCHED_H */

#include <trace/define_trace.h>
```

`TRACE_EVENT` 展开过程比较复杂，详细展开过程可以参考 "Using the TRACE_EVENT() macro [(Part 1)](https://lwn.net/Articles/379903/), [(Part 2)](https://lwn.net/Articles/381064/), [(Part 3)](https://lwn.net/Articles/383362/)" , [Linux tracing - trace event framework](http://terenceli.github.io/%E6%8A%80%E6%9C%AF/2020/08/08/trace-event-framework) 等文章。在这里我们将简略分析每个阶段的功能。

#### 1 声明阶段--DECLARE_TRACE

`DEFINE_EVENT`, `DEFINE_EVENT_FN`, `DEFINE_EVENT_PRINT`, `DEFINE_EVENT_CONDITION`, `TRACE_EVENT`, `TRACE_EVENT_FN`,`TRACE_EVENT_FN_COND`, `TRACE_EVENT_CONDITION` 这些宏展开为 `DECLARE_TRACE` 或 `DECLARE_TRACE_CONDITION`，最终展开为 `__DECLARE_TRACE`。 `__DECLARE_TRACE` 定义如下：

```C
// file：include/linux/tracepoint.h
#define __DECLARE_TRACE(name, proto, args, cond, data_proto)		\
	extern int __traceiter_##name(data_proto);			\
	DECLARE_STATIC_CALL(tp_func_##name, __traceiter_##name);	\
	extern struct tracepoint __tracepoint_##name;			\
	static inline void trace_##name(proto)				\
	{								\
		if (static_key_false(&__tracepoint_##name.key))		\
			__DO_TRACE(name,				\
				TP_ARGS(args),				\
				TP_CONDITION(cond), 0);			\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {		\
			WARN_ON_ONCE(!rcu_is_watching());		\
		}							\
	}								\
	__DECLARE_TRACE_RCU(name, PARAMS(proto), PARAMS(args),		\
			    PARAMS(cond))				\
	static inline int						\
	register_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_register(&__tracepoint_##name,	\
						(void *)probe, data);	\
	}								\
	static inline int						\
	register_trace_prio_##name(void (*probe)(data_proto), void *data,\
				   int prio)				\
	{								\
		return tracepoint_probe_register_prio(&__tracepoint_##name, \
					      (void *)probe, data, prio); \
	}								\
	static inline int						\
	unregister_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_unregister(&__tracepoint_##name,\
						(void *)probe, data);	\
	}								\
	static inline void						\
	check_trace_callback_type_##name(void (*cb)(data_proto))	\
	{								\
	}								\
	static inline bool						\
	trace_##name##_enabled(void)					\
	{								\
		return static_key_false(&__tracepoint_##name.key);	\
	}
```

`__DECLARE_TRACE` 宏展开后实现了 `trace_##name`, `register_trace_##name`, `unregister_trace_##name`, `trace_##name##_enabled` 等函数。我们通过这些函数可以进行 `trace` 相关的事件调用、注册、注销等。注册/注销通过调用 `tracepoint_probe_register` / `tracepoint_probe_unregister` 实现。调用 `trace_##name` 函数时，可以触发我们挂载的函数。以 `trace_sched_kthread_stop` 为例，展开如下：

```C
// file: include/linux/tracepoint.h
static inline void trace_sched_kthread_stop(struct task_struct *t)
{
    if (static_key_false(&__tracepoint_sched_kthread_stop.key))
    {
        // __DO_TRACE(name,TP_ARGS(args), TP_CONDITION(cond), 0);	
        do {
            int __maybe_unused __idx = 0;
            if (!cpu_online(raw_smp_processor_id()))
                return;
            if (WARN_ON_ONCE(RCUIDLE_COND(0)))
                return;
            preempt_disable_notrace();
            if (0) {
                __idx = srcu_read_lock_notrace(&tracepoint_srcu);
                ct_irq_enter_irqson();
            }
            // __DO_TRACE_CALL(name, TP_ARGS(args));
            do {
                struct tracepoint_func *it_func_ptr;
                void *__data;
                it_func_ptr = rcu_dereference_raw((&__tracepoint_sched_kthread_stop)->funcs); 
                if (it_func_ptr) {	
                    __data = (it_func_ptr)->data;	
                    static_call(tp_func_sched_kthread_stop)(__data, t);	
                }
            } while (0)；

            if (0) {
                ct_irq_exit_irqson();
                srcu_read_unlock_notrace(&tracepoint_srcu, __idx);
            }
            preempt_enable_notrace();
        } while (0);
    }
}
```

#### 2 定义阶段--DEFINE_TRACE_FN

这个阶段，`TRACE_EVENT`, `TRACE_EVENT_CONDITION`, `DEFINE_EVENT_FN` 宏转换为 `DEFINE_TRACE_FN` 或 `DEFINE_TRACE` 宏。 `DEFINE_TRACE_FN` 定义如下：

```C
// file: include/linux/tracepoint.h
#define DEFINE_TRACE_FN(_name, _reg, _unreg, proto, args)		\
	static const char __tpstrtab_##_name[]				\
	__section("__tracepoints_strings") = #_name;			\
	extern struct static_call_key STATIC_CALL_KEY(tp_func_##_name);	\
	int __traceiter_##_name(void *__data, proto);			\
	struct tracepoint __tracepoint_##_name	__used			\
	__section("__tracepoints") = {					\
		.name = __tpstrtab_##_name,				\
		.key = STATIC_KEY_INIT_FALSE,				\
		.static_call_key = &STATIC_CALL_KEY(tp_func_##_name),	\
		.static_call_tramp = STATIC_CALL_TRAMP_ADDR(tp_func_##_name), \
		.iterator = &__traceiter_##_name,			\
		.regfunc = _reg,					\
		.unregfunc = _unreg,					\
		.funcs = NULL };					\
	__TRACEPOINT_ENTRY(_name);					\
	int __traceiter_##_name(void *__data, proto)			\
	{								\
		...
	}								\
	DEFINE_STATIC_CALL(tp_func_##_name, __traceiter_##_name);

#define DEFINE_TRACE(name, proto, args)		\
	DEFINE_TRACE_FN(name, NULL, NULL, PARAMS(proto), PARAMS(args));

// file: include/linux/tracepoint.h
#define __TRACEPOINT_ENTRY(name)					 \
	static tracepoint_ptr_t __tracepoint_ptr_##name __used		 \
	__section("__tracepoints_ptrs") = &__tracepoint_##name
```

这个阶段定义并初始化了 `struct tracepoint __tracepoint_##_name`  变量；定义了 `__traceiter_##_name` 函数；通过 `DEFINE_STATIC_CALL` 将 `tp_func_##_name` 调用 和 `__traceiter_##_name` 进行关联。以 `trace_sched_kthread_stop` 为例，`__traceiter_##_name` 展开如下：

```C
int __traceiter_trace_sched_kthread_stop(void *__data, struct task_struct *t)
{
    struct tracepoint_func *it_func_ptr;
    void *it_func;
    it_func_ptr = rcu_dereference_raw((&__tracepoint_sched_kthread_stop)->funcs); 
    if (it_func_ptr) {
        do {
            it_func = READ_ONCE((it_func_ptr)->func); 
            __data = (it_func_ptr)->data;
            ((void(*)(void *, struct task_struct*))(it_func))(__data, t);
        } while ((++it_func_ptr)->func);
    }
    return 0;
}
```

`__traceiter_##_name` 函数遍历 `__tracepoint_##_name` 中 `funcs` (`struct tracepoint_func` 类型) 逐个执行。

#### 3 初始化定义--init

在上述阶段完成后，现在我们通过 `TRACE_INCLUDE` 重新包含 `<trace/events/##system.h>` 文件。在这之后包含 `<trace/trace_events.h>`， `<trace/perf.h>`, `<trace/bpf_probe.h>` 这三个文件进行后续宏展开。

```C
// file: include/trace/define_trace.h
#ifndef TRACE_INCLUDE_FILE
# define TRACE_INCLUDE_FILE TRACE_SYSTEM
# define UNDEF_TRACE_INCLUDE_FILE
#endif

#ifndef TRACE_INCLUDE_PATH
# define __TRACE_INCLUDE(system) <trace/events/system.h>
# define UNDEF_TRACE_INCLUDE_PATH
#else
# define __TRACE_INCLUDE(system) __stringify(TRACE_INCLUDE_PATH/system.h)
#endif

# define TRACE_INCLUDE(system) __TRACE_INCLUDE(system)

/* Let the trace headers be reread */
#define TRACE_HEADER_MULTI_READ

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

#undef DECLARE_TRACE
#define DECLARE_TRACE(name, proto, args)

#ifdef TRACEPOINTS_ENABLED
#include <trace/trace_events.h>
#include <trace/perf.h>
#include <trace/bpf_probe.h>
#endif
...
```

`<trace/trace_events.h>` 文件起始内容如下：

```C
// file: include/trace/trace_events.h
#include <linux/trace_events.h>

#ifndef TRACE_SYSTEM_VAR
#define TRACE_SYSTEM_VAR TRACE_SYSTEM
#endif

#include "stages/init.h"
...
```

`stages/init.h` 文件中展开 `TRACE_DEFINE_ENUM` 和 `TRACE_DEFINE_SIZEOF` 如下：

```C
// file: include/trace/stages/init.h
#undef TRACE_DEFINE_ENUM
#define TRACE_DEFINE_ENUM(a)				\
	static struct trace_eval_map __used __initdata	\
	__##TRACE_SYSTEM##_##a =			\
	{						\
		.system = TRACE_SYSTEM_STRING,		\
		.eval_string = #a,			\
		.eval_value = a				\
	};						\
	static struct trace_eval_map __used		\
	__section("_ftrace_eval_map")			\
	*TRACE_SYSTEM##_##a = &__##TRACE_SYSTEM##_##a

#undef TRACE_DEFINE_SIZEOF
#define TRACE_DEFINE_SIZEOF(a)				\
	static struct trace_eval_map __used __initdata	\
	__##TRACE_SYSTEM##_##a =			\
	{						\
		.system = TRACE_SYSTEM_STRING,		\
		.eval_string = "sizeof(" #a ")",	\
		.eval_value = sizeof(a)			\
	};						\
	static struct trace_eval_map __used		\
	__section("_ftrace_eval_map")			\
	*TRACE_SYSTEM##_##a = &__##TRACE_SYSTEM##_##a
```

这两者定义了 `struct trace_eval_map` 类型的变量，并将其放到 `__section("_ftrace_eval_map")` 中。

#### 4 采样结果定义--stage1_struct_define

接下来，`TRACE_EVENT` 展开为 `DECLARE_EVENT_CLASS` 和 `DEFINE_EVENT`，如下：

```C
// file: include/trace/trace_events.h
#undef TRACE_EVENT
#define TRACE_EVENT(name, proto, args, tstruct, assign, print) \
	DECLARE_EVENT_CLASS(name,			       \
			     ...
			     PARAMS(print));		       \
	DEFINE_EVENT(name, name, PARAMS(proto), PARAMS(args));
```

接下来，包含 "stages/stage1_struct_define.h" 头文件，进行宏展开。这个阶段定义采样结果结构，如下：

```C
// file: include/trace/trace_events.h
#include "stages/stage1_struct_define.h"

#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(name, proto, args, tstruct, assign, print)	\
	struct trace_event_raw_##name {					\
		struct trace_entry	ent;				\
		tstruct							\
		char			__data[];			\
	};								\
									\
	static struct trace_event_class event_class_##name;

#undef DEFINE_EVENT
#define DEFINE_EVENT(template, name, proto, args)	\
	static struct trace_event_call	__used		\
	__attribute__((__aligned__(4))) event_##name
```

`DEFINE_EVENT_FN` 和 `DEFINE_EVENT_PRINT` 宏重定义为 `DEFINE_EVENT`； `TRACE_EVENT_FN` 重定义为 `TRACE_EVENT`；`TRACE_EVENT_FN_COND` 重定义为 `TRACE_EVENT_CONDITION`。

除此之外，在该阶段还展开了 `TRACE_EVENT_FLAGS` 和 `TRACE_EVENT_PERF_PERM` 如下：

```C
// file: include/trace/trace_events.h
#undef TRACE_EVENT_FLAGS
#define TRACE_EVENT_FLAGS(name, value)					\
	__TRACE_EVENT_FLAGS(name, value)

#undef TRACE_EVENT_PERF_PERM
#define TRACE_EVENT_PERF_PERM(name, expr...)				\
	__TRACE_EVENT_PERF_PERM(name, expr)
```

相关定义如下：

```C
// file: include/linux/trace_events.h
#define __TRACE_EVENT_FLAGS(name, value)				\
	static int __init trace_init_flags_##name(void)			\
	{								\
		event_##name.flags |= value;				\
		return 0;						\
	}								\
	early_initcall(trace_init_flags_##name);

#define __TRACE_EVENT_PERF_PERM(name, expr...)				\
	static int perf_perm_##name(struct trace_event_call *tp_event, \
				    struct perf_event *p_event)		\
	{								\
		return ({ expr; });					\
	}								\
	static int __init trace_init_perf_perm_##name(void)		\
	{								\
		event_##name.perf_perm = &perf_perm_##name;		\
		return 0;						\
	}								\
	early_initcall(trace_init_perf_perm_##name);
```

通过 `early_initcall` 调用设置 `event_##name` 的 `flags` 和 `perf_perm` 字段。

#### 5 采样偏移定义--stage2_data_offsets

这个阶段展开 `DECLARE_EVENT_CLASS`，定义 `trace_event_data_offsets_##call` 结构，定义采样数据的偏移量。如下：

```C
// file: include/trace/trace_events.h
#include "stages/stage2_data_offsets.h"

#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
	struct trace_event_data_offsets_##call {			\
		tstruct;						\
	};
```

#### 6 输出函数定义--stage3_trace_output

该阶段展开 `DECLARE_EVENT_CLASS` 和 `DEFINE_EVENT_PRINT`， 定义 `trace_raw_output_##call` 函数和 `trace_event_type_funcs_##call` 变量，如下：

```C
// file: include/trace/trace_events.h
#include "stages/stage3_trace_output.h"

#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
static notrace enum print_line_t					\
trace_raw_output_##call(struct trace_iterator *iter, int flags,		\
			struct trace_event *trace_event)		\
{									\
	struct trace_seq *s = &iter->seq;				\
	struct trace_seq __maybe_unused *p = &iter->tmp_seq;		\
	struct trace_event_raw_##call *field;				\
	int ret;							\
	field = (typeof(field))iter->ent;				\
	ret = trace_raw_output_prep(iter, trace_event);			\
	if (ret != TRACE_TYPE_HANDLED)					\
		return ret;						\
	trace_event_printf(iter, print);				\
	return trace_handle_return(s);					\
}									\
static struct trace_event_functions trace_event_type_funcs_##call = {	\
	.trace			= trace_raw_output_##call,		\
};

#undef DEFINE_EVENT_PRINT
#define DEFINE_EVENT_PRINT(template, call, proto, args, print)		\
static notrace enum print_line_t					\
trace_raw_output_##call(struct trace_iterator *iter, int flags,		\
			 struct trace_event *event)			\
{									\
	struct trace_event_raw_##template *field;			\
	struct trace_entry *entry;					\
	struct trace_seq *p = &iter->tmp_seq;				\
	entry = iter->ent;						\
	if (entry->type != event_##call.event.type) {			\
		WARN_ON_ONCE(1);					\
		return TRACE_TYPE_UNHANDLED;				\
	}								\
	field = (typeof(field))entry;					\
	trace_seq_init(p);						\
	return trace_output_call(iter, #call, print);			\
}									\
static struct trace_event_functions trace_event_type_funcs_##call = {	\
	.trace			= trace_raw_output_##call,		\
};
```

该阶段定义了 `struct trace_event_functions` 类型的变量，`trace_event_functions` 结构定义如下：

```C
// file: include/linux/trace_events.h
typedef enum print_line_t (*trace_print_func)(struct trace_iterator *iter,
				      int flags, struct trace_event *event);
struct trace_event_functions {
	trace_print_func	trace;
	trace_print_func	raw;
	trace_print_func	hex;
	trace_print_func	binary;
};
```

#### 7 采样字段定义--stage4_event_fields

这个阶段展开 `DECLARE_EVENT_CLASS`，定义 `trace_event_fields_##call` 结构，定义采样数据中每个字段结构。如下：

```C
// file: include/trace/trace_events.h
#include "stages/stage4_event_fields.h"

#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, func, print)	\
static struct trace_event_fields trace_event_fields_##call[] = {	\
	tstruct								\
	{} };
```

#### 8 获取偏移量--stage5_get_offsets

这个阶段展开 `DECLARE_EVENT_CLASS`，定义 `trace_event_get_offsets_##call` 函数，该函数获取采样数据大小。如下：

```C
// file: include/trace/trace_events.h
#include "stages/stage5_get_offsets.h"

#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
static inline notrace int trace_event_get_offsets_##call(		\
	struct trace_event_data_offsets_##call *__data_offsets, proto)	\
{									\
	int __data_size = 0;						\
	int __maybe_unused __item_length;				\
	struct trace_event_raw_##call __maybe_unused *entry;		\
									\
	tstruct;							\
									\
	return __data_size;						\
}
```

#### 9 probe函数--stage6_event_callback

这个阶段展开 `DECLARE_EVENT_CLASS`，定义 `trace_event_raw_event_####call` 函数，该函数生成采样数据后，提交到缓冲区中。如下：

```C
// file: include/trace/trace_events.h
#include "stages/stage6_event_callback.h"

#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
									\
static notrace void							\
trace_event_raw_event_##call(void *__data, proto)			\
{									\
	struct trace_event_file *trace_file = __data;			\
	struct trace_event_data_offsets_##call __maybe_unused __data_offsets;\
	struct trace_event_buffer fbuffer;				\
	struct trace_event_raw_##call *entry;				\
	int __data_size;						\
	if (trace_trigger_soft_disabled(trace_file))			\
		return;							\
	__data_size = trace_event_get_offsets_##call(&__data_offsets, args); \
	entry = trace_event_buffer_reserve(&fbuffer, trace_file,	\
				 sizeof(*entry) + __data_size);		\
	if (!entry)							\
		return;							\
	tstruct								\
	{ assign; }							\
	trace_event_buffer_commit(&fbuffer);				\
}
```

同时展开`DEFINE_EVENT`，定义 `ftrace_test_probe_##call` 函数。如下：

```C
// file: include/trace/trace_events.h
#undef DEFINE_EVENT
#define DEFINE_EVENT(template, call, proto, args)			\
static inline void ftrace_test_probe_##call(void)			\
{									\
	check_trace_callback_type_##call(trace_event_raw_event_##template); \
}
```

#### 10 class定义--stage7_class_define

这个阶段定义展开 `DECLARE_EVENT_CLASS`，定义 `struct trace_event_class` 结构，如下：

```C
// file: include/trace/trace_events.h
#include "stages/stage7_class_define.h"

#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
_TRACE_PERF_PROTO(call, PARAMS(proto));					\
static char print_fmt_##call[] = print;					\
static struct trace_event_class __used __refdata event_class_##call = { \
	.system			= TRACE_SYSTEM_STRING,			\
	.fields_array		= trace_event_fields_##call,		\
	.fields			= LIST_HEAD_INIT(event_class_##call.fields),\
	.raw_init		= trace_event_raw_init,			\
	.probe			= trace_event_raw_event_##call,		\
	.reg			= trace_event_reg,			\
	_TRACE_PERF_INIT(call)						\
};

...
#define _TRACE_PERF_PROTO(call, proto)					\
	static notrace void						\
	perf_trace_##call(void *__data, proto);

#define _TRACE_PERF_INIT(call)						\
	.perf_probe		= perf_trace_##call,
```

展开 `DEFINE_EVENT`, `DEFINE_EVENT_PRINT`, 定义 `struct trace_event_call`，如下：

```C
// file: include/trace/trace_events.h
#undef DEFINE_EVENT
#define DEFINE_EVENT(template, call, proto, args)			\
static struct trace_event_call __used event_##call = {			\
	.class			= &event_class_##template,		\
	{								\
		.tp			= &__tracepoint_##call,		\
	},								\
	.event.funcs		= &trace_event_type_funcs_##template,	\
	.print_fmt		= print_fmt_##template,			\
	.flags			= TRACE_EVENT_FL_TRACEPOINT,		\
};									\
static struct trace_event_call __used					\
__section("_ftrace_events") *__event_##call = &event_##call

#undef DEFINE_EVENT_PRINT
#define DEFINE_EVENT_PRINT(template, call, proto, args, print)		\
static char print_fmt_##call[] = print;					\
static struct trace_event_call __used event_##call = {			\
	.class			= &event_class_##template,		\
	{								\
		.tp			= &__tracepoint_##call,		\
	},								\
	.event.funcs		= &trace_event_type_funcs_##call,	\
	.print_fmt		= print_fmt_##call,			\
	.flags			= TRACE_EVENT_FL_TRACEPOINT,		\
};									\
static struct trace_event_call __used					\
__section("_ftrace_events") *__event_##call = &event_##call
```

终于，我们看到所需要的 `trace_event_call` 和 `trace_event_class` 两个关键结构的定义。也看到了 `__section("_ftrace_events")` 存放的内容，`&event_##call` 的地址。

我们在这个阶段完成了 `trace/trace_events.h` 文件的展开。

#### 11 perf函数--stage6_event_callback

现在，我们进入 `include/trace/perf.h` 文件，继续展开。这个阶段展开 `DECLARE_EVENT_CLASS`, 在上一步中声明了 `perf_trace_##call` 函数, 该阶段实现该函数。perf函数获取采样数据后，执行BPF提交。如下：

```C
// file: include/trace/perf.h
#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
static notrace void							\
perf_trace_##call(void *__data, proto)					\
{									\
	struct trace_event_call *event_call = __data;			\
	struct trace_event_data_offsets_##call __maybe_unused __data_offsets;\
	struct trace_event_raw_##call *entry;				\	
	...
	__data_size = trace_event_get_offsets_##call(&__data_offsets, args); \
	head = this_cpu_ptr(event_call->perf_events);			\
	if (!bpf_prog_array_valid(event_call) &&			\
	    __builtin_constant_p(!__task) && !__task &&			\
	    hlist_empty(head))						\
		return;							\
	__entry_size = ALIGN(__data_size + sizeof(*entry) + sizeof(u32),\
			     sizeof(u64));				\
	__entry_size -= sizeof(u32);					\
	entry = perf_trace_buf_alloc(__entry_size, &__regs, &rctx);	\
	if (!entry)							\
		return;							\
	perf_fetch_caller_regs(__regs);					\
	tstruct								\
	{ assign; }							\
	perf_trace_run_bpf_submit(entry, __entry_size, rctx,		\
				  event_call, __count, __regs,		\
				  head, __task);			\
}
```

同时展开`DEFINE_EVENT` 和 `DEFINE_EVENT_PRINT`，定义 `perf_test_probe_##call` 函数。如下：

```C
// file: include/trace/perf.h
#undef DEFINE_EVENT
#define DEFINE_EVENT(template, call, proto, args)			\
static inline void perf_test_probe_##call(void)				\
{									\
	check_trace_callback_type_##call(perf_trace_##template);	\
}

#undef DEFINE_EVENT_PRINT
#define DEFINE_EVENT_PRINT(template, name, proto, args, print)	\
	DEFINE_EVENT(template, name, PARAMS(proto), PARAMS(args))
```

#### 12 bpf_probe定义--stage6_event_callback

现在，我们进入 `include/trace/bpf_probe.h` 文件，继续展开。这个阶段展开 `DECLARE_EVENT_CLASS`, `DEFINE_EVENT`, `DEFINE_EVENT_PRINT`, `DECLARE_TRACE` ，`DECLARE_TRACE_WRITABLE` 等。这个阶段展开后的宏如下：

```C
// file: include/trace/bpf_probe.h
#define __BPF_DECLARE_TRACE(call, proto, args)				\
static notrace void							\
__bpf_trace_##call(void *__data, proto)					\
{									\
	struct bpf_prog *prog = __data;					\
	CONCATENATE(bpf_trace_run, COUNT_ARGS(args))(prog, CAST_TO_U64(args));	\
}

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

#define __CHECK_WRITABLE_BUF_SIZE(call, proto, args, size)		\
static inline void bpf_test_buffer_##call(void)				\
{									\
	FIRST(proto);							\
	(void)BUILD_BUG_ON_ZERO(size != sizeof(*FIRST(args)));		\
}
```

展开定义如下：

```C
#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
	__BPF_DECLARE_TRACE(call, PARAMS(proto), PARAMS(args))

#undef DEFINE_EVENT_WRITABLE
#define DEFINE_EVENT_WRITABLE(template, call, proto, args, size) \
	__CHECK_WRITABLE_BUF_SIZE(call, PARAMS(proto), PARAMS(args), size) \
	__DEFINE_EVENT(template, call, PARAMS(proto), PARAMS(args), size)

#undef DEFINE_EVENT_PRINT
#define DEFINE_EVENT_PRINT(template, name, proto, args, print)	\
	DEFINE_EVENT(template, name, PARAMS(proto), PARAMS(args))

#undef DEFINE_EVENT
#define DEFINE_EVENT(template, call, proto, args)			\
	__DEFINE_EVENT(template, call, PARAMS(proto), PARAMS(args), 0)

#undef DECLARE_TRACE
#define DECLARE_TRACE(call, proto, args)				\
	__BPF_DECLARE_TRACE(call, PARAMS(proto), PARAMS(args))		\
	__DEFINE_EVENT(call, call, PARAMS(proto), PARAMS(args), 0)

#undef DECLARE_TRACE_WRITABLE
#define DECLARE_TRACE_WRITABLE(call, proto, args, size) \
	__CHECK_WRITABLE_BUF_SIZE(call, PARAMS(proto), PARAMS(args), size) \
	__BPF_DECLARE_TRACE(call, PARAMS(proto), PARAMS(args)) \
	__DEFINE_EVENT(call, call, PARAMS(proto), PARAMS(args), size)
```

该阶段定义了 `__bpf_trace_##call` 函数，该函数用于执行bpf程序；定义了 `__bpf_trace_tp_map_##call` 变量，并将其存放到 `__section("__bpf_raw_tp_map")` 中，我们将在后续分析其作用。

现在我们终于完成了一个TRACE_EVENT展开。

### 3.4 ftrace_events的初始化过程

`ftrace_events`的初始化过程分为两个步骤，在`start_kernel`函数中初始化和通过`initcall`机制初始化。

#### 1 `start_kernel` 阶段

在这个阶段注册 `trace_event` 事件，包括：静态`events`, `ftrace_events`； 注册控制指令；必要时根据启动参数开启指定的事件。调用过程如下：

```C
// file: init/main.c
start_kernel(void)
    // file: kernel/trace/trace.c
    --> early_trace_init();
        --> tracer_alloc_buffers();
           // 添加 global_trace
            --> list_add(&global_trace.list, &ftrace_trace_arrays);
        // file: kernel/trace/trace_output.c
        --> init_events();
            // 默认事件注册, type固定
            --> for (i = 0; events[i]; i++) 
                --> event = events[i];
                --> ret = register_trace_event(event);
                    //type == 0 时，分配type
                    --> event->type = alloc_trace_event_type(); 
                        --> next = ida_alloc_range(&trace_event_ida, __TRACE_LAST_TYPE, ...);
                    --> hlist_add_head(&event->node, &event_hash[key]);
    // file: kernel/trace/trace.c
    --> trace_init();
    	// file: kernel/trace/trace_events.c
        --> trace_event_init()
            --> event_trace_memsetup();
                --> field_cachep = KMEM_CACHE(ftrace_event_field, SLAB_PANIC);
                --> file_cachep = KMEM_CACHE(trace_event_file, SLAB_PANIC);
            // file: kernel/trace/trace_syscalls.c
            // 初始化syscall相关内容，设置syscall_nr
            --> init_ftrace_syscalls();
                --> for (i = 0; i < NR_syscalls; i++)
                    --> addr = arch_syscall_addr(i);
                    --> meta = find_syscall_meta(addr);
                    --> meta->syscall_nr = i;
            --> event_trace_enable();
                --> struct trace_array *tr = top_trace_array(); // global_trace
                // 初始化 _ftrace_events 事件
                --> for_each_event(iter, __start_ftrace_events, __stop_ftrace_events)
                    --> call = *iter;
                    --> ret = event_init(call);
                        // event 初始化，设置raw_init时，调用
                        --> call->class->raw_init(call);
                    --> list_add(&call->list, &ftrace_events);
                // file: kernel/trace/trace_events.c
                --> register_trigger_cmds();
                    // file: kernel/trace/trace_events_trigger.c
                    --> register_trigger_traceon_traceoff_cmds();
                        --> register_event_command(&trigger_traceon_cmd);
                            --> list_add(&cmd->list, &trigger_commands);
                        --> register_event_command(&trigger_traceoff_cmd);
                    --> ....
                --> __trace_early_add_events(tr);
                    --> list_for_each_entry(call, &ftrace_events, list)
                        // 添加ftrace_events 到 tr中，创建file
                        --> __trace_early_add_new_event(call, tr);
                            --> file = trace_create_new_event(call, tr);
                                --> file = kmem_cache_alloc(file_cachep, GFP_TRACE);
                                --> file->event_call = call;
                                --> list_add(&file->list, &tr->events);
                        // 创建事件的字段信息
                        --> event_define_fields(call);
                            --> head = trace_get_fields(call);
                            --> struct trace_event_fields *field = call->class->fields_array;
                            --> for (; field->type; field++) 
                                --> if (field->type == TRACE_FUNCTION_TYPE) 
                                    --> field->define_fields(call);
                                --> trace_define_field_ext(call, field->type, field->name,...);
                                    --> __trace_define_field(....);
                        --> trace_early_triggers(file, trace_event_name(call));
                // 开启事件，通过命令行中 trace_event 选项设置
                --> early_enable_events(tr, bootup_event_buf, false);
                    --> token = strsep(&buf, ",");
                    --> ftrace_set_clr_event(tr, token, 1);
                        --> __ftrace_set_clr_event(tr, match, sub, event, set);
                            --> __ftrace_set_clr_event_nolock(tr, match, sub, event, set);
                                --> list_for_each_entry(file, &tr->events, list)
                                    --> ftrace_event_enable_disable(file, set);
                                        --> __ftrace_event_enable_disable(file, enable, 0);
                                            --> call->class->reg(call, TRACE_REG_UNREGISTER, file);
                                            --> call->class->reg(call, TRACE_REG_REGISTER, file);
                --> register_event_cmds();
                    --> register_ftrace_command(&event_enable_cmd);
                    --> register_ftrace_command(&event_disable_cmd);
            --> event_trace_init_fields();
                --> trace_define_generic_fields();
                --> trace_define_common_fields();
```

在 `ftrace_events` 初始化过程中调用了 `call->class->raw_init(call);` 函数，在TRACE_EVENT展开过程中，我们知道该函数为 `trace_event_raw_init` ， 如下：

```C
static struct trace_event_class __used __refdata event_class_##call = { \
	...								\
	.raw_init		= trace_event_raw_init,			\
	...								\
};
```

`trace_event_raw_init` 实现如下：

```C
int trace_event_raw_init(struct trace_event_call *call)
{
	int id;
	id = register_trace_event(&call->event);
	if (!id) return -ENODEV;
	test_event_printk(call);
	return 0;
}
```

可以看到，通过 `register_trace_event` 注册 `trace_event`，在注册过程分配 `event->type`。

#### 2 `core_initcall` 阶段

在这个阶段进行文件系统的注册，主要有：

* `core_initcall(tracefs_init)`
  
进行 `tracefs` 文件系统的注册，通过 `register_filesystem` 函数将 `trace_fs_type` 文件系统注册到系统中。实现如下：

```C
// file: fs/tracefs/inode.c
static int __init tracefs_init(void)
{
	int retval;
	retval = sysfs_create_mount_point(kernel_kobj, "tracing");
	if (retval) return -EINVAL;
	retval = register_filesystem(&trace_fs_type);
	if (!retval) tracefs_registered = true;
	return retval;
}

static struct file_system_type trace_fs_type = {
	.owner =	THIS_MODULE,
	.name =		"tracefs",
	.mount =	trace_mount,
	.kill_sb =	kill_litter_super,
};
MODULE_ALIAS_FS("tracefs");
```

* `core_initcall(debugfs_init)`
  
进行 `debugfs` 文件系统的注册。实现如下：

```C
// file: fs/debugfs/inode.c
static int __init debugfs_init(void)
{
	int retval;
	if (!(debugfs_allow & DEBUGFS_ALLOW_MOUNT)) return -EPERM;
	retval = sysfs_create_mount_point(kernel_kobj, "debug");
	if (retval) return -EINVAL;
	retval = register_filesystem(&debug_fs_type);
	if (retval)
		sysfs_remove_mount_point(kernel_kobj, "debug");
	else
		debugfs_registered = true;
	return retval;
}

static struct file_system_type debug_fs_type = {
	.owner =	THIS_MODULE,
	.name =		"debugfs",
	.mount =	debug_mount,
	.kill_sb =	kill_litter_super,
};
MODULE_ALIAS_FS("debugfs");
```

#### 3 `fs_initcall` 阶段

在 `fs_initcall` 阶段创建有关trace相关文件信息。主要有：

* `fs_initcall(tracer_init_tracefs)`

创建 `trace` 相关目录及文件，实现如下：

```C
// file: kernel/trace/trace.c
static __init int tracer_init_tracefs(void)
    --> tracing_init_dentry();
        --> struct trace_array *tr = &global_trace;
        // 在debugfs目录下创建`tracing`目录, `trace_automount`挂载`tracefs`文件系统
        --> tr->dir = debugfs_create_automount("tracing", NULL, trace_automount, NULL);
    // 通过queue work方式或直接调用
    --> tracer_init_tracefs_work_func(NULL)；
        --> event_trace_init();
            // tr为 `global_trace`
            --> tr = top_trace_array(); 
            //创建`available_events` 文件
            --> trace_create_file("available_events", TRACE_MODE_READ, NULL, tr, &ftrace_avail_fops);
            --> early_event_add_tracer(NULL, tr);
                --> create_event_toplevel_files(parent, tr);
                    --> entry = trace_create_file("set_event", TRACE_MODE_WRITE, parent, tr, &ftrace_set_event_fops);
                    // Tracepoint所在的events目录
                    --> d_events = tracefs_create_dir("events", parent);
                    --> entry = trace_create_file("enable", TRACE_MODE_WRITE, d_events, tr, &ftrace_tr_enable_fops);
                    --> ...
                    --> tr->event_dir = d_events;
                --> __trace_early_add_event_dirs(tr);
                    --> list_for_each_entry(file, &tr->events, list)
                        //创建event需要的文件和目录
                        --> event_create_dir(tr->event_dir, file);
                            //创建子系统目录，对应tp_category
                            --> if (strcmp(call->class->system, TRACE_SYSTEM) != 0) 
                                --> d_events = event_subsystem_dir(tr, call->class->system, file, parent);
                                    --> dir->entry = tracefs_create_dir(name, parent);
                            --> name = trace_event_name(call);
                            // 创建名称目录，对应tp_name
                            --> file->dir = tracefs_create_dir(name, d_events);
                            --> event_define_fields(call);
                            --> trace_create_file("enable", TRACE_MODE_WRITE, file->dir, file, &ftrace_enable_fops);
                            // 创建id文件，内容为call->event.type
                            --> trace_create_file("id", TRACE_MODE_READ, file->dir, (void *)(long)call->event.type, &ftrace_event_id_fops);
                            --> trace_create_file("filter", TRACE_MODE_WRITE, file->dir, file, &ftrace_event_filter_fops);
                            --> trace_create_file("trigger", TRACE_MODE_WRITE, file->dir, file, &event_trigger_fops);
                            --> trace_create_file("hist", TRACE_MODE_READ, file->dir, file, &event_hist_fops);
                            --> trace_create_file("hist_debug", TRACE_MODE_WRITE, file->dir, file, &event_hist_debug_fops);
                            --> trace_create_file("format", TRACE_MODE_WRITE, file->dir, file, &ftrace_event_format_fops);
                            --> trace_create_file("inject", 0200, file->dir, file, &event_inject_fops);
        //创建`tracer`对应的文件
        --> init_tracer_tracefs(&global_trace, NULL);
            --> trace_create_file("available_tracers", TRACE_MODE_READ, d_tracer, tr, &show_traces_fops);
            --> trace_create_file("current_tracer", TRACE_MODE_WRITE, d_tracer, tr, &set_tracer_fops);
            --> ...
            --> trace_create_file("trace_pipe", TRACE_MODE_READ, d_tracer, tr, &tracing_pipe_fops);
            --> ...
            --> ...
        //创建`ftrace`对应的文件
        --> ftrace_init_tracefs_toplevel(&global_trace, NULL);
            --> ftrace_init_dyn_tracefs(d_tracer);
                --> trace_create_file("available_filter_functions", TRACE_MODE_READ, d_tracer, NULL, &ftrace_avail_fops);
                --> trace_create_file("enabled_functions", TRACE_MODE_READ, d_tracer, NULL, &ftrace_enabled_fops);
                --> ...
            --> ftrace_profile_tracefs(d_tracer);
                --> for_each_possible_cpu(cpu)
                    --> register_stat_tracer(&stat->stat);
                --> trace_create_file("function_profile_enabled", TRACE_MODE_WRITE, d_tracer, NULL, &ftrace_profile_fops);
        --> trace_create_file("tracing_thresh", TRACE_MODE_WRITE, NULL, &global_trace, &tracing_thresh_fops);
        --> trace_create_file("README", TRACE_MODE_READ, NULL, NULL, &tracing_readme_fops);
        --> ...
        --> trace_create_eval_file(NULL);
            --> trace_create_file("eval_map", TRACE_MODE_READ, d_tracer, NULL, &tracing_eval_map_fops);
        --> trace_create_file("dyn_ftrace_total_info", TRACE_MODE_READ, NULL, NULL, &tracing_dyn_info_fops);
        --> create_trace_instances(NULL);
            --> tracefs_create_instance_dir("instances", d_tracer, instance_mkdir, instance_rmdir);
        --> update_tracer_options(&global_trace);
            --> __update_tracer_options(tr);
    --> rv_init_interface();
```

在 `__trace_early_add_event_dirs` 函数中，遍历 `tr->events`列表，对每个event创建 `<category>/<name>` 目录。并在该文件夹下创建 `id` 文件，里面存放 `call->event.type` 的值。在 `start_kernel` 阶段，event在初始化注册过程通过 `alloc_trace_event_type` 分配了 `event->type`。至此，我们将 `debugfs` 或 `tracefs` 挂载到系统后，通过读取 `/sys/kernel/debug/tracing/events/<category>/<name>/id` 文件，通过id内核就能识别对应的 `event`。

### 3.5 trace_event调用BPF程序的实现过程

#### 1 trace_event_reg的实现

在 `Tracepoint的PMU操作接口` 这节，我们知道`tp_event` 通过 `tp_event->class->reg(...)` 实现注册/注销、打开/关闭、添加/删除等操作。在 `TRACE_EVENT` 展开过程，我们知道reg函数为 `trace_event_reg`。

```C
static struct trace_event_class __used __refdata event_class_##call = { \
	...								\
	.reg			= trace_event_reg,			\
	_TRACE_PERF_INIT(call)						\
};

#define _TRACE_PERF_INIT(call)						\
	.perf_probe		= perf_trace_##call,
```

`trace_event_reg` 实现如下：

```C
// file: kernel/trace/trace_events.c
int trace_event_reg(struct trace_event_call *call, enum trace_reg type, void *data)
{
	struct trace_event_file *file = data;
	WARN_ON(!(call->flags & TRACE_EVENT_FL_TRACEPOINT));
	switch (type) {
	case TRACE_REG_REGISTER:
		return tracepoint_probe_register(call->tp, call->class->probe, file);
	case TRACE_REG_UNREGISTER:
		tracepoint_probe_unregister(call->tp, call->class->probe, file);
		return 0;
#ifdef CONFIG_PERF_EVENTS
	case TRACE_REG_PERF_REGISTER:
		return tracepoint_probe_register(call->tp, call->class->perf_probe, call);
	case TRACE_REG_PERF_UNREGISTER:
		tracepoint_probe_unregister(call->tp, call->class->perf_probe, call);
		return 0;
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

可以看到，只响应 `TRACE_REG_PERF_REGISTER` 和 `TRACE_REG_PERF_UNREGISTER` 操作。`call->class->perf_probe` 即 `perf_trace_##call` 函数。

* TRACE_REG_PERF_REGISTER 过程

`tracepoint_probe_register` 实现tp_event触发函数注册，实现如下：

```C
// file: kernel/tracepoint.c
int tracepoint_probe_register(struct tracepoint *tp, void *probe, void *data)
    --> tracepoint_probe_register_prio(tp, probe, data, TRACEPOINT_DEFAULT_PRIO);
        --> struct tracepoint_func tp_func;
        --> tp_func.func = probe;
        --> tp_func.data = data;
        --> tp_func.prio = prio;
        --> tracepoint_add_func(tp, &tp_func, prio, true);
            // tp注册函数
            --> if (tp->regfunc && !static_key_enabled(&tp->key))
                --> tp->regfunc();
            // 添加到tp->funcs列表
            --> func_add(&tp_funcs, func, prio);
            --> tracepoint_update_call(tp, tp_funcs);
            --> rcu_assign_pointer(tp->funcs, tp_funcs);
```

* TRACE_REG_PERF_UNREGISTER 过程

`tracepoint_probe_unregister` 实现tp_event触发函数注销，实现如下：

```C
// file: kernel/tracepoint.c
int tracepoint_probe_unregister(struct tracepoint *tp, void *probe, void *data)
    --> struct tracepoint_func tp_func;
    --> tp_func.func = probe;
    --> tp_func.data = data;
    --> tracepoint_remove_func(tp, &tp_func);
        // 从tp->funcs列表中移除
        --> func_remove(&tp_funcs, func);
        --> tracepoint_update_call(tp, tp_funcs);
        --> rcu_assign_pointer(tp->funcs, tp_funcs);
        // 移除最后一个函数时，调用tp注销函数
        --> if (tp->unregfunc && static_key_enabled(&tp->key))
            --> tp->unregfunc();
```

#### 2 trace_event设置BPF程序

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

Tracepoint属于tracing事件，通过`perf_event_attach_bpf_prog` 添加bpf程序到 `tp_event->prog_array` 列表中。

#### 3 trace_event的触发过程

在 `TRACE_EVENT` 展开过程的第一个阶段，我们知道调用 `trace_##name` 函数时，触发我们的tp事件。在上一节中，我们将 `perf_trace_##call` 注册到 `tp->funcs` 列表中。`perf_trace_##call` 在`TRACE_EVENT`展开的第十一阶段展开的，实现过程如下：

```C
// file: include/trace/perf.h
static notrace void perf_trace_##call(void *__data, proto)
    // 获取采样数据大小
    --> __data_size = trace_event_get_offsets_##call(&__data_offsets, args);
    --> entry = perf_trace_buf_alloc(__entry_size, &__regs, &rctx);
        //获取context
        --> *rctxp = rctx = perf_swevent_get_recursion_context();
        //获取trace缓冲区
        --> raw_data = this_cpu_ptr(perf_trace_buf[rctx]);
        --> memset(&raw_data[size - sizeof(u64)], 0, sizeof(u64));
    --> perf_fetch_caller_regs(__regs);	
    // 采集数据
    --> { assign; }
    // file: kernel/events/core.c
    --> perf_trace_run_bpf_submit(entry, __entry_size, rctx, event_call, ...);
        --> if (bpf_prog_array_valid(call))
            // 执行BPF程序
            --> trace_call_bpf(call, raw_data)
                --> bpf_prog_run_array(rcu_dereference(call->prog_array), ctx, bpf_prog_run);
                    --> item = &array->items[0];
                    --> while ((prog = READ_ONCE(item->prog))) 
                            --> run_ctx.bpf_cookie = item->bpf_cookie;
                            --> ret &= run_prog(prog, ctx);
                            --> item++;
            // 释放context
            --> perf_swevent_put_recursion_context(rctx);
        // 没有设置BPF程序或执行失败时，执行默认操作
        --> perf_tp_event(call->event.type, count, raw_data, size, regs, head, rctx, task);
            --> perf_sample_save_raw_data(&data, &raw);
            --> hlist_for_each_entry_rcu(event, head, hlist_entry)
                //检查tp事件是否符合
                --> if (perf_tp_event_match(event, &data, regs))
                    //软件事件溢出处理
                    --> perf_swevent_event(event, count, &data, regs);
                        --> __perf_event_overflow(event, throttle, data, regs);
                            --> READ_ONCE(event->overflow_handler)(event, data, regs);
                            //bpf溢出处理
                            --> bpf_overflow_handler(struct perf_event *event,...)
                                --> prog = READ_ONCE(event->prog);
                                --> perf_prepare_sample(data, event, regs);
                                --> bpf_prog_run(prog, &ctx);
                                //默认溢出处理
                                --> event->orig_overflow_handler(event, data, regs);
            --> perf_swevent_put_recursion_context(rctx);
```

通过上面的调用过程，可以在两个地方执行BPF程序，①在 `trace_call_bpf` 中遍历 `call->prog_array` 列表中的bpf程序逐个执行；②在`perf_swevent_event` 函数中执行 `event->overflow_handler` 时（在设置bpf程序后，设置为 `bpf_overflow_handler` ），执行 `event->prog`。

### 3.6 syscall_tp的实现

在前面我们分析 `TRACE_EVENT` 的展开过程，在`class定义`步骤中我们看到了 `__section("_ftrace_events")` 的一种实现，在这节中，我们将分析 `syscall_tp` 的实现。

#### 1 `ftrace_events` 的定义 

syscalls定义使用的 `SYSCALL_DEFINE` 宏定义如下：

```C
// file：include/linux/syscalls.h
#define SYSCALL_DEFINE0(sname)					\
	SYSCALL_METADATA(_##sname, 0);				\
	...							\

#define SYSCALL_DEFINEx(x, sname, ...)				\
	SYSCALL_METADATA(sname, x, __VA_ARGS__)			\
	__SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

#define SYSCALL_TRACE_ENTER_EVENT(sname)				\
	static struct syscall_metadata __syscall_meta_##sname;		\
	static struct trace_event_call __used				\
	  event_enter_##sname = {					\
		.class			= &event_class_syscall_enter,	\
		{							\
			.name                   = "sys_enter"#sname,	\
		},							\
		.event.funcs            = &enter_syscall_print_funcs,	\
		.data			= (void *)&__syscall_meta_##sname,\
		.flags                  = TRACE_EVENT_FL_CAP_ANY,	\
	};								\
	static struct trace_event_call __used				\
	  __section("_ftrace_events")					\
	 *__event_enter_##sname = &event_enter_##sname;

#define SYSCALL_TRACE_EXIT_EVENT(sname)					\
	static struct syscall_metadata __syscall_meta_##sname;		\
	static struct trace_event_call __used				\
	  event_exit_##sname = {					\
		.class			= &event_class_syscall_exit,	\
		{							\
			.name                   = "sys_exit"#sname,	\
		},							\
		.event.funcs		= &exit_syscall_print_funcs,	\
		.data			= (void *)&__syscall_meta_##sname,\
		.flags                  = TRACE_EVENT_FL_CAP_ANY,	\
	};								\
	static struct trace_event_call __used				\
	  __section("_ftrace_events")					\
	*__event_exit_##sname = &event_exit_##sname;

#define SYSCALL_METADATA(sname, nb, ...)			\
	...							\
	SYSCALL_TRACE_ENTER_EVENT(sname);			\
	SYSCALL_TRACE_EXIT_EVENT(sname);			\
	static struct syscall_metadata __used			\
	  __syscall_meta_##sname = {
		.name 		= "sys"#sname,			\
		.syscall_nr	= -1,	/* Filled in at boot */	\
		...						\
		.enter_event	= &event_enter_##sname,		\
		.exit_event	= &event_exit_##sname,		\
	};							\
	static struct syscall_metadata __used			\
	  __section("__syscalls_metadata")			\
	 *__p_syscall_meta_##sname = &__syscall_meta_##sname;
```

在定义syscall时，`__syscall_meta_##sname` 中`enter_event`字段表示进入系统调用时的事件， `exit_event`字段表示退出系统调用的事件。 

`event_enter_##sname` 和 `event_exit_##sname` 对应的class分别为 `event_class_syscall_enter` 和 `event_class_syscall_exit` ，定义如下：

```C
// file: kernel/trace/trace_syscalls.c
struct trace_event_class __refdata event_class_syscall_enter = {
	.system		= "syscalls",
	.reg		= syscall_enter_register,
	.fields_array	= syscall_enter_fields_array,
	.get_fields	= syscall_get_enter_fields,
	.raw_init	= init_syscall_trace,
};

struct trace_event_class __refdata event_class_syscall_exit = {
	.system		= "syscalls",
	.reg		= syscall_exit_register,
	.fields_array	= (struct trace_event_fields[]){
		SYSCALL_FIELD(int, __syscall_nr),
		SYSCALL_FIELD(long, ret),
		{}
	},
	.fields		= LIST_HEAD_INIT(event_class_syscall_exit.fields),
	.raw_init	= init_syscall_trace,
};
```

#### 2 raw_init的初始化实现

`event_class_syscall_enter` 和 `event_class_syscall_exit` 这两个class的 `raw_init` 函数均设置为 `init_syscall_trace` 。实现如下：

```C
// file: kernel/trace/trace_syscalls.c
static int __init init_syscall_trace(struct trace_event_call *call)
{
	int id;
	int num;
	num = ((struct syscall_metadata *)call->data)->syscall_nr;
	if (num < 0 || num >= NR_syscalls) {
		pr_debug("syscall %s metadata not mapped, disabling ftrace event\n",
				((struct syscall_metadata *)call->data)->name);
		return -ENOSYS;
	}
	//设置打印格式
	if (set_syscall_print_fmt(call) < 0)
		return -ENOMEM;
	// trace_event注册、分配type
	id = trace_event_raw_init(call);
	if (id < 0) {
		free_syscall_print_fmt(call);
		return id;
	}
	return id;
}
```

可以看到，在检查 `syscall_nr` 在范围内后，调用 `trace_event_raw_init` 进行注册。

#### 3 syscall_enter的reg实现

`event_class_syscall_enter` 的reg字段定义为 `.reg = syscall_enter_register,`, 实现如下：

```C
// file: kernel/trace/trace_syscalls.c
static int syscall_enter_register(struct trace_event_call *event, num trace_reg type, void *data)
{
	switch (type) {
	...
#ifdef CONFIG_PERF_EVENTS
	case TRACE_REG_PERF_REGISTER:
		return perf_sysenter_enable(event);
	case TRACE_REG_PERF_UNREGISTER:
		perf_sysenter_disable(event);
		return 0;
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

在我们继续之前，我们看下 `sys_enter` 有关 `TRACE_EVENT` 的宏定义，如下：

```C
// file: include/trace/events/syscalls.h
TRACE_EVENT_FN(sys_enter,
	...
	syscall_regfunc, syscall_unregfunc
);
```

* `TRACE_REG_PERF_REGISTER`

`perf_sysenter_enable` 实现syscall_tp触发函数的注册，实现如下：

```C
//file: kernel/trace/trace_syscalls.c
static int perf_sysenter_enable(struct trace_event_call *call)
{
	int ret = 0;
	int num;
	num = ((struct syscall_metadata *)call->data)->syscall_nr;
	mutex_lock(&syscall_trace_lock);
	if (!sys_perf_refcount_enter)
		ret = register_trace_sys_enter(perf_syscall_enter, NULL);
	if (ret) {
		pr_info("event trace: Could not activate syscall entry trace point");
	} else {
		set_bit(num, enabled_perf_enter_syscalls);
		sys_perf_refcount_enter++;
	}
	mutex_unlock(&syscall_trace_lock);
	return ret;
}
```

首先检查 `sys_perf_refcount_enter` 值，在其为0时，调用 `register_trace_sys_enter` 注册 `perf_syscall_enter` 处理函数。注册成功后设置 `enabled_perf_enter_syscalls` 中syscall_nr对应bit位, `enabled_perf_enter_syscalls` 是个bitmap，定义如下：

```C
// file: kernel/trace/trace_syscalls.c
static DECLARE_BITMAP(enabled_perf_enter_syscalls, NR_syscalls);
```

`register_trace_sys_enter` 在 `TRACE_EVENT` 展开的第一个阶段定义。如下：

```C
// file: include/linux/tracepoint.h
static inline int						\
register_trace_##name(void (*probe)(data_proto), void *data)	\
{								\
	return tracepoint_probe_register(&__tracepoint_##name,	\
					(void *)probe, data);	\
}	
```

通过 `tracepoint_probe_register` 函数将 `perf_syscall_enter` 注册到 `tp->funcs` 列表中。

* `TRACE_REG_PERF_UNREGISTER`

`perf_sysenter_disable` 实现syscall_tp触发函数的注销，实现如下：

```C
//file: kernel/trace/trace_syscalls.c
static void perf_sysenter_disable(struct trace_event_call *call)
{
	int num;
	num = ((struct syscall_metadata *)call->data)->syscall_nr;
	mutex_lock(&syscall_trace_lock);
	sys_perf_refcount_enter--;
	clear_bit(num, enabled_perf_enter_syscalls);
	if (!sys_perf_refcount_enter)
		unregister_trace_sys_enter(perf_syscall_enter, NULL);
	mutex_unlock(&syscall_trace_lock);
}
```

减少 `sys_perf_refcount_enter` 的值，在其为0时，调用 `unregister_trace_sys_enter` 函数注销 `perf_syscall_enter` 处理函数。同时，清除 `enabled_perf_enter_syscalls` 中syscall_nr对应bit位。

* `syscall_regfunc` 和 `syscall_unregfunc`

在 `TRACE_EVENT_FN(sys_enter,...)` 的过程中，设置了 `syscall_regfunc` 和 `syscall_unregfunc` 函数，分别表示注册和注销时调用的函数，实现如下：

```C
// file: kernel/tracepoint.c
int syscall_regfunc(void)
{
	struct task_struct *p, *t;
	if (!sys_tracepoint_refcount) {
		read_lock(&tasklist_lock);
		for_each_process_thread(p, t) {
			set_task_syscall_work(t, SYSCALL_TRACEPOINT);
		}
		read_unlock(&tasklist_lock);
	}
	sys_tracepoint_refcount++;
	return 0;
}

void syscall_unregfunc(void)
{
	struct task_struct *p, *t;
	sys_tracepoint_refcount--;
	if (!sys_tracepoint_refcount) {
		read_lock(&tasklist_lock);
		for_each_process_thread(p, t) {
			clear_task_syscall_work(t, SYSCALL_TRACEPOINT);
		}
		read_unlock(&tasklist_lock);
	}
}
```

`syscall_regfunc` 设置每个进程每个线程的 `SYSCALL_TRACEPOINT` 标记，而 `syscall_unregfunc` 则清除这个标记。实现如下：

```C
// file：include/linux/thread_info.h
#define set_task_syscall_work(t, fl) \
	set_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
#define test_task_syscall_work(t, fl) \
	test_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
#define clear_task_syscall_work(t, fl) \
	clear_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
```

#### 4 syscall_exit的reg实现

`event_class_syscall_exit` 的reg字段定义为 `.reg = syscall_exit_register,`, 实现如下：

```C
// file: kernel/trace/trace_syscalls.c
static int syscall_exit_register(struct trace_event_call *event,
				 enum trace_reg type, void *data)
{
...
#ifdef CONFIG_PERF_EVENTS
	case TRACE_REG_PERF_REGISTER:
		return perf_sysexit_enable(event);
	case TRACE_REG_PERF_UNREGISTER:
		perf_sysexit_disable(event);
		return 0;
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

`sys_exit` 有关 `TRACE_EVENT` 的宏定义，如下：

```C
// file: include/trace/events/syscalls.h
TRACE_EVENT_FN(sys_exit,
	...
	syscall_regfunc, syscall_unregfunc
);
```

和 `sys_enter` 的实现过程类似，`sys_exit` 注册/注销 `perf_syscall_exit`，设置 `enabled_perf_exit_syscalls` 位图信息。

#### 5 syscall_tp设置BPF程序

同`trace_events`相同，通过`ioctl`方式或`bpf`系统调用方式，调用 `perf_event_set_bpf_prog` 函数进行设置。

#### 6 syscall调用过程

系统调用的实现过程参见 [How the Linux kernel handles a system call](https://0xax.gitbook.io/linux-insides/summary/syscall/linux-syscall-2) 或 [内核系统调用（第二部分）](https://github.com/mannkafai/linux-insides-zh/blob/main/04-syscall/04-syscall-02.md)。我们不用关注用户空间和内核空间的切换过程，只关注内核的实现，`do_syscall_64`函数中触发tp的过程如下：

```C
// file：arch/x86/entry/common.c
__visible noinstr void do_syscall_64(struct pt_regs *regs, int nr)
    --> nr = syscall_enter_from_user_mode(regs, nr);
        --> __syscall_enter_from_user_work(regs, syscall);
            --> syscall = syscall_trace_enter(regs, syscall, work);
                //通过`syscall_regfunc`设置标记
                 --> if (unlikely(work & SYSCALL_WORK_SYSCALL_TRACEPOINT))
                    --> trace_sys_enter(regs, syscall);
    --> do_syscall_x64(regs, nr)
        --> regs->ax = sys_call_table[unr](regs);
    --> syscall_exit_to_user_mode(regs);
        --> __syscall_exit_to_user_mode_work(regs);
            --> syscall_exit_to_user_mode_prepare(regs);
                --> syscall_exit_work(regs, work);
                    --> if (work & SYSCALL_WORK_SYSCALL_TRACEPOINT)
                        --> trace_sys_exit(regs, syscall_get_return_value(current, regs));
```

#### 7 sys_enter的触发过程

在 “syscall_enter的reg实现” 中，将 `perf_syscall_enter` 注册到 `tp->funcs` 中。实现如下：

```C
// file: kernel/trace/trace_syscalls.c
static void perf_syscall_enter(void *ignore, struct pt_regs *regs, long id)
	--> syscall_nr = trace_get_syscall_nr(current, regs);
	//检查 syscall_nr 范围
	--> if (syscall_nr < 0 || syscall_nr >= NR_syscalls) return;
	//检查 syscall_nr 是否在 `enabled_perf_enter_syscalls` 中
	--> if (!test_bit(syscall_nr, enabled_perf_enter_syscalls)) return;
	// enter_event 中bpf程序不为空
	--> valid_prog_array = bpf_prog_array_valid(sys_data->enter_event);
	//计算分配数据大小
	--> size = sizeof(unsigned long) * sys_data->nb_args + sizeof(*rec);
	--> rec = perf_trace_buf_alloc(size, NULL, &rctx);
	// 获取采样数据，系统调用编号、参数
	--> rec->nr = syscall_nr;
	--> syscall_get_arguments(current, regs, args);
	--> memcpy(&rec->args, args, sizeof(unsigned long) * sys_data->nb_args);
	// 调用BPF程序
	--> perf_call_bpf_enter(sys_data->enter_event, regs, sys_data, rec);
		//封装系统调用参数
		--> *(struct pt_regs **)&param = regs;
		--> param.syscall_nr = rec->nr;
		--> for (i = 0; i < sys_data->nb_args; i++)
			--> param.args[i] = rec->args[i];
		//调用BPF程序
		--> trace_call_bpf(call, &param);
	//默认执行操作
	--> perf_trace_buf_submit(rec, size, rctx, sys_data->enter_event->event.type, ...);
		--> perf_tp_event(type, count, raw_data, size, regs, head, rctx, task);
```

#### 8 sys_exit的触发过程

在 “syscall_exit的reg实现” 中，将 `perf_syscall_exit` 注册到 `tp->funcs` 中。实现如下：

```C
// file: kernel/trace/trace_syscalls.c
static void perf_syscall_exit(void *ignore, struct pt_regs *regs, long ret)
	--> syscall_nr = trace_get_syscall_nr(current, regs);
	//检查 syscall_nr 范围
	--> if (syscall_nr < 0 || syscall_nr >= NR_syscalls) return;
	//检查 syscall_nr 是否在 `enabled_perf_exit_syscalls` 中
	--> if (!test_bit(syscall_nr, enabled_perf_exit_syscalls)) return;
	// exit_event 中bpf程序不为空
	--> valid_prog_array = bpf_prog_array_valid(sys_data->exit_event);
	//计算分配数据大小
	--> size = ALIGN(sizeof(*rec) + sizeof(u32), sizeof(u64));
	--> rec = perf_trace_buf_alloc(size, NULL, &rctx);
	// 获取采样数据，系统调用编号、返回值
	--> rec->nr = syscall_nr;
	--> rec->ret = syscall_get_return_value(current, regs);
	// 调用BPF程序
	--> perf_call_bpf_exit(sys_data->exit_event, regs, rec);
		//封装系统调用参数
		--> *(struct pt_regs **)&param = regs;
		--> param.syscall_nr = rec->nr;
		--> param.ret = rec->ret;
		//调用BPF程序
		--> trace_call_bpf(call, &param);
	//默认执行操作
	--> perf_trace_buf_submit(rec, size, rctx, sys_data->exit_event->event.type, ...);
		--> perf_tp_event(type, count, raw_data, size, regs, head, rctx, task);
```

## 4 总结

本文分析了`minimal`示例挂载BPF程序到Tracepoint过程中Linux内核的实现过程，分析了 `ftrace_events` 定义、初始化、`TRACE_EVENT` 展开过程、调用BPF程序等过程，分析 syscal_tp 的实现过程。

## 参考资料

* [Using the TRACE_EVENT() macro (Part 1)](https://lwn.net/Articles/379903/)
* [Using the TRACE_EVENT() macro (Part 2)](https://lwn.net/Articles/381064/)
* [Using the TRACE_EVENT() macro (Part 3)](https://lwn.net/Articles/383362/)
* [Linux tracing - trace event framework](http://terenceli.github.io/%E6%8A%80%E6%9C%AF/2020/08/08/trace-event-framework) 
* [Linux内核之Tracepoint机制](https://zhuanlan.zhihu.com/p/547477490)
* [How the Linux kernel handles a system call](https://0xax.gitbook.io/linux-insides/summary/syscall/linux-syscall-2) 
* [内核系统调用（第二部分）](https://github.com/mannkafai/linux-insides-zh/blob/main/04-syscall/04-syscall-02.md)