# TEST RUN的内核实现

## 0 前言

我们在编写程序时，为了检查和验证程序的功能和性能会进行一些单元测试(unit test)。eBPF程序运行在内核空间，我们同样需要进行单元测试。在[SK_LOOKUP的内核实现](./17-sk_lookup.md)中，我们对`sk_lookup`进行了单元测试，今天我们分析BPF程序单元测试的实现过程。

## 1 简介

eBPF程序在进行单元测试时，用户空间需要提供输入的上下文(context)对象，内核执行BPF程序后将结果返回到用户空间。在此过程中，我们可以记录输出结果，了解其执行的副作用。因此，我们可以用于测试和基准测试。

## 2 `sk_lookup`示例程序

### 2.1 BPF程序

BPF程序源码参见[test_sk_lookup.c](../src/test_sk_lookup.c)，主要内容如下：

```C
SEC("sk_lookup")
int sk_assign_eexist(struct bpf_sk_lookup *ctx)
{
    struct bpf_sock *sk;
    int err, ret;

    ret = SK_DROP;
    sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_B);
    if (!sk) goto out;
    err = bpf_sk_assign(ctx, sk, 0);
    if (err) goto out;
    bpf_sk_release(sk);

    sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if (!sk) goto out;
    err = bpf_sk_assign(ctx, sk, 0);
    if (err != -EEXIST) {
        bpf_printk("sk_assign returned %d, expected %d\n", err, -EEXIST);
        goto out;
    }

    ret = SK_PASS; /* Success, redirect to KEY_SERVER_B */
out:
    if (sk) bpf_sk_release(sk);
    return ret;
}
...
```

该程序包含多个BPF程序，使用`sk_lookup`前缀，参数为`bpf_sk_lookup`。

### 2.1 用户程序

#### 1 附加BPF程序

用户程序源码参见[sk_lookup.c](../src/sk_lookup.c)，主要内容如下：

```C
void test_sk_lookup(void)
{
    struct test_sk_lookup *skel;
    int err;
    // 设置测试的网络环境
    err = switch_netns();
    if (err) return;

    // 打开、加载BPF程序
    skel = test_sk_lookup__open_and_load();
    if (CHECK(!skel, "skel open_and_load", "failed\n")) return;
    // 运行测试
    run_tests(skel);
    // 销毁BPF程序
    test_sk_lookup__destroy(skel);
}
```

`run_tests` 函数进行BPF程序测试，如下：

```C
static void run_tests(struct test_sk_lookup *skel)
{
    if (test__start_subtest("query lookup prog"))
        query_lookup_prog(skel);
    test_redirect_lookup(skel);
    test_drop_on_lookup(skel);
    test_drop_on_reuseport(skel);
    test_sk_assign_helper(skel);
    test_multi_prog_lookup(skel);
}
static void test_sk_assign_helper(struct test_sk_lookup *skel)
{
    if (test__start_subtest("sk_assign returns EEXIST"))
        run_sk_assign_v4(skel, skel->progs.sk_assign_eexist);
    if (test__start_subtest("sk_assign honors F_REPLACE"))
        run_sk_assign_v4(skel, skel->progs.sk_assign_replace_flag);
    if (test__start_subtest("sk_assign accepts NULL socket"))
        run_sk_assign_v4(skel, skel->progs.sk_assign_null);
    if (test__start_subtest("access ctx->sk"))
        run_sk_assign_v4(skel, skel->progs.access_ctx_sk);
    if (test__start_subtest("narrow access to ctx v4"))
        run_sk_assign_v4(skel, skel->progs.ctx_narrow_access);
    if (test__start_subtest("narrow access to ctx v6"))
        run_sk_assign_v6(skel, skel->progs.ctx_narrow_access);
    if (test__start_subtest("sk_assign rejects TCP established"))
        run_sk_assign_connected(skel, SOCK_STREAM);
    if (test__start_subtest("sk_assign rejects UDP connected"))
        run_sk_assign_connected(skel, SOCK_DGRAM);
}
```

`run_sk_assign_v4`和`run_sk_assign_v6`函数进行`run_sk_assign`测试，如下：

```C
static void run_sk_assign_v4(struct test_sk_lookup *skel, struct bpf_program *lookup_prog)
{
    run_sk_assign(skel, lookup_prog, INT_IP4, EXT_IP4);
}
static void run_sk_assign(struct test_sk_lookup *skel, struct bpf_program *lookup_prog,
                const char *remote_ip, const char *local_ip)
{
    int server_fds[] = { [0 ... MAX_SERVERS - 1] = -1 };
    struct bpf_sk_lookup ctx;
    __u64 server_cookie;
    int i, err;
    // 初始化`run_opts`
    DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
        .ctx_in = &ctx,
        .ctx_size_in = sizeof(ctx),
        .ctx_out = &ctx,
        .ctx_size_out = sizeof(ctx),
    );
    // 填充`ctx`信息
    if (fill_sk_lookup_ctx(&ctx, local_ip, EXT_PORT, remote_ip, INT_PORT)) return;

    ctx.protocol = IPPROTO_TCP;

    for (i = 0; i < ARRAY_SIZE(server_fds); i++) {
        // 创建测试需要的socket
        server_fds[i] = make_server(SOCK_STREAM, local_ip, 0, NULL);
        if (server_fds[i] < 0) goto close_servers;
        // 更新BPF程序需要的map信息
        err = update_lookup_map(skel->maps.redir_map, i, server_fds[i]);
        if (err) goto close_servers;
    }
    // 获取`cookie`
    server_cookie = socket_cookie(server_fds[SERVER_B]);
    if (!server_cookie) return;

    // 运行`test_run`, 对BPF程序进行的是
    err = bpf_prog_test_run_opts(bpf_program__fd(lookup_prog), &opts);

    // 对测试结果进行判断
    if (CHECK(err, "test_run", "failed with error %d\n", errno)) goto close_servers;
    if (CHECK(ctx.cookie == 0, "ctx.cookie", "no socket selected\n")) goto close_servers;
    CHECK(ctx.cookie != server_cookie, "ctx.cookie", "selected sk %llu instead of %llu\n", ctx.cookie, server_cookie);

close_servers:
    // 关闭测试创建的socket
    for (i = 0; i < ARRAY_SIZE(server_fds); i++) {
        if (server_fds[i] != -1) close(server_fds[i]);
    }
}
```

### 2.3 编译运行

`sk_lookup`程序是Linux内核自带的测试程序，在`tools/testing/selftests/bpf/prog_tests/`目录下。编译后运行，如下：

```bash
$ cd tools/testing/selftests/bpf/
$ sudo make
$ sudo ./test_progs -t sk_lookup -vvv
bpf_testmod.ko is already unloaded.
Loading bpf_testmod.ko...
Failed to load bpf_testmod.ko into the kernel: -8
WARNING! Selftests relying on bpf_testmod.ko will be skipped.
libbpf: loading object 'cgroup_skb_sk_lookup_kern' from buffer
...
run_cgroup_bpf_test:PASS:skel_open_load 0 nsec
run_cgroup_bpf_test:PASS:cgroup_join 0 nsec
...
run_multi_prog_lookup:PASS:connect 0 nsec
run_multi_prog_lookup:PASS:connect 0 nsec
run_multi_prog_lookup:PASS:bpf_map_lookup_elem 0 nsec
run_multi_prog_lookup:PASS:bpf_map_lookup_elem 0 nsec
run_multi_prog_lookup:PASS:bpf_map_lookup_elem 0 nsec
run_multi_prog_lookup:PASS:bpf_map_lookup_elem 0 nsec
#170/50  sk_lookup/multi prog - redir, redir:OK
#170     sk_lookup:OK
Summary: 2/50 PASSED, 0 SKIPPED, 0 FAILED
```

## 3 附加BPF的过程

`sk_lookup.c`文件中在设置`bpf_test_run_opts`选项后，通过 `bpf_prog_test_run_opts` 函数实现对BPF程序的测试，其实现如下：

```C
// file: libbpf/src/bpf.c
int bpf_prog_test_run_opts(int prog_fd, struct bpf_test_run_opts *opts)
{
    const size_t attr_sz = offsetofend(union bpf_attr, test);
    union bpf_attr attr;
    int ret;

    // 检查`opts`设置
    if (!OPTS_VALID(opts, bpf_test_run_opts)) return libbpf_err(-EINVAL);

    // 设置`bpf_attr`属性
    memset(&attr, 0, attr_sz);
    attr.test.prog_fd = prog_fd;
    attr.test.batch_size = OPTS_GET(opts, batch_size, 0);
    attr.test.cpu = OPTS_GET(opts, cpu, 0);
    attr.test.flags = OPTS_GET(opts, flags, 0);
    attr.test.repeat = OPTS_GET(opts, repeat, 0);
    attr.test.duration = OPTS_GET(opts, duration, 0);
    attr.test.ctx_size_in = OPTS_GET(opts, ctx_size_in, 0);
    attr.test.ctx_size_out = OPTS_GET(opts, ctx_size_out, 0);
    attr.test.data_size_in = OPTS_GET(opts, data_size_in, 0);
    attr.test.data_size_out = OPTS_GET(opts, data_size_out, 0);
    attr.test.ctx_in = ptr_to_u64(OPTS_GET(opts, ctx_in, NULL));
    attr.test.ctx_out = ptr_to_u64(OPTS_GET(opts, ctx_out, NULL));
    attr.test.data_in = ptr_to_u64(OPTS_GET(opts, data_in, NULL));
    attr.test.data_out = ptr_to_u64(OPTS_GET(opts, data_out, NULL));

    // BPF系统调用，使用`BPF_PROG_TEST_RUN`指令
    ret = sys_bpf(BPF_PROG_TEST_RUN, &attr, attr_sz);

    // 设置`opts`执行结果
    OPTS_SET(opts, data_size_out, attr.test.data_size_out);
    OPTS_SET(opts, ctx_size_out, attr.test.ctx_size_out);
    OPTS_SET(opts, duration, attr.test.duration);
    OPTS_SET(opts, retval, attr.test.retval);

    return libbpf_err_errno(ret);
}
```

## 4 内核实现

### 4.1 BPF程序测试接口

#### 1 BPF系统调用

`BPF_PROG_TEST_RUN` 是BPF系统调用，如下：

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
    case BPF_PROG_TEST_RUN: err = bpf_prog_test_run(&attr, uattr.user); break;
    ...
    }
    return err;
}
```

#### 2 `BPF_PROG_TEST_RUN`

`bpf_prog_test_run` 在检查attr属性后，获取测试的BPF程序，在支持`test_run`接口时，运行测试。如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_prog_test_run(const union bpf_attr *attr, union bpf_attr __user *uattr)
{
    struct bpf_prog *prog;
    int ret = -ENOTSUPP;
    // 属性检查
    if (CHECK_ATTR(BPF_PROG_TEST_RUN)) return -EINVAL;
    // `attr->test`中`ctx_in,ctx_out`属性检查
    if ((attr->test.ctx_size_in && !attr->test.ctx_in) || (!attr->test.ctx_size_in && attr->test.ctx_in)) return -EINVAL;
    if ((attr->test.ctx_size_out && !attr->test.ctx_out) || (!attr->test.ctx_size_out && attr->test.ctx_out)) return -EINVAL;

    // 获取测试的BPF程序
    prog = bpf_prog_get(attr->test.prog_fd);
    if (IS_ERR(prog)) return PTR_ERR(prog);

    // BPF程序支持`test_run`时，运行测试
    if (prog->aux->ops->test_run)
        ret = prog->aux->ops->test_run(prog, attr, uattr);

    // 释放BPF程序
    bpf_prog_put(prog);
    return ret;
}
```

#### 3 `.test_run`接口

可以看到`.test_run`接口是`aux->ops`的字段，`aux->ops` 在加载阶段设置的，如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_prog_load(union bpf_attr *attr, bpfptr_t uattr, u32 uattr_size)
{
    enum bpf_prog_type type = attr->prog_type;
    struct bpf_prog *prog, *dst_prog = NULL;
    ...
    // 创建BPF程序内存空间
    prog = bpf_prog_alloc(bpf_prog_size(attr->insn_cnt), GFP_USER);
    ...
    // 获取BPF程序类型 
    /* find program type: socket_filter vs tracing_filter */
    err = find_prog_type(type, prog);
    ...
}
```

`find_prog_type`函数设置`aux->ops`，根据程序类型从`bpf_prog_types`数组中获取`ops`后设置，如下：

```C
// file: kernel/bpf/syscall.c
static int find_prog_type(enum bpf_prog_type type, struct bpf_prog *prog)
{
    const struct bpf_prog_ops *ops;
    // 必要的检查
    if (type >= ARRAY_SIZE(bpf_prog_types)) return -EINVAL;
    type = array_index_nospec(type, ARRAY_SIZE(bpf_prog_types));

    // 获取`ops`
    ops = bpf_prog_types[type];
    if (!ops) return -EINVAL;

    // 不支持`offload`时，设置`ops`
    if (!bpf_prog_is_offloaded(prog->aux))
        prog->aux->ops = ops;
    else
        prog->aux->ops = &bpf_offload_prog_ops;
    prog->type = type;
    return 0;
}
```

`bpf_prog_types`变量是一个`struct bpf_prog_ops`类型的数组，其定义如下：

```C
// file: kernel/bpf/syscall.c
static const struct bpf_prog_ops * const bpf_prog_types[] = {
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
    [_id] = & _name ## _prog_ops,
#define BPF_MAP_TYPE(_id, _ops)
#define BPF_LINK_TYPE(_id, _name)
#include <linux/bpf_types.h>
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE
};
```

在定义中，`BPF_PROG_TYPE`宏展开后初始化`bpf_prog_types[]`数组。在`<linux/bpf_types.h>`文件中定义了所有支持的程序类型，如下：

```C
// file: include/linux/bpf_types.h
BPF_PROG_TYPE(BPF_PROG_TYPE_SOCKET_FILTER, sk_filter,
            struct __sk_buff, struct sk_buff)
BPF_PROG_TYPE(BPF_PROG_TYPE_SCHED_CLS, tc_cls_act,
            struct __sk_buff, struct sk_buff)
BPF_PROG_TYPE(BPF_PROG_TYPE_SCHED_ACT, tc_cls_act,
            struct __sk_buff, struct sk_buff)
BPF_PROG_TYPE(BPF_PROG_TYPE_XDP, xdp,
            struct xdp_md, struct xdp_buff)
...
```

在初始化`bpf_prog_types[]`时，`BPF_PROG_TYPE` 定义为 `[_id] = & _name ## _prog_ops,` 。以 `BPF_PROG_TYPE_SOCKET_FILTER` 为例，其展开后为 `[BPF_PROG_TYPE_SOCKET_FILTER] = & sk_filter_prog_ops,` ，后者定义如下：

```C
// file: net/core/filter.c
const struct bpf_prog_ops sk_filter_prog_ops = {
    .test_run   = bpf_prog_test_run_skb,
};
```

### 4.2 不同类型BPF程序的测试接口

#### 4.2.1 XDP

`BPF_PROG_TYPE_XDP` 类型的BPF程序对应的`bpf_prog_ops`为`xdp_prog_ops`，如下：

```C
// file: include/linux/bpf_types.h
BPF_PROG_TYPE(BPF_PROG_TYPE_XDP, xdp,
        struct xdp_md, struct xdp_buff)
```

后者定义如下：

```C
// file: net/core/filter.c
const struct bpf_prog_ops xdp_prog_ops = {
    .test_run       = bpf_prog_test_run_xdp,
};
```

##### `.test_run`的实现过程

`BPF_PROG_TYPE_XDP`程序对应的`.test_run`接口设置为`bpf_prog_test_run_xdp`，后者实现如下：

```C
// file: net/bpf/test_run.c
int bpf_prog_test_run_xdp(struct bpf_prog *prog, const union bpf_attr *kattr,
            union bpf_attr __user *uattr)
{
    bool do_live = (kattr->test.flags & BPF_F_TEST_XDP_LIVE_FRAMES);
    
    ...
    // 不支持`DEVMAP`和`CPUMAP`
    if (prog->expected_attach_type == BPF_XDP_DEVMAP || 
        prog->expected_attach_type == BPF_XDP_CPUMAP)
        return -EINVAL;

    // flags检查，只支持`LIVE_FRAMES`标记
    if (kattr->test.flags & ~BPF_F_TEST_XDP_LIVE_FRAMES) return -EINVAL;
    
    // 已绑定设备时，不能运行
    if (bpf_prog_is_dev_bound(prog->aux)) return -EINVAL;
    ...

    // 初始化BPF运行的上下文
    ctx = bpf_ctx_init(kattr, sizeof(struct xdp_md));
    if (IS_ERR(ctx)) return PTR_ERR(ctx);
    ...

    // 测试环境初始化，复制用户空间设置的测试数据
    data = bpf_test_init(kattr, size, max_data_sz, headroom, tailroom);
    if (IS_ERR(data)) ...

    // 从`lo`设备获取接收队列
    rxqueue = __netif_get_rx_queue(current->nsproxy->net_ns->loopback_dev, 0);
    rxqueue->xdp_rxq.frag_size = headroom + max_data_sz + tailroom;

    // 初始化`xdp_buff`
    xdp_init_buff(&xdp, rxqueue->xdp_rxq.frag_size, &rxqueue->xdp_rxq);
    xdp_prepare_buff(&xdp, data, headroom, size, true);
    sinfo = xdp_get_shared_info_from_buff(&xdp);

    // 将`xdp_md`转换为`xdp_buff`，将`xdp_buff`绑定到用户空间设置的`dev`和`rx_queue`上
    ret = xdp_convert_md_to_buff(ctx, &xdp);
    if (ret) goto free_data;

    // 用户空间设置的数据长度大于一个`xdp_buff`时，创建`frag`
    if (unlikely(kattr->test.data_size_in > size)) { ... }

    //  多次运行时优化，通过`bpf_dispatcher`创建`image`
    if (repeat > 1) bpf_prog_change_xdp(NULL, prog);
    
    // 实时数据、测试数据的执行接口
    if (do_live)
        ret = bpf_test_run_xdp_live(prog, &xdp, repeat, batch_size, &duration);
    else
        ret = bpf_test_run(prog, &xdp, repeat, &retval, &duration, true);

    // 将`xdp_buff`转换为`xdp_md`，在测试失败时减少引用计数
    xdp_convert_buff_to_md(&xdp, ctx);
    if (ret) goto out;

    // 获取BPF程序执行后的数据大小
    size = xdp.data_end - xdp.data_meta + sinfo->xdp_frags_size;
    // 复制测试数据、测试结果、执行时长到用户空间
    ret = bpf_test_finish(kattr, uattr, xdp.data_meta, sinfo, size, retval, duration);
    // 复制BPF运行上下文到用户空间
    if (!ret) ret = bpf_ctx_finish(kattr, uattr, ctx, sizeof(struct xdp_md));

out:
    // 多次运行时优化，释放`bpf_dispatcher`创建的`image`
    if (repeat > 1) bpf_prog_change_xdp(prog, NULL);
    // 释放分配的内存
free_data:
    for (i = 0; i < sinfo->nr_frags; i++)
        __free_page(skb_frag_page(&sinfo->frags[i]));
    kfree(data);
free_ctx:
    kfree(ctx);
    return ret;
}
```

##### 实时模式下BPF程序的执行过程

在用户空间设置 `BPF_F_TEST_XDP_LIVE_FRAMES` 标记时，数据包在执行XDP程序后将由内核处理，就像数据包到达网卡一样。其实现过程通过 `bpf_test_run_xdp_live` 函数实现的，如下：

```C
// file: net/bpf/test_run.c
static int bpf_test_run_xdp_live(struct bpf_prog *prog, struct xdp_buff *ctx, u32 repeat, u32 batch_size, u32 *time)
{
    struct xdp_test_data xdp = { .batch_size = batch_size };
    struct bpf_test_timer t = { .mode = NO_MIGRATE };
    int ret;
    // 默认运行一次
    if (!repeat) repeat = 1;

    // 建立`xdp`运行的数据，即创建`xdp_frame`和`sk_buff`
    ret = xdp_test_run_setup(&xdp, ctx);
    if (ret) return ret;

    // 记录开始时刻
    bpf_test_timer_enter(&t);
    do {
        // 批量运行XDP程序
        xdp.frame_cnt = 0;
        ret = xdp_test_run_batch(&xdp, prog, repeat - t.i);
        if (unlikely(ret < 0)) break;
    } while (bpf_test_timer_continue(&t, xdp.frame_cnt, repeat, &ret, time));
    bpf_test_timer_leave(&t);

    // 释放`xdp`的测试数据
    xdp_test_run_teardown(&xdp);
    return ret;
}
```

`xdp_test_run_batch`函数批量执行XDP程序，如下：

```C
// file: net/bpf/test_run.c
static int xdp_test_run_batch(struct xdp_test_data *xdp, struct bpf_prog *prog, u32 repeat)
{
    struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
    struct xdp_frame **frames = xdp->frames;
    ...

    // 计数本次运行次数
    batch_sz = min_t(u32, repeat, xdp->batch_size);

    local_bh_disable();
    // 设置重定向标记为`NO_DIRECT`
    xdp_set_return_frame_no_direct();
    // 批量执行
    for (i = 0; i < batch_sz; i++) {
        // 获取运行的内存页
        page = page_pool_dev_alloc_pages(xdp->pp);
        ...
        // 获取`xdp_page_head`后重置，将`xdp_frame`填充到`xdp_buff`中
        head = phys_to_virt(page_to_phys(page));
        reset_ctx(head);
 
        // 获取XDP程序的运行上下文
        ctx = &head->ctx;
        frm = head->frame;
        xdp->frame_cnt++;

        // 执行XDP程序
        act = bpf_prog_run_xdp(prog, ctx);

        // XDP程序修改pkg的边界，更新`xdp_frame`
        if (unlikely(ctx_was_changed(head))) {
            ret = xdp_update_frame_from_buff(ctx, frm);
            if (ret) { xdp_return_buff(ctx); continue; }
        }

        // 根据XDP程序的返回结果进行处理
        switch (act) {
        case XDP_TX:
            // 从同一个网卡发出，设置重定向信息(`ri`)
            ri->tgt_index = xdp->dev->ifindex;
            ri->map_id = INT_MAX;
            ri->map_type = BPF_MAP_TYPE_UNSPEC;
            fallthrough;
        case XDP_REDIRECT:
            // 重定向到其他网卡或CPU
            redirect = true;
            // 执行重定向
            ret = xdp_do_redirect_frame(xdp->dev, ctx, frm, prog);
            // 失败时，释放`xdp_buff`
            if (ret) xdp_return_buff(ctx);
            break;
        case XDP_PASS:
            // 记录通过的`xdp_frame`
            frames[nframes++] = frm;
            break;
        default:
            // 其他情况，记录错误信息后，释放`xdp_buff`
            bpf_warn_invalid_xdp_action(NULL, prog, act);
            fallthrough;
        case XDP_DROP:
            xdp_return_buff(ctx);
            break;
        }
    }

out:
    // 重定向时，清除重定向信息
    if (redirect) xdp_do_flush();
    if (nframes) {
        // 将通过的`xdp_frame`发送到内核网络协议栈
        ret = xdp_recv_frames(frames, nframes, xdp->skbs, xdp->dev);
        if (ret) err = ret;
    }
    // 清除`NO_DIRECT`标记
    xdp_clear_return_frame_no_direct();
    local_bh_enable();
    return err;
}
```

`xdp_recv_frames`函数将返回结果为`XDP_PASS`的`xdp_frame`发往内核协议栈继续处理，如下：

```C
// file: net/bpf/test_run.c
static int xdp_recv_frames(struct xdp_frame **frames, int nframes,
                struct sk_buff **skbs, struct net_device *dev)
{
    ...
    LIST_HEAD(list);

    // 分配`skbs`内存空间
    n = kmem_cache_alloc_bulk(net_hotdata.skbuff_cache, gfp, nframes, (void **)skbs);
    if (unlikely(n == 0)) {
        // 内存空间不足时，释放`xdp_frame`
        for (i = 0; i < nframes; i++)
            xdp_return_frame(frames[i]);
        return -ENOMEM;
    }
    // 逐帧处理
    for (i = 0; i < nframes; i++) {
        struct xdp_frame *xdpf = frames[i];
        struct sk_buff *skb = skbs[i];
        // 将`xdp_frame`转换为`sk_buff`
        skb = __xdp_build_skb_from_frame(xdpf, skb, dev);
        // 失败时，释放`xdp_frame`
        if (!skb) { xdp_return_frame(xdpf); continue; }

        list_add_tail(&skb->list, &list);
    }
    // 发往内核网络协议栈
    netif_receive_skb_list(&list);
    return 0;
}
```

##### 测试模式下BPF程序的执行过程

在用户空间没有设置 `BPF_F_TEST_XDP_LIVE_FRAMES` 标记时，只进行测试，将返回结果返回到用户空间。通过`bpf_test_run`函数实现的，如下：

```C
// file: net/bpf/test_run.c
static int bpf_test_run(struct bpf_prog *prog, void *ctx, u32 repeat, u32 *retval, u32 *time, bool xdp)
{
    struct bpf_prog_array_item item = {.prog = prog};
    ...

    // 将`prog`保存到`item.cgroup_storage`中
    for_each_cgroup_storage_type(stype) {
        item.cgroup_storage[stype] = bpf_cgroup_storage_alloc(prog, stype);
        ...
    }

    // 默认运行一次
    if (!repeat) repeat = 1;

    // 记录开始时刻
    bpf_test_timer_enter(&t);
    // 设置运行上下文
    old_ctx = bpf_set_run_ctx(&run_ctx.run_ctx);
    do {
        run_ctx.prog_item = &item;
        local_bh_disable();
        if (xdp)
            // XDP时，执行XDP程序，记录返回结果
            *retval = bpf_prog_run_xdp(prog, ctx);
        else
            // 执行BPF程序，记录返回结果
            *retval = bpf_prog_run(prog, ctx);
        local_bh_enable();
    } while (bpf_test_timer_continue(&t, 1, repeat, &ret, time));
    // 重置运行上下文
    bpf_reset_run_ctx(old_ctx);
    bpf_test_timer_leave(&t);

    // 释放`item.cgroup_storage`
    for_each_cgroup_storage_type(stype)
        bpf_cgroup_storage_free(item.cgroup_storage[stype]);

    return ret;
}
```

`bpf_prog_run_xdp`函数执行设置的XDP程序，实现如下：

```C
// file: include/net/xdp.h
static __always_inline u32 bpf_prog_run_xdp(const struct bpf_prog *prog, struct xdp_buff *xdp)
{
    // 执行BPF程序
    u32 act = __bpf_prog_run(prog, xdp, BPF_DISPATCHER_FUNC(xdp));

    if (static_branch_unlikely(&bpf_master_redirect_enabled_key)) {
        // `XDP_TX`时，重定向到主设备
        if (act == XDP_TX && netif_is_bond_slave(xdp->rxq->dev))
            act = xdp_master_redirect(xdp);
    }
    return act;
}
```

#### 4.2.2 SOCKET_FILTER, TC_CLS, LWT, CGROUP_SKB

`SOCKET_FILTER`, `SCHED_CLS`, `SCHED_ACT`, `LWT_IN`, `LWT_OUT`, `LWT_XMIT`, `LWT_SEG6LOCAL`, `CGROUP_SKB`这些类型的测试接口相同。不同类型对应的`bpf_prog_ops`如下：

```C
// file: include/linux/bpf_types.h
BPF_PROG_TYPE(BPF_PROG_TYPE_SOCKET_FILTER, sk_filter,
        struct __sk_buff, struct sk_buff)
BPF_PROG_TYPE(BPF_PROG_TYPE_SCHED_CLS, tc_cls_act,
        struct __sk_buff, struct sk_buff)
BPF_PROG_TYPE(BPF_PROG_TYPE_SCHED_ACT, tc_cls_act,
        struct __sk_buff, struct sk_buff)
BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SKB, cg_skb,
        struct __sk_buff, struct sk_buff)
BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_IN, lwt_in,
        struct __sk_buff, struct sk_buff)
BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_OUT, lwt_out,
        struct __sk_buff, struct sk_buff)
BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_XMIT, lwt_xmit,
        struct __sk_buff, struct sk_buff)
BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_SEG6LOCAL, lwt_seg6local,
        struct __sk_buff, struct sk_buff)
```

后者定义如下：

```C
// file: net/core/filter.c
const struct bpf_prog_ops sk_filter_prog_ops = {
    .test_run       = bpf_prog_test_run_skb,
};
const struct bpf_prog_ops tc_cls_act_prog_ops = {
    .test_run       = bpf_prog_test_run_skb,
};
const struct bpf_prog_ops cg_skb_prog_ops = {
    .test_run       = bpf_prog_test_run_skb,
};
const struct bpf_prog_ops lwt_in_prog_ops = {
    .test_run       = bpf_prog_test_run_skb,
};
const struct bpf_prog_ops lwt_out_prog_ops = {
    .test_run       = bpf_prog_test_run_skb,
};
const struct bpf_prog_ops lwt_xmit_prog_ops = {
    .test_run       = bpf_prog_test_run_skb,
};
const struct bpf_prog_ops lwt_seg6local_prog_ops = {
    .test_run       = bpf_prog_test_run_skb,
};
```

##### `.test_run`的实现过程

这些类型的BPF程序对应的`.test_run`接口设置为`bpf_prog_test_run_skb`，后者实现如下：

```C
// file: net/bpf/test_run.c
int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr, union bpf_attr __user *uattr)
{
    bool is_l2 = false, is_direct_pkt_access = false;
    struct net *net = current->nsproxy->net_ns;
    // 默认`lo`设备
    struct net_device *dev = net->loopback_dev;
    struct __sk_buff *ctx = NULL;
    struct sk_buff *skb;
    struct sock *sk;
    void *data;
    ...

    // 测试选项检查
    if (kattr->test.flags || kattr->test.cpu || kattr->test.batch_size) return -EINVAL;

    // 初始化测试环境，复制用户空间设置的数据
    data = bpf_test_init(kattr, kattr->test.data_size_in, 
                size, NET_SKB_PAD + NET_IP_ALIGN, SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
    if (IS_ERR(data)) return PTR_ERR(data);

    // 初始化运行上下文，即`__sk_buff`
    ctx = bpf_ctx_init(kattr, sizeof(struct __sk_buff));
    if (IS_ERR(ctx)) { kfree(data); return PTR_ERR(ctx); }

    // 根据程序类型，设置`l2`和`direct_pkt_access`属性
    switch (prog->type) {
    case BPF_PROG_TYPE_SCHED_CLS:
    case BPF_PROG_TYPE_SCHED_ACT:
        is_l2 = true;
        fallthrough;
    case BPF_PROG_TYPE_LWT_IN:
    case BPF_PROG_TYPE_LWT_OUT:
    case BPF_PROG_TYPE_LWT_XMIT:
        is_direct_pkt_access = true;
        break;
    default:
        break;
    }

    // 创建并初始化`sk`
    sk = sk_alloc(net, AF_UNSPEC, GFP_USER, &bpf_dummy_proto, 1);
    sock_init_data(NULL, sk);
    // 将用户空间输入的数据生成skb
    skb = slab_build_skb(data);
    // skb和sk关联       
    skb->sk = sk;

    // 设置skb的`head`和`tail`
    skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN);
    __skb_put(skb, size);
        
    if (ctx && ctx->ifindex > 1) {
        // 指定网卡时，获取对应的网卡
        dev = dev_get_by_index(net, ctx->ifindex);
        if (!dev) { ret = -ENODEV; goto out; }
    }
    // 获取L3协议
    skb->protocol = eth_type_trans(skb, dev);
    // 重置L2位置
    skb_reset_network_header(skb);

    // 获取源IP、目的IP
    switch (skb->protocol) {
    case htons(ETH_P_IP):
        sk->sk_family = AF_INET;
        if (sizeof(struct iphdr) <= skb_headlen(skb)) {
            sk->sk_rcv_saddr = ip_hdr(skb)->saddr;
            sk->sk_daddr = ip_hdr(skb)->daddr;
        }
        break;
#if IS_ENABLED(CONFIG_IPV6)
    case htons(ETH_P_IPV6):
        sk->sk_family = AF_INET6;
        if (sizeof(struct ipv6hdr) <= skb_headlen(skb)) {
            sk->sk_v6_rcv_saddr = ipv6_hdr(skb)->saddr;
            sk->sk_v6_daddr = ipv6_hdr(skb)->daddr;
        }
    break;
#endif
    default:
        break;
    }

    // L2类型的BPF程序时，保留L2数据
    if (is_l2) __skb_push(skb, hh_len);
    // 直接访问skb时，记录skb线性数据区间
    if (is_direct_pkt_access) bpf_compute_data_pointers(skb);
    // 将用户空间的`__sk_buff`转换为内核空间的`sk_buff`
    ret = convert___skb_to_skb(skb, ctx);
    if (ret) goto out;

    // 测试BPF程序
    ret = bpf_test_run(prog, skb, repeat, &retval, &duration, false);
    if (ret) goto out;
    
    // 非L2时，清空L2数据内容
    if (!is_l2) {
        if (skb_headroom(skb) < hh_len) {
            int nhead = HH_DATA_ALIGN(hh_len - skb_headroom(skb));
            if (pskb_expand_head(skb, nhead, 0, GFP_USER)) { ret = -ENOMEM; goto out; }
        }
        memset(__skb_push(skb, hh_len), 0, hh_len);
    }
    // 将内核空间的`sk_buff`转换为用户空间的`__sk_buff`
    convert_skb_to___skb(skb, ctx);

    // 获取skb的长度
    size = skb->len;
    if (WARN_ON_ONCE(skb_is_nonlinear(skb))) size = skb_headlen(skb);

    // 复制测试数据、测试结果、执行时长到用户空间
    ret = bpf_test_finish(kattr, uattr, skb->data, NULL, size, retval, duration);
    // 复制BPF运行上下文到用户空间
    if (!ret) ret = bpf_ctx_finish(kattr, uattr, ctx, sizeof(struct __sk_buff));

out:
    // 清理工作，释放分配的数据
    if (dev && dev != net->loopback_dev)
        dev_put(dev);
    kfree_skb(skb);
    sk_free(sk);
    kfree(ctx);
    return ret;
}
```

##### BPF程序的执行过程

通过`bpf_test_run`函数实现的，执行过程上节。

#### 4.2.3 FLOW_DISSECTOR

`FLOW_DISSECTOR` 类型对应的 `bpf_prog_ops` 如下：

```C
// file: include/linux/bpf_types.h
BPF_PROG_TYPE(BPF_PROG_TYPE_FLOW_DISSECTOR, flow_dissector,
	      struct __sk_buff, struct bpf_flow_dissector)
```

后者定义如下：

```C
// file: net/core/filter.c
const struct bpf_prog_ops flow_dissector_prog_ops = {
    .test_run       = bpf_prog_test_run_flow_dissector,
};
```

##### `.test_run`的实现过程

`FLOW_DISSECTOR` 类型程序对应的`.test_run`接口设置为`bpf_prog_test_run_flow_dissector`，后者实现如下：

```C
// file: net/bpf/test_run.c
int bpf_prog_test_run_flow_dissector(struct bpf_prog *prog, const union bpf_attr *kattr, union bpf_attr __user *uattr)
{
    struct bpf_test_timer t = { NO_PREEMPT };
    struct bpf_flow_dissector ctx = {};
    struct bpf_flow_keys *user_ctx;
    struct bpf_flow_keys flow_keys;
    const struct ethhdr *eth;
    unsigned int flags = 0;
    void *data;
    ...

    // 测试选项检查
    if (kattr->test.flags || kattr->test.cpu || kattr->test.batch_size) return -EINVAL;
    // 数据长度检查
    if (size < ETH_HLEN) return -EINVAL;

    // 初始化测试环境，复制用户空间设置的数据
    data = bpf_test_init(kattr, kattr->test.data_size_in, size, 0, 0);
    if (IS_ERR(data)) return PTR_ERR(data);

    eth = (struct ethhdr *)data;
    // 默认测试一次
    if (!repeat) repeat = 1;

    // 初始化运行上下文，即`bpf_flow_keys`
    user_ctx = bpf_ctx_init(kattr, sizeof(struct bpf_flow_keys));
    if (IS_ERR(user_ctx)) { kfree(data); return PTR_ERR(user_ctx); }

    // 用户空间设置(`bpf_flow_keys`)存在时，验证后，获取`flags`
    if (user_ctx) {
        ret = verify_user_bpf_flow_keys(user_ctx);
        if (ret) goto out;
        flags = user_ctx->flags;
    }

    // 设置BPF程序运行上下文
    ctx.flow_keys = &flow_keys;
    ctx.data = data;
    ctx.data_end = (__u8 *)data + size;

    // 记录开始时刻
    bpf_test_timer_enter(&t);
    do {
        // 测试执行
        retval = bpf_flow_dissect(prog, &ctx, eth->h_proto, ETH_HLEN, size, flags);
    } while (bpf_test_timer_continue(&t, 1, repeat, &ret, &duration));
    bpf_test_timer_leave(&t);

    if (ret < 0) goto out;
    
    // 复制测试数据、测试结果、执行时长到用户空间
    ret = bpf_test_finish(kattr, uattr, &flow_keys, NULL, sizeof(flow_keys), retval, duration);
    // 复制BPF运行上下文到用户空间
    if (!ret) ret = bpf_ctx_finish(kattr, uattr, user_ctx, sizeof(struct bpf_flow_keys));

out:
    // 清理工作，释放分配的数据
    kfree(user_ctx);
    kfree(data);
    return ret;
}
```

##### BPF程序的执行过程

通过`bpf_flow_dissect`函数实现的，如下:

```C
// file: net/core/flow_dissector.c
u32 bpf_flow_dissect(struct bpf_prog *prog, struct bpf_flow_dissector *ctx,
            __be16 proto, int nhoff, int hlen, unsigned int flags)
{
    struct bpf_flow_keys *flow_keys = ctx->flow_keys;
    u32 result;

    // 设置`flow_keys`属性
    memset(flow_keys, 0, sizeof(*flow_keys));
    flow_keys->n_proto = proto;
    flow_keys->nhoff = nhoff;
    flow_keys->thoff = flow_keys->nhoff;

    BUILD_BUG_ON((int)BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG != (int)FLOW_DISSECTOR_F_PARSE_1ST_FRAG);
    BUILD_BUG_ON((int)BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL != (int)FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);
    BUILD_BUG_ON((int)BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP != (int)FLOW_DISSECTOR_F_STOP_AT_ENCAP);
    flow_keys->flags = flags;

    // 运行BPF程序
    result = bpf_prog_run_pin_on_cpu(prog, ctx);

    // 获取BPF程序执行后的结果
    flow_keys->nhoff = clamp_t(u16, flow_keys->nhoff, nhoff, hlen);
    flow_keys->thoff = clamp_t(u16, flow_keys->thoff, flow_keys->nhoff, hlen);

    return result;
}
```

#### 4.2.4 SK_LOOKUP

`SK_LOOKUP` 类型对应的 `bpf_prog_ops` 如下：

```C
// file: include/linux/bpf_types.h
BPF_PROG_TYPE(BPF_PROG_TYPE_SK_LOOKUP, sk_lookup,
        struct bpf_sk_lookup, struct bpf_sk_lookup_kern)
```

后者定义如下：

```C
// file: net/core/filter.c
const struct bpf_prog_ops sk_lookup_prog_ops = {
    .test_run       = bpf_prog_test_run_sk_lookup,
};
```

##### `.test_run`的实现过程

`SK_LOOKUP` 类型程序对应的`.test_run`接口设置为`bpf_prog_test_run_sk_lookup`，后者实现如下：

```C
// file: net/bpf/test_run.c
int bpf_prog_test_run_sk_lookup(struct bpf_prog *prog, const union bpf_attr *kattr, union bpf_attr __user *uattr)
{
    struct bpf_test_timer t = { NO_PREEMPT };
    struct bpf_prog_array *progs = NULL;
    struct bpf_sk_lookup_kern ctx = {};
    u32 repeat = kattr->test.repeat;
    struct bpf_sk_lookup *user_ctx;
    u32 retval, duration;
    int ret = -EINVAL;

    // 测试选项检查
    if (kattr->test.flags || kattr->test.cpu || kattr->test.batch_size) return -EINVAL;
    // 测试的数据选项检查
    if (kattr->test.data_in || kattr->test.data_size_in || kattr->test.data_out || kattr->test.data_size_out)
        return -EINVAL;
    
    // 默认执行一次
    if (!repeat) repeat = 1;

    // 初始化运行上下文，即`bpf_sk_lookup`
    user_ctx = bpf_ctx_init(kattr, sizeof(*user_ctx));
    if (IS_ERR(user_ctx)) return PTR_ERR(user_ctx);

    // 用户空间设置的ctx检查    
    if (!user_ctx) return -EINVAL;
    if (user_ctx->sk) goto out;
    if (!range_is_zero(user_ctx, offsetofend(typeof(*user_ctx), local_port), sizeof(*user_ctx))) goto out;
    if (user_ctx->local_port > U16_MAX) { ret = -ERANGE; goto out; }

    // 设置用户空间设置的选项
    ctx.family = (u16)user_ctx->family;
    ctx.protocol = (u16)user_ctx->protocol;
    ctx.dport = (u16)user_ctx->local_port;
    ctx.sport = user_ctx->remote_port;
    // 设置源IP、目的IP
    switch (ctx.family) {
    case AF_INET:
        ctx.v4.daddr = (__force __be32)user_ctx->local_ip4;
        ctx.v4.saddr = (__force __be32)user_ctx->remote_ip4;
        break;
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        ctx.v6.daddr = (struct in6_addr *)user_ctx->local_ip6;
        ctx.v6.saddr = (struct in6_addr *)user_ctx->remote_ip6;
        break;
#endif
    default:
        ret = -EAFNOSUPPORT;
        goto out;
    }

    // 设置BPF程序
    progs = bpf_prog_array_alloc(1, GFP_KERNEL);
    if (!progs) { ret = -ENOMEM; goto out; }
    progs->items[0].prog = prog;

    // 记录开始时间
    bpf_test_timer_enter(&t);
    do {
        ctx.selected_sk = NULL;
        // 运行BPF程序
        retval = BPF_PROG_SK_LOOKUP_RUN_ARRAY(progs, ctx, bpf_prog_run);
    } while (bpf_test_timer_continue(&t, 1, repeat, &ret, &duration));
    bpf_test_timer_leave(&t);

    // 执行失败时，清理
    if (ret < 0) goto out;

    // 设置用户空间的查找结果
    user_ctx->cookie = 0;
    if (ctx.selected_sk) {
        if (ctx.selected_sk->sk_reuseport && !ctx.no_reuseport) {ret = -EOPNOTSUPP; goto out; }
        user_ctx->cookie = sock_gen_cookie(ctx.selected_sk);
    }

    // 复制测试结果、执行时长到用户空间
    ret = bpf_test_finish(kattr, uattr, NULL, NULL, 0, retval, duration);
    // 复制BPF运行上下文到用户空间
    if (!ret) ret = bpf_ctx_finish(kattr, uattr, user_ctx, sizeof(*user_ctx));

out:
    // 清理工作，释放分配的数据
    bpf_prog_array_free(progs);
    kfree(user_ctx);
    return ret;
}
```

##### BPF程序的执行过程

通过`BPF_PROG_SK_LOOKUP_RUN_ARRAY`宏实现的。宏展开后运行`bpf_prog_run`函数，将查找的sock设置到`ctx.selected_sk`。

#### 4.2.5 NETFILTER

`NETFILTER` 类型对应的 `bpf_prog_ops` 如下：

```C
// file: include/linux/bpf_types.h
BPF_PROG_TYPE(BPF_PROG_TYPE_NETFILTER, netfilter,
        struct bpf_nf_ctx, struct bpf_nf_ctx)
```

后者定义如下：

```C
// file: net/netfilter/nf_bpf_link.c
const struct bpf_prog_ops netfilter_prog_ops = {
    .test_run = bpf_prog_test_run_nf,
};
```

##### `.test_run`的实现过程

`NETFILTER` 类型程序对应的`.test_run`接口设置为`bpf_prog_test_run_nf`，后者实现如下：

```C
// file: net/bpf/test_run.c
int bpf_prog_test_run_nf(struct bpf_prog *prog, const union bpf_attr *kattr, union bpf_attr __user *uattr)
{
    struct net *net = current->nsproxy->net_ns;
    // 默认`lo`
    struct net_device *dev = net->loopback_dev;
    // 默认IPV4的`NF_INET_LOCAL_OUT`
    struct nf_hook_state *user_ctx, hook_state = {
        .pf = NFPROTO_IPV4,
        .hook = NF_INET_LOCAL_OUT,
    };
    u32 size = kattr->test.data_size_in;
    u32 repeat = kattr->test.repeat;
    struct bpf_nf_ctx ctx = {
        .state = &hook_state,
    };
    struct sk_buff *skb = NULL;
    u32 retval, duration;
    void *data;
    int ret;

    // 测试选项检查
    if (kattr->test.flags || kattr->test.cpu || kattr->test.batch_size) return -EINVAL;
    // 测试数据长度检查
    if (size < sizeof(struct iphdr)) return -EINVAL;
    
    // 初始化测试环境，复制用户空间设置的数据
    data = bpf_test_init(kattr, kattr->test.data_size_in, size, 
                NET_SKB_PAD + NET_IP_ALIGN, SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
    if (IS_ERR(data)) return PTR_ERR(data);

    // 默认运行一次
    if (!repeat) repeat = 1;

    // 初始化运行上下文，即`nf_hook_state`
    user_ctx = bpf_ctx_init(kattr, sizeof(struct nf_hook_state));
    if (IS_ERR(user_ctx)) { kfree(data); return PTR_ERR(user_ctx); }
    // 验证并复制用户空间设置的`nf_hook_state`
    if (user_ctx) {
        ret = verify_and_copy_hook_state(&hook_state, user_ctx, dev);
        if (ret) goto out;
    }
    // 将用户空间输入的数据生成skb
    skb = slab_build_skb(data);
    if (!skb) { ret = -ENOMEM; goto out; }

    data = NULL; /* data released via kfree_skb */
    // 设置skb的`head`和`tail`
    skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN);
    __skb_put(skb, size);

    ret = -EINVAL;
    // 根据挂载点的不同，设置skb
    if (hook_state.hook != NF_INET_LOCAL_OUT) {
        if (size < ETH_HLEN + sizeof(struct iphdr)) goto out;
        // 设置L3协议，从数据中获取
        skb->protocol = eth_type_trans(skb, dev);
        switch (skb->protocol) {
        case htons(ETH_P_IP):
            if (hook_state.pf == NFPROTO_IPV4) break;
            goto out;
        case htons(ETH_P_IPV6):
            if (size < ETH_HLEN + sizeof(struct ipv6hdr)) goto out;
            if (hook_state.pf == NFPROTO_IPV6) break;
            goto out;
        default: ret = -EPROTO; goto out;
        }
        // 保留L2信息
        skb_reset_network_header(skb);
    } else {
        // 设置L3协议，使用用户空间指定的协议
        skb->protocol = nfproto_eth(hook_state.pf);
    }

    // 设置skb
    ctx.skb = skb;

    // 测试BPF程序
    ret = bpf_test_run(prog, &ctx, repeat, &retval, &duration, false);
    if (ret) goto out;
    
    // 复制测试结果、执行时长到用户空间
    ret = bpf_test_finish(kattr, uattr, NULL, NULL, 0, retval, duration);

out:
    kfree(user_ctx);
    kfree_skb(skb);
    kfree(data);
    return ret;
}
```

##### BPF程序的执行过程

通过`bpf_test_run`函数实现的。

#### 4.2.6 TRACING

`TRACING` 类型对应的 `bpf_prog_ops` 如下：

```C
// file: include/linux/bpf_types.h
BPF_LINK_TYPE(BPF_LINK_TYPE_TRACING, tracing)
```

后者定义如下：

```C
// file: kernel/trace/bpf_trace.c
const struct bpf_prog_ops tracing_prog_ops = {
    .test_run = bpf_prog_test_run_tracing,
};
```

##### `.test_run`的实现过程

`TRACING` 类型程序对应的`.test_run`接口设置为`bpf_prog_test_run_tracing`，后者实现如下：

```C
// file: net/bpf/test_run.c
int bpf_prog_test_run_tracing(struct bpf_prog *prog, const union bpf_attr *kattr, union bpf_attr __user *uattr)
{
    struct bpf_fentry_test_t arg = {};
    u16 side_effect = 0, ret = 0;
    int b = 2, err = -EFAULT;
    u32 retval = 0;

    // 测试选项检查
    if (kattr->test.flags || kattr->test.cpu || kattr->test.batch_size) return -EINVAL;

    // 根据不同的附加类型
    switch (prog->expected_attach_type) {
    case BPF_TRACE_FENTRY:
    case BPF_TRACE_FEXIT:
        // `FENTRY`,`FEXIT`调用测试函数
        if (bpf_fentry_test1(1) != 2 ||
            bpf_fentry_test2(2, 3) != 5 ||
            bpf_fentry_test3(4, 5, 6) != 15 ||
            bpf_fentry_test4((void *)7, 8, 9, 10) != 34 ||
            bpf_fentry_test5(11, (void *)12, 13, 14, 15) != 65 ||
            bpf_fentry_test6(16, (void *)17, 18, 19, (void *)20, 21) != 111 ||
            bpf_fentry_test7((struct bpf_fentry_test_t *)0) != 0 ||
            bpf_fentry_test8(&arg) != 0 ||
            bpf_fentry_test9(&retval) != 0)
            goto out;
        break;
    case BPF_MODIFY_RETURN:
        // `MODIFY_RETURN`调用测试函数，记录测试结果
        ret = bpf_modify_return_test(1, &b);
        if (b != 2) side_effect++;
        b = 2;
        ret += bpf_modify_return_test2(1, &b, 3, 4, (void *)5, 6, 7);
        if (b != 2) side_effect++;
        break;
    default:
        goto out;
    }
    // 设置运行结果，并拷贝到用户空间
    retval = ((u32)side_effect << 16) | ret;
    if (copy_to_user(&uattr->test.retval, &retval, sizeof(retval))) goto out;

    err = 0;
out:
    trace_bpf_test_finish(&err);
    return err;
}
```

##### BPF程序的执行过程

`FENTRY`,`FEXIT`,`MODIFY_RETURN`类型的BPF程序在内核中调用测试函数，在函数执行过程中调用BPF测试。


#### 4.2.7 RAW_TRACEPOINT

`RAW_TRACEPOINT` 类型对应的 `bpf_prog_ops` 如下：

```C
// file: include/linux/bpf_types.h
BPF_PROG_TYPE(BPF_PROG_TYPE_RAW_TRACEPOINT, raw_tracepoint,
        struct bpf_raw_tracepoint_args, u64)
```

后者定义如下：

```C
// file: kernel/trace/bpf_trace.c
const struct bpf_prog_ops raw_tracepoint_prog_ops = {
#ifdef CONFIG_NET
    .test_run = bpf_prog_test_run_raw_tp,
#endif
};
```

##### `.test_run`的实现过程

`RAW_TRACEPOINT` 类型程序对应的`.test_run`接口设置为`bpf_prog_test_run_raw_tp`，后者实现如下：

```C
// file: net/bpf/test_run.c
int bpf_prog_test_run_raw_tp(struct bpf_prog *prog, const union bpf_attr *kattr, union bpf_attr __user *uattr)
{
    void __user *ctx_in = u64_to_user_ptr(kattr->test.ctx_in);
    __u32 ctx_size_in = kattr->test.ctx_size_in;
    struct bpf_raw_tp_test_run_info info;
    int cpu = kattr->test.cpu, err = 0;
    int current_cpu;

    // 测试选项检查
    if (kattr->test.data_in || kattr->test.data_out || kattr->test.ctx_out || 
        kattr->test.duration || kattr->test.repeat || kattr->test.batch_size) return -EINVAL;

    // `ctx_in`检查
    if (ctx_size_in < prog->aux->max_ctx_offset || ctx_size_in > MAX_BPF_FUNC_ARGS * sizeof(u64)) return -EINVAL;

    // 指定CPU设置检查
    if ((kattr->test.flags & BPF_F_TEST_RUN_ON_CPU) == 0 && cpu != 0) return -EINVAL;

    // 设置用户空间设置的运行上下文
    if (ctx_size_in) {
        info.ctx = memdup_user(ctx_in, ctx_size_in);
        if (IS_ERR(info.ctx)) return PTR_ERR(info.ctx);
    } else {
        info.ctx = NULL;
    }
    // 设置BPF程序
    info.prog = prog;

    // 获取当前CPU，在指定的CPU上运行测试
    current_cpu = get_cpu();
    if ((kattr->test.flags & BPF_F_TEST_RUN_ON_CPU) == 0 || cpu == current_cpu) {
        // 没有设置CPU，或者是当前CPU，运行测试
        __bpf_prog_test_run_raw_tp(&info);
    } else if (cpu >= nr_cpu_ids || !cpu_online(cpu)) {
        // CPU设置不正确，或者CPU离线，设置错误码
        err = -ENXIO;
    } else {
        // 不是当前CPU时，运行测试
        err = smp_call_function_single(cpu, __bpf_prog_test_run_raw_tp, &info, 1);
    }
    put_cpu();

    // 拷贝运行结果到用户空间
    if (!err && copy_to_user(&uattr->test.retval, &info.retval, sizeof(u32))) err = -EFAULT;

    kfree(info.ctx);
    return err;
}
```

##### BPF程序的执行过程

通过在指定的CPU上调用`__bpf_prog_test_run_raw_tp`函数实现的，如下:

```C
// file: net/bpf/test_run.c
static void __bpf_prog_test_run_raw_tp(void *data)
{
    struct bpf_raw_tp_test_run_info *info = data;
    struct bpf_trace_run_ctx run_ctx = {};
    struct bpf_run_ctx *old_run_ctx;
    // 设置运行上下文
    old_run_ctx = bpf_set_run_ctx(&run_ctx.run_ctx);

    rcu_read_lock();
    // 运行BPF程序
    info->retval = bpf_prog_run(info->prog, info->ctx);
    rcu_read_unlock();
    
    // 重置上下文
    bpf_reset_run_ctx(old_run_ctx);
}
```

#### 4.2.8 SYSCALL

`SYSCALL` 类型对应的 `bpf_prog_ops` 如下：

```C
// file: include/linux/bpf_types.h
BPF_PROG_TYPE(BPF_PROG_TYPE_SYSCALL, bpf_syscall,
        void *, void *)
```

后者定义如下：

```C
// file: kernel/bpf/syscall.c
const struct bpf_prog_ops bpf_syscall_prog_ops = {
    .test_run = bpf_prog_test_run_syscall,
};
```

##### `.test_run`的实现过程

`SYSCALL` 类型程序对应的`.test_run`接口设置为`bpf_prog_test_run_syscall`，后者实现如下：

```C
// file: net/bpf/test_run.c
int bpf_prog_test_run_syscall(struct bpf_prog *prog, const union bpf_attr *kattr, union bpf_attr __user *uattr)
{
    void __user *ctx_in = u64_to_user_ptr(kattr->test.ctx_in);
    __u32 ctx_size_in = kattr->test.ctx_size_in;
    void *ctx = NULL;
    u32 retval;
    int err = 0;

    // 测试选项检查
    if (kattr->test.data_in || kattr->test.data_out || kattr->test.ctx_out || kattr->test.duration ||
        kattr->test.repeat || kattr->test.flags || kattr->test.batch_size) return -EINVAL;
    
    // `ctx_in`检查
    if (ctx_size_in < prog->aux->max_ctx_offset || ctx_size_in > U16_MAX) return -EINVAL;
    // 存在`ctx_in`时，复制到内核空间
    if (ctx_size_in) {
        ctx = memdup_user(ctx_in, ctx_size_in);
        if (IS_ERR(ctx)) return PTR_ERR(ctx);
    }

    rcu_read_lock_trace();
    // 运行BPF程序
    retval = bpf_prog_run_pin_on_cpu(prog, ctx);
    rcu_read_unlock_trace();

    // 拷贝运行结果到用户空间
    if (copy_to_user(&uattr->test.retval, &retval, sizeof(u32))) { err = -EFAULT; goto out; }
    // 存在`ctx_in`时，复制到用户空间
    if (ctx_size_in) if (copy_to_user(ctx_in, ctx, ctx_size_in)) err = -EFAULT;

out:
    kfree(ctx);
    return err;
}
```

##### BPF程序的执行过程

通过`bpf_prog_run_pin_on_cpu`函数实现。


#### 4.2.9 STRUCT_OPS

`STRUCT_OPS` 类型对应的 `bpf_prog_ops` 如下：

```C
// file: include/linux/bpf_types.h
BPF_PROG_TYPE(BPF_PROG_TYPE_STRUCT_OPS, bpf_struct_ops,
        void *, void *)
```

后者定义如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
const struct bpf_prog_ops bpf_struct_ops_prog_ops = {
#ifdef CONFIG_NET
    .test_run = bpf_struct_ops_test_run,
#endif
};
```

##### `.test_run`的实现过程

`STRUCT_OPS` 类型程序对应的`.test_run`接口设置为`bpf_struct_ops_test_run`，后者实现如下：

```C
// file: net/bpf/bpf_dummy_struct_ops.c
int bpf_struct_ops_test_run(struct bpf_prog *prog, const union bpf_attr *kattr, union bpf_attr __user *uattr)
{
    // `bpf_dummy_ops`
    const struct bpf_struct_ops *st_ops = &bpf_bpf_dummy_ops;
    const struct btf_type *func_proto;
    struct bpf_dummy_ops_test_args *args;
    struct bpf_tramp_links *tlinks = NULL;
    struct bpf_tramp_link *link = NULL;
    void *image = NULL;
    unsigned int op_idx;
    u32 image_off = 0;
    int prog_ret;
    s32 type_id;
    int err;

    // 查找`bpf_dummy_ops`
    type_id = btf_find_by_name_kind(bpf_dummy_ops_btf, bpf_bpf_dummy_ops.name, BTF_KIND_STRUCT);
    if (type_id < 0) return -EINVAL;
    if (prog->aux->attach_btf_id != type_id) return -EOPNOTSUPP;

    // 初始化函数原型，设置用户空间输入的参数、状态
    func_proto = prog->aux->attach_func_proto;
    args = dummy_ops_init_args(kattr, btf_type_vlen(func_proto));
    if (IS_ERR(args)) return PTR_ERR(args);

    // 检查函数原型及参数
    err = check_test_run_args(prog, args);
    if (err) goto out;

    // 创建`bpf_dummy_ops`
    tlinks = kcalloc(BPF_TRAMP_MAX, sizeof(*tlinks), GFP_KERNEL);
    if (!tlinks) { err = -ENOMEM; goto out; }

    // 分配并初始化`tramp_link`
    link = kzalloc(sizeof(*link), GFP_USER);
    if (!link) { err = -ENOMEM; goto out; }
    /* prog doesn't take the ownership of the reference from caller */
    bpf_prog_inc(prog);
    bpf_link_init(&link->link, BPF_LINK_TYPE_STRUCT_OPS, &bpf_struct_ops_link_lops, prog);

    // 设置为BPF trampoline，附加的函数为`dummy_ops_test_ret_function`
    op_idx = prog->expected_attach_type;
    err = bpf_struct_ops_prepare_trampoline(tlinks, link, &st_ops->func_models[op_idx],
                &dummy_ops_test_ret_function, &image, &image_off, true);
    if (err < 0) goto out;

    // 设置`image`访问权限
    err = arch_protect_bpf_trampoline(image, PAGE_SIZE);
    if (err) goto out;

    // 调用函数
    prog_ret = dummy_ops_call_op(image, args);
    // 复制执行状态
    err = dummy_ops_copy_args(args);
    if (err) goto out;
    
    // 将返回值写入用户空间
    if (put_user(prog_ret, &uattr->test.retval)) err = -EFAULT;
out:
    kfree(args);
    bpf_struct_ops_image_free(image);
    if (link) bpf_link_put(&link->link);
    kfree(tlinks);
    return err;
}
```

`bpf_bpf_dummy_ops`是`struct bpf_dummy_ops`的`STRUCT_OPS`操作接口，其定义如下：

```C
// file: net/bpf/bpf_dummy_struct_ops.c
static struct bpf_struct_ops bpf_bpf_dummy_ops = {
    .verifier_ops = &bpf_dummy_verifier_ops,
    .init = bpf_dummy_init,
    .check_member = bpf_dummy_ops_check_member,
    .init_member = bpf_dummy_init_member,
    .reg = bpf_dummy_reg,
    .unreg = bpf_dummy_unreg,
    .name = "bpf_dummy_ops",
    .cfi_stubs = &__bpf_bpf_dummy_ops,
    .owner = THIS_MODULE,
};
```

`struct bpf_dummy_ops`是被测试的`ops`，其定义如下：

```C
// file: include/linux/bpf.h
struct bpf_dummy_ops_state {
    int val;
};
struct bpf_dummy_ops {
    int (*test_1)(struct bpf_dummy_ops_state *cb);
    int (*test_2)(struct bpf_dummy_ops_state *cb, int a1, unsigned short a2, char a3, unsigned long a4);
    int (*test_sleepable)(struct bpf_dummy_ops_state *cb);
};
```

`__bpf_bpf_dummy_ops`为`struct bpf_dummy_ops`的打桩实现(`stub`)，如下：

```C
// file: net/bpf/bpf_dummy_struct_ops.c
static int bpf_dummy_ops__test_1(struct bpf_dummy_ops_state *cb__nullable)
{
    return 0;
}
static int bpf_dummy_test_2(struct bpf_dummy_ops_state *cb, int a1, unsigned short a2, char a3, unsigned long a4)
{
    return 0;
}
static int bpf_dummy_test_sleepable(struct bpf_dummy_ops_state *cb)
{
    return 0;
}
static struct bpf_dummy_ops __bpf_bpf_dummy_ops = {
    .test_1 = bpf_dummy_ops__test_1,
    .test_2 = bpf_dummy_test_2,
    .test_sleepable = bpf_dummy_test_sleepable,
};
```

##### BPF程序的执行过程

在`dummy_ops_call_op`函数中调用附加的函数，在函数执行过程中执行BPF程序，如下：

```C
// file: net/bpf/bpf_dummy_struct_ops.c
static int dummy_ops_call_op(void *image, struct bpf_dummy_ops_test_args *args)
{
    // 获取函数地址
    dummy_ops_test_ret_fn test = (void *)image + cfi_get_offset();
    struct bpf_dummy_ops_state *state = NULL;

    /* state needs to be NULL if args[0] is 0 */
    if (args->args[0])
        state = &args->state;
    // 调用函数
    return test(state, args->args[1], args->args[2], args->args[3], args->args[4]);
}
```

`dummy_ops_test_ret_fn`为测试`bpf_dummy_ops`时的通用函数原型，定义如下：

```C
// file: net/bpf/bpf_dummy_struct_ops.c
typedef int (*dummy_ops_test_ret_fn)(struct bpf_dummy_ops_state *state, ...);
```

## 5 总结

本文通过`sk_lookup`示例程序分析了对BPF程序测试的实现过程。用户空间可以通过`BPF_PROG_TEST_RUN`指令实现对不同类型的BPF程序进行测试，从而验证BPF程序的功能和性能。

## 参考资料

* [Running BPF programs from userspace](https://www.kernel.org/doc/html/v6.11/bpf/bpf_prog_run.html)
* [BPF Syscall BPF_PROG_TEST_RUN command](https://ebpf-docs.dylanreimerink.nl/linux/syscall/BPF_PROG_TEST_RUN/)
* [bpf: program testing framework](https://lwn.net/Articles/718784/)