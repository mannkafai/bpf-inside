# SOCKMAP的内核实现

## 0 前言

在[XDP的内核实现](./12-xdp.md)中我们分析了通过XDP实现网络数据重定向的过程，今天我们借助`test_sockmap`示例程序分析通过`SOCKMAP`实现在socket间重定向的实现过程。

## 1 简介

`SOCKMAP`/`SOCKHASH`是一种特殊用途的BPF MAP，map中的值是对socket的结构的引用，该MAP支持socket间的重定向。在通过`sock_ops` BPF程序捕获socket创建事件后，关联到`sockmap`中。`sockmap`附加`sk_skb/sk_msg` BPF程序，实现socket的重定向。该类程序的典型使用场景为流解析器（strparser）框架。

## 2 `test_sockmap`示例程序

### 2.1 BPF程序

`SOCKMAP`BPF程序支持`SOCKHASH`和`SOCKMAP`两种类型，通过 `SOCKMAP` 和 `TEST_MAP_TYPE` 宏定义实现。`SOCKHASH`对应 [test_sockhash_kern.c](../src/test_sockhash_kern.c) ，如下：

```C
// file: ../src/test_sockhash_kern.c
#undef SOCKMAP
#define TEST_MAP_TYPE BPF_MAP_TYPE_SOCKHASH
#include "./test_sockmap_kern.h"
```

`SOCKMAP`对应 [test_sockmap_kern.c](../src/test_sockmap_kern.c) ，如下：

```C
// file: ../src/test_sockmap_kern.c
#define SOCKMAP
#define TEST_MAP_TYPE BPF_MAP_TYPE_SOCKMAP
#include "./test_sockmap_kern.h"
```

两者的实现在 [test_sockmap_kern.h](../src/test_sockmap_kern.h) 中，主要内容如下：

```C
// sockmap
struct {
    __uint(type, TEST_MAP_TYPE);
    __uint(max_entries, 20);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

// txmsg使用的sockmap
struct {
    __uint(type, TEST_MAP_TYPE);
    __uint(max_entries, 20);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} sock_map_txmsg SEC(".maps");

// redir使用的sockmap
struct {
    __uint(type, TEST_MAP_TYPE);
    __uint(max_entries, 20);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} sock_map_redir SEC(".maps");

// skb选项
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, int);
    __type(value, int);
} sock_skb_opts SEC(".maps");

SEC("sk_skb1")
int bpf_prog1(struct __sk_buff *skb)
{
    int *f, two = 2;
    // skb_opts[2]表示指定skb的长度
    f = bpf_map_lookup_elem(&sock_skb_opts, &two);
    if (f && *f) { return *f; }
    return skb->len;
}

SEC("sk_skb2")
int bpf_prog2(struct __sk_buff *skb)
{
    __u32 lport = skb->local_port;
    __u32 rport = skb->remote_port;
    int len, *f, ret, zero = 0;
    __u64 flags = 0;

    // 重定向的key
    if (lport == 10000) ret = 10; else ret = 1;
    len = (__u32)skb->data_end - (__u32)skb->data;
    // skb_opts[0]表示中重定向信息
    f = bpf_map_lookup_elem(&sock_skb_opts, &zero);
    if (f && *f) {
        ret = 3;
        flags = *f;
    }
    // 通过`sockmap`或者`sockhash`重定向`skb`
#ifdef SOCKMAP
    return bpf_sk_redirect_map(skb, &sock_map, ret, flags);
#else
    return bpf_sk_redirect_hash(skb, &sock_map, &ret, flags);
#endif
}

SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
    __u32 lport, rport;
    int op, err = 0, index, key, ret;
    op = (int) skops->op;

    switch (op) {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        lport = skops->local_port;
        rport = skops->remote_port;
        if (lport == 10000) {
            // 被动建立连接(accept)，设置为`sock_map[1]`
            ret = 1;
#ifdef SOCKMAP
            err = bpf_sock_map_update(skops, &sock_map, &ret, BPF_NOEXIST);
#else
            err = bpf_sock_hash_update(skops, &sock_map, &ret, BPF_NOEXIST);
#endif
        }
        break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        lport = skops->local_port;
        rport = skops->remote_port;
        if (bpf_ntohl(rport) == 10001) {
            // 主动建立连接(connect)，设置为`sock_map[10]`
            ret = 10;
#ifdef SOCKMAP
            err = bpf_sock_map_update(skops, &sock_map, &ret, BPF_NOEXIST);
#else
            err = bpf_sock_hash_update(skops, &sock_map, &ret, BPF_NOEXIST);
#endif
        }
        break;
    default:
        break;
    }
    return 0;
}

SEC("sk_msg1")
int bpf_prog4(struct sk_msg_md *msg)
{
    ...
    return SK_PASS;
}

SEC("sk_msg2")
int bpf_prog6(struct sk_msg_md *msg)
{
    ...
    
    f = bpf_map_lookup_elem(&sock_redir_flags, &zero);
    if (f && *f) {
        key = 2;
        flags = *f;
    }
    // 通过`sockmap`或者`sockhash`重定向`msg`
#ifdef SOCKMAP
    return bpf_msg_redirect_map(msg, &sock_map_redir, key, flags);
#else
    return bpf_msg_redirect_hash(msg, &sock_map_redir, &key, flags);
#endif
}
...
```

### 2.2 用户程序

用户程序源码参见[test_sockmap.c](../src/test_sockmap.c)，主要内容如下：

#### 1 附加BPF程序

```C
// file: ../src/test_sockmap.c
static int run_options(struct sockmap_options *options, int cg_fd,  int test)
{
    int i, key, next_key, err, tx_prog_fd = -1, zero = 0;

    // BASE测试跳过BPF的设置过程
    if (test == BASE || test == BASE_SENDPAGE) goto run;

    // 附加`SKB_STREAM_PARSER`程序到`sock_map`
    if (!txmsg_omit_skb_parser) {
        err = bpf_prog_attach(prog_fd[0], map_fd[0], BPF_SK_SKB_STREAM_PARSER, 0);
        if (err) { ... }
    }
    // 附加`SKB_STREAM_VERDICT`程序到`sock_map`
    err = bpf_prog_attach(prog_fd[1], map_fd[0], BPF_SK_SKB_STREAM_VERDICT, 0);
    if (err) { ... }
    ...

    // 附加cgroups程序
    err = bpf_prog_attach(prog_fd[3], cg_fd, BPF_CGROUP_SOCK_OPS, 0);
    if (err) { ... }

run:
    // 创建测试使用的socket，s1(监听:10000),p1,c1;s2(监听:10001),p2,c2
    err = sockmap_init_sockets(options->verbose);
    if (err) { ... }

    // 附加txmsg到sockmap
    if (txmsg_pass) tx_prog_fd = prog_fd[4];
    else if (txmsg_redir) tx_prog_fd = prog_fd[5];
    else if (txmsg_apply) tx_prog_fd = prog_fd[6];
    else if (txmsg_cork) tx_prog_fd = prog_fd[7];
    else if (txmsg_drop) tx_prog_fd = prog_fd[8];
    else tx_prog_fd = 0;

    if (tx_prog_fd) {
        int redir_fd, i = 0;
        // 附加`MSG_VERDICT`BPF程序到`sock_map_txmsg`
        err = bpf_prog_attach(tx_prog_fd, map_fd[1], BPF_SK_MSG_VERDICT, 0);
        if (err) { ... }

        // 更新`sock_map_txmsg`的socket
        err = bpf_map_update_elem(map_fd[1], &i, &c1, BPF_ANY);
        if (err) { ... }

        // 更新`sock_map_redir`的socket
        if (txmsg_redir) redir_fd = c2; else redir_fd = c1;
        err = bpf_map_update_elem(map_fd[2], &i, &redir_fd, BPF_ANY);
        if (err) { ... }
    }
    if (skb_use_parser) {
        // 指定长度时，更新到`sock_skb_opts[2]`
        i = 2;
        err = bpf_map_update_elem(map_fd[7], &i, &skb_use_parser, BPF_ANY);
    }

    if (txmsg_drop) options->drop_expected = true;
    // 设置测试模式后进行测试
    if (test == PING_PONG)
        err = forever_ping_pong(options->rate, options);
    else if (test == SENDMSG) {
        options->base = false;
        options->sendpage = false;
        err = sendmsg_test(options);
    } else if (test == SENDPAGE) { ... 
    } else if (test == BASE) { ... 
    } else if (test == BASE_SENDPAGE) { ... 
    } else fprintf(stderr, "unknown test\n");

out:
    // 分离BPF程序
    bpf_prog_detach2(prog_fd[3], cg_fd, BPF_CGROUP_SOCK_OPS);
    bpf_prog_detach2(prog_fd[0], map_fd[0], BPF_SK_SKB_STREAM_PARSER);
    bpf_prog_detach2(prog_fd[1], map_fd[0], BPF_SK_SKB_STREAM_VERDICT);
    bpf_prog_detach2(prog_fd[0], map_fd[8], BPF_SK_SKB_STREAM_PARSER);
    bpf_prog_detach2(prog_fd[2], map_fd[8], BPF_SK_SKB_STREAM_VERDICT);

    if (tx_prog_fd >= 0) bpf_prog_detach2(tx_prog_fd, map_fd[1], BPF_SK_MSG_VERDICT);

    // 更新map的值，重置为0
    for (i = 0; i < 8; i++) {
        key = next_key = 0;
        bpf_map_update_elem(map_fd[i], &key, &zero, BPF_ANY);
        while (bpf_map_get_next_key(map_fd[i], &key, &next_key) == 0) {
            bpf_map_update_elem(map_fd[i], &key, &zero, BPF_ANY);
            key = next_key;
        }
    }
    // 关闭创建的socket
    close(s1);
    close(s2);
    close(p1);
    close(p2);
    close(c1);
    close(c2);
    return err;
}
```

#### 2 读取数据过程

`test_sockmap` 测试程序通过发送、接收的数据量判断是否完全发送。

### 2.3 编译运行

`test_sockmap`程序是Linux内核自带的测试程序，在`tools/testing/selftests/bpf/prog_tests/`目录下。编译后运行，如下：

```bash
$ cd tools/testing/selftests/bpf/
$ sudo make
$ sudo ./test_sockmap  -v 2
[TEST 0]: (1, 1, 1, sendmsg, pass,): connected sockets: c1 <-> p1, c2 <-> p2
cgroups binding: c1(25) <-> s1(23) - - - c2(26) <-> s2(24)
tx_sendmsg: TX: 1B 0.000000B/s 0.000000 GB/s RX: 0B 0.000000B/s 0.000000GB/s
msg_loop_rx: iov_count 1 iov_buf 1 cnt 1 err 0
rx_sendmsg: TX: 0B 0.000000B/s 0.000000GB/s RX: 1B 0.000000B/s 0.000000GB/s 
 PASS
....
# 1/ 6  sockmap::txmsg test passthrough:OK
...
#43/ 1 sockhash:ktls:txmsg test push/pop data:OK
 [TEST 295]: (2, 1, 256, sendpage, pass,ktls,): connected sockets: c1 <-> p1, c2 <-> p2
cgroups binding: c1(63) <-> s1(61) - - - c2(64) <-> s2(62)
socket(peer2) kTLS enabled
socket(client1) kTLS enabled
tx_sendmsg: TX: 512B 0.000000B/s 0.000000 GB/s RX: 0B 0.000000B/s 0.000000GB/s
msg_loop_rx: iov_count 1 iov_buf 256 cnt 2 err 0
rx_sendmsg: TX: 0B 0.000000B/s 0.000000GB/s RX: 512B 0.000000B/s 0.000000GB/s 
 PASS
#44/ 1 sockhash:ktls:txmsg test ingress parser:OK
#45/ 0 sockhash:ktls:txmsg test ingress parser2:OK
Pass: 45 Fail: 0
```

## 3 sockmap附加和分离的过程

`test_sockmap_kern.h`文件中BPF程序的SEC名称为`SEC("sk_skb")` 和 `SEC("sk_msg")`，在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("sk_skb/stream_parser", SK_SKB, BPF_SK_SKB_STREAM_PARSER, SEC_ATTACHABLE_OPT),
    SEC_DEF("sk_skb/stream_verdict",SK_SKB, BPF_SK_SKB_STREAM_VERDICT, SEC_ATTACHABLE_OPT),
    SEC_DEF("sk_skb", SK_SKB, 0, SEC_NONE),
    SEC_DEF("sk_msg", SK_MSG, BPF_SK_MSG_VERDICT, SEC_ATTACHABLE_OPT),
    ...
};
```

`sk_skb`和`sk_msg`前缀不支持自动附加，需要通过手动方式附加。

### 3.1 附加过程

`sk_skb/sk_msg`类型的BPF程序通过`bpf_prog_attach`方式附加，设置`opts->flags`后调用 `bpf_prog_attach_opts` ，如下：

```C
// file: libbpf/src/bpf.c
int bpf_prog_attach(int prog_fd, int target_fd, enum bpf_attach_type type, unsigned int flags)
{
    DECLARE_LIBBPF_OPTS(bpf_prog_attach_opts, opts, .flags = flags, );
    return bpf_prog_attach_opts(prog_fd, target_fd, type, &opts);
}
```

`bpf_prog_attach_opts` 函数实现BPF程序的附加，如下：

```C
// file: libbpf/src/bpf.c
int bpf_prog_attach_opts(int prog_fd, int target_fd, enum bpf_attach_type type,
        const struct bpf_prog_attach_opts *opts)
{
    const size_t attr_sz = offsetofend(union bpf_attr, replace_bpf_fd);
    union bpf_attr attr;
    int ret;
    // 检查opts是否有效
    if (!OPTS_VALID(opts, bpf_prog_attach_opts)) return libbpf_err(-EINVAL);
    // 设置bpf系统调用的属性
    memset(&attr, 0, attr_sz);
    attr.target_fd = target_fd;
    attr.attach_bpf_fd = prog_fd;
    attr.attach_type   = type;
    attr.attach_flags  = OPTS_GET(opts, flags, 0);
    attr.replace_bpf_fd = OPTS_GET(opts, replace_prog_fd, 0);
    // BPF系统调用，使用`BPF_PROG_ATTACH`指令
    ret = sys_bpf(BPF_PROG_ATTACH, &attr, attr_sz);
    return libbpf_err_errno(ret);
}
```

### 3.2 分离过程

`bpf_prog_detach2` 函数实现`sk_skb/sk_msg` BPF程序的分离，如下：

```C
// file: libbpf/src/bpf.c
int bpf_prog_detach2(int prog_fd, int target_fd, enum bpf_attach_type type)
{
    const size_t attr_sz = offsetofend(union bpf_attr, replace_bpf_fd);
    union bpf_attr attr;
    int ret;
    // 设置bpf系统调用的属性
    memset(&attr, 0, attr_sz);
    attr.target_fd = target_fd;
    attr.attach_bpf_fd = prog_fd;
    attr.attach_type = type;
    // BPF系统调用，使用`BPF_PROG_DETACH`指令
    ret = sys_bpf(BPF_PROG_DETACH, &attr, attr_sz);
    return libbpf_err_errno(ret);
}
```

## 4 内核实现

### 4.1 附加和分离的内核实现

#### 1 附加的实现

##### (1) BPF系统调用

附加`sk_skb/sk_msg`使用`BPF_PROG_ATTACH` BPF系统调用，如下：

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
    case BPF_PROG_ATTACH: err = bpf_prog_attach(&attr); break;
    ...
    }
    return err;
}
```

##### (2) `BPF_PROG_ATTACH`

`bpf_prog_attach` 在检查BPF程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。`sk_skb/sk_msg`类型的bpf程序对应 `sock_map_get_from_fd` 处理函数。如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_prog_attach(const union bpf_attr *attr)
{
    enum bpf_prog_type ptype;
    struct bpf_prog *prog;
    int ret;

    // 检查bpf_attr属性
    if (CHECK_ATTR(BPF_PROG_ATTACH)) return -EINVAL;
    if (attr->attach_flags & ~BPF_F_ATTACH_MASK) return -EINVAL;

    // 获取附加程序类型
    ptype = attach_type_to_prog_type(attr->attach_type);
    if (ptype == BPF_PROG_TYPE_UNSPEC) return -EINVAL;
    
    // 获取 bpf_prog
    prog = bpf_prog_get_type(attr->attach_bpf_fd, ptype);
    if (IS_ERR(prog)) return PTR_ERR(prog);
    
    // 检查 PROG_TYPE 和 expected_attach_type 是否匹配
    if (bpf_prog_attach_check_attach_type(prog, attr->attach_type)) { ... }

    switch (ptype) {
    case BPF_PROG_TYPE_SK_SKB:
    case BPF_PROG_TYPE_SK_MSG:
        ret = sock_map_get_from_fd(attr, prog);
        break;
    ...
    default:
        ret = -EINVAL;
    }
    // 附加失败时，释放bpf程序
    if (ret) bpf_prog_put(prog);
    return ret;
}
```

##### (3) `sock_map_get_from_fd`

`sock_map_get_from_fd` 函数附加SK_SKB/SK_MSG BPF程序附加到sockmap，实现如下：

```C
// file: net/core/sock_map.c
int sock_map_get_from_fd(const union bpf_attr *attr, struct bpf_prog *prog)
{
    u32 ufd = attr->target_fd;
    struct bpf_map *map;
    struct fd f;
    int ret;
    // 属性检查
    if (attr->attach_flags || attr->replace_bpf_fd) return -EINVAL;
    // 获取属性中的map
    f = fdget(ufd);
    map = __bpf_map_get(f);
    if (IS_ERR(map)) return PTR_ERR(map);
    // 更新map中的bpg程序
    ret = sock_map_prog_update(map, prog, NULL, attr->attach_type);
    fdput(f);
    return ret;
}
```

`sock_map_prog_update` 函数更新sockmap中BPF程序，如下：

```C
// file: net/core/sock_map.c
static int sock_map_prog_update(struct bpf_map *map, struct bpf_prog *prog, 
                                struct bpf_prog *old, u32 which)
{
    struct bpf_prog **pprog;
    int ret;
    // 查找对应类型的程序地址
    ret = sock_map_prog_lookup(map, &pprog, which);
    if (ret) return ret;
    // 存在旧的程序时，替换已有的程序
    if (old) return psock_replace_prog(pprog, prog, old);
    // 否则，设置程序
    psock_set_prog(pprog, prog);
    return 0;
}
```

`sock_map_prog_lookup`函数查找对应类型的程序，如下：

```C
// file: net/core/sock_map.c
static int sock_map_prog_lookup(struct bpf_map *map, struct bpf_prog ***pprog, u32 which)
{
    // 获取map中`psock_progs`
    struct sk_psock_progs *progs = sock_map_progs(map);

    if (!progs) return -EOPNOTSUPP;

    switch (which) {
    case BPF_SK_MSG_VERDICT:
        *pprog = &progs->msg_parser;
        break;
#if IS_ENABLED(CONFIG_BPF_STREAM_PARSER)
    case BPF_SK_SKB_STREAM_PARSER:
        *pprog = &progs->stream_parser;
        break;
#endif
    case BPF_SK_SKB_STREAM_VERDICT:
        if (progs->skb_verdict) return -EBUSY;
        *pprog = &progs->stream_verdict;
        break;
    case BPF_SK_SKB_VERDICT:
        if (progs->stream_verdict) return -EBUSY;
        *pprog = &progs->skb_verdict;
        break;
    default:
        return -EOPNOTSUPP;
    }
    return 0;
}
```

`sock_map_progs`获取sockmap中的`sk_psock_progs`, 实现如下：

```C
// file: net/core/sock_map.c
static struct sk_psock_progs *sock_map_progs(struct bpf_map *map)
{
    switch (map->map_type) {
    case BPF_MAP_TYPE_SOCKMAP:
        return &container_of(map, struct bpf_stab, map)->progs;
    case BPF_MAP_TYPE_SOCKHASH:
        return &container_of(map, struct bpf_shtab, map)->progs;
    default:
        break;
    }
    return NULL;
}
```

sockmap支持`SOCKMAP`(struct bpf_stab)和`SOCKHASH`(struct bpf_shtab)两种类型，其对应的类型定义如下：

```C
// file: net/core/sock_map.c
struct bpf_stab {
    struct bpf_map map;
    struct sock **sks;
    struct sk_psock_progs progs;
    raw_spinlock_t lock;
};
// file: net/core/sock_map.c
struct bpf_shtab {
    struct bpf_map map;
    struct bpf_shtab_bucket *buckets;
    u32 buckets_num;
    u32 elem_size;
    struct sk_psock_progs progs;
    atomic_t count;
};
```

这种类型的map都包含`sk_psock_progs`类型的结构，如下：

```C
// file: include/linux/skmsg.h
struct sk_psock_progs {
    struct bpf_prog     *msg_parser;
    struct bpf_prog     *stream_parser;
    struct bpf_prog     *stream_verdict;
    struct bpf_prog     *skb_verdict;
};
```

`.msg_parser` 对应 `BPF_SK_MSG_VERDICT` 类型的BPF程序，判决发送msg的处理方式; `stream_parser` 对应 `BPF_SK_SKB_STREAM_PARSER` 类型的BPF程序，在接收skb时，解析skb的长度；`.stream_verdict`对应`BPF_SK_SKB_STREAM_VERDICT`类型的BPF程序，在接收skb时，判决skb的处理方式；`skb_verdict`对应`BPF_SK_SKB_VERDICT`类型的BPF程序，在接收skb时，判决skb的处理方式。`.stream_verdict` 和 `.skb_verdict` 不能同时设置。

#### 2 分离的实现

##### (1) BPF系统调用

使用`BPF_PROG_DETACH` BPF系统调用，如下：

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
    case BPF_PROG_DETACH: err = bpf_prog_detach(&attr); break;
    ...
    }
    return err;
}
```

##### (2) `BPF_PROG_DETACH`

`bpf_prog_detach` 在检查BPF程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理，`sk_skb/sk_msg`类型的bpf程序对应 `sock_map_prog_detach` 处理函数。如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_prog_detach(const union bpf_attr *attr)
{
    enum bpf_prog_type ptype;
    // 检查bpf_attr属性
    if (CHECK_ATTR(BPF_PROG_DETACH)) return -EINVAL;
    // 获取附加程序类型
    ptype = attach_type_to_prog_type(attr->attach_type);

    switch (ptype) {
    case BPF_PROG_TYPE_SK_MSG:
    case BPF_PROG_TYPE_SK_SKB:
        return sock_map_prog_detach(attr, ptype);
    ...
    default:
        return -EINVAL;
    }
}
```

##### (3) `sock_map_prog_detach`

`sock_map_prog_detach` 函数获取map和bpf程序后分离程序，实现如下：

```C
// file: net/core/sock_map.c
int sock_map_prog_detach(const union bpf_attr *attr, enum bpf_prog_type ptype)
{
    u32 ufd = attr->target_fd;
    struct bpf_prog *prog;
    struct bpf_map *map;
    struct fd f;
    int ret;

    // `attr`属性检查
    if (attr->attach_flags || attr->replace_bpf_fd) return -EINVAL;
    // 获取map
    f = fdget(ufd);
    map = __bpf_map_get(f);
    if (IS_ERR(map)) return PTR_ERR(map);

    // 获取BPF程序
    prog = bpf_prog_get(attr->attach_bpf_fd);
    if (IS_ERR(prog)) { ret = PTR_ERR(prog); goto put_map; }
    // 检查附加类型是否匹配
    if (prog->type != ptype) { ret = -EINVAL; goto put_prog;}

    // 更新程序，设置为NULL
    ret = sock_map_prog_update(map, NULL, prog, attr->attach_type);
put_prog:
    bpf_prog_put(prog);
put_map:
    fdput(f);
    return ret;
}
```

### 4.2 sock关联sockmap的过程

#### 1 用户空间关联sockmap的实现过程

用户空间通过`bpf_map_update_elem`更新map中的 key/value 关联BPF程序，其中value为socket。

##### (1) BPF系统调用

使用`BPF_MAP_UPDATE_ELEM` BPF系统调用，如下：

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
    case BPF_MAP_UPDATE_ELEM: err = map_update_elem(&attr, uattr); break;
    ...
    }
    return err;
}
```

`map_update_elem` 函数实现更新过程，实现如下：

```C
// file: kernel/bpf/syscall.c
static int map_update_elem(union bpf_attr *attr, bpfptr_t uattr)
{
    bpfptr_t ukey = make_bpfptr(attr->key, uattr.is_kernel);
    bpfptr_t uvalue = make_bpfptr(attr->value, uattr.is_kernel);
    int ufd = attr->map_fd;
    ...
    
    // `ATTR`检查
    if (CHECK_ATTR(BPF_MAP_UPDATE_ELEM)) return -EINVAL;
    
    // 根据fd获取map后，进行权限检查
    f = fdget(ufd);
    map = __bpf_map_get(f);
    if (IS_ERR(map)) return PTR_ERR(map);
    bpf_map_write_active_inc(map);
    if (!(map_get_sys_perms(map, f) & FMODE_CAN_WRITE)) { ... }
    // `flags`锁定检查
    if ((attr->flags & BPF_F_LOCK) && !btf_record_has_field(map->record, BPF_SPIN_LOCK)) { ... }

    // 获取设置的key、value
    key = ___bpf_copy_key(ukey, map->key_size);
    if (IS_ERR(key)) { err = PTR_ERR(key); goto err_put; }
    value_size = bpf_map_value_size(map);
    value = kvmemdup_bpfptr(uvalue, value_size);
    if (IS_ERR(value)) { err = PTR_ERR(value); goto free_key; }

    // bpf_map更新值
    err = bpf_map_update_value(map, f.file, key, value, attr->flags);

    kvfree(value);
free_key:
    kvfree(key);
err_put:
    // 减少写入计数
    bpf_map_write_active_dec(map);
    fdput(f);
    return err;
}
```

`bpf_map_update_value` 函数根据map的类型进行相关的更新操作，`SOCKHASH`和`SOCKMAP`对应 `sock_map_update_elem_sys` 函数，如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_map_update_value(struct bpf_map *map, struct file *map_file,
                void *key, void *value, __u64 flags)
{
    int err;
    if (bpf_map_is_offloaded(map)) {
        return bpf_map_offload_update_elem(map, key, value, flags);
    } else if ( ... ) { 
        ...
    } else if (map->map_type == BPF_MAP_TYPE_SOCKHASH ||
        map->map_type == BPF_MAP_TYPE_SOCKMAP) {
        return sock_map_update_elem_sys(map, key, value, flags);
    } 
    ...
}
```

##### (2) `sock_map_update_elem_sys`

`sock_map_update_elem_sys` 函数更新sockmap的值，实现如下：

```C
// file: net/core/sock_map.c
int sock_map_update_elem_sys(struct bpf_map *map, void *key, void *value, u64 flags)
{
    struct socket *sock;
    struct sock *sk;
    int ret;
    u64 ufd;

    // 获取ufd，即：socket
    if (map->value_size == sizeof(u64)) ufd = *(u64 *)value;
    else ufd = *(u32 *)value;
    if (ufd > S32_MAX) return -EINVAL;

    // 根据socket获取内核中sock
    sock = sockfd_lookup(ufd, &ret);
    if (!sock) return ret;

    // 获取sk
    sk = sock->sk;
    if (!sk) { ret = -EINVAL; goto out; }

    // 检查sk是否支持sockmap，需要设置`sk->sk_prot->psock_update_sk_prot`
    if (!sock_map_sk_is_suitable(sk)) { ret = -EOPNOTSUPP; goto out; }

    sock_map_sk_acquire(sk);
    if (!sock_map_sk_state_allowed(sk)) 
        // TCP连接时，需要处于建立连接或监听状态，其他socket默认支持
        ret = -EOPNOTSUPP;
    else if (map->map_type == BPF_MAP_TYPE_SOCKMAP)
        // sockmap更新
        ret = sock_map_update_common(map, *(u32 *)key, sk, flags);
    else
        // sockhash更新
        ret = sock_hash_update_common(map, key, sk, flags);
    sock_map_sk_release(sk);
out:
    sockfd_put(sock);
    return ret;
}
```

##### (3) `sock_map_update_common`

`sock_map_update_common` 函数实现sockmap的更新，sockmap通过数组的方式管理sock，只能支持指定数量的socket。实现如下：

```C
// file: net/core/sock_map.c
static int sock_map_update_common(struct bpf_map *map, u32 idx, struct sock *sk, u64 flags)
{
    // 将`bpf_map`转换为`bpf_stab`
    struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
    struct sk_psock_link *link;
    struct sk_psock *psock;
    struct sock *osk;
    int ret;

    WARN_ON_ONCE(!rcu_read_lock_held());
    // flags和idx检查，idx不能大于map中最大条目数
    if (unlikely(flags > BPF_EXIST)) return -EINVAL;
    if (unlikely(idx >= map->max_entries)) return -E2BIG;

    // 分配`sk_psock_link`内存空间
    link = sk_psock_init_link();
    if (!link) return -ENOMEM;
    // map关联sk
    ret = sock_map_link(map, sk);
    if (ret < 0) goto out_free;
    
    // 获取`psock` 
    psock = sk_psock(sk);
    WARN_ON_ONCE(!psock);

    raw_spin_lock_bh(&stab->lock);
    // idx的项和flags标记检查
    osk = stab->sks[idx];
    if (osk && flags == BPF_NOEXIST) { ret = -EEXIST; goto out_unlock;
    } else if (!osk && flags == BPF_EXIST) { ret = -ENOENT; goto out_unlock; }
    
    // 将psock_link添加到`psock`中
    sock_map_add_link(psock, link, map, &stab->sks[idx]);
    // idx的值设置为当前sk，并释放之前的sk
    stab->sks[idx] = sk;
    if (osk) sock_map_unref(osk, &stab->sks[idx]);
    
    raw_spin_unlock_bh(&stab->lock);
    return 0;
out_unlock:
    raw_spin_unlock_bh(&stab->lock);
    if (psock) sk_psock_put(sk, psock);
out_free:
    sk_psock_free_link(link);
    return ret;
}
```

##### (4) `sock_hash_update_common`

`sock_hash_update_common` 函数实现sockhash的更新，sockhash通过的hash方式管理sock，可以支持动态数量的socket。其实现如下：

```C
// file: net/core/sock_map.c
static int sock_hash_update_common(struct bpf_map *map, void *key, struct sock *sk, u64 flags)
{
    // 将`bpf_map`转换为`bpf_shtab`
    struct bpf_shtab *htab = container_of(map, struct bpf_shtab, map);
    u32 key_size = map->key_size, hash;
    struct bpf_shtab_elem *elem, *elem_new;
    struct bpf_shtab_bucket *bucket;
    struct sk_psock_link *link;
    struct sk_psock *psock;
    int ret;

    WARN_ON_ONCE(!rcu_read_lock_held());
    // flag标记检查
    if (unlikely(flags > BPF_EXIST)) return -EINVAL;

    // 分配`sk_psock_link`内存空间
    link = sk_psock_init_link();
    if (!link) return -ENOMEM;
    // map关联sk
    ret = sock_map_link(map, sk);
    if (ret < 0) goto out_free;

    // 获取`psock` 
    psock = sk_psock(sk);
    WARN_ON_ONCE(!psock);

    // 获取hash和bucket
    hash = sock_hash_bucket_hash(key, key_size);
    bucket = sock_hash_select_bucket(htab, hash);

    raw_spin_lock_bh(&bucket->lock);

    // 获取key对应的elem，进行flags标记检查
    elem = sock_hash_lookup_elem_raw(&bucket->head, hash, key, key_size);
    if (elem && flags == BPF_NOEXIST) { ret = -EEXIST; goto out_unlock;
    } else if (!elem && flags == BPF_EXIST) { ret = -ENOENT; goto out_unlock; }

    // 分配新的elem
    elem_new = sock_hash_alloc_elem(htab, key, key_size, hash, sk, elem);
    if (IS_ERR(elem_new)) { ret = PTR_ERR(elem_new); goto out_unlock; }

    //  将link添加到`psock`中
    sock_map_add_link(psock, link, map, elem_new);

    // 添加新的elem到bucket中
    hlist_add_head_rcu(&elem_new->node, &bucket->head);
    // 旧的elem存在时，释放
    if (elem) {
        hlist_del_rcu(&elem->node);
        sock_map_unref(elem->sk, elem);
        sock_hash_free_elem(htab, elem);
    }
    raw_spin_unlock_bh(&bucket->lock);
    return 0;
out_unlock:
    raw_spin_unlock_bh(&bucket->lock);
    sk_psock_put(sk, psock);
out_free:
    sk_psock_free_link(link);
    return ret;
}
```

#### 2 BPF程序关联sockmap的实现过程

BPF程序通过`bpf_sock_map_update` 或者 `bpf_sock_hash_update` 更新map中的 key/value 关联BPF程序。

##### (1) `bpf_sock_map_update`

`bpf_sock_map_update` 函数是BPF程序，其实现如下，获取`sock_ops`中的sk后，调用 `sock_map_update_common` 函数，如下：

```C
// file: net/core/sock_map.c
BPF_CALL_4(bpf_sock_map_update, struct bpf_sock_ops_kern *, sops,
            struct bpf_map *, map, void *, key, u64, flags)
{
    WARN_ON_ONCE(!rcu_read_lock_held());
    // 检查sk是否支持sockmap，并且ops支持sockmap
    if (likely(sock_map_sk_is_suitable(sops->sk) && sock_map_op_okay(sops)))
        return sock_map_update_common(map, *(u32 *)key, sops->sk, flags);
    return -EOPNOTSUPP;
}
```

`sock_map_op_okay`检查ops是否支持sockmap，在`PASSIVE_ESTABLISHED_CB`(被动建立连接), `ACTIVE_ESTABLISHED_CB`(主动建立连接) 和 `TCP_LISTEN_CB`(监听) 三种情况下支持sockmap，如下：

```C
// file: net/core/sock_map.c
static bool sock_map_op_okay(const struct bpf_sock_ops_kern *ops)
{
    return ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB ||
            ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
            ops->op == BPF_SOCK_OPS_TCP_LISTEN_CB;
}
```

##### (2) `bpf_sock_hash_update`

`bpf_sock_hash_update` 函数是BPF程序，其实现如下，获取`sock_ops`中的sk后，调用 `sock_hash_update_common` 函数，如下：

```C
// file: net/core/sock_map.c
BPF_CALL_4(bpf_sock_hash_update, struct bpf_sock_ops_kern *, sops,
            struct bpf_map *, map, void *, key, u64, flags)
{
    WARN_ON_ONCE(!rcu_read_lock_held());
    // 检查sk是否支持sockmap，并且ops支持sockmap
    if (likely(sock_map_sk_is_suitable(sops->sk) && sock_map_op_okay(sops)))
        return sock_hash_update_common(map, key, sops->sk, flags);
    return -EOPNOTSUPP;
}
```

#### 3 关联sockmap的实现过程

`sockmap`和`sockhash`都是调用`sock_map_link`函数实现`map`和`sk`的关联，其实现如下：

```C
// file: net/core/sock_map.c
static int sock_map_link(struct bpf_map *map, struct sock *sk)
{
    struct sk_psock_progs *progs = sock_map_progs(map);
    struct bpf_prog *stream_verdict = NULL;
    struct bpf_prog *stream_parser = NULL;
    struct bpf_prog *skb_verdict = NULL;
    struct bpf_prog *msg_parser = NULL;
    struct sk_psock *psock;
    int ret;

    // 获取并增加`progs`中引用计数
    stream_verdict = READ_ONCE(progs->stream_verdict);
    if (stream_verdict) {
        stream_verdict = bpf_prog_inc_not_zero(stream_verdict);
        if (IS_ERR(stream_verdict)) return PTR_ERR(stream_verdict);
    }
    stream_parser = READ_ONCE(progs->stream_parser);
    if (stream_parser) {
        stream_parser = bpf_prog_inc_not_zero(stream_parser);
        if (IS_ERR(stream_parser)) { ret = PTR_ERR(stream_parser); goto out_put_stream_verdict; }
    }
    msg_parser = READ_ONCE(progs->msg_parser);
    if (msg_parser) {
        msg_parser = bpf_prog_inc_not_zero(msg_parser);
        if (IS_ERR(msg_parser)) { ret = PTR_ERR(msg_parser); goto out_put_stream_parser; }
    }
    skb_verdict = READ_ONCE(progs->skb_verdict);
    if (skb_verdict) {
        skb_verdict = bpf_prog_inc_not_zero(skb_verdict);
        if (IS_ERR(skb_verdict)) { ret = PTR_ERR(skb_verdict); goto out_put_msg_parser; }
    }

    // 获取`psock` 
    psock = sock_map_psock_get_checked(sk);
    if (IS_ERR(psock)) { ret = PTR_ERR(psock); goto out_progs; }

    if (psock) {
        // psock存在时，检查psock，不能多次设置`psock_progs`
        if ((msg_parser && READ_ONCE(psock->progs.msg_parser)) ||
            (stream_parser  && READ_ONCE(psock->progs.stream_parser)) ||
            (skb_verdict && READ_ONCE(psock->progs.skb_verdict)) || 
            (skb_verdict && READ_ONCE(psock->progs.stream_verdict)) ||
            (stream_verdict && READ_ONCE(psock->progs.skb_verdict)) ||
            (stream_verdict && READ_ONCE(psock->progs.stream_verdict))) {
            sk_psock_put(sk, psock);
            ret = -EBUSY;
            goto out_progs;
        }
    } else {
        // psock不存在时，创建并初始化psock
        psock = sk_psock_init(sk, map->numa_node);
        if (IS_ERR(psock)) { ret = PTR_ERR(psock); goto out_progs; }
    }
    // 设置`psock`的`psock_progs`
    if (msg_parser) psock_set_prog(&psock->progs.msg_parser, msg_parser);
    if (stream_parser) psock_set_prog(&psock->progs.stream_parser, stream_parser);
    if (stream_verdict) psock_set_prog(&psock->progs.stream_verdict, stream_verdict);
    if (skb_verdict) psock_set_prog(&psock->progs.skb_verdict, skb_verdict);

    // 调用`.psock_update_sk_prot`接口，设置`psock`的`sk_prot`
    ret = sock_map_init_proto(sk, psock);
    if (ret < 0) { sk_psock_put(sk, psock); goto out; }

    write_lock_bh(&sk->sk_callback_lock);
    if (stream_parser && stream_verdict && !psock->saved_data_ready) {
        // `stream_parser`和`stream_verdict`同时存在时，初始化并设置`strparser`
        ret = sk_psock_init_strp(sk, psock);
        if (ret) { ... }
        sk_psock_start_strp(sk, psock);
    } else if (!stream_parser && stream_verdict && !psock->saved_data_ready) {
        // `stream_verdict`存在时，开启判决处理
        sk_psock_start_verdict(sk,psock);
    } else if (!stream_verdict && skb_verdict && !psock->saved_data_ready) {
        // `skb_verdict`存在时，开启判决处理
        sk_psock_start_verdict(sk, psock);
    }
    write_unlock_bh(&sk->sk_callback_lock);
    return 0;
    // 失败时释放BPF程序
out_progs:
    if (skb_verdict) bpf_prog_put(skb_verdict);
out_put_msg_parser:
    if (msg_parser) bpf_prog_put(msg_parser);
out_put_stream_parser:
    if (stream_parser) bpf_prog_put(stream_parser);
out_put_stream_verdict:
    if (stream_verdict) bpf_prog_put(stream_verdict);
out:
    return ret;
}
```

### 4.3 sock取消sockmap的过程

#### 1 用户空间取消sockmap的实现过程

用户空间通过`bpf_map_delete_elem`删除map中的 key/value 取消关联BPF程序。

##### (1) BPF系统调用

使用`BPF_MAP_DELETE_ELEM` BPF系统调用，如下：

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
    case BPF_MAP_DELETE_ELEM: err = map_delete_elem(&attr, uattr); break;
    ...
    }
    return err;
}
```

`map_delete_elem` 函数实现删除过程，实现如下：

```C
// file: kernel/bpf/syscall.c
static int map_delete_elem(union bpf_attr *attr, bpfptr_t uattr)
{
    bpfptr_t ukey = make_bpfptr(attr->key, uattr.is_kernel);
    int ufd = attr->map_fd;
    struct bpf_map *map;
    struct fd f;
    void *key;
    int err;

    // `ATTR`检查
    if (CHECK_ATTR(BPF_MAP_DELETE_ELEM)) return -EINVAL;

    // 根据fd获取map后，进行权限检查
    f = fdget(ufd);
    map = __bpf_map_get(f);
    if (IS_ERR(map)) return PTR_ERR(map);
    bpf_map_write_active_inc(map);
    if (!(map_get_sys_perms(map, f) & FMODE_CAN_WRITE)) { ... }

    // 复制用户空间的key
    key = ___bpf_copy_key(ukey, map->key_size);
    if (IS_ERR(key)) { err = PTR_ERR(key); goto err_put; }

    if (bpf_map_is_offloaded(map)) {
        err = bpf_map_offload_delete_elem(map, key); goto out;
    } else if (IS_FD_PROG_ARRAY(map) || map->map_type == BPF_MAP_TYPE_STRUCT_OPS) {
        // `PROG_ARRAY`和`STRUCT_OPS`类型的删除接口
        err = map->ops->map_delete_elem(map, key);
        goto out;
    }
    // 其他类型的MAP的删除过程
    bpf_disable_instrumentation();
    rcu_read_lock();
    err = map->ops->map_delete_elem(map, key);
    rcu_read_unlock();
    bpf_enable_instrumentation();
    maybe_wait_bpf_programs(map);
out:
    kvfree(key);
err_put:
    bpf_map_write_active_dec(map);
    fdput(f);
    return err;
}
```

##### (2) `sock_map_delete_elem`

`sockmap`类型的`ops`接口设置为`sock_map_ops`，其定义如下：

```C
// file: net/core/sock_map.c
const struct bpf_map_ops sock_map_ops = {
    ...
    .map_delete_elem    = sock_map_delete_elem,
    ...
};
```

`.map_delete_elem`接口设置为`sock_map_delete_elem`， 其实现如下：

```C
// file: net/core/sock_map.c
static long sock_map_delete_elem(struct bpf_map *map, void *key)
{
    struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
    u32 i = *(u32 *)key;
    struct sock **psk;
    // 检查key是否超过map限制
    if (unlikely(i >= map->max_entries)) return -EINVAL;
    
    // 获取key对应的psock后，删除
    psk = &stab->sks[i];
    return __sock_map_delete(stab, NULL, psk);
}
```

`__sock_map_delete`函数删除sockmap关联的psock，如下：

```C
static int __sock_map_delete(struct bpf_stab *stab, struct sock *sk_test, struct sock **psk)
{
    struct sock *sk;
    int err = 0;

    raw_spin_lock_bh(&stab->lock);
    sk = *psk;
    // sk_tesk为NULL或者当前sk时，设置psk为NULL
    if (!sk_test || sk_test == sk)
        sk = xchg(psk, NULL);
    // sk存在时，释放sk
    if (likely(sk))
        sock_map_unref(sk, psk);
    else
        err = -EINVAL;

    raw_spin_unlock_bh(&stab->lock);
    return err;
}
```

##### (3) `sock_hash_delete_elem`

`sockhash`类型的`ops`接口设置为`sock_hash_ops`，其定义如下：

```C
// file: net/core/sock_map.c
const struct bpf_map_ops sock_hash_ops = {
    ...
    .map_delete_elem    = sock_hash_delete_elem,
    ...
};
```

`.map_delete_elem`接口设置为`sock_hash_delete_elem`， 其实现如下：

```C
// file: net/core/sock_map.c
static long sock_hash_delete_elem(struct bpf_map *map, void *key)
{
    struct bpf_shtab *htab = container_of(map, struct bpf_shtab, map);
    u32 hash, key_size = map->key_size;
    struct bpf_shtab_bucket *bucket;
    struct bpf_shtab_elem *elem;
    int ret = -ENOENT;

    // 根据key计算`hash`和`bucket`
    hash = sock_hash_bucket_hash(key, key_size);
    bucket = sock_hash_select_bucket(htab, hash);

    raw_spin_lock_bh(&bucket->lock);
    // 从bucket中获取指定的elem
    elem = sock_hash_lookup_elem_raw(&bucket->head, hash, key, key_size);
    if (elem) {
        hlist_del_rcu(&elem->node);
        // 释放`sk`和`elem`
        sock_map_unref(elem->sk, elem);
        sock_hash_free_elem(htab, elem);
        ret = 0;
    }
    raw_spin_unlock_bh(&bucket->lock);
    return ret;
}
```

#### 2 取消关联sockmap的实现过程

`sock_map_unref`函数实现psock取消关联sockmap，其实现如下：

```C
// file: net/core/sock_map.c
static void sock_map_unref(struct sock *sk, void *link_raw)
{
    struct sk_psock *psock = sk_psock(sk);
    if (likely(psock)) {
        // sockmap删除link
        sock_map_del_link(sk, psock, link_raw);
        // 释放psock
        sk_psock_put(sk, psock);
    }
}
```

##### (1) `sock_map_del_link`

`sock_map_del_link`函数实现sockmap删除link，如下：

```C
// file: net/core/sock_map.c
static void sock_map_del_link(struct sock *sk, struct sk_psock *psock, void *link_raw)
{
    bool strp_stop = false, verdict_stop = false;
    struct sk_psock_link *link, *tmp;

    spin_lock_bh(&psock->link_lock);
    // 遍历psock的link列表
    list_for_each_entry_safe(link, tmp, &psock->link, list) {
        if (link->link_raw == link_raw) {
            // 当前查找的link
            struct bpf_map *map = link->map;
            struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
            // 检查`strp_stop`和`verdict_stop`的情况
            if (psock->saved_data_ready && stab->progs.stream_parser)
                strp_stop = true;
            if (psock->saved_data_ready && stab->progs.stream_verdict)
                verdict_stop = true;
            if (psock->saved_data_ready && stab->progs.skb_verdict)
                verdict_stop = true;
            // 删除和释放link
            list_del(&link->list);
            sk_psock_free_link(link);
        }
    }
    spin_unlock_bh(&psock->link_lock);
    if (strp_stop || verdict_stop) {
        write_lock_bh(&sk->sk_callback_lock);
        // 根据`strp_stop`和`verdict_stop`，停止`strparser`和`verdict`
        if (strp_stop) sk_psock_stop_strp(sk, psock);
        if (verdict_stop) sk_psock_stop_verdict(sk, psock);
        
        // 重新调用`.psock_update_sk_prot`接口，设置`psock`的`sk_prot`
        if (psock->psock_update_sk_prot) psock->psock_update_sk_prot(sk, psock, false);
        write_unlock_bh(&sk->sk_callback_lock);
    }
}
```

##### (2) `sk_psock_put`

`sk_psock_put`函数释放psock，其实现如下：

```C
// file: include/linux/skmsg.h
static inline void sk_psock_put(struct sock *sk, struct sk_psock *psock)
{  
    // 减少引用计数，计数为0时，释放psock
    if (refcount_dec_and_test(&psock->refcnt)) sk_psock_drop(sk, psock);
}
```

`sk_psock_drop`函数释放psock，释放psock的资源，如下：

```C
// file: net/core/skmsg.c
void sk_psock_drop(struct sock *sk, struct sk_psock *psock)
{
    write_lock_bh(&sk->sk_callback_lock);
    sk_psock_restore_proto(sk, psock);
    rcu_assign_sk_user_data(sk, NULL);
    if (psock->progs.stream_parser)
        // 存在`stream_parser`时，停止`strparser`
        sk_psock_stop_strp(sk, psock);
    else if (psock->progs.stream_verdict || psock->progs.skb_verdict)
        // 存在`stream_verdict/skb_verdict`时，停止`verdict`
        sk_psock_stop_verdict(sk, psock);
    write_unlock_bh(&sk->sk_callback_lock);
    // 停止`psock`
    sk_psock_stop(psock);
    // 设置psock的工作队列为清理操作
    INIT_RCU_WORK(&psock->rwork, sk_psock_destroy);
    queue_rcu_work(system_wq, &psock->rwork);
}
```

`sk_psock_destroy`函数进行psock的销毁工作，如下：

```C
// file: net/core/skmsg.c
static void sk_psock_destroy(struct work_struct *work)
{
    struct sk_psock *psock = container_of(to_rcu_work(work), struct sk_psock, rwork);
    // 清理`strparser`
    sk_psock_done_strp(psock);

    // 取消工作队列
    cancel_delayed_work_sync(&psock->work);
    // 释放`psock`接收队列的`ingress_skb`和`ingress_msg`
    __sk_psock_zap_ingress(psock);
    mutex_destroy(&psock->work_mutex);
    
    // 清理`psock_progs`
    psock_progs_drop(&psock->progs);
    // 销毁`psock`的link队列
    sk_psock_link_destroy(psock);
    // 释放cork
    sk_psock_cork_free(psock);

    // 存在重定向的sk时，释放
    if (psock->sk_redir) sock_put(psock->sk_redir);
    // 释放psock和sk
    sock_put(psock->sk);
    kfree(psock);
}
```

`sk_psock_done_strp` 函数完成`strparser`的清理工作，实现如下：

```C
// file: net/core/skmsg.c
static void sk_psock_done_strp(struct sk_psock *psock)
{
    // 存在`stream_parser`程序时，清理
    if (psock->progs.stream_parser)
        strp_done(&psock->strp);
}
```

`strp_done`函数完成最终的清理工作，如下：

```C
// file: net/core/skmsg.c
void strp_done(struct strparser *strp)
{
    WARN_ON(!strp->stopped);
    // 取消工作队列
    cancel_delayed_work_sync(&strp->msg_timer_work);
    cancel_work_sync(&strp->work);
    // 释放`skb_head`
    if (strp->skb_head) {
        kfree_skb(strp->skb_head);
        strp->skb_head = NULL;
    }
}
```

### 4.4 sockmap触发BPF程序的过程

#### 1 psock的初始化和关闭

##### (1) 初始化psock

在`sock_map_link`函数中进行sockmap的关联，其中首先初始化psock，`sk_psock_init`函数完成该项功能，其实现如下：

```C
// file: net/core/skmsg.c
struct sk_psock *sk_psock_init(struct sock *sk, int node)
{
    struct sk_psock *psock;
    struct proto *prot;

    write_lock_bh(&sk->sk_callback_lock);

    // IPV4/IPV6协议的sock，设置ulp_ops时，不能关联sockmap
    if (sk_is_inet(sk) && inet_csk_has_ulp(sk)) { psock = ERR_PTR(-EINVAL); goto out; }
    // 设置用户数据时，不能关联sockmap
    if (sk->sk_user_data) { psock = ERR_PTR(-EBUSY); goto out; }
    // 分配psock的内存空间
    psock = kzalloc_node(sizeof(*psock), GFP_ATOMIC | __GFP_NOWARN, node);
    if (!psock) { psock = ERR_PTR(-ENOMEM); goto out; }

    // 设置psock的相关属性
    prot = READ_ONCE(sk->sk_prot);
    psock->sk = sk;
    psock->eval = __SK_NONE;
    psock->sk_proto = prot;
    // 保存`unhash`，`destory`、`close`、`sk_write_space`接口
    psock->saved_unhash = prot->unhash;
    psock->saved_destroy = prot->destroy;
    psock->saved_close = prot->close;
    psock->saved_write_space = sk->sk_write_space;
    // 初始化link队列
    INIT_LIST_HEAD(&psock->link);
    spin_lock_init(&psock->link_lock);
    // 初始化工作队列、接收消息、接收skb队列
    INIT_DELAYED_WORK(&psock->work, sk_psock_backlog);
    mutex_init(&psock->work_mutex);
    INIT_LIST_HEAD(&psock->ingress_msg);
    spin_lock_init(&psock->ingress_lock);
    skb_queue_head_init(&psock->ingress_skb);
    // 设置psock状态和引用计数
    sk_psock_set_state(psock, SK_PSOCK_TX_ENABLED);
    refcount_set(&psock->refcnt, 1);

    __rcu_assign_sk_user_data_with_flags(sk, psock, 
                SK_USER_DATA_NOCOPY | SK_USER_DATA_PSOCK);
    sock_hold(sk);

out:
    write_unlock_bh(&sk->sk_callback_lock);
    return psock;
}
```

##### (2) 初始化`proto`接口

在创建psock之后，接下来初始化`proto`，`sock_map_init_proto`函数完成该项工作，实现如下：

```C
// file: net/core/sock_map.c
static int sock_map_init_proto(struct sock *sk, struct sk_psock *psock)
{
    // `sk_prot`必须支持`.psock_update_sk_prot`接口
    if (!sk->sk_prot->psock_update_sk_prot) return -EINVAL;
    // 调用`.psock_update_sk_prot`接口
    psock->psock_update_sk_prot = sk->sk_prot->psock_update_sk_prot;
    return sk->sk_prot->psock_update_sk_prot(sk, psock, false);
}
```

`.psock_update_sk_prot`接口替换`sk->sk_prot`接口，修改`.destroy`,`.close`,`.recvmsg`,`.sendmsg`等接口。

* UDP协议更新`proto`接口

IPV4和IPV6的UDP协议`.psock_update_sk_prot`接口设置为`udp_bpf_update_proto`，如下：

```C
// file: net/ipv4/udp.c
struct proto udp_prot = {
    .name   = "UDP",
#ifdef CONFIG_BPF_SYSCALL
    .psock_update_sk_prot   = udp_bpf_update_proto,
#endif
    ...
};

// file: net/ipv4/udp.c
struct proto udpv6_prot = {
    .name   = "UDPv6",
#ifdef CONFIG_BPF_SYSCALL
    .psock_update_sk_prot   = udp_bpf_update_proto,
#endif
    ...
};
```

其实现如下：

```C
// file: net/ipv4/udp_bpf.c
int udp_bpf_update_proto(struct sock *sk, struct sk_psock *psock, bool restore)
{
    int family = sk->sk_family == AF_INET ? UDP_BPF_IPV4 : UDP_BPF_IPV6;
    // 恢复时设置sk为之前的状态
    if (restore) {
        sk->sk_write_space = psock->saved_write_space;
        sock_replace_proto(sk, psock->sk_proto);
        return 0;
    }
    // IPV6协议时，必要时重新构建协议
    if (sk->sk_family == AF_INET6)
        udp_bpf_check_v6_needs_rebuild(psock->sk_proto);
    // 替换`sk-sk_prot`
    sock_replace_proto(sk, &udp_bpf_prots[family]);
    return 0;
}
```

`udp_bpf_prots`是个数组，包含两个元素，如下：

```C
// file: net/ipv4/udp_bpf.c
enum {
    UDP_BPF_IPV4,
    UDP_BPF_IPV6,
    UDP_BPF_NUM_PROTS,
};
static struct proto udp_bpf_prots[UDP_BPF_NUM_PROTS];
```

IPV4的UDP_BPF操作接口在`initcall`阶段初始化，如下：

```C
// file: net/ipv4/udp_bpf.c
static int __init udp_bpf_v4_build_proto(void)
{
    udp_bpf_rebuild_protos(&udp_bpf_prots[UDP_BPF_IPV4], &udp_prot);
    return 0;
}
late_initcall(udp_bpf_v4_build_proto);
```

`udp_bpf_rebuild_protos`函数构建udp_bpf协议，如下：

```C
// file: net/ipv4/udp_bpf.c
static void udp_bpf_rebuild_protos(struct proto *prot, const struct proto *base)
{
    *prot        = *base;
    prot->close  = sock_map_close;
    prot->recvmsg = udp_bpf_recvmsg;
    prot->sock_is_readable = sk_msg_is_readable;
}
```

即设置`.close`，`.recvmsg`，`.sock_is_readable`接口。

* TCP协议更新`proto`接口

IPV4和IPV6的TCP协议`.psock_update_sk_prot`接口设置为`tcp_bpf_update_proto`，如下：

```C
// file: net/ipv4/tcp_ipv4.c
struct proto tcp_prot = {
    .name = "TCP",
#ifdef CONFIG_BPF_SYSCALL
    .psock_update_sk_prot = tcp_bpf_update_proto,
#endif
    ...
};

// file: net/ipv6/tcp_ipv6.c
struct proto tcpv6_prot = {
    .name = "TCPv6",
#ifdef CONFIG_BPF_SYSCALL
    .psock_update_sk_prot = tcp_bpf_update_proto,
#endif
    ...
};
```

其实现如下：

```C
// file: net/ipv4/tcp_bpf.c
int tcp_bpf_update_proto(struct sock *sk, struct sk_psock *psock, bool restore)
{
    int family = sk->sk_family == AF_INET6 ? TCP_BPF_IPV6 : TCP_BPF_IPV4;
    // config根据`progs`的不同分为`BASE`,`RX`,`TX`,`TXRX`四种情况
    int config = psock->progs.msg_parser   ? TCP_BPF_TX   : TCP_BPF_BASE;
    if (psock->progs.stream_verdict || psock->progs.skb_verdict) {
        config = (config == TCP_BPF_TX) ? TCP_BPF_TXRX : TCP_BPF_RX;
    }

    if (restore) {
        // 恢复时，根据`ulp`的设置进行不同的恢复过程
        if (inet_csk_has_ulp(sk)) {
            WRITE_ONCE(sk->sk_prot->unhash, psock->saved_unhash);
            tcp_update_ulp(sk, psock->sk_proto, psock->saved_write_space);
        } else {
            sk->sk_write_space = psock->saved_write_space;
            sock_replace_proto(sk, psock->sk_proto);
        }
        return 0;
    }
    // IPV6协议时，必要时重新构建协议
    if (sk->sk_family == AF_INET6) {
        if (tcp_bpf_assert_proto_ops(psock->sk_proto)) return -EINVAL;
        tcp_bpf_check_v6_needs_rebuild(psock->sk_proto);
    }
    // 替换`sk-sk_prot`
    sock_replace_proto(sk, &tcp_bpf_prots[family][config]);
    return 0;
}
```

`tcp_bpf_prots`是个二维数组，如下：

```C
// file: net/ipv4/tcp_bpf.c
enum {
    TCP_BPF_IPV4,
    TCP_BPF_IPV6,
    TCP_BPF_NUM_PROTS,
};
enum {
    TCP_BPF_BASE,
    TCP_BPF_TX,
    TCP_BPF_RX,
    TCP_BPF_TXRX,
    TCP_BPF_NUM_CFGS,
};
static struct proto tcp_bpf_prots[TCP_BPF_NUM_PROTS][TCP_BPF_NUM_CFGS];
```

IPV4的TCP_BPF操作接口在`initcall`阶段初始化，如下：

```C
// file: net/ipv4/tcp_bpf.c
static int __init tcp_bpf_v4_build_proto(void)
{
    tcp_bpf_rebuild_protos(tcp_bpf_prots[TCP_BPF_IPV4], &tcp_prot);
    return 0;
}
late_initcall(tcp_bpf_v4_build_proto);
```

`tcp_bpf_rebuild_protos`函数构建tcp_bpf协议，如下：

```C
// file: net/ipv4/tcp_bpf.c
static void tcp_bpf_rebuild_protos(struct proto prot[TCP_BPF_NUM_CFGS], struct proto *base)
{
    // BASE设置
    prot[TCP_BPF_BASE]              = *base;
    prot[TCP_BPF_BASE].destroy      = sock_map_destroy;
    prot[TCP_BPF_BASE].close        = sock_map_close;
    prot[TCP_BPF_BASE].recvmsg      = tcp_bpf_recvmsg;
    prot[TCP_BPF_BASE].sock_is_readable	= sk_msg_is_readable;

    // TX设置，在BASE基础上设置
    prot[TCP_BPF_TX]                = prot[TCP_BPF_BASE];
    prot[TCP_BPF_TX].sendmsg        = tcp_bpf_sendmsg;
    prot[TCP_BPF_TX].sendpage       = tcp_bpf_sendpage;

    // RX设置，在BASE基础上设置
    prot[TCP_BPF_RX]                = prot[TCP_BPF_BASE];
    prot[TCP_BPF_RX].recvmsg        = tcp_bpf_recvmsg_parser;

    // TXRX设置，在TX基础上设置
    prot[TCP_BPF_TXRX]              = prot[TCP_BPF_TX];
    prot[TCP_BPF_TXRX].recvmsg      = tcp_bpf_recvmsg_parser;
}
```

##### (3) 关闭psock

在用户空间关闭socket时，`.close`接口替换为`sock_map_close`，其实现如下：

```C
// file: net/core/sock_map.c
void sock_map_close(struct sock *sk, long timeout)
{
    void (*saved_close)(struct sock *sk, long timeout);
    struct sk_psock *psock;

    lock_sock(sk);
    rcu_read_lock();
    psock = sk_psock_get(sk);
    if (unlikely(!psock)) {
        // psock不存在时，使用`sk`的close接口
        rcu_read_unlock();
        release_sock(sk);
        saved_close = READ_ONCE(sk->sk_prot)->close;
    } else {
        saved_close = psock->saved_close;
        // 释放link信息
        sock_map_remove_links(sk, psock);
        rcu_read_unlock();
        // 停止`psock`
        sk_psock_stop(psock);
        release_sock(sk);
        // 取消`psock`的工作队列
        cancel_delayed_work_sync(&psock->work);
        sk_psock_put(sk, psock);
    }
    // 确保不会递归调用
    if (WARN_ON_ONCE(saved_close == sock_map_close)) 
        return;
    // 调用保存的`.close`接口
    saved_close(sk, timeout);
}
```

`sock_map_remove_links`函数释放psock关联的link列表，实现如下：

```C
// file: net/core/sock_map.c
static void sock_map_remove_links(struct sock *sk, struct sk_psock *psock)
{
    struct sk_psock_link *link;
    
    while ((link = sk_psock_link_pop(psock))) {
        // 取消link关联后释放
        sock_map_unlink(sk, link);
        sk_psock_free_link(link);
    }
}
```

#### 2 `strparser`的实现过程

##### (1) 开启过程

在`stream_parser`和`stream_verdict`都设置的情况下，即`strparser`模式，需要初始化后开始。实现如下：

```C
// file: net/core/sock_map.c
static int sock_map_link(struct bpf_map *map, struct sock *sk)
{
    ...
    if (stream_parser && stream_verdict && !psock->saved_data_ready) {
        ret = sk_psock_init_strp(sk, psock);
        if (ret) { ... }
        sk_psock_start_strp(sk, psock);
    }
    ...
}
```

`sk_psock_init_strp`函数初始化`strparser`，设置回调设置后进行初始化，其实现如下：

```C
// file: net/core/sock_map.c
int sk_psock_init_strp(struct sock *sk, struct sk_psock *psock)
{
    static const struct strp_callbacks cb = {
        .rcv_msg = sk_psock_strp_read,
        .read_sock_done = sk_psock_strp_read_done,
        .parse_msg  = sk_psock_strp_parse,
    };
    return strp_init(&psock->strp, sk, &cb);
}
```

`strp_init`函数初始化`strparser`，设置回调相关设置，其实现如下：

```C
// file: net/strparser/strparser.c
int strp_init(struct strparser *strp, struct sock *sk, const struct strp_callbacks *cb)
{
    // 检查必要的设置
    if (!cb || !cb->rcv_msg || !cb->parse_msg) return -EINVAL;

    // sk参数决定了`stream parser`的工作模式。
    // sk设置的情况下，`strparser`进入接收回调模式，上层接口调用`.strp_data_ready`接口处理接收过程；
    // sk未设置的情况下，`strparser`进入通用模式，上层接口调用`strp_process`接口处理每个接收的skb；
    if (!sk) { if (!cb->lock || !cb->unlock) return -EINVAL; }

    memset(strp, 0, sizeof(*strp));
    // 设置`strp`相关属性
    strp->sk = sk;
    strp->cb.lock = cb->lock ? : strp_sock_lock;
    strp->cb.unlock = cb->unlock ? : strp_sock_unlock;
    strp->cb.rcv_msg = cb->rcv_msg;
    strp->cb.parse_msg = cb->parse_msg;
    strp->cb.read_sock_done = cb->read_sock_done ? : default_read_sock_done;
    strp->cb.abort_parser = cb->abort_parser ? : strp_abort_strp;

    // 初始化工作队列
    INIT_DELAYED_WORK(&strp->msg_timer_work, strp_msg_timeout);
    INIT_WORK(&strp->work, strp_work);

	return 0;
}
```

`sk_psock_start_strp`函数开启`strparser`, 修改`.sk_data_ready`和`.sk_write_space`接口，其实现如下：

```C
// file: net/core/skmsg.c
void sk_psock_start_strp(struct sock *sk, struct sk_psock *psock)
{
    if (psock->saved_data_ready) return;
    // 保存sk的`.saved_data_ready`接口
    psock->saved_data_ready = sk->sk_data_ready;
    // 修改sk的`.saved_data_ready`接口
    sk->sk_data_ready = sk_psock_strp_data_ready;
    sk->sk_write_space = sk_psock_write_space;
}
```

##### (2) 数据接收过程

在socket接收数据后会触发`.sk_data_ready`接口，`strparser`设置为`sk_psock_strp_data_ready`，其实现如下：

```C
// file: net/core/skmsg.c
static void sk_psock_strp_data_ready(struct sock *sk)
{
    struct sk_psock *psock;

    trace_sk_data_ready(sk);

    rcu_read_lock();
    psock = sk_psock(sk);
    if (likely(psock)) {
        if (tls_sw_has_ctx_rx(sk)) {
            // tls存在时，调用保存的接口，即sk之前的接口
            psock->saved_data_ready(sk);
        } else {
            write_lock_bh(&sk->sk_callback_lock);
            // 调用`strp_data_ready`接口
            strp_data_ready(&psock->strp);
            write_unlock_bh(&sk->sk_callback_lock);
        }
    }
    rcu_read_unlock();
}
```

`strp_data_ready`函数处理接收的数据，如下：

```C
// file: net/strparser/strparser.c
void strp_data_ready(struct strparser *strp)
{
    // 停止或暂停时返回
    if (unlikely(strp->stopped) || strp->paused) return;

    // 同步工作队列，sk被用户空间占用时，开启工作队列
    if (sock_owned_by_user_nocheck(strp->sk)) {
        queue_work(strp_wq, &strp->work);
        return;
    }
    // 检查是否满足最小长度
    if (strp->need_bytes) {
        if (strp_peek_len(strp) < strp->need_bytes) return;
    }
    // 读取sock，内存不足时，开启工作队列
    if (strp_read_sock(strp) == -ENOMEM)
        queue_work(strp_wq, &strp->work);
}
```

`strp->work`设置为`strp_work`，其实现如下：

```C
// file: net/strparser/strparser.c
static void strp_work(struct work_struct *w)
{
    do_strp_work(container_of(w, struct strparser, work));
}
```

`do_strp_work`函数为工作队列设置的操作接口，如下：

```C
// file: net/strparser/strparser.c
static void do_strp_work(struct strparser *strp)
{
    strp->cb.lock(strp);

    // 停止或暂停时退出
    if (unlikely(strp->stopped)) goto out;
    if (strp->paused) goto out;
    // 读取sock数据
    if (strp_read_sock(strp) == -ENOMEM)
        queue_work(strp_wq, &strp->work);

out:
    strp->cb.unlock(strp);
}
```

##### (3) 读取数据过程

`strparser`通过直接调用或工作队列读取数据，`strp_read_sock`完成该项工作，如下：

```C
// file: net/strparser/strparser.c
static int strp_read_sock(struct strparser *strp)
{
    struct socket *sock = strp->sk->sk_socket;
    read_descriptor_t desc;
    // sock不存在或接口不满足时返回
    if (unlikely(!sock || !sock->ops || !sock->ops->read_sock)) return -EBUSY;

    // 设置读取描述信息
    desc.arg.data = strp;
    desc.error = 0;
    desc.count = 1; /* give more than one skb per call */

    // 调用`.read_sock`接口
    sock->ops->read_sock(strp->sk, &desc, strp_recv);
    // 调用`.read_sock_done`接口，检查是否完成读取
    desc.error = strp->cb.read_sock_done(strp, desc.error);
    return desc.error;
}
```

`sock->ops->read_sock`接口只支持TCP协议，设置为`tcp_read_sock`，实现如下：

```C
// file: net/ipv4/tcp.c
int tcp_read_sock(struct sock *sk, read_descriptor_t *desc, sk_read_actor_t recv_actor)
{
    struct sk_buff *skb;
    ...
    // 不支持LISTEN状态
    if (sk->sk_state == TCP_LISTEN) return -ENOTCONN;

    while ((skb = tcp_recv_skb(sk, seq, &offset)) != NULL) {
        if (offset < skb->len) {
            ...
            // 调用`.recv_actor`接口
            used = recv_actor(desc, skb, offset, len);
            ...
        }
        ...
    }
    ...
    return copied;
}
```

`.recv_actor`设置为`strp_recv`，其实现如下：

```C
// file: net/strparser/strparser.c
static int strp_recv(read_descriptor_t *desc, struct sk_buff *orig_skb,
            unsigned int orig_offset, size_t orig_len)
{
    struct strparser *strp = (struct strparser *)desc->arg.data;
    return __strp_recv(desc, orig_skb, orig_offset, orig_len, strp->sk->sk_rcvbuf, strp->sk->sk_rcvtimeo);
}
```

`__strp_recv`函数完成具体的接收工作，其实现如下：

```C
// file: net/strparser/strparser.c
static int __strp_recv(read_descriptor_t *desc, struct sk_buff *orig_skb,
            unsigned int orig_offset, size_t orig_len, size_t max_msg_size, long timeo)
{
    struct strparser *strp = (struct strparser *)desc->arg.data;
    struct _strp_msg *stm;
    struct sk_buff *head, *skb;
    ...
    bool cloned_orig = false;

    // 暂停时返回
    if (strp->paused) return 0;
    // 处理`strparser`头信息，确定数据开始位置
    head = strp->skb_head;
    if (head) { ...  }

    while (eaten < orig_len) {
        ...
        // 确定开始处理的skb
        head = strp->skb_head;
        if (!head) { ... }
        
        // 不是完整消息时，确定长度
        if (!stm->strp.full_len) {
            ssize_t len;
            // 调用`.parse_msg`接口确定`skb`的长度
            len = (*strp->cb.parse_msg)(strp, head);
            ...
        }
        extra = (ssize_t)(stm->accum_len + cand_len) - stm->strp.full_len;
        // 消息不完整时处理过程
        if (extra < 0) { ... }

        // 获取到一个完整消息时的处理过程
        ...

        // 将skb发送到上层处理
        strp->cb.rcv_msg(strp, head);
        
        // 上层处理暂停`strp`时退出处理
        if (unlikely(strp->paused)) { break; }
    }
    if (cloned_orig) kfree_skb(orig_skb);
    // 增加统计信息
    STRP_STATS_ADD(strp->stats.bytes, eaten);
    return eaten;
}
```

##### (4) 解析消息的过程

在读取数据过程中，通过`.parse_msg`确定skb的长度，`strparser`将该接口设置为`sk_psock_strp_parse`，其实现如下：

```C
// file: net/core/skmsg.c
static int sk_psock_strp_parse(struct strparser *strp, struct sk_buff *skb)
{
    struct sk_psock *psock = container_of(strp, struct sk_psock, strp);
    struct bpf_prog *prog;
    int ret = skb->len;

    rcu_read_lock();
    // 执行设置的`stream_parser`BPF程序
    prog = READ_ONCE(psock->progs.stream_parser);
    if (likely(prog)) {
        skb->sk = psock->sk;
        ret = bpf_prog_run_pin_on_cpu(prog, skb);
        skb->sk = NULL;
    }
    rcu_read_unlock();
    return ret;
}
```

##### (5) 接收SKB的过程

在读取数据过程中，通过`.rcv_msg`将skb传递到上层进行处理，`strparser`将该接口设置为`sk_psock_strp_read`，其实现如下：

```C
// file: net/core/skmsg.c
static void sk_psock_strp_read(struct strparser *strp, struct sk_buff *skb)
{
    struct sk_psock *psock;
    struct bpf_prog *prog;
    int ret = __SK_DROP;
    struct sock *sk;

    rcu_read_lock();
    sk = strp->sk;
    psock = sk_psock(sk);

    // psock不存在时，丢弃skb
    if (unlikely(!psock)) { sock_drop(sk, skb); goto out; }
	
    // 执行设置的`stream_verdict`BPF程序
    prog = READ_ONCE(psock->progs.stream_verdict);
    if (likely(prog)) {
        // 运行BPF程序前，清除skb的路由和重定向信息
        skb->sk = sk;
        skb_dst_drop(skb);
        skb_bpf_redirect_clear(skb);
        // 运行BPF程序
        ret = bpf_prog_run_pin_on_cpu(prog, skb);
        skb_bpf_set_strparser(skb);
        // 确定判决结果
        ret = sk_psock_map_verd(ret, skb_bpf_redirect_fetch(skb));
        skb->sk = NULL;
    }
    // 执行判决处理
    sk_psock_verdict_apply(psock, skb, ret);
out:
    rcu_read_unlock();
}
```

##### (6) 停止过程

在sockmap或sockhash删除socket时，停止`strparser`，`sk_psock_stop_strp`函数完成该项工作，如下：

```C
// file: net/core/skmsg.c
void sk_psock_stop_strp(struct sock *sk, struct sk_psock *psock)
{
    // 将`stream_parser`程序置空
    psock_set_prog(&psock->progs.stream_parser, NULL);
    
    if (!psock->saved_data_ready) return;
    // 恢复`.sk_data_ready`接口
    sk->sk_data_ready = psock->saved_data_ready;
    psock->saved_data_ready = NULL;
    // 停止`strparser`
    strp_stop(&psock->strp);
}
```

`strp_stop`函数设置停止状态，如下：

```C
// file: net/core/skmsg.c
void strp_stop(struct strparser *strp)
{
    strp->stopped = 1;
}
```

#### 3 `verdict`的实现过程

##### (1) 开启过程

在没有设置`stream_parser`，但设置`stream_verdict`或`skb_verdict`的情况下，即`verdict`模式。`sk_psock_start_verdict` 函数开启`verdict`模式，实现如下：

```C
// file: net/core/skmsg.c
void sk_psock_start_verdict(struct sock *sk, struct sk_psock *psock)
{
    if (psock->saved_data_ready) return;
    
    // 保存sk的`.saved_data_ready`接口
    psock->saved_data_ready = sk->sk_data_ready;
    // 修改sk的`.saved_data_ready`接口
    sk->sk_data_ready = sk_psock_verdict_data_ready;
    sk->sk_write_space = sk_psock_write_space;
}
```

##### (2) 数据接收过程

在socket接收数据后会触发`.sk_data_ready`接口，`verdict`模式设置为`sk_psock_verdict_data_ready`，其实现如下：

```C
// file: net/core/skmsg.c
static void sk_psock_verdict_data_ready(struct sock *sk)
{
    struct socket *sock = sk->sk_socket;
    int copied;

    trace_sk_data_ready(sk);

    // sock不存在或接口不满足时返回
    if (unlikely(!sock || !sock->ops || !sock->ops->read_skb)) return;
    // 调用`.read_skb`接口读取数据
    copied = sock->ops->read_skb(sk, sk_psock_verdict_recv);
    if (copied >= 0) {
        struct sk_psock *psock;
        
        rcu_read_lock();
        psock = sk_psock(sk);
        // 唤醒sock
        psock->saved_data_ready(sk);
        rcu_read_unlock();
    }
}
```

`sock->ops->read_skb`接口支持TCP/UDP协议，以UDP为例，设置为`udp_read_skb`，实现如下：

```C
// file: net/ipv4/udp.c
int udp_read_skb(struct sock *sk, skb_read_actor_t recv_actor)
{
    struct sk_buff *skb;
    int err;

try_again:
    // 读取skb
    skb = skb_recv_udp(sk, MSG_DONTWAIT, &err);
    if (!skb) return err;
    // 校验和不正确时，更新统计信息后，重新获取skb
    if (udp_lib_checksum_complete(skb)) {
        int is_udplite = IS_UDPLITE(sk);
        struct net *net = sock_net(sk);

        __UDP_INC_STATS(net, UDP_MIB_CSUMERRORS, is_udplite);
        __UDP_INC_STATS(net, UDP_MIB_INERRORS, is_udplite);
        atomic_inc(&sk->sk_drops);
        kfree_skb(skb);
        goto try_again;
    }
    WARN_ON_ONCE(!skb_set_owner_sk_safe(skb, sk));
    // 调用`.recv_actor`接口
    return recv_actor(sk, skb);
}
```

##### (2) skb的处理过程

`.recv_actor`设置为`sk_psock_verdict_recv`，其实现如下：

```C
// file: net/core/skmsg.c
static int sk_psock_verdict_recv(struct sock *sk, struct sk_buff *skb)
{
    struct sk_psock *psock;
    struct bpf_prog *prog;
    int ret = __SK_DROP;
    int len = skb->len;

    rcu_read_lock();
    // psock不存在时，丢弃skb
    psock = sk_psock(sk);
    if (unlikely(!psock)) {
        len = 0;
        tcp_eat_skb(sk, skb);
        sock_drop(sk, skb);
        goto out;
    }
    // 获取`stream_verdict`或`skb_verdict` BPF程序
    prog = READ_ONCE(psock->progs.stream_verdict);
    if (!prog) prog = READ_ONCE(psock->progs.skb_verdict);
    if (likely(prog)) {
        // 运行BPF程序前，清除skb的路由和重定向信息
        skb_dst_drop(skb);
        skb_bpf_redirect_clear(skb);
        // 运行BPF程序
        ret = bpf_prog_run_pin_on_cpu(prog, skb);
        // 确定判决结果
        ret = sk_psock_map_verd(ret, skb_bpf_redirect_fetch(skb));
    }
    // 执行判决处理
    ret = sk_psock_verdict_apply(psock, skb, ret);
    if (ret < 0) len = ret;
out:
    rcu_read_unlock();
    return len;
}
```

##### (3) 停止过程

在sockmap或sockhash删除socket时，停止`verdict`，`sk_psock_stop_verdict`函数完成该项工作，如下：

```C
// file: net/core/skmsg.c
void sk_psock_stop_verdict(struct sock *sk, struct sk_psock *psock)
{
    // 将`stream_verdict`和`skb_verdict`程序置空
    psock_set_prog(&psock->progs.stream_verdict, NULL);
    psock_set_prog(&psock->progs.skb_verdict, NULL);

    if (!psock->saved_data_ready) return;

    // 恢复`.sk_data_ready`接口
    sk->sk_data_ready = psock->saved_data_ready;
    psock->saved_data_ready = NULL;
}
```

#### 4 INGRESS路径的判决过程

##### (1) 处理框架

`strparser`和`verdict`模式在运行`verdict`类型的BPF程序后，`sk_psock_map_verd`函数将BPF程序的执行结果转换为对应的类型后，调用`sk_psock_verdict_apply` 函数进行判决处理，如下：

```C
// file: net/core/skmsg.c
static int sk_psock_map_verd(int verdict, bool redir)
{
    switch (verdict) {
    case SK_PASS:
        // 重定向或通过
        return redir ? __SK_REDIRECT : __SK_PASS;
    case SK_DROP:
    default:
        break;
    }
    // 默认丢弃
    return __SK_DROP;
}
```

`sk_psock_verdict_apply`函数根据上述结果进行对应处理，如下：

```C
// file: net/core/skmsg.c
static int sk_psock_verdict_apply(struct sk_psock *psock, struct sk_buff *skb, int verdict)
{
    struct sock *sk_other;
    int err = 0;
    u32 len, off;

    switch (verdict) {
    case __SK_PASS: // PASS情形
        ... 
        break;
    case __SK_REDIRECT: // 重定向类型
        ... 
        break;
    case __SK_DROP: // 错误、丢弃、其他情况
    default:
out_free:
        ... 
    }
    return err;
}
```

##### (2) 继续处理(PASS)的实现程

在运行`stream_verdict`/`skb_verdict`BPF程序后，在没有设置重定向标记时，返回结果为`SK_PASS`时，进行后续处理，处理过程如下：

```C
// file: net/core/skmsg.c
static int sk_psock_verdict_apply(struct sk_psock *psock, struct sk_buff *skb, int verdict)
{
    struct sock *sk_other;
    int err = 0;
    u32 len, off;

    switch (verdict) {
    case __SK_PASS:
        err = -EIO;
        sk_other = psock->sk;
        if (sock_flag(sk_other, SOCK_DEAD) || !sk_psock_test_state(psock, SK_PSOCK_TX_ENABLED))
            goto out_free;

        // 设置`INGRESS`标记
        skb_bpf_set_ingress(skb);
        // `ingress_skb`队列为空时，直接处理后添加到`ingress_msg`队列中
        if (skb_queue_empty(&psock->ingress_skb)) {
            // 确定skb的长度和偏移量
            len = skb->len;
            off = 0;
            if (skb_bpf_strparser(skb)) { 
                struct strp_msg *stm = strp_msg(skb);
                off = stm->offset;
                len = stm->full_len;
            }
            // 将skb存放到ingress队列中
            err = sk_psock_skb_ingress_self(psock, skb, off, len);
        }
        if (err < 0) {
            // 出现错误时，添加到到`ingress_skb`队列中，开启工作队列进行后续处理
            spin_lock_bh(&psock->ingress_lock);
            if (sk_psock_test_state(psock, SK_PSOCK_TX_ENABLED)) {
                skb_queue_tail(&psock->ingress_skb, skb);
                schedule_delayed_work(&psock->work, 0);
                err = 0;
            }
            spin_unlock_bh(&psock->ingress_lock);
            if (err < 0) goto out_free;
        }
        break;
    case __SK_REDIRECT: 
        ... 
        break;
    case __SK_DROP:
    default:
out_free:    
        ...
    }
    return err;
}
```

`psock->work`设置的处理接口为`sk_psock_backlog`， 其实现如下：

```C
// file: net/core/skmsg.c
static void sk_psock_backlog(struct work_struct *work)
{
    struct delayed_work *dwork = to_delayed_work(work);
    struct sk_psock *psock = container_of(dwork, struct sk_psock, work);
    struct sk_psock_work_state *state = &psock->work_state;
    struct sk_buff *skb = NULL;
    u32 len = 0, off = 0;
    bool ingress;
    int ret;

    mutex_lock(&psock->work_mutex);
    // 检查长度设置
    if (unlikely(state->len)) { len = state->len; off = state->off; }

    // 获取`ingress_skb`队列中第一个skb
    while ((skb = skb_peek(&psock->ingress_skb))) {
        len = skb->len;
        off = 0;
        if (skb_bpf_strparser(skb)) { 
            struct strp_msg *stm = strp_msg(skb);
            off = stm->offset;
            len = stm->full_len;
        }
        // 是否为ingress
        ingress = skb_bpf_ingress(skb);
        skb_bpf_redirect_clear(skb);
        do {
            ret = -EIO;
            // sk正常的情况先，处理psock的skb
            if (!sock_flag(psock->sk, SOCK_DEAD))
                ret = sk_psock_handle_skb(psock, skb, off, len, ingress);
            // 处理错误时，处理过程
            if (ret <= 0) { ... }
            off += ret;
            len -= ret;
        } while (len);
        // 从`ingress_skb`队列中弹出skb，不需要时释放skb
        skb = skb_dequeue(&psock->ingress_skb);
        if (!ingress) { kfree_skb(skb); }
    }
end:
    mutex_unlock(&psock->work_mutex);
}
```

`sk_psock_handle_skb`函数处理每个skb，决定发送还是接收，如下：

```C
// file: net/core/skmsg.c
static int sk_psock_handle_skb(struct sk_psock *psock, struct sk_buff *skb, u32 off, u32 len, bool ingress)
{
    if (!ingress) {
        // `egress`的情况，发送skb
        if (!sock_writeable(psock->sk)) return -EAGAIN;
        return skb_send_sock(psock->sk, skb, off, len);
    }
    // 将skb转换为msg，存放到`ingress_msg`队列中
    return sk_psock_skb_ingress(psock, skb, off, len);
}
```


* 发送SKB

在skb没有设置`BPF_F_INGRESS`标记时，需要将该skb发送，其实现如下：

```C
// file: net/core/skbuff.c
int skb_send_sock(struct sock *sk, struct sk_buff *skb, int offset, int len)
{
    return __skb_send_sock(sk, skb, offset, len, sendmsg_unlocked, sendpage_unlocked);
}
```

* 接收SKB

`sk_psock_skb_ingress` 函数实现skb INGRESS路径的处理，如下：

```C
// file: net/core/skmsg.c
static int sk_psock_skb_ingress(struct sk_psock *psock, struct sk_buff *skb, u32 off, u32 len)
{
    struct sock *sk = psock->sk;
    struct sk_msg *msg;
    int err;

    // 相同的sk时，跳过内存审计
    if (unlikely(skb->sk == sk)) 
        return sk_psock_skb_ingress_self(psock, skb, off, len);
    // 否则，创建msg
    msg = sk_psock_create_ingress_msg(sk, skb);
    if (!msg) return -EAGAIN;
    // 转移skb所有者后，添加到`ingress`队列中
    skb_set_owner_r(skb, sk);
    err = sk_psock_skb_ingress_enqueue(skb, off, len, psock, sk, msg);
    if (err < 0) kfree(msg);
    return err;
}
```

`sk_psock_skb_ingress_self`函数同样创建msg后，添加到`ingress`队列中，如下：

```C
// file: net/core/skmsg.c
static int sk_psock_skb_ingress_self(struct sk_psock *psock, struct sk_buff *skb, u32 off, u32 len)
{
    // 创建msg
    struct sk_msg *msg = alloc_sk_msg(GFP_ATOMIC);
    struct sock *sk = psock->sk;
    int err;

    if (unlikely(!msg)) return -EAGAIN;
    // 转移skb所有者后，添加到`ingress`队列中
    skb_set_owner_r(skb, sk);
    err = sk_psock_skb_ingress_enqueue(skb, off, len, psock, sk, msg);
    if (err < 0) kfree(msg);
    return err;
}
```

`sk_psock_skb_ingress_enqueue`函数将skb添加到msg中，并唤醒sock，如下：

```C
// file: net/core/skmsg.c
static int sk_psock_skb_ingress_enqueue(struct sk_buff *skb, u32 off, u32 len, 
                struct sk_psock *psock, struct sock *sk, struct sk_msg *msg)
{
    int num_sge, copied;
    // 添加scatter-gather列表
    num_sge = skb_to_sgvec(skb, msg->sg.data, off, len);
    if (num_sge < 0) {
        if (skb_linearize(skb)) return -EAGAIN;
        num_sge = skb_to_sgvec(skb, msg->sg.data, off, len);
        if (unlikely(num_sge < 0)) return num_sge;
    }
    // 设置msg信息
    copied = len;
    msg->sg.start = 0;
    msg->sg.size = copied;
    msg->sg.end = num_sge;
    msg->skb = skb;
    // 添加消息到`psock->ingress_msg`列表中 
    sk_psock_queue_msg(psock, msg);
    // 唤醒socket
    sk_psock_data_ready(sk, psock);
    return copied;
}
```

##### (3) 重定向(REDIRECT)的实现过程

* BPF程序中的重定向设置
  
执行`stream_verdict`/`skb_verdict`BPF程序，`bpf_sk_redirect_map` 和 `bpf_sk_redirect_hash` BPF函数设置sockmap和sockhash的重定向。如下：

```C
// file: net/core/sock_map.c
BPF_CALL_4(bpf_sk_redirect_map, struct sk_buff *, skb, struct bpf_map *, map, u32, key, u64, flags)
{
    struct sock *sk;
    // flags只支持`BPF_F_INGRESS`标志设置
    if (unlikely(flags & ~(BPF_F_INGRESS))) return SK_DROP;

    // 确定key对应的sock后，检查是否能够重定向
    sk = __sock_map_lookup_elem(map, key);
    if (unlikely(!sk || !sock_map_redirect_allowed(sk))) return SK_DROP;
    
    // 设置重定向信息
    skb_bpf_set_redir(skb, sk, flags & BPF_F_INGRESS);
    return SK_PASS;
}

// file: net/core/sock_map.c
BPF_CALL_4(bpf_sk_redirect_hash, struct sk_buff *, skb, struct bpf_map *, map, void *, key, u64, flags)
{
    struct sock *sk;
    // flags只支持`BPF_F_INGRESS`标志设置
    if (unlikely(flags & ~(BPF_F_INGRESS))) return SK_DROP;

    // 确定key对应的sock后，检查是否能够重定向
    sk = __sock_hash_lookup_elem(map, key);
    if (unlikely(!sk || !sock_map_redirect_allowed(sk))) return SK_DROP;

    // 设置重定向信息
    skb_bpf_set_redir(skb, sk, flags & BPF_F_INGRESS);
    return SK_PASS;
}
```

`skb_bpf_set_redir`函数设置重定向新，将sk和flags标记设置到重定向信息中，如下：

```C
// file: include/linux/skmsg.h
static inline void skb_bpf_set_redir(struct sk_buff *skb, struct sock *sk_redir, bool ingress)
{
    // 设置重定向的sk
    skb->_sk_redir = (unsigned long)sk_redir;
    // 设置重定向的flags
    if (ingress) skb->_sk_redir |= BPF_F_INGRESS;
}
```

* 重定向到其他socket的过程

`sk_psock_verdict_apply`函数根据上述结果进行对应处理，如下：

```C
// file: net/core/skmsg.c
static int sk_psock_verdict_apply(struct sk_psock *psock, struct sk_buff *skb, int verdict)
{
    struct sock *sk_other;
    int err = 0;
    u32 len, off;

    switch (verdict) {
    case __SK_PASS: 
        ... 
        break;
    case __SK_REDIRECT: 
        tcp_eat_skb(psock->sk, skb);
        err = sk_psock_skb_redirect(psock, skb);
        break;
    case __SK_DROP:
    default:
out_free:
        ...
    }
    return err;
}
```

`sk_psock_skb_redirect`函数重定向skb到其他socket的接收队列中，实现如下：

```C
// file: net/core/skmsg.c
static int sk_psock_skb_redirect(struct sk_psock *from, struct sk_buff *skb)
{
    struct sk_psock *psock_other;
    struct sock *sk_other;
    // 获取重定向的sk
    sk_other = skb_bpf_redirect_fetch(skb);

    // 没有设置重定向socket时，丢弃skb
    if (unlikely(!sk_other)) { 
        skb_bpf_redirect_clear(skb);
        sock_drop(from->sk, skb);
        return -EIO;
    }
    // 获取重定向的psock
    psock_other = sk_psock(sk_other);
    // 重定向的psock不存在，重定向的sock关闭时，丢弃skb
    if (!psock_other || sock_flag(sk_other, SOCK_DEAD)) {
        skb_bpf_redirect_clear(skb);
        sock_drop(from->sk, skb);
        return -EIO;
    }
    spin_lock_bh(&psock_other->ingress_lock);
    //  重定向的psock不支持TX时，丢弃skb
    if (!sk_psock_test_state(psock_other, SK_PSOCK_TX_ENABLED)) {
        spin_unlock_bh(&psock_other->ingress_lock);
        skb_bpf_redirect_clear(skb);
        sock_drop(from->sk, skb);
        return -EIO;
    }
    // 添加到重定向的`ingress_skb`
    skb_queue_tail(&psock_other->ingress_skb, skb);
    // 开启工作队列, 此时，skb没有设置`ingress`标记，将发送
    schedule_delayed_work(&psock_other->work, 0);
    spin_unlock_bh(&psock_other->ingress_lock);
    return 0;
}
```

##### (4) 丢弃(DROP)的实现过程

在运行`stream_verdict`/`skb_verdict`BPF程序后，返回结果为`SK_DROP`时，丢弃skb，处理过程如下：

```C
// file: net/core/skmsg.c
static int sk_psock_verdict_apply(struct sk_psock *psock, struct sk_buff *skb, int verdict)
{
    struct sock *sk_other;
    int err = 0;
    u32 len, off;

    switch (verdict) {
    case __SK_PASS:
        ... 
        break;
    case __SK_REDIRECT: 
        ... 
        break;
    case __SK_DROP:
    default:
out_free: 
        // 清除重定向标记时，丢弃skb
        skb_bpf_redirect_clear(skb);
        tcp_eat_skb(psock->sk, skb);
        sock_drop(psock->sk, skb);
    }
    return err;
}
```

#### 5 EGRESS路径的判决过程

##### (1) 设置过程

在sockmap或sockhash设置`BPF_SK_MSG_VERDICT`类型的BPF程序时，对发送的skb进行判决处理。目前只支持TCP协议，`tcp_bpf_rebuild_protos`函数构建tcp_bpf协议时，替换`.sendmsg`和`.sendpage`接口，如下：

```C
// file: net/ipv4/tcp_bpf.c
static void tcp_bpf_rebuild_protos(struct proto prot[TCP_BPF_NUM_CFGS], struct proto *base)
{
    // BASE设置
    prot[TCP_BPF_BASE]              = *base;
    prot[TCP_BPF_BASE].destroy      = sock_map_destroy;
    prot[TCP_BPF_BASE].close        = sock_map_close;
    prot[TCP_BPF_BASE].recvmsg      = tcp_bpf_recvmsg;
    prot[TCP_BPF_BASE].sock_is_readable	= sk_msg_is_readable;

    // TX设置，在BASE基础上设置
    prot[TCP_BPF_TX]                = prot[TCP_BPF_BASE];
    prot[TCP_BPF_TX].sendmsg        = tcp_bpf_sendmsg;
    prot[TCP_BPF_TX].sendpage       = tcp_bpf_sendpage;

    // RX设置，在BASE基础上设置
    prot[TCP_BPF_RX]                = prot[TCP_BPF_BASE];
    prot[TCP_BPF_RX].recvmsg        = tcp_bpf_recvmsg_parser;

    // TXRX设置，在TX基础上设置
    prot[TCP_BPF_TXRX]              = prot[TCP_BPF_TX];
    prot[TCP_BPF_TXRX].recvmsg      = tcp_bpf_recvmsg_parser;
}
```

##### (2) 发送数据的实现过程

* `tcp_bpf_sendmsg`

`.sendmsg`接口替换为`tcp_bpf_sendmsg`， 其实现如下：

```C
// file: net/ipv4/tcp_bpf.c
static int tcp_bpf_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
    struct sk_msg tmp, *msg_tx = NULL;
    int copied = 0, err = 0;
    struct sk_psock *psock;
    long timeo;
    int flags;

    // 清除内核内部`do_tcp_sendpages()`调用
    flags = (msg->msg_flags & ~MSG_SENDPAGE_DECRYPTED);
    flags |= MSG_NO_SHARED_FRAGS;

    // psock不存在时，使用`tcp_sendmsg`接口发送
    psock = sk_psock_get(sk);
    if (unlikely(!psock)) return tcp_sendmsg(sk, msg, size);

    lock_sock(sk);
    timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
    while (msg_data_left(msg)) {
        bool enospc = false;
        u32 copy, osize;
        // sk错误时，退出发送
        if (sk->sk_err) { err = -sk->sk_err; goto out_err; }

        // 发送空间不足时，等待
        copy = msg_data_left(msg);
        if (!sk_stream_memory_free(sk)) goto wait_for_sndbuf;

        // 获取发送的msg
        if (psock->cork) {
            msg_tx = psock->cork;
        } else {
            msg_tx = &tmp;
            sk_msg_init(msg_tx);
        }
        // 创建`scatterlist`空间
        osize = msg_tx->sg.size;
        err = sk_msg_alloc(sk, msg_tx, msg_tx->sg.size + copy, msg_tx->sg.end - 1);
        if (err) {
            if (err != -ENOSPC) goto wait_for_memory;
            enospc = true;
            copy = msg_tx->sg.size - osize;
        }
        // 拷贝发送内容
        err = sk_msg_memcopy_from_iter(sk, &msg->msg_iter, msg_tx, copy);
        if (err < 0) { sk_msg_trim(sk, msg_tx, osize); goto out_err; }

        copied += copy;
        // cork设置，等待足够的发送内容
        if (psock->cork_bytes) {
            if (size > psock->cork_bytes)
                psock->cork_bytes = 0;
            else
                psock->cork_bytes -= size;
            if (psock->cork_bytes && !enospc) goto out_err;
            psock->eval = __SK_NONE;
            psock->cork_bytes = 0;
        }
        // 判决发送的消息
        err = tcp_bpf_send_verdict(sk, psock, msg_tx, &copied, flags);
        if (unlikely(err < 0)) goto out_err;
        // 继续下一个消息的发送
        continue;
wait_for_sndbuf:
        set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
        // 等待足够的发送内存空间
        err = sk_stream_wait_memory(sk, &timeo);
        if (err) {
            if (msg_tx && msg_tx != psock->cork)
                sk_msg_free(sk, msg_tx);
            goto out_err;
        }
    }
out_err:
    // 出现错误时，进行错误处理
    if (err < 0) err = sk_stream_error(sk, msg->msg_flags, err);
    // 释放占用的sk、psock
    release_sock(sk);
    sk_psock_put(sk, psock);
    return copied ? copied : err;
}
```

* `tcp_bpf_sendpage`

`.sendpage`接口替换为`tcp_bpf_sendpage`， 其实现如下：

```C
// file: net/ipv4/tcp_bpf.c
static int tcp_bpf_sendpage(struct sock *sk, struct page *page, int offset, size_t size, int flags)
{
    struct sk_msg tmp, *msg = NULL;
    int err = 0, copied = 0;
    struct sk_psock *psock;
    bool enospc = false;

    // psock不存在时，使用`tcp_sendpage`接口发送
    psock = sk_psock_get(sk);
    if (unlikely(!psock)) return tcp_sendpage(sk, page, offset, size, flags);

    lock_sock(sk);
    // 获取发送的msg
    if (psock->cork) {
        msg = psock->cork;
    } else {
        msg = &tmp;
        sk_msg_init(msg);
    }

    // 发送ring已经满的情况，退出发送
    if (unlikely(sk_msg_full(msg))) goto out_err;
    // 添加到page到msg中
    sk_msg_page_add(msg, page, size, offset);
    sk_mem_charge(sk, size);
    copied = size;
    if (sk_msg_full(msg))
        enospc = true;

    // cork设置，等待足够的发送内容
    if (psock->cork_bytes) {
        if (size > psock->cork_bytes)
            psock->cork_bytes = 0;
        else
            psock->cork_bytes -= size;
        if (psock->cork_bytes && !enospc)
            goto out_err;
        psock->eval = __SK_NONE;
        psock->cork_bytes = 0;
    }
    // 判决发送的消息
    err = tcp_bpf_send_verdict(sk, psock, msg, &copied, flags);
out_err:
    // 释放占用的sk、psock
    release_sock(sk);
    sk_psock_put(sk, psock);
    return copied ? copied : err;
}
```

##### (3) 发送数据的判决过程

`tcp_bpf_send_verdict`函数实现EGRESS路径发送消息的判决，实现如下：

```C
// file: net/ipv4/tcp_bpf.c
static int tcp_bpf_send_verdict(struct sock *sk, struct sk_psock *psock,
                struct sk_msg *msg, int *copied, int flags)
{
    bool cork = false, enospc = sk_msg_full(msg), redir_ingress;
    struct sock *sk_redir;
    u32 tosend, origsize, sent, delta = 0;
    u32 eval;
    int ret;

more_data:
    if (psock->eval == __SK_NONE) {
        // 计算msg的变化情况
        delta = msg->sg.size;
        // 运行BPF程序，获取判决结果
        psock->eval = sk_psock_msg_verdict(sk, psock, msg);
        delta -= msg->sg.size;
    }
    // 存在cork时，检查数据情况，并分配`cork`空间
    if (msg->cork_bytes && msg->cork_bytes > msg->sg.size && !enospc) {
        psock->cork_bytes = msg->cork_bytes - msg->sg.size;
        if (!psock->cork) {
            psock->cork = kzalloc(sizeof(*psock->cork), GFP_ATOMIC | __GFP_NOWARN);
            if (!psock->cork) return -ENOMEM;
        }
        memcpy(psock->cork, msg, sizeof(*msg));
        return 0;
    }
    // 计算发送的数据量
    tosend = msg->sg.size;
    if (psock->apply_bytes && psock->apply_bytes < tosend)
        tosend = psock->apply_bytes;
    eval = __SK_NONE;

    switch (psock->eval) {
    case __SK_PASS: // PASS的处理过程
        ...
        break;
    case __SK_REDIRECT: // 重定向的处理过程
        ...
        break;
    case __SK_DROP: // DROP和默认处理过程
    default:
        ...
        return -EACCES;
    }

    // 正确处理时
    if (likely(!ret)) {
        // 一个完整数据时，清除`sk_redir`的socket
        if (!psock->apply_bytes) {
            psock->eval =  __SK_NONE;
            if (psock->sk_redir) {
                sock_put(psock->sk_redir);
                psock->sk_redir = NULL;
            }
        }
        if (msg && msg->sg.data[msg->sg.start].page_link && 
                    msg->sg.data[msg->sg.start].length) {
            if (eval == __SK_REDIRECT)
                sk_mem_charge(sk, tosend - sent);
            goto more_data;
        }
    }
    return ret;
}
```

`sk_psock_msg_verdict`函数获取判决结果，实现如下：

```C
// file: net/core/skmsg.c
int sk_psock_msg_verdict(struct sock *sk, struct sk_psock *psock, struct sk_msg *msg)
{
    struct bpf_prog *prog;
    int ret;

    rcu_read_lock();
    prog = READ_ONCE(psock->progs.msg_parser);
    // `msg_parser`程序不存在时，默认为`PASS`
    if (unlikely(!prog)) { ret = __SK_PASS; goto out; }

    sk_msg_compute_data_pointers(msg);
    msg->sk = sk;
    // 运行BPF程序
    ret = bpf_prog_run_pin_on_cpu(prog, msg);
    // 转换判决结果
    ret = sk_psock_map_verd(ret, msg->sk_redir);
    psock->apply_bytes = msg->apply_bytes;
    if (ret == __SK_REDIRECT) {
        // 重定向时，清除之前重定向的sock
        if (psock->sk_redir) {
            sock_put(psock->sk_redir);
            psock->sk_redir = NULL;
        }
        // msg中没有设置重定向的sock时，丢弃skb
        if (!msg->sk_redir) { 
            ret = __SK_DROP;
            goto out;
        }
        // 设置重定向路径和sk
        psock->redir_ingress = sk_msg_to_ingress(msg);
        psock->sk_redir = msg->sk_redir;
        sock_hold(psock->sk_redir);
    }
out:
    rcu_read_unlock();
    return ret;
}
```

##### (4) 继续处理(PASS)的实现程

在运行`msg_parser`BPF程序后，在没有设置重定向标记时，返回结果为`SK_PASS`时，进行后续处理，调用`tcp_bpf_push`函数发送数据，处理过程如下：

```C
// file: net/ipv4/tcp_bpf.c
static int tcp_bpf_send_verdict(struct sock *sk, struct sk_psock *psock,
                struct sk_msg *msg, int *copied, int flags)
{
    ...
    switch (psock->eval) {
    case __SK_PASS: // PASS的处理过程
        // 发送msg，记录发送结果
        ret = tcp_bpf_push(sk, msg, tosend, flags, true);
        // 出现发送错误时，释放msk
        if (unlikely(ret)) {
            *copied -= sk_msg_free(sk, msg);
            break;
        }
        // 处理发送的字节数
        sk_msg_apply_bytes(psock, tosend);
        break;
    case __SK_REDIRECT: // 重定向的处理过程
        ...
        break;
    case __SK_DROP: // DROP和默认处理过程
    default:
        ...
        return -EACCES;
    }
}
```

##### (4) 重定向(REDIRECT)的实现过程

* BPF程序中的重定向设置
  
执行`msg_parser`BPF程序，`bpf_msg_redirect_map` 和 `bpf_msg_redirect_hash` BPF函数设置sockmap和sockhash的重定向。如下：

```C
// file: net/core/sock_map.c
BPF_CALL_4(bpf_msg_redirect_map, struct sk_msg *, msg, struct bpf_map *, map, u32, key, u64, flags)
{
    struct sock *sk;
    // flags只支持`BPF_F_INGRESS`标志设置
    if (unlikely(flags & ~(BPF_F_INGRESS))) return SK_DROP;
    // 确定key对应的sock后，检查是否能够重定向
    sk = __sock_map_lookup_elem(map, key);
    if (unlikely(!sk || !sock_map_redirect_allowed(sk))) return SK_DROP;
    // 设置重定向信息
    msg->flags = flags;
    msg->sk_redir = sk;
    return SK_PASS;
}

// file: net/core/sock_map.c
BPF_CALL_4(bpf_msg_redirect_hash, struct sk_msg *, msg, struct bpf_map *, map, void *, key, u64, flags)
{
    struct sock *sk;
    // flags只支持`BPF_F_INGRESS`标志设置
    if (unlikely(flags & ~(BPF_F_INGRESS))) return SK_DROP;
    // 确定key对应的sock后，检查是否能够重定向
    sk = __sock_hash_lookup_elem(map, key);
    if (unlikely(!sk || !sock_map_redirect_allowed(sk))) return SK_DROP;
    // 设置重定向信息
    msg->flags = flags;
    msg->sk_redir = sk;
    return SK_PASS;
}
```

* 重定向到其他socket的过程

在运行`msg_parser`BPF程序后，在设置重定向标记时，返回结果为`SK_PASS`时，进行重定向处理，处理过程如下：

```C
// file: net/ipv4/tcp_bpf.c
static int tcp_bpf_send_verdict(struct sock *sk, struct sk_psock *psock,
                struct sk_msg *msg, int *copied, int flags)
{
    ...
    switch (psock->eval) {
    case __SK_PASS: // PASS的处理过程
        ...
        break;
    case __SK_REDIRECT: // 重定向的处理过程
        // 是否重定向到INGRESS路径
        redir_ingress = psock->redir_ingress;
        sk_redir = psock->sk_redir;
        sk_msg_apply_bytes(psock, tosend);
        // 释放psock前的清理
        if (!psock->apply_bytes) {
            eval = psock->eval;
            psock->eval = __SK_NONE;
            psock->sk_redir = NULL;
        }
        // 记录cork信息
        if (psock->cork) {
            cork = true;
            psock->cork = NULL;
        }
        // 回退发送占用空间
        sk_msg_return(sk, msg, tosend);
        release_sock(sk);

        origsize = msg->sg.size;
        // 重定向发送处理
        ret = tcp_bpf_sendmsg_redir(sk_redir, redir_ingress, msg, tosend, flags);
        sent = origsize - msg->sg.size;

        if (eval == __SK_REDIRECT) sock_put(sk_redir);

        lock_sock(sk);
        if (unlikely(ret < 0)) {
            // 出现错误时，释放msg
            int free = sk_msg_free_nocharge(sk, msg);
            if (!cork) *copied -= free;
        }
        if (cork) {
            // 释放msg
            sk_msg_free(sk, msg);
            kfree(msg);
            msg = NULL;
            ret = 0;
        }
        break;
    case __SK_DROP: // DROP和默认处理过程
    default:
        ...
        return -EACCES;
    }
}
```

`tcp_bpf_sendmsg_redir`函数实现msg的重定向，实现如下：

```C
// file: net/ipv4/tcp_bpf.c
int tcp_bpf_sendmsg_redir(struct sock *sk, bool ingress,
        struct sk_msg *msg, u32 bytes, int flags)
{
    struct sk_psock *psock = sk_psock_get(sk);
    int ret;
    // psock不存在时，返回错误信息
    if (unlikely(!psock)) return -EPIPE;

    ret = ingress ? bpf_tcp_ingress(sk, psock, msg, bytes, flags) :
            tcp_bpf_push_locked(sk, msg, bytes, flags, false);
    sk_psock_put(sk, psock);
    return ret;
}
```

* 重定向到INGRESS路径

在设置`BPF_F_INGRESS`标记时，将MSG重定到INGRESS路径，`bpf_tcp_ingress`函数实现该功能，如下：

```C
// file: net/ipv4/tcp_bpf.c
static int bpf_tcp_ingress(struct sock *sk, struct sk_psock *psock,
            struct sk_msg *msg, u32 apply_bytes, int flags)
{
    bool apply = apply_bytes;
    struct scatterlist *sge;
    u32 size, copied = 0;
    struct sk_msg *tmp;
    int i, ret = 0;

    // 分配msg空间
    tmp = kzalloc(sizeof(*tmp), __GFP_NOWARN | GFP_KERNEL);
    if (unlikely(!tmp)) return -ENOMEM;

    lock_sock(sk);
    tmp->sg.start = msg->sg.start;
    i = msg->sg.start;
    do {
        // 复制整个完整的消息 
        ...
    } while (i != msg->sg.end);

    if (!ret) {
        msg->sg.start = i;
        // 正常复制时，添加到`psock->ingress_msg`列表中后，唤醒psock
        sk_psock_queue_msg(psock, tmp);
        sk_psock_data_ready(sk, psock);
    } else {
        // 失败时，释放msg
        sk_msg_free(sk, tmp);
        kfree(tmp);
    }
    release_sock(sk);
    return ret;
}
```

`sk_psock_queue_msg`函数将msg添加到`ingress_msg`队列中，如下：

```C
// file: include/linux/skmsg.h
static inline void sk_psock_queue_msg(struct sk_psock *psock, struct sk_msg *msg)
{
    spin_lock_bh(&psock->ingress_lock);
    if (sk_psock_test_state(psock, SK_PSOCK_TX_ENABLED))
        list_add_tail(&msg->list, &psock->ingress_msg);
    else {
        sk_msg_free(psock->sk, msg);
        kfree(msg);
    }
    spin_unlock_bh(&psock->ingress_lock);
}
```

* 重定向到EGRESS路径

没有设置`BPF_F_INGRESS`标记时，将MSG重定向到EGRESS路径，`tcp_bpf_push_locked`函数实现该功能，如下：

```C
// file: net/ipv4/tcp_bpf.c
static int tcp_bpf_push_locked(struct sock *sk, struct sk_msg *msg,
                u32 apply_bytes, int flags, bool uncharge)
{
    int ret;
    lock_sock(sk);
    // 调用`tcp_bpf_push`发送数据
    ret = tcp_bpf_push(sk, msg, apply_bytes, flags, uncharge);
    release_sock(sk);
    return ret;
}
```

##### (5) 丢弃(DROP)的实现过程

在运行`msg_parser`BPF程序后，返回结果为`SK_DROP`时，丢弃msg，处理过程如下：

```C
// file: net/ipv4/tcp_bpf.c
static int tcp_bpf_send_verdict(struct sock *sk, struct sk_psock *psock,
                struct sk_msg *msg, int *copied, int flags)
{
    ...
    switch (psock->eval) {
    case __SK_PASS: // PASS的处理过程
        ...
        break;
    case __SK_REDIRECT: // 重定向的处理过程
        ...
        break;
    case __SK_DROP: // DROP和默认处理过程
    default:
        // 释放msg
        sk_msg_free_partial(sk, msg, tosend);
        sk_msg_apply_bytes(psock, tosend);
        *copied -= (tosend + delta);
        return -EACCES;
    }
}
```

## 5 总结

本文通过`test_sockmap`示例程序分析了BPF在sockmap中应用，分析了`流解析器（strparser）`框架的实现过程，通过将BPF程序挂载到sockmap上，实现socket间数据的重定向。

## 参考资料

* [BPF_MAP_TYPE_SOCKMAP and BPF_MAP_TYPE_SOCKHASH](https://www.kernel.org/doc/html/v6.3/bpf/map_sockmap.html)
* [Stream Parser (strparser)](https://www.kernel.org/doc/html/v6.2/networking/strparser.html)
* [BPF: sockmap and sk redirect support](https://lwn.net/Articles/731133/)
* [bpf,sockmap: sendmsg/sendfile ULP](https://lwn.net/Articles/748628/)
* [sockmap integration for ktls](https://lwn.net/Articles/768371/)
* [Combining kTLS and BPF for Introspection and Policy Enforcement](http://vger.kernel.org/lpc_net2018_talks/ktls_bpf_paper.pdf)
* [内核 strparser 是如何工作的](https://switch-router.gitee.io/blog/strparser/)
* [利用 ebpf sockmap/redirection 提升 socket 性能](https://arthurchiao.art/blog/socket-acceleration-with-ebpf-zh/)
