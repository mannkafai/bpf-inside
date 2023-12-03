# FLOW_DISSECTOR的内核实现

## 0 前言

在[LWT的内核实现](./15-lwt.md)中，我们在分析了路由规则的实现过程。在添加路由过程中，我们略过了根据skb确定输入路由规则剖析的过程。路由规则剖析是基于流分析器(flow dissector)实现的，今天我们借助 `test_flow_dissector` 程序分析流分析器(flow dissector)的实现过程。

## 1 简介

流分析器(flow dissector)是从数据包中解析元数据的程序，它用在网络子系统的各个地方（如：RFS、流哈希等）。BPF流分析器是尝试在BPF中重新实现基于C的流分析器逻辑，以获得BPF验证器的所有好处（即对指令和尾部调用数量的限制）。

## 2 `test_flow_dissector`示例程序

### 2.1 BPF程序

BPF程序源码参见[bpf_flow.c](../src/bpf_flow.c)，主要内容如下：

```C
#define FLOW_CONTINUE_SADDR 0x7f00007f /* 127.0.0.127 */

// 获取IP头信息
static __always_inline void *bpf_flow_dissect_get_header(struct __sk_buff *skb,
                            __u16 hdr_size, void *buffer)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u16 thoff = skb->flow_keys->thoff;
    __u8 *hdr;

    // 验证偏移量是否未溢出
    if (thoff > (USHRT_MAX - hdr_size)) return NULL;
    // 获取IP头部
    hdr = data + thoff;
    if (hdr + hdr_size <= data_end) return hdr;
    // 获取skb中数据
    if (bpf_skb_load_bytes(skb, thoff, buffer, hdr_size)) return NULL;

    return buffer;
}
// 解析网络协议
static __always_inline int parse_eth_proto(struct __sk_buff *skb, __be16 proto)
{
    struct bpf_flow_keys *keys = skb->flow_keys;
    switch (proto) {
    case bpf_htons(ETH_P_IP): 
        bpf_tail_call_static(skb, &jmp_table, IP); 
        break;
    case bpf_htons(ETH_P_IPV6): 
        bpf_tail_call_static(skb, &jmp_table, IPV6); 
        break;
    case bpf_htons(ETH_P_MPLS_MC):
    case bpf_htons(ETH_P_MPLS_UC):
        bpf_tail_call_static(skb, &jmp_table, MPLS);
        break;
    case bpf_htons(ETH_P_8021Q):
    case bpf_htons(ETH_P_8021AD):
        bpf_tail_call_static(skb, &jmp_table, VLAN);
        break;
    default:
        /* Protocol not supported */
        return export_flow_keys(keys, BPF_DROP);
    }
    return export_flow_keys(keys, BPF_DROP);
}

SEC("flow_dissector")
int _dissect(struct __sk_buff *skb)
{
    struct bpf_flow_keys *keys = skb->flow_keys;
    
    if (keys->n_proto == bpf_htons(ETH_P_IP)) {
        // 来自`FLOW_CONTINUE_SADDR`的IP流量回退到标志分析器
        struct iphdr *iph, _iph;
        iph = bpf_flow_dissect_get_header(skb, sizeof(*iph), &_iph);
        if (iph && iph->ihl == 5 && iph->saddr == bpf_htonl(FLOW_CONTINUE_SADDR)) {
            return BPF_FLOW_DISSECTOR_CONTINUE;
        }
    }
    // 其他协议解析
    return parse_eth_proto(skb, keys->n_proto);
}
```

可以看到，BPF程序从`skb`中获取`bpf_flow_keys`后，根据协议进行对应处理。`struct bpf_flow_keys`结构定义了`skb`流相关信息，如下：

```C
// file: /usr/include/linux/bpf.h
struct bpf_flow_keys {
    __u16   nhoff;
    __u16   thoff;
    __u16   addr_proto;     /* ETH_P_* of valid addrs */
    __u8    is_frag;
    __u8    is_first_frag;
    __u8    is_encap;
    __u8    ip_proto;
    __be16  n_proto;
    __be16  sport;
    __be16  dport;
    union {
        struct {
            __be32  ipv4_src;
            __be32  ipv4_dst;
        };
        struct {
            __u32   ipv6_src[4];    /* in6_addr; network order */
            __u32   ipv6_dst[4];    /* in6_addr; network order */
        };
    };
    __u32	flags;
    __be32	flow_label;
};
```

### 2.2 用户程序

`test_flow_dissector`程序通过脚本测试的，BPF程序在[test_flow_dissector.sh](../src/test_flow_dissector.sh)中通过`flow_dissector_load`程序加载和分离的，如下：

```bash
# file: ../src/test_flow_dissector.sh
BPF_FILE="bpf_flow.bpf.o"
...
// 附加BPF程序
./flow_dissector_load -p $BPF_FILE -s _dissect
```

`flow_dissector_load`程序通过[flow_dissector_load.c](../src/flow_dissector_load.c)实现的，在其中实现BPF程序的附加和分离。

#### 1 附加BPF程序

`load_and_attach_program`函数实现`FLOW_DISSECTOR`的附加，如下：

```C
// file: ../src/flow_dissector_load.c
const char *cfg_pin_path = "/sys/fs/bpf/flow_dissector";
const char *cfg_map_name = "jmp_table";

static void load_and_attach_program(void)
{
    int prog_fd, ret;
    struct bpf_object *obj;

    /* Use libbpf 1.0 API mode */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // 获取BPF程序
    ret = bpf_flow_load(&obj, cfg_path_name, cfg_prog_name, cfg_map_name, NULL, &prog_fd, NULL);
    if (ret) error(1, 0, "bpf_flow_load %s", cfg_path_name);
    // 附加`FLOW_DISSECTOR`
    ret = bpf_prog_attach(prog_fd, 0 /* Ignore */, BPF_FLOW_DISSECTOR, 0);
    if (ret) error(1, 0, "bpf_prog_attach %s", cfg_path_name);
    // pin BPF程序
    ret = bpf_object__pin(obj, cfg_pin_path);
    if (ret) error(1, 0, "bpf_object__pin %s", cfg_pin_path);
}
```

#### 2 分离BPF程序

`detach_program`函数实现`FLOW_DISSECTOR`的分离，如下：

```C
// file: ../src/flow_dissector_load.c
static void detach_program(void)
{
    char command[64];
    int ret;
    // 分离`FLOW_DISSECTOR`
    ret = bpf_prog_detach(0, BPF_FLOW_DISSECTOR);
    if (ret) error(1, 0, "bpf_prog_detach");

    // unpin BPF程序
    sprintf(command, "rm -r %s", cfg_pin_path);
    ret = system(command);
    if (ret) error(1, errno, "%s", command);
}
```

#### 3 读取数据过程

`test_flow_dissector` 程序对网络数据包中解析元数据，测试程序通过发送、接收的数据量判断是否完全发送。

### 2.3 编译运行

`test_flow_dissector`程序是Linux内核自带的测试程序，在`tools/testing/selftests/bpf/prog_tests/`目录下。编译后运行，如下：

```bash
$ cd tools/testing/selftests/bpf/
$ sudo make
$ sudo ./test_flow_dissector.sh 
Testing global flow dissector...
Error: failed prog attach to map
bpffs not mounted. Mounting...
Testing IPv4...
inner.dest4: 127.0.0.1
inner.source4: 127.0.0.3
pkts: tx=10 rx=10
inner.dest4: 127.0.0.1
inner.source4: 127.0.0.3
pkts: tx=10 rx=0
inner.dest4: 127.0.0.1
inner.source4: 127.0.0.3
pkts: tx=10 rx=10
Testing IPv4 from 127.0.0.127 (fallback to generic dissector)...
....
Testing IPv6...
inner.dest6: ::1
inner.source6: ::1
pkts: tx=10 rx=10
inner.dest6: ::1
inner.source6: ::1
pkts: tx=10 rx=0
inner.dest6: ::1
inner.source6: ::1
pkts: tx=10 rx=10
selftests: test_flow_dissector [PASS]
```

## 3 flow_dissector附加和分离的过程

`bpf_flow.c`文件中BPF程序的SEC名称为`SEC("flow_dissector")`，在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("flow_dissector",   FLOW_DISSECTOR, BPF_FLOW_DISSECTOR, SEC_ATTACHABLE_OPT),
    ...
};
```

`flow_dissector`前缀不支持自动附加，需要通过手动方式附加。

### 3.1 传统方式附加和分离

传统方式附加`flow_dissector`类型的BPF程序通过`bpf_prog_attach`方式附加，设置`opts->flags`后调用`bpf_prog_attach_opts`，如下：

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

`bpf_prog_detach` 函数实现flow_dissector BPF程序的分离，如下：

```C
// file: libbpf/src/bpf.c
int bpf_prog_detach(int target_fd, enum bpf_attach_type type)
{
    const size_t attr_sz = offsetofend(union bpf_attr, replace_bpf_fd);
    union bpf_attr attr;
    int ret;

    // 设置bpf系统调用的属性
    memset(&attr, 0, attr_sz);
    attr.target_fd = target_fd;
    attr.attach_type = type;

    // BPF系统调用，使用`BPF_PROG_DETACH`指令
    ret = sys_bpf(BPF_PROG_DETACH, &attr, attr_sz);
    return libbpf_err_errno(ret);
}
```

### 3.2 Link方式附加和分离

`bpf_program__attach_netns`函数附加BPF程序到网络命名空间，实现如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link * bpf_program__attach_netns(const struct bpf_program *prog, int netns_fd)
{
    return bpf_program__attach_fd(prog, netns_fd, 0, "netns");
}
```

`bpf_program__attach_fd` 函数设置link属性后，调用`bpf_link_create`进行实际的创建，如下：

```C
// file: libbpf/src/libbpf.c
static struct bpf_link * bpf_program__attach_fd(const struct bpf_program *prog, 
                        int target_fd, int btf_id, const char *target_name)
{
    DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts, .target_btf_id = btf_id);
    struct bpf_link *link;
    ...
    // 获取BPF程序fd
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) { ... }

    // 分配link，并设置detach接口
    link = calloc(1, sizeof(*link));
    if (!link) return libbpf_err_ptr(-ENOMEM);
    link->detach = &bpf_link__detach_fd;

    // 创建link
    attach_type = bpf_program__expected_attach_type(prog);
    link_fd = bpf_link_create(prog_fd, target_fd, attach_type, &opts);
    if (pfd < 0) { ... }
    // 设置link->fd
    link->fd = pfd;
    return link;
}
```

`bpf_link_create` 在设置和检查`bpf_attr`属性后，使用 `BPF_LINK_CREATE` 指令进行BPF系统调用。如下：

```C
// file: libbpf/src/bpf.c
int bpf_link_create(int prog_fd, int target_fd, enum bpf_attach_type attach_type,
            const struct bpf_link_create_opts *opts)
{
    const size_t attr_sz = offsetofend(union bpf_attr, link_create);
    __u32 target_btf_id, iter_info_len;
    union bpf_attr attr;

    ...
    iter_info_len = OPTS_GET(opts, iter_info_len, 0);
    target_btf_id = OPTS_GET(opts, target_btf_id, 0);

    // 检查字段的设置情况，不能同时有效
    if (iter_info_len || target_btf_id) { ... }

    // attr属性设置
    memset(&attr, 0, attr_sz);
    attr.link_create.prog_fd = prog_fd;
    attr.link_create.target_fd = target_fd;
    attr.link_create.attach_type = attach_type;
    attr.link_create.flags = OPTS_GET(opts, flags, 0);

    // 设置了`btf_id`，直接进行处理
    if (target_btf_id) {
        attr.link_create.target_btf_id = target_btf_id;
        goto proceed;
    }
    switch (attach_type) {
    ...
    default:
        if (!OPTS_ZEROED(opts, flags)) return libbpf_err(-EINVAL);
        break;
    }
proceed:
    // BPF系统调用，使用`BPF_LINK_CREATE`指令
    fd = sys_bpf_fd(BPF_LINK_CREATE, &attr, attr_sz);
    // 创建link成功后返回
    if (fd >= 0) return fd;

    // 出现`EINVAL`错误时，重新尝试
    err = -errno;
    if (err != -EINVAL) return libbpf_err(err);
    ...
}
```

`bpf_link__destroy`函数实现link的销毁，在销毁的过程中分离bpf程序。

## 4 内核实现

### 4.1 传统方式附加和分离的内核实现

#### 1 传统方式附加的实现

##### (1) BPF系统调用

传统方式使用`BPF_PROG_ATTACH` BPF系统调用，如下：

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

`bpf_prog_attach` 在检查BPF程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。flow_dissector类型的bpf程序对应 `netns_bpf_prog_attach` 处理函数。如下：

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
    ...
    case BPF_PROG_TYPE_FLOW_DISSECTOR:
        ret = netns_bpf_prog_attach(attr, prog);
        break;
    default:
        ret = -EINVAL;
    }
    // 附加失败时，释放bpf程序
    if (ret) bpf_prog_put(prog);
    return ret;
}
```

##### (3) `netns_bpf_prog_attach`

`netns_bpf_prog_attach` 函数附加FLOW_DISSECTOR BPF程序附加到网络命名空间，实现如下：

```C
// file: kernel/bpf/net_namespace.c
int netns_bpf_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    struct bpf_prog_array *run_array;
    enum netns_bpf_attach_type type;
    struct bpf_prog *attached;
    struct net *net;
    int ret;

    // attr属性检查
    if (attr->target_fd || attr->attach_flags || attr->replace_bpf_fd) return -EINVAL;
    // BPF程序类型转换为网络命名空间支持的类型
    type = to_netns_bpf_attach_type(attr->attach_type);
    if (type < 0) return -EINVAL;

    // 获取当前的网络命名空间
    net = current->nsproxy->net_ns;
    mutex_lock(&netns_bpf_mutex);

    // 直接附加BPF程序和link方式冲突
    if (!list_empty(&net->bpf.links[type])) { ret = -EEXIST; goto out_unlock; }

    // 只支持`FLOW_DISSECTOR`类型
    switch (type) {
    case NETNS_BPF_FLOW_DISSECTOR:
        // FLOW_DISSECTOR类型BPF程序附加检查，只支持root命名空间附加
        ret = flow_dissector_bpf_prog_attach_check(net, prog);
        break;
    default:
        ret = -EINVAL;
        break;
    }
    if (ret) goto out_unlock;

    attached = net->bpf.progs[type];
    // 同样的程序不能附加两次
    if (attached == prog) { ret = -EINVAL; goto out_unlock; }

    // 获取BPF程序列表
    run_array = rcu_dereference_protected(net->bpf.run_array[type], lockdep_is_held(&netns_bpf_mutex));
    if (run_array) {
        // 程序列表存在时，修改第一个程序
        WRITE_ONCE(run_array->items[0].prog, prog);
    } else {
        // 程序列表不存在时，分配列表后设置第一个程序
        run_array = bpf_prog_array_alloc(1, GFP_KERNEL);
        if (!run_array) { ret = -ENOMEM; goto out_unlock; }
        run_array->items[0].prog = prog;
        rcu_assign_pointer(net->bpf.run_array[type], run_array);
    }
    // 修改网络命名空间中对应类型的程序
    net->bpf.progs[type] = prog;
    // 释放之前附加的程序
    if (attached) bpf_prog_put(attached);

out_unlock:
    mutex_unlock(&netns_bpf_mutex);
    return ret;
}
```

`to_netns_bpf_attach_type` 函数将BPF程序类型转换为网络命名空间支持的类型，目前支持 `BPF_FLOW_DISSECTOR` 和 `BPF_SK_LOOKUP` 两种类型的程序，如下：

```C
// file: include/linux/bpf-netns.h
static inline enum netns_bpf_attach_type
to_netns_bpf_attach_type(enum bpf_attach_type attach_type)
{
    switch (attach_type) {
    case BPF_FLOW_DISSECTOR: return NETNS_BPF_FLOW_DISSECTOR;
    case BPF_SK_LOOKUP: return NETNS_BPF_SK_LOOKUP;
    default: return NETNS_BPF_INVALID;
    }
}
```

#### 2 传统方式分离的实现

##### (1) BPF系统调用

传统方式使用`BPF_PROG_DETACH` BPF系统调用，如下：

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

`bpf_prog_detach` 在检查BPF程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理，flow_dissector类型的bpf程序对应 `netns_bpf_prog_detach` 处理函数。如下：

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
    ...
    case BPF_PROG_TYPE_FLOW_DISSECTOR:
        return netns_bpf_prog_detach(attr, ptype);
    default:
        return -EINVAL;
    }
}
```

##### (3) `netns_bpf_prog_detach`

`netns_bpf_prog_detach` 函数获取bpf程序后分离程序，实现如下：

```C
// file: kernel/bpf/net_namespace.c
int netns_bpf_prog_detach(const union bpf_attr *attr, enum bpf_prog_type ptype)
{
    enum netns_bpf_attach_type type;
    struct bpf_prog *prog;
    int ret;
    // attr属性检查
    if (attr->target_fd) return -EINVAL;
    // BPF程序类型转换为网络命名空间支持的类型
    type = to_netns_bpf_attach_type(attr->attach_type);
    if (type < 0) return -EINVAL;
    
    // 获取BPF程序
    prog = bpf_prog_get_type(attr->attach_bpf_fd, ptype);
    if (IS_ERR(prog)) return PTR_ERR(prog);

    mutex_lock(&netns_bpf_mutex);
    // 网络命名空间分离BPF程序
    ret = __netns_bpf_prog_detach(current->nsproxy->net_ns, type, prog);
    mutex_unlock(&netns_bpf_mutex);
    
    // 释放BPF程序
    bpf_prog_put(prog);
    return ret;
}
```

`__netns_bpf_prog_detach`函数完成真正的分离实现，如下：

```C
// file: kernel/bpf/net_namespace.c
static int __netns_bpf_prog_detach(struct net *net,
            enum netns_bpf_attach_type type, struct bpf_prog *old)
{
    struct bpf_prog *attached;
    // 通过link方式附加的程序不能分离
    if (!list_empty(&net->bpf.links[type])) return -EINVAL;

    attached = net->bpf.progs[type];
    // 未附加或者附加的程序不同时，返回错误
    if (!attached || attached != old) return -ENOENT;
    // 分离程序列表
    netns_bpf_run_array_detach(net, type);
    // 将网络命名空间中程序置空
    net->bpf.progs[type] = NULL;
    bpf_prog_put(attached);
    return 0;
}
```

### 4.2 Link方式附加和分离的内核实现

#### 1 Link方式附加的实现过程

##### (1) BPF系统调用

`BPF_LINK_CREATE` 是BPF系统调用，如下：

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
    case BPF_LINK_CREATE: err = link_create(&attr, uattr); break;
    ...
    }
    return err;
}
```

##### (2) `BPF_LINK_CREATE`

`link_create` 在检查BFP程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 `flow_dissector` 前缀设置的程序类型为`BPF_PROG_TYPE_FLOW_DISSECTOR`, 对应 `netns_bpf_link_create` 处理函数。如下：

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
    case BPF_PROG_TYPE_FLOW_DISSECTOR:
    case BPF_PROG_TYPE_SK_LOOKUP:
        ret = netns_bpf_link_create(attr, prog);
        break;
    ...
    }
    ...
}
```

##### (3) `netns_bpf_link_create`

`netns_bpf_link_create` 函数获取对应的网络命名空间后，设置`net_link`的信息后，附加BPF程序到网络命名空间上。如下：

```C
// file: kernel/bpf/net_namespace.c
int netns_bpf_link_create(const union bpf_attr *attr, struct bpf_prog *prog)
{
    enum netns_bpf_attach_type netns_type;
    struct bpf_netns_link *net_link;
    struct net *net;

    if (attr->link_create.flags) return -EINVAL;
    // BPF程序类型转换
    type = attr->link_create.attach_type;
    netns_type = to_netns_bpf_attach_type(type);
    if (netns_type < 0) return -EINVAL;

    // 获取指定的网络命名空间
    net = get_net_ns_by_fd(attr->link_create.target_fd);
    if (IS_ERR(net)) return PTR_ERR(net);
    // 创建 net_link
    net_link = kzalloc(sizeof(*net_link), GFP_USER);
    if (!net_link) { ... }
    // 设置link属性
    bpf_link_init(&net_link->link, BPF_LINK_TYPE_NETNS, &bpf_netns_link_ops, prog);
    net_link->net = net;
    net_link->type = type;
    net_link->netns_type = netns_type;

    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&net_link->link, &link_primer);
    if (err) { ... }
    // 附加BPF程序到网络命名空间
    err = netns_bpf_link_attach(net, &net_link->link, netns_type);
    if (err) { ... }

    put_net(net);
    // fd 和 file 进行关联
    return bpf_link_settle(&link_primer);
out_put_net:
    put_net(net);
    return err;
}
```

##### (4) `netns_bpf_link_attach`

`netns_bpf_link_attach`函数附加BPF程序到网络命名空间，如下：

```C
// file: kernel/bpf/net_namespace.c
static int netns_bpf_link_attach(struct net *net, struct bpf_link *link, enum netns_bpf_attach_type type)
{
    struct bpf_netns_link *net_link = container_of(link, struct bpf_netns_link, link);
    struct bpf_prog_array *run_array;
    ...

    mutex_lock(&netns_bpf_mutex);
    // 获取指定类型的BPF程序数量
    cnt = link_count(net, type);
    // 检查BPF程序数量是否超过最大限制，FLOW_DISSECTOR最大1个，SK_LOOKUP最大64个
    if (cnt >= netns_bpf_max_progs(type)) { ... }
    // Links和直接附加程序不兼容
    if (net->bpf.progs[type]) { ...	}

    switch (type) {
    case NETNS_BPF_FLOW_DISSECTOR:
        // FLOW_DISSECTOR类型BPF程序附加检查
        err = flow_dissector_bpf_prog_attach_check(net, link->prog); break;
    case NETNS_BPF_SK_LOOKUP: 
        // SK_LOOKUP不进行检查
        err = 0; break;
    default: err = -EINVAL; break;
    }
    if (err) goto out_unlock;

    // 分配BPF程序数组空间
    run_array = bpf_prog_array_alloc(cnt + 1, GFP_KERNEL);
    if (!run_array) { ...	}

    // 添加net_link到links列表中
    list_add_tail(&net_link->node, &net->bpf.links[type]);
    // 填充BPF程序到数组中
    fill_prog_array(net, type, run_array);
    // 替换BPF程序列表后，释放旧的程序列表
    run_array = rcu_replace_pointer(net->bpf.run_array[type], run_array, 
                    lockdep_is_held(&netns_bpf_mutex));
    bpf_prog_array_free(run_array);

    // 更新SK_LOOKUP和FLOW_DISSECTOR的计数，标记附加点已使用
    netns_bpf_attach_type_need(type);
out_unlock:
    mutex_unlock(&netns_bpf_mutex);
    return err;
}
```

#### 2 Link方式分离的实现过程

##### (1) `bpf_netns_link_ops`接口

在创建net_link时，设置了link的操作接口，`bpf_netns_link_ops` 是我们设置的`link->ops`，如下：

```C
// file: kernel/bpf/net_namespace.c
int netns_bpf_link_create(const union bpf_attr *attr, struct bpf_prog *prog)
{
    ...
    // 设置link属性
    bpf_link_init(&net_link->link, BPF_LINK_TYPE_NETNS, &bpf_netns_link_ops, prog);
    net_link->net = net;
    net_link->type = type;
    net_link->netns_type = netns_type;
    // 提供用户空间使用的 fd, id，anon_inode信息
    err = bpf_link_prime(&net_link->link, &link_primer);
    ...
}
```

定义如下：

```C
// file: kernel/bpf/net_namespace.c
static const struct bpf_link_ops bpf_netns_link_ops = {
    .release = bpf_netns_link_release,
    .dealloc = bpf_netns_link_dealloc,
    .detach = bpf_netns_link_detach,
    .update_prog = bpf_netns_link_update_prog,
    .fill_link_info = bpf_netns_link_fill_info,
    .show_fdinfo = bpf_netns_link_show_fdinfo,
};
```

##### (2) 更新bpf程序

* BPF系统调用
  
`BPF_LINK_UPDATE` 是BPF系统调用，如下：

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
    case BPF_LINK_UPDATE: err = link_update(&attr); break;
    ...
    }
    return err;
}
```

`link_update` 在获取link和设置的bpf程序后，调用`ops->update_prog` 接口。如下：

```C
// file: kernel/bpf/syscall.c
static int link_update(union bpf_attr *attr)
{
    ...
    // 检查设置的参数
    if (CHECK_ATTR(BPF_LINK_UPDATE)) return -EINVAL;

    flags = attr->link_update.flags;
    if (flags & ~BPF_F_REPLACE) return -EINVAL;

    // 获取 link 和 new_prog
    link = bpf_link_get_from_fd(attr->link_update.link_fd);
    if (IS_ERR(link)) return PTR_ERR(link);
    new_prog = bpf_prog_get(attr->link_update.new_prog_fd);
    if (IS_ERR(new_prog)) { ... }

    // 获取 old_prog
    if (flags & BPF_F_REPLACE) {
        old_prog = bpf_prog_get(attr->link_update.old_prog_fd);
        if (IS_ERR(old_prog)) { ...  }
    } else if (attr->link_update.old_prog_fd) { ... }

    // ops更新接口调用
    if (link->ops->update_prog)
        ret = link->ops->update_prog(link, new_prog, old_prog);
    else
        ret = -EINVAL;
    ...
}
```

* `net_link`更新

`.update_prog` 更新接口，更新当前设置的bpf程序，设置为 `bpf_netns_link_update_prog` 。实现如下:

```C
// file：kernel/bpf/net_namespace.c
static int bpf_netns_link_update_prog(struct bpf_link *link, 
            struct bpf_prog *new_prog, struct bpf_prog *old_prog)
{
    struct bpf_netns_link *net_link = container_of(link, struct bpf_netns_link, link);
    enum netns_bpf_attach_type type = net_link->netns_type;
    struct bpf_prog_array *run_array;

    // BPF程序及类型检查
    if (old_prog && old_prog != link->prog) return -EPERM;
    if (new_prog->type != link->prog->type) return -EINVAL;

    mutex_lock(&netns_bpf_mutex);
    // 网络命名空间检查
    net = net_link->net;
    if (!net || !check_net(net)) { ... }

    run_array = rcu_dereference_protected(net->bpf.run_array[type], lockdep_is_held(&netns_bpf_mutex));
    // 查找对应的net_link后替换对应的程序
    idx = link_index(net, type, net_link);
    // 更新程序数组中指定索引的程序
    ret = bpf_prog_array_update_at(run_array, idx, new_prog);
    if (ret) goto out_unlock;
    // 替换link关联的程序，释放旧的程序
    old_prog = xchg(&link->prog, new_prog);
    bpf_prog_put(old_prog);

out_unlock:
    mutex_unlock(&netns_bpf_mutex);
    return ret;
}
```

##### (3) 注销bpf程序

`.release` 释放接口，分离当前设置的bpf程序，设置为 `bpf_netns_link_release` 。实现如下:

```C
// file：kernel/bpf/net_namespace.c
static void bpf_netns_link_release(struct bpf_link *link)
{
    struct bpf_netns_link *net_link = container_of(link, struct bpf_netns_link, link);
    enum netns_bpf_attach_type type = net_link->netns_type;
    struct bpf_prog_array *old_array, *new_array;
    ...

    mutex_lock(&netns_bpf_mutex);
    // 获取网络命名空间
    net = net_link->net;
    if (!net) goto out_unlock;
    // 标记附加点未使用
    netns_bpf_attach_type_unneed(type);
    // 记录当前附加点的位置
    idx = link_index(net, type, net_link);
    // 从列表中删除附加点
    list_del(&net_link->node);

    cnt = link_count(net, type);
    if (!cnt) {
        // 计算为0时，用NULL替换`run_array`
        netns_bpf_run_array_detach(net, type);
        goto out_unlock;
    }
    old_array = rcu_dereference_protected(net->bpf.run_array[type], lockdep_is_held(&netns_bpf_mutex));
    new_array = bpf_prog_array_alloc(cnt, GFP_KERNEL);
    if (!new_array) {
        // 分配失败，用`dummy_bpf_prog`替换指定位置的BPF程序
        WARN_ON(bpf_prog_array_delete_safe_at(old_array, idx));
        goto out_unlock;
    }
    // 填充BPF程序数组，替换后释放旧的BPF程序数组
    fill_prog_array(net, type, new_array);
    rcu_assign_pointer(net->bpf.run_array[type], new_array);
    bpf_prog_array_free(old_array);

out_unlock:
    net_link->net = NULL;
    mutex_unlock(&netns_bpf_mutex);
}
```

### 4.3 FLOW_DISSECTOR的内核实现

#### 1 主要的结构介绍

`FLOW_DISSECTOR`主要使用的结构包括：

`struct flow_dissector` 表示支持的key集合，其定义如下：

```C
// file: include/net/flow_dissector.h
struct flow_dissector {
    unsigned int used_keys; /* each bit repesents presence of one key id */
    unsigned short int offset[FLOW_DISSECTOR_KEY_MAX];
};
```

`.used_keys`字段表示使用的key_id, `.offset`字段表示每个key的偏移量。`FLOW_DISSECTOR`支持多种KEY，如下：

```C
// file: include/net/flow_dissector.h
enum flow_dissector_key_id {
	FLOW_DISSECTOR_KEY_CONTROL, /* struct flow_dissector_key_control */
	FLOW_DISSECTOR_KEY_BASIC, /* struct flow_dissector_key_basic */
	FLOW_DISSECTOR_KEY_IPV4_ADDRS, /* struct flow_dissector_key_ipv4_addrs */
	FLOW_DISSECTOR_KEY_IPV6_ADDRS, /* struct flow_dissector_key_ipv6_addrs */
	FLOW_DISSECTOR_KEY_PORTS, /* struct flow_dissector_key_ports */
	FLOW_DISSECTOR_KEY_PORTS_RANGE, /* struct flow_dissector_key_ports */
	FLOW_DISSECTOR_KEY_ICMP, /* struct flow_dissector_key_icmp */
	FLOW_DISSECTOR_KEY_ETH_ADDRS, /* struct flow_dissector_key_eth_addrs */
	FLOW_DISSECTOR_KEY_TIPC, /* struct flow_dissector_key_tipc */
	FLOW_DISSECTOR_KEY_ARP, /* struct flow_dissector_key_arp */
	FLOW_DISSECTOR_KEY_VLAN, /* struct flow_dissector_key_vlan */
	FLOW_DISSECTOR_KEY_FLOW_LABEL, /* struct flow_dissector_key_tags */
	FLOW_DISSECTOR_KEY_GRE_KEYID, /* struct flow_dissector_key_keyid */
	FLOW_DISSECTOR_KEY_MPLS_ENTROPY, /* struct flow_dissector_key_keyid */
	FLOW_DISSECTOR_KEY_ENC_KEYID, /* struct flow_dissector_key_keyid */
	FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS, /* struct flow_dissector_key_ipv4_addrs */
	FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS, /* struct flow_dissector_key_ipv6_addrs */
	FLOW_DISSECTOR_KEY_ENC_CONTROL, /* struct flow_dissector_key_control */
	FLOW_DISSECTOR_KEY_ENC_PORTS, /* struct flow_dissector_key_ports */
	FLOW_DISSECTOR_KEY_MPLS, /* struct flow_dissector_key_mpls */
	FLOW_DISSECTOR_KEY_TCP, /* struct flow_dissector_key_tcp */
	FLOW_DISSECTOR_KEY_IP, /* struct flow_dissector_key_ip */
	FLOW_DISSECTOR_KEY_CVLAN, /* struct flow_dissector_key_vlan */
	FLOW_DISSECTOR_KEY_ENC_IP, /* struct flow_dissector_key_ip */
	FLOW_DISSECTOR_KEY_ENC_OPTS, /* struct flow_dissector_key_enc_opts */
	FLOW_DISSECTOR_KEY_META, /* struct flow_dissector_key_meta */
	FLOW_DISSECTOR_KEY_CT, /* struct flow_dissector_key_ct */
	FLOW_DISSECTOR_KEY_HASH, /* struct flow_dissector_key_hash */
	FLOW_DISSECTOR_KEY_NUM_OF_VLANS, /* struct flow_dissector_key_num_of_vlans */
	FLOW_DISSECTOR_KEY_PPPOE, /* struct flow_dissector_key_pppoe */
	FLOW_DISSECTOR_KEY_L2TPV3, /* struct flow_dissector_key_l2tpv3 */

	FLOW_DISSECTOR_KEY_MAX,
};
```

每个KEY使用不同的结构，如：`FLOW_DISSECTOR_KEY_CONTROL` 使用 `struct flow_dissector_key_control` 结构。

`struct flow_keys_basic` 或 `struct flow_keys` 结构表示解析skb后的结果，定义如下：

```C
// file: include/net/flow_dissector.h
struct flow_keys_basic {
    struct flow_dissector_key_control control;
    struct flow_dissector_key_basic basic;
};

// file: include/net/flow_dissector.h
struct flow_keys {
    struct flow_dissector_key_control control;
#define FLOW_KEYS_HASH_START_FIELD basic
    struct flow_dissector_key_basic basic __aligned(SIPHASH_ALIGNMENT);
    struct flow_dissector_key_tags tags;
    struct flow_dissector_key_vlan vlan;
    struct flow_dissector_key_vlan cvlan;
    struct flow_dissector_key_keyid keyid;
    struct flow_dissector_key_ports ports;
    struct flow_dissector_key_icmp icmp;
	/* 'addrs' must be the last member */
    struct flow_dissector_key_addrs addrs;
};
```

每个KEY在`struct flow_dissector` 中使用 `struct flow_dissector_key` 表示，如下：

```C
// file: include/net/flow_dissector.h
struct flow_dissector_key {
    enum flow_dissector_key_id key_id;
    size_t offset; /* offset of struct flow_dissector_key_* in target the struct */
};
```

`.key_id`表示key，`.offset`表示在`struct flow_keys_basic` 或 `struct flow_keys`的偏移量。

#### 2 内核中内置的流分析器

Linux内核中内置了三个`flow_dissector`， 分别为`flow_keys_dissector`(解析基础信息、地址信息、端口信息、VLAN等)，`flow_keys_dissector_symmetric`(解析基础信息、地址信息、端口信息) 和 `flow_keys_basic_dissector`(解析基础信息)。定义如下：

```C
// file: net/core/flow_dissector.c
static struct flow_dissector flow_keys_dissector_symmetric __read_mostly;

// file: net/core/flow_dissector.c
struct flow_dissector flow_keys_dissector __read_mostly;
EXPORT_SYMBOL(flow_keys_dissector);

// file: net/core/flow_dissector.c
struct flow_dissector flow_keys_basic_dissector __read_mostly;
EXPORT_SYMBOL(flow_keys_basic_dissector);
```

在`initcall`阶段初始化，如下：

```C
// file: net/core/flow_dissector.c
static int __init init_default_flow_dissectors(void)
{
    skb_flow_dissector_init(&flow_keys_dissector, 
                flow_keys_dissector_keys, ARRAY_SIZE(flow_keys_dissector_keys));
    skb_flow_dissector_init(&flow_keys_dissector_symmetric,
                flow_keys_dissector_symmetric_keys, ARRAY_SIZE(flow_keys_dissector_symmetric_keys));
    skb_flow_dissector_init(&flow_keys_basic_dissector,
                flow_keys_basic_dissector_keys, ARRAY_SIZE(flow_keys_basic_dissector_keys));
    return 0;
}
core_initcall(init_default_flow_dissectors);
```

以 `flow_keys_basic_dissector` 为例，`flow_keys_basic_dissector_keys` 定义了支持的KEY，定义如下：

```C
// file: net/core/flow_dissector.c
static const struct flow_dissector_key flow_keys_basic_dissector_keys[] = {
    {
        .key_id = FLOW_DISSECTOR_KEY_CONTROL,
        .offset = offsetof(struct flow_keys, control),
    },
    {
        .key_id = FLOW_DISSECTOR_KEY_BASIC,
        .offset = offsetof(struct flow_keys, basic),
    },
};
```

`skb_flow_dissector_init` 函数实现 `dissector_keys` 和 `dissector` 的关联。如下：

```C
// file: net/core/flow_dissector.c
void skb_flow_dissector_init(struct flow_dissector *flow_dissector,
                const struct flow_dissector_key *key, unsigned int key_count)
{
    unsigned int i;
    memset(flow_dissector, 0, sizeof(*flow_dissector));

    for (i = 0; i < key_count; i++, key++) {
        // 检查key的偏移量，和是否重复设置
        BUG_ON(key->offset > USHRT_MAX);
        BUG_ON(dissector_uses_key(flow_dissector, key->key_id));
        // 设置`dissector`中使用的key及其偏移量
        dissector_set_key(flow_dissector, key->key_id);
        flow_dissector->offset[key->key_id] = key->offset;
    }
    // 确保`dissector`总是包含`control`和`basic`字段
    BUG_ON(!dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_CONTROL));
    BUG_ON(!dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_BASIC));
}
```

`dissector_set_key`函数设置`dissector`使用的key，通过bit位指定。如下：

```C
// file: net/core/flow_dissector.c
static void dissector_set_key(struct flow_dissector *flow_dissector,
                enum flow_dissector_key_id key_id)
{
    flow_dissector->used_keys |= (1 << key_id);
}
```

#### 3 `flow_dissector`的执行过程

##### (1) 核心执行过程

`__skb_flow_dissect`是核心的执行函数，提取skb中`flow_keys`。实现如下：

```C
// file: net/core/flow_dissector.c
bool __skb_flow_dissect(const struct net *net, const struct sk_buff *skb,
            struct flow_dissector *flow_dissector, void *target_container, const void *data,
            __be16 proto, int nhoff, int hlen, unsigned int flags)
{
    struct flow_dissector_key_control *key_control;
    struct flow_dissector_key_basic *key_basic;
    struct flow_dissector_key_addrs *key_addrs;
    struct flow_dissector_key_tags *key_tags;
    struct flow_dissector_key_vlan *key_vlan;
    enum flow_dissect_ret fdret;
    enum flow_dissector_key_id dissector_vlan = FLOW_DISSECTOR_KEY_MAX;
    bool mpls_el = false;
    int mpls_lse = 0;
    int num_hdrs = 0;
    u8 ip_proto = 0;
    bool ret;
    
    // data不存在时，从skb中获取data、协议、网络头的偏移位置和长度
    if (!data) {
        data = skb->data;
        proto = skb_vlan_tag_present(skb) ? skb->vlan_proto : skb->protocol;
        nhoff = skb_network_offset(skb);
        hlen = skb_headlen(skb);
        ...
    }
    // 获取`key_control`和`key_basic`
    key_control = skb_flow_dissector_target(flow_dissector, 
                    FLOW_DISSECTOR_KEY_CONTROL, target_container);
    key_basic = skb_flow_dissector_target(flow_dissector,
                    FLOW_DISSECTOR_KEY_BASIC, target_container);
    // 获取网络命名空间
    if (skb) {
        if (!net) {
            if (skb->dev) net = dev_net(skb->dev);
            else if (skb->sk) net = sock_net(skb->sk);
        }
    }

    WARN_ON_ONCE(!net);
    if (net) {
        enum netns_bpf_attach_type type = NETNS_BPF_FLOW_DISSECTOR;
        struct bpf_prog_array *run_array;
        
        rcu_read_lock();
        // 从`init_net`或`net`命名空间中获取`FLOW_DISSECTOR` BPF程序列表
        run_array = rcu_dereference(init_net.bpf.run_array[type]);
        if (!run_array)
            run_array = rcu_dereference(net->bpf.run_array[type]);

        if (run_array) {
            struct bpf_flow_keys flow_keys;
            // 设置BPF程序运行的上下文
            struct bpf_flow_dissector ctx = {
                .flow_keys = &flow_keys,
                .data = data,
                .data_end = data + hlen,
            };
            __be16 n_proto = proto;
            struct bpf_prog *prog;
            u32 result;

            if (skb) {
                ctx.skb = skb;
                n_proto = skb->protocol;
            }
            // 获取第一个BPF程序后，运行
            prog = READ_ONCE(run_array->items[0].prog);
            result = bpf_flow_dissect(prog, &ctx, n_proto, nhoff, hlen, flags);
            // `CONTINUE`时，使用内核中默认的`dissector`
            if (result == BPF_FLOW_DISSECTOR_CONTINUE)
                goto dissect_continue;
            // 将BPF转换为目标
            __skb_flow_bpf_to_target(&flow_keys, flow_dissector, target_container);
            rcu_read_unlock();
            // 其他情况返回`true`(BPF_OK)，或`false`(其他值)
            return result == BPF_OK;
        }
dissect_continue:
        rcu_read_unlock();
    }

    // 解析`key_eth_addrs`和`key_num_of_vlans`
    if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
        struct ethhdr *eth = eth_hdr(skb);
        struct flow_dissector_key_eth_addrs *key_eth_addrs;
        key_eth_addrs = skb_flow_dissector_target(flow_dissector,
                            FLOW_DISSECTOR_KEY_ETH_ADDRS, target_container);
        memcpy(key_eth_addrs, eth, sizeof(*key_eth_addrs));
    }
    if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_NUM_OF_VLANS)) {
        struct flow_dissector_key_num_of_vlans *key_num_of_vlans;
        key_num_of_vlans = skb_flow_dissector_target(flow_dissector,
                                FLOW_DISSECTOR_KEY_NUM_OF_VLANS, target_container);
        key_num_of_vlans->num_of_vlans = 0;
    }

proto_again:
    fdret = FLOW_DISSECT_RET_CONTINUE;
    
    // 根据L3协议解析
    switch (proto) {
    case htons(ETH_P_IP): {
        const struct iphdr *iph;
        struct iphdr _iph;
        // 获取ip头
        iph = __skb_header_pointer(skb, nhoff, sizeof(_iph), data, hlen, &_iph);
        if (!iph || iph->ihl < 5) { fdret = FLOW_DISSECT_RET_OUT_BAD; break; }

        nhoff += iph->ihl * 4;
        ip_proto = iph->protocol;
        if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
            key_addrs = skb_flow_dissector_target(flow_dissector,
                                FLOW_DISSECTOR_KEY_IPV4_ADDRS, target_container);
            memcpy(&key_addrs->v4addrs.src, &iph->saddr, sizeof(key_addrs->v4addrs.src));
            memcpy(&key_addrs->v4addrs.dst, &iph->daddr, sizeof(key_addrs->v4addrs.dst));
            key_control->addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
        }
        // 分析ipv4信息
        __skb_flow_dissect_ipv4(skb, flow_dissector, target_container, data, iph);

        if (ip_is_fragment(iph)) {
            // IP分段的情况，判断返回结果
            key_control->flags |= FLOW_DIS_IS_FRAGMENT;
            if (iph->frag_off & htons(IP_OFFSET)) {  
                fdret = FLOW_DISSECT_RET_OUT_GOOD; break;
            } else {
                key_control->flags |= FLOW_DIS_FIRST_FRAG;
                if (!(flags & FLOW_DISSECTOR_F_PARSE_1ST_FRAG)) {
                    fdret = FLOW_DISSECT_RET_OUT_GOOD; break;
                }
            }
        }
        break;
    }
    case htons(ETH_P_IPV6): { 
        ... break; 
    }
    case htons(ETH_P_8021AD):
    case htons(ETH_P_8021Q): { 
        ... break; 
    }
    case htons(ETH_P_PPP_SES): { 
        ... break; 
    }
    ...
    ...
    default:
        fdret = FLOW_DISSECT_RET_OUT_BAD;
        break;
    }

    // 根据L3结果对应处理
    switch (fdret) {
    case FLOW_DISSECT_RET_OUT_GOOD:
        goto out_good;
    case FLOW_DISSECT_RET_PROTO_AGAIN:
        if (skb_flow_dissect_allowed(&num_hdrs))
            goto proto_again;
        goto out_good;
    case FLOW_DISSECT_RET_CONTINUE:
    case FLOW_DISSECT_RET_IPPROTO_AGAIN:
        break;
    case FLOW_DISSECT_RET_OUT_BAD:
    default:
        goto out_bad;
    }

ip_proto_again:
    fdret = FLOW_DISSECT_RET_CONTINUE;
    
    // IP协议处理
    switch (ip_proto) {
    case IPPROTO_GRE:
        if (flags & FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP) {
            fdret = FLOW_DISSECT_RET_OUT_GOOD;
            break;
        }
        fdret = __skb_flow_dissect_gre(skb, key_control, flow_dissector,
                    target_container, data, &proto, &nhoff, &hlen, flags);
        break;
    case NEXTHDR_HOP:
    case NEXTHDR_ROUTING:
    case NEXTHDR_DEST: {
        ... break;
    }
    case NEXTHDR_FRAGMENT: {
        ... break;
    }
    case IPPROTO_IPIP: {
        ... break;
    }
    case IPPROTO_IPV6: {
        ... break;
    }
    case IPPROTO_MPLS:
        proto = htons(ETH_P_MPLS_UC);
        fdret = FLOW_DISSECT_RET_PROTO_AGAIN;
        break;
    case IPPROTO_TCP:
        __skb_flow_dissect_tcp(skb, flow_dissector, target_container, data, nhoff, hlen);
        break;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        __skb_flow_dissect_icmp(skb, flow_dissector, target_container, data, nhoff, hlen);
        break;
    case IPPROTO_L2TP:
        __skb_flow_dissect_l2tpv3(skb, flow_dissector, target_container, data, nhoff, hlen);
        break;
    default:
        break;
    }

    // 不是分片时，获取端口信息
    if (!(key_control->flags & FLOW_DIS_IS_FRAGMENT))
        __skb_flow_dissect_ports(skb, flow_dissector, target_container, data, nhoff, ip_proto, hlen);

    // 根据IP结果对应处理
    switch (fdret) {
    case FLOW_DISSECT_RET_PROTO_AGAIN:
        if (skb_flow_dissect_allowed(&num_hdrs))
            goto proto_again;
        break;
    case FLOW_DISSECT_RET_IPPROTO_AGAIN:
        if (skb_flow_dissect_allowed(&num_hdrs))
            goto ip_proto_again;
        break;
    case FLOW_DISSECT_RET_OUT_GOOD:
    case FLOW_DISSECT_RET_CONTINUE:
        break;
    case FLOW_DISSECT_RET_OUT_BAD:
    default:
        goto out_bad;
    }

out_good:
    ret = true;

out:
    // 返回时设置`key_control`和`key_basic`
    key_control->thoff = min_t(u16, nhoff, skb ? skb->len : hlen);
    key_basic->n_proto = proto;
    key_basic->ip_proto = ip_proto;
    return ret;

out_bad:
    ret = false;
    goto out;
}
```

##### (2) BPF_FLOW_DISSECTOR执行过程

在设置`BPF_FLOW_DISSECTOR`程序时，调用`bpf_flow_dissect`函数执行bpf程序，如下：

```C
// file: net/core/flow_dissector.c
u32 bpf_flow_dissect(struct bpf_prog *prog, struct bpf_flow_dissector *ctx,
            __be16 proto, int nhoff, int hlen, unsigned int flags)
{
    struct bpf_flow_keys *flow_keys = ctx->flow_keys;
    u32 result;

    memset(flow_keys, 0, sizeof(*flow_keys));
    flow_keys->n_proto = proto;
    flow_keys->nhoff = nhoff;
    flow_keys->thoff = flow_keys->nhoff;

    BUILD_BUG_ON((int)BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG !=
                (int)FLOW_DISSECTOR_F_PARSE_1ST_FRAG);
    BUILD_BUG_ON((int)BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL !=
                (int)FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);
    BUILD_BUG_ON((int)BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP !=
                (int)FLOW_DISSECTOR_F_STOP_AT_ENCAP);
    flow_keys->flags = flags;

    // 在同一个CPU上运行BPF程序
    result = bpf_prog_run_pin_on_cpu(prog, ctx);

    //确定`nhoff`和`thoff`
    flow_keys->nhoff = clamp_t(u16, flow_keys->nhoff, nhoff, hlen);
    flow_keys->thoff = clamp_t(u16, flow_keys->thoff, flow_keys->nhoff, hlen);

    return result;
}
```

`__skb_flow_bpf_to_target`函数将获取的`flow_keys`设置到目标中，如下：

```C
// file: net/core/flow_dissector.c
static void __skb_flow_bpf_to_target(const struct bpf_flow_keys *flow_keys,
                struct flow_dissector *flow_dissector, void *target_container)
{
    struct flow_dissector_key_ports *key_ports = NULL;
    struct flow_dissector_key_control *key_control;
    struct flow_dissector_key_basic *key_basic;
    struct flow_dissector_key_addrs *key_addrs;
    struct flow_dissector_key_tags *key_tags;

    // `key_control`设置
    key_control = skb_flow_dissector_target(flow_dissector,
                    FLOW_DISSECTOR_KEY_CONTROL, target_container);
    key_control->thoff = flow_keys->thoff;
    if (flow_keys->is_frag) key_control->flags |= FLOW_DIS_IS_FRAGMENT;
    if (flow_keys->is_first_frag) key_control->flags |= FLOW_DIS_FIRST_FRAG;
    if (flow_keys->is_encap) key_control->flags |= FLOW_DIS_ENCAPSULATION;

    // `key_basic`设置
    key_basic = skb_flow_dissector_target(flow_dissector,
                    FLOW_DISSECTOR_KEY_BASIC, target_container);
    key_basic->n_proto = flow_keys->n_proto;
    key_basic->ip_proto = flow_keys->ip_proto;

    if (flow_keys->addr_proto == ETH_P_IP &&
        dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
        // IPV4地址设置
        key_addrs = skb_flow_dissector_target(flow_dissector,
                        FLOW_DISSECTOR_KEY_IPV4_ADDRS, target_container);
        key_addrs->v4addrs.src = flow_keys->ipv4_src;
        key_addrs->v4addrs.dst = flow_keys->ipv4_dst;
        key_control->addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
    } else if (flow_keys->addr_proto == ETH_P_IPV6 &&
        dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
        // IPV6地址设置
        key_addrs = skb_flow_dissector_target(flow_dissector,
                        FLOW_DISSECTOR_KEY_IPV6_ADDRS, target_container);
        memcpy(&key_addrs->v6addrs.src, &flow_keys->ipv6_src, sizeof(key_addrs->v6addrs.src));
        memcpy(&key_addrs->v6addrs.dst, &flow_keys->ipv6_dst, sizeof(key_addrs->v6addrs.dst));
        key_control->addr_type = FLOW_DISSECTOR_KEY_IPV6_ADDRS;
    }

    // `key_ports`设置
    if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_PORTS))
        key_ports = skb_flow_dissector_target(flow_dissector,
                        FLOW_DISSECTOR_KEY_PORTS, target_container);
    else if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_PORTS_RANGE))
        key_ports = skb_flow_dissector_target(flow_dissector,
                        FLOW_DISSECTOR_KEY_PORTS_RANGE, target_container);
    if (key_ports) {
        key_ports->src = flow_keys->sport;
        key_ports->dst = flow_keys->dport;
    }

    // `key_tags`设置
    if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_FLOW_LABEL)) {
        key_tags = skb_flow_dissector_target(flow_dissector,
                        FLOW_DISSECTOR_KEY_FLOW_LABEL, target_container);
        key_tags->flow_label = ntohl(flow_keys->flow_label);
    }
}
```

`skb_flow_dissector_target` 函数获取`keys`中对应的信息，如下：

```C
// file: net/core/flow_dissector.c
static inline void *skb_flow_dissector_target(struct flow_dissector *flow_dissector,
                    enum flow_dissector_key_id key_id, void *target_container)
{
    return ((char *)target_container) + flow_dissector->offset[key_id];
}
```

##### (3) IPV4信息解析过程

`__skb_flow_dissect_ipv4`函数解析ipv4信息，如下：

```C
// file: net/core/flow_dissector.c
static void _skb_flow_dissect_ipv4(const struct sk_buff *skb, struct flow_dissector *flow_dissector, 
            void *target_container, const void *data, const struct iphdr *iph)
{
    struct flow_dissector_key_ip *key_ip;
    if (!dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_IP)) return;

    // `key_ip`设置
    key_ip = skb_flow_dissector_target(flow_dissector,
                FLOW_DISSECTOR_KEY_IP, target_container);
    key_ip->tos = iph->tos;
    key_ip->ttl = iph->ttl;
}
```

##### (4) IPV6信息解析过程

`__skb_flow_dissect_ipv6`函数解析ipv6信息，如下：

```C
// file: net/core/flow_dissector.c
static void __skb_flow_dissect_ipv6(const struct sk_buff *skb, struct flow_dissector *flow_dissector,
            void *target_container, const void *data, const struct ipv6hdr *iph)
{
    struct flow_dissector_key_ip *key_ip;
    if (!dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_IP)) return;

    key_ip = skb_flow_dissector_target(flow_dissector,
                FLOW_DISSECTOR_KEY_IP, target_container);
    key_ip->tos = ipv6_get_dsfield(iph);
    key_ip->ttl = iph->hop_limit;
}
```

##### (5) TCP信息解析过程

`__skb_flow_dissect_tcp`函数解析tcp信息，如下：

```C
// file: net/core/flow_dissector.c
static void __skb_flow_dissect_tcp(const struct sk_buff *skb, struct flow_dissector *flow_dissector, 
            void *target_container, const void *data, int thoff, int hlen)
{
    struct flow_dissector_key_tcp *key_tcp;
    struct tcphdr *th, _th;
    
    if (!dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_TCP)) return;
    // 获取tcp头信息 
    th = __skb_header_pointer(skb, thoff, sizeof(_th), data, hlen, &_th);
    if (!th) return;
    
    if (unlikely(__tcp_hdrlen(th) < sizeof(_th))) return;

    key_tcp = skb_flow_dissector_target(flow_dissector,
                    FLOW_DISSECTOR_KEY_TCP, target_container);
    // 获取flags标记
    key_tcp->flags = (*(__be16 *) &tcp_flag_word(th) & htons(0x0FFF));
}
```

##### (6) 端口信息解析过程

`__skb_flow_dissect_ports`函数解析端口信息，如下：

```C
// file: net/core/flow_dissector.c
static void __skb_flow_dissect_ports(const struct sk_buff *skb, struct flow_dissector *flow_dissector,
            void *target_container, const void *data, int nhoff, u8 ip_proto, int hlen)
{
    enum flow_dissector_key_id dissector_ports = FLOW_DISSECTOR_KEY_MAX;
    struct flow_dissector_key_ports *key_ports;

    if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_PORTS))
        dissector_ports = FLOW_DISSECTOR_KEY_PORTS;
    else if (dissector_uses_key(flow_dissector, FLOW_DISSECTOR_KEY_PORTS_RANGE))
        dissector_ports = FLOW_DISSECTOR_KEY_PORTS_RANGE;

    if (dissector_ports == FLOW_DISSECTOR_KEY_MAX)
        return;
    // 获取`key_ports`后设置ports
    key_ports = skb_flow_dissector_target(flow_dissector, dissector_ports, target_container);
    key_ports->ports = __skb_flow_get_ports(skb, nhoff, ip_proto, data, hlen);
}
```

`__skb_flow_get_ports`函数获取上层协议的端口，如下：

```C
// file: net/core/flow_dissector.c
__be32 __skb_flow_get_ports(const struct sk_buff *skb, int thoff, u8 ip_proto, const void *data, int hlen)
{
    // 获取端口的偏移位置
    int poff = proto_ports_offset(ip_proto);
    // data不存在时，使用skb->data
    if (!data) {
        data = skb->data;
        hlen = skb_headlen(skb);
    }
    // 偏移位置存在时，获取端口
    if (poff >= 0) {
        __be32 *ports, _ports;
        ports = __skb_header_pointer(skb, thoff + poff, sizeof(_ports), data, hlen, &_ports);
        if (ports)
            return *ports;
    }
    return 0;
}
```

### 4.4 FLOW_DISSECTOR的使用场景

#### 1 解析skb中基本信息

##### (1) 实现过程

`skb_flow_dissect_flow_keys_basic` 函数解析skb中基本信息，包括：`control`和`basic` 信息。实现如下：

```C
// file: include/linux/skbuff.h
static inline bool skb_flow_dissect_flow_keys_basic(const struct net *net,
                const struct sk_buff *skb, struct flow_keys_basic *flow, 
                const void *data, __be16 proto, int nhoff, int hlen, unsigned int flags)
{
    memset(flow, 0, sizeof(*flow));
    return __skb_flow_dissect(net, skb, &flow_keys_basic_dissector, flow, data, proto, nhoff, hlen, flags);
}
```

##### (2) 使用的场景

`flow_keys_basic_dissector` 适用于获取skb中L2/L3/L4头信息，适用的场景如下：

* ETH确定以太网帧的报头长度

`eth_get_headlen` 函数确定以太网帧的报头长度，实现如下：

```C
// file: net/ethernet/eth.c
u32 eth_get_headlen(const struct net_device *dev, const void *data, u32 len)
{
    const unsigned int flags = FLOW_DISSECTOR_F_PARSE_1ST_FRAG;
    const struct ethhdr *eth = (const struct ethhdr *)data;
    struct flow_keys_basic keys;

    // 长度不足时，返回长度
    if (unlikely(len < sizeof(*eth))) return len;

    // 解析L2/L3剩余的头，检查L4，
    if (!skb_flow_dissect_flow_keys_basic(dev_net(dev), NULL, &keys, data,
                    eth->h_proto, sizeof(*eth), len, flags))
        return max_t(u32, keys.control.thoff, sizeof(*eth));
    
    // 解析L4头长度
    return min_t(u32, __skb_get_poff(NULL, data, &keys, len), len);
}
```

* 探测传输层(L4)头

`skb_probe_transport_header` 函数探测传输层位置，如下：

```C
// file: include/linux/skbuff.h
static inline void skb_probe_transport_header(struct sk_buff *skb)
{
    struct flow_keys_basic keys;
    if (skb_transport_header_was_set(skb)) return;
    // 正确解析后设置传输层的偏移位置
    if (skb_flow_dissect_flow_keys_basic(NULL, skb, &keys, NULL, 0, 0, 0, 0))
        skb_set_transport_header(skb, keys.control.thoff);
}
```

* 获取载荷数据的偏移位置

`skb_get_poff` 函数获取载荷数据的偏移量，如下：

```C
// file: net/core/flow_dissector.c
u32 skb_get_poff(const struct sk_buff *skb)
{
    struct flow_keys_basic keys;
    if (!skb_flow_dissect_flow_keys_basic(NULL, skb, &keys, NULL, 0, 0, 0, 0))
        return 0;
    // 正确解析后，获取偏移量
    return __skb_get_poff(skb, skb->data, &keys, skb_headlen(skb));
}
```

`__skb_get_poff` 函数根据不同的协议进行获取，如下：

```C
// file: net/core/flow_dissector.c
u32 __skb_get_poff(const struct sk_buff *skb, const void *data,
            const struct flow_keys_basic *keys, int hlen)
{
    u32 poff = keys->control.thoff;

    // 不是第一个的分段时，跳过L4头
    if ((keys->control.flags & FLOW_DIS_IS_FRAGMENT) &&
        !(keys->control.flags & FLOW_DIS_FIRST_FRAG))
        return poff;
    // 根据L4协议获取偏移位置
    switch (keys->basic.ip_proto) {
    case IPPROTO_TCP: {
        // 通过u8类型访问doff，避免不对齐的访问
        const u8 *doff;
        u8 _doff;
        doff = __skb_header_pointer(skb, poff + 12, sizeof(_doff), data, hlen, &_doff);
        if (!doff) return poff;
        // 跳过TCP头部的长度
        poff += max_t(u32, sizeof(struct tcphdr), (*doff & 0xF0) >> 2);
        break;
    }
    case IPPROTO_UDP:
    case IPPROTO_UDPLITE:
        // UDP和UDPLITE直接加上UDP头部长度
        poff += sizeof(struct udphdr);
        break;
    // 其他的情况，暂时不关心头部的扩展信息
    case IPPROTO_ICMP: poff += sizeof(struct icmphdr); break;
    case IPPROTO_ICMPV6: poff += sizeof(struct icmp6hdr); break;
    case IPPROTO_IGMP: poff += sizeof(struct igmphdr); break;
    case IPPROTO_DCCP: poff += sizeof(struct dccp_hdr); break;
    case IPPROTO_SCTP: poff += sizeof(struct sctphdr); break;
    }
    return poff;
}
```

#### 2 解析skb中key信息

##### (1) 实现过程

`skb_flow_dissect_flow_keys` 函数解析skb中key信息。实现如下：

```C
// file: include/linux/skbuff.h
static inline bool skb_flow_dissect_flow_keys(const struct sk_buff *skb,
                        struct flow_keys *flow, unsigned int flags)
{
    memset(flow, 0, sizeof(*flow));
    return __skb_flow_dissect(NULL, skb, &flow_keys_dissector, flow, NULL, 0, 0, 0, flags);
}
```

##### (2) 使用的场景

`flow_keys_dissector` 适用于获取skb中主要的key信息，适用的场景如下：

* 网卡驱动接收数据时引导数据包

在开启`RFS_ACCEL`(接收流控制加速)选项时，通过hash来引导数据包，通过网络设备的`.ndo_rx_flow_steer`接口实现的。以Intel网卡为例，其实现如下：

```C
static const struct net_device_ops ice_netdev_ops = {
    ...
#ifdef CONFIG_RFS_ACCEL
    .ndo_rx_flow_steer = ice_rx_flow_steer,
#endif
    ...
};
```

在`ice_rx_flow_steer`函数中解析skb中关键信息，实现如下：

```C
// file: drivers/net/ethernet/intel/ice/ice_arfs.c
int ice_rx_flow_steer(struct net_device *netdev, const struct sk_buff *skb, u16 rxq_idx, u32 flow_id)
{
    struct ice_netdev_priv *np = netdev_priv(netdev);
    struct ice_arfs_entry *arfs_entry;
    struct ice_vsi *vsi = np->vsi;
    struct flow_keys fk;
    ...

    // aRFS分配失败时返回错误
    if (unlikely(!vsi->arfs_fltr_list)) return -ENODEV;

    pf = vsi->back;
    if (skb->encapsulation) return -EPROTONOSUPPORT;
    //  解析skb中key信息
    if (!skb_flow_dissect_flow_keys(skb, &fk, 0)) return -EPROTONOSUPPORT;

    n_proto = fk.basic.n_proto;
    // L3仅支持IPV4和IPV6协议
    if ((n_proto == htons(ETH_P_IP) && !ip_is_fragment(ip_hdr(skb))) || n_proto == htons(ETH_P_IPV6))
        ip_proto = fk.basic.ip_proto;
    else
        return -EPROTONOSUPPORT;

    // L4仅支持TCP和UDP协议
    if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP) return -EPROTONOSUPPORT;
    // aRFS仅支持四元组
    if (!ice_arfs_is_perfect_flow_set(&pf->hw, n_proto, ip_proto)) return -EOPNOTSUPP;

    // 基于skb hash选择一个aRFS桶
    idx = skb_get_hash_raw(skb) & ICE_ARFS_LST_MASK;
    spin_lock_bh(&vsi->arfs_lock);
    // 遍历桶中的项
    hlist_for_each_entry(arfs_entry, &vsi->arfs_fltr_list[idx], list_entry) {
        struct ice_fdir_fltr *fltr_info;
        // 查找已存在的流
        if (arfs_entry->flow_id != flow_id) continue;

        fltr_info = &arfs_entry->fltr_info;
        ret = fltr_info->fltr_id;
        if (fltr_info->q_index == rxq_idx || arfs_entry->fltr_state != ICE_ARFS_ACTIVE)
            goto out;

        // 更新队列转发到现有的流
        fltr_info->q_index = rxq_idx;
        arfs_entry->fltr_state = ICE_ARFS_INACTIVE;
        ice_arfs_update_active_fltr_cntrs(vsi, arfs_entry, false);
        goto out_schedule_service_task;
    }
    // 流不存在时，创建流
    arfs_entry = ice_arfs_build_entry(vsi, &fk, rxq_idx, flow_id);
    if (!arfs_entry) { ret = -ENOMEM; goto out; }
    // 设置流信息
    ret = arfs_entry->fltr_info.fltr_id;
    INIT_HLIST_NODE(&arfs_entry->list_entry);
    hlist_add_head(&arfs_entry->list_entry, &vsi->arfs_fltr_list[idx]);
out_schedule_service_task:
    // 唤醒服务的task
    ice_service_task_schedule(pf);
out:
    spin_unlock_bh(&vsi->arfs_lock);
    return ret;
}
```

* IPV4确定输入路由

在接收IPV4的网络包后，通过`ip_route_input_slow`函数确定输入路由过程中，调用 `fib4_rules_early_flow_dissect` 函数分析skb中L4协议、源/目的端口。如下：

```C
// file: net/ipv4/route.c
static int ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                    u8 tos, struct net_device *dev, struct fib_result *res)
{
    ...
    fl4.flowi4_l3mdev = 0;
    fl4.flowi4_oif = 0;
    fl4.flowi4_iif = dev->ifindex;
    fl4.flowi4_mark = skb->mark;
    fl4.flowi4_tos = tos;
    fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
    fl4.flowi4_flags = 0;
    fl4.daddr = daddr;
    fl4.saddr = saddr;
    fl4.flowi4_uid = sock_net_uid(net, NULL);
    fl4.flowi4_multipath_hash = 0;

    if (fib4_rules_early_flow_dissect(net, skb, &fl4, &_flkeys)) {
        flkeys = &_flkeys;
    } else {
        fl4.flowi4_proto = 0;
        fl4.fl4_sport = 0;
        fl4.fl4_dport = 0;
    }
    ...
}
```

`fib4_rules_early_flow_dissect` 函数在需要路由分析时，解析skb中L4协议、源/目的端口，如下：

```C
// file: include/net/ip_fib.h
static inline bool fib4_rules_early_flow_dissect(struct net *net,
                struct sk_buff *skb, struct flowi4 *fl4, struct flow_keys *flkeys)
{
    unsigned int flag = FLOW_DISSECTOR_F_STOP_AT_ENCAP;
    // 不需要路由分析时，返回
    if (!net->ipv4.fib_rules_require_fldissect) return false;

    // 分析skb后，设置L4协议、源/目的端口
    skb_flow_dissect_flow_keys(skb, flkeys, flag);
    fl4->fl4_sport = flkeys->ports.src;
    fl4->fl4_dport = flkeys->ports.dst;
    fl4->flowi4_proto = flkeys->basic.ip_proto;

    return true;
}
```

此外，`fib_multipath_hash`函数确定多路径路由hash过程中，同样调用 `skb_flow_dissect_flow_keys` 函数分析skb中信息。

* IPV6确定输入路由

在接收IPV6的网络包后，通过`ip6_route_input`函数确定输入路由过程中，调用 `fib6_rules_early_flow_dissect` 函数分析skb中L4协议、源/目的端口。如下：

```C
// file: net/ipv6/route.c
void ip6_route_input(struct sk_buff *skb)
{
    struct flowi6 fl6 = {
        .flowi6_iif = skb->dev->ifindex,
        .daddr = iph->daddr,
        .saddr = iph->saddr,
        .flowlabel = ip6_flowinfo(iph),
        .flowi6_mark = skb->mark,
        .flowi6_proto = iph->nexthdr,
    };
    ...
    if (fib6_rules_early_flow_dissect(net, skb, &fl6, &_flkeys))
        flkeys = &_flkeys;
    ...
}
```

`fib6_rules_early_flow_dissect` 函数在需要路由分析时，解析skb中L4协议、源/目的端口，如下：

```C
// file: include/net/ip6_fib.h
static inline bool fib6_rules_early_flow_dissect(struct net *net,
                    struct sk_buff *skb, struct flowi6 *fl6, struct flow_keys *flkeys)
{
    unsigned int flag = FLOW_DISSECTOR_F_STOP_AT_ENCAP;

    if (!net->ipv6.fib6_rules_require_fldissect)
        return false;
    // 分析skb后，设置L4协议、源/目的端口
    skb_flow_dissect_flow_keys(skb, flkeys, flag);
    fl6->fl6_sport = flkeys->ports.src;
    fl6->fl6_dport = flkeys->ports.dst;
    fl6->flowi6_proto = flkeys->basic.ip_proto;
    
    return true;
}
```

此外，`rt6_multipath_hash`函数确定多路径路由hash过程中，同样调用 `skb_flow_dissect_flow_keys` 函数分析skb中信息。

* 获取skb的hash值

```C
// file: net/core/flow_dissector.c
static inline u32 ___skb_get_hash(const struct sk_buff *skb,
                struct flow_keys *keys, const siphash_key_t *keyval)
{
    // 分析skb
    skb_flow_dissect_flow_keys(skb, keys, FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);
    // 根据keys计算hash
    return __flow_hash_from_keys(keys, keyval);
}
```

* `cls_flow`计算classid

在使用`flow`类型的`tcf_proto`时，对网络数据包进行分类。在设置参与计算的key时，获取skb中对应的值，如下：

```C
// file: net/sched/cls_flow.c
static struct tcf_proto_ops cls_flow_ops __read_mostly = {
    .kind       = "flow",
    .classify   = flow_classify,
    ...
};
```

`flow_classify`函数实现网络数据包的分类，如下：

```C
// file: net/sched/cls_flow.c
TC_INDIRECT_SCOPE int flow_classify(struct sk_buff *skb,
                    const struct tcf_proto *tp, struct tcf_result *res)
{
    struct flow_head *head = rcu_dereference_bh(tp->root);
    struct flow_filter *f;
    u32 keymask;
    u32 classid;
    unsigned int n, key;
    int r;
    // 遍历列表
    list_for_each_entry_rcu(f, &head->filters, list) {
        u32 keys[FLOW_KEY_MAX + 1];
        struct flow_keys flow_keys;
        
         (!tcf_em_tree_match(skb, &f->ematches, NULL)) continue;

        keymask = f->keymask;
        // 需要获取key时，分析skb中的key
        if (keymask & FLOW_KEYS_NEEDED)
            skb_flow_dissect_flow_keys(skb, &flow_keys, 0);

        for (n = 0; n < f->nkeys; n++) {
            key = ffs(keymask) - 1;
            keymask &= ~(1 << key);
            keys[n] = flow_key_get(skb, key, &flow_keys);
        }
        // 计算classid
        if (f->mode == FLOW_MODE_HASH)
            classid = jhash2(keys, f->nkeys, f->hashrnd);
        else {
            classid = keys[0];
            classid = (classid & f->mask) ^ f->xor;
            classid = (classid >> f->rshift) + f->addend;
        }
        if (f->divisor) classid %= f->divisor;
        // 设置返回结果的class、classid
        res->class   = 0;
        res->classid = TC_H_MAKE(f->baseclass, f->baseclass + classid);

        // 执行action
        r = tcf_exts_exec(skb, &f->exts, res);
        if (r < 0) continue;
        return r;
    }
    return -1;
}
```

#### 3 解析skb中symmetric信息

##### (1) 实现过程

`__skb_get_hash_symmetric` 函数解析skb中symmetric信息后，计数hash。实现如下：

```C
// file: net/core/flow_dissector.c
u32 __skb_get_hash_symmetric(const struct sk_buff *skb)
{
    struct flow_keys keys;
    __flow_hash_secret_init();

    memset(&keys, 0, sizeof(keys));
    __skb_flow_dissect(NULL, skb, &flow_keys_dissector_symmetric,
                &keys, NULL, 0, 0, 0, FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);

    return __flow_hash_from_keys(&keys, &hashrnd);
}
EXPORT_SYMBOL_GPL(__skb_get_hash_symmetric);
```

##### (2) 使用场景

* NFT_HASH_SYM

nft表达式中计算`hash`时，选择`NFT_HASH_SYM`方式时，在计算值时调用。如下：

```C
// file: net/netfilter/nft_hash.c
static const struct nft_expr_ops nft_symhash_ops = {
    .type       = &nft_hash_type,
    .size       = NFT_EXPR_SIZE(sizeof(struct nft_symhash)),
    .eval       = nft_symhash_eval,
    .init       = nft_symhash_init,
    .dump       = nft_symhash_dump,
    .reduce     = nft_symhash_reduce,
};
```

`nft_symhash_eval`函数计算symhash，如下：

```C
// file: net/netfilter/nft_hash.c
static void nft_symhash_eval(const struct nft_expr *expr,
                struct nft_regs *regs, const struct nft_pktinfo *pkt)
{
    struct nft_symhash *priv = nft_expr_priv(expr);
    struct sk_buff *skb = pkt->skb;
    u32 h;

    h = reciprocal_scale(__skb_get_hash_symmetric(skb), priv->modulus);
    regs->data[priv->dreg] = h + priv->offset;
}
```

* `AF_PACKET`计算`FANOUT_HASH`

在`AF_PACKET`使用fanout接收数据时，根据类型计算索引时使用，如下：

```C
// file: net/packet/af_packet.c
static int packet_rcv_fanout(struct sk_buff *skb, struct net_device *dev,
            struct packet_type *pt, struct net_device *orig_dev)
{
    struct packet_fanout *f = pt->af_packet_priv;
    unsigned int num = READ_ONCE(f->num_members);
    struct net *net = read_pnet(&f->net);
    struct packet_sock *po;
    unsigned int idx;

    if (!net_eq(dev_net(dev), net) || !num) { kfree_skb(skb); return 0; }
    if (fanout_has_flag(f, PACKET_FANOUT_FLAG_DEFRAG)) {
        skb = ip_check_defrag(net, skb, IP_DEFRAG_AF_PACKET);
        if (!skb) return 0;
    }

    switch (f->type) {
    case PACKET_FANOUT_HASH:
    default:
        // 使用HASH，默认方式
        idx = fanout_demux_hash(f, skb, num);
        break;
        ...
    }
    
    if (fanout_has_flag(f, PACKET_FANOUT_FLAG_ROLLOVER))
        idx = fanout_demux_rollover(f, skb, idx, true, num);
    // 选择sk
    po = pkt_sk(rcu_dereference(f->arr[idx]));
    return po->prot_hook.func(skb, dev, &po->prot_hook, orig_dev);
}
```

`fanout_demux_hash` 函数计算hash值，如下：

```C
// file: net/packet/af_packet.c
static unsigned int fanout_demux_hash(struct packet_fanout *f,
                struct sk_buff *skb, unsigned int num)
{
    return reciprocal_scale(__skb_get_hash_symmetric(skb), num);
}
```

#### 3  自定义skb中的解析信息

##### (1) 实现过程

`skb_flow_dissect` 函数自定义`flow_dissector`，解析skb中需要的信息，实现如下：

```C
// file: include/linux/skbuff.h
static inline bool skb_flow_dissect(const struct sk_buff *skb, 
        struct flow_dissector *flow_dissector, void *target_container, unsigned int flags)
{
    return __skb_flow_dissect(NULL, skb, flow_dissector, target_container, NULL, 0, 0, 0, flags);
}
```

##### (2) 使用场景

* `cls_flower`

在使用`flower`类型的`tcf_proto`时，对网络数据包进行分类。获取skb中对应的值，如下：

```C
// file: net/sched/cls_flower.c
static struct tcf_proto_ops cls_fl_ops __read_mostly = {
    .kind       = "flower",
    .classify   = fl_classify,
    .init       = fl_init,
    .destroy    = fl_destroy,
    ...
};
```

`fl_classify`函数实现网络数据包的分类，如下：

```C
// file: net/sched/cls_flower.c
TC_INDIRECT_SCOPE int fl_classify(struct sk_buff *skb,
                    const struct tcf_proto *tp, struct tcf_result *res)
{
    struct cls_fl_head *head = rcu_dereference_bh(tp->root);
    bool post_ct = tc_skb_cb(skb)->post_ct;
    u16 zone = tc_skb_cb(skb)->zone;
    struct fl_flow_key skb_key;
    struct fl_flow_mask *mask;
    struct cls_fl_filter *f;
    // 变量列表
    list_for_each_entry_rcu(mask, &head->masks, list) {
        // 初始化`control`和`basic`
        flow_dissector_init_keys(&skb_key.control, &skb_key.basic);
        fl_clear_masked_range(&skb_key, mask);

        // 获取`meta`信息
        skb_flow_dissect_meta(skb, &mask->dissector, &skb_key);
        skb_key.basic.n_proto = skb_protocol(skb, false);
        // 获取`tunnel_info`
        skb_flow_dissect_tunnel_info(skb, &mask->dissector, &skb_key);
        // 获取`conntrack`信息
        skb_flow_dissect_ct(skb, &mask->dissector, &skb_key,
            fl_ct_info_to_flower_map, ARRAY_SIZE(fl_ct_info_to_flower_map), post_ct, zone);
        // 获取hash信息
        skb_flow_dissect_hash(skb, &mask->dissector, &skb_key);
        // 获取`key`信息
        skb_flow_dissect(skb, &mask->dissector, &skb_key,
            FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP);

        // 根据key获取filter
        f = fl_mask_lookup(mask, &skb_key);
        if (f && !tc_skip_sw(f->flags)) {
            *res = f->res;
            // 执行`action`
            return tcf_exts_exec(skb, &f->exts, res);
        }
    }
    return -1;
}
```

`test_flow_dissector.sh` 进行测试时，使用的就是该场景。如下：

```bash
# file: ../src/test_flow_dissector.sh
tc filter add dev lo parent ffff: protocol ip pref 1337 flower ip_proto \
	udp src_port 9 action drop
```

## 5 总结

本文通过`test_flow_dissector`示例程序分析了BPF在流分析器中应用，通过将BPF程序挂载到网络命名空间中，实现对接收数据流的分析。

## 参考资料

* [BPF_PROG_TYPE_FLOW_DISSECTOR](https://www.kernel.org/doc/html/v6.2/bpf/prog_flow_dissector.html)
* [Linux Ethernet Bonding Driver HOWTO](https://www.kernel.org/doc/html/v6.2/networking/bonding.html)
* [Linux网络栈的性能缩放](https://zhuanlan.zhihu.com/p/148756667)