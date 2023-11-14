# STRUCT_OPS的内核实现

## 0 前言

在上一篇文章中我们分析了BPF在cgroup中应用，可以在cgroup级别对socket进行动态控制。今天，我们借助`bpf_dctcp`示例程序分析BPF在TCP中的另一项应用，动态设置拥塞控制算法。

## 1 简介

`STRUCT_OPS`允许BPF程序实现一些特定的内核函数指针，具有替换内核中`ops`结构(`struct xxx_ops`)的能力。其中第一个用例是用BPF实现TCP拥塞控制算法（即实现`struct tcp_congestion_ops`）。

## 2 `bpf_dctcp`示例程序

### 2.1 BPF程序

BPF程序源码参见[bpf_dctcp.c](../src/bpf_dctcp.c)，主要内容如下：

```C
struct dctcp {
    __u32 old_delivered;
    __u32 old_delivered_ce;
    __u32 prior_rcv_nxt;
    __u32 dctcp_alpha;
    __u32 next_seq;
    __u32 ce_state;
    __u32 loss_cwnd;
};

SEC("struct_ops/dctcp_init")
void BPF_PROG(dctcp_init, struct sock *sk)
{
    ...
}

SEC("struct_ops/dctcp_ssthresh")
__u32 BPF_PROG(dctcp_ssthresh, struct sock *sk)
{
    struct dctcp *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    ca->loss_cwnd = tp->snd_cwnd;
    return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->dctcp_alpha) >> 11U), 2U);
}

SEC("struct_ops/dctcp_cwnd_undo")
__u32 BPF_PROG(dctcp_cwnd_undo, struct sock *sk)
{
    const struct dctcp *ca = inet_csk_ca(sk);
    return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

extern void tcp_reno_cong_avoid(struct sock *sk, __u32 ack, __u32 acked) __ksym;

SEC("struct_ops/dctcp_reno_cong_avoid")
void BPF_PROG(dctcp_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
    tcp_reno_cong_avoid(sk, ack, acked);
}

SEC(".struct_ops")
struct tcp_congestion_ops dctcp = {
    .init       = (void *)dctcp_init,
    .in_ack_event   = (void *)dctcp_update_alpha,
    .cwnd_event = (void *)dctcp_cwnd_event,
    .ssthresh   = (void *)dctcp_ssthresh,
    .cong_avoid = (void *)dctcp_cong_avoid,
    .undo_cwnd  = (void *)dctcp_cwnd_undo,
    .set_state  = (void *)dctcp_state,
    .flags      = TCP_CONG_NEEDS_ECN,
    .name       = "bpf_dctcp",
};
```

### 2.2 用户程序

用户程序源码参见[bpf_tcp_ca.c](../src/bpf_tcp_ca.c)，主要内容如下：

#### 1 附加BPF程序

```C
static void test_dctcp(void)
{
    struct bpf_dctcp *dctcp_skel;
    struct bpf_link *link;
    // 打开并加载BPF程序
    dctcp_skel = bpf_dctcp__open_and_load();
    if (CHECK(!dctcp_skel, "bpf_dctcp__open_and_load", "failed\n"))	return;
    // 附加`struct_ops`
    link = bpf_map__attach_struct_ops(dctcp_skel->maps.dctcp);
    ...
    // 进行测试
    do_test("bpf_dctcp", dctcp_skel->maps.sk_stg_map);
    ...
    // 销毁link和BPF程序
    bpf_link__destroy(link);
    bpf_dctcp__destroy(dctcp_skel);
}

static void do_test(const char *tcp_ca, const struct bpf_map *sk_stg_map)
{
    struct sockaddr_in6 sa6 = {};
    ...
    WRITE_ONCE(stop, 0);
    // 创建server和client的socket
    lfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (CHECK(lfd == -1, "socket", "errno:%d\n", errno)) return;
    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (CHECK(fd == -1, "socket", "errno:%d\n", errno)) { close(lfd); return; }
    
    // 设置tcp_ca，TCP拥塞控制算法
    if (settcpca(lfd, tcp_ca) || settcpca(fd, tcp_ca) ||
        settimeo(lfd, 0) || settimeo(fd, 0))
        goto done;

    ...
    ...

done:
    close(lfd);
    close(fd);
}

static int settcpca(int fd, const char *tcp_ca)
{
    int err;
    // 设置TCP拥塞控制算法
    err = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, tcp_ca, strlen(tcp_ca));
    if (CHECK(err == -1, "setsockopt(fd, TCP_CONGESTION)", "errno:%d\n", errno))
        return -1;
    return 0;
}
```

#### 2 读取数据过程

`bpf_tcp_ca` 程序是适用于数据中心的TCP拥塞控制算法，测试程序通过发送、接收的数据量判断是否完全发送。

### 2.3 编译运行

`bpf_tcp_ca`程序是Linux内核自带的测试程序，在`tools/testing/selftests/bpf/prog_tests/`目录下。编译后运行，如下：

```bash
$ cd tools/testing/selftests/bpf/
$ sudo make
$ sudo ./test_progs -t bpf_tcp_ca -vvv
bpf_testmod.ko is already unloaded.
Loading bpf_testmod.ko...
Failed to load bpf_testmod.ko into the kernel: -8
WARNING! Selftests relying on bpf_testmod.ko will be skipped.
libbpf: loading object 'bpf_dctcp' from buffer
libbpf: elf: section(2) .symtab, size 1488, link 1, flags 0, type=2
libbpf: elf: section(3) struct_ops/dctcp_init, size 776, link 0, flags 6, type=1
libbpf: sec 'struct_ops/dctcp_init': found program 'dctcp_init' at insn offset 0 (0 bytes), code size 97 insns (776 bytes)
....
test_dctcp:PASS:bpf_dctcp__open_and_load 0 nsec
test_dctcp:PASS:bpf_map__attach_struct_ops 0 nsec
do_test:PASS:socket 0 nsec
do_test:PASS:socket 0 nsec
settcpca:PASS:setsockopt(fd, TCP_CONGESTION) 0 nsec
settcpca:PASS:setsockopt(fd, TCP_CONGESTION) 0 nsec
do_test:PASS:bind 0 nsec
do_test:PASS:getsockname 0 nsec
do_test:PASS:listen 0 nsec
do_test:PASS:bpf_map_update_elem(sk_stg_map) 0 nsec
do_test:PASS:connect 0 nsec
do_test:PASS:bpf_map_lookup_elem(sk_stg_map) 0 nsec
do_test:PASS:pthread_create 0 nsec
server:PASS:send 0 nsec
do_test:PASS:recv 0 nsec
do_test:PASS:pthread_join 0 nsec
test_dctcp:PASS:Unexpected stg_result 0 nsec
#20/1    bpf_tcp_ca/dctcp:OK
...
```

## 3 struct_ops附加BPF的过程

`struct_ops`支持多种前缀类型的bpf程序，libbpf中支持struct_ops BPF程序如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("struct_ops+",      STRUCT_OPS, 0, SEC_NONE),
    SEC_DEF("struct_ops.s+",    STRUCT_OPS, 0, SEC_SLEEPABLE),
    ...
};
```

struct_ops BPF程序都不支持自动附加，需要手动附加。

### 3.1 `.struct_ops`的创建过程

`SEC(".struct_ops")` 标记的结构在BPF程序中编译为`struct_ops_maps` ，在打开阶段通过 `bpf_object_init_struct_ops` 函数进行初始化。实现如下：

```C
// file: libbpf/src/libbpf.c
static int bpf_object_init_struct_ops(struct bpf_object *obj)
{
    int err;
    err = init_struct_ops_maps(obj, STRUCT_OPS_SEC, obj->efile.st_ops_shndx, obj->efile.st_ops_data, 0);
    err = err ?: init_struct_ops_maps(obj, STRUCT_OPS_LINK_SEC, obj->efile.st_ops_link_shndx,
                        obj->efile.st_ops_link_data, BPF_F_LINK);
    return err;
}
```

`STRUCT_OPS_SEC`  和 `STRUCT_OPS_LINK_SEC` 定义如下：

```C
// file: libbpf/src/libbpf.c
#define STRUCT_OPS_SEC ".struct_ops"
#define STRUCT_OPS_LINK_SEC ".struct_ops.link"
```

`init_struct_ops_maps` 函数初始化`.struct_ops`，实现如下：

```C
// file: libbpf/src/libbpf.c
static int init_struct_ops_maps(struct bpf_object *obj, const char *sec_name,
                        int shndx, Elf_Data *data, __u32 map_flags)
{
    const struct btf_type *type, *datasec;
    const struct btf_var_secinfo *vsi;
    struct bpf_struct_ops *st_ops;
    struct bpf_map *map;
    ...

    if (shndx == -1) return 0;

    // 从BTF中获取secid
    btf = obj->btf;
    datasec_id = btf__find_by_name_kind(btf, sec_name, BTF_KIND_DATASEC);
    if (datasec_id < 0) { ... }
    // 获取sec变量信息
    datasec = btf__type_by_id(btf, datasec_id);
    vsi = btf_var_secinfos(datasec);
    for (i = 0; i < btf_vlen(datasec); i++, vsi++) {
        // 获取`vsi`变量
        type = btf__type_by_id(obj->btf, vsi->type);
        var_name = btf__name_by_offset(obj->btf, type->name_off);
        type_id = btf__resolve_type(obj->btf, vsi->type);
        if (type_id < 0) { ... }
        // 获取`btf`中`struct_ops`类型和名称
        type = btf__type_by_id(obj->btf, type_id);
        tname = btf__name_by_offset(obj->btf, type->name_off);
        if (!tname[0]) { ... }
        if (!btf_is_struct(type)) { ... }
        // 添加`map`到`obj`中
        map = bpf_object__add_map(obj);
        if (IS_ERR(map)) return PTR_ERR(map);
        // 设置`map`段信息
        map->sec_idx = shndx;
        map->sec_offset = vsi->offset;
        map->name = strdup(var_name);
        if (!map->name) return -ENOMEM;
        // 设置`map`定义信息
        map->def.type = BPF_MAP_TYPE_STRUCT_OPS;
        map->def.key_size = sizeof(int);
        map->def.value_size = type->size;
        map->def.max_entries = 1;
        map->def.map_flags = map_flags;
        // 分配并设置`st_ops`信息
        map->st_ops = calloc(1, sizeof(*map->st_ops));
        if (!map->st_ops) return -ENOMEM;
        st_ops = map->st_ops;
        st_ops->data = malloc(type->size);
        st_ops->progs = calloc(btf_vlen(type), sizeof(*st_ops->progs));
        st_ops->kern_func_off = malloc(btf_vlen(type) * sizeof(*st_ops->kern_func_off));
        // 检查`st_ops`属性是否异常
        if (!st_ops->data || !st_ops->progs || !st_ops->kern_func_off) return -ENOMEM;
        // 检查`vsi`变量是否超过边界
        if (vsi->offset + type->size > data->d_size) { ... }
        // 设置`st_ops` 数据、类型属性
        memcpy(st_ops->data, data->d_buf + vsi->offset, type->size);
        st_ops->tname = tname;
        st_ops->type = type;
        st_ops->type_id = type_id;
    }
    return 0;
}
```

在加载阶段通过 `bpf_map__init_kern_struct_ops` 函数初始化`.struct_ops`内核相关属性，如下：

```C
// file: libbpf/src/libbpf.c
static int bpf_map__init_kern_struct_ops(struct bpf_map *map, 
            const struct btf *btf, const struct btf *kern_btf)
{
    const struct btf_member *member, *kern_member, *kern_data_member;
    const struct btf_type *type, *kern_type, *kern_vtype;
    struct bpf_struct_ops *st_ops;
    ...
    
    // 获取`.struct_ops`内核中属性
    st_ops = map->st_ops;
    type = st_ops->type;
    tname = st_ops->tname;
    err = find_struct_ops_kern_types(kern_btf, tname, &kern_type, &kern_type_id,
                    &kern_vtype, &kern_vtype_id, &kern_data_member);
    if (err) return err;

    // 设置`map`定义信息
    map->def.value_size = kern_vtype->size;
    map->btf_vmlinux_value_type_id = kern_vtype_id;
    // 分配`st_ops`内核变量数据
    st_ops->kern_vdata = calloc(1, kern_vtype->size);
    if (!st_ops->kern_vdata) return -ENOMEM;
    // 获取`内核数据`的位置
    data = st_ops->data;
    kern_data_off = kern_data_member->offset / 8;
    kern_data = st_ops->kern_vdata + kern_data_off;
    // 获取`.struct_ops`变量
    member = btf_members(type);
    for (i = 0; i < btf_vlen(type); i++, member++) {
        const struct btf_type *mtype, *kern_mtype;
        // 从用户空间btf中获取变量名称，从内核btf中获取内核字段
        mname = btf__name_by_offset(btf, member->name_off);
        kern_member = find_member_by_name(kern_btf, kern_type, mname);
        if (!kern_member) { ... }

        kern_member_idx = kern_member - btf_members(kern_type);
        ...
        // 计算用户字段和内核字段的位置
        moff = member->offset / 8;
        kern_moff = kern_member->offset / 8;
        mdata = data + moff;
        kern_mdata = kern_data + kern_moff;

        // 检查用户空间和内核空间变量的类型是否匹配
        mtype = skip_mods_and_typedefs(btf, member->type, &mtype_id);
        kern_mtype = skip_mods_and_typedefs(kern_btf, kern_member->type, &kern_mtype_id);
        if (BTF_INFO_KIND(mtype->info) != BTF_INFO_KIND(kern_mtype->info)) { ... }
        // 该字段是指针，表示是函数
        if (btf_is_ptr(mtype)) {
            struct bpf_program *prog;
            // 获取BPF程序，在重定位阶段获取的
            prog = st_ops->progs[i];
            if (!prog) continue;
            // 获取内核类型
            kern_mtype = skip_mods_and_typedefs(kern_btf, kern_mtype->type, &kern_mtype_id);
            if (!btf_is_func_proto(kern_mtype)) { ... }
            // 设置bpf程序btf_id和附加类型
            prog->attach_btf_id = kern_type_id;
            prog->expected_attach_type = kern_member_idx;
            // 设置`st_ops`内核函数的偏移位置
            st_ops->kern_func_off[i] = kern_data_off + kern_moff;
            continue;
        }
        // 检查用户空间和内核空间变量的大小是否匹配
        msize = btf__resolve_size(btf, mtype_id);
        kern_msize = btf__resolve_size(kern_btf, kern_mtype_id);
        if (msize < 0 || kern_msize < 0 || msize != kern_msize) { ... }
        // 复制用户空间设置的值到内核空间
        memcpy(kern_mdata, mdata, msize);
    }
    return 0;
}
```

### 3.2 `.struct_ops`的附加过程

在用户空间程序中调用 `bpf_map__attach_struct_ops`函数附加 `.struct_ops` 到内核中，实现如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link *bpf_map__attach_struct_ops(const struct bpf_map *map)
{
    struct bpf_link_struct_ops *link;
    __u32 zero = 0;
    int err, fd;
    // 不是`struct_ops`或已经附加，返回错误
    if (!bpf_map__is_struct_ops(map) || map->fd == -1) return libbpf_err_ptr(-EINVAL);
    // 分配`link`
    link = calloc(1, sizeof(*link));
    if (!link) return libbpf_err_ptr(-EINVAL);

    // 更新`map`字段，`0`表示的值即`.struct_ops`信息
    err = bpf_map_update_elem(map->fd, &zero, map->st_ops->kern_vdata, 0);
    // `EBUSY`状态检查，在创建或更新link时，返回`EBUSY`。`struct_ops`一旦设置就不能更改
    if (err && (!(map->def.map_flags & BPF_F_LINK) || err != -EBUSY)) { ... }

    // 设置`link`的分离接口
    link->link.detach = bpf_link__detach_struct_ops;
    
    if (!(map->def.map_flags & BPF_F_LINK)) {
        // 没有设置`LINK`标记，即: `.struct_ops`类型设置fd
        link->link.fd = map->fd;
        link->map_fd = -1;
        return &link->link;
    }
    // 设置`LINK`标记，即: `.struct_ops.link` 类型创建内核LINK
    fd = bpf_link_create(map->fd, 0, BPF_STRUCT_OPS, NULL);
    if (fd < 0) { ... }

    link->link.fd = fd;
    link->map_fd = map->fd;
    return &link->link;
}
```

### 3.3 `.struct_ops`的分离过程

附加`.struct_ops`时，设置`link`的分离接口为 `bpf_link__detach_struct_ops` , 在销毁`link`时调用。其实现如下：

```C
// file: libbpf/src/libbpf.c
static int bpf_link__detach_struct_ops(struct bpf_link *link)
{
    struct bpf_link_struct_ops *st_link;
    __u32 zero = 0;
    // 获取`st_link`
    st_link = container_of(link, struct bpf_link_struct_ops, link);
    // `.struct_ops`类型时，从map中删除
    if (st_link->map_fd < 0)
        return bpf_map_delete_elem(link->fd, &zero);
    // `.struct_ops.link`类型时，关闭`link`
    return close(link->fd);
}
```

## 4 内核实现

### 4.1 `struct_ops`的内核实现

#### 1 `struct_ops`的定义

Linux内核(6.2)中实现了两种`struct_ops`, 在 `bpf_struct_ops_types.h` 文件中定义，如下：

```C
// file: kernel/bpf/bpf_struct_ops_types.h
#ifdef CONFIG_BPF_JIT
#ifdef CONFIG_NET
BPF_STRUCT_OPS_TYPE(bpf_dummy_ops)
#endif
#ifdef CONFIG_INET
#include <net/tcp.h>
BPF_STRUCT_OPS_TYPE(tcp_congestion_ops)
#endif
#endif
```

通过 `BPF_STRUCT_OPS_TYPE` 宏进行不同的展开。展开过程如下：

##### (1) BTF定义

```C
// file: kernel/bpf/bpf_struct_ops.c
#define BPF_STRUCT_OPS_TYPE(_name)                  \
extern struct bpf_struct_ops bpf_##_name;           \
                                                    \
struct bpf_struct_ops_##_name {                     \
    BPF_STRUCT_OPS_COMMON_VALUE;                    \
    struct _name data ____cacheline_aligned_in_smp; \
};
#include "bpf_struct_ops_types.h"
#undef BPF_STRUCT_OPS_TYPE
```

`struct bpf_struct_ops_##_name` 定义了BTF需要的类型定义。`BPF_STRUCT_OPS_COMMON_VALUE` 同样是个宏，定义了`STRUCT_OPS`结构的通用字段，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
#define BPF_STRUCT_OPS_COMMON_VALUE     \
    refcount_t refcnt;                  \
    enum bpf_struct_ops_state state
```

##### (2) `bpf_struct_ops`定义

`bpf_struct_ops` 是同名结构的数组，定义了`struct_ops`的操作接口，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
enum {
#define BPF_STRUCT_OPS_TYPE(_name) BPF_STRUCT_OPS_TYPE_##_name,
#include "bpf_struct_ops_types.h"
#undef BPF_STRUCT_OPS_TYPE
    __NR_BPF_STRUCT_OPS_TYPE,
};

static struct bpf_struct_ops * const bpf_struct_ops[] = {
#define BPF_STRUCT_OPS_TYPE(_name)				\
    [BPF_STRUCT_OPS_TYPE_##_name] = &bpf_##_name,
#include "bpf_struct_ops_types.h"
#undef BPF_STRUCT_OPS_TYPE
};
```

`struct bpf_struct_ops`结构定义了`struct_ops`的操作接口，如下：

```C
// file: include/linux/bpf.h
#define BPF_STRUCT_OPS_MAX_NR_MEMBERS 64
struct bpf_struct_ops {
    const struct bpf_verifier_ops *verifier_ops;
    int (*init)(struct btf *btf);
    int (*check_member)(const struct btf_type *t, const struct btf_member *member,
                const struct bpf_prog *prog);
    int (*init_member)(const struct btf_type *t, const struct btf_member *member,
                void *kdata, const void *udata);
    int (*reg)(void *kdata);
    void (*unreg)(void *kdata);
    const struct btf_type *type;
    const struct btf_type *value_type;
    const char *name;
    struct btf_func_model func_models[BPF_STRUCT_OPS_MAX_NR_MEMBERS];
    u32 type_id;
    u32 value_id;
};
```

通过该结构定义可以了解到，`struct_ops` 最多支持64个属性，支持初始化(`.init`)、初始化字段(`.init_member`)、注册(`.reg`)、注销(`.unreg`)等接口。

#### 2 `struct_ops`的初始化过程

`struct_ops`在获取内核BTF(`btf_vmlinux`)信息的过程中初始化，调用过程如下：

```C
// file: kernel/bpf/verifier.c
struct btf *bpf_get_btf_vmlinux(void)
{
    if (!btf_vmlinux && IS_ENABLED(CONFIG_DEBUG_INFO_BTF)) {
        mutex_lock(&bpf_verifier_lock);
        if (!btf_vmlinux) btf_vmlinux = btf_parse_vmlinux();
        mutex_unlock(&bpf_verifier_lock);
    }
    return btf_vmlinux;
}
```

`btf_parse_vmlinux`函数解析`vmlinux` BTF信息，在解析的过程中初始化`struct_ops`，如下：

```C
// file: kernel/bpf/btf.c
struct btf *btf_parse_vmlinux(void)
    --> bpf_struct_ops_init(btf, log);
```

`bpf_struct_ops_init` 函数实现`struct_ops`的初始化，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
void bpf_struct_ops_init(struct btf *btf, struct bpf_verifier_log *log)
{
    s32 type_id, value_id, module_id;
    const struct btf_member *member;
    struct bpf_struct_ops *st_ops;
    const struct btf_type *t;
    char value_name[128];
    const char *mname;
    u32 i, j;

    // 确保"struct bpf_struct_ops_##_name"触发BTF类型
#define BPF_STRUCT_OPS_TYPE(_name) BTF_TYPE_EMIT(struct bpf_struct_ops_##_name);
#include "bpf_struct_ops_types.h"
#undef BPF_STRUCT_OPS_TYPE

    // 获取BTF 模块id
    module_id = btf_find_by_name_kind(btf, "module", BTF_KIND_STRUCT);
    if (module_id < 0) { ... }
    module_type = btf_type_by_id(btf, module_id);

    for (i = 0; i < ARRAY_SIZE(bpf_struct_ops); i++) {
        st_ops = bpf_struct_ops[i];
        // 获取`st_ops`名称id
        sprintf(value_name, "%s%s", VALUE_PREFIX, st_ops->name);
        value_id = btf_find_by_name_kind(btf, value_name, BTF_KIND_STRUCT);
        if (value_id < 0) { ...	continue; }
        // 获取`st_ops`类型id
        type_id = btf_find_by_name_kind(btf, st_ops->name, BTF_KIND_STRUCT);
        if (type_id < 0) { ...	continue; }
        // 获取`st_ops`类型，检查字段是否超过限制
        t = btf_type_by_id(btf, type_id);
        if (btf_type_vlen(t) > BPF_STRUCT_OPS_MAX_NR_MEMBERS) { ...	continue; }

        // 初始化`st_ops`类型中的字段
        for_each_member(j, t, member) {
            const struct btf_type *func_proto;
            // 获取字段名称
            mname = btf_name_by_offset(btf, member->name_off);
            if (!*mname) { ... }
            // 检查字段大小
            if (__btf_member_bitfield_size(t, member)) { ... }
            // 解析并初始化函数原型
            func_proto = btf_type_resolve_func_ptr(btf, member->type, NULL);
            if (func_proto && 
                btf_distill_func_proto(log, btf, func_proto, mname, &st_ops->func_models[j])) { ... }
        }
        if (j == btf_type_vlen(t)) {
            // 全部变量都存在时，尝试初始化，失败时设置`st_ops`类型
            if (st_ops->init(btf)) {
                ...
            } else {
                st_ops->type_id = type_id;
                st_ops->type = t;
                st_ops->value_id = value_id;
                st_ops->value_type = btf_type_by_id(btf, value_id);
            }
        }
    }
}
```

### 4.2 `struct_ops_map`的内核实现

`.struct_ops`在BPF中是`BPF_MAP_TYPE_STRUCT_OPS`类型的MAP，通过map进行`struct_ops`生命周期的管理。

#### 1 创建过程

##### (1) BPF系统调用

BPF中通过`BPF_MAP_CREATE` BPF系统调用创建map，如下：

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
    case BPF_MAP_CREATE: err = map_create(&attr); break;
    ...
    }
    return err;
}
```

`map_create`函数实现bpf map的创建，如下：

```C
// file: kernel/bpf/syscall.c
static int map_create(union bpf_attr *attr)
{
    int numa_node = bpf_map_attr_numa_node(attr);
    struct btf_field_offs *foffs;
    struct bpf_map *map;
    int f_flags;
    int err;

    // 检查`attr`设置，检查BTF、BLOOM_FILTER、flags、numa_node是否正确设置
    err = CHECK_ATTR(BPF_MAP_CREATE);
    ...

    // 获取map类型后初始化map
    map = find_and_alloc_map(attr);
    if (IS_ERR(map)) return PTR_ERR(map);
    // 复制名称
    err = bpf_obj_name_cpy(map->name, attr->map_name, sizeof(attr->map_name));
    if (err < 0) goto free_map;
    // map初始值设置
    atomic64_set(&map->refcnt, 1);
    atomic64_set(&map->usercnt, 1);
    mutex_init(&map->freeze_mutex);
    spin_lock_init(&map->owner.lock);

    if (attr->btf_key_type_id || attr->btf_value_type_id || attr->btf_vmlinux_value_type_id) {
        struct btf *btf;
        btf = btf_get_by_fd(attr->btf_fd);
        if (IS_ERR(btf)) { ... }
        if (btf_is_kernel(btf)) { ... }
        // BTF相关字段设置
        map->btf = btf;
        if (attr->btf_value_type_id) {
            err = map_check_btf(map, btf, attr->btf_key_type_id, attr->btf_value_type_id);
            if (err) goto free_map;
        }
        map->btf_key_type_id = attr->btf_key_type_id;
        map->btf_value_type_id = attr->btf_value_type_id;
        map->btf_vmlinux_value_type_id = attr->btf_vmlinux_value_type_id;
    }
    // btf解析字段偏移
    foffs = btf_parse_field_offs(map->record);
    if (IS_ERR(foffs)) { ... }
    map->field_offs = foffs;

    // LSM安全检查
    err = security_bpf_map_alloc(map);
    if (err) goto free_map_field_offs;
    // 分配map id
    err = bpf_map_alloc_id(map);
    if (err) goto free_map_sec;
    // 保存 内存cgroup (`memcg`)
    bpf_map_save_memcg(map);
    // map关联file
    err = bpf_map_new_fd(map, f_flags);
    // 关联文件失败时，释放map
    if (err < 0) { bpf_map_put_with_uref(map); return err; }
    // 返回fd
    return err;

free_map_sec:
    security_bpf_map_free(map);
free_map_field_offs:
    kfree(map->field_offs);
free_map:
    btf_put(map->btf);
    map->ops->map_free(map);
    return err;
}
```

这其中最重要是确定map的类型后初始化，`find_and_alloc_map` 函数完成该项工作，如下：

```C
// file: kernel/bpf/syscall.c
static struct bpf_map *find_and_alloc_map(union bpf_attr *attr)
{
    const struct bpf_map_ops *ops;
    u32 type = attr->map_type;
    struct bpf_map *map;
    int err;
    
    // 检查type是否越界 
    if (type >= ARRAY_SIZE(bpf_map_types)) return ERR_PTR(-EINVAL);
    type = array_index_nospec(type, ARRAY_SIZE(bpf_map_types));

    // 获取`map_ops`操作接口
    ops = bpf_map_types[type];
    if (!ops) return ERR_PTR(-EINVAL);

    // `.map_alloc_check`接口，分配map前的检查
    if (ops->map_alloc_check) {
        err = ops->map_alloc_check(attr);
        if (err) return ERR_PTR(err);
    }
    if (attr->map_ifindex) ops = &bpf_map_offload_ops;
    // `.map_alloc`接口，分配map
    map = ops->map_alloc(attr);
    if (IS_ERR(map)) return map;
    // map设置
    map->ops = ops;
    map->map_type = type;
    return map;
}
```

`bpf_map_types`数组是个`struct bpf_map_ops *`列表，存放map对应的操作接口。其定义如下：

```C
// file: kernel/bpf/syscall.c
static const struct bpf_map_ops * const bpf_map_types[] = {
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type)
#define BPF_MAP_TYPE(_id, _ops) \
    [_id] = &_ops,
#define BPF_LINK_TYPE(_id, _name)
#include <linux/bpf_types.h>
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE
};
```

`bpf_map_new_fd` 函数实现map和fd的关联，如下：

```C
// file: kernel/bpf/syscall.c
int bpf_map_new_fd(struct bpf_map *map, int flags)
{
    int ret;
    // LSM安全检查
    ret = security_bpf_map(map, OPEN_FMODE(flags));
    if (ret < 0) return ret;
    // 创建fd
    return anon_inode_getfd("bpf-map", &bpf_map_fops, map, flags | O_CLOEXEC);
}
```

`bpf_map_fops`是设置的文件操作接口，定义如下：

```C
// file: kernel/bpf/syscall.c
const struct file_operations bpf_map_fops = {
#ifdef CONFIG_PROC_FS
    .show_fdinfo    = bpf_map_show_fdinfo,
#endif
    .release    = bpf_map_release,
    .read       = bpf_dummy_read,
    .write      = bpf_dummy_write,
    .mmap       = bpf_map_mmap,
    .poll       = bpf_map_poll,
};
```

##### (2) `struct_ops_map`的创建过程

`BPF_MAP_TYPE_STRUCT_OPS` 类型的map对应的操作接口为 `bpf_struct_ops_map_ops`, 如下：

```C
// file: include/linux/bpf_types.h
BPF_MAP_TYPE(BPF_MAP_TYPE_STRUCT_OPS, bpf_struct_ops_map_ops)
```

其定义如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
BTF_ID_LIST_SINGLE(bpf_struct_ops_map_btf_ids, struct, bpf_struct_ops_map)
const struct bpf_map_ops bpf_struct_ops_map_ops = {
    .map_alloc_check = bpf_struct_ops_map_alloc_check,
    .map_alloc = bpf_struct_ops_map_alloc,
    .map_free = bpf_struct_ops_map_free,
    .map_get_next_key = bpf_struct_ops_map_get_next_key,
    .map_lookup_elem = bpf_struct_ops_map_lookup_elem,
    .map_delete_elem = bpf_struct_ops_map_delete_elem,
    .map_update_elem = bpf_struct_ops_map_update_elem,
    .map_seq_show_elem = bpf_struct_ops_map_seq_show_elem,
    .map_btf_id = &bpf_struct_ops_map_btf_ids[0],
};
```

`.map_alloc_check`接口在创建map前调用，设置为 `bpf_struct_ops_map_alloc_check`, 实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static int bpf_struct_ops_map_alloc_check(union bpf_attr *attr)
{
    if (attr->key_size != sizeof(unsigned int) || attr->max_entries != 1 ||
        attr->map_flags || !attr->btf_vmlinux_value_type_id)
        return -EINVAL;
    return 0;
}
```

`STRUCT_OPS`类型的map，只能包含一个项、key为4个字节、不设置flags标记、类型必须在内核`btf`中存在。


`.map_alloc`接口在创建map时调用，设置为 `bpf_struct_ops_map_alloc`, 实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static struct bpf_map *bpf_struct_ops_map_alloc(union bpf_attr *attr)
{
    const struct bpf_struct_ops *st_ops;
    size_t st_map_size;
    struct bpf_struct_ops_map *st_map;
    const struct btf_type *t, *vt;
    struct bpf_map *map;
    
    // 权限检查
    if (!bpf_capable()) return ERR_PTR(-EPERM);

    // 根据`btf_vmlinux_value_type_id`获取`st_ops`
    st_ops = bpf_struct_ops_find_value(attr->btf_vmlinux_value_type_id);
    if (!st_ops) return ERR_PTR(-ENOTSUPP);
    
    // 值类型检查
    vt = st_ops->value_type;
    if (attr->value_size != vt->size) return ERR_PTR(-EINVAL);
    t = st_ops->type;
    
    // 计算`st_map`大小后分配内存空间
    st_map_size = sizeof(*st_map) + (vt->size - sizeof(struct bpf_struct_ops_value));
    st_map = bpf_map_area_alloc(st_map_size, NUMA_NO_NODE);
    if (!st_map) return ERR_PTR(-ENOMEM);
    // 获取bpf_map
    st_map->st_ops = st_ops;
    map = &st_map->map;

    // `st_map`用户空间、links、image内存空间分配
    st_map->uvalue = bpf_map_area_alloc(vt->size, NUMA_NO_NODE);
    st_map->links = bpf_map_area_alloc(btf_type_vlen(t) * sizeof(struct bpf_links *), NUMA_NO_NODE);
    st_map->image = bpf_jit_alloc_exec(PAGE_SIZE);
    if (!st_map->uvalue || !st_map->links || !st_map->image) { ... }

    mutex_init(&st_map->lock);
    set_vm_flush_reset_perms(st_map->image);
    // map属性设置
    bpf_map_init_from_attr(map, attr);
    
    return map;
}
```

`bpf_struct_ops_find_value`函数获取对应的`st_ops`，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static const struct bpf_struct_ops * bpf_struct_ops_find_value(u32 value_id)
{
    unsigned int i;
    // 没有设置`value`,`btf_vmlinux`不存在时返回空
    if (!value_id || !btf_vmlinux) return NULL;
    // 从`bpf_struct_ops`中获取
    for (i = 0; i < ARRAY_SIZE(bpf_struct_ops); i++) {
        if (bpf_struct_ops[i]->value_id == value_id) 
            return bpf_struct_ops[i];
    }
    return NULL;
}
```

#### 2 附加过程

`.struct_ops`通过更新map中的值实现附加。

##### (1) BPF系统调用

BPF中通过`BPF_MAP_UPDATE_ELEM` BPF系统调用更新map中的值，如下：

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

`bpf_map_update_value` 函数根据map的类型进行相关的更新操作，如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_map_update_value(struct bpf_map *map, struct file *map_file,
                void *key, void *value, __u64 flags)
{
    int err;
    if (bpf_map_is_offloaded(map)) {
        return bpf_map_offload_update_elem(map, key, value, flags);
    } else if (map->map_type == BPF_MAP_TYPE_CPUMAP ||
            map->map_type == BPF_MAP_TYPE_STRUCT_OPS) {
        return map->ops->map_update_elem(map, key, value, flags);
    } 
    ...
}
```

`STRUCT_OPS`类型的map通过`ops`操作接口更新值。

##### (2) `struct_ops_map`的更新过程

`.map_update_elem`接口在更新map时调用，设置为 `bpf_struct_ops_map_update_elem`, 实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static long bpf_struct_ops_map_update_elem(struct bpf_map *map, void *key, void *value, u64 flags)
{
    struct bpf_struct_ops_map *st_map = (struct bpf_struct_ops_map *)map;
    const struct bpf_struct_ops *st_ops = st_map->st_ops;
    struct bpf_struct_ops_value *uvalue, *kvalue;
    const struct btf_member *member;
    const struct btf_type *t = st_ops->type;
    struct bpf_tramp_links *tlinks = NULL;
    void *udata, *kdata;
    int prog_fd, err = 0;
    void *image, *image_end;
    u32 i;

    // 不支持flags设置
    if (flags) return -EINVAL;
    // key 必须为0
    if (*(u32 *)key != 0) return -E2BIG;
    // 检查值类型是否是否匹配
    err = check_zero_holes(st_ops->value_type, value);
    if (err) return err;
    // 检查类型是否匹配
    uvalue = value;
    err = check_zero_holes(t, uvalue->data);
    if (err) return err;

    // 检查是否重复更新
    if (uvalue->state || refcount_read(&uvalue->refcnt)) return -EINVAL;
    // 分配`tramp_links`内存空间
    tlinks = kcalloc(BPF_TRAMP_MAX, sizeof(*tlinks), GFP_KERNEL);
    if (!tlinks) return -ENOMEM;

    uvalue = (struct bpf_struct_ops_value *)st_map->uvalue;
    kvalue = (struct bpf_struct_ops_value *)&st_map->kvalue;

    mutex_lock(&st_map->lock);
    // 检查kvalue状态
    if (kvalue->state != BPF_STRUCT_OPS_STATE_INIT) { err = -EBUSY; goto unlock; }

    // 复制用户空间设置的值
    memcpy(uvalue, value, map->value_size);

    udata = &uvalue->data;
    kdata = &kvalue->data;
    image = st_map->image;
    image_end = st_map->image + PAGE_SIZE;

    for_each_member(i, t, member) {
        const struct btf_type *mtype, *ptype;
        struct bpf_prog *prog;
        struct bpf_tramp_link *link;
        u32 moff;
        // 获取`struct_ops`中字段的偏移量和类型
        moff = __btf_member_bit_offset(t, member) / 8;
        ptype = btf_type_resolve_ptr(btf_vmlinux, member->type, NULL);
        if (ptype == module_type) {
            // 类型时module时，设置内核字段
            if (*(void **)(udata + moff)) goto reset_unlock;
            *(void **)(kdata + moff) = BPF_MODULE_OWNER;
            continue;
        }
        // 初始化字段，返回值：<0:表示错误，>0:表示该字段已经处理，0:表示使用BPF程序的字段
        err = st_ops->init_member(t, member, kdata, udata);
        if (err < 0) goto reset_unlock;
        if (err > 0) continue;
        // 所有非空的变量指针必须设置为0
        if (!ptype || !btf_type_is_func_proto(ptype)) {
            u32 msize; 
            // 获取变量的大小
            mtype = btf_type_by_id(btf_vmlinux, member->type);
            mtype = btf_resolve_size(btf_vmlinux, mtype, &msize);
            if (IS_ERR(mtype)) { err = PTR_ERR(mtype); goto reset_unlock; }
            // 字段必须设置为0
            if (memchr_inv(udata + moff, 0, msize)) { err = -EINVAL; goto reset_unlock; }
            // 继续下一个字段
            continue;
        }
        // 字段为BPF程序
        prog_fd = (int)(*(unsigned long *)(udata + moff));
        if (!prog_fd) continue;
        // 获取BPF程序
        prog = bpf_prog_get(prog_fd);
        if (IS_ERR(prog)) { err = PTR_ERR(prog); goto reset_unlock; }
        // 检查BPF程序类型、附加的btf_id和附加类型是否匹配
        if (prog->type != BPF_PROG_TYPE_STRUCT_OPS || 
            prog->aux->attach_btf_id != st_ops->type_id ||
            prog->expected_attach_type != i) { ...  }
        // 分配并初始化`tramp_link`
        link = kzalloc(sizeof(*link), GFP_USER);
        if (!link) { ... }
        bpf_link_init(&link->link, BPF_LINK_TYPE_STRUCT_OPS, &bpf_struct_ops_link_lops, prog);
        st_map->links[i] = &link->link;
        // `stract_ops`字段为BPF程序时，设置为BPF trampoline
        err = bpf_struct_ops_prepare_trampoline(tlinks, link, &st_ops->func_models[i], image, image_end);
        if (err < 0) goto reset_unlock;
        // 计算image位置
        *(void **)(kdata + moff) = image;
        image += err;

        // 设置 prog_id 到用户空间
        *(unsigned long *)(udata + moff) = prog->aux->id;
    }
    // 增加相关引用计数
    refcount_set(&kvalue->refcnt, 1);
    bpf_map_inc(map);

    // 设置`image`可执行后，注册`st_ops`
    set_memory_rox((long)st_map->image, 1);
    err = st_ops->reg(kdata);
    if (likely(!err)) {
        // 注册成功后，设置为`INUSE`状态
        smp_store_release(&kvalue->state, BPF_STRUCT_OPS_STATE_INUSE);
        goto unlock;
    }
    // 注册失败时，设置`image`内存标记，设置为只能读写
    set_memory_nx((long)st_map->image, 1);
    set_memory_rw((long)st_map->image, 1);
    bpf_map_put(map);

reset_unlock:
    // 释放`st_map`的BPF程序，清空`st_map`的用户空间、内核空间的值
    bpf_struct_ops_map_put_progs(st_map);
    memset(uvalue, 0, map->value_size);
    memset(kvalue, 0, map->value_size);
unlock:
    // 释放`tlinks`
    kfree(tlinks);
    mutex_unlock(&st_map->lock);
    return err;
}
```

`bpf_struct_ops_prepare_trampoline` 函数处理`struct_ops`字段为BPF程序的情形，实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
int bpf_struct_ops_prepare_trampoline(struct bpf_tramp_links *tlinks, struct bpf_tramp_link *link,
                    const struct btf_func_model *model, void *image, void *image_end)
{
    u32 flags;
    // 设置`FENTRY`
    tlinks[BPF_TRAMP_FENTRY].links[0] = link;
    tlinks[BPF_TRAMP_FENTRY].nr_links = 1;
    // `BPF_TRAMP_F_RET_FENTRY_RET`只能由`bpf_struct_ops`单独使用
    flags = model->ret_size > 0 ? BPF_TRAMP_F_RET_FENTRY_RET : 0;
    // 生成bpf_trampoline
    return arch_prepare_bpf_trampoline(NULL, image, image_end, model, flags, tlinks, NULL);
}
```

#### 3 分离过程

`.struct_ops`通过删除map中的值实现分离。

##### (1) BPF系统调用

BPF中通过`BPF_MAP_DELETE_ELEM` BPF系统调用删除map中的值，如下：

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

##### (2) `struct_ops_map`的删除过程

`.map_delete_elem`接口在删除map时调用，设置为 `bpf_struct_ops_map_delete_elem`, 实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static long bpf_struct_ops_map_delete_elem(struct bpf_map *map, void *key)
{
    enum bpf_struct_ops_state prev_state;
    struct bpf_struct_ops_map *st_map;
    // 获取`st_map`和之前的状态
    st_map = (struct bpf_struct_ops_map *)map;
    prev_state = cmpxchg(&st_map->kvalue.state, BPF_STRUCT_OPS_STATE_INUSE, BPF_STRUCT_OPS_STATE_TOBEFREE);
    switch (prev_state) {
    case BPF_STRUCT_OPS_STATE_INUSE:
        // 注销`st_ops`
        st_map->st_ops->unreg(&st_map->kvalue.data);
        // 减少kvalue的引用计数
        if (refcount_dec_and_test(&st_map->kvalue.refcnt)) bpf_map_put(map);
        return 0;
    case BPF_STRUCT_OPS_STATE_TOBEFREE:
        return -EINPROGRESS;
    case BPF_STRUCT_OPS_STATE_INIT:
        return -ENOENT;
    default:
        WARN_ON_ONCE(1);
        return -ENOENT;
    }
}
```

#### 4 释放过程

`.struct_ops`通过删除map实现释放。

##### (1) `map`的文件操作接口

在创建map时，将map和fd关联，设置的文件操作接口为`bpf_map_fops`，定义如下：

```C
// file: kernel/bpf/syscall.c
const struct file_operations bpf_map_fops = {
#ifdef CONFIG_PROC_FS
    .show_fdinfo    = bpf_map_show_fdinfo,
#endif
    .release    = bpf_map_release,
    .read       = bpf_dummy_read,
    .write      = bpf_dummy_write,
    .mmap       = bpf_map_mmap,
    .poll       = bpf_map_poll,
};
```

`.release`接口在关闭(`close`系统调用)时调用，设置为`bpf_map_release`，实现如下：

```C
// file: kernel/bpf/syscall.c
static int bpf_map_release(struct inode *inode, struct file *filp)
{
    struct bpf_map *map = filp->private_data;
    // `map_release`接口
    if (map->ops->map_release)
        map->ops->map_release(map, filp);
    bpf_map_put_with_uref(map);
    return 0;
}
```

`bpf_map_put_with_uref`函数在释放使用计数后释放map，如下

```C
// file: kernel/bpf/syscall.c
void bpf_map_put_with_uref(struct bpf_map *map)
{
    bpf_map_put_uref(map);
    bpf_map_put(map);
}
// file: kernel/bpf/syscall.c
static void bpf_map_put_uref(struct bpf_map *map)
{
    // 减少引用计数后，调用`map_release_uref`接口
    if (atomic64_dec_and_test(&map->usercnt)) {
        if (map->ops->map_release_uref) 
            map->ops->map_release_uref(map);
    }
}
```

`bpf_map_put`函数在减少引用计数后，通过工作队列释放map，如下：

```C
// file: kernel/bpf/syscall.c
void bpf_map_put(struct bpf_map *map)
{
    if (atomic64_dec_and_test(&map->refcnt)) {
        // 释放id和btf
        bpf_map_free_id(map);
        btf_put(map->btf);
        // 设置工作队列后，添加到队列中
        INIT_WORK(&map->work, bpf_map_free_deferred);
        queue_work(system_unbound_wq, &map->work);
    }
}
```

`bpf_map_free_deferred` 函数是设置的释放接口，实现如下：

```C
// file: kernel/bpf/syscall.c
static void bpf_map_free_deferred(struct work_struct *work)
{
    struct bpf_map *map = container_of(work, struct bpf_map, work);
    struct btf_field_offs *foffs = map->field_offs;
    struct btf_record *rec = map->record;
    // LSM安全检查
    security_bpf_map_free(map);
    bpf_map_release_memcg(map);
    // `.map_free`接口
    map->ops->map_free(map);
    // 延时释放`field_offs`和`btf_record`
    kfree(foffs);
    btf_record_free(rec);
}
```

##### (2) `struct_ops_map`的删除过程

`.map_free`接口释放map时调用，设置为 `bpf_struct_ops_map_free`, 实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static void bpf_struct_ops_map_free(struct bpf_map *map)
{
    struct bpf_struct_ops_map *st_map = (struct bpf_struct_ops_map *)map;
    // 释放BPF程序
    if (st_map->links)
        bpf_struct_ops_map_put_progs(st_map);
    // 释放`links`,`image`,`uvalue`后，释放`st_map`
    bpf_map_area_free(st_map->links);
    bpf_jit_free_exec(st_map->image);
    bpf_map_area_free(st_map->uvalue);
    bpf_map_area_free(st_map);
}
```

`bpf_struct_ops_map_put_progs` 函数释放`struct_ops`的BPF程序，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static void bpf_struct_ops_map_put_progs(struct bpf_struct_ops_map *st_map)
{
    const struct btf_type *t = st_map->st_ops->type;
    u32 i;
    // 遍历`st_ops`类型的字段
    for (i = 0; i < btf_type_vlen(t); i++) {
        // 设置`link`时，释放
        if (st_map->links[i]) {
            bpf_link_put(st_map->links[i]);
            st_map->links[i] = NULL;
        }
    }
}
```

`bpf_struct_ops_link_lops`是`st_map->links[]`设置的操作接口，其定义如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
const struct bpf_link_ops bpf_struct_ops_link_lops = {
    .release = bpf_struct_ops_link_release,
    .dealloc = bpf_struct_ops_link_dealloc,
};
```

`.release` 和 `.dealloc` 实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static void bpf_struct_ops_link_release(struct bpf_link *link)
{
}
// file: kernel/bpf/bpf_struct_ops.c
static void bpf_struct_ops_link_dealloc(struct bpf_link *link)
{
    // 转换为`bpf_tramp_link`后释放
    struct bpf_tramp_link *tlink = container_of(link, struct bpf_tramp_link, link);
    kfree(tlink);
}
```

### 4.3 `bpf_tcp_congestion_ops`的实现

`struct_ops`的一个典型的用例就是基于BPF实现TCP拥塞控制算法，在内核中定义为`bpf_tcp_congestion_ops`，如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
struct bpf_struct_ops bpf_tcp_congestion_ops = {
    .verifier_ops = &bpf_tcp_ca_verifier_ops,
    .reg = bpf_tcp_ca_reg,
    .unreg = bpf_tcp_ca_unreg,
    .check_member = bpf_tcp_ca_check_member,
    .init_member = bpf_tcp_ca_init_member,
    .init = bpf_tcp_ca_init,
    .name = "tcp_congestion_ops",
};
```

接下来我们逐一分析。

#### 1 检查字段的过程

`.check_member`接口在加载阶段检查`struct_ops`字段时调用，检查是否支持指定的字段。实现如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static int bpf_tcp_ca_check_member(const struct btf_type *t, 
            const struct btf_member *member, const struct bpf_prog *prog)
{
    if (is_unsupported(__btf_member_bit_offset(t, member) / 8))
        return -ENOTSUPP;
    return 0;
}
```

`is_unsupported` 函数根据字段偏移位置判读是否支持该字段，如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static bool is_unsupported(u32 member_offset)
{
    unsigned int i;
    for (i = 0; i < ARRAY_SIZE(unsupported_ops); i++) {
        if (member_offset == unsupported_ops[i]) 
            return true;
    }
    return false;
}
```

`unsupported_ops`数组表示不支持的字段，定义如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static u32 unsupported_ops[] = {
    offsetof(struct tcp_congestion_ops, get_info),
};
```

即：不支持`get_info`字段。

`bpf_tcp_ca_verifier_ops`结构在加载阶段验证`struct_ops`，定义如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static const struct bpf_verifier_ops bpf_tcp_ca_verifier_ops = {
    .get_func_proto     = bpf_tcp_ca_get_func_proto,
    .is_valid_access    = bpf_tcp_ca_is_valid_access,
    .btf_struct_access  = bpf_tcp_ca_btf_struct_access,
};
```

#### 2 初始化过程

`.init`在初始化`struct_ops`时调用，设置为`bpf_tcp_ca_init`，实现如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static int bpf_tcp_ca_init(struct btf *btf)
{
    s32 type_id;
    // 获取`sock`的btf类型
    type_id = btf_find_by_name_kind(btf, "sock", BTF_KIND_STRUCT);
    if (type_id < 0) return -EINVAL;
    sock_id = type_id;

    // 获取`tcp_sock`的btf类型
    type_id = btf_find_by_name_kind(btf, "tcp_sock", BTF_KIND_STRUCT);
    if (type_id < 0) return -EINVAL;
    tcp_sock_id = type_id;
    tcp_sock_type = btf_type_by_id(btf, tcp_sock_id);
    return 0;
}
```

#### 3 初始化字段的过程

`.init_member`接口在附加`struct_ops`时调用，设置`bpf_tcp_ca_init_member`, 支持`flags`和`name`字段的设置。实现如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static int bpf_tcp_ca_init_member(const struct btf_type *t,
        const struct btf_member *member, void *kdata, const void *udata)
{
    const struct tcp_congestion_ops *utcp_ca;
    struct tcp_congestion_ops *tcp_ca;
    u32 moff;
    // 将udata,kdata分别转换为`utcp_ca`,`tcp_ca`
    utcp_ca = (const struct tcp_congestion_ops *)udata;
    tcp_ca = (struct tcp_congestion_ops *)kdata;

    // 计算字段的偏移量
    moff = __btf_member_bit_offset(t, member) / 8;
    switch (moff) {
    case offsetof(struct tcp_congestion_ops, flags):
        // `flags`字段时，检查后设置
        if (utcp_ca->flags & ~TCP_CONG_MASK) 
            return -EINVAL;
        tcp_ca->flags = utcp_ca->flags;
        return 1;
    case offsetof(struct tcp_congestion_ops, name):
        // `name`字段，复制后检查是否存在同名的`tcp_ca`
        if (bpf_obj_name_cpy(tcp_ca->name, utcp_ca->name, sizeof(tcp_ca->name)) <= 0)
            return -EINVAL;
        if (tcp_ca_find(utcp_ca->name))
            return -EEXIST;
        return 1;
    }
    return 0;
}
```

#### 4 注册的过程

`.reg`接口在注册`struct_ops`时调用，设置`bpf_tcp_ca_reg`, 注册`tcp_ca`。实现如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static int bpf_tcp_ca_reg(void *kdata)
{
    return tcp_register_congestion_control(kdata);
}
```

`tcp_register_congestion_control` 函数注册TCP拥塞控制算法(`tcp_ca`)，其实现如下：

```C
// file: net/ipv4/tcp_cong.c
int tcp_register_congestion_control(struct tcp_congestion_ops *ca)
{
    int ret = 0;
    // 所有的`ca`必须实现的接口
    if (!ca->ssthresh || !ca->undo_cwnd || !(ca->cong_avoid || ca->cong_control)) {
        pr_err("%s does not implement required ops\n", ca->name);
        return -EINVAL;
    }
    // 计算`key`
    ca->key = jhash(ca->name, sizeof(ca->name), strlen(ca->name));

    spin_lock(&tcp_cong_list_lock);
    if (ca->key == TCP_CA_UNSPEC || tcp_ca_find_key(ca->key)) {
        // `ca`存在时提示错误
        pr_notice("%s already registered or non-unique key\n", ca->name);
        ret = -EEXIST;
    } else {
        // 不存在时，添加到`ca`列表中
        list_add_tail_rcu(&ca->list, &tcp_cong_list);
        pr_debug("%s registered\n", ca->name);
    }
    spin_unlock(&tcp_cong_list_lock);
    return ret;
}
```

#### 5 注销的过程

`.unreg`接口在注销`struct_ops`时调用，设置`bpf_tcp_ca_unreg`, 注销`tcp_ca`。实现如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static void bpf_tcp_ca_unreg(void *kdata)
{
    tcp_unregister_congestion_control(kdata);
}
```

`tcp_unregister_congestion_control`函数注销TCP拥塞控制算法(`tcp_ca`)，其实现如下：

```C
// file: net/ipv4/tcp_cong.c
void tcp_unregister_congestion_control(struct tcp_congestion_ops *ca)
{
    // 从列表中删除
    spin_lock(&tcp_cong_list_lock);
    list_del_rcu(&ca->list);
    spin_unlock(&tcp_cong_list_lock);
    // RCU同步，等待读者完成后再完全删除模块
    synchronize_rcu();
}
```

#### 6 `bpf_tcp_ca`支持的`kfunc`

`bpf_tcp_ca_kfunc_set`列表表示`bpf_tcp_ca`支持的`kfunc`，定义如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static const struct btf_kfunc_id_set bpf_tcp_ca_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &bpf_tcp_ca_check_kfunc_ids,
};

BTF_SET8_START(bpf_tcp_ca_check_kfunc_ids)
BTF_ID_FLAGS(func, tcp_reno_ssthresh)
BTF_ID_FLAGS(func, tcp_reno_cong_avoid)
BTF_ID_FLAGS(func, tcp_reno_undo_cwnd)
BTF_ID_FLAGS(func, tcp_slow_start)
BTF_ID_FLAGS(func, tcp_cong_avoid_ai)
BTF_SET8_END(bpf_tcp_ca_check_kfunc_ids)
```

在`initcall`阶段初始化，如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static int __init bpf_tcp_ca_kfunc_init(void)
{
    return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_tcp_ca_kfunc_set);
}
late_initcall(bpf_tcp_ca_kfunc_init);
```

此外，在`net/ipv4/tcp_cubic.c`，`kernel/bpf/helpers.c`等文件也提供了`BPF_PROG_TYPE_STRUCT_OPS`使用的`kfunc`，这里就不一一介绍了。

### 4.4 `tcp_ca`的设置过程

#### 1 默认拥塞控制设置

在创建socket时，调用`sk->sk_prot->init`的接口。ipv4 TCP协议设置的`.init`接口为`tcp_v4_init_sock`，如下：

```C
// file: net/ipv4/tcp_ipv4.c
struct proto tcp_prot = {
    .name           = "TCP",
    .owner          = THIS_MODULE,
    ...
    .init           = tcp_v4_init_sock,
    ...
};
```

其实现如下：

```C
// file: net/ipv4/tcp_ipv4.c
static int tcp_v4_init_sock(struct sock *sk)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    tcp_init_sock(sk);
    
    icsk->icsk_af_ops = &ipv4_specific;
#ifdef CONFIG_TCP_MD5SIG
    tcp_sk(sk)->af_specific = &tcp_sock_ipv4_specific;
#endif
    return 0;
}
```

ipv6 TCP协议设置的`.init`接口为`tcp_v6_init_sock`，如下：

```C
// file: net/ipv6/tcp_ipv6.c
struct proto tcpv6_prot = {
    .name           = "TCPv6",
    .owner          = THIS_MODULE,
    ...
    .init           = tcp_v6_init_sock,
    ...
};
```

其实现如下：

```C
// file: net/ipv6/tcp_ipv6.c
static int tcp_v6_init_sock(struct sock *sk)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    tcp_init_sock(sk);
    icsk->icsk_af_ops = &ipv6_specific;
#ifdef CONFIG_TCP_MD5SIG
    tcp_sk(sk)->af_specific = &tcp_sock_ipv6_specific;
#endif
    return 0;
}
```

ipv4/6的TCP在初始化sock过程中调用`tcp_init_sock`函数初始化tcp_sock，其中设置拥塞控制，如下：

```C
// file: net/ipv4/tcp.c
void tcp_init_sock(struct sock *sk)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct tcp_sock *tp = tcp_sk(sk);

    tp->out_of_order_queue = RB_ROOT;
    sk->tcp_rtx_queue = RB_ROOT;
    tcp_init_xmit_timers(sk);
    INIT_LIST_HEAD(&tp->tsq_node);
    INIT_LIST_HEAD(&tp->tsorted_sent_queue);

    icsk->icsk_rto = TCP_TIMEOUT_INIT;
    icsk->icsk_rto_min = TCP_RTO_MIN;
    icsk->icsk_delack_max = TCP_DELACK_MAX;
    tp->mdev_us = jiffies_to_usecs(TCP_TIMEOUT_INIT);
    minmax_reset(&tp->rtt_min, tcp_jiffies32, ~0U);
    // 初始化发送窗口大小
    tcp_snd_cwnd_set(tp, TCP_INIT_CWND);

    tp->app_limited = ~0U;
    tp->rate_app_limited = 1;
    // 发送 ssthresh,mss设置
    tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
    tp->snd_cwnd_clamp = ~0;
    tp->mss_cache = TCP_MSS_DEFAULT;

    tp->reordering = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_reordering);
    // 设置拥塞控制
    tcp_assign_congestion_control(sk);

    tp->tsoffset = 0;
    tp->rack.reo_wnd_steps = 1;

    sk->sk_write_space = sk_stream_write_space;
    sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

    icsk->icsk_sync_mss = tcp_sync_mss;
    // 设置发送缓冲区、接收缓冲区大小
    WRITE_ONCE(sk->sk_sndbuf, READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_wmem[1]));
    WRITE_ONCE(sk->sk_rcvbuf, READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_rmem[1]));

    set_bit(SOCK_SUPPORT_ZC, &sk->sk_socket->flags);
    sk_sockets_allocated_inc(sk);
}
```

`tcp_assign_congestion_control`函数设置tcp sock的拥塞控制，如下：

```C
// file: net/ipv4/tcp_cong.c
void tcp_assign_congestion_control(struct sock *sk)
{
    struct net *net = sock_net(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    const struct tcp_congestion_ops *ca;

    rcu_read_lock();
    // 获取默认的拥塞控制，可通过`net.ipv4.tcp_congestion_control`选项设置
    ca = rcu_dereference(net->ipv4.tcp_congestion_control);
    // 默认拥塞控制失败时，使用`tcp_reno`拥塞控制
    if (unlikely(!bpf_try_module_get(ca, ca->owner)))
        ca = &tcp_reno;
    // 设置拥塞控制接口
    icsk->icsk_ca_ops = ca;
    rcu_read_unlock();
    
    memset(icsk->icsk_ca_priv, 0, sizeof(icsk->icsk_ca_priv));
    // 设置或清除`ECN`标记
    if (ca->flags & TCP_CONG_NEEDS_ECN)
        INET_ECN_xmit(sk);
    else
        INET_ECN_dontxmit(sk);
}
```

#### 2 修改拥塞控制设置

`TCP`通过`IPPROTO_TCP:TCP_CONGESTION`选项修改拥塞控制算法。如下：

```C
setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, tcp_ca, strlen(tcp_ca));
```

在内核中实现如下：

```C
// file: net/ipv4/tcp.c
int do_tcp_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct net *net = sock_net(sk);
    int val;
    int err = 0;

    switch (optname) {
    case TCP_CONGESTION: {
        char name[TCP_CA_NAME_MAX];
        if (optlen < 1) return -EINVAL;
        // 复制`ca`名称
        val = strncpy_from_sockptr(name, optval, min_t(long, TCP_CA_NAME_MAX-1, optlen));
        if (val < 0) return -EFAULT;
        name[val] = 0;

        sockopt_lock_sock(sk);
        // 设置拥塞控制算法
        err = tcp_set_congestion_control(sk, name, !has_current_bpf_ctx(),
                    sockopt_ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN));
        sockopt_release_sock(sk);
        return err;
    }
    ...
    }
}
```

`tcp_set_congestion_control` 函数修改socket的拥塞控制算法，实现如下：

```C
// file: net/ipv4/tcp_cong.c
int tcp_set_congestion_control(struct sock *sk, const char *name, bool load, bool cap_net_admin)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    const struct tcp_congestion_ops *ca;
    int err = 0;
    
    if (icsk->icsk_ca_dst_locked) return -EPERM;

    rcu_read_lock();
    // 根据名称获取拥塞控制算法
    if (!load) 
        ca = tcp_ca_find(name);
    else
        ca = tcp_ca_find_autoload(sock_net(sk), name);

    // 相同的拥塞控制算法时返回
    if (ca == icsk->icsk_ca_ops) { 
        icsk->icsk_ca_setsockopt = 1;
        goto out;
    }
    // 检查`ca`，不正确时返回错误码
    if (!ca)
        err = -ENOENT;
    else if (!((ca->flags & TCP_CONG_NON_RESTRICTED) || cap_net_admin))
        err = -EPERM;
    else if (!bpf_try_module_get(ca, ca->owner))
        err = -EBUSY;
    else
        // 正确时，重新初始化拥塞控制算法
        tcp_reinit_congestion_control(sk, ca);
 out:
    rcu_read_unlock();
    return err;
}
```

`tcp_ca_find`函数根据名称获取拥塞控制算法，如下：

```C
// file: net/ipv4/tcp_cong.c
struct tcp_congestion_ops *tcp_ca_find(const char *name)
{
    struct tcp_congestion_ops *e;
    // 遍历列表，查找相同名称的拥塞控制算法
    list_for_each_entry_rcu(e, &tcp_cong_list, list) {
        if (strcmp(e->name, name) == 0)
            return e;
    }
    return NULL;
}
```

`tcp_ca_find_autoload`函数在未查找到拥塞控制算法时，加载相应模块后再次查找。如下：

```C
// file: net/ipv4/tcp_cong.c
static struct tcp_congestion_ops *tcp_ca_find_autoload(struct net *net, const char *name)
{
    struct tcp_congestion_ops *ca = tcp_ca_find(name);
#ifdef CONFIG_MODULES
    if (!ca && capable(CAP_NET_ADMIN)) {
        rcu_read_unlock();
        request_module("tcp_%s", name);
        rcu_read_lock();
        ca = tcp_ca_find(name);
    }
#endif
    return ca;
}
```

`tcp_reinit_congestion_control`函数重新初始化拥塞控制算法，实现如下：

```C
// file: net/ipv4/tcp_cong.c
static void tcp_reinit_congestion_control(struct sock *sk, const struct tcp_congestion_ops *ca)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    // 清除拥塞控制算法
    tcp_cleanup_congestion_control(sk);
    // 设置拥塞控制接口
    icsk->icsk_ca_ops = ca;
    icsk->icsk_ca_setsockopt = 1;
    memset(icsk->icsk_ca_priv, 0, sizeof(icsk->icsk_ca_priv));

    // 设置或清除`ECN`标记
    if (ca->flags & TCP_CONG_NEEDS_ECN)
        INET_ECN_xmit(sk);
    else
        INET_ECN_dontxmit(sk);
    // 非关闭或监听的socket，初始化拥塞控制算法
    if (!((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)))
        tcp_init_congestion_control(sk);
}
```

`tcp_cleanup_congestion_control` 函数清除sk的拥塞控制算法，如下：

```C
// file: net/ipv4/tcp_cong.c
void tcp_cleanup_congestion_control(struct sock *sk)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    // 调用`.release`接口，释放`sk`的拥塞控制
    if (icsk->icsk_ca_ops->release)
        icsk->icsk_ca_ops->release(sk);
    // 释放拥塞控制算法
    bpf_module_put(icsk->icsk_ca_ops, icsk->icsk_ca_ops->owner);
}
```

`tcp_init_congestion_control` 函数初始化sk的拥塞控制算法，如下：

```C
// file: net/ipv4/tcp_cong.c
void tcp_init_congestion_control(struct sock *sk)
{
    struct inet_connection_sock *icsk = inet_csk(sk);

    tcp_sk(sk)->prior_ssthresh = 0;
    // 调用`.init`接口，初始化`sk`的拥塞控制
    if (icsk->icsk_ca_ops->init)
        icsk->icsk_ca_ops->init(sk);
    // 设置或清除`ECN`标记
    if (tcp_ca_needs_ecn(sk))
        INET_ECN_xmit(sk);
    else
        INET_ECN_dontxmit(sk);
    // 修改标记表示拥塞控制已经初始化
    icsk->icsk_ca_initialized = 1;
}
```

## 5 总结

本文通过`bpf_dctcp`示例程序分析了使用BPF实现TCP拥塞控制算法的过程。是借助`STRUCT_OPS`进行实现的，`STRUCT_OPS`通过使用BPF程序取代内核中特定的内核函数指针，具有替换内核中`ops`结构(`struct xxx_ops`)的能力。

## 参考资料

* [Introduce BPF STRUCT_OPS](https://lwn.net/Articles/809092/)
* [Kernel operations structures in BPF](https://lwn.net/Articles/811631/)
* [BPF 进阶笔记（五）：几种 TCP 相关的 BPF](https://arthurchiao.art/blog/bpf-advanced-notes-5-zh/#2-tcp-%E6%8B%A5%E5%A1%9E%E6%8E%A7%E5%88%B6cc)
* [深入浅出 BPF TCP 拥塞算法实现原理](https://www.ebpf.top/post/ebpf_struct_ops/)
