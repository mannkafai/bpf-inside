# STRUCT_OPS的内核实现

## 0 前言

在上一篇文章中我们分析了BPF在cgroup中应用，可以在cgroup级别对socket进行动态控制。今天，我们借助`bpf_dctcp`示例程序分析BPF在TCP中的另一项应用，动态设置拥塞控制算法。

## 1 简介

`STRUCT_OPS`允许BPF程序实现一些特定的内核函数指针，具有替换内核中`ops`结构(`struct xxx_ops`)的能力。其中第一个用例是用BPF实现TCP拥塞控制算法（即实现`struct tcp_congestion_ops`）。

## 2 `bpf_dctcp`示例程序

### 2.1 BPF程序

BPF程序源码参见[bpf_dctcp.c](../src/bpf_dctcp.c)，主要内容如下：

```C
struct bpf_dctcp {
    __u32 old_delivered;
    __u32 old_delivered_ce;
    __u32 prior_rcv_nxt;
    __u32 dctcp_alpha;
    __u32 next_seq;
    __u32 ce_state;
    __u32 loss_cwnd;
};

SEC("struct_ops")
void BPF_PROG(bpf_dctcp_init, struct sock *sk)
{
    ...
}

SEC("struct_ops")
__u32 BPF_PROG(bpf_dctcp_ssthresh, struct sock *sk)
{
    struct dctcp *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    ca->loss_cwnd = tp->snd_cwnd;
    return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->dctcp_alpha) >> 11U), 2U);
}

SEC("struct_ops")
__u32 BPF_PROG(bpf_dctcp_cwnd_undo, struct sock *sk)
{
    const struct dctcp *ca = inet_csk_ca(sk);
    return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

extern void tcp_reno_cong_avoid(struct sock *sk, __u32 ack, __u32 acked) __ksym;

SEC("struct_ops")
void BPF_PROG(bpf_dctcp_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
    tcp_reno_cong_avoid(sk, ack, acked);
}

SEC(".struct_ops")
struct tcp_congestion_ops dctcp = {
    .init       = (void *)bpf_dctcp_init,
    .in_ack_event   = (void *)bpf_dctcp_update_alpha,
    .cwnd_event = (void *)bpf_dctcp_cwnd_event,
    .ssthresh   = (void *)bpf_dctcp_ssthresh,
    .cong_avoid = (void *)bpf_dctcp_cong_avoid,
    .undo_cwnd  = (void *)bpf_dctcp_cwnd_undo,
    .set_state  = (void *)bpf_dctcp_state,
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
    struct cb_opts cb_opts = {
        .cc = "bpf_dctcp",
    };
    struct network_helper_opts opts = {
        .post_socket_cb = cc_cb,
        .cb_opts    = &cb_opts,
    };
    struct network_helper_opts cli_opts = {
        .post_socket_cb = stg_post_socket_cb,
        .cb_opts    = &cb_opts,
    };
    int lfd = -1, fd = -1, tmp_stg, err;
    struct bpf_dctcp *dctcp_skel;
    struct bpf_link *link;

    // 打开并加载BPF程序
    dctcp_skel = bpf_dctcp__open_and_load();
    if (!ASSERT_OK_PTR(dctcp_skel, "bpf_dctcp__open_and_load")) return;
    // 附加`struct_ops`
    link = bpf_map__attach_struct_ops(dctcp_skel->maps.dctcp);
    if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops")) {
        bpf_dctcp__destroy(dctcp_skel);
        return;
    }

    cb_opts.map_fd = bpf_map__fd(dctcp_skel->maps.sk_stg_map);
    // 测试
    if (!start_test(NULL, &opts, &cli_opts, &lfd, &fd)) goto done;

    err = bpf_map_lookup_elem(cb_opts.map_fd, &fd, &tmp_stg);
    if (!ASSERT_ERR(err, "bpf_map_lookup_elem(sk_stg_map)") ||
            !ASSERT_EQ(errno, ENOENT, "bpf_map_lookup_elem(sk_stg_map)"))
        goto done;
    // 发送数据
    ASSERT_OK(send_recv_data(lfd, fd, total_bytes), "send_recv_data");
    ASSERT_EQ(dctcp_skel->bss->stg_result, expected_stg, "stg_result");

done:
    // 销毁link和BPF程序
    bpf_link__destroy(link);
    bpf_dctcp__destroy(dctcp_skel);
    if (lfd != -1) close(lfd);
    if (fd != -1) close(fd);
}
// 测试函数
static bool start_test(char *addr_str,
                const struct network_helper_opts *srv_opts,
                const struct network_helper_opts *cli_opts,
                int *srv_fd, int *cli_fd)
{
    // 启动server
    *srv_fd = start_server_str(AF_INET6, SOCK_STREAM, addr_str, 0, srv_opts);
    if (!ASSERT_NEQ(*srv_fd, -1, "start_server_str")) goto err;

    // 连接server
    *cli_fd = connect_to_fd_opts(*srv_fd, cli_opts);
    if (!ASSERT_NEQ(*cli_fd, -1, "connect_to_fd_opts")) goto err;

    return true;

err:
    // 错误时的清理
    if (*srv_fd != -1) { close(*srv_fd); *srv_fd = -1; }
    if (*cli_fd != -1) { close(*cli_fd); *cli_fd = -1; }
    return false;
}
// 设置TCP拥塞控制算法
static int cc_cb(int fd, void *opts)
{
    struct cb_opts *cb_opts = (struct cb_opts *)opts;
    return settcpca(fd, cb_opts->cc);
}
// 设置TCP拥塞控制算法
static int settcpca(int fd, const char *tcp_ca)
{
    int err;
    // 设置TCP拥塞控制算法
    err = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, tcp_ca, strlen(tcp_ca));
    if (!ASSERT_NEQ(err, -1, "setsockopt"))
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
    const char *sec_name;
    int sec_idx, err;
    // 遍历所有的`sec`
    for (sec_idx = 0; sec_idx < obj->efile.sec_cnt; ++sec_idx) {
        struct elf_sec_desc *desc = &obj->efile.secs[sec_idx];
        // 跳过非`struct_ops`的`sec`
        if (desc->sec_type != SEC_ST_OPS) continue;

        sec_name = elf_sec_name(obj, elf_sec_by_idx(obj, sec_idx));
        if (!sec_name) return -LIBBPF_ERRNO__FORMAT;
        // 初始化`struct_ops`
        err = init_struct_ops_maps(obj, sec_name, sec_idx, desc->data);
        if (err) return err;
    }
    return 0;
}
```

`SEC_ST_OPS` 表示`struct_ops`类型的`sec`，在`bpf_object__elf_collect`中确定的，如下：

```C
// file: libbpf/src/libbpf.c
static int bpf_object__elf_collect(struct bpf_object *obj)
{
    ...
    scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        ...
        else if (sh->sh_type == SHT_PROGBITS && data->d_size > 0) {
            ...
            // 确定`sec`类型为`SEC_ST_OPS`
            else if (strcmp(name, STRUCT_OPS_SEC) == 0 ||
                    strcmp(name, STRUCT_OPS_LINK_SEC) == 0 ||
                    strcmp(name, "?" STRUCT_OPS_SEC) == 0 ||
                    strcmp(name, "?" STRUCT_OPS_LINK_SEC) == 0) {
                sec_desc->sec_type = SEC_ST_OPS;
                sec_desc->shdr = sh;
                sec_desc->data = data;
                obj->efile.has_st_ops = true;
            }
            ...
        }
    }
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
                        int shndx, Elf_Data *data)
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
        map->btf_value_type_id = type_id;
        // SEC("?.struct_ops") 表示不自动创建
        if (sec_name[0] == '?') {
            map->autocreate = false;
            sec_name++;
        }
        // 设置`map`定义信息
        map->def.type = BPF_MAP_TYPE_STRUCT_OPS;
        map->def.key_size = sizeof(int);
        map->def.value_size = type->size;
        map->def.max_entries = 1;
        map->def.map_flags = strcmp(sec_name, STRUCT_OPS_LINK_SEC) == 0 ? BPF_F_LINK : 0;
        map->autoattach = true;

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
        // 设置`st_ops` 类型属性
        memcpy(st_ops->data, data->d_buf + vsi->offset, type->size);
        st_ops->type_id = type_id;
    }
    return 0;
}
```

在加载阶段通过 `bpf_map__init_kern_struct_ops` 函数初始化`.struct_ops`内核相关属性，如下：

```C
// file: libbpf/src/libbpf.c
static int bpf_map__init_kern_struct_ops(struct bpf_map *map)
{
    const struct btf_member *member, *kern_member, *kern_data_member;
    const struct btf_type *type, *kern_type, *kern_vtype;
    struct bpf_object *obj = map->obj;
    const struct btf *btf = obj->btf;
    struct bpf_struct_ops *st_ops;
    ...
    
    // 获取`.struct_ops`内核中属性
    st_ops = map->st_ops;
    type = btf__type_by_id(btf, st_ops->type_id);
    tname = btf__name_by_offset(btf, type->name_off);
    err = find_struct_ops_kern_types(obj, tname, &mod_btf, &kern_type, &kern_type_id, 
                &kern_vtype, &kern_vtype_id, &kern_data_member);
    if (err) return err;

    // 获取`kern_btf`
    kern_btf = mod_btf ? mod_btf->btf : obj->btf_vmlinux;
    // 设置`map`定义信息
    map->mod_btf_fd = mod_btf ? mod_btf->fd : -1;
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
        ...
        // 从用户空间btf中获取变量名称, 计算偏移位置
        mname = btf__name_by_offset(btf, member->name_off);
        moff = member->offset / 8;
        mdata = data + moff;
        msize = btf__resolve_size(btf, member->type);
        // 检查用户空间字段大小是否异常
        if (msize < 0) { ... }
        
        // 从内核btf中获取内核字段
        kern_member = find_member_by_name(kern_btf, kern_type, mname);
        if (!kern_member) { ... }

        kern_member_idx = kern_member - btf_members(kern_type);
        // 检查用户空间和内核空间字段是否是位域, `struct_ops`不支持位域
        if (btf_member_bitfield_size(type, i) ||
            btf_member_bitfield_size(kern_type, kern_member_idx)) {
            pr_warn("struct_ops init_kern %s: bitfield %s is not supported\n", map->name, mname);
            return -ENOTSUP;
        }
        // 计算内核字段的偏移位置
        kern_moff = kern_member->offset / 8;
        kern_mdata = kern_data + kern_moff;

        // 检查用户空间和内核空间变量的类型是否匹配
        mtype = skip_mods_and_typedefs(btf, member->type, &mtype_id);
        kern_mtype = skip_mods_and_typedefs(kern_btf, kern_member->type, &kern_mtype_id);
        if (BTF_INFO_KIND(mtype->info) != BTF_INFO_KIND(kern_mtype->info)) { ... }
        // 该字段是指针，表示是函数
        if (btf_is_ptr(mtype)) {
            // 获取BPF程序，在重定位阶段获取的
            prog = *(void **)mdata;
            // 用户替换了BPF程序或者置空，设置`autoload`为`false`
            if (st_ops->progs[i] && st_ops->progs[i] != prog)
                st_ops->progs[i]->autoload = false;
            // 设置`st_ops`的BPF程序
            st_ops->progs[i] = prog;
            if (!prog) continue;
            // 检查是否是有效的`struct_ops`程序
            if (!is_valid_st_ops_program(obj, prog)) { ... }
            // 获取内核类型
            kern_mtype = skip_mods_and_typedefs(kern_btf, kern_mtype->type, &kern_mtype_id);
            if (!btf_is_func_proto(kern_mtype)) { ... }

            if (mod_btf) prog->attach_btf_obj_fd = mod_btf->fd;
            // 设置bpf程序btf_id和附加类型
            if (!prog->attach_btf_id) {
                prog->attach_btf_id = kern_type_id;
                prog->expected_attach_type = kern_member_idx;
            }
            // 设置`st_ops`内核函数的偏移位置
            st_ops->kern_func_off[i] = kern_data_off + kern_moff;
            continue;
        }
        // 检查用户空间和内核空间变量的大小是否匹配
        kern_msize = btf__resolve_size(kern_btf, kern_mtype_id);
        if (kern_msize < 0 || msize != kern_msize) { ... }
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
    if (!bpf_map__is_struct_ops(map)) { ... }
    if (map->fd < 0) { ... }
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

### 3.4  `.struct_ops.link`的管理

`.struct_ops.link`类型时，通过link实现`struct_ops`的注册/注销等管理。如下：

```C
// file: libbpf/src/libbpf.c
struct bpf_link *bpf_map__attach_struct_ops(const struct bpf_map *map)
{
    ....

    // 设置`LINK`标记，即: `.struct_ops.link` 类型创建内核LINK
    fd = bpf_link_create(map->fd, 0, BPF_STRUCT_OPS, NULL);
    if (fd < 0) { ... }

    link->link.fd = fd;
    link->map_fd = map->fd;
    return &link->link;
}
```

`bpf_link_create`在设置和检查`bpf_attr`属性后，使用`BPF_LINK_CREATE`指令进行BPF系统调用。如下：

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
    // 根据附加类型设置opts属性
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

## 4 内核实现

### 4.1 `struct_ops`的内核实现

#### 1 `bpf_struct_ops`的定义

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
    int (*reg)(void *kdata, struct bpf_link *link);
    void (*unreg)(void *kdata, struct bpf_link *link);
    int (*update)(void *kdata, void *old_kdata, struct bpf_link *link);
    int (*validate)(void *kdata);
    void *cfi_stubs;
    struct module *owner;
    const char *name;
    struct btf_func_model func_models[BPF_STRUCT_OPS_MAX_NR_MEMBERS];
};
```

通过该结构定义可以了解到，`struct_ops` 最多支持64个属性，支持初始化(`.init`)、初始化字段(`.init_member`)、注册(`.reg`)、注销(`.unreg`)等接口。

Linux内核V6.9之前只支持几种固定类型`bpf_struct_ops`，如`bpf_dummy_ops`和`tcp_congestion_ops`等，后续版本支持动态注册`bpf_struct_ops`，`register_bpf_struct_ops`函数用于注册`bpf_struct_ops`。

#### 2 `struct_ops`的注册过程

`register_bpf_struct_ops`函数动态注册`bpf_struct_ops`，以`tcp_congestion_ops`为例，在内核初始化阶段注册，如下：

```C
// file:net/ipv4/bpf_tcp_ca.c
static int __init bpf_tcp_ca_kfunc_init(void)
{
    int ret;

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_tcp_ca_kfunc_set);
    ret = ret ?: register_bpf_struct_ops(&bpf_tcp_congestion_ops, tcp_congestion_ops);

    return ret;
}
late_initcall(bpf_tcp_ca_kfunc_init);
```

`register_bpf_struct_ops`是个宏定义，如下：

```C
// file: include/linux/bpf.h
#define register_bpf_struct_ops(st_ops, type)               \
    ({                                                      \
        struct bpf_struct_ops_##type {                      \
            struct bpf_struct_ops_common_value common;      \
            struct type data ____cacheline_aligned_in_smp;  \
        };                                                  \
        BTF_TYPE_EMIT(struct bpf_struct_ops_##type);        \
        __register_bpf_struct_ops(st_ops);                  \
    })
```

`register_bpf_struct_ops`定义了一个`struct bpf_struct_ops_##type`结构，`BTF_TYPE_EMIT`触发`struct bpf_struct_ops_##type`类型的BTF信息，`__register_bpf_struct_ops`函数实现具体的注册功能，如下：

```C
// file: kernel/bpf/btf.c
int __register_bpf_struct_ops(struct bpf_struct_ops *st_ops)
{
    struct bpf_verifier_log *log;
    struct btf *btf;
    int err = 0;

    // 获取BTF
    btf = btf_get_module_btf(st_ops->owner);
    if (!btf) return check_btf_kconfigs(st_ops->owner, "struct_ops");
    if (IS_ERR(btf)) return PTR_ERR(btf);
    // 分配`log`
    log = kzalloc(sizeof(*log), GFP_KERNEL | __GFP_NOWARN);
    if (!log) { err = -ENOMEM; goto errout; }

    log->level = BPF_LOG_KERNEL;
    // 添加`struct_ops`到BTF
    err = btf_add_struct_ops(btf, st_ops, log);

errout:
    kfree(log);
    btf_put(btf);
    return err;
}
```

`btf_add_struct_ops`函数添加`struct_ops`到BTF，如下：

```C
// file: kernel/bpf/btf.c
static int btf_add_struct_ops(struct btf *btf, struct bpf_struct_ops *st_ops,
            struct bpf_verifier_log *log)
{
    struct btf_struct_ops_tab *tab, *new_tab;
    int i, err;

    tab = btf->struct_ops_tab;
    if (!tab) {
        // 初次注册`struct_ops`，分配4个槽位
        tab = kzalloc(struct_size(tab, ops, 4), GFP_KERNEL);
        if (!tab) return -ENOMEM;
        tab->capacity = 4;
        btf->struct_ops_tab = tab;
    }
    // 检查`struct_ops`是否已存在
    for (i = 0; i < tab->cnt; i++)
        if (tab->ops[i].st_ops == st_ops) return -EEXIST;
    
    if (tab->cnt == tab->capacity) {
        // 槽位已满，按照2倍扩容
        new_tab = krealloc(tab, struct_size(tab, ops, tab->capacity * 2), GFP_KERNEL);
        if (!new_tab) return -ENOMEM;
        tab = new_tab;
        tab->capacity *= 2;
        btf->struct_ops_tab = tab;
    }
    // 注册`struct_ops`
    tab->ops[btf->struct_ops_tab->cnt].st_ops = st_ops;
    // 初始化`struct_ops`
    err = bpf_struct_ops_desc_init(&tab->ops[btf->struct_ops_tab->cnt], btf, log);
    if (err) return err;
    // 增加`struct_ops`数量，完成实际的注册
    btf->struct_ops_tab->cnt++;
    return 0;
}
```

`bpf_struct_ops_desc_init` 函数实现`struct_ops`的初始化，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
int bpf_struct_ops_desc_init(struct bpf_struct_ops_desc *st_ops_desc,
        struct btf *btf, struct bpf_verifier_log *log)
{
    struct bpf_struct_ops *st_ops = st_ops_desc->st_ops;
    struct bpf_struct_ops_arg_info *arg_info;
    const struct btf_member *member;
    const struct btf_type *t;
    s32 type_id, value_id;
    char value_name[128];
    const char *mname;
    int i, err;

    // 检查`st_ops`名称长度，加上前缀不能超过128
    if (strlen(st_ops->name) + VALUE_PREFIX_LEN >= sizeof(value_name)) { ... }
    sprintf(value_name, "%s%s", VALUE_PREFIX, st_ops->name);
    
    // `st_ops`必须有`cfi_stubs`
    if (!st_ops->cfi_stubs) { ... }

    // 从BTF中获取`st_ops`名称id
    type_id = btf_find_by_name_kind(btf, st_ops->name, BTF_KIND_STRUCT);
    if (type_id < 0) { ... }
    // 从BTF中获取`st_ops`值id
    value_id = btf_find_by_name_kind(btf, value_name, BTF_KIND_STRUCT);
    if (value_id < 0) { ... }
    // 检查`st_ops`值类型是否是有效类型
    if (!is_valid_value_type(btf, value_id, t, value_name)) return -EINVAL;

    // 分配`arg_info`
    arg_info = kcalloc(btf_type_vlen(t), sizeof(*arg_info), GFP_KERNEL);
    if (!arg_info) return -ENOMEM;

    // 设置描述信息
    st_ops_desc->arg_info = arg_info;
    st_ops_desc->type = t;
    st_ops_desc->type_id = type_id;
    st_ops_desc->value_id = value_id;
    st_ops_desc->value_type = btf_type_by_id(btf, value_id);

    // 初始化`st_ops`类型中的字段
    for_each_member(i, t, member) {
        const struct btf_type *func_proto, *ret_type;
        void **stub_func_addr;
        u32 moff;
        
        // 获取字段名称
        moff = __btf_member_bit_offset(t, member) / 8;
        mname = btf_name_by_offset(btf, member->name_off);
        if (!*mname) { ... }
        // 检查字段是否是位域，不支持位域
        if (__btf_member_bitfield_size(t, member)) { ... }
        // 检查字段是否是模块成员
        if (!st_ops_ids[IDX_MODULE_ID] && is_module_member(btf, member->type)) { ... }
        // 解析并初始化函数原型
        func_proto = btf_type_resolve_func_ptr(btf, member->type, NULL);
        // 函数原型不存在或不支持，跳过该字段
        if (!func_proto || bpf_struct_ops_supported(st_ops, moff)) continue;

        if (func_proto->type) {
            // 解析函数返回类型
            ret_type = btf_type_resolve_ptr(btf, func_proto->type, NULL);
            // 检查返回类型是否是结构体
            if (ret_type && !__btf_type_is_struct(ret_type)) { ... }
        }
        // 解析函数的参数
        if (btf_distill_func_proto(log, btf, func_proto, mname, &st_ops->func_models[i])) { ... }
        // 获取桩函数地址
        stub_func_addr = *(void **)(st_ops->cfi_stubs + moff);
        // 初始化函数的参数
        err = prepare_arg_info(btf, st_ops->name, mname, func_proto, stub_func_addr, arg_info + i);
        if (err) goto errout;
    }
    // 存在`.init`接口时，进行初始化
    if (st_ops->init(btf)) { ... }
    return 0;

errout:
    // 注册失败时，清理
    bpf_struct_ops_desc_release(st_ops_desc);
    return err;
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
    case BPF_MAP_CREATE: map_create(&attr, uattr.is_kernel); break;
    ...
    }
    return err;
}
```

`map_create`函数实现bpf map的创建，如下：

```C
// file: kernel/bpf/syscall.c
static int map_create(union bpf_attr *attr, bool kernel)
{
    int numa_node = bpf_map_attr_numa_node(attr);
    struct btf_field_offs *foffs;
    struct bpf_map *map;
    int f_flags;
    int err;

    // 检查`attr`设置，检查BTF、BLOOM_FILTER、flags、numa_node是否正确设置
    err = CHECK_ATTR(BPF_MAP_CREATE);
    // 获取`BPF_F_TOKEN_FD`
    token_flag = attr->map_flags & BPF_F_TOKEN_FD;
    attr->map_flags &= ~BPF_F_TOKEN_FD;

    // 检查`attr`中`key`和`value`的BTF类型
    if (attr->btf_vmlinux_value_type_id) {
        if (attr->map_type != BPF_MAP_TYPE_STRUCT_OPS ||
            attr->btf_key_type_id || attr->btf_value_type_id)
            return -EINVAL;
    } else if (attr->btf_key_type_id && !attr->btf_value_type_id) {
        return -EINVAL;
    }
    // `BLOOM_FILTER`和`ARENA`不支持`extra`字段
    if (attr->map_type != BPF_MAP_TYPE_BLOOM_FILTER && 
        attr->map_type != BPF_MAP_TYPE_ARENA && attr->map_extra != 0)
        return -EINVAL;
    
    // 检查设置的读写标记是否正确
    f_flags = bpf_get_file_flag(attr->map_flags);
    if (f_flags < 0) return f_flags;

    // 检查`numa_node`是否有效
    if (numa_node != NUMA_NO_NODE && ((unsigned int)numa_node >= nr_node_ids || !node_online(numa_node)))
        return -EINVAL;

    // 检查type是否越界 
    map_type = attr->map_type;
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
    // 不支持`.map_mem_usage`接口时，无效
    if (!ops->map_mem_usage) return -EINVAL;
    // 设置token时，获取对应的token
    if (token_flag) { ... }

    err = -EPERM;
    // 非特权BPF时，检查token是否有效
    if (sysctl_unprivileged_bpf_disabled && !bpf_token_capable(token, CAP_BPF)) goto put_token;
    ...

    // `.map_alloc`接口，分配map
    map = ops->map_alloc(attr);
    if (IS_ERR(map)) return map;
    // map设置
    map->ops = ops;
    map->map_type = type;

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

    // LSM安全检查
    err = security_bpf_map_create(map, attr, token, kernel);
    if (err) goto free_map_sec;
    // 分配map id
    err = bpf_map_alloc_id(map);
    if (err) goto free_map_sec;
    // 保存 内存cgroup (`memcg`)
    bpf_map_save_memcg(map);
    // 释放`token`
    bpf_token_put(token);
    // map关联file
    err = bpf_map_new_fd(map, f_flags);
    // 关联文件失败时，释放map
    if (err < 0) { bpf_map_put_with_uref(map); return err; }
    // 返回fd
    return err;

free_map_sec:
    security_bpf_map_free(map);
free_map:
    bpf_map_free(map);
put_token:
    bpf_token_put(token);
    return err;
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
    .get_unmapped_area = bpf_get_unmapped_area,
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
    .map_mem_usage = bpf_struct_ops_map_mem_usage,
    .map_btf_id = &bpf_struct_ops_map_btf_ids[0],
};
```

`.map_alloc_check`接口在创建map前调用，设置为 `bpf_struct_ops_map_alloc_check`, 实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static int bpf_struct_ops_map_alloc_check(union bpf_attr *attr)
{
    if (attr->key_size != sizeof(unsigned int) || attr->max_entries != 1 ||
        (attr->map_flags & ~(BPF_F_LINK | BPF_F_VTYPE_BTF_OBJ_FD)) ||
        !attr->btf_vmlinux_value_type_id)
        return -EINVAL;
    return 0;
}
```

`STRUCT_OPS`类型的map，只能包含一个项、key为4个字节，支持`BPF_F_LINK`和`BPF_F_VTYPE_BTF_OBJ_FD`标记、类型必须在内核`btf`中存在。

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
    
    if (attr->map_flags & BPF_F_VTYPE_BTF_OBJ_FD) {
        // 从`module`中获取`btf`
        btf = btf_get_by_fd(attr->value_type_btf_obj_fd);
        if (IS_ERR(btf)) return ERR_CAST(btf);
        if (!btf_is_module(btf)) { btf_put(btf); return ERR_PTR(-EINVAL); }
        mod = btf_try_get_module(btf);
        btf_put(btf);
        if (!mod) return ERR_PTR(-EINVAL);
    } else {
        // 从vmlinux中获取`btf`
        btf = bpf_get_btf_vmlinux();
        if (IS_ERR(btf)) return ERR_CAST(btf);
        if (!btf) return ERR_PTR(-ENOTSUPP);
    }

    // 根据`btf_vmlinux_value_type_id`获取`st_ops`
    st_ops = bpf_struct_ops_find_value(btf, attr->btf_vmlinux_value_type_id);
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
    st_map->funcs_cnt = count_func_ptrs(btf, t);
    st_map->links = bpf_map_area_alloc(st_map->funcs_cnt * sizeof(struct bpf_link *), NUMA_NO_NODE);
    st_map->ksyms = bpf_map_area_alloc(st_map->funcs_cnt * sizeof(struct bpf_ksym *), NUMA_NO_NODE);
    if (!st_map->uvalue || !st_map->links || !st_map->ksyms) { ... }

    st_map->btf = btf;
    // map属性设置
    bpf_map_init_from_attr(map, attr);
    
    return map;
errout_free:
    __bpf_struct_ops_map_free(map);
errout:
    module_put(mod);
    return ERR_PTR(ret);
}
```

`bpf_struct_ops_find_value`函数获取对应的`st_ops`，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
const struct bpf_struct_ops_desc *
bpf_struct_ops_find_value(struct btf *btf, u32 value_id)
{
    const struct bpf_struct_ops_desc *st_ops_list;
    unsigned int i;
    u32 cnt;

    if (!value_id) return NULL;
    if (!btf->struct_ops_tab) return NULL;

    cnt = btf->struct_ops_tab->cnt;
    st_ops_list = btf->struct_ops_tab->ops;
    // 遍历所有的`st_ops`，查找`value_id`对应的`st_ops`
    for (i = 0; i < cnt; i++) {
        if (st_ops_list[i].value_id == value_id) return &st_ops_list[i];
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
    ...
    
    // `ATTR`检查
    if (CHECK_ATTR(BPF_MAP_UPDATE_ELEM)) return -EINVAL;
    
    // 根据fd获取map后，进行权限检查
    CLASS(fd, f)(attr->map_fd);
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
    err = bpf_map_update_value(map, fd_file(f), key, value, attr->flags);

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
            map->map_type == BPF_MAP_TYPE_ARENA ||
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
    const struct bpf_struct_ops_desc *st_ops_desc = st_map->st_ops_desc;
    const struct bpf_struct_ops *st_ops = st_ops_desc->st_ops;
    struct bpf_struct_ops_value *uvalue, *kvalue;
    ...

    // 不支持flags设置
    if (flags) return -EINVAL;
    // key 必须为0
    if (*(u32 *)key != 0) return -E2BIG;
    // 检查值类型是否匹配
    err = check_zero_holes(st_map->btf, st_ops_desc->value_type, value);
    if (err) return err;
    // 检查类型是否匹配
    uvalue = value;
    err = check_zero_holes(st_map->btf, t, uvalue->data);
    if (err) return err;

    // 检查是否重复更新
    if (uvalue->common.state || refcount_read(&uvalue->common.refcnt)) return -EINVAL;
    // 分配`tramp_links`内存空间
    tlinks = kcalloc(BPF_TRAMP_MAX, sizeof(*tlinks), GFP_KERNEL);
    if (!tlinks) return -ENOMEM;

    uvalue = (struct bpf_struct_ops_value *)st_map->uvalue;
    kvalue = (struct bpf_struct_ops_value *)&st_map->kvalue;

    mutex_lock(&st_map->lock);
    // 检查kvalue状态
    if (kvalue->common.state != BPF_STRUCT_OPS_STATE_INIT) { err = -EBUSY; goto unlock; }

    // 复制用户空间设置的值
    memcpy(uvalue, value, map->value_size);

    udata = &uvalue->data;
    kdata = &kvalue->data;
    
    plink = st_map->links;
    pksym = st_map->ksyms;
    tname = btf_name_by_offset(st_map->btf, t->name_off);
    module_type = btf_type_by_id(btf_vmlinux, st_ops_ids[IDX_MODULE_ID]);
    for_each_member(i, t, member) {
        const struct btf_type *mtype, *ptype;
        struct bpf_prog *prog;
        struct bpf_tramp_link *link;
        struct bpf_ksym *ksym;
        u32 moff;
        // 获取`struct_ops`中字段的偏移量和类型
        moff = __btf_member_bit_offset(t, member) / 8;
        mname = btf_name_by_offset(st_map->btf, member->name_off);
        ptype = btf_type_resolve_ptr(st_map->btf, member->type, NULL);
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
            mtype = btf_type_by_id(st_map->btf, member->type);
            mtype = btf_resolve_size(st_map->btf, mtype, &msize);
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
            prog->aux->attach_btf_id != st_ops_desc->type_id ||
            prog->expected_attach_type != i)  { ...  }
        // 分配并初始化`tramp_link`
        link = kzalloc(sizeof(*link), GFP_USER);
        if (!link) { ... }
        bpf_link_init(&link->link, BPF_LINK_TYPE_STRUCT_OPS, &bpf_struct_ops_link_lops, prog);
        *plink++ = &link->link;
        // 初始化`ksym`
        ksym = kzalloc(sizeof(*ksym), GFP_USER);
        if (!ksym) { ... }
        *pksym++ = ksym;

        // `stract_ops`字段为BPF程序时，设置为BPF trampoline
        trampoline_start = image_off;
        err = bpf_struct_ops_prepare_trampoline(tlinks, link, &st_ops->func_models[i],
                *(void **)(st_ops->cfi_stubs + moff), &image, &image_off,
                st_map->image_pages_cnt < MAX_TRAMP_IMAGE_PAGES);
        if (err < 0) goto reset_unlock;
        if (cur_image != image) {
            // 当前页用完了，增加`image`页
            st_map->image_pages[st_map->image_pages_cnt++] = image;
            cur_image = image;
            trampoline_start = 0;
        }
        // 设置`trampoline`地址到内核空间
        *(void **)(kdata + moff) = image + trampoline_start + cfi_get_offset();
        // 设置 prog_id 到用户空间
        *(unsigned long *)(udata + moff) = prog->aux->id;
        // 初始化`trampoline`的`ksym`
        bpf_struct_ops_ksym_init(tname, mname, image + trampoline_start,
                image_off - trampoline_start, ksym);
    }
    // 存在`.validate`函数时，验证内核空间数据
    if (st_ops->validate) { 
        err = st_ops->validate(kdata);
        if (err) goto reset_unlock;
    }
    // 保护`image`页
    for (i = 0; i < st_map->image_pages_cnt; i++) {
        err = arch_protect_bpf_trampoline(st_map->image_pages[i], PAGE_SIZE);
        if (err) goto reset_unlock;
    }
    // 使用`BPF_F_LINK`时，通过`bpf_link`处理注册和注销
    if (st_map->map.map_flags & BPF_F_LINK) {
        err = 0;
        smp_store_release(&kvalue->common.state, BPF_STRUCT_OPS_STATE_READY);
        goto unlock;
    }
    // 注册`st_ops`
    err = st_ops->reg(kdata, NULL);
    if (likely(!err)) {
        // 注册成功后，增加计数，设置为`INUSE`状态
        bpf_map_inc(map);
        smp_store_release(&kvalue->common.state, BPF_STRUCT_OPS_STATE_INUSE);
        goto unlock;
    }

reset_unlock:
    // 释放`st_map`的`ksym`,`image`,`BPF程序`，清空`st_map`的用户空间、内核空间的值
    bpf_struct_ops_map_free_ksyms(st_map);
    bpf_struct_ops_map_free_image(st_map);
    bpf_struct_ops_map_put_progs(st_map);
    memset(uvalue, 0, map->value_size);
    memset(kvalue, 0, map->value_size);
unlock:
    // 释放`tlinks`
    kfree(tlinks);
    mutex_unlock(&st_map->lock);
    // 注册成功时，增加`ksym`
    if (!err) bpf_struct_ops_map_add_ksyms(st_map);
    return err;
}
```

`bpf_struct_ops_prepare_trampoline` 函数处理`struct_ops`字段为BPF程序的情形，实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
int bpf_struct_ops_prepare_trampoline(struct bpf_tramp_links *tlinks, struct bpf_tramp_link *link,
            const struct btf_func_model *model, void *stub_func, 
            void **_image, u32 *_image_off, bool allow_alloc)
{
    u32 image_off = *_image_off, flags = BPF_TRAMP_F_INDIRECT;
    void *image = *_image;
    int size;
    // 设置`FENTRY`
    tlinks[BPF_TRAMP_FENTRY].links[0] = link;
    tlinks[BPF_TRAMP_FENTRY].nr_links = 1;
    // `BPF_TRAMP_F_RET_FENTRY_RET`只能由`bpf_struct_ops`单独使用
    flags = model->ret_size > 0 ? BPF_TRAMP_F_RET_FENTRY_RET : 0;
    // 计算`trampoline`大小
    size = arch_bpf_trampoline_size(model, flags, tlinks, stub_func);
    if (size <= 0) return size ? : -EFAULT;
    // 必要时分配`image`页
    if (!image || size > PAGE_SIZE - image_off) {
        if (!allow_alloc) return -E2BIG;
        // 分配`image`页
        image = bpf_struct_ops_image_alloc();
        if (IS_ERR(image)) return PTR_ERR(image);
        image_off = 0;
    }
    // 生成`trampoline`
    size = arch_prepare_bpf_trampoline(NULL, image + image_off,
            image + image_off + size, model, flags, tlinks, stub_func);
    // 失败时的检查，释放刚分配的`image`页
    if (size <= 0) { 
        if (image != *_image) bpf_struct_ops_image_free(image);
        return size ? : -EFAULT;
    }
    // 成功时，更新`image`和`image_off`
    *_image = image;
    *_image_off = image_off + size;
    return 0;
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
    struct bpf_map *map;
    void *key;
    int err;

    // `ATTR`检查
    if (CHECK_ATTR(BPF_MAP_DELETE_ELEM)) return -EINVAL;

    // 根据fd获取map后，进行权限检查
    CLASS(fd, f)(attr->map_fd);
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
    if (!err) maybe_wait_bpf_programs(map);
out:
    kvfree(key);
err_put:
    bpf_map_write_active_dec(map);
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
    // `BPF_F_LINK`不能删除
    if (st_map->map.map_flags & BPF_F_LINK) return -EOPNOTSUPP;
    // 检查状态
    prev_state = cmpxchg(&st_map->kvalue.common.state, BPF_STRUCT_OPS_STATE_INUSE, BPF_STRUCT_OPS_STATE_TOBEFREE);
    switch (prev_state) {
    case BPF_STRUCT_OPS_STATE_INUSE:
        // 注销`st_ops`
        st_map->st_ops_desc->st_ops->unreg(&st_map->kvalue.data, NULL);
        // 释放map
        bpf_map_put(map);
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
    .get_unmapped_area = bpf_get_unmapped_area,
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
        WARN_ON_ONCE(atomic64_read(&map->sleepable_refcnt));
        if (READ_ONCE(map->free_after_mult_rcu_gp))
            call_rcu_tasks_trace(&map->rcu, bpf_map_free_mult_rcu_gp);
        else if (READ_ONCE(map->free_after_rcu_gp))
            call_rcu(&map->rcu, bpf_map_free_rcu_gp);
        else
            bpf_map_free_in_work(map);
    }
}
```

`bpf_map_free_in_work`函数在工作队列中释放map，实现如下：

```C
// file: kernel/bpf/syscall.c
static void bpf_map_free_in_work(struct bpf_map *map)
{
    INIT_WORK(&map->work, bpf_map_free_deferred);
    queue_work(system_unbound_wq, &map->work);
}
```

`bpf_map_free_deferred` 函数是设置的释放接口，实现如下：

```C
// file: kernel/bpf/syscall.c
static void bpf_map_free_deferred(struct work_struct *work)
{
    struct bpf_map *map = container_of(work, struct bpf_map, work);
    // LSM安全检查
    security_bpf_map_free(map);
    bpf_map_release_memcg(map);
    bpf_map_free(map);
}
```

`bpf_map_free`函数释放map，实现如下：

```C
// file: kernel/bpf/syscall.c
static void bpf_map_free(struct bpf_map *map)
{
    struct btf_record *rec = map->record;
    struct btf *btf = map->btf;

    migrate_disable();
    // `.map_free`接口
    map->ops->map_free(map);
    migrate_enable();

    btf_record_free(rec);
    btf_put(btf);
}
```

##### (2) `struct_ops_map`的释放过程

`.map_free`接口释放map时调用，设置为 `bpf_struct_ops_map_free`, 实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static void bpf_struct_ops_map_free(struct bpf_map *map)
{
    struct bpf_struct_ops_map *st_map = (struct bpf_struct_ops_map *)map;
    // 是BTF模块，需要释放模块
    if (btf_is_module(st_map->btf))
        module_put(st_map->st_ops_desc->st_ops->owner);
    bpf_struct_ops_map_del_ksyms(st_map);
    synchronize_rcu_mult(call_rcu, call_rcu_tasks);
    __bpf_struct_ops_map_free(map);
}
```

`bpf_struct_ops_map_del_ksyms` 函数释放`st_map`的ksyms，实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static void bpf_struct_ops_map_del_ksyms(struct bpf_struct_ops_map *st_map)
{
    u32 i;
    for (i = 0; i < st_map->funcs_cnt; i++) {
        if (!st_map->ksyms[i]) break;
        bpf_image_ksym_del(st_map->ksyms[i]);
    }
}
```

`__bpf_struct_ops_map_free`函数释放`st_map`，实现如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static void __bpf_struct_ops_map_free(struct bpf_map *map)
{
    struct bpf_struct_ops_map *st_map = (struct bpf_struct_ops_map *)map;

    // 释放`struct_ops`的BPF程序
    if (st_map->links)
        bpf_struct_ops_map_put_progs(st_map);
    // 释放ksyms
    if (st_map->ksyms)
        bpf_struct_ops_map_free_ksyms(st_map);
    bpf_map_area_free(st_map->links);
    bpf_map_area_free(st_map->ksyms);
    // 释放image
    bpf_struct_ops_map_free_image(st_map);
    bpf_map_area_free(st_map->uvalue);
    bpf_map_area_free(st_map);
}
```

`bpf_struct_ops_map_put_progs` 函数释放`struct_ops`的BPF程序，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static void bpf_struct_ops_map_put_progs(struct bpf_struct_ops_map *st_map)
{
    u32 i;
    for (i = 0; i < st_map->funcs_cnt; i++) {
        if (!st_map->links[i]) break;
        // 释放link
        bpf_link_put(st_map->links[i]);
        st_map->links[i] = NULL;
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

### 4.3 `.struct_ops.link`的内核实现

#### 1 注册过程

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

`link_create` 在检查BFP程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。 `.struct_ops.link` 设置的附加类型为`BPF_STRUCT_OPS`，对应 `bpf_struct_ops_link_create` 处理函数。如下：

```C
// file: kernel/bpf/syscall.c
static int link_create(union bpf_attr *attr, bpfptr_t uattr)
{
    ...
    if (attr->link_create.attach_type == BPF_STRUCT_OPS)
        return bpf_struct_ops_link_create(attr);
    ...
}
```

##### (3) `bpf_struct_ops_link_create`

`bpf_struct_ops_link_create` 函数检查用户输入的参数信息，设置`link`操作接口后，注册`struct_ops`。如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
int bpf_struct_ops_link_create(union bpf_attr *attr)
{
    struct bpf_struct_ops_link *link = NULL;
    struct bpf_link_primer link_primer;
    struct bpf_struct_ops_map *st_map;
    struct bpf_map *map;
    int err;

    // 获取`struct_ops`的map
    map = bpf_map_get(attr->link_create.map_fd);
    if (IS_ERR(map)) return PTR_ERR(map);

    st_map = (struct bpf_struct_ops_map *)map;
    // 检查`struct_ops`的map是否能够注册，
    // 即:设置了`BPF_F_LINK`标记，状态为`BPF_STRUCT_OPS_STATE_READY`    
    if (!bpf_struct_ops_valid_to_reg(map)) { err = -EINVAL; goto err_out; }
    
    // 创建 link
    link = kzalloc(sizeof(*link), GFP_USER);
    if (!link) { err = -ENOMEM; goto err_out; }
    // 设置`link`属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_STRUCT_OPS, &bpf_struct_ops_map_lops, NULL);
    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    if (err) goto err_out;
    // 初始化wq
    init_waitqueue_head(&link->wait_hup);

    mutex_lock(&update_mutex);
    // `struct_ops`的注册操作
    err = st_map->st_ops_desc->st_ops->reg(st_map->kvalue.data, &link->link);
    if (err) { ... }
    RCU_INIT_POINTER(link->map, map);
    mutex_unlock(&update_mutex);

    // fd 和 file 进行关联
    return bpf_link_settle(&link_primer);
err_out:
    // 失败时的清理
    bpf_map_put(map);
    kfree(link);
    return err;
}
```

#### 2 注销BPF程序的过程

##### (1) `bpf_struct_ops_map_lops`接口

在`bpf_struct_ops_link_create`函数附加link过程中，设置了用户空间操作`bpf_link`的文件接口，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
int bpf_struct_ops_link_create(union bpf_attr *attr)
{
    ...
    // 设置link属性
    bpf_link_init(&link->link, BPF_LINK_TYPE_STRUCT_OPS, &bpf_struct_ops_map_lops, NULL);
    ...
    // 提供用户空间使用的 fd, id，anon_inode 信息
    err = bpf_link_prime(&link->link, &link_primer);
    ...
}
```

`bpf_struct_ops_map_lops` 是设置的文件操作接口，定义如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static const struct bpf_link_ops bpf_struct_ops_map_lops = {
    .dealloc = bpf_struct_ops_map_link_dealloc,
    .detach = bpf_struct_ops_map_link_detach,
    .show_fdinfo = bpf_struct_ops_map_link_show_fdinfo,
    .fill_link_info = bpf_struct_ops_map_link_fill_link_info,
    .update_map = bpf_struct_ops_map_link_update,
    .poll = bpf_struct_ops_map_link_poll,
};
```

##### (2) 分离接口

`.detach`接口分离`bpf_link`关联的程序。`bpf_struct_ops_map_link_detach`分离`link`，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static int bpf_struct_ops_map_link_detach(struct bpf_link *link)
{
    struct bpf_struct_ops_link *st_link = container_of(link, struct bpf_struct_ops_link, link);
    struct bpf_struct_ops_map *st_map;
    struct bpf_map *map;

    mutex_lock(&update_mutex);

    map = rcu_dereference_protected(st_link->map, lockdep_is_held(&update_mutex));
    if (!map) { mutex_unlock(&update_mutex); return 0; }
    st_map = container_of(map, struct bpf_struct_ops_map, map);
    // `struct_ops`注销接口
    st_map->st_ops_desc->st_ops->unreg(&st_map->kvalue.data, link);
    // 设置`st_link`的`map`为NULL
    RCU_INIT_POINTER(st_link->map, NULL);
    bpf_map_put(&st_map->map);

    mutex_unlock(&update_mutex);
    // 唤醒等待队列
    wake_up_interruptible_poll(&st_link->wait_hup, EPOLLHUP);
    return 0;
}
```

##### (3) 释放接口

`.dealloc`接口释放`bpf_link`。`bpf_struct_ops_map_link_dealloc`释放`st_link`，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static void bpf_struct_ops_map_link_dealloc(struct bpf_link *link)
{
    struct bpf_struct_ops_link *st_link;
    struct bpf_struct_ops_map *st_map;

    st_link = container_of(link, struct bpf_struct_ops_link, link);
    st_map = (struct bpf_struct_ops_map *)rcu_dereference_protected(st_link->map, true);
    if (st_map) {
        // `struct_ops`注销接口
        st_map->st_ops_desc->st_ops->unreg(&st_map->kvalue.data, link);
        bpf_map_put(&st_map->map);
    }
    // 释放`st_link`
    kfree(st_link);
}
```

##### (4) 更新接口

`.update_map`接口修改`bpf_link`关联的`struct_ops`。`bpf_struct_ops_map_link_update`函数实现该功能，如下：

```C
// file: kernel/bpf/bpf_struct_ops.c
static int bpf_struct_ops_map_link_update(struct bpf_link *link, struct bpf_map *new_map,
                struct bpf_map *expected_old_map)
{
    struct bpf_struct_ops_map *st_map, *old_st_map;
    struct bpf_map *old_map;
    struct bpf_struct_ops_link *st_link;
    int err;

    st_link = container_of(link, struct bpf_struct_ops_link, link);
    st_map = container_of(new_map, struct bpf_struct_ops_map, map);

    // 检查`struct_ops`的map是否能够注册
    if (!bpf_struct_ops_valid_to_reg(new_map)) return -EINVAL;
    // 检查`struct_ops`的`update`接口是否存在
    if (!st_map->st_ops_desc->st_ops->update) return -EOPNOTSUPP;

    mutex_lock(&update_mutex);

    // 获取当前`link`关联的`map`
    old_map = rcu_dereference_protected(st_link->map, lockdep_is_held(&update_mutex));
    if (!old_map) { err = -ENOLINK; goto err_out; }
    if (expected_old_map && old_map != expected_old_map) { ... }

    // 获取`old_map`对应的`st_map`
    old_st_map = container_of(old_map, struct bpf_struct_ops_map, map);
    if (st_map->st_ops_desc != old_st_map->st_ops_desc) { ... }

    // `update`接口，更新`struct_ops`
    err = st_map->st_ops_desc->st_ops->update(st_map->kvalue.data, old_st_map->kvalue.data, link);
    if (err) goto err_out;

    bpf_map_inc(new_map);
    // 设置`st_link`的`map`为`new_map`
    rcu_assign_pointer(st_link->map, new_map);
    bpf_map_put(old_map);

err_out:
    mutex_unlock(&update_mutex);
    return err;
}
```

### 4.4 `bpf_tcp_congestion_ops`的实现

`struct_ops`的一个典型的用例就是基于BPF实现TCP拥塞控制算法，在内核中定义为`bpf_tcp_congestion_ops`，如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static struct tcp_congestion_ops __bpf_ops_tcp_congestion_ops = {
    .ssthresh = bpf_tcp_ca_ssthresh,
    .cong_avoid = bpf_tcp_ca_cong_avoid,
    .set_state = bpf_tcp_ca_set_state,
    .cwnd_event = bpf_tcp_ca_cwnd_event,
    .in_ack_event = bpf_tcp_ca_in_ack_event,
    .pkts_acked = bpf_tcp_ca_pkts_acked,
    .min_tso_segs = bpf_tcp_ca_min_tso_segs,
    .cong_control = bpf_tcp_ca_cong_control,
    .undo_cwnd = bpf_tcp_ca_undo_cwnd,
    .sndbuf_expand = bpf_tcp_ca_sndbuf_expand,

    .init = __bpf_tcp_ca_init,
    .release = __bpf_tcp_ca_release,
};
static struct bpf_struct_ops bpf_tcp_congestion_ops = {
    .verifier_ops = &bpf_tcp_ca_verifier_ops,
    .reg = bpf_tcp_ca_reg,
    .unreg = bpf_tcp_ca_unreg,
    .update = bpf_tcp_ca_update,
    .init_member = bpf_tcp_ca_init_member,
    .init = bpf_tcp_ca_init,
    .validate = bpf_tcp_ca_validate,
    .name = "tcp_congestion_ops",
    .cfi_stubs = &__bpf_ops_tcp_congestion_ops,
    .owner = THIS_MODULE,
};
```

接下来我们逐一分析。

#### 1 初始化接口

`.init`在注册`struct_ops`时调用，设置为`bpf_tcp_ca_init`，实现如下：

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

    // 获取`tcp_congestion_ops`的btf类型
    type_id = btf_find_by_name_kind(btf, "tcp_congestion_ops", BTF_KIND_STRUCT);
    if (type_id < 0) return -EINVAL;
    tcp_congestion_ops_type = btf_type_by_id(btf, type_id);

    return 0;
}
```

#### 2 初始化字段的过程

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
        if (utcp_ca->flags & ~TCP_CONG_MASK) return -EINVAL;
        tcp_ca->flags = utcp_ca->flags;
        return 1;
    case offsetof(struct tcp_congestion_ops, name):
        // 复制`name`字段到内核空间
        if (bpf_obj_name_cpy(tcp_ca->name, utcp_ca->name, sizeof(tcp_ca->name)) <= 0)
            return -EINVAL;
        return 1;
    }
    return 0;
}
```

#### 3 注册的过程

`.reg`接口在注册`struct_ops`时调用，设置`bpf_tcp_ca_reg`, 注册`tcp_ca`。实现如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static int bpf_tcp_ca_reg(void *kdata, struct bpf_link *link)
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
    ret = tcp_validate_congestion_control(ca);
    if (ret) return ret;
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

#### 4 注销的过程

`.unreg`接口在注销`struct_ops`时调用，设置`bpf_tcp_ca_unreg`, 注销`tcp_ca`。实现如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static void bpf_tcp_ca_unreg(void *kdata, struct bpf_link *link)
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

#### 5 `bpf_tcp_ca`支持的`kfunc`

`bpf_tcp_ca_kfunc_set`列表表示`bpf_tcp_ca`支持的`kfunc`，定义如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static const struct btf_kfunc_id_set bpf_tcp_ca_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &bpf_tcp_ca_check_kfunc_ids,
};

BTF_KFUNCS_START(bpf_tcp_ca_check_kfunc_ids)
BTF_ID_FLAGS(func, tcp_reno_ssthresh)
BTF_ID_FLAGS(func, tcp_reno_cong_avoid)
BTF_ID_FLAGS(func, tcp_reno_undo_cwnd)
BTF_ID_FLAGS(func, tcp_slow_start)
BTF_ID_FLAGS(func, tcp_cong_avoid_ai)
BTF_KFUNCS_END(bpf_tcp_ca_check_kfunc_ids)
```

在`initcall`阶段初始化，如下：

```C
// file: net/ipv4/bpf_tcp_ca.c
static int __init bpf_tcp_ca_kfunc_init(void)
{
    int ret;
    // 注册`bpf_tcp_ca`支持的`kfunc`
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_tcp_ca_kfunc_set);
    // 注册`bpf_tcp_congestion_ops`
    ret = ret ?: register_bpf_struct_ops(&bpf_tcp_congestion_ops, tcp_congestion_ops);

    return ret;
}
late_initcall(bpf_tcp_ca_kfunc_init);
```

此外，在`net/ipv4/tcp_cubic.c`，`kernel/bpf/helpers.c`等文件也提供了`BPF_PROG_TYPE_STRUCT_OPS`使用的`kfunc`，这里就不一一介绍了。

### 4.5 `tcp_ca`的设置过程

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
    int rto_min_us, rto_max_ms;

    tp->out_of_order_queue = RB_ROOT;
    sk->tcp_rtx_queue = RB_ROOT;
    tcp_init_xmit_timers(sk);
    INIT_LIST_HEAD(&tp->tsq_node);
    INIT_LIST_HEAD(&tp->tsorted_sent_queue);

    icsk->icsk_rto = TCP_TIMEOUT_INIT;
    rto_max_ms = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_rto_max_ms);
    icsk->icsk_rto_max = msecs_to_jiffies(rto_max_ms);

    rto_min_us = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_rto_min_us);
    icsk->icsk_rto_min = usecs_to_jiffies(rto_min_us);
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
    tcp_scaling_ratio_init(sk);

    set_bit(SOCK_SUPPORT_ZC, &sk->sk_socket->flags);
    sk_sockets_allocated_inc(sk);
    xa_init_flags(&sk->sk_user_frags, XA_FLAGS_ALLOC1);
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
    if (icsk->icsk_ca_initialized && icsk->icsk_ca_ops->release)
        icsk->icsk_ca_ops->release(sk);
    icsk->icsk_ca_initialized = 0;
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
