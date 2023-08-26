# SOCKFILTER的内核实现

## 0 前言

在日常开发过程中我们借助`tcpdump`，`wireshark` 等工具分析网络数据包，底层使用的就是BPF技术。今天我们借助`sockfilter`示例程序分析使用BPF进行socket数据过滤的内核实现过程。

## 1 简介

Linux Socket Filtering (LSF) 从 Berkeley Packet Filter（BPF）衍生而来，但在Linux中提到`BPF`或`LSF`时，都是指Linux内核中的同一套过滤机制。BPF 允许用户空间程序向任意 socket 附加过滤器（filter），对流经 socket 的数据进行控制（放行或拒绝）。

## 2 `sockfilter`示例程序

### 2.1 BPF程序

BPF程序源码参见[sockfilter.bpf.c](../src/sockfilter.bpf.c)，主要内容如下：

```C
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
    struct so_event *e;
    __u8 verlen;
    __u16 proto;
    __u32 nhoff = ETH_HLEN;

    // 获取skb L3协议
    bpf_skb_load_bytes(skb, 12, &proto, 2);
    proto = __bpf_ntohs(proto);
    if (proto != ETH_P_IP) return 0;

    // 检查是否IP分片
    if (ip_is_fragment(skb, nhoff)) 
        return 0;

    // 预留采样缓冲区
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &e->ip_proto, 1);

    if (e->ip_proto != IPPROTO_GRE) {
        // 获取IP头中源地址和目标地址
        bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
        bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
    }
    // 获取端口信息
    bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
    bpf_skb_load_bytes(skb, nhoff + ((verlen & 0xF) << 2), &(e->ports), 4);
    e->pkt_type = skb->pkt_type;
    e->ifindex = skb->ifindex;
    // 提交到map中
    bpf_ringbuf_submit(e, 0);

    return skb->len;
}
```

该程序包含一个BPF程序`socket_handler`，使用`socket`前缀。参数为`__sk_buff`类型，`__sk_buff` 是BPF对内核中`sk_buff`结构的转换。

[sockfilter.h](../src/sockfilter.h)文件中定义的`struct so_event`结构为BPF程序和用户空间程序间交互数据的结构。

### 2.2 用户程序

用户程序源码参见[sockfilter.c](../src/sockfilter.c)，主要内容如下：

#### 1 附加BPF程序

```C
int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct sockfilter_bpf *skel;
    int err, prog_fd, sock;
    ...
    // 设置 libbpf 调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);
    // 打开并加载BPF程序
    skel = sockfilter_bpf__open_and_load();
    if (!skel) { ... }
    // 设置环形缓冲区poll函数
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) { ... }
    // 在本地网络接口上创建原始socket
    sock = open_raw_sock("lo");
    if (sock < 0) { ... }
    // 附加BPF程序
    prog_fd = bpf_program__fd(skel->progs.socket_handler);
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) { ... }
    // 设置`INT`处理函数
    if (signal(SIGINT, sig_int) == SIG_ERR) { ... }
    
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) { ... }
        sleep(1);
    }
cleanup:
    // 销毁BPF程序
    close(sock);
    ring_buffer__free(rb);
    sockfilter_bpf__destroy(skel);
    return -err;
}
```

#### 2 读取数据过程

`socket_handler` BPF程序获取网络包的协议类型、发送/接收地址、发送/接收端口后，提交到 `RINGBUF` 中，用户空间程序读取结果后打印输出。

### 2.3 编译运行

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make sockfilter 
$ sudo ./sockfilter 
libbpf: loading object 'sockfilter_bpf' from buffer
...
interface: lo   protocol: TCP   127.0.0.1:57032(src) -> 127.0.0.1:43005(dst)
interface: lo   protocol: TCP   127.0.0.1:43005(src) -> 127.0.0.1:34824(dst)
interface: lo   protocol: TCP   127.0.0.1:43005(src) -> 127.0.0.1:57032(dst)
interface: lo   protocol: TCP   127.0.0.1:34824(src) -> 127.0.0.1:43005(dst)
interface: lo   protocol: TCP   127.0.0.1:57032(src) -> 127.0.0.1:43005(dst)
...
```

## 3 附加BPF的过程

`sockfilter.bpf.c`文件中BPF程序的SEC名称为 `SEC("socket")` ，在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("socket",   SOCKET_FILTER, 0, SEC_NONE),
    ...
};
```

`socket` 前缀不支持自动附加，需要通过手动方式附加。在用户空间程序创建原始socket，在socket上附加BPF程序。用户空间程的 `open_raw_sock` 函数在指定网络接口设备上创建原始socket，如下：

```C
static int open_raw_sock(const char *name)
{
    struct sockaddr_ll sll;
    int sock;
    // socket系统调用
    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock < 0) { ... }

    // 设置sockaddr
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(name);
    sll.sll_protocol = htons(ETH_P_ALL);
    // 绑定地址
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) { ... }
    
    return sock;
}
```

在socket上附加BPF程序，如下：

```C
int main(int argc, char **argv)
{
    ...
    prog_fd = bpf_program__fd(skel->progs.socket_handler);
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) { ... }
}
```

## 4 内核实现

### 4.1 内核附加过程

#### 1 `socket`系统调用

##### (1) 系统调用接口

```C
// file: net/socket.c
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
    return __sys_socket(family, type, protocol);
}

// file: net/socket.c
int __sys_socket(int family, int type, int protocol)
{
    struct socket *sock;
    int flags;
    // 创建socket
    sock = __sys_socket_create(family, type, protocol);
    if (IS_ERR(sock)) return PTR_ERR(sock);

    flags = type & ~SOCK_TYPE_MASK;
    if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
        flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;
    // socke关联fd
    return sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
}
```

`__sys_socket_create` 函数创建对应的socket，调用过程如下：

```C
// file: net/socket.c
static struct socket *__sys_socket_create(int family, int type, int protocol)
    --> sock_create(family, type, protocol, &sock);
        --> __sock_create(current->nsproxy->net_ns, family, type, protocol, res, 0);
```

`__sock_create` 函数创建一个socket，在创建期间进行LSM安全检查。实现如下：

```C
// file: net/socket.c
int __sock_create(struct net *net, int family, int type, int protocol,
            struct socket **res, int kern)
{
    int err;
    struct socket *sock;
    const struct net_proto_family *pf;

    // 检查协议是否在范围内
    if (family < 0 || family >= NPROTO) return -EAFNOSUPPORT;
    if (type < 0 || type >= SOCK_MAX) return -EINVAL;
    // 兼容性检查，
    if (family == PF_INET && type == SOCK_PACKET) {
        family = PF_PACKET;
    }
    // 创建socket前LSM安全检查
    err = security_socket_create(family, type, protocol, kern);
    if (err) return err;

    // 创建inode和socket对象
    sock = sock_alloc();
    if (!sock) { ... }
    // 设置sock类型
    sock->type = type;

#ifdef CONFIG_MODULES
    // 网络家族不存在时，尝试以module方式加载
    if (rcu_access_pointer(net_families[family]) == NULL)
        request_module("net-pf-%d", family);
#endif
    ...
    // 获取对应的网络家族
    pf = rcu_dereference(net_families[family]);
    ...    
    // 网络家族创建接口
    err = pf->create(net, sock, protocol, kern);
    if (err < 0) goto out_module_put;
    ...
    // 创建socket后LSM安全检查
    err = security_socket_post_create(sock, family, type, protocol, kern);
    if (err) goto out_sock_release;
    // 设置返回结果
    *res = sock;
    return 0;
    ...
}
```

`sock_map_fd` 函数将`socket`映射为用户空间使用的`fd`，实现如下：

```C
// file: net/socket.c
static int sock_map_fd(struct socket *sock, int flags)
{
    struct file *newfile;
    // 获取未使用的fd，获取失败时释放sock
    int fd = get_unused_fd_flags(flags);
    if (unlikely(fd < 0)) {
        sock_release(sock);
        return fd;
    }
    // 将sock和文件绑定，成功时将文件和fd关联
    newfile = sock_alloc_file(sock, flags, NULL);
    if (!IS_ERR(newfile)) {
        fd_install(fd, newfile);
        return fd;
    }
    // 创建文件失败时，释放fd
    put_unused_fd(fd);
    return PTR_ERR(newfile);
}
```

`sock_alloc_file` 函数将sock和文件进行绑定，实现如下：

```C
// file: net/socket.c
struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
{
    struct file *file;
    if (!dname)
        dname = sock->sk ? sock->sk->sk_prot_creator->name : "";

    // 创建sock昵称，失败时释放sock
    file = alloc_file_pseudo(SOCK_INODE(sock), sock_mnt, dname,
            O_RDWR | (flags & O_NONBLOCK), &socket_file_ops);
    if (IS_ERR(file)) {
        sock_release(sock);
        return file;
    }
    // 绑定sock和file
    sock->file = file;
    file->private_data = sock;
    stream_open(SOCK_INODE(sock), file);
    return file;
}
```

##### (2) `packet_create`实现过程

`PF_PACKET` 和 `AF_PACKET` 表示相同的类型，如下：

```C
// file: include/linux/socket.h
#define PF_PACKET   AF_PACKET
```

`PF_PACKET`类型的网络协议定义如下：

```C
// file: net/packet/af_packet.c
static const struct net_proto_family packet_family_ops = {
    .family =   PF_PACKET,
    .create =   packet_create,
    .owner =    THIS_MODULE,
};
```

在`initcall`阶段注册的，如下：

```C
// file: net/packet/af_packet.c
static int __init packet_init(void)
{
    int rc;
    // 注册网络命名空间相关接口
    rc = register_pernet_subsys(&packet_net_ops);
    if (rc) goto out;
    // 注册通知链
    rc = register_netdevice_notifier(&packet_netdev_notifier);
    if (rc) goto out_pernet;
    // 注册协议类型
    rc = proto_register(&packet_proto, 0);
    if (rc) goto out_notifier;
    // 注册网络协议
    rc = sock_register(&packet_family_ops);
    if (rc) goto out_proto;
    return 0;
    ...
}
module_init(packet_init);
```

`PF_PACKET`类型的创建接口设置为`packet_create`, 实现如下：

```C
// file: net/packet/af_packet.c
static int packet_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    struct sock *sk;
    struct packet_sock *po;
    __be16 proto = (__force __be16)protocol;

    // 权限检查，参数检查
    if (!ns_capable(net->user_ns, CAP_NET_RAW)) return -EPERM;
    if (sock->type != SOCK_DGRAM && sock->type != SOCK_RAW && sock->type != SOCK_PACKET)
        return -ESOCKTNOSUPPORT;
    
    // 设置sock处于未连接状态
    sock->state = SS_UNCONNECTED;

    err = -ENOBUFS;
    // 分配sock内存空间
    sk = sk_alloc(net, PF_PACKET, GFP_KERNEL, &packet_proto, kern);
    if (sk == NULL) goto out;

    // sock->ops 设置
    sock->ops = &packet_ops;
    if (sock->type == SOCK_PACKET)
        sock->ops = &packet_ops_spkt;

    // sock初始化
    sock_init_data(sock, sk);

    // `packet_sock`设置，设置协议和发送接口
    po = pkt_sk(sk);
    init_completion(&po->skb_completion);
    sk->sk_family = PF_PACKET;
    po->num = proto;
    po->xmit = dev_queue_xmit;

    // 创建接收等待(`po->rx_ring.pending_refcnt`)
    err = packet_alloc_pending(po);
    if (err) goto out2;

    packet_cached_dev_reset(po);

    // 设置sk析构接口
    sk->sk_destruct = packet_sock_destruct;

    // `packet_sock`设置
    spin_lock_init(&po->bind_lock);
    mutex_init(&po->pg_vec_lock);
    po->rollover = NULL;
    // 设置`packet_sock`挂钩接口
    po->prot_hook.func = packet_rcv;
    if (sock->type == SOCK_PACKET)
        po->prot_hook.func = packet_rcv_spkt;

    po->prot_hook.af_packet_priv = sk;
    po->prot_hook.af_packet_net = sock_net(sk);

    if (proto) {
        // 注册`packet_sock`挂钩
        po->prot_hook.type = proto;
        __register_prot_hook(sk);
    }

    mutex_lock(&net->packet.sklist_lock);
    // 添加到 命名空间的packet列表中
    sk_add_node_tail_rcu(sk, &net->packet.sklist);
    mutex_unlock(&net->packet.sklist_lock);

    sock_prot_inuse_add(net, &packet_proto, 1);
    return 0;
}
```

`sock_init_data()` 函数初始化sock，在获取`uid`后调用`sock_init_data_uid`函数进行初始化，如下：

```C
// file: net/core/sock.c
void sock_init_data(struct socket *sock, struct sock *sk)
{
    kuid_t uid = sock ? SOCK_INODE(sock)->i_uid : make_kuid(sock_net(sk)->user_ns, 0);
    sock_init_data_uid(sock, sk, uid);
}

// file: net/core/sock.c
void sock_init_data_uid(struct socket *sock, struct sock *sk, kuid_t uid)
{
    // 初始化sk，初始化：接收队列、发送队列、错误队列
    sk_init_common(sk);
    sk->sk_send_head = NULL;

    // 定时器设置
    timer_setup(&sk->sk_timer, NULL, 0);

    // 设置接收缓冲区大小、发送缓冲区大小、连接状态等
    sk->sk_allocation   =   GFP_KERNEL;
    sk->sk_rcvbuf       =   READ_ONCE(sysctl_rmem_default);
    sk->sk_sndbuf       =   READ_ONCE(sysctl_wmem_default);
    sk->sk_state        =   TCP_CLOSE;
    sk->sk_use_task_frag    =   true;
    sk_set_socket(sk, sock);

    sock_set_flag(sk, SOCK_ZAPPED);

    // 等待队列（wq）设置
    if (sock) {
        sk->sk_type = sock->type;
        RCU_INIT_POINTER(sk->sk_wq, &sock->wq);
        sock->sk = sk;
    } else {
        RCU_INIT_POINTER(sk->sk_wq, NULL);
    }
    sk->sk_uid = uid;

    // sk lockdep设置
    rwlock_init(&sk->sk_callback_lock);
    if (sk->sk_kern_sock)
        lockdep_set_class_and_name(&sk->sk_callback_lock,
            af_kern_callback_keys + sk->sk_family,
            af_family_kern_clock_key_strings[sk->sk_family]);
    else
        lockdep_set_class_and_name(&sk->sk_callback_lock,
            af_callback_keys + sk->sk_family,
            af_family_clock_key_strings[sk->sk_family]);

    // sk数据通知接口设置
    sk->sk_state_change =   sock_def_wakeup;
    sk->sk_data_ready   =   sock_def_readable;
    sk->sk_write_space  =   sock_def_write_space;
    sk->sk_error_report =   sock_def_error_report;
    sk->sk_destruct     =   sock_def_destruct;

    sk->sk_frag.page    =   NULL;
    sk->sk_frag.offset  =   0;
    sk->sk_peek_off     =   -1;

    sk->sk_peer_pid     =   NULL;
    sk->sk_peer_cred    =   NULL;
    spin_lock_init(&sk->sk_peer_lock);

    // sk接收、发送超时时间设置
    sk->sk_write_pending    =   0;
    sk->sk_rcvlowat     =   1;
    sk->sk_rcvtimeo     =   MAX_SCHEDULE_TIMEOUT;
    sk->sk_sndtimeo     =   MAX_SCHEDULE_TIMEOUT;

    sk->sk_stamp = SK_DEFAULT_STAMP;
#if BITS_PER_LONG==32
    seqlock_init(&sk->sk_stamp_seq);
#endif
    atomic_set(&sk->sk_zckey, 0);

#ifdef CONFIG_NET_RX_BUSY_POLL
    sk->sk_napi_id  =   0;
    sk->sk_ll_usec  =   READ_ONCE(sysctl_net_busy_read);
#endif

    sk->sk_max_pacing_rate = ~0UL;
    sk->sk_pacing_rate = ~0UL;
    WRITE_ONCE(sk->sk_pacing_shift, 10);
    sk->sk_incoming_cpu = -1;

    // 清空sk接收队列
    sk_rx_queue_clear(sk);

    smp_wmb();
    // 计数设置
    refcount_set(&sk->sk_refcnt, 1);
    atomic_set(&sk->sk_drops, 0);
}
```

#### 2 `bind`系统调用

##### (1) 系统调用接口

```C
// file: net/socket.c
SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
{
    return __sys_bind(fd, umyaddr, addrlen);
}

// file: net/socket.c
int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
    struct socket *sock;
    struct sockaddr_storage address;
    int err, fput_needed;

    // 查找fd对应的sock
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (sock) {
        // 用户空间地址移动到内核空间
        err = move_addr_to_kernel(umyaddr, addrlen, &address);
        if (!err) {
            // bind LSM安全检查
            err = security_socket_bind(sock, (struct sockaddr *)&address,  addrlen);
            if (!err)
                // sock bind接口
                err = sock->ops->bind(sock, (struct sockaddr *) &address, addrlen);
        }
        fput_light(sock->file, fput_needed);
    }
    return err;
}
```

##### (2) `packet_bind`实现过程

在创建socket时，设置了`sock->ops`接口，如下：

```C
// file: net/packet/af_packet.c
static int packet_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    ...
    sock->ops = &packet_ops;
    if (sock->type == SOCK_PACKET)
        sock->ops = &packet_ops_spkt;
    ...
}
```

在`socket`系统调用时，`type`设置为`SOCK_RAW`，对应`packet_ops`，定义如下：

```C
// file: net/packet/af_packet.c
static const struct proto_ops packet_ops = {
    .family =   PF_PACKET,
    .owner  =   THIS_MODULE,
    .release=   packet_release,
    .bind   =   packet_bind,
    ...
};
```

`.bind` 接口设置为`packet_bind`，实现如下：

```C
// file: net/packet/af_packet.c
static int packet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    struct sockaddr_ll *sll = (struct sockaddr_ll *)uaddr;
    struct sock *sk = sock->sk;
    // 检查设置的地址
    if (addr_len < sizeof(struct sockaddr_ll)) return -EINVAL;
    if (sll->sll_family != AF_PACKET) return -EINVAL;

    return packet_do_bind(sk, NULL, sll->sll_ifindex, sll->sll_protocol ? : pkt_sk(sk)->num);
}
```

`packet_do_bind` 函数实现具体的绑定操作。如下：

```C
// file: net/packet/af_packet.c
static int packet_do_bind(struct sock *sk, const char *name, int ifindex, __be16 proto)
{
    struct packet_sock *po = pkt_sk(sk);
    bool unlisted = false;
    ...
    // 设置fanout时，退出
    if (po->fanout) { ... }

    // 通过 名称 或 索引 获取网络设备
    if (name) {
        dev = dev_get_by_name_rcu(sock_net(sk), name);
        if (!dev) { ... }
    } else if (ifindex) {
        dev = dev_get_by_index_rcu(sock_net(sk), ifindex);
        if (!dev) { ... }
    }
    // 协议不同或设备不同时，需要重新设置
    need_rehook = po->prot_hook.type != proto || po->prot_hook.dev != dev;

    if (need_rehook) {
        dev_hold(dev);
        if (po->running) {
            rcu_read_unlock();
            // packet_socket 在运行时，注销
            WRITE_ONCE(po->num, 0);
            __unregister_prot_hook(sk, true);
            rcu_read_lock();
            if (dev)
                unlisted = !dev_get_by_index_rcu(sock_net(sk), dev->ifindex);
        }
        // 重新设置协议
        WRITE_ONCE(po->num, proto);
        po->prot_hook.type = proto;

        netdev_put(po->prot_hook.dev, &po->prot_hook.dev_tracker);
        // 重新设置关联的设备信息
        if (unlikely(unlisted)) {
            po->prot_hook.dev = NULL;
            WRITE_ONCE(po->ifindex, -1);
            packet_cached_dev_reset(po);
        } else {
            netdev_hold(dev, &po->prot_hook.dev_tracker, GFP_ATOMIC);
            po->prot_hook.dev = dev;
            WRITE_ONCE(po->ifindex, dev ? dev->ifindex : 0);
            packet_cached_dev_assign(po, dev);
        }
        dev_put(dev);
    }

    // 没有设置协议或不需要重新设置时，退出
    if (proto == 0 || !need_rehook)
        goto out_unlock;

    // 注册 packet_socket 或 汇报错误信息
    if (!unlisted && (!dev || (dev->flags & IFF_UP))) {
        register_prot_hook(sk);
    } else {
        sk->sk_err = ENETDOWN;
        if (!sock_flag(sk, SOCK_DEAD))
            sk_error_report(sk);
    }

out_unlock:
    rcu_read_unlock();
    spin_unlock(&po->bind_lock);
    release_sock(sk);
    return ret;
}
```

#### 3 注册`prot_hook`

`__register_prot_hook` 函数注册`prot_hook`, 在`packet_sock`没有运行时，注册协议处理程序到网络协议栈中，如下：

```C
// file: net/packet/af_packet.c
static void __register_prot_hook(struct sock *sk)
{
    struct packet_sock *po = pkt_sk(sk);
    if (!po->running) {
        if (po->fanout) 
            __fanout_link(sk, po);
        else 
            dev_add_pack(&po->prot_hook);
        sock_hold(sk);
        po->running = 1;
    }
}
```

`dev_add_pack` 函数将将协议处理程序添加到网络堆栈，获取协议列表后，添加到列表中。如下：

```C
// file: net/core/dev.c
void dev_add_pack(struct packet_type *pt)
{
    struct list_head *head = ptype_head(pt);

    spin_lock(&ptype_lock);
    list_add_rcu(&pt->list, head);
    spin_unlock(&ptype_lock);
}
```

`ptype_head` 获取指定协议的列表，如下：

```C
// file: net/core/dev.c
static inline struct list_head *ptype_head(const struct packet_type *pt)
{
    if (pt->type == htons(ETH_P_ALL))
        return pt->dev ? &pt->dev->ptype_all : &ptype_all;
    else
        return pt->dev ? &pt->dev->ptype_specific :
                &ptype_base[ntohs(pt->type) & PTYPE_HASH_MASK];
}
```

#### 4 注销`prot_hook`

`unregister_prot_hook` 函数注销`prot_hook`，从协议列表中移除网络处理程序。如下：

```C
// file: net/packet/af_packet.c
static void unregister_prot_hook(struct sock *sk, bool sync)
{
    struct packet_sock *po = pkt_sk(sk);
    if (po->running)
        __unregister_prot_hook(sk, sync);
}

// file: net/packet/af_packet.c
static void __unregister_prot_hook(struct sock *sk, bool sync)
{
    struct packet_sock *po = pkt_sk(sk);
    lockdep_assert_held_once(&po->bind_lock);

    po->running = 0;
    if (po->fanout)
        __fanout_unlink(sk, po);
    else
        __dev_remove_pack(&po->prot_hook);
    // 释放sk
    __sock_put(sk);

    if (sync) {
        // 同步数据包接收处理
        spin_unlock(&po->bind_lock);
        synchronize_net();
        spin_lock(&po->bind_lock);
    }
}
```

`__dev_remove_pack` 函数删除之前添加到内核的协议处理程序，如下：

```C
// file: net/packet/af_packet.c
void __dev_remove_pack(struct packet_type *pt)
{
    // 获取协议列表
    struct list_head *head = ptype_head(pt);
    struct packet_type *pt1;

    spin_lock(&ptype_lock);
    // 遍历列表，找到对应的`packet_type`后删除
    list_for_each_entry(pt1, head, list) {
        if (pt == pt1) {
            list_del_rcu(&pt->list);
            goto out;
        }
    }
    pr_warn("dev_remove_pack: %p not found\n", pt);
out:
    spin_unlock(&ptype_lock);
}
```

### 4.2 注册/注销BPF程序

#### 1 `setsockopt`系统调用

用户通过 `setsockopt` 系统调用附加BPF程序，`setsockopt` 系统调用实现如下：

```C
// file: net/socket.c
SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, 
        char __user *, optval, int, optlen)
{
    return __sys_setsockopt(fd, level, optname, optval, optlen);
}

// file: net/socket.c
int __sys_setsockopt(int fd, int level, int optname, char __user *user_optval, int optlen)
{
    sockptr_t optval = USER_SOCKPTR(user_optval);
    char *kernel_optval = NULL;
    int err, fput_needed;
    struct socket *sock;

    // 检查选项长度
    if (optlen < 0) return -EINVAL;
    
    // 获取sock 
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (!sock) return err;

    // LSM安全检查
    err = security_socket_setsockopt(sock, level, optname);
    if (err) goto out_put;

    if (!in_compat_syscall())
        // CGROUP SETSOCKOPT BPF程序检查
        err = BPF_CGROUP_RUN_PROG_SETSOCKOPT(sock->sk, &level, &optname,
                    user_optval, &optlen, &kernel_optval);
    // 错误时退出
    if (err < 0) goto out_put;
    if (err > 0) { err = 0; goto out_put; }

    if (kernel_optval)
        optval = KERNEL_SOCKPTR(kernel_optval);
    // 判断是否使用SOL_SOCKET
    if (level == SOL_SOCKET && !sock_use_custom_sol_socket(sock))
        err = sock_setsockopt(sock, level, optname, optval, optlen);
    else if (unlikely(!sock->ops->setsockopt))
        err = -EOPNOTSUPP;
    else    
        err = sock->ops->setsockopt(sock, level, optname, optval, optlen);
    // 释放内核`optval`
    kfree(kernel_optval);
out_put:
    // 释放sock->file
    fput_light(sock->file, fput_needed);
    return err;
}
```

#### 2 `ATTACH_BPF`选项

BPF程序使用 `SOL_SOCKET` 级别进行设置，对应 `sock_setsockopt` 函数。`sock_setsockopt()` 调用 `sk_setsockopt()`, 后者对`optname`进行对应的操作。其实现如下：

```C
// file: net/core/sock.c
int sock_setsockopt(struct socket *sock, int level, int optname, 
    sockptr_t optval, unsigned int optlen)
{
    return sk_setsockopt(sock->sk, level, optname, optval, optlen);
}

// file: net/core/sock.c
int sk_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen)
{
    struct socket *sock = sk->sk_socket;
    int val;
    ...
    // 无参数选项设置
    if (optname == SO_BINDTODEVICE) 
        return sock_setbindtodevice(sk, optval, optlen);

    // 检查参数长度是否正确
    if (optlen < sizeof(int)) return -EINVAL;
    // 获取参数值
    if (copy_from_sockptr(&val, optval, sizeof(val)))
        return -EFAULT;

    valbool = val ? 1 : 0;

    sockopt_lock_sock(sk);
    switch (optname) {
    ...
    // 附加BPF程序
    case SO_ATTACH_BPF:
        ret = -EINVAL;
        if (optlen == sizeof(u32)) {
            u32 ufd;
            ret = -EFAULT;
            // 获取设置的prog
            if (copy_from_sockptr(&ufd, optval, sizeof(ufd))) break;
            // 附加bpf程序
            ret = sk_attach_bpf(ufd, sk);
        }
        break;
    // 分离FILTER
    case SO_DETACH_FILTER:
        ret = sk_detach_filter(sk);
        break;
    // 锁定FILTER
    case SO_LOCK_FILTER:
        if (sock_flag(sk, SOCK_FILTER_LOCKED) && !valbool)
            ret = -EPERM;
        else
            sock_valbool_flag(sk, SOCK_FILTER_LOCKED, valbool);
        break;
    ...
    }
    sockopt_release_sock(sk);
    return ret;
}
```

`SO_ATTACH_BPF` 选项对应的设置函数为 `sk_attach_bpf`，实现如下：

```C
// file: net/core/filter.c
int sk_attach_bpf(u32 ufd, struct sock *sk)
{
    // 获取prog，检查类型是否为`SOCKET_FILTER`，失败时返回
    struct bpf_prog *prog = __get_bpf(ufd, sk);
    if (IS_ERR(prog)) return PTR_ERR(prog);

    // 附加bpf程序，失败时释放prog
    err = __sk_attach_prog(prog, sk);
    if (err < 0) { ... }
    return 0;
}

// file: net/core/filter.c
static int __sk_attach_prog(struct bpf_prog *prog, struct sock *sk)
{
    struct sk_filter *fp, *old_fp;

    fp = kmalloc(sizeof(*fp), GFP_KERNEL);
    if (!fp) return -ENOMEM;
    // 设置bpf程序
    fp->prog = prog;

    // 检查prog长度及sk内存使用量是否超过`sysctl_optmem_max`限制
    if (!__sk_filter_charge(sk, fp)) {
        kfree(fp);
        return -ENOMEM;
    }

    refcount_set(&fp->refcnt, 1);
    // 获取之前设置的`sk_filter`
    old_fp = rcu_dereference_protected(sk->sk_filter, lockdep_sock_is_held(sk));
    // 设置`sk_filter`
    rcu_assign_pointer(sk->sk_filter, fp);

    // 存在`sk_filter`时，归还sk内存使用量，释放`sk_filter`
    if (old_fp)
        sk_filter_uncharge(sk, old_fp);
    return 0;
}
```

#### 3 `SO_DETACH_FILTER`选项

`SO_DETACH_FILTER` 选项分离filter，取消对socket的过滤。对应的设置函数为 `sk_detach_filter`，实现如下：

```C
// file: net/core/filter.c
int sk_detach_filter(struct sock *sk)
{
    int ret = -ENOENT;
    struct sk_filter *filter;

    // 锁定时不能删除
    if (sock_flag(sk, SOCK_FILTER_LOCKED)) return -EPERM;

    filter = rcu_dereference_protected(sk->sk_filter, lockdep_sock_is_held(sk));
    if (filter) {
        RCU_INIT_POINTER(sk->sk_filter, NULL);
        sk_filter_uncharge(sk, filter);
        ret = 0;
    }
    return ret;
}
```

#### 4 `SO_LOCK_FILTER`选项

`SO_LOCK_FILTER` 选项锁定filter，在锁定时，不能分离filter。设置/清除 `SOCK_FILTER_LOCKED` 标记位实现锁定/解锁。对应的设置函数为 `sock_valbool_flag`，实现如下：

```C
// file: include/net/sock.h
static inline void sock_valbool_flag(struct sock *sk, enum sock_flags bit, int valbool)
{
    if (valbool) 
        sock_set_flag(sk, bit);
    else
        sock_reset_flag(sk, bit);
}
```

#### 5 `sk_filter_[un]charge`

`sk_filter_charge` 函数增加`sk_filter`引用，增加sock缓冲区使用大小，如下：

```C
// file: net/core/filter.c
bool sk_filter_charge(struct sock *sk, struct sk_filter *fp)
{
    if (!refcount_inc_not_zero(&fp->refcnt)) return false;

    if (!__sk_filter_charge(sk, fp)) {
        sk_filter_release(fp);
        return false;
    }
    return true;
}
```

`__sk_filter_charge` 检查`sk_filter`内存占用情况，如下：

```C
// file: net/core/filter.c
static bool __sk_filter_charge(struct sock *sk, struct sk_filter *fp)
{
    // bpf程序大小
    u32 filter_size = bpf_prog_size(fp->prog->len);
    // 使用的缓冲区大小，对应`/proc/sys/net/core/optmem_max`文件
    int optmem_max = READ_ONCE(sysctl_optmem_max);

    // 检查缓冲区使用是否超过限制
    if (filter_size <= optmem_max &&
        atomic_read(&sk->sk_omem_alloc) + filter_size < optmem_max) {
        atomic_add(filter_size, &sk->sk_omem_alloc);
        return true;
    }
    return false;
}
```

`sk_filter_uncharge` 函数减少sock缓冲区使用大小，释放`sk_filter`，如下：

```C
// file: net/core/filter.c
void sk_filter_uncharge(struct sock *sk, struct sk_filter *fp)
{
    u32 filter_size = bpf_prog_size(fp->prog->len);

    atomic_sub(filter_size, &sk->sk_omem_alloc);
    sk_filter_release(fp);
}
// file: net/core/filter.c
static void sk_filter_release(struct sk_filter *fp)
{
    if (refcount_dec_and_test(&fp->refcnt))
        call_rcu(&fp->rcu, sk_filter_release_rcu);
}
```

### 4.3 网络数据抓包实现过程

#### 1 接收路径上抓包

`__netif_receive_skb_core` 函数将skb发送内核网络协议栈，在 [XDP的内核实现](./12-xdp.md) 中我们分析了XDP的实现过程，在经过XDP处理后，能够继续接收的网络包进行后续处理，下一步就是抓包处理。如下：

```C
// file: net/core/dev.c
static int __netif_receive_skb_core(struct sk_buff **pskb, bool pfmemalloc, struct packet_type **ppt_prev)
{
    orig_dev = skb->dev;
    ...
    pt_prev = NULL;
    ...

another_round:
    skb->skb_iif = skb->dev->ifindex;
    __this_cpu_inc(softnet_data.processed);

    // 通用模式XDP程序
    if (static_branch_unlikely(&generic_xdp_needed_key)) { ... }

    // vlan处理
    if (eth_type_vlan(skb->protocol)) { 
        skb = skb_vlan_untag(skb);
        if (unlikely(!skb)) goto out;
    }
    // IFB设备需要跳过tc
    if (skb_skip_tc_classify(skb)) goto skip_classify;

    if (pfmemalloc) goto skip_taps;

    // 全局抓包处理
    list_for_each_entry_rcu(ptype, &ptype_all, list) {
        if (pt_prev)
            ret = deliver_skb(skb, pt_prev, orig_dev);
        pt_prev = ptype;
    }

    // 设备抓包处理
    list_for_each_entry_rcu(ptype, &skb->dev->ptype_all, list) {
        if (pt_prev)
            ret = deliver_skb(skb, pt_prev, orig_dev);
        pt_prev = ptype;
    }
    ...
}
```

`ptype_all` 和 `skb->dev->ptype_all` 是需要抓包的列表，通过`socket`和`bind`系统调用添加到相应的列表中。

#### 2 发送路径上抓包

网络数据包发送过程也非常复杂，具体发送过程可参考 [Linux 网络栈监控和调优：发送数据（2017）](http://arthurchiao.art/blog/tuning-stack-tx-zh/)。

我们使用 `sendmsg` 系统调用、或者 `dev_queue_xmit` 方式、或者 `softirq` 方式发送的网络数据包，最终直接或间接调用 `dev_hard_start_xmit()` 函数，该函数调用网络设备驱动程序来实际执行发送操作。其实现如下：

```C
// file: net/core/dev.c
struct sk_buff *dev_hard_start_xmit(struct sk_buff *first, struct net_device *dev, 
        struct netdev_queue *txq, int *ret)
{
    struct sk_buff *skb = first;
    int rc = NETDEV_TX_OK;

    while (skb) {
        struct sk_buff *next = skb->next;
        // `skb->next`置空，从列表中删除
        skb_mark_not_on_list(skb);
        // 发送网络包
        rc = xmit_one(skb, dev, txq, next != NULL);
        // 未完成发送时，添加到列表中，退出
        if (unlikely(!dev_xmit_complete(rc))) {
            skb->next = next;
            goto out;
        }
        // 发送下一个skb
        skb = next;
        // 发送队列停止时，退出
        if (netif_tx_queue_stopped(txq) && skb) {
            rc = NETDEV_TX_BUSY;
            break;
        }
    }
out:
    *ret = rc;
    return skb;
}
```

`xmit_one` 函数在调用网卡设备驱动前，进行抓包处理。如下：

```C
// file: net/core/dev.c
static int xmit_one(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq, bool more)
{
    unsigned int len;
    int rc;

    // 网卡设备启用了抓包
    if (dev_nit_active(dev))
        dev_queue_xmit_nit(skb, dev);

    len = skb->len;
    trace_net_dev_start_xmit(skb, dev);
    // 调用网卡设备发送skb
    rc = netdev_start_xmit(skb, dev, txq, more);
    trace_net_dev_xmit(skb, rc, dev, len);
    return rc;
}
```

`dev_queue_xmit_nit` 函数实现发送过程网络抓包实现，如下：

```C
// file: net/core/dev.c
void dev_queue_xmit_nit(struct sk_buff *skb, struct net_device *dev)
{
    struct packet_type *ptype;
    struct sk_buff *skb2 = NULL;
    struct packet_type *pt_prev = NULL;
    // 全局抓包列表
    struct list_head *ptype_list = &ptype_all;

    rcu_read_lock();
again:
    list_for_each_entry_rcu(ptype, ptype_list, list) {
        // ptype忽略发送帧
        if (ptype->ignore_outgoing) continue;

        // 不能发送skb到其来源
        if (skb_loop_sk(ptype, skb)) continue;

        if (pt_prev) {
            // 交付skb
            deliver_skb(skb2, pt_prev, skb->dev);
            pt_prev = ptype;
            continue;
        }

        // 只复制一次skb
        skb2 = skb_clone(skb, GFP_ATOMIC);
        if (!skb2) goto out_unlock;

        // 设置skb2
        net_timestamp_set(skb2);
        skb_reset_mac_header(skb2);
        if (skb_network_header(skb2) < skb2->data ||
            skb_network_header(skb2) > skb_tail_pointer(skb2)) {
            net_crit_ratelimited("protocol %04x is buggy, dev %s\n",
                        ntohs(skb2->protocol), dev->name);
            skb_reset_network_header(skb2);
        }
        skb2->transport_header = skb2->network_header;
        // 设置skb类型，标记为发送包
        skb2->pkt_type = PACKET_OUTGOING;
        pt_prev = ptype;
    }

    if (ptype_list == &ptype_all) {
        // 设备抓包列表
        ptype_list = &dev->ptype_all;
        goto again;
    }
out_unlock:
    if (pt_prev) {
        // skb可能在rx路径上循环，frags必须是独占的，不能共享
        if (!skb_orphan_frags_rx(skb2, GFP_ATOMIC))
            // 发送最后一个
            pt_prev->func(skb2, skb->dev, pt_prev, skb->dev);
        else
            kfree_skb(skb2);
    }
    rcu_read_unlock();
}
```

#### 3 抓取数据包的过滤过程

##### (1) `packet_rcv`实现过程

在接收/发送过程中抓包通过调用`deliver_skb` 函数 或 `pt_prev->func` 接口，进行后续处理。`deliver_skb` 函数在孤立`skb->frags`，增加skb引用计数后，调用 `pt_prev->func`， 如下：

```C
// file: net/core/dev.c
static inline int deliver_skb(struct sk_buff *skb, struct packet_type *pt_prev, struct net_device *orig_dev)
{
    if (unlikely(skb_orphan_frags_rx(skb, GFP_ATOMIC))) 
        return -ENOMEM;
    refcount_inc(&skb->users);
    return pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
}
```

在创建`packet_socket`时，设置的`func` 为 `packet_rcv`，如下：

```C
// file: net/packet/af_packet.c
static int packet_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    ...
    // 默认设置
    po->prot_hook.func = packet_rcv;
    // SOCK_PACKET类型设置
    if (sock->type == SOCK_PACKET)
        po->prot_hook.func = packet_rcv_spkt;
    ...
}
```

`packet_rcv` 函数使用BPF程序过滤skb，对满足过滤条件的skb添加到接收队列中。如下：

```C
// file: net/packet/af_packet.c
static int packet_rcv(struct sk_buff *skb, struct net_device *dev,
            struct packet_type *pt, struct net_device *orig_dev)
{
    // 原始skb数据和长度
    u8 *skb_head = skb->data;
    int skb_len = skb->len;
    ...

    // 跳过发往`loopback`的包
    if (skb->pkt_type == PACKET_LOOPBACK) goto drop;

    // 获取sk，po
    sk = pt->af_packet_priv;
    po = pkt_sk(sk);

    // 跳过其他网络命名空间的包
    if (!net_eq(dev_net(dev), sock_net(sk))) goto drop;

    skb->dev = dev;
    if (dev_has_header(dev)) {
        // 网卡设备L2头部处理
        if (sk->sk_type != SOCK_DGRAM)
            skb_push(skb, skb->data - skb_mac_header(skb));
        else if (skb->pkt_type == PACKET_OUTGOING) 
            skb_pull(skb, skb_network_offset(skb));
    }

    snaplen = skb->len;
    // BPF过滤，返回结果为0时丢弃
    res = run_filter(skb, sk, snaplen);
    if (!res) goto drop_n_restore;
    // 设置修剪后的skb长度 
    if (snaplen > res) snaplen = res;

    // sk接收占用的内存超过接收缓冲区大小时，丢弃
    if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf)
        goto drop_n_acct;

    if (skb_shared(skb)) {
        // 复制skb
        struct sk_buff *nskb = skb_clone(skb, GFP_ATOMIC);
        if (nskb == NULL) goto drop_n_acct;

        if (skb_head != skb->data) {
            skb->data = skb_head;
            skb->len = skb_len;
        }
        consume_skb(skb);
        skb = nskb;
    }
    // 检查SKB_CB大小
    sock_skb_cb_check_size(sizeof(*PACKET_SKB_CB(skb)) + MAX_ADDR_LEN - 8);

    // 设置skb_cb信息，设置`sockaddr_ll`地址
    sll = &PACKET_SKB_CB(skb)->sa.ll;
    sll->sll_hatype = dev->type;
    sll->sll_pkttype = skb->pkt_type;
    if (unlikely(packet_sock_flag(po, PACKET_SOCK_ORIGDEV)))
        sll->sll_ifindex = orig_dev->ifindex;
    else
        sll->sll_ifindex = dev->ifindex;
    sll->sll_halen = dev_parse_header(skb, sll->sll_addr);

    // 设置原始包长度
    PACKET_SKB_CB(skb)->sa.origlen = skb->len;

    // 修改skb长度，失败时丢弃
    if (pskb_trim(skb, snaplen)) goto drop_n_acct;

    // 设置为接收所有者，过程中增加`sk_rmem_alloc`
    skb_set_owner_r(skb, sk);
    skb->dev = NULL;
    // 清除dst路由信息
    skb_dst_drop(skb);

    // 清除`连接追踪`(conntrack)引用
    nf_reset_ct(skb);

    spin_lock(&sk->sk_receive_queue.lock);
    po->stats.stats1.tp_packets++;
    // 设置丢弃计数
    sock_skb_set_dropcount(sk, skb);
    // 清除接收时间戳
    skb_clear_delivery_time(skb);
    // 添加到sk接收队列中
    __skb_queue_tail(&sk->sk_receive_queue, skb);
    spin_unlock(&sk->sk_receive_queue.lock);
    // 通知数据准备完成
    sk->sk_data_ready(sk);
    return 0;

drop_n_acct:
    // 丢弃时，增加计数
    is_drop_n_account = true;
    atomic_inc(&po->tp_drops);
    atomic_inc(&sk->sk_drops);

drop_n_restore:
    // 恢复skb
    if (skb_head != skb->data && skb_shared(skb)) {
        skb->data = skb_head;
        skb->len = skb_len;
    }
drop:
    // 释放skb
    if (!is_drop_n_account) 
        consume_skb(skb);
    else 
        kfree_skb(skb);
    return 0;
}
```

##### (2) `packet`过滤过程

`run_filter` 函数实现抓包过程中的过滤，获取和运行`sk_filter`，如下：

```C
// file: net/packet/af_packet.c
static unsigned int run_filter(struct sk_buff *skb, const struct sock *sk, unsigned int res)
{
    struct sk_filter *filter;
    rcu_read_lock();
    filter = rcu_dereference(sk->sk_filter);
    if (filter != NULL)
        res = bpf_prog_run_clear_cb(filter->prog, skb);
    rcu_read_unlock();
    return res;
}
```

`bpf_prog_run_clear_cb` 函数清除`bpf_skb_cb`区域数据后，设置BPF在同一个CPU上运行。如下：

```C
// file: include/linux/filter.h
static inline u32 bpf_prog_run_clear_cb(const struct bpf_prog *prog, struct sk_buff *skb)
{
    // 获取cb数据
    u8 *cb_data = bpf_skb_cb(skb);
    u32 res;
    // bpf程序访问cb数据时，清空数据内容
    if (unlikely(prog->cb_access))
        memset(cb_data, 0, BPF_SKB_CB_LEN);
    // 设置bpf运行在同一个CPU上
    res = bpf_prog_run_pin_on_cpu(prog, skb);
    return res;
}

// file: include/linux/filter.h
static inline u32 bpf_prog_run_pin_on_cpu(const struct bpf_prog *prog, const void *ctx)
{
    u32 ret;
    // 禁用迁移
    migrate_disable();
    // 运行bpf程序
    ret = bpf_prog_run(prog, ctx);
    // 启用迁移
    migrate_enable();
    return ret;
}
```

`bpf_skb_cb` 获取`qdisc_skb_cb`区域，如下：

```C
// file: include/linux/filter.h
static inline u8 *bpf_skb_cb(const struct sk_buff *skb)
{
    BUILD_BUG_ON(sizeof_field(struct __sk_buff, cb) != BPF_SKB_CB_LEN);
    BUILD_BUG_ON(sizeof_field(struct __sk_buff, cb) != sizeof_field(struct qdisc_skb_cb, data));
    // (struct qdisc_skb_cb *)skb->cb
    return qdisc_skb_cb(skb)->data;
}
```

eBPF 程序可以读/写`skb->cb[]`区域，在尾部调用之间传输元数据。由于这也需要使用`tc`，因此暂存内存将映射到`qdisc_skb_cb`的数据区域。在某些套接字过滤器的情况下，需要保存/恢复`cb`，保证`skb->cb[]`数据不会丢失。无特权的 eBPF 程序附加到套接字，我们需要清除 `bpf_skb_cb()` 区域，以免将之前的内容泄漏到用户空间。

### 4.4 读取数据的过程

#### (1) 系统调用

用户空间程序可以通过 `recv`, `recvfrom`, `recvmsg`, `recvmmsg` 系统调用读取数据。如下：

```C
// file: net/socket.c
SYSCALL_DEFINE4(recv, int, fd, void __user *, ubuf, size_t, size, unsigned int, flags)
{
    return __sys_recvfrom(fd, ubuf, size, flags, NULL, NULL);
}
// file: net/socket.c
SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
        unsigned int, flags, struct sockaddr __user *, addr, int __user *, addr_len)
{
    return __sys_recvfrom(fd, ubuf, size, flags, addr, addr_len);
}
// file: net/socket.c
SYSCALL_DEFINE3(recvmsg, int, fd, struct user_msghdr __user *, msg, unsigned int, flags)
{
    return __sys_recvmsg(fd, msg, flags, true);
}
// file: net/socket.c
SYSCALL_DEFINE5(recvmmsg, int, fd, struct mmsghdr __user *, mmsg,
        unsigned int, vlen, unsigned int, flags, struct __kernel_timespec __user *, timeout)
{
    if (flags & MSG_CMSG_COMPAT) return -EINVAL;
    return __sys_recvmmsg(fd, mmsg, vlen, flags, timeout, NULL);
}
```

这些系统调用在获取sock后，直接或间接调用 `sock_recvmsg_nosec` 函数。以 `__sys_recvfrom` 为例，如下：

```C
// file: net/socket.c
int __sys_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags,
        struct sockaddr __user *addr, int __user *addr_len)
{
    struct sockaddr_storage address;
    // msg设置`msg_name`
    struct msghdr msg = {
        .msg_name = addr ? (struct sockaddr *)&address : NULL,
    };
    struct iovec iov;
    ...
    // msg数据设置
    err = import_single_range(ITER_DEST, ubuf, size, &iov, &msg.msg_iter);
    if (unlikely(err)) return err;

    // 查找fd对应的sock
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (!sock) goto out;

    if (sock->file->f_flags & O_NONBLOCK)
        flags |= MSG_DONTWAIT;
    // 从sock接收消息
    err = sock_recvmsg(sock, &msg, flags);
    if (err >= 0 && addr != NULL) {
        // 复制sockaddr到用户空间
        err2 = move_addr_to_user(&address, msg.msg_namelen, addr, addr_len);
        if (err2 < 0) err = err2;
    }
    // 释放sock文件
    fput_light(sock->file, fput_needed);
out:
    return err;
}
```

`sock_recvmsg` 函数在通过LSM检查后，从sock中读取消息，如下：

```C
// file: net/socket.c
int sock_recvmsg(struct socket *sock, struct msghdr *msg, int flags)
{
    // LSM检查
    int err = security_socket_recvmsg(sock, msg, msg_data_left(msg), flags);
    return err ?: sock_recvmsg_nosec(sock, msg, flags);
}
// file: net/socket.c
static inline int sock_recvmsg_nosec(struct socket *sock, struct msghdr *msg, int flags)
{
    int ret = INDIRECT_CALL_INET(sock->ops->recvmsg, inet6_recvmsg, inet_recvmsg, 
                sock, msg, msg_data_left(msg), flags);
    if (trace_sock_recv_length_enabled())
        call_trace_sock_recv_length(sock->sk, ret, flags);
    return ret;
}
```

`INDIRECT_CALL_INET` 宏将常用的`inet6_recvmsg`和`inet_recvmsg`函数放到前面提升效率，不是这两个函数时调用`sock->ops->recvmsg`。

#### (2) `packet_recvmsg`实现过程

`AF_PACKET`设置的`ops->recvmsg`接口为`packet_recvmsg`，实现如下：

```C
// file: net/packet/af_packet.c
static int packet_recvmsg(struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
    struct sock *sk = sock->sk;
    ...
    err = -EINVAL;
    // 检查flags设置
    if (flags & ~(MSG_PEEK|MSG_DONTWAIT|MSG_TRUNC|MSG_CMSG_COMPAT|MSG_ERRQUEUE)) goto out;

    if (flags & MSG_ERRQUEUE) {
        // 设置`ERRQUEUE`标志，从errqueue中读取数据
        err = sock_recv_errqueue(sk, msg, len, SOL_PACKET, PACKET_TX_TIMESTAMP);
        goto out;
    }

    // 数据报文接收处理，接收错误时返回
    skb = skb_recv_datagram(sk, flags, &err);
    if (skb == NULL) goto out;

    packet_rcv_try_clear_pressure(pkt_sk(sk));

    // scatter-gather 列表的头信息
    if (pkt_sk(sk)->has_vnet_hdr) {
        err = packet_rcv_vnet(msg, skb, &len);
        if (err) goto out_free;
	    vnet_hdr_len = sizeof(struct virtio_net_hdr);
    }

    // 用户空间的缓冲区不足时，丢失部分数据
    copied = skb->len;
    if (copied > len) {
        copied = len;
        msg->msg_flags |= MSG_TRUNC;
    }
    // 复制skb数据到msg，失败时返回
    err = skb_copy_datagram_msg(skb, 0, msg, copied);
    if (err) goto out_free;

    if (sock->type != SOCK_PACKET) {
        // 设置 `sockaddr` family 和 protocol 字段 
        struct sockaddr_ll *sll = &PACKET_SKB_CB(skb)->sa.ll;
        origlen = PACKET_SKB_CB(skb)->sa.origlen;
        sll->sll_family = AF_PACKET;
        sll->sll_protocol = skb->protocol;
    }
    // 读取skb中cmsgs，如：时间戳、丢包计数、mark信息
    sock_recv_cmsgs(msg, sk, skb);

    // msg_name存在时，获取`sockaddr`
    if (msg->msg_name) {
        const size_t max_len = min(sizeof(skb->cb), sizeof(struct sockaddr_storage));
        int copy_len;

        if (sock->type == SOCK_PACKET) {
            __sockaddr_check_size(sizeof(struct sockaddr_pkt));
            msg->msg_namelen = sizeof(struct sockaddr_pkt);
            copy_len = msg->msg_namelen;
        } else {
            struct sockaddr_ll *sll = &PACKET_SKB_CB(skb)->sa.ll; 
            msg->msg_namelen = sll->sll_halen + offsetof(struct sockaddr_ll, sll_addr);
            copy_len = msg->msg_namelen;
            // msg_namelen 不足时，补齐
            if (msg->msg_namelen < sizeof(struct sockaddr_ll)) {
                memset(msg->msg_name + offsetof(struct sockaddr_ll, sll_addr),
                    0, sizeof(sll->sll_addr));
                msg->msg_namelen = sizeof(struct sockaddr_ll);
            }
        }
        if (WARN_ON_ONCE(copy_len > max_len)) {
            copy_len = max_len;
            msg->msg_namelen = copy_len;
        }
        // 复制`sa`到`msg_name`
        memcpy(msg->msg_name, &PACKET_SKB_CB(skb)->sa, copy_len);
    }
    // skb设置辅助数据标记时，读取辅助数据
    if (packet_sock_flag(pkt_sk(sk), PACKET_SOCK_AUXDATA)) {
        struct tpacket_auxdata aux;
        // 状态设置
        aux.tp_status = TP_STATUS_USER;
        if (skb->ip_summed == CHECKSUM_PARTIAL)
            aux.tp_status |= TP_STATUS_CSUMNOTREADY;
        else if (skb->pkt_type != PACKET_OUTGOING && skb_csum_unnecessary(skb))
            aux.tp_status |= TP_STATUS_CSUM_VALID;
        if (skb_is_gso(skb) && skb_is_gso_tcp(skb))
            aux.tp_status |= TP_STATUS_GSO_TCP;
        // 长度信息
        aux.tp_len = origlen;
        aux.tp_snaplen = skb->len;
        aux.tp_mac = 0;
        aux.tp_net = skb_network_offset(skb);
        if (skb_vlan_tag_present(skb)) {
            aux.tp_vlan_tci = skb_vlan_tag_get(skb);
            aux.tp_vlan_tpid = ntohs(skb->vlan_proto);
            aux.tp_status |= TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID;
        } else {
            aux.tp_vlan_tci = 0;
            aux.tp_vlan_tpid = 0;
        }
        // 设置msg数据
        put_cmsg(msg, SOL_PACKET, PACKET_AUXDATA, sizeof(aux), &aux);
    }
    // 释放skb，返回复制的字节数
    err = vnet_hdr_len + ((flags&MSG_TRUNC) ? skb->len : copied);
out_free:
    skb_free_datagram(sk, skb);
out:
    return err;
}
```

#### (3) 接收错误信息

用户程序设置了 `MSG_ERRQUEUE` 标记时，`sock_recv_errqueue` 函数从错误队列中读取错误报文，实现如下：

```C
// file: net/core/sock.c
int sock_recv_errqueue(struct sock *sk, struct msghdr *msg, int len, int level, int type)
{
    struct sock_exterr_skb *serr;
    ...

    err = -EAGAIN;
    // 从`sk_error_queue`中获取一个`skb`，不存在时返回
    skb = sock_dequeue_err_skb(sk);
    if (skb == NULL) goto out;

    // 用户空间的缓冲区不足时，丢失部分数据
    copied = skb->len;
    if (copied > len) {
        msg->msg_flags |= MSG_TRUNC;
        copied = len;
    }
    // 复制skb数据到msg，失败时返回
    err = skb_copy_datagram_msg(skb, 0, msg, copied);
    if (err) goto out_free_skb;
    // 获取接收时间
    sock_recv_timestamp(msg, sk, skb);

    // skb->cb 存放错误信息
    serr = SKB_EXT_ERR(skb);
    // 设置错误信息
    put_cmsg(msg, level, type, sizeof(serr->ee), &serr->ee);

    // 释放skb，返回复制的字节数
    msg->msg_flags |= MSG_ERRQUEUE;
    err = copied;

out_free_skb:
    kfree_skb(skb);
out:
    return err;
}
```

#### (4) 接收数据报文

`skb_recv_datagram` 函数从接收队列中获取skb，实现如下：

```C
// file: net/core/datagram.c
struct sk_buff *skb_recv_datagram(struct sock *sk, unsigned int flags, int *err)
{
    int off = 0;
    return __skb_recv_datagram(sk, &sk->sk_receive_queue, flags, &off, err);
}
```

`__skb_recv_datagram` 函数实现skb的接收过程，计算等待时间后，尝试获取skb。在设置等待时间的情况下，一直尝试获取skb，直到 (1)获取到skb，(2)获取时出现错误、(3)到达等待时间 三种情况的一种时，退出等待。如下：

```C
// file: net/core/datagram.c
struct sk_buff *__skb_recv_datagram(struct sock *sk, struct sk_buff_head *sk_queue, 
                unsigned int flags, int *off, int *err)
{
    struct sk_buff *skb, *last;
    long timeo;
    // `DONTWAIT`标记表示不等待，等待时间为0，否则使用`sk->sk_rcvtimeo` 
    timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

    do {
        // 尝试获取skb
        skb = __skb_try_recv_datagram(sk, sk_queue, flags, off, err, &last);
        // 获取到skb时，返回
        if (skb) return skb;
        // 非`EAGAIN`时，退出循环
        if (*err != -EAGAIN) break;
        // 在超时等待时间内没有更多的skb，一直循环
    } while (timeo && !__skb_wait_for_more_packets(sk, sk_queue, err, &timeo, last));

    return NULL;
}
```

`__skb_try_recv_datagram` 函数以数据报文的方式获取skb，如下：

```C
// file: net/core/datagram.c
struct sk_buff *__skb_try_recv_datagram(struct sock *sk, struct sk_buff_head *queue,
                unsigned int flags, int *off, int *err, struct sk_buff **last)
{
    struct sk_buff *skb;
    unsigned long cpu_flags;
    // 获取错误码，出现错误时设置错误码后返回
    int error = sock_error(sk);
    if (error) goto no_packet;

    do {
        spin_lock_irqsave(&queue->lock, cpu_flags);
        // 从队列中获取skb，PEEK方式获取指定offset的skb，否则获取第一个skb
        skb = __skb_try_recv_from_queue(sk, queue, flags, off, &error, last);
        spin_unlock_irqrestore(&queue->lock, cpu_flags);

        // 出现错误时设置错误码后返回
        if (error) goto no_packet;
        // 获取到skb时，返回skb
        if (skb) return skb;

        // 检查是否支持忙碌等待，不支持退出循环
        if (!sk_can_busy_loop(sk)) break;
        // 忙碌等待
        sk_busy_loop(sk, flags & MSG_DONTWAIT);
        // 队列发送变化时，退出循环
    } while (READ_ONCE(queue->prev) != *last);
    // 无skb时，默认错误码
    error = -EAGAIN;
no_packet:
    *err = error;
    return NULL;
}
```

`__skb_wait_for_more_packets` 函数等待新的skb，实现如下：

```C
// file: net/core/datagram.c
int __skb_wait_for_more_packets(struct sock *sk, struct sk_buff_head *queue,
            int *err, long *timeo_p, const struct sk_buff *skb)
{
    int error;
    // 定义wait，设置当前task不可中断，准备wait队列
    DEFINE_WAIT_FUNC(wait, receiver_wake_function);
    prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
    
    // socket出现错误
    error = sock_error(sk);
    if (error) goto out_err;
    
    // 新skb到来
    if (READ_ONCE(queue->prev) != skb) goto out;
    
    // socket关闭
    if (sk->sk_shutdown & RCV_SHUTDOWN) goto out_noerr;

    error = -ENOTCONN;
    // 基于连接的socket，seq帧判断
    if (connection_based(sk) && !(sk->sk_state == TCP_ESTABLISHED || sk->sk_state == TCP_LISTEN))
        goto out_err;
    // 处理信号
    if (signal_pending(current)) goto interrupted;
    error = 0;

    // 调度其他任务执行，计算剩余等待时间
    *timeo_p = schedule_timeout(*timeo_p);
out:
    // 清理wait队列
    finish_wait(sk_sleep(sk), &wait);
    return error;
interrupted:
    error = sock_intr_errno(*timeo_p);
out_err:
    *err = error;
    goto out;
out_noerr:
    *err = 0;
    error = 1;
    goto out;
}
```

### 4.5 发送数据的过程

#### (1) 系统调用

用户空间程序可以通过 `send`, `sendto`, `sendmsg`, `sendmmsg` 系统调用发送数据。如下：

```C
// file: net/socket.c
SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len, unsigned int, flags)
{
    return __sys_sendto(fd, buff, len, flags, NULL, 0);
}
// file: net/socket.c
SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
    unsigned int, flags, struct sockaddr __user *, addr, int, addr_len)
{
    return __sys_sendto(fd, buff, len, flags, addr, addr_len);
}
// file: net/socket.c
SYSCALL_DEFINE3(sendmsg, int, fd, struct user_msghdr __user *, msg, unsigned int, flags)
{
    return __sys_sendmsg(fd, msg, flags, true);
}
// file: net/socket.c
SYSCALL_DEFINE4(sendmmsg, int, fd, struct mmsghdr __user *, mmsg,
        unsigned int, vlen, unsigned int, flags)
{
    return __sys_sendmmsg(fd, mmsg, vlen, flags, true);
}
```

这些系统调用在获取sock后，直接或间接调用 `sock_sendmsg_nosec` 函数。以 `__sys_sendto` 为例，如下：

```C
// file: net/socket.c
int __sys_sendto(int fd, void __user *buff, size_t len, unsigned int flags,
        struct sockaddr __user *addr,  int addr_len)
{
    struct sockaddr_storage address;
    // msg设置`msg_name`
    struct msghdr msg;
    struct iovec iov;
    ...
    // msg数据设置
    err = import_single_range(ITER_SOURCE, buff, len, &iov, &msg.msg_iter);
    if (unlikely(err)) return err;

    // 查找fd对应的sock
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (!sock) goto out;

    // 设置msg信息
    msg.msg_name = NULL;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_namelen = 0;
    msg.msg_ubuf = NULL;
    if (addr) {
        // 设置msg_name
        err = move_addr_to_kernel(addr, addr_len, &address);
        if (err < 0) goto out_put;
        msg.msg_name = (struct sockaddr *)&address;
        msg.msg_namelen = addr_len;
    }
    if (sock->file->f_flags & O_NONBLOCK)
        flags |= MSG_DONTWAIT;
    msg.msg_flags = flags;
    // 发送数据报文
    err = sock_sendmsg(sock, &msg);
out_put:
    // 释放sock文件
    fput_light(sock->file, fput_needed);
out:
    return err;
}
```

`sock_sendmsg` 函数在通过LSM检查后，发送数据，如下：

```C
// file: net/socket.c
int sock_sendmsg(struct socket *sock, struct msghdr *msg)
{   
    // LSM检查
    int err = security_socket_sendmsg(sock, msg, msg_data_left(msg));
    return err ?: sock_sendmsg_nosec(sock, msg);
}
// file: net/socket.c
static inline int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)
{
    int ret = INDIRECT_CALL_INET(sock->ops->sendmsg, inet6_sendmsg, inet_sendmsg, 
                sock, msg, msg_data_left(msg));
    BUG_ON(ret == -EIOCBQUEUED);

    if (trace_sock_send_length_enabled())
        call_trace_sock_send_length(sock->sk, ret, 0);
    return ret;
}
```

`INDIRECT_CALL_INET` 宏将常用的`inet6_sendmsg`和`inet_sendmsg`函数放到前面提升效率，不是这两个函数时调用`sock->ops->sendmsg`。

#### (2) `packet_sendmsg`实现过程

`AF_PACKET`设置的`ops->sendmsg`接口为`packet_sendmsg`，通过`tpacket_snd`或`packet_snd`发送数据报文，实现如下：

```C
// file: net/packet/af_packet.c
static int packet_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
    struct sock *sk = sock->sk;
    struct packet_sock *po = pkt_sk(sk);

    if (data_race(po->tx_ring.pg_vec))
        return tpacket_snd(po, msg);
    
    return packet_snd(sock, msg, len);
}
```

通过内存映射方式发送数据时，通过`tpacket_snd`发送数据，其他方式以`packet_snd`发送数据。以`packet_snd`为例，实现如下：

```C
// file: net/packet/af_packet.c
static int packet_snd(struct socket *sock, struct msghdr *msg, size_t len)
{
    struct sock *sk = sock->sk;
    // 以`msg_name`初始化`saddr`
    DECLARE_SOCKADDR(struct sockaddr_ll *, saddr, msg->msg_name);
    // 分散-聚集列表的头部信息，指定GSO或CSUM时，使用该头部信息
    struct virtio_net_hdr vnet_hdr = { 0 };
    int offset = 0;
    struct packet_sock *po = pkt_sk(sk);
    bool has_vnet_hdr = false;
    ...

    // 获取发送的网卡设备和协议
    if (likely(saddr == NULL)) {
        // 用户空间没有设置时，使用默认的dev和proto
        dev = packet_cached_dev_get(po);
        proto = READ_ONCE(po->num);
    } else {
        err = -EINVAL;
        ...
        // 使用设置的dev和proto
        proto = saddr->sll_protocol;
        dev = dev_get_by_index(sock_net(sk), saddr->sll_ifindex);
        if (sock->type == SOCK_DGRAM) {
            ...
            addr = saddr->sll_addr;
        }
    }
    // dev不存在或者离线状态，退出
    err = -ENXIO;
    if (unlikely(dev == NULL)) goto out_unlock;
    err = -ENETDOWN;
    if (unlikely(!(dev->flags & IFF_UP))) goto out_unlock;

    // 获取cmsg，设置sk相关参数
    sockcm_init(&sockc, sk);
    sockc.mark = sk->sk_mark;
    if (msg->msg_controllen) {
        err = sock_cmsg_send(sk, msg, &sockc);
        if (unlikely(err)) goto out_unlock;
    }

    // RAW类型，设置保留长度
    if (sock->type == SOCK_RAW)
        reserve = dev->hard_header_len;
    if (po->has_vnet_hdr) {
        // 虚拟网络头部解析
        err = packet_snd_vnet_parse(msg, &len, &vnet_hdr);
        if (err) goto out_unlock;
        has_vnet_hdr = true;
    }
    // 循环冗余校验字段(FCS)支持性检查，长度为4个字节
    if (unlikely(sock_flag(sk, SOCK_NOFCS))) {
        if (!netif_supports_nofcs(dev)) {
            err = -EPROTONOSUPPORT;
            goto out_unlock;
        }
        extra_len = 4; /* We're doing our own CRC */
    }

    err = -EMSGSIZE;
    // 检查msg长度是否超过网络包长度
    if (!vnet_hdr.gso_type && (len > dev->mtu + reserve + VLAN_HLEN + extra_len))
        goto out_unlock;

    // 计算skb各区域长度，创建skb
    err = -ENOBUFS;
    hlen = LL_RESERVED_SPACE(dev);
    tlen = dev->needed_tailroom;
    linear = __virtio16_to_cpu(vio_le(), vnet_hdr.hdr_len);
    linear = max(linear, min_t(int, len, dev->hard_header_len));
    skb = packet_alloc_skb(sk, hlen + tlen, hlen, len, linear, 
            msg->msg_flags & MSG_DONTWAIT, &err);
    if (skb == NULL) goto out_unlock;

    // 重置skb网络头部位置
    skb_reset_network_header(skb);

    err = -EINVAL;
    // 设置skb头部
    if (sock->type == SOCK_DGRAM) {
        // 网卡设备设置skb头部信息
        offset = dev_hard_header(skb, dev, ntohs(proto), addr, NULL, len);
        if (unlikely(offset < 0)) goto out_free;
    } else if (reserve) {
        // 预留skb头部信息
        skb_reserve(skb, -reserve);
        if (len < reserve + sizeof(struct ipv6hdr) && dev->min_header_len != dev->hard_header_len)
            skb_reset_network_header(skb);
    }
    // 复制数据到skb中
    err = skb_copy_datagram_from_iter(skb, offset, &msg->msg_iter, len);
    if (err) goto out_free;

    // `SOCK_RAW` 检查skb头部和长度信息
    if ((sock->type == SOCK_RAW && !dev_validate_header(dev, skb->data, len)) || !skb->len) {
        err = -EINVAL;
        goto out_free;
    }
    // 设置TX发送时间戳
    skb_setup_tx_timestamp(skb, sockc.tsflags);
    // VLAN pkt检查
    if (!vnet_hdr.gso_type && (len > dev->mtu + reserve + extra_len) &&
        !packet_extra_vlan_len_allowed(dev, skb)) {
        err = -EMSGSIZE;
        goto out_free;
    }
    // skb属性检查
    skb->protocol = proto;
    skb->dev = dev;
    skb->priority = sk->sk_priority;
    skb->mark = sockc.mark;
    skb->tstamp = sockc.transmit_time;
    // no_fcs设置
    if (unlikely(extra_len == 4)) skb->no_fcs = 1;
    
    // 解析头部信息，`SOCK_RAW:ETH_P_ALL`模式下获取`protocol`, VLAN网络包移动头部到正确的位置
    packet_parse_headers(skb, sock);

    if (has_vnet_hdr) {
        // 虚拟网络头部设置
        err = virtio_net_hdr_to_skb(skb, &vnet_hdr, vio_le());
        if (err) goto out_free;
        len += sizeof(vnet_hdr);
        // skb网络协议设置
        virtio_net_hdr_set_proto(skb, &vnet_hdr);
    }
    // 发送skb
    err = READ_ONCE(po->xmit)(skb);
    if (unlikely(err != 0)) {
        // NET_XMIT_CN 提示用户减少发送
        if (err > 0) err = net_xmit_errno(err);
        if (err) goto out_unlock;
    }
    // 正确发送时，返回长度
    dev_put(dev);
    return len;
    // 错误时，释放skb，返回错误码
out_free:
    kfree_skb(skb);
out_unlock:
    dev_put(dev);
out:
    return err;
}
```

`po->xmit` 接口发送skb，默认设置为`dev_queue_xmit`，如下：

```C
// file: net/packet/af_packet.c
static int packet_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    ...
    po->xmit = dev_queue_xmit;
    ...
}
```

### 4.6 获取socket状态的过程

用户空间程序在接收网络数据包时，在无数据时且没有设置`MSG_DONTWAIT`标记时，用户空间程序将一直等待某个事件发生，没有发生时，进程将一直阻塞。用户空间程序可以通过 `select`, `poll`, `epoll` 方式获取socket状态，判断可读或可写事件，根据状态进行网络数据的接收和释放。

#### (1) 系统调用

以`poll`为例，系统调用如下：

```C
// file: fs/select.c
SYSCALL_DEFINE3(poll, struct pollfd __user *, ufds, unsigned int, nfds, int, timeout_msecs)
{
    struct timespec64 end_time, *to = NULL;
    int ret;
    
    // 设置等待时间时，计算结束时间
    if (timeout_msecs >= 0) {
        to = &end_time;
        poll_select_set_timeout(to, timeout_msecs / MSEC_PER_SEC, 
            NSEC_PER_MSEC * (timeout_msecs % MSEC_PER_SEC));
    }
    // 执行poll
    ret = do_sys_poll(ufds, nfds, to);

    // 检查是否重新开始
    if (ret == -ERESTARTNOHAND) {
        struct restart_block *restart_block;
        // 重新开始 poll参数设置
        restart_block = &current->restart_block;
        restart_block->poll.ufds = ufds;
        restart_block->poll.nfds = nfds;

        if (timeout_msecs >= 0) {
            restart_block->poll.tv_sec = end_time.tv_sec;
            restart_block->poll.tv_nsec = end_time.tv_nsec;
            restart_block->poll.has_timeout = 1;
        } else
            restart_block->poll.has_timeout = 0;
        // 设置重新开始执行函数
        ret = set_restart_fn(restart_block, do_restart_poll);
    }
    return ret;
}
```

#### (2) `do_sys_poll`实现过程

`do_sys_poll` 函数执行实现的poll实现，复制`ufds`到内核中，执行poll操作获取`fcount`，之后将期间获取的事件复制到用户空间。如下：

```C
// file: fs/select.c
static int do_sys_poll(struct pollfd __user *ufds, unsigned int nfds, struct timespec64 *end_time)
{
    struct poll_wqueues table;
    int err = -EFAULT, fdcount, len;
    // 使用栈空间，节省内存并提升效率，`256`字节
    long stack_pps[POLL_STACK_ALLOC/sizeof(long)];
    struct poll_list *const head = (struct poll_list *)stack_pps;
    struct poll_list *walk = head;
    unsigned long todo = nfds;

    // fd数据操作limit限制时，退出
    if (nfds > rlimit(RLIMIT_NOFILE)) return -EINVAL;

    // 栈空间可以使用的fd数量
    len = min_t(unsigned int, nfds, N_STACK_PPS);
    for (;;) {
        walk->next = NULL;
        walk->len = len;
        if (!len) break;
        // 复制`pollfd`到内核空间
        if (copy_from_user(walk->entries, ufds + nfds-todo, sizeof(struct pollfd) * walk->len))
            goto out_fds;
        // 计算剩余fd数量，
        todo -= walk->len;
        if (!todo) break;

        // 计算页使用的fd数据，分配内存页
        len = min(todo, POLLFD_PER_PAGE);
        walk = walk->next = kmalloc(struct_size(walk, entries, len), GFP_KERNEL);
        if (!walk) { ... }
    }

    // poll_wait设置
    poll_initwait(&table);
    fdcount = do_poll(head, &table, end_time);
    poll_freewait(&table);
    
    // 检查用户空间是否可读
    if (!user_write_access_begin(ufds, nfds * sizeof(*ufds))) goto out_fds;

    // 遍历所有的poll列表，复制`revents`到用户空间
    for (walk = head; walk; walk = walk->next) {
        struct pollfd *fds = walk->entries;
        int j;
        for (j = walk->len; j; fds++, ufds++, j--)
            unsafe_put_user(fds->revents, &ufds->revents, Efault);
    }
    user_write_access_end();

    err = fdcount;
out_fds:
    // 释放分配的poll列表
    walk = head->next;
    while (walk) {
        struct poll_list *pos = walk;
        walk = walk->next;
        kfree(pos);
    }
    return err;

Efault:
    user_write_access_end();
    err = -EFAULT;
    goto out_fds;
}
```

#### (3) 设置poll等待队列

`poll_initwait` 函数设置poll等待队列信息，如下：

```C
// file: fs/select.c
void poll_initwait(struct poll_wqueues *pwq)
{   
    // poll_table设置
    init_poll_funcptr(&pwq->pt, __pollwait);
    pwq->polling_task = current;
    pwq->triggered = 0;
    pwq->error = 0;
    pwq->table = NULL;
    pwq->inline_index = 0;
}
```

#### (4) 进行`poll`

```C
// file: fs/select.c
static int do_poll(struct poll_list *list, struct poll_wqueues *wait, struct timespec64 *end_time)
{
    poll_table* pt = &wait->pt;
    ktime_t expire, *to = NULL;
    int timed_out = 0, count = 0;
    u64 slack = 0;
    ...

    // 优化不等待的情况
    if (end_time && !end_time->tv_sec && !end_time->tv_nsec) {
        pt->_qproc = NULL;
        timed_out = 1;
    }
    // 计算休闲时间(最大100ms)
    if (end_time && !timed_out) 
        slack = select_estimate_accuracy(end_time);

    for (;;) {
        struct poll_list *walk;
        // 遍历poll列表
        for (walk = list; walk != NULL; walk = walk->next) {
            struct pollfd * pfd, * pfd_end;
            pfd = walk->entries;
            pfd_end = pfd + walk->len;
            // 遍历pollfd
            for (; pfd != pfd_end; pfd++) {
                // 检查pollfd事件，满足一个时，记录fd事件，注销后续服务
                if (do_pollfd(pfd, pt, &can_busy_loop, busy_flag)) {
                    count++;
                    pt->_qproc = NULL;
                    /* found something, stop busy polling */
                    busy_flag = 0;
                    can_busy_loop = false;
			    }
		    }
        }
        // 所有pollfd都注册时，下次循环时，不需要再次注册
        pt->_qproc = NULL;
        if (!count) {
            count = wait->error;
            // 设置当前task处于等待状态
            if (signal_pending(current))
                count = -ERESTARTNOHAND;
        }
        // 触发事件、或者出现错误、或者超时，退出循环
        if (count || timed_out) break;

        ...
        // 计算过期时间
        if (end_time && !to) {
            expire = timespec64_to_ktime(*end_time);
            to = &expire;
        }
        // 调度其他任务执行，判断是否超时
        if (!poll_schedule_timeout(wait, TASK_INTERRUPTIBLE, to, slack))
            timed_out = 1;
	}
	return count;
}
```

`do_pollfd` 函数检查`pollfd`可轮询事件，我们只关注`pollfd->events`对应的事件，将结果记录到`pollfd->revents`。如下：

```C
// file: fs/select.c
static inline __poll_t do_pollfd(struct pollfd *pollfd, poll_table *pwait,
                bool *can_busy_poll, __poll_t busy_flag)
{
    int fd = pollfd->fd;
    __poll_t mask = 0, filter;
    struct fd f;

    if (fd < 0) goto out;
    mask = EPOLLNVAL;
    // 获取fd对应的文件
    f = fdget(fd);
    if (!f.file) goto out;

    // poll事件转换为epoll事件
    filter = demangle_poll(pollfd->events) | EPOLLERR | EPOLLHUP;
    pwait->_key = filter | busy_flag;
    // 查询fd的事件状态 
    mask = vfs_poll(f.file, pwait);
    if (mask & busy_flag) *can_busy_poll = true;
    mask &= filter;		/* Mask out unneeded events. */
    fdput(f);

out:
    // epoll事件转换为poll事件，记录到`revents`
    pollfd->revents = mangle_poll(mask);
    return mask;
}
```

`vfs_poll` 获取文件的epoll事件，调用`f_op->poll` 接口，如下：

```C
// file: include/linux/poll.h
static inline __poll_t vfs_poll(struct file *file, struct poll_table_struct *pt)
{
	if (unlikely(!file->f_op->poll))
		return DEFAULT_POLLMASK;
	return file->f_op->poll(file, pt);
}
```

#### (5) `packet_poll`实现过程

`f_op->poll`设置为`sock_poll`，如下：

```C
// file: net/socket.c
static const struct file_operations socket_file_ops = {
    ...
    .poll =	sock_poll,
    ...
};
```

实现如下：

```C
// file: net/socket.c
static __poll_t sock_poll(struct file *file, poll_table *wait)
{
    struct socket *sock = file->private_data;
    __poll_t events = poll_requested_events(wait), flag = 0;

    if (!sock->ops->poll) return 0;

    // 检查是否忙碌循环
    if (sk_can_busy_loop(sock->sk)) {
        if (events & POLL_BUSY_LOOP)
            sk_busy_loop(sock->sk, 1);
        flag = POLL_BUSY_LOOP;
    }
    // 具体sock的poll实现
    return sock->ops->poll(file, sock, wait) | flag;
}
```

`AF_PACKET`设置的`ops->poll`接口为`packet_poll`。获取sock后，通过`datagram_poll`实现，如下：

```C
// file: net/packet/af_packet.c
static __poll_t packet_poll(struct file *file, struct socket *sock, poll_table *wait)
{
    struct sock *sk = sock->sk;
    struct packet_sock *po = pkt_sk(sk);
    __poll_t mask = datagram_poll(file, sock, wait);
    ...
    return mask;
}
```

`datagram_poll` 是通用数据数据报文轮询，如下：

```C
// file: net/core/datagram.c
__poll_t datagram_poll(struct file *file, struct socket *sock, poll_table *wait)
{
    struct sock *sk = sock->sk;
    __poll_t mask;
    u8 shutdown;

    // 注册到`poll_table`中
    sock_poll_wait(file, sock, wait);
    mask = 0;

    // 异常事件
    if (READ_ONCE(sk->sk_err) || !skb_queue_empty_lockless(&sk->sk_error_queue))
        mask |= EPOLLERR | (sock_flag(sk, SOCK_SELECT_ERR_QUEUE) ? EPOLLPRI : 0);

    // 关闭事件
    shutdown = READ_ONCE(sk->sk_shutdown);
    if (shutdown & RCV_SHUTDOWN)
        mask |= EPOLLRDHUP | EPOLLIN | EPOLLRDNORM;
    if (shutdown == SHUTDOWN_MASK)
        mask |= EPOLLHUP;

    // 可读事件
    if (!skb_queue_empty_lockless(&sk->sk_receive_queue))
        mask |= EPOLLIN | EPOLLRDNORM;

    // 基于连接的sock，终止和启动事件
    if (connection_based(sk)) {
        int state = READ_ONCE(sk->sk_state);
        if (state == TCP_CLOSE) 
            mask |= EPOLLHUP;
        if (state == TCP_SYN_SENT)
            return mask;
    }
    // 可写事件
    if (sock_writeable(sk))
        mask |= EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND;
    else
        sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);
    return mask;
}
```

#### (6) 注册`poll`事件

`sock_poll_wait` 函数将sock注册到`poll_table`中，如下：

```C
// file: include/net/sock.h
static inline void sock_poll_wait(struct file *filp, struct socket *sock, poll_table *p)
{
    if (!poll_does_not_wait(p)) {
        poll_wait(filp, &sock->wq.wait, p);
        // 确保socket flags同步更新
        smp_mb();
    }
}
// file: include/linux/poll.h
static inline void poll_wait(struct file * filp, wait_queue_head_t * wait_address, poll_table *p)
{
    if (p && p->_qproc && wait_address)
        p->_qproc(filp, wait_address, p);
}
```

`p->_qproc` 设置为`__pollwait`，添加新的等待信息，实现如下：

```C
// file: fs/select.c
static void __pollwait(struct file *filp, wait_queue_head_t *wait_address, poll_table *p)
{
    struct poll_wqueues *pwq = container_of(p, struct poll_wqueues, pt);
    // 获取`entry`
    struct poll_table_entry *entry = poll_get_entry(pwq);
    if (!entry) return;
    entry->filp = get_file(filp);
    entry->wait_address = wait_address;
    entry->key = p->_key;
    init_waitqueue_func_entry(&entry->wait, pollwake);
    entry->wait.private = pwq;
    // 添加`entry`到`wait_address`
    add_wait_queue(wait_address, &entry->wait);
}
```

`poll_get_entry` 函数获取等待队列`entry`，每个`pollfd`对应一个`entry`。这些`entry`以页的形式形成列表，当前页满了后分配新的页。如下：

```C
// file: fs/select.c
static struct poll_table_entry *poll_get_entry(struct poll_wqueues *p)
{
    struct poll_table_page *table = p->table;
    // 获取线性entry
    if (p->inline_index < N_INLINE_POLL_ENTRIES)
        return p->inline_entries + p->inline_index++;
        
    // 线性`entry`使用完了后，分配`page`
    if (!table || POLL_TABLE_FULL(table)) {
        // table不存在或已满的情况下创建新的table
        struct poll_table_page *new_table;
        new_table = (struct poll_table_page *) __get_free_page(GFP_KERNEL);
        if (!new_table) { ... }
        
        // 组织链表
        new_table->entry = new_table->entries;
        new_table->next = table;
        p->table = new_table;
        table = new_table;
    }
    return table->entry++;
}
```

#### (7) 唤醒`poll`事件

`PF_PACKET`在接收数据时通知数据准备完成，绑定失败时、设备离线时通知错误信息，唤起等待事件。在接收数据的`packet_rcv`函数的最后，调用`sk->sk_data_ready`接口函数，唤起等待事件。

```C
// file: net/core/sock.c
void sock_init_data_uid(struct socket *sock, struct sock *sk, kuid_t uid)
{
    ...
    sk->sk_state_change	=	sock_def_wakeup;
    sk->sk_data_ready	=	sock_def_readable;
    sk->sk_write_space	=	sock_def_write_space;
    sk->sk_error_report	=	sock_def_error_report;
    ...
}
```

`.sk_data_ready`接口设置`sock_def_readable`，实现如下：

```C
// file: net/core/sock.c
void sock_def_readable(struct sock *sk)
{
    struct socket_wq *wq;
    trace_sk_data_ready(sk);

    rcu_read_lock();
    wq = rcu_dereference(sk->sk_wq);
    if (skwq_has_sleeper(wq))
        wake_up_interruptible_sync_poll(&wq->wait, EPOLLIN | EPOLLPRI | EPOLLRDNORM | EPOLLRDBAND);
    sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
    rcu_read_unlock();
}
```

`.sk_error_report`接口设置`sock_def_error_report`，实现如下：

```C
// file: net/core/sock.c
static void sock_def_error_report(struct sock *sk)
{
    struct socket_wq *wq;

    rcu_read_lock();
    wq = rcu_dereference(sk->sk_wq);
    if (skwq_has_sleeper(wq))
        wake_up_interruptible_poll(&wq->wait, EPOLLERR);
    sk_wake_async(sk, SOCK_WAKE_IO, POLL_ERR);
    rcu_read_unlock();
}
```

`wake_up_interruptible_sync_poll` 和 `wake_up_interruptible_poll` 是对 `__wake_up_common_lock` 的调用封装。如下：

```C
// file: include/linux/wait.h
#define wake_up_interruptible_poll(x, m)					\
	__wake_up(x, TASK_INTERRUPTIBLE, 1, poll_to_key(m))
#define wake_up_interruptible_sync_poll(x, m)					\
	__wake_up_sync_key((x), TASK_INTERRUPTIBLE, poll_to_key(m))

// file: kernel/sched/wait.c
int __wake_up(struct wait_queue_head *wq_head, unsigned int mode, int nr_exclusive, void *key)
{
    return __wake_up_common_lock(wq_head, mode, nr_exclusive, 0, key);
}
// file: kernel/sched/wait.c
void __wake_up_sync_key(struct wait_queue_head *wq_head, unsigned int mode, void *key)
{
    if (unlikely(!wq_head)) return;
    __wake_up_common_lock(wq_head, mode, 1, WF_SYNC, key);
}
```

`__wake_up_common_lock` 函数唤起等待队列的线程。如下：

```C
// file: kernel/sched/wait.c
static int __wake_up_common_lock(struct wait_queue_head *wq_head, unsigned int mode,
        int nr_exclusive, int wake_flags, void *key)
{
    unsigned long flags;
    wait_queue_entry_t bookmark;
    int remaining = nr_exclusive;

    // 书签，表示正在正在运行的队列
    bookmark.flags = 0;
    bookmark.private = NULL;
    bookmark.func = NULL;
    INIT_LIST_HEAD(&bookmark.entry);

    do {
        spin_lock_irqsave(&wq_head->lock, flags);
        remaining = __wake_up_common(wq_head, mode, remaining, wake_flags, key, &bookmark);
        spin_unlock_irqrestore(&wq_head->lock, flags);
    } while (bookmark.flags & WQ_FLAG_BOOKMARK);

    return nr_exclusive - remaining;
}
```

`__wake_up_common` 函数实现核心的唤醒操作，如下：

```C
// file: kernel/sched/wait.c
static int __wake_up_common(struct wait_queue_head *wq_head, unsigned int mode,
            int nr_exclusive, int wake_flags, void *key, wait_queue_entry_t *bookmark)
{
    wait_queue_entry_t *curr, *next;

    // 获取当前执行的队列
    if (bookmark && (bookmark->flags & WQ_FLAG_BOOKMARK)) {
        // 获取下一个执行的队列，删除书签
        curr = list_next_entry(bookmark, entry);
        list_del(&bookmark->entry);
        bookmark->flags = 0;
    } else
        curr = list_first_entry(&wq_head->head, wait_queue_entry_t, entry);
    
    // 执行完成
    if (&curr->entry == &wq_head->head) 
        return nr_exclusive;

    // 遍历等待队列列表
    list_for_each_entry_safe_from(curr, next, &wq_head->head, entry) {
        unsigned flags = curr->flags;
        if (flags & WQ_FLAG_BOOKMARK) continue;
        // 唤醒等待队列
        ret = curr->func(curr, mode, wake_flags, key);
        
        if (ret < 0) break;
        if (ret && (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive) break;

        // 记录书签
        if (bookmark && (++cnt > WAITQUEUE_WALK_BREAK_CNT) && (&next->entry != &wq_head->head)) {
            bookmark->flags = WQ_FLAG_BOOKMARK;
            list_add_tail(&bookmark->entry, &next->entry);
            break;
        }
    }
    return nr_exclusive;
}
```

`curr->func` 调用等待队列设置的函数，设置为`pollwake`。实现如下：

```C
// file: fs/select.c
static int pollwake(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
    struct poll_table_entry *entry;
    entry = container_of(wait, struct poll_table_entry, wait);
    if (key && !(key_to_poll(key) & entry->key)) return 0;
    return __pollwake(wait, mode, sync, key);
}
```

`__pollwake` 函数设置poll等待队列触发，如下：

```C
// file: fs/select.c
static int __pollwake(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
    struct poll_wqueues *pwq = wait->private;
    DECLARE_WAITQUEUE(dummy_wait, pwq->polling_task);
    
    smp_wmb();
    // 设置触发标记，线程执行时，`poll`等待时停止切换其他任务
    pwq->triggered = 1;

    // 默认唤醒
    return default_wake_function(&dummy_wait, mode, sync, key);
}
```

`do_poll` 函数通过 `poll_schedule_timeout` 函数，切换到其他任务执行。在唤醒`poll`等待队列时，将停止切换。如下：

```C
// file: fs/select.c
static int poll_schedule_timeout(struct poll_wqueues *pwq, int state, 
            ktime_t *expires, unsigned long slack)
{
    int rc = -EINTR;

    set_current_state(state);
    if (!pwq->triggered)
        // 调度其他任务执行
        rc = schedule_hrtimeout_range(expires, slack, HRTIMER_MODE_ABS);
    __set_current_state(TASK_RUNNING);
    
    smp_store_mb(pwq->triggered, 0);
    return rc;
}
```

#### (8) 释放`poll`等待队列

`poll_freewait` 函数释放poll等待队列和占用的页，如下：

```C
// file: fs/select.c
void poll_freewait(struct poll_wqueues *pwq)
{
    struct poll_table_page * p = pwq->table;
    // 释放线性`entry`
    for (i = 0; i < pwq->inline_index; i++)
        free_poll_entry(pwq->inline_entries + i);

    while (p) {
        struct poll_table_entry * entry;
        struct poll_table_page *old;
        entry = p->entry;
        do {
            entry--;
            free_poll_entry(entry);
        } while (entry > p->entries);
        old = p;
        p = p->next;
        // 释放页
        free_page((unsigned long) old);
    }
}
```

### 4.6 关闭socket的过程

#### 1 `close`系统调用

用户空间程序在退出程序时，通过`close`系统调用关闭socket。`close`系统调用如下:

```C
// file: fs/open.c
SYSCALL_DEFINE1(close, unsigned int, fd)
{
    int retval = close_fd(fd);
    if (unlikely(retval == -ERESTARTSYS || retval == -ERESTARTNOINTR || 
            retval == -ERESTARTNOHAND || retval == -ERESTART_RESTARTBLOCK))
        retval = -EINTR;
    return retval;
}
```

`close_fd` 函数的调用过程如下：

```C
// file: fs/open.c
int close_fd(unsigned fd)
    --> struct files_struct *files = current->files;
        // 选择fd对应的文件
    --> file = pick_file(files, fd);
    --> filp_close(file, files);
            // 调用flush接口
        --> retval = filp->f_op->flush(filp, id);
        --> fput(filp);
            // 通过`task_work`调用
            --> __fput(file);
                    // 设置FASYNC标记时，调用`fasync`接口
                --> file->f_op->fasync(-1, file, 0);            
                    // 调用release接口
                --> file->f_op->release(inode, file);
```

#### 2 `sock_close`实现过程

在`socket`系统调用时，将`sock`和`file`关联，设置了文件的操作接口，如下：

```C
// file: net/socket.c
struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
{
    ...
    file = alloc_file_pseudo(SOCK_INODE(sock), sock_mnt, dname,
            O_RDWR | (flags & O_NONBLOCK), &socket_file_ops);
    ...
}
```

`socket_file_ops` 定义如下：

```C
// file: net/socket.c
static const struct file_operations socket_file_ops = {
    .owner =    THIS_MODULE,
    ...
    .release =  sock_close,
};
```

`.release` 接口设置为`sock_close`，实现如下：

```C
// file: net/socket.c
static int sock_close(struct inode *inode, struct file *filp)
{
    __sock_release(SOCKET_I(inode), inode);
    return 0;
}

// file: net/socket.c
static void __sock_release(struct socket *sock, struct inode *inode)
{
    if (sock->ops) {
        struct module *owner = sock->ops->owner;
        if (inode) inode_lock(inode);
        // sock->ops释放接口
        sock->ops->release(sock);
        sock->sk = NULL;
        if (inode) inode_unlock(inode);
        sock->ops = NULL;
        module_put(owner);
    }
    ...
    // 释放`SOCK_INODE`
    if (!sock->file) {
        iput(SOCK_INODE(sock));
        return;
    }
    sock->file = NULL;
}
```

#### 3 `packet_release`实现过程

在`socket`系统调用时，`sock->ops`设置为`packet_ops`，`.release`接口设置为 `packet_release` , 实现如下：

```C
// file: net/packet/af_packet.c
static int packet_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    ...
    if (!sk) return 0;
    
    net = sock_net(sk);
    po = pkt_sk(sk);

    // 从网络命名空间中删除`sk`
    mutex_lock(&net->packet.sklist_lock);
    sk_del_node_init_rcu(sk);
    mutex_unlock(&net->packet.sklist_lock);

    // 协议使用计数修改
    sock_prot_inuse_add(net, sk->sk_prot, -1);

    spin_lock(&po->bind_lock);
    // 注销prot_hook
    unregister_prot_hook(sk, false);
    packet_cached_dev_reset(po);

    if (po->prot_hook.dev) {
        // 释放tracker
        netdev_put(po->prot_hook.dev, &po->prot_hook.dev_tracker);
        po->prot_hook.dev = NULL;
    }
    spin_unlock(&po->bind_lock);

    // 刷新mclist
    packet_flush_mclist(sk);

    lock_sock(sk);
    if (po->rx_ring.pg_vec) {
        // 清空RX缓冲区
        memset(&req_u, 0, sizeof(req_u));
        packet_set_ring(sk, &req_u, 1, 0);
    }
    if (po->tx_ring.pg_vec) {
        // 清空TX缓冲区
        memset(&req_u, 0, sizeof(req_u));
        packet_set_ring(sk, &req_u, 1, 1);
    }
    // 释放sk
    release_sock(sk);
    // 释放fanout
    f = fanout_release(sk);
    // 同步数据包接收处理
    synchronize_net();

    kfree(po->rollover);
    if (f) {
        // 释放fanout数据
        fanout_release_data(f);
        kvfree(f);
    }
    // 设置sk死亡状态
    sock_orphan(sk);
    sock->sk = NULL;

    // 清空接收队列
    skb_queue_purge(&sk->sk_receive_queue);
    // 释放待定计数
    packet_free_pending(po);

    // 释放sk
    sock_put(sk);
    return 0;
}
```

`sock_put` 函数减少sk引用计数，计数为0时，释放sk。如下：

```C
// file: include/net/sock.h
static inline void sock_put(struct sock *sk)
{
    if (refcount_dec_and_test(&sk->sk_refcnt))
        sk_free(sk);
}
// file: include/net/sock.h
void sk_free(struct sock *sk)
{
    if (refcount_dec_and_test(&sk->sk_wmem_alloc))
        __sk_free(sk);
}
// file: net/core/sock.c
static void __sk_free(struct sock *sk)
{
    if (likely(sk->sk_net_refcnt))
        sock_inuse_add(sock_net(sk), -1);

    if (unlikely(sk->sk_net_refcnt && sock_diag_has_destroy_listeners(sk)))
        // netlink广播sk销毁信息，
        sock_diag_broadcast_destroy(sk);
    else
        sk_destruct(sk);
}
```

#### 4 `sk_destruct`实现过程

`sk_destruct` 函数析构sk，释放分配的资源，如下：

```C
// file: net/core/sock.c
void sk_destruct(struct sock *sk)
{
    bool use_call_rcu = sock_flag(sk, SOCK_RCU_FREE);

    if (rcu_access_pointer(sk->sk_reuseport_cb)) {
        // 释放`reuseport_cb`
        reuseport_detach_sock(sk);
        use_call_rcu = true;
    }
    // 直接调用或rcu调用`__sk_destruct`
    if (use_call_rcu)
        call_rcu(&sk->sk_rcu, __sk_destruct);
    else
        __sk_destruct(&sk->sk_rcu);
}
```

`__sk_destruct` 函数析构sk，如下：

```C
// file: net/core/sock.c
static void __sk_destruct(struct rcu_head *head)
{
    struct sock *sk = container_of(head, struct sock, sk_rcu);
    // sk->sk_destruct 接口
    if (sk->sk_destruct)
        sk->sk_destruct(sk);

    filter = rcu_dereference_check(sk->sk_filter, 
                refcount_read(&sk->sk_wmem_alloc) == 0);
    if (filter) {
        // 释放sk_filter
        sk_filter_uncharge(sk, filter);
        RCU_INIT_POINTER(sk->sk_filter, NULL);
    }
    // 禁用时间标记
    sock_disable_timestamp(sk, SK_FLAGS_TIMESTAMP);

#ifdef CONFIG_BPF_SYSCALL
    bpf_sk_storage_free(sk);
#endif
    ...
    // 释放sk_frag
    if (sk->sk_frag.page) {
        put_page(sk->sk_frag.page);
        sk->sk_frag.page = NULL;
    }

    put_cred(sk->sk_peer_cred);
    put_pid(sk->sk_peer_pid);

    // 释放 ns_tracker
    if (likely(sk->sk_net_refcnt))
        put_net_track(sock_net(sk), &sk->ns_tracker);
    else
        __netns_tracker_free(sock_net(sk), &sk->ns_tracker, false);

    // 释放 sk_prot
    sk_prot_free(sk->sk_prot_creator, sk);
}
```

#### 5 `packet_sock_destruct`实现过程

`sk->sk_destruct`接口设置为 `packet_sock_destruct`，实现如下：

```C
// file: net/packet/af_packet.c
static void packet_sock_destruct(struct sock *sk)
{
    // 清空错误队列
    skb_queue_purge(&sk->sk_error_queue);

    // 检查接收和发送占用的内存量
    WARN_ON(atomic_read(&sk->sk_rmem_alloc));
    WARN_ON(refcount_read(&sk->sk_wmem_alloc));
    // 检查sk死亡状态
    if (!sock_flag(sk, SOCK_DEAD)) {
        pr_err("Attempt to release alive packet socket: %p\n", sk);
        return;
    }
}
```

## 5 总结

本文通过`sockfilter`示例程序分析了Linux内核使用BPF对抓包过滤的实现过程，在此基础上分析了用户空间在进行网络操作时Linux内核内部的实现过程。


## 参考资料

* [Linux Socket Filtering aka Berkeley Packet Filter (BPF)](https://www.kernel.org/doc/html/latest/networking/filter.html)
* [[译] Linux Socket Filtering (LSF, aka BPF)](https://arthurchiao.art/blog/linux-socket-filtering-aka-bpf-zh/)
* [Linux 网络栈接收数据（RX）：原理及内核实现（2022）](https://arthurchiao.art/blog/linux-net-stack-implementation-rx-zh/)
* [Linux 网络栈监控和调优：发送数据（2017）](http://arthurchiao.art/blog/tuning-stack-tx-zh/)
* [深入理解 Cilium 的 eBPF 收发包路径（datapath）（KubeCon, 2019）](https://arthurchiao.art/blog/understanding-ebpf-datapath-in-cilium-zh/)
* [ A Standard for the Transmission of IP Datagrams over IEEE 802 Networks](https://www.rfc-editor.org/rfc/rfc1042)
* [INTERNET PROTOCOL (rfc791)](https://www.rfc-editor.org/rfc/rfc791)
* [Ethernet Frame Format](https://www.geeksforgeeks.org/ethernet-frame-format/)