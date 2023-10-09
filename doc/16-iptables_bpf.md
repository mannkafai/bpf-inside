# IPTABLES_BPF内核实现

## 0 前言

在上一篇文章中，我们分析网络数据包在L3在确定输入/输出路由后进行后续处理，在处理过程中需要通过`NF_HOOK`点进行检查。今天我们借助`iptables_test`示例程序分析BPF程序在netfilter中的应用。

## 1 简介

iptables是Linux防火墙系统的重要组成部分，它基于内核的包过滤框架(netfilter)实现的。iptables与协议栈内有包过滤功能的hook交互来完成工作，每个进入网络系统的包（接收或发送）在经过协议栈时都会触发这些hook，程序可以通过注册hook函数的方式在一些关键路径上处理网络流量。iptables相关的内核模块在这些hook点注册了处理函数，因此可以通过配置iptables规则来使得网络流量符合防火墙规则。

## 2 `iptables_test`示例程序

### 2.1 BPF程序

BPF程序源码参见[iptables_test.bpf.c](../src/iptables_test.bpf.c)，主要内容如下：

```C
SEC("socket")
int iptables_accepted(struct __sk_buff *skb)
{
    // 获取skb cookie
    uint32_t cookie = bpf_get_socket_cookie(skb);
    // 从map中获取cookie对应的统计信息
    struct stats *rst = bpf_map_lookup_elem(&cookie_stats, &cookie);
    if (rst == NULL)
    {
        // 不存在时，设置统计信息后，添加到map中
        struct stats stat;
        stat.uid = bpf_get_socket_uid(skb);
        stat._res = 0;
        stat.packets = 1;
        stat.bytes = skb->len;
        bpf_map_update_elem(&cookie_stats, &cookie, &stat, BPF_ANY);
    }
    else
    {   
        // 更新统计信息
        rst->uid = bpf_get_socket_uid(skb);
        rst->packets += 1;
        rst->bytes += skb->len;
    }
    return 0;
}
```

该程序包括一个BPF程序`iptables_accepted`，使用 `socket` 前缀。

### 2.2 用户程序

用户程序源码参见[iptables_test.c](../src/iptables_test.c)，主要内容如下：

#### 1 附加/分离BPF程序

```C
int main(int argc, char **argv)
{
    // 命令行选项设置
    int opt;
    bool cfg_test_traffic = false;
    bool cfg_test_cookie = false;
    while ((opt = getopt(argc, argv, "ts")) != -1) { ... }

    // 设置libbpf调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);
    // 打开并加载BPF程序
    skel = iptables_test_bpf__open_and_load();
    // 获取`cookie_stats` map_fd
    map_fd = bpf_map__fd(skel->maps.cookie_stats);
    // 附加BPF程序到iptables规则中
    prog_attach_iptables();
    if (cfg_test_traffic)
    {
        if (signal(SIGINT, finish) == SIG_ERR)
            error(1, errno, "register SIGINT handler failed");
        if (signal(SIGTERM, finish) == SIG_ERR)
            error(1, errno, "register SIGTERM handler failed");
        while (!test_finish)
        {
            print_table();
            printf("\n");
            sleep(1);
        }
    }
    else if (cfg_test_cookie)
    {
        udp_client();
    }

cleanup:
    // 从iptables规则中删除BPF程序
    prog_detach_iptables();
    // 销毁BPF程序
    iptables_test_bpf__destroy(skel);
    return -err;
}
```

`prog_attach_iptables` 函数附加BPF程序到iptables规则中，实现如下：

```C
static void prog_attach_iptables()
{
    char rules[256];
    char template[] = "/tmp/bpf.XXXXXX";
    // 创建临时目录
    char *temp_ = mkdtemp(template);
    if (temp_ == NULL) { ... }
    snprintf(temp_dir, sizeof(temp_dir), "%s", temp_);
    // 挂载BPF文件系统
    ret = mount(temp_dir, temp_dir, "bpf", 0, NULL);
    if (ret) { ... }
    // pin BPF程序
    snprintf(file, sizeof(file), "%s/bpf_prog", temp_dir);
    if (bpf_program__pin(skel->progs.iptables_accepted, file)) { ... }
    // 生成iptables命令后，执行该命令
    ret = snprintf(rules, sizeof(rules),
                   "iptables -A OUTPUT -m bpf --object-pinned %s -j ACCEPT", file);
    if (ret < 0 || ret >= sizeof(rules)) { ... }
    ret = system(rules);
    if (ret < 0) { ... }
}
```

`prog_detach_iptables` 函数从iptables规则中删除BPF程序，实现如下：

```C
static void prog_detach_iptables()
{
    int ret;
    char rules[256];
    // 生成iptables命令后，执行该命令
    ret = snprintf(rules, sizeof(rules),
                   "iptables -D OUTPUT -m bpf --object-pinned %s -j ACCEPT", file);
    if (ret < 0 || ret >= sizeof(rules)) { ... }
    ret = system(rules);
    if (ret < 0) { ... }
    // unpin BPF程序
    ret = bpf_program__unpin(skel->progs.iptables_accepted, file);
    if (ret) { ... }
    // 卸载挂载的目录
    ret = umount(temp_dir);
    if (ret) { ... }
    // 删除临时目录
    ret = rmdir(temp_dir);
    if (ret) { ... }
}
```

#### 2 读取数据过程

用户空间程序默认使用`-t`选项测试网络流量，每秒调用`print_table`函数从`skel->maps.cookie_stats`从读取采样结果显示。如下：

```C
static void print_table(void)
{
    struct stats curEntry;
    uint32_t curN = UINT32_MAX;
    uint32_t nextN;
    int res;

    while (bpf_map_get_next_key(map_fd, &curN, &nextN) > -1)
    {
        curN = nextN;
        res = bpf_map_lookup_elem(map_fd, &curN, &curEntry);
        if (res < 0)
            error(1, errno, "fail to get entry value of Key: %u\n", curN);
        else
            printf("cookie: %u, uid: 0x%x, Packet Count: %lu, Bytes Count: %lu\n",
                   curN, curEntry.uid, curEntry.packets, curEntry.bytes);
    }
}
```

### 2.3 编译运行

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make iptables_test
$ sudo ./iptables_test 
libbpf: loading object 'iptables_test_bpf' from buffer
...
libbpf: prog 'iptables_accepted': pinned at '/tmp/bpf.iyq4MA/bpf_prog'

cookie: 64, uid: 0x3e8, Packet Count: 1, Bytes Count: 73
cookie: 63, uid: 0x3e8, Packet Count: 2, Bytes Count: 125
cookie: 62, uid: 0x3e8, Packet Count: 3, Bytes Count: 232
cookie: 16467, uid: 0x0, Packet Count: 1, Bytes Count: 52
cookie: 8239, uid: 0x0, Packet Count: 4, Bytes Count: 456
cookie: 61, uid: 0x3e8, Packet Count: 4, Bytes Count: 235
....
```

## 3 iptables附加/卸载BPF的过程

iptables支持`BPF_PROG_TYPE_SOCKET_FILTER`类型的BPF程序，通过BPF指令或者`pinned`方式附加。附加指令如下：

```bash
# 挂载bpf文件系统
mount -t bpf bpf ${BPF_MOUNT}
# iptables的filter表中插入规则
iptables -A OUTPUT -m bpf --object-pinned ${BPF_MOUNT}/{PINNED_PATH} -j ACCEPT
```

在程序执行完成后，同样使用`iptables`命令删除附加的BPF程序，如下：

```bash
# iptables的filter表中删除规则
iptables -D OUTPUT -m bpf --object-pinned ${BPF_MOUNT}/{PINNED_PATH} -j ACCEPT
# 卸载bpf目录
umount ${BPF_MOUNT}
```

### 3.1 iptables内部实现介绍

iptables同时支持IPV4和IPV6协议，在内部通过`libiptc`库实现的，`libiptc`库用来显查询、修改、添加和删除netfilter的规则和策略。`iptables-v4`和`iptables-v6`通过宏定义方式使用`libiptc`库。

#### (1) `iptables-v4`的宏定义

头文件定义如下：

```C
// file: include/libiptc/libiptc.h
...
struct xtc_handle *iptc_init(const char *tablename);
...
int iptc_append_entry(const xt_chainlabel chain, const struct ipt_entry *e, struct xtc_handle *handle);
int iptc_check_entry(const xt_chainlabel chain, const struct ipt_entry *origfw,
            unsigned char *matchmask, struct xtc_handle *handle);
int iptc_delete_entry(const xt_chainlabel chain, const struct ipt_entry *origfw,
            unsigned char *matchmask, struct xtc_handle *handle);
...
int iptc_commit(struct xtc_handle *handle);
```

源文件定义如下：

```C
// file: libiptc/libip4tc.c
#define STRUCT_COUNTERS_INFO    struct xt_counters_info
#define STRUCT_STANDARD_TARGET  struct xt_standard_target
#define STRUCT_REPLACE  struct ipt_replace
...
#define TC_APPEND_ENTRY     iptc_append_entry
#define TC_CHECK_ENTRY      iptc_check_entry
#define TC_DELETE_ENTRY     iptc_delete_entry
...
#define TC_INIT         iptc_init
#define TC_FREE         iptc_free
#define TC_COMMIT       iptc_commit
...
#define TC_AF           AF_INET
#define TC_IPPROTO      IPPROTO_IP
#define SO_SET_REPLACE      IPT_SO_SET_REPLACE
#define SO_SET_ADD_COUNTERS IPT_SO_SET_ADD_COUNTERS
#define SO_GET_INFO         IPT_SO_GET_INFO
#define SO_GET_ENTRIES      IPT_SO_GET_ENTRIES
#define SO_GET_VERSION      IPT_SO_GET_VERSION
...
#include "libiptc.c"
...
```

#### (2) `iptables-v6`的宏定义

头文件定义如下：

```C
// file: include/libiptc/libip6tc.h
...
struct xtc_handle *ip6tc_init(const char *tablename);
...
int ip6tc_append_entry(const xt_chainlabel chain, const struct ip6t_entry *e, struct xtc_handle *handle);
int ip6tc_check_entry(const xt_chainlabel chain, const struct ip6t_entry *origfw,
            unsigned char *matchmask, struct xtc_handle *handle);
int ip6tc_delete_entry(const xt_chainlabel chain, const struct ip6t_entry *origfw,
            unsigned char *matchmask, struct xtc_handle *handle);
...
int ip6tc_commit(struct xtc_handle *handle);
```

源文件定义如下：

```C
// file: libiptc/libip6tc.c
#define STRUCT_COUNTERS_INFO    struct xt_counters_info
#define STRUCT_STANDARD_TARGET  struct xt_standard_target
#define STRUCT_REPLACE          struct ip6t_replace
...
#define TC_APPEND_ENTRY     ip6tc_append_entry
#define TC_CHECK_ENTRY      ip6tc_check_entry
#define TC_DELETE_ENTRY     ip6tc_delete_entry
...
#define TC_INIT         ip6tc_init
#define TC_FREE         ip6tc_free
#define TC_COMMIT       ip6tc_commit
...
#define TC_AF           AF_INET6
#define TC_IPPROTO      IPPROTO_IPV6
#define SO_SET_REPLACE      IP6T_SO_SET_REPLACE
#define SO_SET_ADD_COUNTERS IP6T_SO_SET_ADD_COUNTERS
#define SO_GET_INFO         IP6T_SO_GET_INFO
#define SO_GET_ENTRIES      IP6T_SO_GET_ENTRIES
#define SO_GET_VERSION      IP6T_SO_GET_VERSION
...
#include "libiptc.c"
...
```

#### (3) `libiptc`的宏展开

`libiptc.c`文件是`iptables`的核心功能实现，通过宏展开后实现iptables的函数功能，如下：

```C
// file: libiptc/libiptc.c
struct xtc_handle {
    int sockfd;
    int changed;  /* Have changes been made? */
    // 链信息
    struct list_head chains;

    struct chain_head *chain_iterator_cur;
    struct rule_head *rule_iterator_cur;
    // 用户定义的链数量
    unsigned int num_chains;

    struct chain_head **chain_index; 
    // chain_index的数量
    unsigned int        chain_index_sz;

    int sorted_offsets;
    // 从内核中获取的规则信息 
    STRUCT_GETINFO info;
    STRUCT_GET_ENTRIES *entries;
};
...
int TC_APPEND_ENTRY(const IPT_CHAINLABEL chain, const STRUCT_ENTRY *e, struct xtc_handle *handle) { ... }
int TC_CHECK_ENTRY(const IPT_CHAINLABEL chain, const STRUCT_ENTRY *origfw,
                    unsigned char *matchmask, struct xtc_handle *handle) { ... }
int TC_DELETE_ENTRY(const IPT_CHAINLABEL chain,	const STRUCT_ENTRY *origfw,
                    unsigned char *matchmask, struct xtc_handle *handle) { ... }
...
struct xtc_handle * TC_INIT(const char *tablename) { ... }
int TC_COMMIT(struct xtc_handle *handle) {... }
...
```

### 3.2 `iptables`的实现过程

`iptables`在netfilter框架中入口点为`iptables_main`，实现如下：

```C
// file: iptables/iptables-standalone.c
int iptables_main(int argc, char *argv[])
{
    int ret;
    // 默认使用`filter`表
    char *table = "filter";
    struct xtc_handle *handle = NULL;

    iptables_globals.program_name = "iptables";
    // 初始化ipv4 iptables框架
    ret = xtables_init_all(&iptables_globals, NFPROTO_IPV4);
    if (ret < 0) { ... }
    // 初始化通用扩展程序和ipv4专用扩展程序
    init_extensions();
    init_extensions4();
    // 执行命令行参数
    ret = do_command4(argc, argv, &table, &handle, false);
    if (ret) {
        // 提交`xtc_handle`将修改内容提交到内核中
        ret = iptc_commit(handle);
        // 释放`xtc_handle`
        iptc_free(handle);
    }
    // xtables清理过程
    xtables_fini();

    if (!ret) { ... }
    exit(!ret);
}
```

#### (1) 初始化过程

`xtables_init_all`函数初始化xtables框架，`xtables_set_nfproto`设置协议的操作接口，`xtables_set_params`设置全局参数，如下：

```C
// file: libxtables/xtables.c
int xtables_init_all(struct xtables_globals *xtp, uint8_t nfproto)
{
    // 全局初始化，初始化`xtables_libdir`目录，确定Xtable so文件的查找目录
    xtables_init();
    // 设置协议操作接口
    xtables_set_nfproto(nfproto);
    // 设置xtables使用的全局参数
    return xtables_set_params(xtp);
}
```

`xtables_set_nfproto` 函数根据协议设置操作接口，如下：

```C
// file: libxtables/xtables.c
void xtables_set_nfproto(uint8_t nfproto)
{
    switch (nfproto) {
    case NFPROTO_IPV4: afinfo = &afinfo_ipv4; break;
    case NFPROTO_IPV6: afinfo = &afinfo_ipv6; break;
    case NFPROTO_BRIDGE: afinfo = &afinfo_bridge; break;
    case NFPROTO_ARP: afinfo = &afinfo_arp; break;
    default: fprintf(stderr, ...);
    }
}
```

`NFPROTO_IPV4`对应`afinfo_ipv4`，定义如下：

```C
// file: libxtables/xtables.c
static const struct xtables_afinfo afinfo_ipv4 = {
    .kmod          = "ip_tables",
    .proc_exists   = "/proc/net/ip_tables_names",
    .libprefix     = "libipt_",
    .family        = NFPROTO_IPV4,
    .ipproto       = IPPROTO_IP,
    .so_rev_match  = IPT_SO_GET_REVISION_MATCH,
    .so_rev_target = IPT_SO_GET_REVISION_TARGET,
};
```

#### (2) 命令行参数解析

`do_command4` 函数是整个系统的核心，负责解析用户输入的参数后调用相应的处理函数，如下：

```C
// file: iptables/iptables.c
int do_command4(int argc, char *argv[], char **table, struct xtc_handle **handle, bool restore)
{
    // 解析ipv4协议
    struct xt_cmd_parse_ops cmd_parse_ops = {
        .proto_parse    = ipv4_proto_parse,
        .post_parse     = ipv4_post_parse,
    };
    // xt命令解析设置
    struct xt_cmd_parse p = {
        .table      = *table,
        .restore    = restore,
        .line       = line,
        .ops        = &cmd_parse_ops,
    };
    // iptables解析状态
    struct iptables_command_state cs = {
        .jumpto = "",
        .argv   = argv,
    };
    // xtables解析的参数
    struct xtables_args args = {
        .family = AF_INET,
    };
    struct ipt_entry *e = NULL;
    ...
    // 解析用户输入的参数
    do_parse(argc, argv, &p, &cs, &args);
    // 解析的参数设置
    command     = p.command;
    chain       = p.chain;
    *table      = p.table;
    rulenum     = p.rulenum;
    policy      = p.policy;
    newname     = p.newname;
    verbose     = p.verbose;
    wait        = args.wait;
    ...
    // 尝试获取xtables锁，检查`env:XTABLES_LOCKFILE`文件是否能够打开
    if (!restore) xtables_lock_or_exit(wait);
    // handle不存在时，初始化
    if (!*handle) *handle = iptc_init(*table);
    // handle不存在时，尝试加载iptables模块后，再次初始化
    if (!*handle && xtables_load_ko(xtables_modprobe_program, false) != -1)
        *handle = iptc_init(*table);
    
    // 附加、删除、检查、插入、替换指令时，获取防火墙规则
    if (command == CMD_APPEND || command == CMD_DELETE || 
        command == CMD_CHECK || command == CMD_INSERT || command == CMD_REPLACE) {
        // target存在时，chain存在时，释放target
        if (cs.target && iptc_is_chain(cs.jumpto, *handle)) { 
            if (cs.target->t) free(cs.target->t);
            cs.target = NULL;
         }
        // 未指定target或者指定的target是chain时，使用标准的target
        if (!cs.target && (strlen(cs.jumpto) == 0 || iptc_is_chain(cs.jumpto, *handle))) {
            // 获取标准的target
            cs.target = xtables_find_target(XT_STANDARD_TARGET, XTF_LOAD_MUST_SUCCEED);
            // target属性设置
            size = sizeof(struct xt_entry_target) + cs.target->size;
            cs.target->t = xtables_calloc(1, size);
            cs.target->t->u.target_size = size;
            strcpy(cs.target->t->u.user.name, cs.jumpto);
            if (!iptc_is_chain(cs.jumpto, *handle)) 
                cs.target->t->u.user.revision = cs.target->revision;
            // 初始化target
            xs_init_target(cs.target);
        }

        if (!cs.target) {
            // 获取指定的target
            xtables_find_target(cs.jumpto, XTF_LOAD_MUST_SUCCEED);
        } else {
            // 生成防火墙规则
            e = generate_entry(&cs.fw, cs.matches, cs.target->t);
        } 
    }
    // 执行命令
    switch (command) {
    case CMD_APPEND:
        ret = append_entry(chain, e, nsaddrs, saddrs, smasks, ndaddrs, daddrs, dmasks, 
                cs.options&OPT_VERBOSE, *handle);
        break;
    case CMD_DELETE:
        ret = delete_entry(chain, e, nsaddrs, saddrs, smasks, ndaddrs, daddrs, dmasks,
                cs.options&OPT_VERBOSE, *handle, cs.matches, cs.target);
        break;
    ...
    }
    if (verbose > 1) dump_entries(*handle);

    // 清理iptables状态信息，释放match和target
    xtables_clear_iptables_command_state(&cs);
    // 释放申请的内容
    if (e != NULL) { free(e); e = NULL; }
    free(saddrs);
    free(smasks);
    free(daddrs);
    free(dmasks);
    xtables_free_opts(1);
    return ret;
}
```

`do_parse` 函数解析用户输入的命令行参数信息，如下：

```C
// file: iptables/xshared.c
void do_parse(int argc, char *argv[], struct xt_cmd_parse *p, 
        struct iptables_command_state *cs, struct xtables_args *args)
{
    struct xtables_match *m;
    struct xtables_rule_match *matchp;
    bool wait_interval_set = false;
    struct xtables_target *t;
    bool table_set = false;
    bool invert = false;

    // 重置`optind`为0，支持`do_command4`再次调用
    optind = 0;
    // 清除matches和targets状态，支持`do_command4`再次调用
    for (m = xtables_matches; m; m = m->next)
        m->mflags = 0;
    for (t = xtables_targets; t; t = t->next) {
        t->tflags = 0; 
        t->used = 0;
    }
    // 抑制错误信息
    opterr = 0;

    xt_params->opts = xt_params->orig_opts;
    // 解析命令行参数
    while ((cs->c = getopt_long(argc, argv, optstring_lookup(afinfo->family), 
                        xt_params->opts, NULL)) != -1) {
        // 命令状态
        switch (cs->c) { 
        case 'A':
            add_command(&p->command, CMD_APPEND, CMD_NONE, invert);
            p->chain = optarg;
            break;
        case 'C':
            add_command(&p->command, CMD_CHECK, CMD_NONE, invert);
            p->chain = optarg;
            break;
        case 'D':
            add_command(&p->command, CMD_DELETE, CMD_NONE, invert);
            p->chain = optarg;
            if (xs_has_arg(argc, argv)) {
                p->rulenum = parse_rulenumber(argv[optind++]);
                p->command = CMD_DELETE_NUM;
            }
            break;
            ...
        case 'j':
            set_option(&cs->options, OPT_JUMP, &args->invflags, invert);
            command_jump(cs, argv[optind - 1]);
            break;
        case 'm':
            command_match(cs, invert);
            break;
        ...
        default:
            if (command_default(cs, xt_params, invert))
                continue;
            break;
        }
        invert = false;
    }
    ...
    // NAT设置检查、`wait`和`wait-interval`匹配性检查
    if (strcmp(p->table, "nat") == 0 &&
        ((p->policy != NULL && strcmp(p->policy, "DROP") == 0) ||
        (cs->jumpto != NULL && strcmp(cs->jumpto, "DROP") == 0)))
        xtables_error(PARAMETER_PROBLEM, ...);
    if (!args->wait && wait_interval_set) xtables_error(PARAMETER_PROBLEM, ...);
    
    // match和target最终检查
    for (matchp = cs->matches; matchp; matchp = matchp->next)
        xtables_option_mfcall(matchp->match);
    if (cs->target != NULL)
        xtables_option_tfcall(cs->target);
    // 命令行参数解析完成后的解析接口
    if (p->ops->post_parse)
        p->ops->post_parse(p->command, cs, args);
    // 通用选项检查
    generic_opt_check(p->command, cs->options);

    // chain长度检查
    if (p->chain != NULL && strlen(p->chain) >= XT_EXTENSION_MAXNAMELEN)
        xtables_error(PARAMETER_PROBLEM, ...);
    // 指令和链匹配性检查
    if (p->command == CMD_APPEND || p->command == CMD_DELETE || p->command == CMD_DELETE_NUM ||
        p->command == CMD_CHECK || p->command == CMD_INSERT || p->command == CMD_REPLACE) {
        if (strcmp(p->chain, "PREROUTING") == 0 || strcmp(p->chain, "INPUT") == 0) {
            // 进入路径(incoming)的网络网络数据不支持`-o`选项设置
            if (cs->options & OPT_VIANAMEOUT) xtables_error(PARAMETER_PROBLEM, ...);
        }
        if (strcmp(p->chain, "POSTROUTING") == 0 || strcmp(p->chain, "OUTPUT") == 0) {
            // 发送路径(outgoing)的网络数据包不支持`-i`选项设置
            if (cs->options & OPT_VIANAMEIN) xtables_error(PARAMETER_PROBLEM, ...);
        }
    }
}
```

#### (3) `-m`参数的解析

##### 1 `-m`解析实现过程

`-m`或者`--match`参数指定使用的匹配项，匹配项的集合构成了调用目标的条件。匹配按照命令行执行的方式从前到后进行评估、并以短路的方式工作，即：一个匹配项的评估结果为false时，后续的匹配项将不再进行评估。

`iptables`支持多种方式的匹配规则，如：`bpf`,`cgroup`,`cluster`,`comment`,`connbytes`等，具体可参考[iptables-extensions(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)。

`command_match`函数实现了`-m`参数的解析，具体实现如下：

```C
// file: iptables/xshared.c
static void command_match(struct iptables_command_state *cs, bool invert)
{
    struct option *opts = xt_params->opts;
    struct xtables_match *m;
    size_t size;

    // `-m`不支持`!`标记
    if (invert) xtables_error(PARAMETER_PROBLEM, "unexpected ! flag before --match");
    // 获取`match`
    m = xtables_find_match(optarg, XTF_LOAD_MUST_SUCCEED, &cs->matches);
    // 创建`match_entry`
    size = XT_ALIGN(sizeof(struct xt_entry_match)) + m->size;
    m->m = xtables_calloc(1, size);
    m->m->u.match_size = size;
    // 用户空间名称设置
    if (m->real_name == NULL) {
        strcpy(m->m->u.user.name, m->name);
    } else {
        strcpy(m->m->u.user.name, m->real_name);
        // 别名转换
        if (!(m->ext_flags & XTABLES_EXT_ALIAS)) ...
    }
    m->m->u.user.revision = m->revision;
    // 初始化match
    xs_init_match(m);
    // 复制的match时，不进行后续操作
    if (m == m->next) return;
    // 非复制match时，合并命令行选项
    if (m->x6_options != NULL)
        opts = xtables_options_xfrm(xt_params->orig_opts, opts, m->x6_options, &m->option_offset);
    else if (m->extra_opts != NULL)
        opts = xtables_merge_options(xt_params->orig_opts, opts, m->extra_opts, &m->option_offset);
    if (opts == NULL) xtables_error(OTHER_PROBLEM, "can't alloc memory!");
    xt_params->opts = opts;
}
```

`xtables_find_match` 函数根据名称获取match，获取成功时添加到`cs->matches`规则列表中，如下：

```C
// file: iptables/xshared.c
struct xtables_match * xtables_find_match(const char *name, enum xtables_tryload tryload,
            struct xtables_rule_match **matches)
{
    const char *icmp6 = "icmp6";
    ...
    // match名称长度检查
    if (strlen(name) >= XT_EXTENSION_MAXNAMELEN) xtables_error(PARAMETER_PROBLEM, ...);
    // icmpv6名称转换
    if ( (strcmp(name,"icmpv6") == 0) || (strcmp(name,"ipv6-icmp") == 0) || (strcmp(name,"icmp6") == 0) )
        name = icmp6;

    // 触发延时初始化，检查匹配性后添加到`xtables_matches`列表中
    for (dptr = &xtables_pending_matches; *dptr; ) { 
        if (extension_cmp(name, (*dptr)->name, (*dptr)->family)) {
            ptr = *dptr;
            *dptr = (*dptr)->next;
            seen = true;
            // 初始化match，期间通过`SO_GET_REVISION_MATCH`获取支持的版本信息
            if (!found && xtables_fully_register_pending_match(ptr, prev)) {
                found = true;
                prev = ptr;
                continue;
            } else if (prev) {
                continue;
            }
            *dptr = ptr;
        }
        dptr = &((*dptr)->next);
     }
    // 存在对应的match，但加载失败时，进行提示
    if (seen && !found) fprintf(stderr, ...);

    // 遍历以加载的match，查找或复制match
    for (ptr = xtables_matches; ptr; ptr = ptr->next) {
        if (extension_cmp(name, ptr->name, ptr->family)) {
            struct xtables_match *clone;
            // 初次使用
            if (ptr->m == NULL) break;
            // 第二次及后续使用时，复制match
            clone = xtables_malloc(sizeof(struct xtables_match));
            memcpy(clone, ptr, sizeof(struct xtables_match));
            clone->udata = NULL;
            clone->mflags = 0;
            // 表示是个复制
            clone->next = clone;

            ptr = clone;
            break;
        }
    }
    ...
    // 创建匹配规则添加到规则列表中
    if (ptr && matches) {
        struct xtables_rule_match **i;
        struct xtables_rule_match *newentry;
        // 创建匹配规则
        newentry = xtables_malloc(sizeof(struct xtables_rule_match));
        // 检查是否存在同样的匹配规则
        for (i = matches; *i; i = &(*i)->next) {
            if (extension_cmp(name, (*i)->match->name, (*i)->match->family))
                (*i)->completed = true;
        }
        newentry->match = ptr;
        newentry->completed = false;
        newentry->next = NULL;
        *i = newentry;
    }
    return ptr;
}
```

`xs_init_match` 函数初始化匹配规则，分配的用户数据区域后，调用匹配规则初始化接口，如下：

```C
// file: iptables/xshared.c
void xs_init_match(struct xtables_match *match)
{
    // 重新分配匹配规则的内存区域
    if (match->udata_size != 0) {
        free(match->udata);
        match->udata = xtables_calloc(1, match->udata_size);
    }
    // 匹配规则初始化接口
    if (match->init != NULL)
        match->init(match->m);
}
```

`command_default`函数中实现`target`和`match`命令行参数的解析，如下：

```C
// file: iptables/xshared.c
static int command_default(struct iptables_command_state *cs,
            struct xtables_globals *gl, bool invert)
{
    struct xtables_rule_match *matchp;
    struct xtables_match *m;

    // 解析target命令行参数
    if (cs->target != NULL &&
        (cs->target->parse != NULL || cs->target->x6_parse != NULL) &&
        cs->c >= cs->target->option_offset &&
        cs->c < cs->target->option_offset + XT_OPTION_OFFSET_SCALE) {
        xtables_option_tpcall(cs->c, cs->argv, invert, cs->target, &cs->fw);
        return 0;
    }
    // 遍历匹配规则链表，解析匹配规则的命令行参数
    for (matchp = cs->matches; matchp; matchp = matchp->next) {
        m = matchp->match;

        if (matchp->completed || (m->x6_parse == NULL && m->parse == NULL))
            continue;
        if (cs->c < matchp->match->option_offset ||
            cs->c >= matchp->match->option_offset + XT_OPTION_OFFSET_SCALE)
            continue;
        xtables_option_mpcall(cs->c, cs->argv, invert, m, &cs->fw);
        return 0;
    }

    // 尝试加载协议匹配规则，加载成功时创建新的匹配规则
    m = load_proto(cs);
    if (m != NULL) {
        // 创建匹配规则
        ...
    }
    // 命令行参数不匹配时，提示错误信息
    if (cs->c == ':') xtables_error(PARAMETER_PROBLEM, ...);
    if (cs->c == '?') xtables_error(PARAMETER_PROBLEM, ...);
    xtables_error(PARAMETER_PROBLEM, ...);
}
```

`xtables_option_mpcall`函数实现match的命令行参数解析，如下：

```C
// file: libxtables/xtoptions.c
void xtables_option_mpcall(unsigned int c, char **argv, bool invert, struct xtables_match *m, void *fw)
{
    struct xt_option_call cb;
    //`x6_parse`接口不存在时，调用`parse`接口
    if (m->x6_parse == NULL) {
        if (m->parse != NULL)
            m->parse(c - m->option_offset, argv, invert, &m->mflags, fw, &m->m);
        return;
    }
    // 获取`options`选项
    c -= m->option_offset;
    cb.entry = xtables_option_lookup(m->x6_options, c);
    if (cb.entry == NULL) xtables_error(OTHER_PROBLEM, ...);
    // 设置选项属性
    cb.arg      = optarg;
    cb.invert   = invert;
    cb.ext_name = m->name;
    cb.data     = m->m->data;
    cb.xflags   = m->mflags;
    cb.match    = &m->m;
    cb.xt_entry = fw;
    cb.udata    = m->udata;
    // 调用`x6_parse`接口
    m->x6_parse(&cb);
    m->mflags = cb.xflags;
}
```

##### 2 `bpf`匹配规则的解析

iptables支持`bpf`参数，用于指定一个`BPF`程序来匹配数据包。在`iptables`中，bpf支持两个版本的匹配规则，定义如下：

```C
// file: extensions/libxt_bpf.c
static struct xtables_match bpf_matches[] = {
    ...
    {
        .family     = NFPROTO_UNSPEC,
        .name       = "bpf",
        .version    = XTABLES_VERSION,
        .revision   = 1,
        .size       = XT_ALIGN(sizeof(struct xt_bpf_info_v1)),
        .userspacesize  = XT_ALIGN(offsetof(struct xt_bpf_info_v1,filter)),
        .help       = bpf_help_v1,
        .print      = bpf_print_v1,
        .save       = bpf_save_v1,
        .x6_parse   = bpf_parse_v1,
        .x6_fcheck  = bpf_fcheck_v1,
        .x6_options = bpf_opts_v1,
    },
};
```

在`_init`函数中进行注册的，如下：

```C
// file: extensions/libxt_bpf.c
void _init(void)
{
    xtables_register_matches(bpf_matches, ARRAY_SIZE(bpf_matches));
}
```

`xt_bpf`的v1版本兼用v0版本，下面以v1版进行说明。v1版本执行两种方式设置bpf程序，`--bytecode code`通过`nfbpf_compile`工具生成bpf字节码方式设置，`--object-pinned path`通过PINED bpf程序方式设置。

`.x6_parse`接口在解析命令行参数时调用，设置为`bpf_parse_v1`，实现如下：

```C
// file: extensions/libxt_bpf.c
static void bpf_parse_v1(struct xt_option_call *cb)
{
    struct xt_bpf_info_v1 *bi = (void *) cb->data;

    xtables_option_parse(cb);
    switch (cb->entry->id) {
    case O_BCODE_STDIN:
        // bpf字节码方式
        bpf_parse_string(bi->bpf_program, &bi->bpf_program_num_elem,
                ARRAY_SIZE(bi->bpf_program), cb->arg);
        bi->mode = XT_BPF_MODE_BYTECODE;
        break;
    case O_OBJ_PINNED:
        // PINED bpf方式
        bpf_parse_obj_pinned(bi, cb->arg);
        bi->mode = XT_BPF_MODE_FD_PINNED;
        break;
    default:
        xtables_error(PARAMETER_PROBLEM, "bpf: unknown option");
    }
}
```

`bpf_parse_string`函数实现bpf字节码方式设置，最多支持64条指令。编码格式类似于代码格式类似于`tcpdump -ddd`的输出命令：第一行存储指令数，第二行开始每条指令存储一行。每条指令遵循"U16 U8 U8 U32"格式，每行指令间以`,`分割。实现如下：

```C
// file: extensions/libxt_bpf.c
static void bpf_parse_string(struct sock_filter *pc, __u16 *lenp, __u16 len_max, const char *bpf_program)
{
    const char separator = ',';
    ...

    // 解析指令长度
    if (sscanf(bpf_program, "%hu%c", &len, &sp) != 2 || sp != separator)
        xtables_error(PARAMETER_PROBLEM, ...);
    // 指令长度未设置或超过长度时，记录错误信息
    if (!len) xtables_error(PARAMETER_PROBLEM, ...);
    if (len > len_max) xtables_error(PARAMETER_PROBLEM, ...);

    // 解析指令内容
    i = 0;
    token = bpf_program;
    while ((token = strchr(token, separator)) && (++token)[0]) {
        if (i >= len) xtables_error(PARAMETER_PROBLEM, ...);
        // 解析单条指令
        if (sscanf(token, "%hu %hhu %hhu %u,", &pc->code, &pc->jt, &pc->jf, &pc->k) != 4)
            xtables_error(PARAMETER_PROBLEM, "bpf: error at instr %d", i);
        i++;
        pc++;
    }
    // 长度不正确时，记录错误信息
    if (i != len) xtables_error(PARAMETER_PROBLEM, ...);
    // 设置指令数量
    *lenp = len;
}
```

`bpf_parse_obj_pinned`函数实现pined BPF程序的解析，如下：

```C
// file: extensions/libxt_bpf.c
static void bpf_parse_obj_pinned(struct xt_bpf_info_v1 *bi, const char *filepath)
{
    // 通过`BPF:BPF_OBJ_GET`系统调用获取bpf_fd
    bi->fd = bpf_obj_get_readonly(filepath);
    if (bi->fd < 0) xtables_error(PARAMETER_PROBLEM, ...);

    // 设置bpf程序关闭方式，不能通过`close`显式关闭，在程序退出时自动关闭
    if (fcntl(bi->fd, F_SETFD, FD_CLOEXEC) == -1) {
        xtables_error(OTHER_PROBLEM, ...);
    }
}
```

#### (4) `-j`参数的解析

##### 1 `-j`解析实现过程

`-j`或者`--jump`参数指定了规则的目标，即：匹配的数据包将怎么办。目标可以是用户自定义的链，或者Linux内核内置的或扩展的目标。

`iptables`支持多种方式的目标，如：`ACCEPT`,`DROP`,`QUEUE`,`RETURN`,`SNAT`,`DNAT`,`MASQUERADE`,`REDIRECT`等。但一条记录只能有一个目标，即：`-j`参数只能出现一次。

`command_jump`函数实现`-j`参数的解析，如下：

```C
// file: iptables/xshared.c
void command_jump(struct iptables_command_state *cs, const char *jumpto)
{
    struct option *opts = xt_params->opts;
    size_t size;

    // 检查`jumpto`参数，确保长度在支持的范围内，中间不能包含空格
    cs->jumpto = xt_parse_target(jumpto);
    // 获取target，获取方式和`match`相同，通过延时加载target后获取
    cs->target = xtables_find_target(cs->jumpto, XTF_TRY_LOAD);
    // target不存在时返回
    if (cs->target == NULL) return;

    // 创建`target_entry`
    size = XT_ALIGN(sizeof(struct xt_entry_target)) + cs->target->size;
    cs->target->t = xtables_calloc(1, size);
    cs->target->t->u.target_size = size;
    // target名称设置
    if (cs->target->real_name == NULL) {
        strcpy(cs->target->t->u.user.name, cs->jumpto);
    } else {
        strcpy(cs->target->t->u.user.name, cs->target->real_name);
        if (!(cs->target->ext_flags & XTABLES_EXT_ALIAS)) ...
    }
    cs->target->t->u.user.revision = cs->target->revision;
    // 初始化target
    xs_init_target(cs->target);
    // target命令行选项设置
    if (cs->target->x6_options != NULL)
        opts = xtables_options_xfrm(xt_params->orig_opts, opts, cs->target->x6_options,
                        &cs->target->option_offset);
    else
        opts = xtables_merge_options(xt_params->orig_opts, opts, cs->target->extra_opts,
                        &cs->target->option_offset);
    if (opts == NULL) xtables_error(OTHER_PROBLEM, "can't alloc memory!");
    xt_params->opts = opts;
}
```

`xtables_find_target` 函数通过名称确定匹配目标，实现如下：

```C
// file: libxtables/xtables.c
struct xtables_target *xtables_find_target(const char *name, enum xtables_tryload tryload)
{
    struct xtables_target *prev = NULL;
    struct xtables_target **dptr;
    struct xtables_target *ptr;
    bool found = false;
    bool seen = false;

    // ACCEPT、DROP、QUEUE、RETURN是标准目标
    if (strcmp(name, "") == 0 || 
        strcmp(name, XTC_LABEL_ACCEPT) == 0 || strcmp(name, XTC_LABEL_DROP) == 0 || 
        strcmp(name, XTC_LABEL_QUEUE) == 0 ||  strcmp(name, XTC_LABEL_RETURN) == 0)
        name = "standard";
    // 检查是否在`非目标`列表中存在
    else if (notargets_hlist_lookup(name) && tryload != XTF_LOAD_MUST_SUCCEED)
        return NULL;

    // 触发延时初始化
    for (dptr = &xtables_pending_targets; *dptr; ) {
        if (extension_cmp(name, (*dptr)->name, (*dptr)->family)) {
            ptr = *dptr;
            *dptr = (*dptr)->next;
            seen = true;
            // 注册target，期间通过`SO_GET_REVISION_TARGET`获取支持的版本信息
            if (!found && xtables_fully_register_pending_target(ptr, prev)) {
                found = true;
                prev = ptr;
                continue;
            } else if (prev) {
                continue;
            }
            *dptr = ptr;
        }
        dptr = &((*dptr)->next);
    }
    // 存在对应的target，但加载失败时，提示
    if (seen && !found) fprintf(stderr, ...);

    for (ptr = xtables_targets; ptr; ptr = ptr->next) {
        if (extension_cmp(name, ptr->name, ptr->family)) {
            struct xtables_target *clone;
            // 第一次使用target时
            if (ptr->t == NULL) break;

            // 第二次及后续使用时，需要复制target
            clone = xtables_malloc(sizeof(struct xtables_target));
            memcpy(clone, ptr, sizeof(struct xtables_target));
            clone->udata = NULL;
            clone->tflags = 0;
            // 表示是复制的target
            clone->next = clone;
            ptr = clone;
            break;
        }
    }

#ifndef NO_SHARED_LIBS
    if (!ptr && tryload != XTF_DONT_LOAD && tryload != XTF_DURING_LOAD) {
        // 尝试已扩展的方式获取target
        ptr = load_extension(xtables_libdir, afinfo->libprefix, name, true);

        if (ptr == NULL && tryload == XTF_LOAD_MUST_SUCCEED)
            xt_params->exit_err(PARAMETER_PROBLEM, ...);
    }
#else
    if (ptr && !ptr->loaded) {
        // 加载target，检查加载标记
        if (tryload != XTF_DONT_LOAD) ptr->loaded = 1;
        else ptr = NULL;
    }
    if (ptr == NULL && tryload == XTF_LOAD_MUST_SUCCEED) {
        xt_params->exit_err(PARAMETER_PROBLEM, ...);
    }
#endif
    // target存在时，标记为使用状态；不存在时，添加到非目标(notarget)列表中
    if (ptr) 
        ptr->used = 1;
    else 
        notargets_hlist_insert(name);
    return ptr;
}
```

`xs_init_target` 函数初始化匹配目标，分配的用户数据区域后，调用目标初始化接口，如下：

```C
// file: iptables/xshared.c
void xs_init_target(struct xtables_target *target)
{
    // 重新分配目标的内存区域
    if (target->udata_size != 0) {
        free(target->udata);
        target->udata = xtables_calloc(1, target->udata_size);
    }
    // 目标初始化接口
    if (target->init != NULL)
        target->init(target->t);
}
```

和`match`类似，在`command_default`函数中调用`xtables_option_tpcall`函数实现target的命令行参数解析，如下：

```C
// file: libxtables/xtoptions.c
void xtables_option_tpcall(unsigned int c, char **argv, bool invert, struct xtables_target *t, void *fw)
{
    struct xt_option_call cb;
    //`x6_parse`接口不存在时，调用`parse`接口
    if (t->x6_parse == NULL) {
        if (t->parse != NULL)
            t->parse(c - t->option_offset, argv, invert, &t->tflags, fw, &t->t);
        return;
    }
    // 获取`options`选项
    c -= t->option_offset;
    cb.entry = xtables_option_lookup(t->x6_options, c);
    if (cb.entry == NULL) xtables_error(OTHER_PROBLEM, ...);
    // 设置选项属性
    cb.arg      = optarg;
    cb.invert   = invert;
    cb.ext_name = t->name;
    cb.data     = t->t->data;
    cb.xflags   = t->tflags;
    cb.target   = &t->t;
    cb.xt_entry = fw;
    cb.udata    = t->udata;
    // 调用`x6_parse`接口
    t->x6_parse(&cb);
    t->tflags = cb.xflags;
}
```

##### 2 `standard`目标的解析

`ACCEPT`、`DROP`、`QUEUE`、`RETURN`和空目标，都属于标准目标。在`iptables`中，定义如下：

```C
// file: extensions/libxt_standard.c
static struct xtables_target standard_target = {
    .family     = NFPROTO_UNSPEC,
    .name       = "standard",
    .version    = XTABLES_VERSION,
    .size       = XT_ALIGN(sizeof(int)),
    .userspacesize  = XT_ALIGN(sizeof(int)),
    .help       = standard_help,
};
```

在`_init`函数中注册，如下：

```C
// file: extensions/libxt_standard.c
void _init(void)
{
    xtables_register_target(&standard_target);
}
```

`standard`目标不需要设置额外的参数，因此不需要解析接口。

#### (5) 其他关键参数说明

##### 1 `-A`参数解析

`-A`或`--append`参数用于添加一条或多条防火墙规则到选择的chain中，Linux内核中默认支持`PREROUTING`,`INPUT`,`OUTPUT`,`FORWARD`和`POSTROUTING`五个链。

##### 2 `-D`参数解析

`-D`或`--delete`参数用于从选择的chain中删除一条或多条防火墙规则。

##### 3 `-t`参数解析

`-t`或`--table`参数指定操作`iptables`的表名，如`filter`、`nat`、`mangle`、`raw`和`security`。

#### (6) 生成防火墙规则

在`do_parse`函数解析命令行参数过程中，调用`p->ops->post_parse`接口进行解析后的处理，`iptables`设置的接口为`ipv4_post_parse`, 实现如下：

```C
// file: iptables/xshared.c
void ipv4_post_parse(int command, struct iptables_command_state *cs, struct xtables_args *args)
{
    // flags设置
    cs->fw.ip.flags = args->flags;
    cs->fw.ip.invflags = args->invflags;
    // 网卡设备输入接口设置
    memcpy(cs->fw.ip.iniface, args->iniface, IFNAMSIZ);
    memcpy(cs->fw.ip.iniface_mask, args->iniface_mask, IFNAMSIZ*sizeof(unsigned char));
    // 网卡设备输出接口设置
    memcpy(cs->fw.ip.outiface, args->outiface, IFNAMSIZ);
    memcpy(cs->fw.ip.outiface_mask, args->outiface_mask, IFNAMSIZ*sizeof(unsigned char));
    // 跳转设置
    if (args->goto_set)
        cs->fw.ip.flags |= IPT_F_GOTO;

    // 计数器设置
    cs->counters.pcnt = args->pcnt_cnt;
    cs->counters.bcnt = args->bcnt_cnt;
    cs->fw.counters.pcnt = args->pcnt_cnt;
    cs->fw.counters.bcnt = args->bcnt_cnt;
    // 替换、插入、删除、追加、检查时，源地址和目的地址检查，未设置时，使用零地址
    if (command & (CMD_REPLACE | CMD_INSERT | CMD_DELETE | CMD_APPEND | CMD_CHECK)) {
        if (!(cs->options & OPT_DESTINATION)) 
            args->dhostnetworkmask = "0.0.0.0/0";
        if (!(cs->options & OPT_SOURCE))
            args->shostnetworkmask = "0.0.0.0/0";
    }
    // 源地址和目的地址解析
    if (args->shostnetworkmask)
        xtables_ipparse_multiple(args->shostnetworkmask, 
                &args->s.addr.v4, &args->s.mask.v4, &args->s.naddrs);
    if (args->dhostnetworkmask)
        xtables_ipparse_multiple(args->dhostnetworkmask,
                &args->d.addr.v4, &args->d.mask.v4, &args->d.naddrs);
    // 地址和标记匹配性检查
    if ((args->s.naddrs > 1 || args->d.naddrs > 1) && 
        (cs->fw.ip.invflags & (IPT_INV_SRCIP | IPT_INV_DSTIP)))
        xtables_error(PARAMETER_PROBLEM, ...);
}
```

在解析命令行参数后，附加、删除、检查、插入、替换指令时，需要生成防火墙规则，`generate_entry`函数实现该功能，如下：

```C
// file: iptables/iptables.c
static struct ipt_entry * generate_entry(const struct ipt_entry *fw,
            struct xtables_rule_match *matches, struct xt_entry_target *target)
{
    unsigned int size;
    struct xtables_rule_match *matchp;
    struct ipt_entry *e;

    // ipv4防火墙结构体大小
    size = sizeof(struct ipt_entry);
    // 计数所有match占用空间
    for (matchp = matches; matchp; matchp = matchp->next)
        size += matchp->match->m->u.match_size;
    // 分配内存空间，包括target占用的空间
    e = xtables_malloc(size + target->u.target_size);
    // 复制防火墙结构
    *e = *fw;
    // 设置target的偏移量
    e->target_offset = size;
    // 设置next_offset，即防火墙规则的总体占用大小
    e->next_offset = size + target->u.target_size;

    size = 0;
    // 复制match结构体
    for (matchp = matches; matchp; matchp = matchp->next) {
        memcpy(e->elems + size, matchp->match->m, matchp->match->m->u.match_size);
        size += matchp->match->m->u.match_size;
    }
    // 复制target结构体
    memcpy(e->elems + size, target, target->u.target_size);
    return e;
}
```

#### (7) 初始化`xtc_handle`

`struct xtc_handle`保存iptables的配置信息，包括链表、表、规则、链、链的规则等，`TC_INIT`函数实现该功能，如下：

```C
// file: libiptc/libiptc.c
struct xtc_handle *TC_INIT(const char *tablename)
{
    struct xtc_handle *h;
    STRUCT_GETINFO info;
    unsigned int tmp;
    socklen_t s;
    int sockfd;

retry:
    iptc_fn = TC_INIT;

    // table长度超过长度时，返回
    if (strlen(tablename) >= TABLE_MAXNAMELEN) { ... }
    // 创建SOCK_RAW类型的socket
    sockfd = socket(TC_AF, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) return NULL;
    // 设置`FD_CLOEXEC`标记，当进程终止时，socket描述符会被自动关闭
    if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) { ... }
    
    // 设置`ipt[6]_getinfo`名称
    s = sizeof(info);
    strcpy(info.name, tablename);
    // 获取`ipt[6]_getinfo`信息，获取`valid_hooks`、`num_entries`、`size`等信息
    if (getsockopt(sockfd, TC_IPPROTO, SO_GET_INFO, &info, &s) < 0) { ... }

    // 分配`struct xtc_handle`结构体，根据`ipt[6]_getinfo`分配占用内存
    h = alloc_handle(&info);
    if (h == NULL) { close(sockfd); return NULL;}

    // 初始化当前状态
    h->sockfd = sockfd;
    h->info = info;
    h->entries->size = h->info.size;
    tmp = sizeof(STRUCT_GET_ENTRIES) + h->info.size;
    // 获取所有的防火墙规则
    if (getsockopt(h->sockfd, TC_IPPROTO, SO_GET_ENTRIES, h->entries, &tmp) < 0)
        goto error;
        
    // 解析table，失败时进入错误处理
    if (parse_table(h) < 0) goto error;

    return h;
error:
    TC_FREE(h);
    // 另一个不同的程序修改防火墙规则时，重新尝试
    if (errno == EAGAIN) goto retry;
    return NULL;
}
```

`parse_table`函数解析当前设置的防火墙规则，填充到`xtc_handle`中正确的位置，如下：

```C
// file: libiptc/libiptc.c
static int parse_table(struct xtc_handle *h)
{
    STRUCT_ENTRY *prev;
    unsigned int num = 0;
    struct chain_head *c;

    h->sorted_offsets = 1;
    // 遍历`entries`，填充到`xtc_handle`中
    ENTRY_ITERATE(h->entries->entrytable, h->entries->size,
                    cache_add_entry, h, &prev, &num);

    // 构建`chain_index`，用于链表搜索速度优化
    if ((iptcc_chain_index_alloc(h)) < 0) return -ENOMEM;
    iptcc_chain_index_build(h);

    // 第二次chain遍历，修复第一次遍历的异常情况，处理target是chain的情况
    list_for_each_entry(c, &h->chains, list) {
        struct rule_head *r;
        // 遍历规则
        list_for_each_entry(r, &c->rules, list) {
            struct chain_head *lc;
            STRUCT_STANDARD_TARGET *t;

            // target不是chain的情况，继续
            if (r->type != IPTCC_R_JUMP) continue;

            // 获取规则中target及其对应的chain
            t = (STRUCT_STANDARD_TARGET *)GET_TARGET(r->entry);
            lc = iptcc_find_chain_by_offset(h, t->verdict);
            if (!lc) return -1;
            // 设置规则跳转的chain
            r->jump = lc;
            lc->references++;
        }
    }
    return 1;
}
```

`cache_add_entry` 函数解析防火墙规则后添加到缓存中，如下：

```C
// file: libiptc/libiptc.c
static int cache_add_entry(STRUCT_ENTRY *e, struct xtc_handle *h, STRUCT_ENTRY **prev, unsigned int *num)
{
    unsigned int builtin;
    unsigned int offset = (char *)e - (char *)h->entries->entrytable;

    // 最后一项为策略规则，表示防火墙规则结束
    if (iptcb_entry2offset(h,e) + e->next_offset == h->entries->size) {
        // 删除前一个链的策略规则，缓存中不包含链策略规则
        __iptcc_p_del_policy(h, *num);
        h->chain_iterator_cur = NULL;
        goto out_inc;
    }

    // 错误目标或Linux内置的钩子入口点时，表示一个新的链
    if (strcmp(GET_TARGET(e)->u.user.name, ERROR_TARGET) == 0) {
        // 创建新的链
        struct chain_head *c = iptcc_alloc_chain_head((const char *)GET_TARGET(e)->data, 0);
        if (!c) { errno = -ENOMEM; return -1; }
        
        // 更新用户创建的链计数
        h->num_chains++; 
        // 添加到`h->chains`列表中
        __iptcc_p_add_chain(h, c, offset, num);
    } else if ((builtin = iptcb_ent_is_hook_entry(e, h)) != 0) {
        // 创建内置的链，PREROUTING`,`INPUT`,`OUTPUT`,`FORWARD`和`POSTROUTING`
        struct chain_head *c = iptcc_alloc_chain_head((char *)hooknames[builtin-1], builtin);
        if (!c) { errno = -ENOMEM; return -1; }

        c->hooknum = builtin;
        // 添加到`h->chains`列表中
        __iptcc_p_add_chain(h, c, offset, num);
        // 跳转到添加规则处理
        goto new_rule;
    } else {
        // 普通规则处理
        struct rule_head *r;
new_rule:
        // 创建并初始化规则
        if (!(r = iptcc_alloc_rule(h->chain_iterator_cur, e->next_offset))) { ... }

        // 设置规则属性
        r->index = *num;
        r->offset = offset;
        memcpy(r->entry, e, e->next_offset);
        r->counter_map.maptype = COUNTER_MAP_NORMAL_MAP;
        r->counter_map.mappos = r->index;
        
        // 不是标准目标时处理
        if (!strcmp(GET_TARGET(e)->u.user.name, STANDARD_TARGET)) {
            STRUCT_STANDARD_TARGET *t;
            t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);
            // 检查目标占用的空间是否匹配，不匹配时释放规则后返回
            if (t->target.u.target_size != ALIGN(sizeof(STRUCT_STANDARD_TARGET))) { ... }
            if (t->verdict < 0) {
                // 标准目标
                r->type = IPTCC_R_STANDARD;
            } else if (t->verdict == r->offset+e->next_offset) {
                // 穿越目标，跳转到其他目标中
                r->type = IPTCC_R_FALLTHROUGH;
            } else {
                // 跳转目标，跳转到指定的chain中
                r->type = IPTCC_R_JUMP;
            }
        } else {
            // 扩展目标，如：SNAT、DNAT...
            r->type = IPTCC_R_MODULE;
        }
        // 添加规则到当前链中
        list_add_tail(&r->list, &h->chain_iterator_cur->rules);
        h->chain_iterator_cur->num_rules++;
    }
out_inc:
    (*num)++;
    return 0;
}
```

`__iptcc_p_add_chain` 函数添加新创建的链到缓存中，如下：

```C
// file: libiptc/libiptc.c
static void __iptcc_p_add_chain(struct xtc_handle *h, struct chain_head *c,
                unsigned int offset, unsigned int *num)
{
    struct list_head  *tail = h->chains.prev;
    struct chain_head *ctail;
    // 删除策略规则
    __iptcc_p_del_policy(h, *num);
    // 设置偏移位置和索引
    c->head_offset = offset;
    c->index = *num;

    // 内置的链直接添加到链列表中
    if (iptcc_is_builtin(c)) /* Only user defined chains are sorted*/
        list_add_tail(&c->list, &h->chains);
    else {
        ctail = list_entry(tail, struct chain_head, list);
        // 按照名称顺序添加链列表中
        if (strcmp(c->name, ctail->name) > 0 || iptcc_is_builtin(ctail))
            list_add_tail(&c->list, &h->chains);/* Already sorted*/
        else {
            // 按照名称顺序插入到指定的位置
            iptc_insert_chain(h, c);/* Was not sorted */
            // 内核未对链排序时，用于二分查找的偏移信息无效
            h->sorted_offsets = 0;
        }
    }
    // 设置当前迭代的链
    h->chain_iterator_cur = c;
}
```

#### (8) `-A`追加防火墙规则

`-A`或`--append`表示向防火墙表中追加规则，对应`append_entry`函数。实现如下：

```C
// file: iptables/iptables.c
static int append_entry(const xt_chainlabel chain, struct ipt_entry *fw,
        unsigned int nsaddrs, const struct in_addr saddrs[], const struct in_addr smasks[],
        unsigned int ndaddrs, const struct in_addr daddrs[], const struct in_addr dmasks[],
        int verbose, struct xtc_handle *handle)
{
    unsigned int i, j;
    int ret = 1;

    for (i = 0; i < nsaddrs; i++) {
        // 设置源地址信息
        fw->ip.src.s_addr = saddrs[i].s_addr;
        fw->ip.smsk.s_addr = smasks[i].s_addr;
        for (j = 0; j < ndaddrs; j++) {
            // 设置目的地址信息
            fw->ip.dst.s_addr = daddrs[j].s_addr;
            fw->ip.dmsk.s_addr = dmasks[j].s_addr;
            // 打印防火墙规则
            if (verbose) print_firewall_line(fw, handle);
            // 追加防火墙规则
            ret &= iptc_append_entry(chain, fw, handle);
        }
    }
    return ret;
}
```

在遍历每个源地址和目的地址时，会调用`iptc_append_entry`函数将规则添加到防火墙表中。`iptc_append_entry`函数对应`TC_APPEND_ENTRY`宏，实现如下：

```C
// file: libiptc/libiptc.c
int TC_APPEND_ENTRY(const IPT_CHAINLABEL chain, const STRUCT_ENTRY *e, struct xtc_handle *handle)
{
    struct chain_head *c;
    struct rule_head *r;
    iptc_fn = TC_APPEND_ENTRY;

    // 查找链表
    if (!(c = iptcc_find_label(chain, handle))) { ... }
    // 创建防火墙规则 
    if (!(r = iptcc_alloc_rule(c, e->next_offset))) { ... }
    // 复制防火墙规则，设置目标映射类型
    memcpy(r->entry, e, e->next_offset);
    r->counter_map.maptype = COUNTER_MAP_SET;
    // 防火墙规则映射目标
    if (!iptcc_map_target(handle, r, false)) { ... }
    // 添加防火墙规则到链表中
    list_add_tail(&r->list, &c->rules);
    c->num_rules++;
    // 设置handle发生变化
    set_changed(handle);
    return 1;
}
```

`iptcc_map_target`函数设置防火墙规则的目标类型，实现如下：

```C
// file: libiptc/libiptc.c
static int iptcc_map_target(struct xtc_handle *const handle, struct rule_head *r, bool dry_run)
{
    STRUCT_ENTRY *e = r->entry;
    STRUCT_ENTRY_TARGET *t = GET_TARGET(e);

    // 目标为空的情况下，设置为`FALLTHROUGH`, 跳转到下一个目标
    if (strcmp(t->u.user.name, "") == 0) { 
        r->type = IPTCC_R_FALLTHROUGH;
        return 1;
    }
    // ACCEPT, DROP, QUEUE, RETURN为标准目标
    else if (strcmp(t->u.user.name, LABEL_ACCEPT) == 0)
        return iptcc_standard_map(r, -NF_ACCEPT - 1);
    else if (strcmp(t->u.user.name, LABEL_DROP) == 0)
        return iptcc_standard_map(r, -NF_DROP - 1);
    else if (strcmp(t->u.user.name, LABEL_QUEUE) == 0)
        return iptcc_standard_map(r, -NF_QUEUE - 1);
    else if (strcmp(t->u.user.name, LABEL_RETURN) == 0)
        return iptcc_standard_map(r, RETURN);
    else if (TC_BUILTIN(t->u.user.name, handle)) {
        // 目标为内置目标时，设置错误码，即：不能跳转到内置目标
        errno = EINVAL;
        return 0;
    } else {
        struct chain_head *c;
        // 检查目标是否链名
        c = iptcc_find_label(t->u.user.name, handle);
        if (c) {
            // 目标为链时，设置防火墙规则的跳转目标
            r->type = IPTCC_R_JUMP;
            r->jump = c;
            c->references++;
            return 1;
        }
    }
    // 其他情况下设置目标为模块，由内核进行进一步判断
    memset(t->u.user.name + strlen(t->u.user.name), 0,
            FUNCTION_MAXNAMELEN - 1 - strlen(t->u.user.name));
    r->type = IPTCC_R_MODULE;
    if (!dry_run) set_changed(handle);

    return 1;
}
```

`iptcc_standard_map`函数进行标准目标的设置，设置名称、判决结果、类型等，如下：

```C
// file: libiptc/libiptc.c
static int iptcc_standard_map(struct rule_head *r, int verdict)
{
    STRUCT_ENTRY *e = r->entry;
    STRUCT_STANDARD_TARGET *t;
    t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);
    // target的大小是否对齐
    if (t->target.u.target_size != ALIGN(sizeof(STRUCT_STANDARD_TARGET))) {
        errno = EINVAL;
        return 0;
    }
    // 设置目标名称为标准名称
    memset(t->target.u.user.name, 0, XT_EXTENSION_MAXNAMELEN);
    strcpy(t->target.u.user.name, STANDARD_TARGET);
    t->target.u.user.revision = 0;
    // 设置目标判决结果
    t->verdict = verdict;
    // 设置防火墙类型为标准类型
    r->type = IPTCC_R_STANDARD;
    return 1;
}
```

#### (9) `-D`删除防火墙规则

`-D`或`--delete`表示从防火墙表中删除规则，对应`delete_entry`函数。实现如下：

```C
// file: iptables/iptables.c
static int delete_entry(const xt_chainlabel chain, struct ipt_entry *fw,
        unsigned int nsaddrs, const struct in_addr saddrs[], const struct in_addr smasks[],
        unsigned int ndaddrs, const struct in_addr daddrs[], const struct in_addr dmasks[],
        int verbose, struct xtc_handle *handle, struct xtables_rule_match *matches, 
        const struct xtables_target *target)
{
    unsigned int i, j;
    int ret = 1;
    unsigned char *mask;
    // 标记要删除的规则，将用户空间内容设置为`0xFF`
    mask = make_delete_mask(matches, target, sizeof(*fw));
    for (i = 0; i < nsaddrs; i++) {
        // 设置规则源地址信息
        fw->ip.src.s_addr = saddrs[i].s_addr;
        fw->ip.smsk.s_addr = smasks[i].s_addr;
        for (j = 0; j < ndaddrs; j++) {
            // 设置规则目的地址信息
            fw->ip.dst.s_addr = daddrs[j].s_addr;
            fw->ip.dmsk.s_addr = dmasks[j].s_addr;
            // 打印防火墙规则
            if (verbose) print_firewall_line(fw, handle);
            // 删除规则
            ret &= iptc_delete_entry(chain, fw, mask, handle);
        }
    }
    free(mask);
    return ret;
}
```

在遍历每个源地址和目的地址时，会调用`iptc_delete_entry`函数删除规则。`iptc_delete_entry`函数对应`TC_DELETE_ENTRY`宏，实现如下：

```C
// file: libiptc/libiptc.c
int TC_DELETE_ENTRY(const IPT_CHAINLABEL chain,	const STRUCT_ENTRY *origfw,
        unsigned char *matchmask, struct xtc_handle *handle)
{   
    return delete_entry(chain, origfw, matchmask, handle, false);
}
```

`delete_entry`函数查找匹配的规则后，根据`dry_run`标志检查是否删除规则。如下：

```C
// file: libiptc/libiptc.c
static int delete_entry(const IPT_CHAINLABEL chain, const STRUCT_ENTRY *origfw,
            unsigned char *matchmask, struct xtc_handle *handle, bool dry_run)
{
    struct chain_head *c;
    struct rule_head *r, *i;

    iptc_fn = TC_DELETE_ENTRY;
    // 查找chain是否存在，不存在时返回
    if (!(c = iptcc_find_label(chain, handle))) { errno = ENOENT; return 0; }

    // 创建规则链表节点
    r = iptcc_alloc_rule(c, origfw->next_offset);
    if (!r) { errno = ENOMEM; return 0; }
    // 设置规则为原始的规则信息
    memcpy(r->entry, origfw, origfw->next_offset);
    r->counter_map.maptype = COUNTER_MAP_NOMAP;
    // 设置防火墙规则的映射目标
    if (!iptcc_map_target(handle, r, dry_run)) { free(r); return 0;} 
    else {
        // 目标是其他链时，减少引用计数
        if (r->type == IPTCC_R_JUMP && r->jump)
            r->jump->references--;
    }
    // 遍历所有的规则
    list_for_each_entry(i, &c->rules, list) {
        unsigned char *mask;
        // 检查规则是否匹配，不匹配时继续查找
        mask = is_same(r->entry, i->entry, matchmask);
        if (!mask) continue;
        // 判断两个规则是否相同，不同时继续查找
        if (!target_same(r, i, mask)) continue;
        // 检查目标时，设置dry_run为true，则不删除规则
        if (dry_run){ free(r); return 1; }

        // 在当前规则迭代器删除规则时，移动规则迭代器到前一个
        if (i == handle->rule_iterator_cur) {
            handle->rule_iterator_cur = 
                list_entry(handle->rule_iterator_cur->list.prev, struct rule_head, list);
        }
        // 删除规则，减少引用计数，从规则列表中移除
        c->num_rules--;
        iptcc_delete_rule(i);
        // 设置为修改状态
        set_changed(handle);
        free(r);
        return 1;
    }
    // 未找到相同规则时，释放规则后设置错误码
    free(r);
    errno = ENOENT;
    return 0;
}
```

#### (10) 提交防火墙规则

在添加、删除等操作防火墙规则后，通过 `iptc_commit` 函数提交到内核。`iptc_commit`函数对应`TC_COMMIT`宏，实现如下：

```C
// file: libiptc/libiptc.c
int TC_COMMIT(struct xtc_handle *handle)
{
    // 防火墙规则替换信息
    STRUCT_REPLACE *repl;
    STRUCT_COUNTERS_INFO *newcounters;
    struct chain_head *c;
    ...

    iptc_fn = TC_COMMIT;

    // 如果没有修改,则不需要提交
    if (!handle->changed) goto finished;
    // 计算替换规则的大小和数量，数量为0时进入错误处理
    new_number = iptcc_compile_table_prep(handle, &new_size);
    if (new_number < 0) { errno = ENOMEM; goto out_zero; }

    // 分配repl空间
    repl = malloc(sizeof(*repl) + new_size);
    if (!repl) { errno = ENOMEM; goto out_zero; }
    memset(repl, 0, sizeof(*repl) + new_size);

    // 计算计数器长度
    counterlen = sizeof(STRUCT_COUNTERS_INFO) + sizeof(STRUCT_COUNTERS) * new_number;
    
    // 分配当前规则的计数器空间
    repl->counters = calloc(handle->info.num_entries, sizeof(STRUCT_COUNTERS));
    if (!repl->counters) { errno = ENOMEM; goto out_free_repl; }
    
    // 分配新规则的计数器空间 
    newcounters = malloc(counterlen);
    if (!newcounters) { errno = ENOMEM; goto out_free_repl_counters; }
    memset(newcounters, 0, counterlen);

    // 设置repl信息，设置名称、新的计数器信息、旧的计数器信息
    strcpy(repl->name, handle->info.name);
    repl->num_entries = new_number;
    repl->size = new_size;
    repl->num_counters = handle->info.num_entries;
    repl->valid_hooks  = handle->info.valid_hooks;

    // 填充repl规则内容
    ret = iptcc_compile_table(handle, repl);
    if (ret < 0) { errno = ret; goto out_free_newcounters; }
    
    // 通过`TC_IPPROTO::SO_SET_REPLACE`选项设置替换信息
    ret = setsockopt(handle->sockfd, TC_IPPROTO, SO_SET_REPLACE, repl, sizeof(*repl) + repl->size);
    if (ret < 0) goto out_free_newcounters;

    // 设置计数器信息
    strcpy(newcounters->name, handle->info.name);
    newcounters->num_counters = new_number;

    list_for_each_entry(c, &handle->chains, list) {
        struct rule_head *r;
        // 内置链有自己的计数器
        if (iptcc_is_builtin(c)) {
            switch(c->counter_map.maptype) {
            case COUNTER_MAP_NOMAP: 
                // NOMAP表示将计数器设置为0
                counters_nomap(newcounters, c->foot_index);
                break;
            case COUNTER_MAP_NORMAL_MAP:
                // NORMAL_MAP表示使用`repl`中的计数器值
                counters_normal_map(newcounters, repl, c->foot_index, c->counter_map.mappos);
                break;
            case COUNTER_MAP_ZEROED:
                // ZEROED表示计新的计数器值为旧的数器值减去`repl`中计数器值
                counters_map_zeroed(newcounters, repl, c->foot_index, c->counter_map.mappos, &c->counters);
                break;
            case COUNTER_MAP_SET:
                // SET表示使用旧的计数器值
                counters_map_set(newcounters, c->foot_index, &c->counters);
                break;
            }
        }
        // 遍历链的规则，设置计数器信息
        list_for_each_entry(r, &c->rules, list) {
            switch (r->counter_map.maptype) {
            case COUNTER_MAP_NOMAP:
                counters_nomap(newcounters, r->index);
                break;
            case COUNTER_MAP_NORMAL_MAP:
                counters_normal_map(newcounters, repl, r->index, r->counter_map.mappos);
                break;
            case COUNTER_MAP_ZEROED:
                counters_map_zeroed(newcounters, repl, r->index, r->counter_map.mappos, &r->entry->counters);
                break;
            case COUNTER_MAP_SET:
                counters_map_set(newcounters, r->index, &r->entry->counters);
                break;
            }
        }
    }
    // 通过`TC_IPPROTO::SO_SET_ADD_COUNTERS`选项设置计数器信息
    ret = setsockopt(handle->sockfd, TC_IPPROTO, SO_SET_ADD_COUNTERS, newcounters, counterlen);
    if (ret < 0) goto out_free_newcounters;

    // 释放资源信息
    free(repl->counters);
    free(repl);
    free(newcounters);
finished:
    return 1;

    // 失败时，释放资源信息
out_free_newcounters:
    free(newcounters);
out_free_repl_counters:
    free(repl->counters);
out_free_repl:
    free(repl);
out_zero:
    return 0;
}
```

`iptcc_compile_table_prep`函数计算替换规则的大小和数量,具体实现如下:

```C
// file: libiptc/libiptc.c
static int iptcc_compile_table_prep(struct xtc_handle *h, unsigned int *size)
{
    struct chain_head *c;
    unsigned int offset = 0, num = 0;
    int ret = 0;
    // 第一次遍历链表，计算每个规则的偏移量
    list_for_each_entry(c, &h->chains, list) {
        ret = iptcc_compile_chain_offsets(h, c, &offset, &num);
        if (ret < 0) return ret;
    }
    // 在每个链表末尾添加一个错误规则
    num++;
    offset += sizeof(STRUCT_ENTRY) + ALIGN(sizeof(struct xt_error_target));
    // 计算规则总大小
    *size = offset;
    return num;
}
```

`iptcc_compile_chain_offsets`函数计算缓存中每条规则的偏移量和索引，如下：

```C
// file: libiptc/libiptc.c
static int iptcc_compile_chain_offsets(struct xtc_handle *h, struct chain_head *c, 
            unsigned int *offset, unsigned int *num)
{
    struct rule_head *r;
    // 设置链的偏移量
    c->head_offset = *offset;
    if (!iptcc_is_builtin(c))  {
        // 不是内置链时，设置链头部信息
        *offset += sizeof(STRUCT_ENTRY) + ALIGN(sizeof(struct xt_error_target));
        (*num)++;
    }
    // 遍历链中的规则，设置规则的偏移位置和编号
    list_for_each_entry(r, &c->rules, list) {
        r->offset = *offset;
        r->index = *num;
        *offset += r->size;
        (*num)++;
    }
    // 设置链的结束偏移量和索引
    c->foot_offset = *offset;
    c->foot_index = *num;
    *offset += sizeof(STRUCT_ENTRY) + ALIGN(sizeof(STRUCT_STANDARD_TARGET));
    (*num)++;

    return 1;
}
```

`iptcc_compile_table` 函数填充防火墙表中的替换信息，将防火墙规则填充到偏移位置，并在链的末尾添加一个错误规则。如下：

```C
// file: libiptc/libiptc.c
static int iptcc_compile_table(struct xtc_handle *h, STRUCT_REPLACE *repl)
{
    struct chain_head *c;
    struct iptcb_chain_error *error;

    // 第二次遍历，填充缓存中的规则到偏移位置
    list_for_each_entry(c, &h->chains, list) {
        int ret = iptcc_compile_chain(h, repl, c);
        if (ret < 0) return ret;
    }
    // 在链的末尾添加一个错误规则
    error = (void *)repl->entries + repl->size - IPTCB_CHAIN_ERROR_SIZE;
    error->entry.target_offset = sizeof(STRUCT_ENTRY);
    error->entry.next_offset = IPTCB_CHAIN_ERROR_SIZE;
    error->target.target.u.user.target_size = ALIGN(sizeof(struct xt_error_target));
    strcpy((char *)&error->target.target.u.user.name, ERROR_TARGET);
    strcpy((char *)&error->target.errorname, "ERROR");

    return 1;
}
```

`iptcc_compile_chain` 函数填充链信息到替换信息中，设置防火墙规则中每个链的开始和结束位置，填充链的开始/结束信息。如下：

```C
// file: libiptc/libiptc.c
static int iptcc_compile_chain(struct xtc_handle *h, STRUCT_REPLACE *repl, struct chain_head *c)
{
    int ret;
    struct rule_head *r;
    struct iptcb_chain_start *head;
    struct iptcb_chain_foot *foot;

    if (!iptcc_is_builtin(c)) {
        // 设置用户自定义的链的头部信息
        head = (void *)repl->entries + c->head_offset;
        head->e.target_offset = sizeof(STRUCT_ENTRY);
        head->e.next_offset = IPTCB_CHAIN_START_SIZE;
        strcpy(head->name.target.u.user.name, ERROR_TARGET);
        head->name.target.u.target_size = ALIGN(sizeof(struct xt_error_target));
        strncpy(head->name.errorname, c->name, XT_FUNCTION_MAXNAMELEN);
        head->name.errorname[XT_FUNCTION_MAXNAMELEN - 1] = '\0';
    } else {
        // 内置的链设置开始和结束位置
        repl->hook_entry[c->hooknum-1] = c->head_offset;
        repl->underflow[c->hooknum-1] = c->foot_offset;
    }
    // 遍历链中规则，填充规则到替换信息中
    list_for_each_entry(r, &c->rules, list) {
        ret = iptcc_compile_rule(h, repl, r);
        if (ret < 0) return ret;
    }
    // 填充链的结束信息
    foot = (void *)repl->entries + c->foot_offset;
    foot->e.target_offset = sizeof(STRUCT_ENTRY);
    foot->e.next_offset = IPTCB_CHAIN_FOOT_SIZE;
    strcpy(foot->target.target.u.user.name, STANDARD_TARGET);
    foot->target.target.u.target_size = ALIGN(sizeof(STRUCT_STANDARD_TARGET));
    // 内置的链设置判决值，其他的设置判决结果为`返回`(RETURN)
    if (iptcc_is_builtin(c))
        foot->target.verdict = c->verdict;
    else
        foot->target.verdict = RETURN;
    // 设置策略计数器
    foot->e.counters = c->counters;

    return 0;
}
```

`iptcc_compile_rule`函数填充防火墙规则到替换信息中，实现如下：

```C
// file: libiptc/libiptc.c
static inline int iptcc_compile_rule(struct xtc_handle *h, STRUCT_REPLACE *repl, struct rule_head *r)
{
    // 处理跳转情况
    if (r->type == IPTCC_R_JUMP) {
        STRUCT_STANDARD_TARGET *t;
        t = (STRUCT_STANDARD_TARGET *)GET_TARGET(r->entry);
        // 设置规则的用户名称为标准名称
        memset(t->target.u.user.name, 0, XT_EXTENSION_MAXNAMELEN);
        strcpy(t->target.u.user.name, STANDARD_TARGET);
        t->target.u.user.revision = 0;
        // 只有内置的链才能设置跳转，我们可以安全地假设它们总是有头部
        t->verdict = r->jump->head_offset + IPTCB_CHAIN_START_SIZE;
    } else if (r->type == IPTCC_R_FALLTHROUGH) {
        // FULLTHROUGH情况，设置判决结果为跳转的偏移位置
        STRUCT_STANDARD_TARGET *t;
        t = (STRUCT_STANDARD_TARGET *)GET_TARGET(r->entry);
        t->verdict = r->offset + r->size;
    }
    // 复制规则到替换信息中
    memcpy((char *)repl->entries+r->offset, r->entry, r->size);
    return 1;
}
```

### 3.3 `iptables6`的实现过程

`iptables6`在netfilter框架中入口点为`ip6tables_main`，实现过程和`iptables_main`相同，其中使用的结构类型不同。

## 4 内核实现(ipv4)

### 4.1 NF_HOOK的初始化和注销过程

#### (1) netfilter介绍

##### 1 HOOKS介绍

netfilter提供了不同类型的hook点，网络数据包经过协议栈时会触发内核模块注册在这里的处理函数。这些处理函数决定了网络数据包的处理结果，放行还是拒绝。Linux内核中提供的hook点使用`netns_nf`结构表示，如下：

```C
// file: include/net/netns/netfilter.h
struct netns_nf {
    ...
    const struct nf_logger __rcu *nf_loggers[NFPROTO_NUMPROTO];
    // ipv4 hooks
    struct nf_hook_entries __rcu *hooks_ipv4[NF_INET_NUMHOOKS];
    // ipv6 hooks
    struct nf_hook_entries __rcu *hooks_ipv6[NF_INET_NUMHOOKS];
    // arp hooks
    struct nf_hook_entries __rcu *hooks_arp[NF_ARP_NUMHOOKS];
    // bridge hooks
    struct nf_hook_entries __rcu *hooks_bridge[NF_INET_NUMHOOKS];
    ...
};
```

Linux内核支持多种协议的NF，如下：

```C
// file: include/uapi/linux/netfilter.h
enum {
    NFPROTO_UNSPEC =  0,
    NFPROTO_INET   =  1,
    NFPROTO_IPV4   =  2,
    NFPROTO_ARP    =  3,
    NFPROTO_NETDEV =  5,
    NFPROTO_BRIDGE =  7,
    NFPROTO_IPV6   = 10,
#ifndef __KERNEL__ /* no longer supported by kernel */
    NFPROTO_DECNET = 12,
#endif
    NFPROTO_NUMPROTO,
};
```

ARP协议支持三个hook点，如下：

```C
// file: include/uapi/linux/netfilter_arp.h
#define NF_ARP_IN   0
#define NF_ARP_OUT  1
#define NF_ARP_FORWARD  2

#ifndef __KERNEL__
#define NF_ARP_NUMHOOKS 3
#endif
```

ipv4,ipv6,bridge协议支持五个hook点，如下：

```C
// file: include/uapi/linux/netfilter.h
enum nf_inet_hooks {
    NF_INET_PRE_ROUTING,
    NF_INET_LOCAL_IN,
    NF_INET_FORWARD,
    NF_INET_LOCAL_OUT,
    NF_INET_POST_ROUTING,
    NF_INET_NUMHOOKS,
    NF_INET_INGRESS = NF_INET_NUMHOOKS,
};
```

网卡设备支持两个hook点，如下：

```C
// file: include/uapi/linux/netfilter.h
enum nf_dev_hooks {
    NF_NETDEV_INGRESS,
    NF_NETDEV_EGRESS,
    NF_NETDEV_NUMHOOKS
};
```

##### 2 iptable的链和表

iptable使用表(table)来组织规则，Linux内核按照操作类型将防火墙规则分为不同的表(table)。每个表内部进一步组织为链(chain)，链中包含规则(rule)。

Linux内核中提供表(table)的类型如下：

* filter: 用于过滤数据包，是iptables默认使用的表。在防火墙领域，filter表提供了防火墙的一些常见的功能。
* nat: 用于网络地址转换，用于修改数据包的源/目的地址、端口信息。改变该包的路由时的行为，通常用于将包路由到无法直接访问的网络。这在使用互联网时非常有用，因为它允许将一个内部的网络地址转换为外部可访问的地址。
* mangle: 用于修改数据包内容，如：修改TTL、TOS等IP头内容。
* raw: 用于决定数据包是否被状态跟踪机制处理。
* security: 用于给网络数据包标记强制访问控制(MAC)相关标记。

这些表内部规则进一步组织为链(chain),链(chain)决定了网络数据包nfhook点位置。Linux内核默认提供5个链，和5个hook点一一对应，分别为：PREROUTING, INPUT,FORWARD,OUTPUT和POSTROUTING。

iptable的表(table)和链(chain)关系如下：

| Tables/Chains | PREROUTING | INPUT | FORWARD | OUTPUT | POSTROUTING |
| :-----------: | :--------: | :---: | :-----: | :----: | :---------: |
| （路由判断）    |            |       |         |   Y    |             |
| **raw**       |     Y      |       |         |   Y    |             |
| （连接追踪）    |     Y      |       |         |   Y    |             |
| **mangle**    |     Y      |   Y   |    Y    |   Y    |      Y      |
| **nat(DNAT)** |     Y      |       |         |   Y    |             |
| （路由判断）    |     Y      |       |         |   Y    |             |
| **filter**    |            |   Y   |    Y    |   Y    |             |
| **security**  |            |   Y   |    Y    |   Y    |             |
| **nat(SNAT)** |            |   Y   |         |   Y    |      Y      |

当网络数据包触发netfilter hook点时，处理过程将沿着列的顺序从上到下执行，执行的顺序按照表的优先级进行排列的。

#### (2) `xtable`的初始化/销毁过程

netfilter中使用的table在内核中使用`xtable`表示，`xtable`相关的结构包括`xt_af`和`xt_templates`。`xt_af`表示NF协议使用的`match`和`target`信息，`xt_templates`表示NF协议使用的`table`模板。

##### 1 全局初始化/销毁`xtable`

在`module_init`阶段初始化`xt_af`和`xt_templates`，如下：

```C
// file: net/netfilter/x_tables.c
module_init(xt_init);
static int __init xt_init(void)
{
    unsigned int i;
    int rv;
    // `xt_recseq`初始化
    for_each_possible_cpu(i) {
        seqcount_init(&per_cpu(xt_recseq, i));
    }
    // 分配`xt_af`信息
    xt = kcalloc(NFPROTO_NUMPROTO, sizeof(struct xt_af), GFP_KERNEL);
    if (!xt) return -ENOMEM;

    for (i = 0; i < NFPROTO_NUMPROTO; i++) {
        //初始化`xt[i]`
        mutex_init(&xt[i].mutex);
#ifdef CONFIG_NETFILTER_XTABLES_COMPAT
        mutex_init(&xt[i].compat_mutex);
        xt[i].compat_tab = NULL;
#endif
        // 初始化`target`和`match`列表
        INIT_LIST_HEAD(&xt[i].target);
        INIT_LIST_HEAD(&xt[i].match);
        // 初始化`xt_templates`
        INIT_LIST_HEAD(&xt_templates[i]);
    }
    // 注册网络命名空间操作
    rv = register_pernet_subsys(&xt_net_ops);
    if (rv < 0) kfree(xt);
    return rv;
}
```

在`module_exit`阶段注销网络命名空间接口和释放`xtable`相关的资源，实现如下：

```C
// file: net/netfilter/x_tables.c
module_exit(xt_fini);
static void __exit xt_fini(void)
{
    unregister_pernet_subsys(&xt_net_ops);
    kfree(xt);
}
```

##### 2 网络命名空间初始化/注销`xtables`

`xt_net_ops`变量定义了创建/销毁网络命名空间时的操作接口，定义如下：

```C
// file: net/netfilter/x_tables.c
static struct pernet_operations xt_net_ops = {
    .init = xt_net_init,
    .exit = xt_net_exit,
    .id   = &xt_pernet_id,
    .size = sizeof(struct xt_pernet),
};
```

`xt_net_init`函数在创建网络命名空间时调用，实现每个NF协议的`xtable`的初始化，实现如下：

```C
// file: net/netfilter/x_tables.c
static int __net_init xt_net_init(struct net *net)
{
    // 获取网络命名空间的`xt_pernet`
    struct xt_pernet *xt_net = net_generic(net, xt_pernet_id);
    int i;
    for (i = 0; i < NFPROTO_NUMPROTO; i++)
        INIT_LIST_HEAD(&xt_net->tables[i]);
    return 0;
}
```

`xt_pernet`结构定义了网络命名空间使用的`xtables`，定义如下：

```C
// file: net/netfilter/x_tables.c
struct xt_pernet {
    struct list_head tables[NFPROTO_NUMPROTO];
};
```

`xt_net_exit`函数在销毁网络命名空间时调用，检查每个NF协议的`xtable`是否为空，实现如下：

```C
// file: net/netfilter/x_tables.c
static void __net_exit xt_net_exit(struct net *net)
{
    struct xt_pernet *xt_net = net_generic(net, xt_pernet_id);
    int i;
    for (i = 0; i < NFPROTO_NUMPROTO; i++)
        WARN_ON_ONCE(!list_empty(&xt_net->tables[i]));
}
```

#### (3) `target`的注册/注销过程

##### 1 `target`注册/注销接口

`target`用于指定拦截网络数据包后的处理操作，target可以是一个特定的链（如INPUT、OUTPUT、FORWARD等），也可以是一个用户定义的目标，如ACCEPT、DROP、REJECT等。

`xt_register_target`和`xt_register_targets`函数实现一个和多个Linux内核内置`target`的注册，如下：

```C
// file: net/netfilter/x_tables.c
int xt_register_target(struct xt_target *target)
{
    // 获取NFPROTO
    u_int8_t af = target->family;
    mutex_lock(&xt[af].mutex);
    // 添加到target列表中
    list_add(&target->list, &xt[af].target);
    mutex_unlock(&xt[af].mutex);
    return 0;
}
```

`xt_unregister_target`和`xt_register_targets`函数实现一个和多个Linux内核内置`target`的注销，如下：

```C
// file: net/netfilter/x_tables.c
void xt_unregister_target(struct xt_target *target)
{
    // 获取NFPROTO
    u_int8_t af = target->family;
    mutex_lock(&xt[af].mutex);
    // 从`target`列表中删除
    list_del(&target->list);
    mutex_unlock(&xt[af].mutex);
}
```

##### 2 一些内置的`target`

Linux内核中提供了丰富的`target`接口，例如：

* `SNAT`/`DNAT`

`SNAT`和`DNAT`用于网络地址转换，在`module_init`阶段注册，实现如下：

```C
// file: net/netfilter/xt_nat.c
module_init(xt_nat_init);
static int __init xt_nat_init(void)
{
    return xt_register_targets(xt_nat_target_reg, ARRAY_SIZE(xt_nat_target_reg));
}
```

在`module_exit`阶段注销target，实现如下：

```C
// file: net/netfilter/xt_nat.c
module_exit(xt_nat_exit);
static void __exit xt_nat_exit(void)
{
    xt_unregister_targets(xt_nat_target_reg, ARRAY_SIZE(xt_nat_target_reg));
}
```

`xt_nat_target_reg`变量包括了3个不同版本的`SNAT`/`DNAT`实现，其定义如下：

```C
// file: net/netfilter/xt_nat.c
static struct xt_target xt_nat_target_reg[] __read_mostly = {
    ...
    {
        .name       = "SNAT",
        .revision   = 2,
        .checkentry = xt_nat_checkentry,
        .destroy    = xt_nat_destroy,
        .target     = xt_snat_target_v2,
        .targetsize = sizeof(struct nf_nat_range2),
        .table      = "nat",
        .hooks      = (1 << NF_INET_POST_ROUTING) | (1 << NF_INET_LOCAL_IN),
        .me         = THIS_MODULE,
    },
    {
        .name       = "DNAT",
        .revision   = 2,
        .checkentry = xt_nat_checkentry,
        .destroy    = xt_nat_destroy,
        .target     = xt_dnat_target_v2,
        .targetsize = sizeof(struct nf_nat_range2),
        .table      = "nat",
        .hooks      = (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_LOCAL_OUT),
        .me         = THIS_MODULE,
    },
};
```

* `REJECT`

`REJECT`用于拒绝数据包，在`module_init`/`module_exit`阶段注册/注销，实现如下：

```C
// file: net/ipv4/netfilter/ipt_REJECT.c
static int __init reject_tg_init(void)
{
    return xt_register_target(&reject_tg_reg);
}
static void __exit reject_tg_exit(void)
{
    xt_unregister_target(&reject_tg_reg);
}
module_init(reject_tg_init);
module_exit(reject_tg_exit);
```

`reject_tg_reg`变量定义了ipv4网络数据包`REJECT`的实现，如下：

```C
// file: net/ipv4/netfilter/ipt_REJECT.c
static struct xt_target reject_tg_reg __read_mostly = {
    .name       = "REJECT",
    .family     = NFPROTO_IPV4,
    .target     = reject_tg,
    .targetsize = sizeof(struct ipt_reject_info),
    .table      = "filter",
    .hooks      = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) |
                  (1 << NF_INET_LOCAL_OUT),
    .checkentry = reject_tg_check,
    .me         = THIS_MODULE,
};
```

#### (4) `match`的注册/注销过程

##### 1 `match`注册/注销接口

`match`用于指定拦截网络数据包的匹配操作。和`target`类似，`xt_register_match`和`xt_register_matches`函数实现一个和多个内置`match`的注册，如下：

```C
// file: net/netfilter/x_tables.c
int xt_register_match(struct xt_match *match)
{
    // 获取NFPROTO
    u_int8_t af = match->family;
    mutex_lock(&xt[af].mutex);
    // 添加到match列表中
    list_add(&match->list, &xt[af].match);
    mutex_unlock(&xt[af].mutex);
    return 0;
}
```

`xt_unregister_match`和`xt_unregister_matches`函数实现一个和多个Linux内核内置`target`的注销，如下：

```C
// file: net/netfilter/x_tables.c
void xt_unregister_match(struct xt_match *match)
{
    u_int8_t af = match->family;
    mutex_lock(&xt[af].mutex);
    // 从`match`列表中删除
    list_del(&match->list);
    mutex_unlock(&xt[af].mutex);
}
```

##### 2 一些内置的`match`

Linux内核中提供了丰富的`match`接口，例如：

* `bpf`

`bpf`可以使用eBPF程序实现网络数据包的过滤。在`module_init`/`module_exit`阶段注册/注销，实现如下：

```C
// file: net/netfilter/xt_bpf.c
static int __init bpf_mt_init(void)
{
    return xt_register_matches(bpf_mt_reg, ARRAY_SIZE(bpf_mt_reg));
}
static void __exit bpf_mt_exit(void)
{
    xt_unregister_matches(bpf_mt_reg, ARRAY_SIZE(bpf_mt_reg));
}
module_init(bpf_mt_init);
module_exit(bpf_mt_exit);
```

`bpf_mt_reg`变量包括了2个不同版本的`bpf`实现，其定义如下：

```C
// file: net/netfilter/xt_bpf.c
static struct xt_match bpf_mt_reg[] __read_mostly = {
    ...
    {
        .name       = "bpf",
        .revision   = 1,
        .family     = NFPROTO_UNSPEC,
        .checkentry = bpf_mt_check_v1,
        .match      = bpf_mt_v1,
        .destroy    = bpf_mt_destroy_v1,
        .matchsize  = sizeof(struct xt_bpf_info_v1),
        .usersize   = offsetof(struct xt_bpf_info_v1, filter),
        .me         = THIS_MODULE,
    },
};
```

* `conntrack`

`conntrack`跟踪连接的详细信息，包括源IP地址、源端口、目标IP地址、目标端口、协议等，可用帮助网络工具理解并处理数据包的流式行为。在`module_init`/`module_exit`阶段注册/注销，实现如下：

```C
// file: net/netfilter/xt_conntrack.c
static int __init conntrack_mt_init(void)
{
    return xt_register_matches(conntrack_mt_reg, ARRAY_SIZE(conntrack_mt_reg));
}
static void __exit conntrack_mt_exit(void)
{
    xt_unregister_matches(conntrack_mt_reg, ARRAY_SIZE(conntrack_mt_reg));
}
module_init(conntrack_mt_init);
module_exit(conntrack_mt_exit);
```

`conntrack_mt_reg`变量包括了3个不同版本的`conntrack`实现，其定义如下：

```C
// file: net/netfilter/xt_conntrack.c
static struct xt_match conntrack_mt_reg[] __read_mostly = {
    ...
    {
        .name       = "conntrack",
        .revision   = 3,
        .family     = NFPROTO_UNSPEC,
        .matchsize  = sizeof(struct xt_conntrack_mtinfo3),
        .match      = conntrack_mt_v3,
        .checkentry = conntrack_mt_check,
        .destroy    = conntrack_mt_destroy,
        .me         = THIS_MODULE,
    },
};
```

#### (5) `table`的注册和注销过程

##### 1 `table_template`注册/注销接口

`table`用于指定要处理的表，`xt_register_template`函数实现`xtable`模板的注册，如下：

```C
// file: net/netfilter/x_tables.c
int xt_register_template(const struct xt_table *table, int (*table_init)(struct net *net))
{
    int ret = -EEXIST, af = table->af;
    struct xt_template *t;

    mutex_lock(&xt[af].mutex);
    // 遍历模板，根据名称检查是否已经注册
    list_for_each_entry(t, &xt_templates[af], list) {
        if (WARN_ON_ONCE(strcmp(table->name, t->name) == 0)) 
            goto out_unlock;
    }
    ret = -ENOMEM;
    // 分配xt_template结构
    t = kzalloc(sizeof(*t), GFP_KERNEL);
    if (!t) goto out_unlock;

    BUILD_BUG_ON(sizeof(t->name) != sizeof(table->name));
    // 初始化模板，设置名称、初始化函数、module名称
    strscpy(t->name, table->name, sizeof(t->name));
    t->table_init = table_init;
    t->me = table->me;
    // 添加到模板列表中
    list_add(&t->list, &xt_templates[af]);
    ret = 0;
out_unlock:
    mutex_unlock(&xt[af].mutex);
    return ret;
}
```

`xt_unregister_template`函数实现`xtable`模板的注销，如下：

```C
// file: net/netfilter/x_tables.c
void xt_unregister_template(const struct xt_table *table)
{
    struct xt_template *t;
    int af = table->af;
    mutex_lock(&xt[af].mutex);
    // 遍历模板，存在同名的模板时，从列表中删除
    list_for_each_entry(t, &xt_templates[af], list) {
        if (strcmp(table->name, t->name)) continue;
        // 从列表中删除表模板
        list_del(&t->list);
        mutex_unlock(&xt[af].mutex);
        kfree(t);
        return;
    }
    mutex_unlock(&xt[af].mutex);
    WARN_ON_ONCE(1);
}
```

##### 2 全局初始化/注销`table_template`

Linux内核中`ARP`协议提供了`filter`表，`IPV4`/`IPV6`协议提供了`raw`,`filter`,`nat`,`mangle`,`security`5个表。我们以ipv4的`filter`表为例进行说明。

ipv4的`filter`表实现对ipv4协议网络数据包的过滤。在`module_init`/`module_exit`阶段注册/注销，实现如下：

```C
// file: net/ipv4/netfilter/iptable_filter.c
static int __init iptable_filter_init(void)
{
    // 注册表模板，设置表初始化接口
    int ret = xt_register_template(&packet_filter, iptable_filter_table_init);
    if (ret < 0) return ret;
    // 分配hook_ops结构
    filter_ops = xt_hook_ops_alloc(&packet_filter, ipt_do_table);
    if (IS_ERR(filter_ops)) { ... }
    // 注册网络命名空间操作接口
    ret = register_pernet_subsys(&iptable_filter_net_ops);
    if (ret < 0) { ... }
    return ret;
}
static void __exit iptable_filter_fini(void)
{
    // 注销网络命名空间操作接口
    unregister_pernet_subsys(&iptable_filter_net_ops);
    // 注销表模板
    xt_unregister_template(&packet_filter);
    // 释放hook_ops结构
    kfree(filter_ops);
}
module_init(iptable_filter_init);
module_exit(iptable_filter_fini);
```

`packet_filter`变量定义了`filter`表的模板，其定义如下：

```C
// file: net/ipv4/netfilter/iptable_filter.c
static const struct xt_table packet_filter = {
    .name           = "filter",
    .valid_hooks    = FILTER_VALID_HOOKS,
    .me             = THIS_MODULE,
    .af             = NFPROTO_IPV4,
    .priority       = NF_IP_PRI_FILTER,
};
```

`.valid_hooks`字段指定了表可以处理的hook类型，即支持的链。如下：

```C
// file: net/ipv4/netfilter/iptable_filter.c
#define FILTER_VALID_HOOKS ((1 << NF_INET_LOCAL_IN) | \
                (1 << NF_INET_FORWARD) | \
                (1 << NF_INET_LOCAL_OUT))
```

`.priority`字段指定了表的优先级。ipv4协议支持的表优先级定义如下：

```C
// file: include/uapi/linux/netfilter_ipv4.h
enum nf_ip_hook_priorities {
    NF_IP_PRI_FIRST = INT_MIN,
    NF_IP_PRI_RAW_BEFORE_DEFRAG = -450,
    NF_IP_PRI_CONNTRACK_DEFRAG = -400,
    NF_IP_PRI_RAW = -300,
    NF_IP_PRI_SELINUX_FIRST = -225,
    NF_IP_PRI_CONNTRACK = -200,
    NF_IP_PRI_MANGLE = -150,
    NF_IP_PRI_NAT_DST = -100,
    NF_IP_PRI_FILTER = 0,
    NF_IP_PRI_SECURITY = 50,
    NF_IP_PRI_NAT_SRC = 100,
    NF_IP_PRI_SELINUX_LAST = 225,
    NF_IP_PRI_CONNTRACK_HELPER = 300,
    NF_IP_PRI_CONNTRACK_CONFIRM = INT_MAX,
    NF_IP_PRI_LAST = INT_MAX,
};
```

`filter_ops`是`struct nf_hook_ops`结构，表示在创建新表时设置的hooks信息，通过`xt_hook_ops_alloc`函数创建。创建过程如下：

```C
// file: net/netfilter/x_tables.c
struct nf_hook_ops * xt_hook_ops_alloc(const struct xt_table *table, nf_hookfn *fn)
{
    unsigned int hook_mask = table->valid_hooks;
    // `hweight32`函数计算有效的bits数量，即：bit为1的数量
    uint8_t i, num_hooks = hweight32(hook_mask);
    uint8_t hooknum;
    struct nf_hook_ops *ops;
    // 不存在hooks时，返回错误信息
    if (!num_hooks) return ERR_PTR(-EINVAL);
    // 分配一个`nf_hook_ops`数组
    ops = kcalloc(num_hooks, sizeof(*ops), GFP_KERNEL);
    if (ops == NULL) return ERR_PTR(-ENOMEM);
    // 遍历有效的hook
    for (i = 0, hooknum = 0; i < num_hooks && hook_mask != 0;  hook_mask >>= 1, ++hooknum) {
        // bit无效时，继续下一个
        if (!(hook_mask & 1)) continue;
        // 设置`ops[i]`属性信息，如：hook函数、协议、hooknum(链)，优先级
        ops[i].hook     = fn;
        ops[i].pf       = table->af;
        ops[i].hooknum  = hooknum;
        ops[i].priority = table->priority;
        ++i;
    }
    return ops;
}
```

##### 3 网络命名空间初始化/注销`table`

`iptable_filter_net_ops`设置了网络命名的操作接口，定义如下：

```C
// file: net/ipv4/netfilter/iptable_filter.c
static struct pernet_operations iptable_filter_net_ops = {
    .init = iptable_filter_net_init,
    .pre_exit = iptable_filter_net_pre_exit,
    .exit = iptable_filter_net_exit,
};
```

`.init`接口设置为`iptable_filter_net_init`，在创建网络命名空间时调用，其实现如下：

```C
// file: net/ipv4/netfilter/iptable_filter.c
static int __net_init iptable_filter_net_init(struct net *net)
{   
    // 在不支持转发时，初始化`net->ipv4.iptable_filter`
    if (!forward)
        return iptable_filter_table_init(net);
    return 0;
}
```

`iptable_filter_table_init`函数同时也是`packet_filter`表模板设置的初始化函数，在第一次使用表时进行初始化时调用(后续分析其实现过程)。`iptable_filter_table_init`函数实现`ipv4.iptable_filter`的注册，实现如下：

```C
// file: net/ipv4/netfilter/iptable_filter.c
static int iptable_filter_table_init(struct net *net)
{
    struct ipt_replace *repl;
    int err;
    // 分配ipv4表默认规则
    repl = ipt_alloc_initial_table(&packet_filter);
    if (repl == NULL) return -ENOMEM;
    // 设置默认规则的目标判决结果，使用ipv4的标准目标
    ((struct ipt_standard *)repl->entries)[1].target.verdict = 
        forward ? -NF_ACCEPT - 1 : -NF_DROP - 1;
    // 注册ipv4表，注册xtable和hook
    err = ipt_register_table(net, &packet_filter, repl, filter_ops);
    kfree(repl);
    return err;
}
```

`.pre_exit`接口设置为`iptable_filter_net_pre_exit`，在退出网络命名空间前调用，其实现如下：

```C
// file: net/ipv4/netfilter/iptable_filter.c
static void __net_exit iptable_filter_net_pre_exit(struct net *net)
{   
    // 注销`ipv4.iptable_filter`hook信息
    ipt_unregister_table_pre_exit(net, "filter");
}
// file: net/ipv4/netfilter/ip_tables.c
void ipt_unregister_table_pre_exit(struct net *net, const char *name)
{   
    // 获取`net->ipv4.iptable_xxx`表
    struct xt_table *table = xt_find_table(net, NFPROTO_IPV4, name);
    // 表存在时，注销hook
    if (table) nf_unregister_net_hooks(net, table->ops, hweight32(table->valid_hooks));
}
```

`.exit`接口设置为`iptable_filter_net_exit`，在退出网络命名空间时调用，其实现如下：

```C
// file: net/ipv4/netfilter/iptable_filter.c
static void __net_exit iptable_filter_net_exit(struct net *net)
{
    // 注销`ipv4.iptable_filter`表
    ipt_unregister_table_exit(net, "filter");
}
// file: net/ipv4/netfilter/ip_tables.c
void ipt_unregister_table_exit(struct net *net, const char *name)
{   
    // 获取`net->ipv4.iptable_xxx`表
    struct xt_table *table = xt_find_table(net, NFPROTO_IPV4, name);
    // 表存在时，注销表
    if (table) __ipt_unregister_table(net, table);
}
```

##### 4 ipv4注册/注销`table`

Linux内核中`ip_tables`,`ip6_tables`,`arp_tables`分别通过`ipt_[un]register_table`,`ip6t_[un]register_table`,`arpt_[un]register_table`函数注册/注销`table`。我们以`ip_tables`为例，`ipt_register_table`函数实现ip_table的注册，如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
int ipt_register_table(struct net *net, const struct xt_table *table,
            const struct ipt_replace *repl, const struct nf_hook_ops *template_ops)
{
    struct nf_hook_ops *ops;
    struct xt_table_info *newinfo;
    struct xt_table_info bootstrap = {0};
    void *loc_cpu_entry;
    struct xt_table *new_table;

    // 分配`xt_table_info`
    newinfo = xt_alloc_table_info(repl->size);
    if (!newinfo) return -ENOMEM;
    // 复制替换信息(`repl`)的防火墙规则到`newinfo`
    loc_cpu_entry = newinfo->entries;
    memcpy(loc_cpu_entry, repl->entries, repl->size);

    // 转换防火墙表，检查防火墙规则中的`match`和`target`是否合法
    ret = translate_table(net, newinfo, loc_cpu_entry, repl);
    if (ret != 0) { ... }
    
    // 注册xtable，失败时清除设置的规则
    new_table = xt_register_table(net, table, &bootstrap, newinfo);
    if (IS_ERR(new_table)) {
        struct ipt_entry *iter;
        // 清理防火墙规则
        xt_entry_foreach(iter, loc_cpu_entry, newinfo->size)
            cleanup_entry(iter, net);
        xt_free_table_info(newinfo);
        return PTR_ERR(new_table);
    }
    // 没有模板时，直接返回。这是'nat'表使用的，它注册到nat核心而不是netfilter核心。
    if (!template_ops) return 0;

    // 计算hook的数量
    num_ops = hweight32(table->valid_hooks);
    if (num_ops == 0) { ret = -EINVAL; goto out_free; }

    // 复制`template_ops`到`ops`
    ops = kmemdup(template_ops, sizeof(*ops) * num_ops, GFP_KERNEL);
    if (!ops) { ret = -ENOMEM; goto out_free; }

    // `ops`和`new_table`相互关联
    for (i = 0; i < num_ops; i++)
        ops[i].priv = new_table;
    new_table->ops = ops;

    // 注册net_hooks
    ret = nf_register_net_hooks(net, ops, num_ops);
    if (ret != 0) goto out_free;

    return ret;
out_free:
    // 失败时，注销防火墙表
    __ipt_unregister_table(net, new_table);
    return ret;
}
```

`__ipt_unregister_table` 函数注销防火墙表，如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static void __ipt_unregister_table(struct net *net, struct xt_table *table)
{
    struct xt_table_info *private;
    void *loc_cpu_entry;
    struct module *table_owner = table->me;
    struct ipt_entry *iter;
    // 注销xtables
    private = xt_unregister_table(table);

    // 减少模块引用计数，释放资源
    loc_cpu_entry = private->entries;
    // 清理防火墙规则
    xt_entry_foreach(iter, loc_cpu_entry, private->size)
        cleanup_entry(iter, net);
    if (private->number > private->initial_entries)
        module_put(table_owner);
    // 释放`xt_table_info`
    xt_free_table_info(private);
}
```

##### 5 注册/注销`xtable`

`ip_tables`,`ip6_tables`,`arp_tables`使用的都是`xtable`。`xt_register_table`函数实现`xtable`的注册，如下：

```C
// file: net/netfilter/x_tables.c
struct xt_table *xt_register_table(struct net *net, const struct xt_table *input_table,
                    struct xt_table_info *bootstrap, struct xt_table_info *newinfo)
{
    struct xt_pernet *xt_net = net_generic(net, xt_pernet_id);
    struct xt_table_info *private;
    struct xt_table *t, *table;
    int ret;

    // 复制xt_table信息
    table = kmemdup(input_table, sizeof(struct xt_table), GFP_KERNEL);
    if (!table) { ret = -ENOMEM; goto out; }

    mutex_lock(&xt[table->af].mutex);
    // 检查是否已经注册过
    list_for_each_entry(t, &xt_net->tables[table->af], list) {
        if (strcmp(t->name, table->name) == 0) { ret = -EEXIST; goto unlock; }
    }
    // 设置`table->private`为`bootstrap`
    table->private = bootstrap;
    // 替换xt_table, 设置`table->private`为`newinfo`
    if (!xt_replace_table(table, 0, newinfo, &ret)) goto unlock;

    private = table->private;
    pr_debug("table->private->number = %u\n", private->number);
    // 保存初始条目数
    private->initial_entries = private->number;

    // 添加到`tables`列表中
    list_add(&table->list, &xt_net->tables[table->af]);
    mutex_unlock(&xt[table->af].mutex);
    return table;
    // 失败时的清理
unlock:
    mutex_unlock(&xt[table->af].mutex);
    kfree(table);
out:
    return ERR_PTR(ret);
}
```

`xt_unregister_table`函数注销`xt_table`，如下：

```C
// file: net/netfilter/x_tables.c
void *xt_unregister_table(struct xt_table *table)
{
    struct xt_table_info *private;
    mutex_lock(&xt[table->af].mutex);
    private = table->private;
    // 从列表中删除
    list_del(&table->list);
    mutex_unlock(&xt[table->af].mutex);
    // 记录日志信息
    audit_log_nfcfg(table->name, table->af, private->number, AUDIT_XT_OP_UNREGISTER, GFP_KERNEL);
    // 释放`table->ops`和`table`
    kfree(table->ops);
    kfree(table);
    return private;
}
```

##### 6 注册/注销`nfhooks`

`nf_register_net_hook`和`nf_register_net_hooks`函数实现一个或多个`nfhook`的注册。以注册单个hook为例，如下：

```C
// file: net/netfilter/core.c
int nf_register_net_hook(struct net *net, const struct nf_hook_ops *reg)
{
    int err;
    if (reg->pf == NFPROTO_INET) {
        if (reg->hooknum == NF_INET_INGRESS) {
            err = __nf_register_net_hook(net, NFPROTO_INET, reg);
            if (err < 0) return err;
        } else {
            // NFPROTO_INET时，注册ipv4和ipv6
            err = __nf_register_net_hook(net, NFPROTO_IPV4, reg);
            if (err < 0) return err;
            err = __nf_register_net_hook(net, NFPROTO_IPV6, reg);
            if (err < 0) {
                __nf_unregister_net_hook(net, NFPROTO_IPV4, reg);
                return err;
            }
        }
    } else {
        // 注册其他协议的hook
        err = __nf_register_net_hook(net, reg->pf, reg);
        if (err < 0) return err;
    }
    return 0;
}
```

`__nf_register_net_hook`函数实现`nfhook`的注册，如下：

```C
// file: net/netfilter/core.c
static int __nf_register_net_hook(struct net *net, int pf, const struct nf_hook_ops *reg)
{
    struct nf_hook_entries *p, *new_hooks;
    struct nf_hook_entries __rcu **pp;
    int err;

    // NETDEV和INET两种协议支持的hook检查，
    switch (pf) {
    case NFPROTO_NETDEV: ... break;
    case NFPROTO_INET: ... break;
    }

    // 获取hooks列表指针
    pp = nf_hook_entry_head(net, pf, reg->hooknum, reg->dev);
    if (!pp) return -EINVAL;

    mutex_lock(&nf_hook_mutex);
    p = nf_entry_dereference(*pp);
    // 创建新的内存空间，复制旧的hooks后，添加新的hook
    new_hooks = nf_hook_entries_grow(p, reg);

    // new_hooks正常，则修改hooks列表地址指向位置，完成hooks的修改
    if (!IS_ERR(new_hooks)) {
        // 验证hooks，调整优先级
        hooks_validate(new_hooks);
        // 修改hooks列表地址指向位置，完成hooks的修改
        rcu_assign_pointer(*pp, new_hooks);
    }
    mutex_unlock(&nf_hook_mutex);
    // new_hooks有错误，则返回错误码
    if (IS_ERR(new_hooks)) return PTR_ERR(new_hooks);

    // ingress/egress hook时，增加队列长度
    if (nf_ingress_hook(reg, pf)) net_inc_ingress_queue();
    if (nf_egress_hook(reg, pf)) net_inc_egress_queue();
    // 增加hooks的static_key计数
    nf_static_key_inc(reg, pf);

    // 释放旧的hooks
    nf_hook_entries_free(p);
    return 0;
}
```

`nf_hook_entry_head`函数获取对应协议和hooknum的hooks列表指针，如下：

```C
// file: net/netfilter/core.c
static struct nf_hook_entries __rcu **
nf_hook_entry_head(struct net *net, int pf, unsigned int hooknum, struct net_device *dev)
{
    switch (pf) {
    case NFPROTO_NETDEV: break;
    case NFPROTO_ARP:
        // 获取net->nf.hooks_arp[hooknum]
        if (WARN_ON_ONCE(ARRAY_SIZE(net->nf.hooks_arp) <= hooknum)) return NULL;
        return net->nf.hooks_arp + hooknum;
    case NFPROTO_BRIDGE:
        // 获取net->nf.hooks_bridge[hooknum]
        if (WARN_ON_ONCE(ARRAY_SIZE(net->nf.hooks_bridge) <= hooknum)) return NULL;
        return net->nf.hooks_bridge + hooknum;
    case NFPROTO_INET:
        // NFPROTO_INET::NF_INET_INGRESS对应网卡设备的`dev->nf_hooks_ingress`
        if (WARN_ON_ONCE(hooknum != NF_INET_INGRESS)) return NULL;
        if (!dev || dev_net(dev) != net) { WARN_ON_ONCE(1); return NULL; }
        return &dev->nf_hooks_ingress;
    case NFPROTO_IPV4:
        // 获取net->nf.hooks_ipv4[hooknum]
        if (WARN_ON_ONCE(ARRAY_SIZE(net->nf.hooks_ipv4) <= hooknum)) return NULL;
        return net->nf.hooks_ipv4 + hooknum;
    case NFPROTO_IPV6:
        // 获取net->nf.hooks_ipv6[hooknum]
        if (WARN_ON_ONCE(ARRAY_SIZE(net->nf.hooks_ipv6) <= hooknum)) return NULL;
        return net->nf.hooks_ipv6 + hooknum;
    default:
        // 默认返回NULL
        WARN_ON_ONCE(1); return NULL;
    }
    // NFPROTO_NETDEV:NF_NETDEV_IN[E]GRESS，对应网卡设备的`dev->nf_hooks_in[e]gress`
    if (hooknum == NF_NETDEV_INGRESS) {
        if (dev && dev_net(dev) == net) return &dev->nf_hooks_ingress;
    }
    if (hooknum == NF_NETDEV_EGRESS) {
        if (dev && dev_net(dev) == net) return &dev->nf_hooks_egress;
    }
    WARN_ON_ONCE(1);
    return NULL;
}
```

`nf_hook_entries_grow`函数实现hooks表的动态扩容，实现如下：

```C
// file: net/netfilter/core.c
static struct nf_hook_entries *nf_hook_entries_grow(const struct nf_hook_entries *old, const struct nf_hook_ops *reg)
{
    unsigned int i, alloc_entries, nhooks, old_entries;
    struct nf_hook_ops **orig_ops = NULL;
    struct nf_hook_ops **new_ops;
    struct nf_hook_entries *new;
    bool inserted = false;

    // 默认增加一个hooks
    alloc_entries = 1;
    old_entries = old ? old->num_hook_entries : 0;

    if (old) {
        // 获取旧的hooks中有效的hook数量
        orig_ops = nf_hook_entries_get_hook_ops(old);
        for (i = 0; i < old_entries; i++) {
            // dummy_ops表示删除的hook
            if (orig_ops[i] != &dummy_ops)
                alloc_entries++;
        }
    }
    // 每个family/hooknum最多支持1024个hook
    if (alloc_entries > MAX_HOOK_COUNT) return ERR_PTR(-E2BIG);

    // 创建新的hooks表
    new = allocate_hook_entries_size(alloc_entries);
    if (!new) return ERR_PTR(-ENOMEM);
    // 获取hook_ops位置
    new_ops = nf_hook_entries_get_hook_ops(new);

    i = 0;
    nhooks = 0;
    while (i < old_entries) {
        // 跳过删除的hook
        if (orig_ops[i] == &dummy_ops) { ++i; continue; }

        // 从旧表中复制hook_ops，注销的hook按照优先级插入到列表中
        if (inserted || reg->priority > orig_ops[i]->priority) {
            new_ops[nhooks] = (void *)orig_ops[i];
            new->hooks[nhooks] = old->hooks[i];
            i++;
        } else {
            new_ops[nhooks] = (void *)reg;
            new->hooks[nhooks].hook = reg->hook;
            new->hooks[nhooks].priv = reg->priv;
            inserted = true;
        }
        nhooks++;
    }
    // 默认情况，注册的hook没有添加时，添加到最后
    if (!inserted) {
        new_ops[nhooks] = (void *)reg;
        new->hooks[nhooks].hook = reg->hook;
        new->hooks[nhooks].priv = reg->priv;
    }
    return new;
}
```

`allocate_hook_entries_size`函数分配hooks列表需要的内存，`nf_hook_entries`按照 `nf_hook_entries | nf_hook_entry * num | nf_hook_ops * num | nf_hook_entries_rcu_head` 的内存分布注册hook列表。如下：

```C
// file: net/netfilter/core.c
static struct nf_hook_entries *allocate_hook_entries_size(u16 num)
{
    struct nf_hook_entries *e;
    size_t alloc = sizeof(*e) +
                sizeof(struct nf_hook_entry) * num +
                sizeof(struct nf_hook_ops *) * num +
                sizeof(struct nf_hook_entries_rcu_head);
    // num为0时，直接返回
    if (num == 0) return NULL;
    // 分配需要的内存空间，设置hooks的数量
    e = kvzalloc(alloc, GFP_KERNEL_ACCOUNT);
    if (e) e->num_hook_entries = num;
    return e;
}
```

`nf_unregister_net_hook`和`nf_unregister_net_hooks`函数实现一个或多个`nfhook`的注销。以注销单个hook为例，如下：

```C
// file: net/netfilter/core.c
void nf_unregister_net_hook(struct net *net, const struct nf_hook_ops *reg)
{
    if (reg->pf == NFPROTO_INET) {
        if (reg->hooknum == NF_INET_INGRESS) {
            __nf_unregister_net_hook(net, NFPROTO_INET, reg);
        } else {
            __nf_unregister_net_hook(net, NFPROTO_IPV4, reg);
            __nf_unregister_net_hook(net, NFPROTO_IPV6, reg);
        }
    } else {
        __nf_unregister_net_hook(net, reg->pf, reg);
    }
}
```

`__nf_unregister_net_hook`函数实现单个hook的注销，如下：

```C
// file: net/netfilter/core.c
static void __nf_unregister_net_hook(struct net *net, int pf, const struct nf_hook_ops *reg)
{
    struct nf_hook_entries __rcu **pp;
    struct nf_hook_entries *p;

    // 获取hooks列表指针
    pp = nf_hook_entry_head(net, pf, reg->hooknum, reg->dev);
    if (!pp) return;

    mutex_lock(&nf_hook_mutex);
    p = nf_entry_dereference(*pp);
    // 检查指向的hook是否存在，不存在时返回
    if (WARN_ON_ONCE(!p)) { mutex_unlock(&nf_hook_mutex); return; }

    // 删除hook，将对应的hook_ops标记为`dummy_ops`
    if (nf_remove_net_hook(p, reg)) {
        // 删除成功后，减少hooks的static_key计数
        if (nf_ingress_hook(reg, pf)) net_dec_ingress_queue();
        if (nf_egress_hook(reg, pf)) net_dec_egress_queue();
        nf_static_key_dec(reg, pf);
    } else {
        WARN_ONCE(1, "hook not found, pf %d num %d", pf, reg->hooknum);
    }
    // 收缩hooks列表，返回旧的hooks列表
    p = __nf_hook_entries_try_shrink(p, pp);
    mutex_unlock(&nf_hook_mutex);
    if (!p) return;

    // nf_queue_handler删除nf_hook
    nf_queue_nf_hook_drop(net);
    // 释放旧的hooks列表
    nf_hook_entries_free(p);
}
```

`nf_remove_net_hook`函数删除指定hook，将对应的hook_ops设置为`dummy_ops`，如下：

```C
// file: net/netfilter/core.c
static bool nf_remove_net_hook(struct nf_hook_entries *old, const struct nf_hook_ops *unreg)
{
    struct nf_hook_ops **orig_ops;
    unsigned int i;
    // 获取hook_ops列表指针
    orig_ops = nf_hook_entries_get_hook_ops(old);
    for (i = 0; i < old->num_hook_entries; i++) {
        if (orig_ops[i] != unreg) continue;
        // 确定删除的hook后，设置hook接口为accept_all，表示所有数据包都通过
        WRITE_ONCE(old->hooks[i].hook, accept_all);
        // 设置hook_ops为`dummy_ops`，表示删除成功
        WRITE_ONCE(orig_ops[i], (void *)&dummy_ops);
        return true;
    }
    return false;
}
```

`__nf_hook_entries_try_shrink`函数重新计算hooks列表需要的内存空间，释放已删除的hook，如下：

```C
// file: net/netfilter/core.c
static void *__nf_hook_entries_try_shrink(struct nf_hook_entries *old, struct nf_hook_entries __rcu **pp)
{
    unsigned int i, j, skip = 0, hook_entries;
    struct nf_hook_entries *new = NULL;
    struct nf_hook_ops **orig_ops;
    struct nf_hook_ops **new_ops;

    if (WARN_ON_ONCE(!old)) return NULL;
    // 计算已经删除的hook个数
    orig_ops = nf_hook_entries_get_hook_ops(old);
    for (i = 0; i < old->num_hook_entries; i++) {
        if (orig_ops[i] == &dummy_ops) skip++;
    }
    // 所有hook都删除时，进行设置操作，此时设置为NULL
    hook_entries = old->num_hook_entries;
    if (skip == hook_entries) goto out_assign;

    // 不存在删除的，直接返回
    if (skip == 0) return NULL;
    // 重新计算hook数量后，分配内存空间
    hook_entries -= skip;
    new = allocate_hook_entries_size(hook_entries);
    if (!new) return NULL;

    // 复制旧的hook到新的hooks列表中，跳过`dummy_ops`
    new_ops = nf_hook_entries_get_hook_ops(new);
    for (i = 0, j = 0; i < old->num_hook_entries; i++) {
        if (orig_ops[i] == &dummy_ops)
            continue;
        // 复制hook和hook_ops
        new->hooks[j] = old->hooks[i];
        new_ops[j] = (void *)orig_ops[i];
        j++;
    }
    // 验证hooks列表
    hooks_validate(new);
out_assign:
    // 将hooks列表地址指向新的hooks列表，完成hooks的修改
    rcu_assign_pointer(*pp, new);
    return old;
}
```

`nf_hook_entries_free`函数释放hooks列表，如下：

```C
// file: net/netfilter/core.c
static void nf_hook_entries_free(struct nf_hook_entries *e)
{
    struct nf_hook_entries_rcu_head *head;
    struct nf_hook_ops **ops;
    unsigned int num;
    if (!e) return;

    // 获取hook_ops
    num = e->num_hook_entries;
    ops = nf_hook_entries_get_hook_ops(e);
    // 最后一个hook_ops后面是`nf_hook_entries_rcu_head`
    head = (void *)&ops[num];
    head->allocation = e;
    // rcu释放hook列表
    call_rcu(&head->head, __nf_hook_entries_free);
}
```

### 4.2 RAW socket的操作接口

#### (1) 原始socket的内核定义

`iptables`修改防火墙规则时，在创建原始socket后，通过原始socket进行防火墙规则的获取、修改、创建等操作。在Linux内核中，`inetsw_array`变量定义了创建ipv4 socket时支持的协议类型，其中包括原始socket，如下：

```C
// file: net/ipv4/af_inet.c
static struct inet_protosw inetsw_array[] =
{
    ...
    {
        .type =     SOCK_RAW,
        .protocol = IPPROTO_IP,
        .prot =     &raw_prot,
        .ops =      &inet_sockraw_ops,
        .flags =    INET_PROTOSW_REUSE,
    }
};
```

`SOCK_RAW`设置的`prot`为`raw_prot`，定义如下：

```C
// file: net/ipv4/raw.c
struct proto raw_prot = {
    .name           = "RAW",
    .owner          = THIS_MODULE,
    .close          = raw_close,
    .destroy        = raw_destroy,
    .connect        = ip4_datagram_connect,
    .disconnect     = __udp_disconnect,
    .ioctl          = raw_ioctl,
    .init           = raw_sk_init,
    .setsockopt     = raw_setsockopt,
    .getsockopt     = raw_getsockopt,
    .sendmsg        = raw_sendmsg,
    .recvmsg        = raw_recvmsg,
    ...
};
```

`raw_prot`和`inetsw_array`都在`fs_initcall`阶段初始化，如下：

```C
// file: net/ipv4/af_inet.c
static int __init inet_init(void)
{
    // 注册RAW协议类型
    rc = proto_register(&raw_prot, 1);
    ...
    // 注册ipv4网络家族
    (void)sock_register(&inet_family_ops);
    ...
    // 注册创建socket的软件协议
    for (q = inetsw_array; q < &inetsw_array[INETSW_ARRAY_LEN]; ++q)
        inet_register_protosw(q);
    ...
}
fs_initcall(inet_init);
```

`inet_protosw[]->ops`定义了sock的`connect`、`send`、`recv`等操作接口，原始socket的ops设置为`inet_sockraw_ops`，定义如下：

```C
// file: net/ipv4/af_inet.c
static const struct proto_ops inet_sockraw_ops = {
    .family         = PF_INET,
    .owner          = THIS_MODULE,
    .release        = inet_release,
    .bind           = inet_bind,
    .connect        = inet_dgram_connect,
    .socketpair     = sock_no_socketpair,
    .accept         = sock_no_accept,
    .getname        = inet_getname,
    .poll           = datagram_poll,
    .ioctl          = inet_ioctl,
    .gettstamp      = sock_gettstamp,
    .listen         = sock_no_listen,
    .shutdown       = inet_shutdown,
    .setsockopt     = sock_common_setsockopt,
    .getsockopt     = sock_common_getsockopt,
    .sendmsg        = inet_sendmsg,
    .recvmsg        = inet_recvmsg,
    .mmap           = sock_no_mmap,
    .sendpage       = inet_sendpage,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = inet_compat_ioctl,
#endif
};
```

#### (2) `getsockopt`的实现过程

##### 1 `getsockopt`系统调用

`getsockopt`系统调用用于获取socket的选项设置，在内核中实现如下：

```C
// file: net/socket.c
SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname, char __user *, optval, int __user *, optlen)
{
    return __sys_getsockopt(fd, level, optname, optval, optlen);
}
// file: net/socket.c
int __sys_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
    int err, fput_needed;
    struct socket *sock;
    int max_optlen;
    // 通过fd获取sock
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (!sock) return err;
    // 安全检查
    err = security_socket_getsockopt(sock, level, optname);
    if (err) goto out_put;
    // CGROUP_GETSOCKOPT检查opetlen
    if (!in_compat_syscall())
        max_optlen = BPF_CGROUP_GETSOCKOPT_MAX_OPTLEN(optlen);

    if (level == SOL_SOCKET)
        // SOCKET级别，通过`sock_getsockopt`获取
        err = sock_getsockopt(sock, level, optname, optval, optlen);
    else if (unlikely(!sock->ops->getsockopt))
        err = -EOPNOTSUPP;
    else
        // 其他级别，通过`ops->getsockopt`接口获取
        err = sock->ops->getsockopt(sock, level, optname, optval, optlen);

    // CGROUP_GETSOCKOPT运行BPF程序
    if (!in_compat_syscall())
        err = BPF_CGROUP_RUN_PROG_GETSOCKOPT(sock->sk, level, optname, optval, optlen, max_optlen, err);
out_put:
    fput_light(sock->file, fput_needed);
    return err;
}
```

原始socket的`sock->ops`设置为`inet_sockraw_ops`, 其`.getsockopt`接口设置为`sock_common_getsockopt`，执行`sk->sk_prot`的`getsockopt`接口，实现如下：

```C
// file: net/core/sock.c
int sock_common_getsockopt(struct socket *sock, int level, int optname, 
            char __user *optval, int __user *optlen)
{
    struct sock *sk = sock->sk;
    return READ_ONCE(sk->sk_prot)->getsockopt(sk, level, optname, optval, optlen);
}
```

##### 2 `raw_getsockopt`的实现过程

原始socket的`sk_prot`设置为`raw_prot`，其`.getsockopt`接口设置为`raw_getsockopt`，实现如下：

```C
// file: net/ipv4/raw.c
static int raw_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen)
{   
    // 不是`SOL_RAW`调用`ip_getsockopt`获取IP选项设置，否则获取原始socket的选项设置
    if (level != SOL_RAW) 
        return ip_getsockopt(sk, level, optname, optval, optlen);
    return do_raw_getsockopt(sk, level, optname, optval, optlen);
}
```

在获取防火墙规则时，设置的level为`TC_IPPROTO`(即：`IPPROTO_IP`), 因此执行`ip_getsockopt`，其实现如下：

```C
// file: net/ipv4/ip_sockglue.c
int ip_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen)
{
    int err;
    // 获取ip选择设置
    err = do_ip_getsockopt(sk, level, optname, USER_SOCKPTR(optval), USER_SOCKPTR(optlen));

#if IS_ENABLED(CONFIG_BPFILTER_UMH)
    // bpfilter获取ip选项设置
    if (optname >= BPFILTER_IPT_SO_GET_INFO && optname < BPFILTER_IPT_GET_MAX)
        err = bpfilter_ip_get_sockopt(sk, optname, optval, optlen);
#endif
#ifdef CONFIG_NETFILTER
    if (err == -ENOPROTOOPT && optname != IP_PKTOPTIONS && !ip_mroute_opt(optname)) {
        int len;
        // 获取选项长度
        if (get_user(len, optlen)) return -EFAULT;
        // netfilter获取ip选项设置
        err = nf_getsockopt(sk, PF_INET, optname, optval, &len);
        if (err >= 0) err = put_user(len, optlen);
        return err;
    }
#endif
    return err;
}
```

##### 3 `nf_getsockopt`的实现过程

在获取防火墙规则信息时，选项值在`NETFILTER`范围内，对应的`nf_getsockopt`函数获取netfilter选择设置，实现如下：

```C
// file: net/netfilter/nf_sockopt.c
int nf_getsockopt(struct sock *sk, u_int8_t pf, int val, char __user *opt, int *len)
{
    struct nf_sockopt_ops *ops;
    int ret;
    // 从`nf_sockopts`列表中获取指定协议的选项操作接口
    ops = nf_sockopt_find(sk, pf, val, 1);
    if (IS_ERR(ops)) return PTR_ERR(ops);
    // 调用`get`接口
    ret = ops->get(sk, val, opt, len);
    module_put(ops->owner);
    return ret;
}
```

#### (3) `setsockopt`的实现过程

##### 1 `setsockopt`系统调用

`setsockopt`系统调用用于设置socket的选项值，在内核中实现如下：

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

原始socket的`sock->ops`设置为`inet_sockraw_ops`, 其`.setsockopt`接口设置为`sock_common_setsockopt`，执行`sk->sk_prot`的`setsockopt`接口，实现如下：

```C
// file: net/core/sock.c
int sock_common_setsockopt(struct socket *sock, int level, int optname, sockptr_t optval, unsigned int optlen)
{
    struct sock *sk = sock->sk;
    return READ_ONCE(sk->sk_prot)->setsockopt(sk, level, optname, optval, optlen);
}
```

##### 2 `raw_setsockopt`的实现过程

原始socket的`sk_prot`设置为`raw_prot`，其`.setsockopt`接口设置为`raw_setsockopt`，实现如下：

```C
// file: net/ipv4/raw.c
static int raw_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen)
{
    // 不是`SOL_RAW`调用`ip_setsockopt`设置IP选项设置，否则设置原始socket的选项设置
    if (level != SOL_RAW)
        return ip_setsockopt(sk, level, optname, optval, optlen);
    return do_raw_setsockopt(sk, level, optname, optval, optlen);
}
```

在获取防火墙规则时，设置的level为`TC_IPPROTO`(即：`IPPROTO_IP`), 因此执行`ip_setsockopt`，其实现如下：

```C
// file: net/ipv4/ip_sockglue.c
int ip_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen)
{
    int err;
    // level必须为SOL_IP
    if (level != SOL_IP) return -ENOPROTOOPT;
    // ip选择设置
    err = do_ip_setsockopt(sk, level, optname, optval, optlen);
#if IS_ENABLED(CONFIG_BPFILTER_UMH)
    // bpffilter选项设置
    if (optname >= BPFILTER_IPT_SO_SET_REPLACE && optname < BPFILTER_IPT_SET_MAX)
        err = bpfilter_ip_set_sockopt(sk, optname, optval, optlen);
#endif
#ifdef CONFIG_NETFILTER
    if (err == -ENOPROTOOPT && optname != IP_HDRINCL && optname != IP_IPSEC_POLICY && 
            optname != IP_XFRM_POLICY && !ip_mroute_opt(optname))
        // netfilter选项设置
        err = nf_setsockopt(sk, PF_INET, optname, optval, optlen);
#endif
    return err;
}
```

##### 3 `nf_setsockopt`的实现过程

`nf_setsockopt`函数实现netfilter选项设置，实现如下：

```C
// file: net/netfilter/nf_sockopt.c
int nf_getsockopt(struct sock *sk, u_int8_t pf, int val, char __user *opt, int *len)
{
    struct nf_sockopt_ops *ops;
    int ret;
    // 从`nf_sockopts`列表中获取指定协议的选项操作接口
    ops = nf_sockopt_find(sk, pf, val, 1);
    if (IS_ERR(ops)) return PTR_ERR(ops);
    // 调用`set`接口
    ret = ops->set(sk, val, opt, len);
    module_put(ops->owner);
    return ret;
}
```

#### (4) `nf_sockopt_ops`的注册/注销过程

`nf_set[get]sockopt`函数通过`nf_sockopt_find`函数获取`nf_sockopt_ops`结构，这些结构通过`nf_register_sockopt`函数注册到内核中。注册过程实现如下：

```C
// file: net/netfilter/nf_sockopt.c
int nf_register_sockopt(struct nf_sockopt_ops *reg)
{
    struct nf_sockopt_ops *ops;
    int ret = 0;
    mutex_lock(&nf_sockopt_mutex);
    // 遍历`nf_sockopts`列表，检查是否存在是否存在冲突
    list_for_each_entry(ops, &nf_sockopts, list) {
        if (ops->pf == reg->pf && 
            (overlap(ops->set_optmin, ops->set_optmax, reg->set_optmin, reg->set_optmax) || 
             overlap(ops->get_optmin, ops->get_optmax, reg->get_optmin, reg->get_optmax))) {
            // 相同网络协议的ops，选项重叠时提示
            pr_debug("nf_sock overlap: %u-%u/%u-%u v %u-%u/%u-%u\n", 
                ops->set_optmin, ops->set_optmax, ops->get_optmin, ops->get_optmax,
                reg->set_optmin, reg->set_optmax, reg->get_optmin, reg->get_optmax);
            ret = -EBUSY;
            goto out;
        }
    }
    // 添加到`nf_sockopts`列表中
    list_add(&reg->list, &nf_sockopts);
out:
    mutex_unlock(&nf_sockopt_mutex);
    return ret;
}
```

`nf_unregister_sockopt`函数实现`nf_sockopt_ops`的注销，如下：

```C
// file: net/netfilter/nf_sockopt.c
void nf_unregister_sockopt(struct nf_sockopt_ops *reg)
{
    mutex_lock(&nf_sockopt_mutex);
    // 从列表中删除
    list_del(&reg->list);
    mutex_unlock(&nf_sockopt_mutex);
}
```

### 4.3 `ipt_sockopts`的实现过程

ipv4使用的`nf_sockopt_ops`为`ipt_sockopts`，定义如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static struct nf_sockopt_ops ipt_sockopts = {
    .pf         = PF_INET,
    .set_optmin = IPT_BASE_CTL,
    .set_optmax = IPT_SO_SET_MAX+1,
    .set        = do_ipt_set_ctl,
    .get_optmin = IPT_BASE_CTL,
    .get_optmax = IPT_SO_GET_MAX+1,
    .get        = do_ipt_get_ctl,
    .owner      = THIS_MODULE,
};
```

#### (1) 注册/注销的过程

`ipt_sockopts`通过`module_init/module_exit`函数进行初始化和清理，如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int __init ip_tables_init(void)
{
    int ret;
    // 注册网络命名空间操作接口
    ret = register_pernet_subsys(&ip_tables_net_ops);
    if (ret < 0) goto err1;
    // 注册ipt内置的target，标志target和错误target
    ret = xt_register_targets(ipt_builtin_tg, ARRAY_SIZE(ipt_builtin_tg));
    if (ret < 0) goto err2;
    // 注册ipt内置的match，`icmp`匹配
    ret = xt_register_matches(ipt_builtin_mt, ARRAY_SIZE(ipt_builtin_mt));
    if (ret < 0) goto err4;
    // 注册ipt_sockopts
    ret = nf_register_sockopt(&ipt_sockopts);
    if (ret < 0) goto err5;
    return 0;
    ...
}
// file: net/ipv4/netfilter/ip_tables.c
static void __exit ip_tables_fini(void)
{   
    // 注销ipt_sockopts
    nf_unregister_sockopt(&ipt_sockopts);
    // 注销ipt内置的match
    xt_unregister_matches(ipt_builtin_mt, ARRAY_SIZE(ipt_builtin_mt));
    // 注销ipt内置的target
    xt_unregister_targets(ipt_builtin_tg, ARRAY_SIZE(ipt_builtin_tg));
    // 注销网络命名空间操作接口
    unregister_pernet_subsys(&ip_tables_net_ops);
}
module_init(ip_tables_init);
module_exit(ip_tables_fini);
```

#### (2) `SO_GET_INFO`的实现

`do_ipt_get_ctl`函数实现`IPT_SO_GET_XXX`的处理，如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int do_ipt_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
    int ret;
    // 权限检查，需要NET_ADMIN权限
    if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN)) return -EPERM;
    // 根据选项进行不同操作
    switch (cmd) {
    case IPT_SO_GET_INFO:
        ret = get_info(sock_net(sk), user, len);
        break;
    ...
    default:
        ret = -EINVAL;
    }
    return ret;
}
```

`IPT_SO_GET_INFO`选项获取指定表设置的防火墙信息，对应`get_info`函数，实现如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int get_info(struct net *net, void __user *user, const int *len)
{
    char name[XT_TABLE_MAXNAMELEN];
    struct xt_table *t;
    int ret;
    // 用户空间设置的选项长度必须为`ipt_getinfo`
    if (*len != sizeof(struct ipt_getinfo)) return -EINVAL;
    // 复制用户空间设置的表名称
    if (copy_from_user(name, user, sizeof(name)) != 0) return -EFAULT;
    name[XT_TABLE_MAXNAMELEN-1] = '\0';
    ...
    // 获取指定表
    t = xt_request_find_table_lock(net, AF_INET, name);
    if (!IS_ERR(t)) {
        struct ipt_getinfo info;
        // 获取表信息
        const struct xt_table_info *private = t->private;
        ...
        // 内核空间生成结果
        memset(&info, 0, sizeof(info));
        info.valid_hooks = t->valid_hooks;
        memcpy(info.hook_entry, private->hook_entry, sizeof(info.hook_entry));
        memcpy(info.underflow, private->underflow, sizeof(info.underflow));
        info.num_entries = private->number;
        info.size = private->size;
        strcpy(info.name, name);

        // 复制结果到用户空间，设置返回码
        if (copy_to_user(user, &info, *len) != 0) ret = -EFAULT;
        else ret = 0;

        xt_table_unlock(t);
        module_put(t->me);
    } else
        ret = PTR_ERR(t);
    ...
    return ret;
}
```

`xt_request_find_table_lock`函数获取指定表，如下：

```C
// file: net/netfilter/x_tables.c
struct xt_table *xt_request_find_table_lock(struct net *net, u_int8_t af, const char *name)
{
    // 获取表
    struct xt_table *t = xt_find_table_lock(net, af, name);

#ifdef CONFIG_MODULES
    if (IS_ERR(t)) {
        // 以模块方式加载后，重新获取表
        int err = request_module("%stable_%s", xt_prefix[af], name);
        if (err < 0) return ERR_PTR(err);
        t = xt_find_table_lock(net, af, name);
    }
#endif
    return t;
}
```

`xt_find_table_lock`函数获取指定表，如下：

```C
// file: net/netfilter/x_tables.c
struct xt_table *xt_find_table_lock(struct net *net, u_int8_t af, const char *name)
{
    // 获取xt_pernet
    struct xt_pernet *xt_net = net_generic(net, xt_pernet_id);
    struct module *owner = NULL;
    struct xt_template *tmpl;
    struct xt_table *t;

    mutex_lock(&xt[af].mutex);
    // 在已注册的表中获取，存在时返回
    list_for_each_entry(t, &xt_net->tables[af], list)
        if (strcmp(t->name, name) == 0 && try_module_get(t->me))
            return t;
    // 表不存在时，检查表模板
    list_for_each_entry(tmpl, &xt_templates[af], list) {
        int err;
        if (strcmp(tmpl->name, name)) continue;
        if (!try_module_get(tmpl->me)) goto out;
        owner = tmpl->me;
        mutex_unlock(&xt[af].mutex);
        // 表模板初始化，在初始化过程中注册表
        err = tmpl->table_init(net);
        if (err < 0) { ... }
        mutex_lock(&xt[af].mutex);
        break;
    }
    // 再次从已注册的表中获取，存在时返回
    list_for_each_entry(t, &xt_net->tables[af], list)
        if (strcmp(t->name, name) == 0)  return t;

    module_put(owner);
 out:
    mutex_unlock(&xt[af].mutex);
    // 不存在时返回错误码
    return ERR_PTR(-ENOENT);
}
```

#### (3) `SO_GET_ENTRIES`的实现

`IPT_SO_GET_ENTRIES`选项获取指定表设置的防火墙列表，对应`get_entries`函数，实现如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int do_ipt_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
    ...
    switch (cmd) {
    ...
    case IPT_SO_GET_ENTRIES: 
        ret = get_entries(sock_net(sk), user, len); break;
    ...
    }
    return ret;
}
```

`get_entries`函数获取指定的表后，复制防火墙规则。实现如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int get_entries(struct net *net, struct ipt_get_entries __user *uptr, const int *len)
{
    int ret;
    struct ipt_get_entries get;
    struct xt_table *t;
    // 检查长度是否足够
    if (*len < sizeof(get)) return -EINVAL;
    // 复制用户空间的数据到内核空间
    if (copy_from_user(&get, uptr, sizeof(get)) != 0) return -EFAULT;
    // 检查长度是否匹配
    if (*len != sizeof(struct ipt_get_entries) + get.size) return -EINVAL;
    // 设置名称
    get.name[sizeof(get.name) - 1] = '\0';
    // 获取指定表
    t = xt_find_table_lock(net, AF_INET, get.name);
    if (!IS_ERR(t)) {
        const struct xt_table_info *private = t->private;
        if (get.size == private->size)
            // 长度一致时，复制防火墙信息到用户空间
            ret = copy_entries_to_user(private->size, t, uptr->entrytable);
        else
            ret = -EAGAIN;
        module_put(t->me);
        xt_table_unlock(t);
    } else
        ret = PTR_ERR(t);
    return ret;
}
```

`copy_entries_to_user`函数复制防火墙信息到用户空间，实现如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int copy_entries_to_user(unsigned int total_size, const struct xt_table *table, void __user *userptr)
{
    unsigned int off, num;
    const struct ipt_entry *e;
    struct xt_counters *counters;
    const struct xt_table_info *private = table->private;
    int ret = 0;
    const void *loc_cpu_entry;
    
    // 分配计数器信息，计算每个计数器的大小
    counters = alloc_counters(table);
    if (IS_ERR(counters)) return PTR_ERR(counters);

    loc_cpu_entry = private->entries;
    // 遍历每个防火墙信息
    for (off = 0, num = 0; off < total_size; off += e->next_offset, num++){
        unsigned int i;
        const struct xt_entry_match *m;
        const struct xt_entry_target *t;
        // 获取防火墙信息
        e = loc_cpu_entry + off;
        if (copy_to_user(userptr + off, e, sizeof(*e))) { ... }
        // 复制计数器信息
        if (copy_to_user(userptr + off + offsetof(struct ipt_entry, counters),
            &counters[num], sizeof(counters[num])) != 0) { ... }
        // 复制匹配信息(match)
        for (i = sizeof(struct ipt_entry); i < e->target_offset; i += m->u.match_size) {
            m = (void *)e + i;
            if (xt_match_to_user(m, userptr + off + i)) { ... }
        }
        // 复制目标信息(target)
        t = ipt_get_target_c(e);
        if (xt_target_to_user(t, userptr + off + e->target_offset)) { ... }
    }
 free_counters:
    vfree(counters);
    return ret;
}
```

`alloc_counters`函数分配计数器内存后，获取计数器数量，如下

```C
// file: net/ipv4/netfilter/ip_tables.c
static struct xt_counters *alloc_counters(const struct xt_table *table)
{
    unsigned int countersize;
    struct xt_counters *counters;
    const struct xt_table_info *private = table->private;

    // 获取计数器的快照，每条防火墙单独计数
    countersize = sizeof(struct xt_counters) * private->number;
    counters = vzalloc(countersize);
    if (counters == NULL) return ERR_PTR(-ENOMEM);
    // 获取防火墙计数器快照
    get_counters(private, counters);
    return counters;
}
```

`get_counters`函数获取计数器快照，实现如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static void get_counters(const struct xt_table_info *t, struct xt_counters counters[])
{
    struct ipt_entry *iter;
    unsigned int cpu;
    unsigned int i;
    // 遍历每个CPU
    for_each_possible_cpu(cpu) {
        seqcount_t *s = &per_cpu(xt_recseq, cpu);
        i = 0;
        // 变量每条防火墙
        xt_entry_foreach(iter, t->entries, t->size) {
            struct xt_counters *tmp;
            u64 bcnt, pcnt;
            unsigned int start;
            // 获取防火墙计数器
            tmp = xt_get_per_cpu_counter(&iter->counters, cpu);
            do {
                // 获取防火墙计数器
                start = read_seqcount_begin(s);
                bcnt = tmp->bcnt;
                pcnt = tmp->pcnt;
            } while (read_seqcount_retry(s, start));
            // 添加计数信息
            ADD_COUNTER(counters[i], bcnt, pcnt);
            ++i; /* macro does multi eval of i */
            cond_resched();
        }
    }
}
```

#### (4) `SO_GET_REVISION`的实现

`IPT_SO_GET_REVISION_MATCH`和`IPT_SO_GET_REVISION_TARGET`选项获取match和target的版本号，实现如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int do_ipt_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
    ...
    switch (cmd) {
    ...
    case IPT_SO_GET_REVISION_MATCH:
    case IPT_SO_GET_REVISION_TARGET: {
        struct xt_get_revision rev;
        int target;
        // 用户空间设置的长度不正确时返回
        if (*len != sizeof(rev)) { ... }
        // 拷贝用户空间设置的名称
        if (copy_from_user(&rev, user, sizeof(rev)) != 0) { ... }
        rev.name[sizeof(rev.name)-1] = 0;
        
        // 检查是否是获取target
        if (cmd == IPT_SO_GET_REVISION_TARGET) target = 1;
        else target = 0;

        // 获取版本信息，失败时加载module后重新获取
        try_then_request_module(
            xt_find_revision(AF_INET, rev.name, rev.revision, target, &ret), "ipt_%s", rev.name);
        break;
    }
    ...
    }
    return ret;
}
```

`xt_find_revision`函数获取match或target的版本号，实现如下：

```C
// file: net/netfilter/x_tables.c
int xt_find_revision(u8 af, const char *name, u8 revision, int target, int *err)
{
    int have_rev, best = -1;
    if (target == 1) 
        // 获取target的版本号
        have_rev = target_revfn(af, name, revision, &best);
    else 
        // 获取match的版本号
        have_rev = match_revfn(af, name, revision, &best);

    // 不存在最佳版本号，返回0尝试加载module
    if (best == -1) { *err = -ENOENT; return 0; }
    // 设置返回结果，出现错误时设置错误码
    *err = best;
    if (!have_rev) *err = -EPROTONOSUPPORT;
    return 1;
}
```

`target_revfn`函数获取target的版本号，实现如下：

```C
// file: net/netfilter/x_tables.c
static int target_revfn(u8 af, const char *name, u8 revision, int *bestp)
{
    const struct xt_target *t;
    int have_rev = 0;

    mutex_lock(&xt[af].mutex);
    // 遍历target链表，获取target的版本号
    list_for_each_entry(t, &xt[af].target, list) {
        if (strcmp(t->name, name) == 0) {
            // 设置最佳的版本号
            if (t->revision > *bestp) *bestp = t->revision;
            // 检查是否存在指定的版本号
            if (t->revision == revision) have_rev = 1;
        }
    }
    mutex_unlock(&xt[af].mutex);
    // 指定协议的target不存在时，获取`NFPROTO_UNSPEC`协议的target
    if (af != NFPROTO_UNSPEC && !have_rev)
        return target_revfn(NFPROTO_UNSPEC, name, revision, bestp);

    return have_rev;
}
```

`match_revfn`函数获取match的版本号，实现如下：

```C
// file: net/netfilter/x_tables.c
static int match_revfn(u8 af, const char *name, u8 revision, int *bestp)
{
    const struct xt_match *m;
    int have_rev = 0;

    mutex_lock(&xt[af].mutex);
    // 遍历match链表，获取match的版本号
    list_for_each_entry(m, &xt[af].match, list) {
        if (strcmp(m->name, name) == 0) {
            // 设置最佳的版本号
            if (m->revision > *bestp) *bestp = m->revision;
            // 检查是否存在指定的版本号
            if (m->revision == revision) have_rev = 1;
        }
    }
    mutex_unlock(&xt[af].mutex);
    // 指定协议的match不存在时，获取`NFPROTO_UNSPEC`协议的match
    if (af != NFPROTO_UNSPEC && !have_rev)
        return match_revfn(NFPROTO_UNSPEC, name, revision, bestp);
    
    return have_rev;
}
```

#### (5) `SO_SET_REPLACE`的实现

`do_ipt_set_ctl`函数实现`IPT_SO_SET_XXX`选项的处理，如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int do_ipt_set_ctl(struct sock *sk, int cmd, sockptr_t arg, unsigned int len)
{
    int ret;
    // 检查是否具有NET_ADMIN权限
    if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN)) return -EPERM;

    // 根据选项进行不同的设置
    switch (cmd) {
    case IPT_SO_SET_REPLACE:
        ret = do_replace(sock_net(sk), arg, len);
        break;
    case IPT_SO_SET_ADD_COUNTERS:
        ret = do_add_counters(sock_net(sk), arg, len);
        break;
    default:
        ret = -EINVAL;
    }
    return ret;
}
```

`SO_SET_REPLACE`选项设置iptables防火墙规则，对应`do_replace`函数，实现如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int do_replace(struct net *net, sockptr_t arg, unsigned int len)
{
    int ret;
    struct ipt_replace tmp;
    struct xt_table_info *newinfo;
    void *loc_cpu_entry;
    struct ipt_entry *iter;
    
    // 拷贝iptables替换信息到内核空间
    if (copy_from_sockptr(&tmp, arg, sizeof(tmp)) != 0) return -EFAULT;

    // 检查iptables规则数量是否溢出
    if (tmp.num_counters >= INT_MAX / sizeof(struct xt_counters)) return -ENOMEM;
    if (tmp.num_counters == 0) return -EINVAL;
    tmp.name[sizeof(tmp.name)-1] = 0;

    // 分配xtable信息
    newinfo = xt_alloc_table_info(tmp.size);
    if (!newinfo) return -ENOMEM;

    loc_cpu_entry = newinfo->entries;
    // 拷贝iptables规则到内核空间
    if (copy_from_sockptr_offset(loc_cpu_entry, arg, sizeof(tmp), tmp.size) != 0) { ... }

    // 转换iptables规则
    ret = translate_table(net, newinfo, loc_cpu_entry, &tmp);
    if (ret != 0) goto free_newinfo;
    // 替换iptables规则
    ret = __do_replace(net, tmp.name, tmp.valid_hooks, newinfo, tmp.num_counters, tmp.counters);
    if (ret) goto free_newinfo_untrans;

    return 0;

 free_newinfo_untrans:
    // 清理设置的iptables规则
    xt_entry_foreach(iter, loc_cpu_entry, newinfo->size) 
        cleanup_entry(iter, net);
 free_newinfo:
    // 释放xtable信息
    xt_free_table_info(newinfo);
    return ret;
}
```

##### 1 转换iptables规则

`translate_table`函数转换设置的规则，实现如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int translate_table(struct net *net, struct xt_table_info *newinfo, void *entry0, 
            const struct ipt_replace *repl)
{
    struct xt_percpu_counter_alloc_state alloc_state = { 0 };
    struct ipt_entry *iter;
    unsigned int *offsets;
    unsigned int i;
    int ret = 0;

    // 初始化xtable信息
    newinfo->size = repl->size;
    newinfo->number = repl->num_entries;

    // 初始化所有hooks为不可用的值(-1)
    for (i = 0; i < NF_INET_NUMHOOKS; i++) {
        newinfo->hook_entry[i] = 0xFFFFFFFF;
        newinfo->underflow[i] = 0xFFFFFFFF;
    }
    // 分配防火墙规则偏移位置
    offsets = xt_alloc_entry_offsets(newinfo->number);
    if (!offsets) return -ENOMEM;
    
    i = 0;
    // 遍历iptables规则，检查每个规则的偏移位置
    xt_entry_foreach(iter, entry0, newinfo->size) {
        // 检查iptables规则的占用空间大小
        ret = check_entry_size_and_hooks(iter, newinfo, entry0, entry0 + repl->size,
                        repl->hook_entry, repl->underflow, repl->valid_hooks);
        if (ret != 0) goto out_free;
        // 设置iptables规则的偏移位置
        if (i < repl->num_entries) offsets[i] = (void *)iter - entry0;
        ++i;
        // 目标设置为`ERROR_TARGET`时，增加栈大小
        if (strcmp(ipt_get_target(iter)->u.user.name, XT_ERROR_TARGET) == 0)
            ++newinfo->stacksize;
    }
    // 检查所有的规则都正确
    ret = -EINVAL;
    if (i != repl->num_entries) goto out_free;
    // 验证挂钩入口和下溢点是否已设置
    ret = xt_check_table_hooks(newinfo, repl->valid_hooks);
    if (ret) goto out_free;

    // 确定每个规则可以调用的hook
    if (!mark_source_chains(newinfo, repl->valid_hooks, entry0, offsets)) { 
        ret = -ELOOP;
        goto out_free;
    }
    kvfree(offsets);

    i = 0;
    xt_entry_foreach(iter, entry0, newinfo->size) {
        // 检查iptables规则是否正确
        ret = find_check_entry(iter, net, repl->name, repl->size, &alloc_state);
        if (ret != 0) break;
        ++i;
    }
    // 防火墙规则不正确时，清理已设置的规则 
    if (ret != 0) {
        xt_entry_foreach(iter, entry0, newinfo->size) {
            if (i-- == 0) break;
            cleanup_entry(iter, net);
        }
        return ret;
    }

    return ret;
 out_free:
    kvfree(offsets);
    return ret;
}
```

`check_entry_size_and_hooks`函数验证防火墙规则的正确性，包括检查规则的偏移位置、挂钩入口和下溢点是否已设置、确定每个规则可以调用的hook。如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int check_entry_size_and_hooks(struct ipt_entry *e, struct xt_table_info *newinfo,
                const unsigned char *base, const unsigned char *limit, const unsigned int *hook_entries,
                const unsigned int *underflows, unsigned int valid_hooks)
{
    unsigned int h;
    int err;
    // 检查防火墙规则的偏移位置是否正确
    if ((unsigned long)e % __alignof__(struct ipt_entry) != 0 ||
        (unsigned char *)e + sizeof(struct ipt_entry) >= limit ||
        (unsigned char *)e + e->next_offset > limit)
        return -EINVAL;
    // 检查防火墙规则的长度是否满足最小长度要求
    if (e->next_offset < sizeof(struct ipt_entry) + sizeof(struct xt_entry_target))
        return -EINVAL;
    // 检查ip信息是否正确
    if (!ip_checkentry(&e->ip)) return -EINVAL;

    // 验证target_offset和next_offset是正确的，并且所有匹配大小（如果有）与目标偏移量对齐。
    err = xt_check_entry_offsets(e, e->elems, e->target_offset, e->next_offset);
    if (err) return err;

    // 设置挂钩入口和下溢点数量
    for (h = 0; h < NF_INET_NUMHOOKS; h++) {
        if (!(valid_hooks & (1 << h))) continue;

        if ((unsigned char *)e - base == hook_entries[h])
            newinfo->hook_entry[h] = hook_entries[h];
        if ((unsigned char *)e - base == underflows[h]) {
            if (!check_underflow(e)) return -EINVAL;
            newinfo->underflow[h] = underflows[h];
        }
    }
    // 清除计数器和确认状态
    e->counters = ((struct xt_counters) { 0, 0 });
    e->comefrom = 0;
    return 0;
}
```

`find_check_entry`函数验证防火墙规则是否正确，检查匹配规则和目标信息，实现如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int find_check_entry(struct ipt_entry *e, struct net *net, const char *name,
                unsigned int size, struct xt_percpu_counter_alloc_state *alloc_state)
{
    struct xt_entry_target *t;
    struct xt_target *target;
    int ret;
    unsigned int j;
    struct xt_mtchk_param mtpar;
    struct xt_entry_match *ematch;
    // 分配计数器统计信息
    if (!xt_percpu_counter_alloc(alloc_state, &e->counters)) return -ENOMEM;

    j = 0;
    // 设置match查找属性
    memset(&mtpar, 0, sizeof(mtpar));
    mtpar.net   = net;
    mtpar.table     = name;
    mtpar.entryinfo = &e->ip;
    mtpar.hook_mask = e->comefrom;
    mtpar.family    = NFPROTO_IPV4;
    // 遍历匹配规则，确定每个匹配规则正确
    xt_ematch_foreach(ematch, e) {
        // 查找并检查匹配规则
        ret = find_check_match(ematch, &mtpar);
        if (ret != 0) goto cleanup_matches;
        ++j;
    }
    // 获取设置的匹配目标
    t = ipt_get_target(e);
    target = xt_request_find_target(NFPROTO_IPV4, t->u.user.name, t->u.user.revision);
    if (IS_ERR(target)) { ret = PTR_ERR(target); goto cleanup_matches; }
    // 检查匹配目标
    t->u.kernel.target = target;
    ret = check_target(e, net, name);
    if (ret) goto err;

    return 0;
 err:
    module_put(t->u.kernel.target->me);
 cleanup_matches:
    // 错误时，清理匹配规则
    xt_ematch_foreach(ematch, e) {
        if (j-- == 0) break;
        cleanup_match(ematch, net);
    }
    // 释放计数器
    xt_percpu_counter_free(&e->counters);
    return ret;
}
```

##### 2 确定匹配规则(match)和目标(target)

`find_check_match`函数检查匹配规则是否正确，如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int find_check_match(struct xt_entry_match *m, struct xt_mtchk_param *par)
{
    struct xt_match *match;
    int ret;
    // 获取指定名称和版本的匹配规则
    match = xt_request_find_match(NFPROTO_IPV4, m->u.user.name, m->u.user.revision);
    if (IS_ERR(match)) return PTR_ERR(match);

    // 设置内核空间的匹配规则后，检查匹配
    m->u.kernel.match = match;
    ret = check_match(m, par);
    if (ret) goto err;
    return 0;
err:
    module_put(m->u.kernel.match->me);
    return ret;
}
```

`xt_request_find_match`函数获取指定版本的匹配，如下：

```C
// file: net/netfilter/x_tables.c
struct xt_match * xt_request_find_match(uint8_t nfproto, const char *name, uint8_t revision)
{
    struct xt_match *match;
    // 检查名称长度是否合法
    if (strnlen(name, XT_EXTENSION_MAXNAMELEN) == XT_EXTENSION_MAXNAMELEN) return ERR_PTR(-EINVAL);
    // 获取匹配规则，失败时加载module后再次获取
    match = xt_find_match(nfproto, name, revision);
    if (IS_ERR(match)) {
        request_module("%st_%s", xt_prefix[nfproto], name);
        match = xt_find_match(nfproto, name, revision);
    }
    return match;
}
// file: net/netfilter/x_tables.c
struct xt_match *xt_find_match(u8 af, const char *name, u8 revision)
{
    struct xt_match *m;
    int err = -ENOENT;
    if (strnlen(name, XT_EXTENSION_MAXNAMELEN) == XT_EXTENSION_MAXNAMELEN) return ERR_PTR(-EINVAL);

    mutex_lock(&xt[af].mutex);
    // 遍历特定协议的match列表，获取指定名称和版本的match
    list_for_each_entry(m, &xt[af].match, list) {
        if (strcmp(m->name, name) == 0) {
            if (m->revision == revision) {
                // 名称和版本匹配后，获取到指定的match
                if (try_module_get(m->me)) { 
                    mutex_unlock(&xt[af].mutex);
                    return m;
                }
            } else
                err = -EPROTOTYPE; /* Found something. */
        }
    }
    mutex_unlock(&xt[af].mutex);
    if (af != NFPROTO_UNSPEC)
        // 获取失败时，尝试获取协议无关的match
        return xt_find_match(NFPROTO_UNSPEC, name, revision);
    
    return ERR_PTR(err);
}
```

`check_match`函数检查`match`设置的正确性，如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int check_match(struct xt_entry_match *m, struct xt_mtchk_param *par)
{
    // 设置match的参数
    const struct ipt_ip *ip = par->entryinfo;
    par->match     = m->u.kernel.match;
    par->matchinfo = m->data;
    return xt_check_match(par, m->u.match_size - sizeof(*m), ip->proto, ip->invflags & IPT_INV_PROTO);
}
// file: net/netfilter/x_tables.c
int xt_check_match(struct xt_mtchk_param *par, unsigned int size, u16 proto, bool inv_proto)
{
    int ret;
    // 检查size是否对齐
    if (XT_ALIGN(par->match->matchsize) != size && par->match->matchsize != -1) { ... }
    // 检查表是否匹配
    if (par->match->table != NULL && strcmp(par->match->table, par->table) != 0) { ... }
    // 检查hooks是否支持
    if (par->match->hooks && (par->hook_mask & ~par->match->hooks) != 0) { ... }
    // 检查协议是否支持
    if (par->match->proto && (par->match->proto != proto || inv_proto)) { ... }

    // 调用自定义的检查接口
    if (par->match->checkentry != NULL) {
        ret = par->match->checkentry(par);
        if (ret < 0) return ret;
        else if (ret > 0) return -EIO;
    }
    return 0;
}
```

`xt_request_find_target`函数获取指定版本的目标，实现过程和`xt_request_find_match`类似，从`target`列表中获取指定名称和版本的target。`check_target`函数检查`target`设置的正确性，如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int check_target(struct ipt_entry *e, struct net *net, const char *name)
{
    struct xt_entry_target *t = ipt_get_target(e);
    // 设置target检查参数
    struct xt_tgchk_param par = {
        .net       = net,
        .table     = name,
        .entryinfo = e,
        .target    = t->u.kernel.target,
        .targinfo  = t->data,
        .hook_mask = e->comefrom,
        .family    = NFPROTO_IPV4,
    };
    return xt_check_target(&par, t->u.target_size - sizeof(*t), e->ip.proto, e->ip.invflags & IPT_INV_PROTO);
}
// file: net/netfilter/x_tables.c
int xt_check_target(struct xt_tgchk_param *par, unsigned int size, u16 proto, bool inv_proto)
{
    int ret;
    // 检查size是否对齐
    if (XT_ALIGN(par->target->targetsize) != size) { ... }
    // 检查表是否匹配
    if (par->target->table != NULL && strcmp(par->target->table, par->table) != 0) { ... }
    // 检查hooks是否支持
    if (par->target->hooks && (par->hook_mask & ~par->target->hooks) != 0) { ... }
    // 检查协议是否支持
    if (par->target->proto && (par->target->proto != proto || inv_proto)) { ... }

    // 调用自定义的检查接口
    if (par->target->checkentry != NULL) {
        ret = par->target->checkentry(par);
        if (ret < 0) return ret;
        else if (ret > 0) return -EIO;
    }
    return 0;
}
```

##### 3 替换防火墙规

在检查替换的防火墙规则正确后，`__do_replace`函数使用新的防火墙规则替换现有的规则，如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int __do_replace(struct net *net, const char *name, unsigned int valid_hooks,
        struct xt_table_info *newinfo, unsigned int num_counters, void __user *counters_ptr)
{
    int ret;
    struct xt_table *t;
    struct xt_table_info *oldinfo;
    struct xt_counters *counters;
    struct ipt_entry *iter;

    // 分配计数器
    counters = xt_counters_alloc(num_counters);
    if (!counters) { ... } 
    // 获取指定的表
    t = xt_request_find_table_lock(net, AF_INET, name);
    if (IS_ERR(t)) { ... } 

    // 检查hooks是否匹配
    if (valid_hooks != t->valid_hooks) { ... } 

    // 替换表的规则
    oldinfo = xt_replace_table(t, num_counters, newinfo, &ret);
    if (!oldinfo) goto put_module;

    // 根据规则数量更新表的使用计数
    if ((oldinfo->number > oldinfo->initial_entries) ||
        (newinfo->number <= oldinfo->initial_entries))
        module_put(t->me);
    if ((oldinfo->number > oldinfo->initial_entries) &&
        (newinfo->number <= oldinfo->initial_entries))
        module_put(t->me);

    xt_table_unlock(t);
    // 获取旧的规则计数
    get_old_counters(oldinfo, counters);
    // 释放旧的规则项
    xt_entry_foreach(iter, oldinfo->entries, oldinfo->size)
        cleanup_entry(iter, net);
    // 释放旧的规则信息
    xt_free_table_info(oldinfo);
    // 复制计数器信息到用户空间
    if (copy_to_user(counters_ptr, counters, sizeof(struct xt_counters) * num_counters) != 0) {
        ...
    }
    // 释放计数器
    vfree(counters);
    return 0;
    ...
}
```

`xt_replace_table`函数替换表中的规则，并返回旧规则，如下：

```C
// file: net/netfilter/x_tables.c
struct xt_table_info * xt_replace_table(struct xt_table *table,
        unsigned int num_counters, struct xt_table_info *newinfo, int *error)
{
    struct xt_table_info *private;
    unsigned int cpu;
    int ret;

    // 分配跳跃栈信息空间
    ret = xt_jumpstack_alloc(newinfo);
    if (ret < 0) { .. }

    local_bh_disable();
    private = table->private;

    // 检查数量是否有变化，即：是否存在多个程序同时更新的情况
    if (num_counters != private->number) { .. }

    // 设置初始规则数量
    newinfo->initial_entries = private->initial_entries;

    // 更新表中规则信息
    smp_wmb();
    table->private = newinfo;
    smp_mb();

    // 确保所有CPU都更新了表中的规则
    local_bh_enable();

    // 等待所有CPU更新`xt_recseq`
    for_each_possible_cpu(cpu) {
        seqcount_t *s = &per_cpu(xt_recseq, cpu);
        u32 seq = raw_read_seqcount(s);
        if (seq & 1) {
            do { cond_resched(); cpu_relax(); } 
            while (seq == raw_read_seqcount(s));
        }
    }
    // 日志记录
    audit_log_nfcfg(table->name, table->af, private->number, 
        !private->number ? AUDIT_XT_OP_REGISTER : AUDIT_XT_OP_REPLACE, GFP_KERNEL);
    return private;
}
```

##### 4 清理旧的规则

在替换表的规则后，需要逐项清理旧的规则，`cleanup_entry`函数清理设置设置的规则，如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static void cleanup_entry(struct ipt_entry *e, struct net *net)
{
    struct xt_tgdtor_param par;
    struct xt_entry_target *t;
    struct xt_entry_match *ematch;

    // 清理所有的匹配信息
    xt_ematch_foreach(ematch, e)
        cleanup_match(ematch, net);

    // 清理目标信息
    t = ipt_get_target(e);
    par.net      = net;
    par.target   = t->u.kernel.target;
    par.targinfo = t->data;
    par.family   = NFPROTO_IPV4;
    // 调用目标的销毁接口
    if (par.target->destroy != NULL)
        par.target->destroy(&par);
    module_put(par.target->me);
    // 释放计数器
    xt_percpu_counter_free(&e->counters);
}
```

`cleanup_match`函数清理规则的匹配信息，如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static void cleanup_match(struct xt_entry_match *m, struct net *net)
{
    // 设置匹配参数信息
    struct xt_mtdtor_param par;
    par.net       = net;
    par.match     = m->u.kernel.match;
    par.matchinfo = m->data;
    par.family    = NFPROTO_IPV4;
    // 调用匹配的销毁接口
    if (par.match->destroy != NULL)
        par.match->destroy(&par);
    module_put(par.match->me);
}
```

#### (6) `SO_SET_ADD_COUNTERS`的实现

`SO_SET_ADD_COUNTERS`选项更新防火墙规则的计数信息，对应`do_add_counters`函数，实现如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
static int do_add_counters(struct net *net, sockptr_t arg, unsigned int len)
{
    struct xt_counters_info tmp;
    struct xt_counters *paddc;
    ...

    // 复制用户空间设置的计数信息
    paddc = xt_copy_counters(arg, len, &tmp);
    if (IS_ERR(paddc)) return PTR_ERR(paddc);
    // 获取指定的表
    t = xt_find_table_lock(net, AF_INET, tmp.name);
    if (IS_ERR(t)) { ... }

    local_bh_disable();
    private = t->private;
    // 防火墙规则数量不匹配时，不进行更新
    if (private->number != tmp.num_counters) { ret = -EINVAL; goto unlock_up_free; }

    i = 0;
    addend = xt_write_recseq_begin();
    // 遍历防火墙规则，逐项更新计数信息
    xt_entry_foreach(iter, private->entries, private->size) {
        struct xt_counters *tmp;
        // 获取当前的计数信息
        tmp = xt_get_this_cpu_counter(&iter->counters);
        // 更新当前计数器值
        ADD_COUNTER(*tmp, paddc[i].bcnt, paddc[i].pcnt);
        ++i;
    }
    xt_write_recseq_end(addend);
 unlock_up_free:
    local_bh_enable();
    xt_table_unlock(t);
    module_put(t->me);
 free:
    vfree(paddc);

    return ret;
}
```

### 4.4 NF_HOOK的调用过程

#### (1) `nf_hook`接口

在`netfilter`框架中，`NF_HOOK`函数是整个框架的核心，它负责将数据包送入`hook`点后执行相应的过滤。在Linux内核中我们可以通过 `NF_HOOK`, `NF_HOOK_COND` 和 `NF_HOOK_LIST` 宏进行HOOK点处理。以`NF_HOOK`宏为例，其定义如下：

```C
// file：include/linux/netfilter.h
static inline int NF_HOOK(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk, struct sk_buff *skb,
    struct net_device *in, struct net_device *out, int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
    // 执行nf_hook函数
    int ret = nf_hook(pf, hook, net, sk, skb, in, out, okfn);
    if (ret == 1)
        // 返回值为1时，表示允许网络数据包通过
        ret = okfn(net, sk, skb);
    return ret;
}
```

`nf_hook`函数是核心的处理过程，实现如下：

```C
// file：include/linux/netfilter.h
static inline int nf_hook(u_int8_t pf, unsigned int hook, struct net *net, struct sock *sk, 
            struct sk_buff *skb, struct net_device *indev, struct net_device *outdev,
            int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
    struct nf_hook_entries *hook_head = NULL;
    int ret = 1;

    // static_key检查，
    if (__builtin_constant_p(pf) && __builtin_constant_p(hook) &&
        !static_key_false(&nf_hooks_needed[pf][hook]))
        return 1;

    rcu_read_lock();
    // 获取hook点列表，根据不同的协议和hook点获取
    switch (pf) {
    case NFPROTO_IPV4: hook_head = rcu_dereference(net->nf.hooks_ipv4[hook]); break;
    case NFPROTO_IPV6: hook_head = rcu_dereference(net->nf.hooks_ipv6[hook]); break;
    case NFPROTO_ARP: hook_head = rcu_dereference(net->nf.hooks_arp[hook]); break;
    case NFPROTO_BRIDGE: hook_head = rcu_dereference(net->nf.hooks_bridge[hook]); break;
    default: WARN_ON_ONCE(1); break;
    }

    // hook点列表存在时
    if (hook_head) {
        struct nf_hook_state state;
        // 状态初始化
        nf_hook_state_init(&state, hook, pf, indev, outdev, sk, net, okfn);
        // 进行hook处理
        ret = nf_hook_slow(skb, &state, hook_head, 0);
    }
    rcu_read_unlock();
    return ret;
}
```

`nf_hook_slow`函数遍历hooks列表，逐项进行判决，根据判决结果进行不同的处理。如下：

```C
// file: net/netfilter/core.c
int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state,
    const struct nf_hook_entries *e, unsigned int s)
{
    unsigned int verdict;
    int ret;
    for (; s < e->num_hook_entries; s++) {
        // 进行防火墙规则的执行
        verdict = nf_hook_entry_hookfn(&e->hooks[s], skb, state);
        switch (verdict & NF_VERDICT_MASK) {
        case NF_ACCEPT: 
            // ACCEPT表示skb通过
            break;
        case NF_DROP:
            // DROP表示丢弃skb
            kfree_skb_reason(skb, SKB_DROP_REASON_NETFILTER_DROP);
            // 转换判决结果
            ret = NF_DROP_GETERR(verdict);
            if (ret == 0) ret = -EPERM;
            return ret;
        case NF_QUEUE:
            // QUEUE处理
            ret = nf_queue(skb, state, s, verdict);
            if (ret == 1) continue;
            return ret;
        default:
            // 默认处理规则
            return 0;
        }
    }
    return 1;
}
```

`nf_hook_entry_hookfn`函数进行防火墙规则的执行，如下：

```C
// file: include/linux/netfilter.h
static inline int nf_hook_entry_hookfn(const struct nf_hook_entry *entry, 
                    struct sk_buff *skb, struct nf_hook_state *state)
{   
    // 调用hook接口
    return entry->hook(entry->priv, skb, state);
}
```

#### (2) `ipt_do_table`的实现过程

在通过`nf_register_net_hook`函数注册`nf_hook_ops`时，设置`nf_hook_entry->hook`接口为`nf_hook_ops->hook`，如下：

```C
// file: net/netfilter/core.c
static struct nf_hook_entries * 
    nf_hook_entries_grow(const struct nf_hook_entries *old, const struct nf_hook_ops *reg)
{
    ...
    struct nf_hook_entries *new;
    ...
    // 设置新的hook项
    if (!inserted) {
        new_ops[nhooks] = (void *)reg;
        new->hooks[nhooks].hook = reg->hook;
        new->hooks[nhooks].priv = reg->priv;
    }
    return new;
}
```

ipv4的`filter`表的`hook`接口设置为`ipt_do_table`，如下：

```C
// file: net/ipv4/netfilter/iptable_filter.c
static int __init iptable_filter_init(void)
{
    ...
    filter_ops = xt_hook_ops_alloc(&packet_filter, ipt_do_table);
    ...
}
```

`ipt_do_table`函数是ipv4协议的防火墙规则执行函数，实现如下：

```C
// file: net/ipv4/netfilter/ip_tables.c
unsigned int ipt_do_table(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    const struct xt_table *table = priv;
    unsigned int hook = state->hook;
    static const char nulldevname[IFNAMSIZ] __attribute__((aligned(sizeof(long))));
    const struct iphdr *ip;
    // 设置默认的判据结果为DROP
    unsigned int verdict = NF_DROP;
    ...

    // 初始化
    stackidx = 0;
    ip = ip_hdr(skb);
    indev = state->in ? state->in->name : nulldevname;
    outdev = state->out ? state->out->name : nulldevname;
    // 分片设置
    acpar.fragoff = ntohs(ip->frag_off) & IP_OFFSET;
    acpar.thoff   = ip_hdrlen(skb);
    acpar.hotdrop = false;
    acpar.state   = state;

    WARN_ON(!(table->valid_hooks & (1 << hook)));
    local_bh_disable();
    // 执行状态获取
    addend = xt_write_recseq_begin();
    private = READ_ONCE(table->private); /* Address dependency. */
    cpu        = smp_processor_id();
    table_base = private->entries;
    jumpstack  = (struct ipt_entry **)private->jumpstack[cpu];

    // 启用TEE时，切换到备用栈。TEE对原始SKB发出XT_CONTINUE判决；
    // REJECT 或 SYNPROXY 进行递归
    if (static_key_false(&xt_tee_enabled))
        jumpstack += private->stacksize * __this_cpu_read(nf_skb_duplicated);

    // 获取hook点的规则开始位置
    e = get_entry(table_base, private->hook_entry[hook]);

    do {
        const struct xt_entry_target *t;
        const struct xt_entry_match *ematch;
        struct xt_counters *counter;
        WARN_ON(!e);

        // 检查skb的源/目的地址、协议是否匹配规则
        if (!ip_packet_match(ip, indev, outdev, &e->ip, acpar.fragoff)) {
 no_match:
            e = ipt_next_entry(e);
            continue;
        }
        // 遍历防火墙规则的匹配信息
        xt_ematch_foreach(ematch, e) {
            acpar.match     = ematch->u.kernel.match;
            acpar.matchinfo = ematch->data;
            // 逐项检查是否匹配, 不匹配时，获取下一条防火墙规则
            if (!acpar.match->match(skb, &acpar))
                goto no_match;
        }
        // 更新计数器信息
        counter = xt_get_this_cpu_counter(&e->counters);
        ADD_COUNTER(*counter, skb->len, 1);
        
        // 获取防火墙规则的目标 
        t = ipt_get_target_c(e);
        WARN_ON(!t->u.kernel.target);
        if (!t->u.kernel.target->target) {
            int v;
            // 标准目标时，获取判决结果
            v = ((struct xt_standard_target *)t)->verdict;
            if (v < 0) {
                // 结果不是RETURN时，其他结果(DROP,ACCEPT,STOLEN,QUEUE)时，表示最终的判决结果
                if (v != XT_RETURN) {
                    verdict = (unsigned int)(-v) - 1;
                    break;
                }
                // 结果为RETURN时，从栈中获取下一条防火墙规则
                if (stackidx == 0) {
                    e = get_entry(table_base, private->underflow[hook]);
                } else {
                    e = jumpstack[--stackidx];
                    e = ipt_next_entry(e);
                }
                continue;
            }
            // 跳转目标时，从栈或跳转表中获取下一条防火墙规则
            if (table_base + v != ipt_next_entry(e) && !(e->ip.flags & IPT_F_GOTO)) {
                // 超过栈大小时返回DROP，丢弃skb
                if (unlikely(stackidx >= private->stacksize)) {
                    verdict = NF_DROP;
                    break;
                }
                jumpstack[stackidx++] = e;
            }
            e = get_entry(table_base, v);
            continue;
        }
        // 不是标准目标时，组织目标参数后，获取判决结果
        acpar.target   = t->u.kernel.target;
        acpar.targinfo = t->data;
        verdict = t->u.kernel.target->target(skb, &acpar);
        // 判决结果是`CONTINUE`时，获下一条防火墙规则
        if (verdict == XT_CONTINUE) {
            ip = ip_hdr(skb);
            e = ipt_next_entry(e);
        } else {
            // 其他结果，表示有效的判决值
            break;
        }
    } while (!acpar.hotdrop);

    xt_write_recseq_end(addend);
    local_bh_enable();
    // hotdrop时返回为DROP，其他情况返回判决结果
    if (acpar.hotdrop)
        return NF_DROP;
    else 
        return verdict;
}
```

### 4.5 `bpf_mt`的实现过程

`bpf_mt`是Linux内核支持的match，通过BPF程序匹配数据包，在内核中的定义如下：

```C
// file: net/netfilter/xt_bpf.c
static struct xt_match bpf_mt_reg[] __read_mostly = {
    ...
    {
        .name       = "bpf",
        .revision   = 1,
        .family     = NFPROTO_UNSPEC,
        .checkentry = bpf_mt_check_v1,
        .match      = bpf_mt_v1,
        .destroy    = bpf_mt_destroy_v1,
        .matchsize  = sizeof(struct xt_bpf_info_v1),
        .usersize   = offsetof(struct xt_bpf_info_v1, filter),
        .me         = THIS_MODULE,
    },
};
```

支持两个版本match，V1版本兼容V0版本。我们以V1版本为例进行分析。

#### (1) 注册/注销过程

`bpf_mt_reg`匹配规则通过`module_init/module_exit`方式注册和注销，实现如下：

```C
// file: net/netfilter/xt_bpf.c
static int __init bpf_mt_init(void)
{
    return xt_register_matches(bpf_mt_reg, ARRAY_SIZE(bpf_mt_reg));
}
static void __exit bpf_mt_exit(void)
{
    xt_unregister_matches(bpf_mt_reg, ARRAY_SIZE(bpf_mt_reg));
}
module_init(bpf_mt_init);
module_exit(bpf_mt_exit);
```

#### (2) 检查接口

`.checkentry`接口在设置防火墙规则时检查`match`时调用，该接口设置为`bpf_mt_check_v1`函数，设置BPF程序作为匹配方式。实现如下：

```C
// file: net/netfilter/xt_bpf.c
static int bpf_mt_check_v1(const struct xt_mtchk_param *par)
{
    struct xt_bpf_info_v1 *info = par->matchinfo;
    if (info->mode == XT_BPF_MODE_BYTECODE)
        return __bpf_mt_check_bytecode(info->bpf_program, info->bpf_program_num_elem, &info->filter);
    else if (info->mode == XT_BPF_MODE_FD_ELF)
        return __bpf_mt_check_fd(info->fd, &info->filter);
    else if (info->mode == XT_BPF_MODE_PATH_PINNED)
        return __bpf_mt_check_path(info->path, &info->filter);
    else
        return -EINVAL;
}
```

`XT_BPF_MODE_BYTECODE`通过BPF字节码方式设置BPF程序，对应`__bpf_mt_check_bytecode`函数，实现如下：

```C
// file: net/netfilter/xt_bpf.c
static int __bpf_mt_check_bytecode(struct sock_filter *insns, __u16 len, struct bpf_prog **ret)
{
    struct sock_fprog_kern program;
    // 指令数量超过限制时(64条)时，返回错误
    if (len > XT_BPF_MAX_NUM_INSTR) return -EINVAL;

    program.len = len;
    program.filter = insns;
    // 创建独立的BPF过滤器程序
    if (bpf_prog_create(ret, &program)) { ... }
    return 0;
}
```

`XT_BPF_MODE_FD_ELF`通过BPF ELF文件方式设置BPF程序，对应`__bpf_mt_check_fd`函数，实现如下：

```C
// file: net/netfilter/xt_bpf.c
static int __bpf_mt_check_fd(int fd, struct bpf_prog **ret)
{
    struct bpf_prog *prog;
    // 通过fd获取BPF程序
    prog = bpf_prog_get_type(fd, BPF_PROG_TYPE_SOCKET_FILTER);
    if (IS_ERR(prog)) return PTR_ERR(prog);
    // 设置BPF过滤器程序
    *ret = prog;
    return 0;
}
```

`XT_BPF_MODE_PATH_PINNED`通过PINNED BPF文件路径方式设置BPF程序，对应`__bpf_mt_check_path`函数，实现如下：

```C
// file: net/netfilter/xt_bpf.c
static int __bpf_mt_check_path(const char *path, struct bpf_prog **ret)
{
    // 检查文件路径是否有效
    if (strnlen(path, XT_BPF_PATH_MAX) == XT_BPF_PATH_MAX) return -EINVAL;
    // 通过文件路径获取BPF程序
    *ret = bpf_prog_get_type_path(path, BPF_PROG_TYPE_SOCKET_FILTER);
    return PTR_ERR_OR_ZERO(*ret);
}
```

#### (3) 销毁接口

`.destroy`接口在销毁`match`时调用，该接口设置为`bpf_mt_destroy_v1`函数，销毁设置的BPF程序。实现如下：

```C
// file: net/netfilter/xt_bpf.c
static void bpf_mt_destroy_v1(const struct xt_mtdtor_param *par)
{
    const struct xt_bpf_info_v1 *info = par->matchinfo;
    bpf_prog_destroy(info->filter);
}
```

#### (4) 匹配接口

`.match`接口在`nf_hook`时检查防火墙规则时调用，该接口设置为`bpf_mt_v1`函数，运行设置的BPF程序。实现如下：

```C
// file: net/netfilter/xt_bpf.c
static bool bpf_mt_v1(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct xt_bpf_info_v1 *info = par->matchinfo;
    return !!bpf_prog_run_save_cb(info->filter, (struct sk_buff *) skb);
}
```

### 4.5 `nat_target`的实现过程

`SNAT/DNAT`是Linux内核支持的target，实现NAT的处理，在内核中的定义如下：

```C
// file: net/netfilter/xt_nat.c
static struct xt_target xt_nat_target_reg[] __read_mostly = {
    ...
    {
        .name       = "SNAT",
        .revision   = 2,
        .checkentry = xt_nat_checkentry,
        .destroy    = xt_nat_destroy,
        .target     = xt_snat_target_v2,
        .targetsize = sizeof(struct nf_nat_range2),
        .table      = "nat",
        .hooks      = (1 << NF_INET_POST_ROUTING) |
                      (1 << NF_INET_LOCAL_IN),
        .me         = THIS_MODULE,
    },
    {
        .name       = "DNAT",
        .revision   = 2,
        .checkentry = xt_nat_checkentry,
        .destroy    = xt_nat_destroy,
        .target     = xt_dnat_target_v2,
        .targetsize = sizeof(struct nf_nat_range2),
        .table      = "nat",
        .hooks      = (1 << NF_INET_PRE_ROUTING) |
                      (1 << NF_INET_LOCAL_OUT),
        .me         = THIS_MODULE,
    },
};
```

`SNAT/DNAT`支持三个版本target。我们以SNAT的V2版本为例进行分析。

#### (1) 注册/注销过程

`xt_nat_target_reg`匹配规则通过`module_init/module_exit`方式注册和注销，实现如下：

```C
// file: net/netfilter/xt_nat.c
static int __init xt_nat_init(void)
{
    return xt_register_targets(xt_nat_target_reg, ARRAY_SIZE(xt_nat_target_reg));
}
static void __exit xt_nat_exit(void)
{
    xt_unregister_targets(xt_nat_target_reg, ARRAY_SIZE(xt_nat_target_reg));
}
module_init(xt_nat_init);
module_exit(xt_nat_exit);
```

#### (2) 检查接口

`.checkentry`接口在设置防火墙规则时检查`target`时调用，SNAT的检查接口设置为`xt_nat_checkentry`函数，获取网络命名空间。实现如下：

```C
// file: net/netfilter/xt_nat.c
static int xt_nat_checkentry(const struct xt_tgchk_param *par)
{
    return nf_ct_netns_get(par->net, par->family);
}
```

#### (3) 销毁接口

`.destroy`接口在销毁`target`时调用，该接口设置为`xt_nat_destroy`函数，释放网络命名空间。实现如下：

```C
// file: net/netfilter/xt_nat.c
static void xt_nat_destroy(const struct xt_tgdtor_param *par)
{
    nf_ct_netns_put(par->net, par->family);
}
```

#### (4) 判决接口

`.target`接口在`nf_hook`时检查防火墙规则时调用，该接口设置为`xt_snat_target_v2`函数，获取连接信息后，设置NAT映射信息。实现如下：

```C
// file: net/netfilter/xt_nat.c
static unsigned int xt_snat_target_v2(struct sk_buff *skb, const struct xt_action_param *par)
{
    const struct nf_nat_range2 *range = par->targinfo;
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct;

    ct = nf_ct_get(skb, &ctinfo);
    WARN_ON(!(ct != NULL &&
            (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED ||
            ctinfo == IP_CT_RELATED_REPLY)));

    return nf_nat_setup_info(ct, range, NF_NAT_MANIP_SRC);
}
```

## 5 总结

本文通过`iptables_test`示例程序分析了BPF程序在防火墙中的应用，通过`iptables`工具实现防火墙规则的更新。

## 参考资料

* [iptables(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/iptables.8.html)
* [iptables-extensions(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
* [iptables 命令行工具源码解析](https://yxj-books.readthedocs.io/zh_CN/latest/network/iptables/iptables%E5%B7%A5%E5%85%B7%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90.html)
* [深入理解 iptables 和 netfilter 架构](http://arthurchiao.art/blog/deep-dive-into-iptables-and-netfilter-arch-zh/)
* [BPF comes to firewalls](https://lwn.net/Articles/747551/)