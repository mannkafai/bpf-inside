# LIRC_MODE2的内核实现

## 0 前言

今天我们借助`test_lirc_mode2`示例程序分析如何通过BPF程序实现红外(IR)设备的解码。

## 1 简介

红外遥控器使用许多不同的编码，如果要为每个解码器编写一个解码器，我们最终会在内核中拥有数百个解码器。因此，目前内核仅支持最广泛使用的协议，可以运行 lirc 守护程序来红外解码。红外解码通常可以用几行代码来表示，因此直接在内核实现，没有许多内核空间到用户空间的上下文切换是最佳的解决方案。

## 2 `test_lirc_mode2`示例程序

### 2.1 BPF程序

BPF程序源码参见[test_lirc_mode2.bpf.c](../src/test_lirc_mode2.bpf.c)，主要内容如下：

```C
SEC("lirc_mode2")
int bpf_decoder(unsigned int *sample)
{
    if (LIRC_IS_PULSE(*sample)) {
        unsigned int duration = LIRC_VALUE(*sample);
        if (duration & 0x10000)
            bpf_rc_keydown(sample, 0x40, duration & 0xffff, 0);
        if (duration & 0x20000)
            bpf_rc_pointer_rel(sample, (duration >> 8) & 0xff, duration & 0xff);
    }
    return 0;
}
```

### 2.2 用户程序

用户程序源码参见[test_lirc_mode2.c](../src/test_lirc_mode2.c)，主要内容如下：

#### 1 附加BPF程序

```C
int main(int argc, char **argv)
{
    struct test_lirc_mode2_bpf *skel;
    int ret, lircfd, progfd, inputfd;
    int testir1 = 0x1dead;
    int testir2 = 0x20101;
    u32 prog_ids[10], prog_flags[10], prog_cnt;

    if (argc != 3) { ... }

    // 加载BPF程序
    skel = test_lirc_mode2_bpf__open_and_load();
    if (!skel) { ... }
    progfd = bpf_program__fd(skel->progs.bpf_decoder);

    // 打开lirc设备
    lircfd = open(argv[1], O_RDWR | O_NONBLOCK);
    if (lircfd == -1) { ... }

    // 尝试分离之前附加的BPF程序
    ret = bpf_prog_detach2(progfd, lircfd, BPF_LIRC_MODE2);
    if (ret != -1 || errno != ENOENT) { ... }

    // 打开输入文件
    inputfd = open(argv[2], O_RDONLY | O_NONBLOCK);
    if (inputfd == -1) { ... }

    // 查询LIRC设备已附加的程序数量
    prog_cnt = 10;
    ret = bpf_prog_query(lircfd, BPF_LIRC_MODE2, 0, prog_flags, prog_ids, &prog_cnt);
    if (ret) { ... }
    // 存在附加的程序，退出
    if (prog_cnt != 0) { ... }

    // 附加LIRC BPF程序
    ret = bpf_prog_attach(progfd, lircfd, BPF_LIRC_MODE2, 0);
    if (ret) { ... }

    // 控制红外设备
    ret = write(lircfd, &testir1, sizeof(testir1));
    if (ret != sizeof(testir1)) { ... }

    struct pollfd pfd = { .fd = inputfd, .events = POLLIN };
    struct input_event event;
    for (;;) {
        poll(&pfd, 1, 100);
        // 读取解码后的IR，失败时退出程序
        ret = read(inputfd, &event, sizeof(event));
        if (ret != sizeof(event)) { ... }

        // 检查事件类型，失败时退出测试
        if (event.type == EV_MSC && event.code == MSC_SCAN && event.value == 0xdead) {
            break;
        }
    }
    ...
    
    // 分离LIRC BPF程序
    ret = bpf_prog_detach2(progfd, lircfd, BPF_LIRC_MODE2);
    if (ret) { ... }

    return 0;
}
```

#### 2 读取数据过程

`test_lirc_mode2` 程序通过用户空间读取lirc设备数据。

### 2.3 编译运行

使用cmake编译程序后运行，如下：

```bash
$ cd build
$ cmake ../src
$ make test_lirc_mode2
$ sudo ./test_lirc_mode2.sh
libbpf: loading object 'test_lirc_mode2_bpf' from buffer
...
libbpf: prog 'bpf_decoder': BPF program load failed: Invalid argument
libbpf: prog 'bpf_decoder': failed to load: -22
libbpf: failed to load object 'test_lirc_mode2_bpf'
libbpf: failed to load BPF skeleton 'test_lirc_mode2_bpf': -22
Failed to open BPF skeleton
FAIL: lirc_mode2
```

`LIRC_MODE2`支持BPF程序时，需要内核支持`CONFIG_BPF_LIRC_MODE2`编译选项。目前使用的内核在编译时没有选择该选项，因此运行失败。

## 3 lirc_mode2附加和分离的过程

`test_lirc_mode2.bpf.c`文件中BPF程序的SEC名称为 `SEC("lirc_mode2")`，`lirc_mode2`前缀在libbpf中的处理方式如下：

```C
// file: libbpf/src/libbpf.c
static const struct bpf_sec_def section_defs[] = {
    ...
    SEC_DEF("lirc_mode2", LIRC_MODE2, BPF_LIRC_MODE2, SEC_ATTACHABLE_OPT),
    ...
};
```

`lirc_mode2`前缀不支持自动附加，需要通过手动方式附加。

### 3.1 附加过程

`lirc_mode2`类型的BPF程序通过`bpf_prog_attach`方式附加，设置`opts->flags`后调用 `bpf_prog_attach_opts` ，如下：

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

`bpf_prog_detach2` 函数实现`lirc_mode2` BPF程序的分离，如下：

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

### 4.1 LIRC设备的注册和注销过程

RC设备驱动分为三种类型，在内核中使用`enum rc_driver_type`表示，如下：

```C
// file: include/media/rc-core.h
enum rc_driver_type {
    RC_DRIVER_SCANCODE = 0,
    RC_DRIVER_IR_RAW,
    RC_DRIVER_IR_RAW_TX,
};
```

* RC_DRIVER_SCANCODE：驱动程序或硬件生成扫描码;
* RC_DRIVER_IR_RAW：驱动程序或硬件生成脉冲/间隔序列，需要一个红外脉冲/间隔解码器;
* RC_DRIVER_IR_RAW_TX：仅限设备发射器，驱动程序需要脉冲/间隔数据序列。

红外遥控器使用简单的LED发出红外光，LED会打开和关闭较短或较长的时间，其解释有点类似于摩尔斯电码。当红外光被检测到一段时间后，结果被称为“脉冲”，未检测到红外光时脉冲之间的时间称为“间隔”。

#### 1 注册过程

##### (1) 创建设备

在使用`lirc`设备前首先创建该设备，`rc_allocate_device`函数完成该功能，实现如下：

```C
// file: drivers/media/rc/rc-main.c
struct rc_dev *rc_allocate_device(enum rc_driver_type type)
{
    struct rc_dev *dev;
    // 分配rc设备内存空间
    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev) return NULL;

    if (type != RC_DRIVER_IR_RAW_TX) {
        // 支持输入的设备，创建输入设备
        dev->input_dev = input_allocate_device();
        if (!dev->input_dev) { kfree(dev); return NULL; }
        // 输入设备属性设置
        dev->input_dev->getkeycode = ir_getkeycode;
        dev->input_dev->setkeycode = ir_setkeycode;
        input_set_drvdata(dev->input_dev, dev);
        // 设置`keyup`和`repeat`定时器
        dev->timeout = IR_DEFAULT_TIMEOUT;
        timer_setup(&dev->timer_keyup, ir_timer_keyup, 0);
        timer_setup(&dev->timer_repeat, ir_timer_repeat, 0);
        // 输入设备的spin_lock设置
        spin_lock_init(&dev->rc_map.lock);
        spin_lock_init(&dev->keylock);
    }
    mutex_init(&dev->lock);
    // 设置RC设备的类型、类别后，初始化设备
    dev->dev.type = &rc_dev_type;
    dev->dev.class = &rc_class;
    device_initialize(&dev->dev);
    // 设置驱动类型
    dev->driver_type = type;

    __module_get(THIS_MODULE);
    return dev;
}
```

##### (2) RC设备的注册接口

RC设备通过 `rc_register_device` 函数注册到内核中，实现过程如下：

```C
// file: drivers/media/rc/rc-main.c
int rc_register_device(struct rc_dev *dev)
{
    const char *path;
    int attr = 0;
    int minor;
    int rc;

    if (!dev) return -EINVAL;
    // 分配RC设备号
    minor = ida_alloc_max(&rc_ida, RC_DEV_MAX - 1, GFP_KERNEL);
    if (minor < 0) return minor;

    dev->minor = minor;
    dev_set_name(&dev->dev, "rc%u", dev->minor);
    dev_set_drvdata(&dev->dev, dev);

    // 设备的sysfs组属性设置
    dev->dev.groups = dev->sysfs_groups;
    if (dev->driver_type == RC_DRIVER_SCANCODE && !dev->change_protocol)
        dev->sysfs_groups[attr++] = &rc_dev_ro_protocol_attr_grp;
    else if (dev->driver_type != RC_DRIVER_IR_RAW_TX)
        dev->sysfs_groups[attr++] = &rc_dev_rw_protocol_attr_grp;
    if (dev->s_filter)
        dev->sysfs_groups[attr++] = &rc_dev_filter_attr_grp;
    if (dev->s_wakeup_filter)
        dev->sysfs_groups[attr++] = &rc_dev_wakeup_filter_attr_grp;
    dev->sysfs_groups[attr++] = NULL;

    // `IR_RAW`设备准备原始事件
    if (dev->driver_type == RC_DRIVER_IR_RAW) {
        rc = ir_raw_event_prepare(dev);
        if (rc < 0) goto out_minor;
    }
    // 非发射器的设备，准备输入(RX)设备
    if (dev->driver_type != RC_DRIVER_IR_RAW_TX) {
        rc = rc_prepare_rx_device(dev);
        if (rc) goto out_raw;
    }
    // 设置注册标志后，添加设备
    dev->registered = true;
    rc = device_add(&dev->dev);
    if (rc) goto out_rx_free;

    path = kobject_get_path(&dev->dev.kobj, GFP_KERNEL);
    dev_info(&dev->dev, "%s as %s\n", dev->device_name ?: "Unspecified device", path ?: "N/A");
    kfree(path);

    // 在设置输入设备前，需要注册该设备
    if (dev->allowed_protocols != RC_PROTO_BIT_CEC) {
        rc = lirc_register(dev);
        if (rc < 0) goto out_dev;
    }
    // 输入(RX)设备的设置
    if (dev->driver_type != RC_DRIVER_IR_RAW_TX) {
        rc = rc_setup_rx_device(dev);
        if (rc) goto out_lirc;
    }
    // 注册原始事件(RAW EVENT)
    if (dev->driver_type == RC_DRIVER_IR_RAW) {
        rc = ir_raw_event_register(dev);
        if (rc < 0) goto out_rx;
    }
    // 打印注册信息
    dev_dbg(&dev->dev, "Registered rc%u (driver: %s)\n", dev->minor, 
                dev->driver_name ? dev->driver_name : "unknown");
    return 0;

    // 注册失败时的清理工作
out_rx:
    rc_free_rx_device(dev);
out_lirc:
    if (dev->allowed_protocols != RC_PROTO_BIT_CEC)
        lirc_unregister(dev);
out_dev:
    device_del(&dev->dev);
out_rx_free:
    ir_free_table(&dev->rc_map);
out_raw:
    ir_raw_event_free(dev);
out_minor:
    ida_free(&rc_ida, minor);
    return rc;
}
```

##### (3) 原始事件的注册过程

`ir_raw_event_prepare`函数用于准备原始事件，如下：

```C
// file: drivers/media/rc/rc-ir-raw.c
int ir_raw_event_prepare(struct rc_dev *dev)
{
    if (!dev) return -EINVAL;
    
    // 分配原始事件的内存空间
    dev->raw = kzalloc(sizeof(*dev->raw), GFP_KERNEL);
    if (!dev->raw) return -ENOMEM;
    // 初始化原始事件
    dev->raw->dev = dev;
    dev->change_protocol = change_protocol;
    dev->idle = true;
    spin_lock_init(&dev->raw->edge_spinlock);
    // 设置边缘触发定时器
    timer_setup(&dev->raw->edge_handle, ir_raw_edge_handle, 0);
    // 初始化原始事件的FIFO
    INIT_KFIFO(dev->raw->kfifo);

    return 0;
}
```

`ir_raw_event_register`函数注册原始事件，如下：

```C
// file: drivers/media/rc/rc-ir-raw.c
int ir_raw_event_register(struct rc_dev *dev)
{
    struct task_struct *thread;
    // 创建原始事件的内核线程
    thread = kthread_run(ir_raw_event_thread, dev->raw, "rc%u", dev->minor);
    if (IS_ERR(thread)) return PTR_ERR(thread);

    // 设置线程后，添加到客户端列表中
    dev->raw->thread = thread;
    mutex_lock(&ir_raw_handler_lock);
    list_add_tail(&dev->raw->list, &ir_raw_client_list);
    mutex_unlock(&ir_raw_handler_lock);
    return 0;
}
```

##### (4) LIRC设备的注册过程

`lirc_dev_register`函数注册LIRC设备，如下：

```C
// file: drivers/media/rc/lirc_dev.c
int lirc_register(struct rc_dev *dev)
{
    const char *rx_type, *tx_type;
    int err, minor;

    // 分配LIRC设备号
    minor = ida_alloc_max(&lirc_ida, RC_DEV_MAX - 1, GFP_KERNEL);
    if (minor < 0) return minor;

    // lirc设备属性设置
    device_initialize(&dev->lirc_dev);
    dev->lirc_dev.class = lirc_class;
    dev->lirc_dev.parent = &dev->dev;
    dev->lirc_dev.release = lirc_release_device;
    dev->lirc_dev.devt = MKDEV(MAJOR(lirc_base_dev), minor);
    dev_set_name(&dev->lirc_dev, "lirc%d", minor);

    // 初始化用户空间打开的文件信息
    INIT_LIST_HEAD(&dev->lirc_fh);
    spin_lock_init(&dev->lirc_fh_lock);

    // cdev设备初始化，设置文件操作接口
    cdev_init(&dev->lirc_cdev, &lirc_fops);
    // 添加lirc设备，注册到系统
    err = cdev_device_add(&dev->lirc_cdev, &dev->lirc_dev);
    if (err) goto out_ida;

    get_device(&dev->dev);

    // 获取设备的输入方式
    switch (dev->driver_type) {
    case RC_DRIVER_SCANCODE: rx_type = "scancode"; break;
    case RC_DRIVER_IR_RAW: rx_type = "raw IR"; break;
    default: rx_type = "no"; break;
    }
    // 获取设备的输出方式
    if (dev->tx_ir)
        tx_type = "raw IR";
    else
        tx_type = "no";

    // 打印设备信息
    dev_info(&dev->dev, "lirc_dev: driver %s registered at minor = %d, %s receiver, %s transmitter",
        dev->driver_name, minor, rx_type, tx_type);
    return 0;

out_ida:
    ida_free(&lirc_ida, minor);
    return err;
}
```

#### 2 注销过程

##### (1) 注销接口

RC设备通过 `rc_unregister_device` 函数从内核中注销，实现过程如下：

```C
// file: drivers/media/rc/rc-main.c
void rc_unregister_device(struct rc_dev *dev)
{
    if (!dev) return;
    // `IR_RAW`设备注销原始事件
    if (dev->driver_type == RC_DRIVER_IR_RAW)
        ir_raw_event_unregister(dev);

    // 删除`keyup`和`repeat`定时器
    del_timer_sync(&dev->timer_keyup);
    del_timer_sync(&dev->timer_repeat);

    mutex_lock(&dev->lock);
    // 关闭设备，设置未注册状态
    if (dev->users && dev->close) dev->close(dev);
    dev->registered = false;
    mutex_unlock(&dev->lock);

    // 释放输入设备
    rc_free_rx_device(dev);

    // 注销`lirc`设备
    if (dev->allowed_protocols != RC_PROTO_BIT_CEC)
        lirc_unregister(dev);
    // 删除RC设备
    device_del(&dev->dev);
    // 释放RC设备号
    ida_free(&rc_ida, dev->minor);
    // 自动分配的设备，释放内存空间
    if (!dev->managed_alloc) rc_free_device(dev);
}
```

##### (2) 注销原始事件

`ir_raw_event_unregister`函数注销`lirc`设备的原始事件，如下：

```C
// file: drivers/media/rc/rc-ir-raw.c
void ir_raw_event_unregister(struct rc_dev *dev)
{
    struct ir_raw_handler *handler;
    // 设备或原始事件不存在时，返回
    if (!dev || !dev->raw) return;

    // 停止内核线程和边缘定时器
    kthread_stop(dev->raw->thread);
    del_timer_sync(&dev->raw->edge_handle);

    mutex_lock(&ir_raw_handler_lock);
    // 从客户列表中移除该设备
    list_del(&dev->raw->list);
    // 通知协议处理器设备注销
    list_for_each_entry(handler, &ir_raw_handler_list, list)
        if (handler->raw_unregister && (handler->protocols & dev->enabled_protocols))
            handler->raw_unregister(dev);
    // 释放`lirc`设备关联的BPF程序列表
    lirc_bpf_free(dev);
    // 释放原始事件
    ir_raw_event_free(dev);
    mutex_unlock(&ir_raw_handler_lock);
}
```

`lirc_bpf_free`函数释放RC设备关联的BPF程序，如下：

```C
// file: drivers/media/rc/bpf-lirc.c
void lirc_bpf_free(struct rc_dev *rcdev)
{
    struct bpf_prog_array_item *item;
    struct bpf_prog_array *array;
    // 获取BPF程序列表
    array = lirc_rcu_dereference(rcdev->raw->progs);
    if (!array) return;

    // 释放BPF程序后，释放列表
    for (item = array->items; item->prog; item++)
        bpf_prog_put(item->prog);
    bpf_prog_array_free(array);
}
```
##### (3) 注销LIRC设备

`lirc_unregister`函数注销`lirc`设备，如下：

```C
// file: drivers/media/rc/lirc_dev.c
void lirc_unregister(struct rc_dev *dev)
{
    unsigned long flags;
    struct lirc_fh *fh;
    // 打印注销信息
    dev_dbg(&dev->dev, "lirc_dev: driver %s unregistered from minor = %d\n",
        dev->driver_name, MINOR(dev->lirc_dev.devt));

    spin_lock_irqsave(&dev->lirc_fh_lock, flags);
    // 通知用户空间设备状态
    list_for_each_entry(fh, &dev->lirc_fh, list)
        wake_up_poll(&fh->wait_poll, EPOLLHUP | EPOLLERR);
    spin_unlock_irqrestore(&dev->lirc_fh_lock, flags);
    // 删除`lirc`设备
    cdev_device_del(&dev->lirc_cdev, &dev->lirc_dev);
    // 释放LIRC设备号
    ida_free(&lirc_ida, MINOR(dev->lirc_dev.devt));
}
```

### 4.2 附加和分离的内核实现

#### 1 附加的实现

##### (1) BPF系统调用

附加`lirc_mode2`使用`BPF_PROG_ATTACH` BPF系统调用，如下：

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

`bpf_prog_attach` 在检查BPF程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理。`lirc_mode2`类型的bpf程序对应 `lirc_prog_attach` 处理函数。如下：

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
    case BPF_PROG_TYPE_LIRC_MODE2:
        ret = lirc_prog_attach(attr, prog);
        break;
    default:
        ret = -EINVAL;
    }
    // 附加失败时，释放bpf程序
    if (ret) bpf_prog_put(prog);
    return ret;
}
```

##### (3) `lirc_prog_attach`

`lirc_prog_attach` 函数附加BPF程序到LIRC设备上，实现如下：

```C
// file: drivers/media/rc/bpf-lirc.c
int lirc_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    struct rc_dev *rcdev;
    int ret;

    // 不支持flags设置
    if (attr->attach_flags) return -EINVAL;
    // 获取lirc设备
    rcdev = rc_dev_get_from_fd(attr->target_fd);
    if (IS_ERR(rcdev)) return PTR_ERR(rcdev);
    // 附加BPF程序到lirc设备
    ret = lirc_bpf_attach(rcdev, prog);
    
    put_device(&rcdev->dev);
    return ret;
}
```

`rc_dev_get_from_fd` 函数通过fd获取lirc设备，如下：

```C
// file: drivers/media/rc/lirc_dev.c
struct rc_dev *rc_dev_get_from_fd(int fd)
{
    // 通过fd获取获取文件信息
    struct fd f = fdget(fd);
    struct lirc_fh *fh;
    struct rc_dev *dev;

    // 检查文件是否有效
    if (!f.file) return ERR_PTR(-EBADF);
    if (f.file->f_op != &lirc_fops) { fdput(f); return ERR_PTR(-EINVAL); }

    // 获取文件私有数据，及lirc设备
    fh = f.file->private_data;
    dev = fh->rc;
    
    // 获取设备 
    get_device(&dev->dev);
    fdput(f);
    return dev;
}
```

`lirc_bpf_attach` 函数附加BPF程序到LIRC设备，如下：

```C
// file: drivers/media/rc/bpf-lirc.c
#define BPF_MAX_PROGS 64
static int lirc_bpf_attach(struct rc_dev *rcdev, struct bpf_prog *prog)
{
    struct bpf_prog_array *old_array;
    struct bpf_prog_array *new_array;
    struct ir_raw_event_ctrl *raw;
    int ret;

    // 只支持`IR_RAW`设备
    if (rcdev->driver_type != RC_DRIVER_IR_RAW) return -EINVAL;

    ret = mutex_lock_interruptible(&ir_raw_handler_lock);
    if (ret) return ret;
    // 获取lirc设备raw数据
    raw = rcdev->raw;
    if (!raw) { ret = -ENODEV; goto unlock; }

    // 获取lirc设备附加的BPF程序列表，检查BPF程序数量是否超过最大值
    old_array = lirc_rcu_dereference(raw->progs);
    if (old_array && bpf_prog_array_length(old_array) >= BPF_MAX_PROGS) {
        ret = -E2BIG;
        goto unlock;
    }
    // 创建新的BPF程序列表，添加BPF程序到列表中
    ret = bpf_prog_array_copy(old_array, NULL, prog, 0, &new_array);
    if (ret < 0) goto unlock;

    // 设置BPF程序列表为新的列表，并释放旧的列表 
    rcu_assign_pointer(raw->progs, new_array);
    bpf_prog_array_free(old_array);

unlock:
    mutex_unlock(&ir_raw_handler_lock);
    return ret;
}
```

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

`bpf_prog_detach` 在检查BPF程序类型和attr属性中附加类型匹配后，针对不同程序类型和附加类型进行不同的处理，`lirc_mode2`类型的bpf程序对应 `lirc_prog_detach` 处理函数。如下：

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
    case BPF_PROG_TYPE_LIRC_MODE2:
        return lirc_prog_detach(attr);
    ...
    default:
        return -EINVAL;
    }
}
```

##### (3) `lirc_prog_detach`

`lirc_prog_detach` 函数从lirc设备上分离BPF程序，实现如下：

```C
// file: drivers/media/rc/bpf-lirc.c
int lirc_prog_detach(const union bpf_attr *attr)
{
    struct bpf_prog *prog;
    struct rc_dev *rcdev;
    int ret;

    // 不支持flags设置
    if (attr->attach_flags) return -EINVAL;
    // 获取BPF程序
    prog = bpf_prog_get_type(attr->attach_bpf_fd, BPF_PROG_TYPE_LIRC_MODE2);
    if (IS_ERR(prog)) return PTR_ERR(prog);
    // 获取lirc设备
    rcdev = rc_dev_get_from_fd(attr->target_fd);
    if (IS_ERR(rcdev)) { bpf_prog_put(prog); return PTR_ERR(rcdev); }

    // 分离BPF程序
    ret = lirc_bpf_detach(rcdev, prog);

    bpf_prog_put(prog);
    put_device(&rcdev->dev);
    return ret;
}
```

`lirc_bpf_detach` 函数从lirc设备分离BPF程序，如下：

```C
// file: drivers/media/rc/bpf-lirc.c
static int lirc_bpf_detach(struct rc_dev *rcdev, struct bpf_prog *prog)
{
    struct bpf_prog_array *old_array;
    struct bpf_prog_array *new_array;
    struct ir_raw_event_ctrl *raw;
    int ret;

    // 只支持`IR_RAW`设备
    if (rcdev->driver_type != RC_DRIVER_IR_RAW) return -EINVAL;

    ret = mutex_lock_interruptible(&ir_raw_handler_lock);
    if (ret) return ret;

    // 获取lirc设备raw数据
    raw = rcdev->raw;
    if (!raw) { ret = -ENODEV; goto unlock; }

    // 获取BPF程序数组
    old_array = lirc_rcu_dereference(raw->progs);
    // 从旧的程序列表中删除BPF程序，并复制到新的程序列表中
    ret = bpf_prog_array_copy(old_array, prog, NULL, 0, &new_array);
    if (ret) goto unlock;

    // 设置BPF程序列表为新的列表，并释放旧的列表 
    rcu_assign_pointer(raw->progs, new_array);
    bpf_prog_array_free(old_array);
    bpf_prog_put(prog);
unlock:
    mutex_unlock(&ir_raw_handler_lock);
    return ret;
}
```

### 4.3 IR设备采集数据的处理过程

#### 1 原始数据的采集过程

`lirc`设备提供了多种方式的事件采集方式，所有的事件最终通过`ir_raw_event_store`函数添加到FIFO中，将脉冲/间隔 持续时间传递给原始IR解码器。脉冲是表示为正值；间隔表示为负值；零值表示将重置解码状态机。其实现如下：

```C
// file: drivers/media/rc/rc-ir-raw.c
int ir_raw_event_store(struct rc_dev *dev, struct ir_raw_event *ev)
{
    if (!dev->raw) return -EINVAL;
    // 调试信息
    dev_dbg(&dev->dev, "sample: (%05dus %s)\n", ev->duration, TO_STR(ev->pulse));
    // 添加到原始数据的kfifo队列中
    if (!kfifo_put(&dev->raw->kfifo, *ev)) {
        dev_err(&dev->dev, "IR event FIFO is full!\n");
        return -ENOSPC;
    }
    return 0;
}
```

其他采集数据的方式如下：

* `ir_raw_event_store_edge`函数用于存储IR脉冲/间隔的开始(或者IR的开始/结束接收)，适用于不能提供持续时间，只能提供中断(或类似事件)的设备；
* `ir_raw_event_store_with_timeout`函数用于存储IR脉冲/间隔的持续时间，解码并生成超时；
* `ir_raw_event_store_with_filter`函数效果和`ir_raw_event_store_edge`类似，适用于内部缓存区有限的设备。它会自动合并相同类型的样本并处理超时。非零的返回值表示添加了事件、零值表示空闲处理而忽略该事件。
* `ir_raw_event_set_idle`表示RC设备空闲与否。
  
#### 2 采集数据的处理过程

采集原始数据后，通过`ir_raw_event_handle`函数开启解析存储的IR数据，唤醒内核线程开始处理。如下：

```C
// file: drivers/media/rc/rc-ir-raw.c
void ir_raw_event_handle(struct rc_dev *dev)
{
    if (!dev->raw || !dev->raw->thread) return;
    // 唤醒内核线程
    wake_up_process(dev->raw->thread);
}
```

`dev->raw->thread`线程设置的处理接口为`ir_raw_event_thread`，其实现如下：

```C
// file: drivers/media/rc/rc-ir-raw.c
static int ir_raw_event_thread(void *data)
{
    struct ir_raw_event ev;
    struct ir_raw_handler *handler;
    struct ir_raw_event_ctrl *raw = data;
    struct rc_dev *dev = raw->dev;

    while (1) {
        mutex_lock(&ir_raw_handler_lock);
        while (kfifo_out(&raw->kfifo, &ev, 1)) {
            // 从kfifo中取出数据
            if (is_timing_event(ev)) {
                if (ev.duration == 0)
                    dev_warn_once(&dev->dev, "nonsensical timing event of duration 0");
                if (is_timing_event(raw->prev_ev) && !is_transition(&ev, &raw->prev_ev))
                    dev_warn_once(&dev->dev, "two consecutive events of type %s", TO_STR(ev.pulse));
            }
            // 遍历所有注册的解析器，逐个解析事件
            list_for_each_entry(handler, &ir_raw_handler_list, list)
                if (dev->enabled_protocols & handler->protocols || !handler->protocols)
                    handler->decode(dev, ev);
            // LIRC设备处理原始事件
            lirc_raw_event(dev, ev);
            raw->prev_ev = ev;
        }
        mutex_unlock(&ir_raw_handler_lock);

        // 设置处理线程的运行状态，设置是否继续运行
        set_current_state(TASK_INTERRUPTIBLE);
        if (kthread_should_stop()) {
            __set_current_state(TASK_RUNNING);
            break;
        } else if (!kfifo_is_empty(&raw->kfifo))
            set_current_state(TASK_RUNNING);

        schedule();
    }
    return 0;
}
```

`lirc_raw_event`函数将采集的IR数据发送到LIRC设备，并接力到用户空间。其实现如下：

```C
// file: drivers/media/rc/lirc_dev.c
void lirc_raw_event(struct rc_dev *dev, struct ir_raw_event ev)
{
    unsigned long flags;
    struct lirc_fh *fh;
    int sample;

    if (ev.overflow) {
        // 接收溢出时，表示当前数据丢失
        // 发送lirc溢出消息，只要值设置为高值，lircd就会将其解释为长间隔。重置解码器状态
        sample = LIRC_OVERFLOW(LIRC_VALUE_MASK);
        dev_dbg(&dev->dev, "delivering overflow to lirc_dev\n");
    } else if (ev.carrier_report) {
        // 载波报告信息
        sample = LIRC_FREQUENCY(ev.carrier);
        dev_dbg(&dev->dev, "carrier report (freq: %d)\n", sample);
    } else if (ev.timeout) {
        // 帧结束
        dev->gap_start = ktime_get();
        sample = LIRC_TIMEOUT(ev.duration);
        dev_dbg(&dev->dev, "timeout report (duration: %d)\n", sample);
    } else {
        // 正常采样
        if (dev->gap_start) {
            u64 duration = ktime_us_delta(ktime_get(), dev->gap_start);
            // 限制在LIRC_VALUE_MASK范围内，防止溢出
            duration = min_t(u64, duration, LIRC_VALUE_MASK);

            spin_lock_irqsave(&dev->lirc_fh_lock, flags);
            // 将采样间隔放入用户空间的kfifo中
            list_for_each_entry(fh, &dev->lirc_fh, list)
                kfifo_put(&fh->rawir, LIRC_SPACE(duration));
            spin_unlock_irqrestore(&dev->lirc_fh_lock, flags);
            dev->gap_start = 0;
        }
        sample = ev.pulse ? LIRC_PULSE(ev.duration) : LIRC_SPACE(ev.duration);
        dev_dbg(&dev->dev, "delivering %uus %s to lirc_dev\n", ev.duration, TO_STR(ev.pulse));
    }
    // 运行BPF程序
    lirc_bpf_run(dev, sample);

    spin_lock_irqsave(&dev->lirc_fh_lock, flags);
    // 将采样率放入用户空间的kfifo中，并通知用户空间程序
    list_for_each_entry(fh, &dev->lirc_fh, list) {
        if (kfifo_put(&fh->rawir, sample))
            wake_up_poll(&fh->wait_poll, EPOLLIN | EPOLLRDNORM);
    }
    spin_unlock_irqrestore(&dev->lirc_fh_lock, flags);
}
```

#### 3 BPF程序处理采集数据的过程

`lirc_bpf_run`函数运行LIRC设备关联的BPF程序，其实现如下：

```C
// file: drivers/media/rc/bpf-lirc.c
void lirc_bpf_run(struct rc_dev *rcdev, u32 sample)
{
    struct ir_raw_event_ctrl *raw = rcdev->raw;
    raw->bpf_sample = sample;

    if (raw->progs) {
        rcu_read_lock();
        // 运行BPF程序列表
        bpf_prog_run_array(rcu_dereference(raw->progs), &raw->bpf_sample, bpf_prog_run);
        rcu_read_unlock();
    }
}
```

### 4.4 用户空间控制LIRC设备的实现过程

#### 1 文件操作接口

用户空间通过打开LIRC设备后，进行读取或写入数据等操作。在注册LIRC设备时，设置设备的操作接口为`lirc_fops`, 如下：

```C
// file: drivers/media/rc/lirc_dev.c
int lirc_register(struct rc_dev *dev)
{
    ...
    // cdev设备初始化，设置文件操作接口
    cdev_init(&dev->lirc_cdev, &lirc_fops);
    ...
}
```

其定义如下：

```C
// file: drivers/media/rc/lirc_dev.c
static const struct file_operations lirc_fops = {
    .owner      = THIS_MODULE,
    .write      = lirc_transmit,
    .unlocked_ioctl = lirc_ioctl,
    .compat_ioctl   = compat_ptr_ioctl,
    .read       = lirc_read,
    .poll       = lirc_poll,
    .open       = lirc_open,
    .release    = lirc_close,
    .llseek     = no_llseek,
};
```

#### 2 打开设备的实现

`.open`接口在打开文件时调用，设置为`lirc_open`， 其实现如下：

```C
// file: drivers/media/rc/lirc_dev.c
static int lirc_open(struct inode *inode, struct file *file)
{
    // 获取RC设备
    struct rc_dev *dev = container_of(inode->i_cdev, struct rc_dev, lirc_cdev);
    // 分配在内核空间使用的文件句柄
    struct lirc_fh *fh = kzalloc(sizeof(*fh), GFP_KERNEL);
    unsigned long flags;
    int retval;

    // 创建失败时，返回错误码
    if (!fh) return -ENOMEM;

    get_device(&dev->dev);
    // 设备未注册时，返回错误码
    if (!dev->registered) { retval = -ENODEV; goto out_fh; }

    if (dev->driver_type == RC_DRIVER_IR_RAW) {
        // IR_RAW设备时，分配原始数据的FIFO，`MAX_IR_EVENT_SIZE`定义为512
        if (kfifo_alloc(&fh->rawir, MAX_IR_EVENT_SIZE, GFP_KERNEL)) {
            retval = -ENOMEM; goto out_fh;
        }
    }
    if (dev->driver_type != RC_DRIVER_IR_RAW_TX) {
        // 不是发射器时，分配扫描码的FIFO
        if (kfifo_alloc(&fh->scancodes, 32, GFP_KERNEL)) {
            retval = -ENOMEM; goto out_rawir;
        }
    }
    // 设置发送、接收模式
    fh->send_mode = LIRC_MODE_PULSE;
    fh->rc = dev;
    if (dev->driver_type == RC_DRIVER_SCANCODE)
        fh->rec_mode = LIRC_MODE_SCANCODE;
    else
        fh->rec_mode = LIRC_MODE_MODE2;

    // 打开RC设备
    retval = rc_open(dev);
    if (retval)  goto out_kfifo;

    // 设置等待队列
    init_waitqueue_head(&fh->wait_poll);
    // 设置文件的私有数据
    file->private_data = fh;
    spin_lock_irqsave(&dev->lirc_fh_lock, flags);
    // 添加到到RC设备的文件句柄列表中
    list_add(&fh->list, &dev->lirc_fh);
    spin_unlock_irqrestore(&dev->lirc_fh_lock, flags);

    // 设置文件以数据流方式打开
    stream_open(inode, file);

    return 0;
    // 失败时处理过程
out_kfifo:
    if (dev->driver_type != RC_DRIVER_IR_RAW_TX) kfifo_free(&fh->scancodes);
out_rawir:
    if (dev->driver_type == RC_DRIVER_IR_RAW) kfifo_free(&fh->rawir);
out_fh:
    kfree(fh);
    put_device(&dev->dev);
    return retval;
}
```

#### 3 关闭设备的实现

`.release`接口在关闭文件时调用，设置为`lirc_close`， 其实现如下：

```C
// file: drivers/media/rc/lirc_dev.c
static int lirc_close(struct inode *inode, struct file *file)
{
    struct lirc_fh *fh = file->private_data;
    struct rc_dev *dev = fh->rc;
    unsigned long flags;

    spin_lock_irqsave(&dev->lirc_fh_lock, flags);
    // 从RC设备的文件句柄列表中删除
    list_del(&fh->list);
    spin_unlock_irqrestore(&dev->lirc_fh_lock, flags);

    // 释放原始数据和扫描码的FIFO
    if (dev->driver_type == RC_DRIVER_IR_RAW) 
        kfifo_free(&fh->rawir);
    if (dev->driver_type != RC_DRIVER_IR_RAW_TX)
        kfifo_free(&fh->scancodes);
    // 释放文件句柄
    kfree(fh);
    // 关闭RC设备
    rc_close(dev);
    put_device(&dev->dev);
    return 0;
}
```

#### 4 轮询的设备状态

`.poll`接口在通过`select、poll,epoll`方式查询状态时调用，设置为`lirc_poll`， 其实现如下：

```C
// file: drivers/media/rc/lirc_dev.c
static __poll_t lirc_poll(struct file *file, struct poll_table_struct *wait)
{
    struct lirc_fh *fh = file->private_data;
    struct rc_dev *rcdev = fh->rc;
    __poll_t events = 0;

    poll_wait(file, &fh->wait_poll, wait);

    if (!rcdev->registered) {
        // RC设备未注册时，返回HUP 和 ERR
        events = EPOLLHUP | EPOLLERR;
    } else if (rcdev->driver_type != RC_DRIVER_IR_RAW_TX) {
        // 扫描码或原始数据的FIFO有数据时，返回 IN 和 RDNORM
        if (fh->rec_mode == LIRC_MODE_SCANCODE && !kfifo_is_empty(&fh->scancodes))
            events = EPOLLIN | EPOLLRDNORM;
        if (fh->rec_mode == LIRC_MODE_MODE2 && !kfifo_is_empty(&fh->rawir))
            events = EPOLLIN | EPOLLRDNORM;
    }
    return events;
}
```

#### 5 读取设备数据的实现

`.read`接口在读取数据时调用，设置为`lirc_read`， 其实现如下：

```C
// file: drivers/media/rc/lirc_dev.c
static ssize_t lirc_read(struct file *file, char __user *buffer, size_t length, loff_t *ppos)
{
    struct lirc_fh *fh = file->private_data;
    struct rc_dev *rcdev = fh->rc;
    // 发射器不支持读操作
    if (rcdev->driver_type == RC_DRIVER_IR_RAW_TX) return -EINVAL;
    // 未注册的设备不能读取
    if (!rcdev->registered) return -ENODEV;

    if (fh->rec_mode == LIRC_MODE_MODE2)
        return lirc_read_mode2(file, buffer, length);
    else /* LIRC_MODE_SCANCODE */
        return lirc_read_scancode(file, buffer, length);
}
```

LIRC设备时，通过`lirc_read_mode2`函数读取设备数据，如下：

```C
// file: drivers/media/rc/lirc_dev.c
static ssize_t lirc_read_mode2(struct file *file, char __user *buffer, size_t length)
{
    struct lirc_fh *fh = file->private_data;
    struct rc_dev *rcdev = fh->rc;
    unsigned int copied;
    int ret;
    
    // 用户空间读取的长度检查，必须为`uint`的整数倍
    if (length < sizeof(unsigned int) || length % sizeof(unsigned int)) return -EINVAL;

    do {
        // 不存在原始数据时的处理
        if (kfifo_is_empty(&fh->rawir)) {
            // 非阻塞方式读取时，返回`EAGAIN`错误码
            if (file->f_flags & O_NONBLOCK) return -EAGAIN;

            // 阻塞方式读取时，等待有数据到达或者关闭事件
            ret = wait_event_interruptible(fh->wait_poll, 
                    !kfifo_is_empty(&fh->rawir) || !rcdev->registered);
            if (ret) return ret;
        }
        // 设备关闭时，返回错误码
        if (!rcdev->registered) return -ENODEV;

        ret = mutex_lock_interruptible(&rcdev->lock);
        if (ret) return ret;
        
        // 复制FIFO数据到用户空间缓冲区
        ret = kfifo_to_user(&fh->rawir, buffer, length, &copied);
        mutex_unlock(&rcdev->lock);
        if (ret) return ret;
        
        // 未读取到数据，一直读取
    } while (copied == 0);

    return copied;
}
```

`lirc_read_scancode`函数读取扫描码数据，实现和`lirc_read_mode2`类似，读取`fh->scancodes`中的数据。

#### 5 发送数据的实现

`.write`接口在写入数据时调用，设置为`lirc_transmit`， 其实现如下：

```C
// file: drivers/media/rc/lirc_dev.c
static ssize_t lirc_transmit(struct file *file, const char __user *buf, size_t n, loff_t *ppos)
{
    struct lirc_fh *fh = file->private_data;
    struct rc_dev *dev = fh->rc;
    unsigned int *txbuf;
    struct ir_raw_event *raw = NULL;
    ssize_t ret;
    size_t count;
    ktime_t start;
    s64 towait;
    unsigned int duration = 0; /* signal duration in us */
    int i;

    // 获取设备锁，失败时返回
    ret = mutex_lock_interruptible(&dev->lock);
    if (ret) return ret;
    // 设备未注册时，返回错误
    if (!dev->registered) { ret = -ENODEV; goto out_unlock; }
    // 设备不支持发送接口时，返回错误
    if (!dev->tx_ir) { ret = -EINVAL; goto out_unlock; }

    // 扫描码的处理
    if (fh->send_mode == LIRC_MODE_SCANCODE) {
        struct lirc_scancode scan;

        // 用户空间写入的数据检查
        if (n != sizeof(scan)) { ... }
        if (copy_from_user(&scan, buf, sizeof(scan))) { ... }
        if (scan.flags || scan.keycode || scan.timestamp || scan.rc_proto > RC_PROTO_MAX) { ... }
        if (scan.scancode > U32_MAX || !rc_validate_scancode(scan.rc_proto, scan.scancode)) { ... }

        // 分配原始事件
        raw = kmalloc_array(LIRCBUF_SIZE, sizeof(*raw), GFP_KERNEL);
        if (!raw) { ... }
        // 将扫描码编码为原始事件
        ret = ir_raw_encode_scancode(scan.rc_proto, scan.scancode, raw, LIRCBUF_SIZE);
        if (ret < 0) goto out_kfree_raw;

        count = ret;
        // 分配发送空间
        txbuf = kmalloc_array(count, sizeof(unsigned int), GFP_KERNEL);
        if (!txbuf) { ret = -ENOMEM; goto out_kfree_raw; }

        // 复制原始事件到发送缓冲区
        for (i = 0; i < count; i++)
            txbuf[i] = raw[i].duration;
        if (dev->s_tx_carrier) {
            // 查找指定协议的载波后，设置载波
            int carrier = ir_raw_encode_carrier(scan.rc_proto); 
            if (carrier > 0) dev->s_tx_carrier(dev, carrier);
        }
    } else {
        // 用户空间写入数据长度检查
        if (n < sizeof(unsigned int) || n % sizeof(unsigned int)) { ... }
        count = n / sizeof(unsigned int);
        if (count > LIRCBUF_SIZE || count % 2 == 0) { ... }

        // 将用户空间写入数据转换为发送数据
        txbuf = memdup_user(buf, n);
        if (IS_ERR(txbuf)) { ... }
    }
    // 计算发送间隔
    for (i = 0; i < count; i++) {
        if (txbuf[i] > IR_MAX_DURATION - duration || !txbuf[i]) { ... }
        duration += txbuf[i];
    }
    // 记录开始发送时间
    start = ktime_get();
    // RC设备发送红外数据
    ret = dev->tx_ir(dev, txbuf, count);
    if (ret < 0) goto out_kfree;
    // 释放使用的缓冲区
    kfree(txbuf);
    kfree(raw);
    mutex_unlock(&dev->lock);

    // lircd 间隙在红外信号传输前需要等待
    towait = ktime_us_delta(ktime_add_us(start, duration), ktime_get());
    if (towait > 0) {
        // 中断当前任务，等待红外信号发送
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(usecs_to_jiffies(towait));
    }
    return n;
    // 失败时处理
out_kfree:
    kfree(txbuf);
out_kfree_raw:
    kfree(raw);
out_unlock:
    mutex_unlock(&dev->lock);
    return ret;
}
```

#### 6 ioctl的实现

`.unlocked_ioctl`接口在`ioctl`控制时调用，设置为`lirc_ioctl`， 其实现如下：

```C
// file: drivers/media/rc/lirc_dev.c
static long lirc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct lirc_fh *fh = file->private_data;
    struct rc_dev *dev = fh->rc;
    u32 __user *argp = (u32 __user *)(arg);
    u32 val = 0;
    int ret;

    // _IOC_WRITE指令，读取用户空间数据
    if (_IOC_DIR(cmd) & _IOC_WRITE) {
        ret = get_user(val, argp);
        if (ret) return ret;
    }
    // 获取RC设备锁
    ret = mutex_lock_interruptible(&dev->lock);
    if (ret) return ret;
    // 设备未注册时，返回错误
    if (!dev->registered) { ret = -ENODEV; goto out; }

    switch (cmd) {
    // 获取设备支持的功能
    case LIRC_GET_FEATURES:
        // 扫码设备
        if (dev->driver_type == RC_DRIVER_SCANCODE)
            val |= LIRC_CAN_REC_SCANCODE;
        // LIRC设备
        if (dev->driver_type == RC_DRIVER_IR_RAW) {
            val |= LIRC_CAN_REC_MODE2;
            // 支持获取解析分辨率
            if (dev->rx_resolution) val |= LIRC_CAN_GET_REC_RESOLUTION;
        }
        if (dev->tx_ir) {
            // 支持发送脉冲
            val |= LIRC_CAN_SEND_PULSE;
            // 支持设置传输码
            if (dev->s_tx_mask) val |= LIRC_CAN_SET_TRANSMITTER_MASK;
            // 支持设置发送载波
            if (dev->s_tx_carrier) val |= LIRC_CAN_SET_SEND_CARRIER;
            // 支持设置发送占空比
            if (dev->s_tx_duty_cycle) val |= LIRC_CAN_SET_SEND_DUTY_CYCLE;
        }
        // 支持设置接收载波范围
        if (dev->s_rx_carrier_range)
            val |= LIRC_CAN_SET_REC_CARRIER | LIRC_CAN_SET_REC_CARRIER_RANGE;
        // 支持多波段接收
        if (dev->s_wideband_receiver)
            val |= LIRC_CAN_USE_WIDEBAND_RECEIVER;
        // 支持载波报告
        if (dev->s_carrier_report)
            val |= LIRC_CAN_MEASURE_CARRIER;
        // 支持接收超时时间设置
        if (dev->max_timeout)
            val |= LIRC_CAN_SET_REC_TIMEOUT;
        break;

    // 获取接收模式
    case LIRC_GET_REC_MODE: ... break;
    // 设置接收模式
    case LIRC_SET_REC_MODE: ... break;
    // 获取发送模式
    case LIRC_GET_SEND_MODE: ... break;
    // 设置发送模式
    case LIRC_SET_SEND_MODE: ... break;
    ...
    default:
        ret = -ENOTTY;
    }
    // _IOC_READ指令，读取内核空间数据
    if (!ret && _IOC_DIR(cmd) & _IOC_READ)
        ret = put_user(val, argp);
out:
    mutex_unlock(&dev->lock);
    return ret;
}
```

## 5 总结

本文通过`test_lirc_mode2`示例程序分析了BPF在红外设备解码的实现，通过将BPF程序挂载到LIRC设备上，可以自定义红外解码实现。

## 参考资料

* [IR decoding with BPF](https://lwn.net/Articles/759188/)