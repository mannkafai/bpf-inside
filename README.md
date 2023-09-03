# bpf-inside: 探索BPF内核的实现

通过一些小工具探索BPF在Linux内核的实现。

## 目录

* [使用libbpf库编写BPF程序](doc/01-write%20a%20bpf%20program%20with%20libbpf.md)
* [Linux性能计数器在内核的实现](doc/02-Performance%20Counters%20for%20Linux.md)
* [Tracepoint的内核实现](doc/03-tracepoint%20inside.md)
* [CPU-PMU的内核实现](doc/04-cpu%20pmu.md)
* [SOFTWARE-PMU的内核实现](doc/05-software%20pmu.md)
* [KPROBE的内核实现](doc/06-kprobe%20pmu.md)
* [UPROBE的内核实现](doc/07-uprobe.md)
* [RAW TRACEPOINT的内核实现](doc/08-raw%20tracepoint.md)
* [fentry的内核实现](doc/09-fentry.md)
* [KPROBE.MULTI的内核实现](doc/10-kprobe_multi.md)
* [BPF LSM的内核实现](doc/11-bpf%20lsm.md)
* [XDP的内核实现](doc/12-xdp.md)
* [SOCKFILTER的内核实现](doc/13-sockfilter.md)
* [TC的内核实现](doc/14-tc.md)

## 编译示例

Makefile build:

```shell
$ git submodule update --init --recursive       # check out libbpf
$ cd src
$ make
$ sudo ./bin/minimal
<...>
```

CMake build:

```shell
$ git submodule update --init --recursive       # check out libbpf
$ mkdir build && cd build
$ cmake ../src
$ make
$ sudo ./minimal
<...>
```
