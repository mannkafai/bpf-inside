# bpf-inside: 探索BPF内核的实现

通过一些小工具探索BPF在Linux内核的实现。

## 目录

* [01-使用libbpf库编写BPF程序](doc/01-write%20a%20bpf%20program%20with%20libbpf.md)
* [02-Linux性能计数器在内核的实现](doc/02-Performance%20Counters%20for%20Linux.md)
* [03-Tracepoint的内核实现](doc/03-tracepoint%20inside.md)
* [04-CPU-PMU的内核实现](doc/04-cpu%20pmu.md)
* [05-SOFTWARE-PMU的内核实现](doc/05-software%20pmu.md)
* [06-KPROBE的内核实现](doc/06-kprobe%20pmu.md)
* [07-UPROBE的内核实现](doc/07-uprobe.md)
* [08-RAW TRACEPOINT的内核实现](doc/08-raw%20tracepoint.md)
* [09-fentry的内核实现](doc/09-fentry.md)
* [10-KPROBE.MULTI的内核实现](doc/10-kprobe_multi.md)
* [11-BPF LSM的内核实现](doc/11-bpf%20lsm.md)
* [12-XDP的内核实现](doc/12-xdp.md)
* [13-SOCKFILTER的内核实现](doc/13-sockfilter.md)
* [14-TC的内核实现](doc/14-tc.md)
* [15-LWT的内核实现](doc/15-lwt.md)
* [16-IPTABLES_BPF内核实现](doc/16-iptables_bpf.md)
* [17-SK_LOOKUP的内核实现](doc/17-sk_lookup.md)
* [18-CGROUP_BPF的内核实现](doc/18-cgroup.md)
* [19-STRUCT_OPS的内核实现](doc/19-struct_ops.md)
* [20-FLOW_DISSECTOR的内核实现](doc/20-flow_dissector.md)
* [21-SOCKMAP的内核实现](doc/21-sockmap.md)

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
