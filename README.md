# bpf-inside: 探索BPF内核的实现

通过一些小工具探索BPF在Linux内核的实现。

## 目录


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
