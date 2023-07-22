# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

cmake_minimum_required(VERSION 3.16)
project(examples)

# Tell cmake where to find BpfObject module
get_filename_component(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
list(APPEND CMAKE_MODULE_PATH ${PROJECT_ROOT}/tools/cmake)

# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${PROJECT_ROOT}/libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${PROJECT_ROOT}/bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

find_program(CARGO_EXISTS cargo)
if(CARGO_EXISTS)
  ExternalProject_Add(blazesym
    PREFIX blazesym
    SOURCE_DIR ${PROJECT_ROOT}/blazesym
    CONFIGURE_COMMAND ""
    BUILD_COMMAND cargo build --release
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    STEP_TARGETS build
  )
endif()

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
  set(ARCH "x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
  set(ARCH "arm")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
  set(ARCH "arm64")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "ppc64le")
  set(ARCH "powerpc")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
  set(ARCH "mips")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "riscv64")
  set(ARCH "riscv")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "loongarch64")
  set(ARCH "loongarch")
endif()

set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${PROJECT_ROOT}/vmlinux/${ARCH}/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

set(BZ_APPS profile)

# Create an executable for each application
file(GLOB apps *.bpf.c)
if(NOT CARGO_EXISTS)
  foreach(app ${BZ_APPS})
    list(REMOVE_ITEM apps ${CMAKE_CURRENT_SOURCE_DIR}/${app}.bpf.c)
  endforeach()
endif()
foreach(app ${apps})
  get_filename_component(app_stem ${app} NAME_WE)

  # Build object skeleton and depend skeleton on libbpf build
  bpf_object(${app_stem} ${app_stem}.bpf.c)
  add_dependencies(${app_stem}_skel libbpf-build bpftool-build)

  add_executable(${app_stem} ${app_stem}.c)
  target_link_libraries(${app_stem} ${app_stem}_skel)
endforeach()

if(CARGO_EXISTS)
  foreach(app_stem ${BZ_APPS})
    target_include_directories(${app_stem} PRIVATE
      ${PROJECT_ROOT}/blazesym/include)
    target_link_libraries(${app_stem}
      ${PROJECT_ROOT}/blazesym/target/release/libblazesym.a -lpthread -lrt -ldl)
  endforeach()
endif()
