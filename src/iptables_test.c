// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iptables_test.h"
#include "iptables_test.skel.h"

#define PORT 8888

struct iptables_test_bpf *skel;
int map_fd;
bool test_finish;
char temp_dir[30];
char file[50];

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void prog_attach_iptables()
{
    int ret;
    char rules[256];
    char template[] = "/tmp/bpf.XXXXXX";
    char *temp_ = mkdtemp(template);
    if (temp_ == NULL)
        error(1, errno, "make temp dir");
    snprintf(temp_dir, sizeof(temp_dir), "%s", temp_);

    ret = mount(temp_dir, temp_dir, "bpf", 0, NULL);
    if (ret)
        error(1, errno, "mount bpf");

    snprintf(file, sizeof(file), "%s/bpf_prog", temp_dir);

    if (bpf_program__pin(skel->progs.iptables_accepted, file))
        error(1, errno, "bpf_obj_pin");

    ret = snprintf(rules, sizeof(rules),
                   "iptables -A OUTPUT -m bpf --object-pinned %s -j ACCEPT", file);
    if (ret < 0 || ret >= sizeof(rules))
    {
        printf("error constructing iptables command\n");
        exit(1);
    }
    ret = system(rules);
    if (ret < 0)
    {
        printf("iptables rule update failed: %d/n", WEXITSTATUS(ret));
        exit(1);
    }
}

static void prog_detach_iptables()
{
    int ret;
    char rules[256];
    ret = snprintf(rules, sizeof(rules),
                   "iptables -D OUTPUT -m bpf --object-pinned %s -j ACCEPT", file);
    if (ret < 0 || ret >= sizeof(rules))
    {
        printf("error constructing iptables command\n");
        exit(1);
    }
    ret = system(rules);
    if (ret < 0)
    {
        printf("iptables rule delete failed: %d/n", WEXITSTATUS(ret));
        exit(1);
    }

    ret = bpf_program__unpin(skel->progs.iptables_accepted, file);
    if (ret)
        printf("error unpin bpf prog\n");

    ret = umount(temp_dir);
    if (ret)
        printf("error umount bpf. errno:%d\n", errno);

    ret = rmdir(temp_dir);
    if (ret)
        printf("error rmdir temp dir. ret:%d, errno:%d\n", ret, errno);
}

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
        {
            error(1, errno, "fail to get entry value of Key: %u\n", curN);
        }
        else
        {
            printf("cookie: %u, uid: 0x%x, Packet Count: %lu,"
                   " Bytes Count: %lu\n",
                   curN, curEntry.uid,
                   curEntry.packets, curEntry.bytes);
        }
    }
}

static void udp_client(void)
{
    struct sockaddr_in si_other = {0};
    struct sockaddr_in si_me = {0};
    struct stats dataEntry;
    int s_rcv, s_send, i, recv_len;
    char message = 'a';
    char buf;
    uint64_t cookie;
    int res;
    socklen_t cookie_len = sizeof(cookie);
    socklen_t slen = sizeof(si_other);

    s_rcv = socket(PF_INET, SOCK_DGRAM, 0);
    if (s_rcv < 0)
        error(1, errno, "rcv socket creat failed!\n");
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(PORT);
    if (inet_aton("127.0.0.1", &si_other.sin_addr) == 0)
        error(1, errno, "inet_aton\n");
    if (bind(s_rcv, (struct sockaddr *)&si_other, sizeof(si_other)) == -1)
        error(1, errno, "bind\n");
    s_send = socket(PF_INET, SOCK_DGRAM, 0);
    if (s_send < 0)
        error(1, errno, "send socket creat failed!\n");
    res = getsockopt(s_send, SOL_SOCKET, SO_COOKIE, &cookie, &cookie_len);
    if (res < 0)
        printf("get cookie failed: %s\n", strerror(errno));
    res = bpf_map_lookup_elem(map_fd, &cookie, &dataEntry);
    // if (res != -1)
    // 	error(1, errno, "socket stat found while flow not active\n");
    for (i = 0; i < 10; i++)
    {
        res = sendto(s_send, &message, sizeof(message), 0,
                     (struct sockaddr *)&si_other, slen);
        if (res == -1)
            error(1, errno, "send\n");
        if (res != sizeof(message))
            error(1, 0, "%uB != %luB\n", res, sizeof(message));
        recv_len = recvfrom(s_rcv, &buf, sizeof(buf), 0,
                            (struct sockaddr *)&si_me, &slen);
        if (recv_len < 0)
            error(1, errno, "receive\n");
        res = memcmp(&(si_other.sin_addr), &(si_me.sin_addr),
                     sizeof(si_me.sin_addr));
        if (res != 0)
            error(1, EFAULT, "sender addr error: %d\n", res);
        printf("Message received: %c\n", buf);
        res = bpf_map_lookup_elem(map_fd, &cookie, &dataEntry);
        if (res < 0)
            error(1, errno, "lookup sk stat failed, cookie: %lu\n",
                  cookie);
        printf("cookie: %lu, uid: 0x%x, Packet Count: %lu,"
               " Bytes Count: %lu\n\n",
               cookie, dataEntry.uid,
               dataEntry.packets, dataEntry.bytes);
    }
    close(s_send);
    close(s_rcv);
}

static void finish(int ret)
{
    test_finish = true;
}

int main(int argc, char *argv[])
{
    int opt;
    bool cfg_test_traffic = false;
    bool cfg_test_cookie = false;
    while ((opt = getopt(argc, argv, "ts")) != -1)
    {
        switch (opt)
        {
        case 't':
            cfg_test_traffic = true;
            break;
        case 's':
            cfg_test_cookie = true;
            break;
        }
    }
    if (!cfg_test_cookie && !cfg_test_traffic)
        cfg_test_traffic = true;

    int err;
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open load and verify BPF application */
    skel = iptables_test_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    map_fd = bpf_map__fd(skel->maps.cookie_stats);

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
    prog_detach_iptables();
    iptables_test_bpf__destroy(skel);
    return -err;
}