#ifndef COMMON_H
#define COMMON_H

#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#if !defined(LIBBPF_MAJOR_VERSION)
int bpf_xdp_attach(int ifindex, int prog_fd, unsigned int flags, const void *opts);
int bpf_xdp_detach(int ifindex, unsigned int flags, const void *opts);
#elif LIBBPF_MAJOR_VERSION < 1 || (LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION < 2)
int bpf_xdp_attach(int ifindex, int prog_fd, unsigned int flags, const void *opts);
int bpf_xdp_detach(int ifindex, unsigned int flags, const void *opts);
#endif
#include <xdp/xsk.h>
#include <errno.h>

#define MAX_QUEUES      64

#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif
#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 2)
#endif
#ifndef XDP_FLAGS_HW_MODE
#define XDP_FLAGS_HW_MODE (1U << 3)
#endif

#ifndef XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
#define XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD (1U << 0)
#endif

#endif
