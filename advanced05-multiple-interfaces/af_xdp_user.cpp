/* SPDX-License-Identifier: GPL-2.0 */

#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/xsk.h>
#include <errno.h>
#include <getopt.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ipv6.h>
#include <locale.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "../common/common_libbpf.h"
#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info {
  struct xsk_ring_prod fq;
  struct xsk_ring_cons cq;
  struct xsk_umem *umem;
  void *buffer;
};

struct stats_record {
  uint64_t timestamp;
  uint64_t rx_packets;
  uint64_t rx_bytes;
  uint64_t tx_packets;
  uint64_t tx_bytes;
};

struct xsk_socket_info {
  struct xsk_ring_cons rx;
  struct xsk_ring_prod tx;
  struct xsk_umem_info *umem;
  struct xsk_socket *xsk;

  uint64_t umem_frame_addr[NUM_FRAMES];
  uint32_t umem_frame_free;

  uint32_t outstanding_tx;

  struct stats_record stats;
  struct stats_record prev_stats;
};

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r) {
  r->cached_cons = *r->consumer + r->size;
  return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static bool global_exit;
int num_ifs;

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size) {
  struct xsk_umem_info *umem;
  int ret;

  umem = (struct xsk_umem_info *)calloc(1, sizeof(*umem));
  if (!umem)
    return NULL;

  ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
  if (ret) {
    errno = -ret;
    return NULL;
  }

  umem->buffer = buffer;
  return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {
  uint64_t frame;
  if (xsk->umem_frame_free == 0)
    return INVALID_UMEM_FRAME;

  frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
  xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
  return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame) {
  assert(xsk->umem_frame_free < NUM_FRAMES);

  xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk) {
  return xsk->umem_frame_free;
}

static struct xsk_socket_info *
xsk_configure_socket(struct config *cfg, struct xsk_umem_info *umem) {
  struct xsk_socket_config xsk_cfg;
  struct xsk_socket_info *xsk_info;
  uint32_t idx;
  uint32_t prog_id = 0;
  int i;
  int ret;

  xsk_info = (struct xsk_socket_info *)calloc(1, sizeof(*xsk_info));
  if (!xsk_info)
    return NULL;

  xsk_info->umem = umem;
  xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
  xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
  xsk_cfg.libbpf_flags = 0;
  xsk_cfg.xdp_flags = cfg->xdp_flags;
  xsk_cfg.bind_flags = cfg->xsk_bind_flags;
  ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname, cfg->xsk_if_queue,
                           umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_cfg);

  if (ret)
    goto error_exit;

  ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
  if (ret)
    goto error_exit;

  /* Initialize umem frame allocation */

  for (i = 0; i < NUM_FRAMES; i++)
    xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

  xsk_info->umem_frame_free = NUM_FRAMES;

  /* Stuff the receive path with buffers, we assume we have enough */
  ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                               XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);

  if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
    goto error_exit;

  for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
    *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
        xsk_alloc_umem_frame(xsk_info);

  xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

  return xsk_info;

error_exit:
  errno = -ret;
  return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk) {
  unsigned int completed;
  uint32_t idx_cq;

  if (!xsk->outstanding_tx)
    return;

  sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

  /* Collect/free completed TX buffers */
  completed = xsk_ring_cons__peek(&xsk->umem->cq,
                                  XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

  if (completed > 0) {
    for (int i = 0; i < completed; i++)
      xsk_free_umem_frame(xsk,
                          *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++));

    xsk_ring_cons__release(&xsk->umem->cq, completed);
    xsk->outstanding_tx -=
        completed < xsk->outstanding_tx ? completed : xsk->outstanding_tx;
  }
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend) {
  uint16_t res = (uint16_t)csum;

  res += (__u16)addend;
  return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend) {
  return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new_v) {
  *sum = ~csum16_add(csum16_sub(~(*sum), old), new_v);
}

static bool process_packet(struct xsk_socket_info *xsk, const char *ifname, uint64_t addr,
                           uint32_t len)
{
  uint8_t *pkt = (uint8_t *)xsk_umem__get_data(xsk->umem->buffer, addr);

  printf("[%s] ", ifname);

  for (int i = 0; i < len; i++) {
    printf("%02x", pkt[i]);
  }
  printf("\n");

  /* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
   *
   * Some assumptions to make it easier:
   * - No VLAN handling
   * - Only if nexthdr is ICMP
   * - Just return all data with MAC/IP swapped, and type set to
   *   ICMPV6_ECHO_REPLY
   * - Recalculate the icmp checksum */

  if (false) {
    int ret;
    uint32_t tx_idx = 0;
    uint8_t tmp_mac[ETH_ALEN];
    struct in6_addr tmp_ip;
    struct ethhdr *eth = (struct ethhdr *)pkt;
    struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);
    struct icmp6hdr *icmp = (struct icmp6hdr *)(ipv6 + 1);

    if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
        len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*icmp)) ||
        ipv6->nexthdr != IPPROTO_ICMPV6 ||
        icmp->icmp6_type != ICMPV6_ECHO_REQUEST)
      return false;

    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
    memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
    memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));

    icmp->icmp6_type = ICMPV6_ECHO_REPLY;

    csum_replace2(&icmp->icmp6_cksum, htons(ICMPV6_ECHO_REQUEST << 8),
                  htons(ICMPV6_ECHO_REPLY << 8));

    /* Here we sent the packet out of the receive port. Note that
     * we allocate one entry and schedule it. Your design would be
     * faster if you do batch processing/transmission */

    ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
    if (ret != 1) {
      /* No more transmit slots, drop the packet */
      return false;
    }

    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
    xsk_ring_prod__submit(&xsk->tx, 1);
    xsk->outstanding_tx++;

    xsk->stats.tx_bytes += len;
    xsk->stats.tx_packets++;
    return true;
  }

  return false;
}

static void handle_receive_packets(struct xsk_socket_info *xsk, const char *ifname) {
  unsigned int rcvd, stock_frames, i;
  uint32_t idx_rx = 0, idx_fq = 0;
  int ret;

  rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
  if (!rcvd)
    return;

  /* Stuff the ring with as much frames as possible */
  stock_frames = xsk_prod_nb_free(&xsk->umem->fq, xsk_umem_free_frames(xsk));

  if (stock_frames > 0) {
    ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames, &idx_fq);

    /* This should not happen, but just in case */
    while (ret != stock_frames)
      ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);

    for (i = 0; i < stock_frames; i++)
      *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
          xsk_alloc_umem_frame(xsk);

    xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
  }

  /* Process received packets */
  for (i = 0; i < rcvd; i++) {
    uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
    uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

    if (!process_packet(xsk, ifname, addr, len))
      xsk_free_umem_frame(xsk, addr);

    xsk->stats.rx_bytes += len;
  }

  xsk_ring_cons__release(&xsk->rx, rcvd);
  xsk->stats.rx_packets += rcvd;

  /* Do we need to wake up the kernel for transmission */
  complete_tx(xsk);
}

/*
static void rx_and_process(struct config *cfg,
                           struct xsk_socket_info *xsk_socket) {
  struct pollfd fds[2];
  int ret, nfds = 1;

  memset(fds, 0, sizeof(fds));
  fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
  fds[0].events = POLLIN;

  while (!global_exit) {
    if (cfg->xsk_poll_mode) {
      ret = poll(fds, nfds, -1);
      if (ret <= 0 || ret > 1)
        continue;
    }
    handle_receive_packets(xsk_socket);
  }
}
*/

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void) {
  struct timespec t;
  int res;

  res = clock_gettime(CLOCK_MONOTONIC, &t);
  if (res < 0) {
    fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
    exit(EXIT_FAIL);
  }
  return (uint64_t)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p) {
  double period_ = 0;
  __u64 period = 0;

  period = r->timestamp - p->timestamp;
  if (period > 0)
    period_ = ((double)period / NANOSEC_PER_SEC);

  return period_;
}

static void stats_print(struct stats_record *stats_rec,
                        struct stats_record *stats_prev) {
  uint64_t packets, bytes;
  double period;
  double pps; /* packets per sec */
  double bps; /* bits per sec */

  char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
              " %'11lld Kbytes (%'6.0f Mbits/s)"
              " period:%f\n";

  period = calc_period(stats_rec, stats_prev);
  if (period == 0)
    period = 1;

  packets = stats_rec->rx_packets - stats_prev->rx_packets;
  pps = packets / period;

  bytes = stats_rec->rx_bytes - stats_prev->rx_bytes;
  bps = (bytes * 8) / period / 1000000;

  printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
         stats_rec->rx_bytes / 1000, bps, period);

  packets = stats_rec->tx_packets - stats_prev->tx_packets;
  pps = packets / period;

  bytes = stats_rec->tx_bytes - stats_prev->tx_bytes;
  bps = (bytes * 8) / period / 1000000;

  printf(fmt, "       TX:", stats_rec->tx_packets, pps,
         stats_rec->tx_bytes / 1000, bps, period);

  printf("\n");
}

static void *stats_poll(void *arg) {
  unsigned int interval = 2;
  struct xsk_socket_info **xsks = (struct xsk_socket_info **)arg;
  static struct stats_record previous_stats = {0};

  previous_stats.timestamp = gettime();

  /* Trick to pretty printf with thousands separators use %' */
  setlocale(LC_NUMERIC, "en_US");

  while (!global_exit) {
    sleep(interval);
    for(int i=0;i<num_ifs;i++) {
      xsks[i]->stats.timestamp = gettime();
      stats_print(&xsks[i]->stats, &previous_stats);
    }
    previous_stats = xsks[0]->stats;
  }
  return NULL;
}

static void exit_application(int signal) {
  signal = signal;
  global_exit = true;
}

#define MAX_INTERFACES 5

char enable_interfaces[][IF_NAMESIZE] = {
    "ens224", "ens256"};

int main(int argc, char **argv) {
  int ret;
  uint64_t packet_buffer_size;
  pthread_t stats_poll_thread;

  int xsks_map_fds[MAX_INTERFACES];
  void *packet_buffers[MAX_INTERFACES];
  struct rlimit rlims[MAX_INTERFACES];
  struct config cfgs[MAX_INTERFACES];
  struct xsk_umem_info *umems[MAX_INTERFACES];
  struct xsk_socket_info *xsk_sockets[MAX_INTERFACES];
  struct bpf_object *bpf_objs[MAX_INTERFACES];

  /* Global shutdown handler */
  signal(SIGINT, exit_application);

  num_ifs = sizeof(enable_interfaces) / IF_NAMESIZE;

  printf("enabling %d interfaces\n", num_ifs);
  for (int i = 0; i < num_ifs; i++) {
    memset(&cfgs[i], 0x00, sizeof(struct config));
    bpf_objs[i] = NULL;
    rlims[i].rlim_cur = RLIM_INFINITY;
    rlims[i].rlim_max = RLIM_INFINITY;

    strncpy(cfgs[i].ifname_buf, enable_interfaces[i], IF_NAMESIZE);
    cfgs[i].ifname = (char *) &cfgs[i].ifname_buf;
    cfgs[i].ifindex = if_nametoindex(cfgs[i].ifname);

    printf("index %d\n", cfgs[i].ifindex);

    /* Required option */
    if (cfgs[i].ifindex == -1) {
      fprintf(stderr, "ERROR: Missing interface\n\n");
      exit(EXIT_FAILURE);
    }

    strcpy(cfgs[i].filename, "af_xdp_kern.o");
    strcpy(cfgs[i].progsec, "xdp_sock");
  }

  /* Load custom program */
  for (int i = 0; i < num_ifs; i++) {
    struct bpf_map *map;

    bpf_objs[i] = load_bpf_and_xdp_attach(&cfgs[i]);
    if (!bpf_objs[i]) {
      /* Error handling done in load_bpf_and_xdp_attach() */
      exit(EXIT_FAILURE);
    }

    /* We also need to load the xsks_map */
    map = bpf_object__find_map_by_name(bpf_objs[i], "xsks_map");
    xsks_map_fds[i] = bpf_map__fd(map);
    if (xsks_map_fds[i] < 0) {
      fprintf(stderr, "ERROR: no xsks map found: %s\n",
              strerror(xsks_map_fds[i]));
      exit(EXIT_FAILURE);
    }
  }

  packet_buffer_size = NUM_FRAMES * FRAME_SIZE;

  for (int i = 0; i < num_ifs; i++) {
    /* Allow unlimited locking of memory, so all memory needed for packet
     * buffers can be locked.
     */
    if (setrlimit(RLIMIT_MEMLOCK, &rlims[i])) {
      fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }

    /* Allocate memory for NUM_FRAMES of the default XDP frame size */
    if (posix_memalign(&packet_buffers[i],
                       getpagesize(), /* PAGE_SIZE aligned */
                       packet_buffer_size)) {
      fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }

    /* Initialize shared packet_buffer for umem usage */
    umems[i] = configure_xsk_umem(packet_buffers[i], packet_buffer_size);
    if (umems[i] == NULL) {
      fprintf(stderr, "ERROR: Can't create umem \"%s\"\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    /* Open and configure the AF_XDP (xsk) socket */
    xsk_sockets[i] = xsk_configure_socket(&cfgs[i], umems[i]);
    if (xsk_sockets[i] == NULL) {
      fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  /* Start thread to do statistics display */
  if (verbose) {
    ret = pthread_create(&stats_poll_thread, NULL, stats_poll, xsk_sockets);
    if (ret) {
      fprintf(stderr,
              "ERROR: Failed creating statistics thread "
              "\"%s\"\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  while(!global_exit) {

    struct pollfd fds[MAX_INTERFACES + 1];
    int ret, nfds = num_ifs;

    memset(fds, 0, sizeof(fds));

    for (int i = 0; i < num_ifs; i++) {
      fds[i].fd = xsk_socket__fd(xsk_sockets[i]->xsk);
      fds[i].events = POLLIN;
    }

    while (!global_exit) {
      if (true) {
        ret = poll(fds, nfds, -1);
        if (ret <= 0 || ret > 1){
          continue;
        }
      }

      for (int i = 0; i < num_ifs; i++) {
        if (fds[i].revents & POLLIN) {
          handle_receive_packets(xsk_sockets[i], cfgs[i].ifname);
        }
      }

    }

  }

  /* Cleanup */
  for (int i = 0; i < num_ifs; i++) {
    xsk_socket__delete(xsk_sockets[i]->xsk);
    xsk_umem__delete(umems[i]->umem);
    xdp_link_detach(cfgs[i].ifindex, cfgs[i].xdp_flags, 0);
  }

  return EXIT_OK;
}
