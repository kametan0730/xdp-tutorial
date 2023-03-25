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

#include "net.h"
#include "ethernet.h"
#include "config.h"
#include "ip.h"
#include "binary_trie.h"


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

struct net_device_data{
  int index;
  int xsks_map_fd;
  void *packet_buffer;
  struct rlimit rlim;
  struct config cfg;
  struct xsk_umem_info *umem;
  struct xsk_socket_info *xsk_socket;
  struct bpf_object *bpf_obj;
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

static bool process_packet(struct xsk_socket_info *xsk, struct net_device* dev, const char *ifname, uint64_t addr,
                           uint32_t len)
{
  uint8_t *pkt = (uint8_t *) xsk_umem__get_data(xsk->umem->buffer, addr);

  printf("[%s] ", ifname);

  for (int i = 0; i < len; i++) {
    printf("%02x", pkt[i]);
  }
  printf("\n");

  ethernet_input(dev, pkt, len);

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

static void handle_receive_packets(struct xsk_socket_info *xsk, const char *ifname, struct net_device *dev) {
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

    if (!process_packet(xsk, dev, ifname, addr, len))
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

/**
 * ネットデバイスの送信処理
 * @param dev
 * @param buf
 * @return
 */
int net_device_transmit(struct net_device *dev, uint8_t *buffer, size_t len)
{
  int ret;
  uint32_t tx_idx = 0;

  struct xsk_socket_info *xsk = ((struct net_device_data *)dev->data)->xsk_socket;

  ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
  if (ret != 1)
  {
    /* No more transmit slots, drop the packet */
    return false;
  }

  xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = (uint64_t) buffer;
  xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx++;

  xsk->stats.tx_bytes += len;
  xsk->stats.tx_packets++;

  /*
  struct rte_mbuf *mbuf;
  mbuf = rte_pktmbuf_alloc(mbuf_pool);
  uint8_t *bbb_buf = rte_pktmbuf_mtod(mbuf, uint8_t *);
  mbuf->pkt_len = len;
  mbuf->buf_len = len;
  mbuf->data_len = len;

  memcpy(bbb_buf, buffer, len);

  const uint16_t nb_tx =
      rte_eth_tx_burst(((net_device_data *)dev->data)->port, 0, &mbuf, 1);
  if (nb_tx < 1)
  {
    rte_pktmbuf_free(mbuf);
  }
  */
  return 0;
}

/**
 * ネットワークデバイスの受信処理
 * @param dev
 * @return
 */
int net_device_poll(net_device *dev)
{
  /*
  struct rte_mbuf *buf;
  const uint16_t nb_rx =
      rte_eth_rx_burst(((net_device_data *)dev->data)->port, 0, &buf, 1);

  if (unlikely(nb_rx == 0))
    return 0;
  // 受信したデータをイーサネットに送る
  ethernet_input(dev, rte_pktmbuf_mtod(buf, uint8_t *), buf->data_len);
  */
  return 0;
}

#define MAX_INTERFACES 5

char enable_interfaces[][IF_NAMESIZE] = { "ens224", "ens256"};
unsigned char iface_hwaddrs[][6] = {
    {0x00, 0x50, 0x56, 0x87, 0x4c, 0xb4},
    {0x00, 0x50, 0x56, 0x87, 0x3c, 0x32}
};

/**
 * インターフェース名からデバイスを探す
 * @param interface
 * @return
 */
net_device *get_net_device_by_name(const char *interface)
{
  net_device *dev;
  for (dev = net_dev_list; dev; dev = dev->next)
  {
    if (strcmp(dev->name, interface) == 0)
    {
      return dev;
    }
  }
  return nullptr;
}

int main(int argc, char **argv) {
  int ret;
  uint64_t packet_buffer_size;
  pthread_t stats_poll_thread;

/*
  int xsks_map_fds[MAX_INTERFACES];
  void *packet_buffers[MAX_INTERFACES];
  struct rlimit rlims[MAX_INTERFACES];
  struct config cfgs[MAX_INTERFACES];
  struct xsk_umem_info *umems[MAX_INTERFACES];
  struct xsk_socket_info *xsk_sockets[MAX_INTERFACES];
  struct bpf_object *bpf_objs[MAX_INTERFACES];
*/

  /* Global shutdown handler */
  signal(SIGINT, exit_application);

  num_ifs = sizeof(enable_interfaces) / IF_NAMESIZE;

  printf("enabling %d interfaces\n", num_ifs);
  for (int i = 0; i < num_ifs; i++) {

    struct net_device *dev = (struct net_device *)calloc(1, sizeof(struct net_device) + sizeof(struct net_device_data));

    ((net_device_data *)dev->data)->index = i;
    memset(&((net_device_data *)dev->data)->cfg, 0x00, sizeof(struct config));
    ((net_device_data *)dev->data)->bpf_obj = NULL;
    ((net_device_data *)dev->data)->rlim.rlim_cur = RLIM_INFINITY;
    ((net_device_data *)dev->data)->rlim.rlim_max = RLIM_INFINITY;
    strncpy(((net_device_data *)dev->data)->cfg.ifname_buf, enable_interfaces[i], IF_NAMESIZE);
    ((net_device_data *)dev->data)->cfg.ifname = (char *)&((net_device_data *)dev->data)->cfg.ifname_buf;
    ((net_device_data *)dev->data)->cfg.ifindex = if_nametoindex(((net_device_data *)dev->data)->cfg.ifname);

    dev->ops.transmit = net_device_transmit;
    dev->ops.poll = net_device_poll;

    printf("index %d\n", ((net_device_data *)dev->data)->cfg.ifindex);

    /* Required option */
    if (((net_device_data *)dev->data)->cfg.ifindex == -1)
    {
      fprintf(stderr, "ERROR: Missing interface\n\n");
      exit(EXIT_FAILURE);
    }

    strcpy(((net_device_data *)dev->data)->cfg.filename, "af_xdp_kern.o");
    strcpy(((net_device_data *)dev->data)->cfg.progsec, "xdp_sock");

    sprintf(dev->name, "xdp%d", i);
    memcpy(dev->mac_addr, iface_hwaddrs[i], 6);

    printf("Created dev %s port %s address %02x:%02x:%02x:%02x:%02x:%02x \n", dev->name, ((net_device_data *)dev->data)->cfg.ifname,
           dev->mac_addr[0], dev->mac_addr[1], dev->mac_addr[2], dev->mac_addr[3], dev->mac_addr[4], dev->mac_addr[5]);

    struct net_device *next;
    next = net_dev_list;
    net_dev_list = dev;
    dev->next = next;
  }

  ip_fib = (binary_trie_node *)calloc(
      1, sizeof(binary_trie_node));

  configure_ip_address(get_net_device_by_name("xdp0"),
                       IP_ADDRESS(10, 0, 0, 20), IP_ADDRESS(255, 255, 255, 0));
  configure_ip_address(get_net_device_by_name("xdp1"),
                       IP_ADDRESS(10, 0, 1, 20), IP_ADDRESS(255, 255, 255, 0));

  for (struct net_device *dev = net_dev_list; dev; dev = dev->next)
  {
    struct bpf_map *map;

    ((net_device_data *)dev->data)->bpf_obj = load_bpf_and_xdp_attach(&((net_device_data *)dev->data)->cfg);
    if (!((net_device_data *)dev->data)->bpf_obj)
    {
      /* Error handling done in load_bpf_and_xdp_attach() */
      exit(EXIT_FAILURE);
    }

    /* We also need to load the xsks_map */
    map = bpf_object__find_map_by_name(((net_device_data *)dev->data)->bpf_obj, "xsks_map");
    ((net_device_data *)dev->data)->xsks_map_fd= bpf_map__fd(map);
    if (((net_device_data *)dev->data)->xsks_map_fd< 0)
    {
      fprintf(stderr, "ERROR: no xsks map found: %s\n",
              strerror(((net_device_data *)dev->data)->xsks_map_fd));
      exit(EXIT_FAILURE);
    }
  }

  packet_buffer_size = NUM_FRAMES * FRAME_SIZE;

  for (struct net_device *dev = net_dev_list; dev; dev = dev->next){
    /* Allow unlimited locking of memory, so all memory needed for packet
     * buffers can be locked.
     */
    if (setrlimit(RLIMIT_MEMLOCK, &((net_device_data *)dev->data)->rlim))
    {
      fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }

    /* Allocate memory for NUM_FRAMES of the default XDP frame size */
    if (posix_memalign(&((net_device_data *)dev->data)->packet_buffer,
                       getpagesize(), /* PAGE_SIZE aligned */
                       packet_buffer_size))
    {
      fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }

    /* Initialize shared packet_buffer for umem usage */
    ((net_device_data *)dev->data)->umem = configure_xsk_umem(((net_device_data *)dev->data)->packet_buffer, packet_buffer_size);
    if (((net_device_data *)dev->data)->umem == NULL) {
      fprintf(stderr, "ERROR: Can't create umem \"%s\"\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    /* Open and configure the AF_XDP (xsk) socket */
    ((net_device_data *)dev->data)->xsk_socket = xsk_configure_socket(&((net_device_data *)dev->data)->cfg, ((net_device_data *)dev->data)->umem);
    if (((net_device_data *)dev->data)->xsk_socket == NULL)
    {
      fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  while(!global_exit) {

    struct pollfd fds[MAX_INTERFACES + 1];
    int ret, nfds = num_ifs;

    memset(fds, 0, sizeof(fds));
    for (struct net_device *dev = net_dev_list; dev; dev = dev->next)
    {
      fds[((net_device_data *)dev->data)->index].fd = xsk_socket__fd(((net_device_data *)dev->data)->xsk_socket->xsk);
      fds[((net_device_data *)dev->data)->index].events = POLLIN;
    }

    while (!global_exit) {
      if (true) {
        ret = poll(fds, nfds, -1);
        if (ret <= 0 || ret > 1){
          continue;
        }
      }
      for (struct net_device *dev = net_dev_list; dev; dev = dev->next)
      {
        if (fds[((net_device_data *)dev->data)->index].revents & POLLIN)
        {
          handle_receive_packets(((net_device_data *)dev->data)->xsk_socket, ((net_device_data *)dev->data)->cfg.ifname, dev);
        }
      }

    }

  }

  /* Cleanup */

  for (struct net_device *dev = net_dev_list; dev; dev = dev->next)
  {
    xsk_socket__delete(((net_device_data *)dev->data)->xsk_socket->xsk);
    xsk_umem__delete(((net_device_data *)dev->data)->umem->umem);
    xdp_link_detach(((net_device_data *)dev->data)->cfg.ifindex, ((net_device_data *)dev->data)->cfg.xdp_flags, 0);
  }

  return EXIT_OK;
}
