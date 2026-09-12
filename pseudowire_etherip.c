/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Ginzado Co., Ltd.
 * Copyright(c) 2026 Taisuke "paina" SATO
 *
 * pseudowire-etherip: a DPDK application that extends an L2 segment over EtherIP (RFC 3378).
 *
 * Derived from ginzado-pseudowire (app/ginzado-pseudowire/ginzado_pseudowire.c), replacing
 * its proprietary encapsulation with standard EtherIP (IP protocol number 97).
 *
 * - Frames received on the DL port are encapsulated in EtherIP and sent out the UL port.
 * - EtherIP packets received on the UL port are decapsulated and sent out the DL port.
 * - Encapsulated packets exceeding the UL MTU are split with standard IP fragmentation,
 *   and fragmented packets received on the UL port are reassembled, both using
 *   librte_ip_frag. The remote end therefore does not have to be this application: any
 *   implementation that speaks EtherIP (BSD gif/etherip, router products, ...) will do.
 */

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>

#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_pci.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip4.h>
#include <rte_ip6.h>
#include <rte_ip_frag.h>
#include <rte_atomic.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

/*
 * Packets taken from a port per rte_eth_rx_burst() call. Vector receive paths
 * (ixgbe, i40e, ...) return nothing at all for bursts smaller than 4, so this
 * must not be small; the packets are still handled one by one.
 */
#define PE_RX_BURST 32

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

/* Application option names (those after "--"). */
#define OPTION_REMOTE "remote"
#define OPTION_LOCAL "local"
#define OPTION_MTU "mtu"
#define OPTION_NEXTHOP_MAC "nexthop-mac"
#define OPTION_STATS_SOCKET "stats-socket"
#define OPTION_UL_PORT "ul-port"
#define OPTION_DL_PORT "dl-port"

/* EtherIP (RFC 3378) definitions. */
#define PE_PROTO_ETHERIP 97
#define PE_ETHERIP_VERSION 3
/* The EtherIP header is 16 bits: a 4-bit version (3) followed by 12 reserved bits (0). */
#define PE_ETHERIP_VER_RES (PE_ETHERIP_VERSION << 12)

#define PE_PROTO_ICMP6 58

/* Default and permitted range of the UL side MTU (up to the usual jumbo frame size). */
#define PE_DEFAULT_MTU 1500
#define PE_MIN_MTU_IP4 576
#define PE_MIN_MTU_IP6 1280
#define PE_MAX_MTU 9000
/* The DL port keeps the standard MTU, which bounds the size of the inner frames. */
#define PE_DL_MTU RTE_ETHER_MTU

/* Maximum number of fragments produced when encapsulating. */
#define PE_ENCAP_MAX_FRAGS RTE_LIBRTE_IP_FRAG_MAX_FRAG

/*
 * Reassembly table parameters.
 * A fragment whose siblings are lost stays in the table for TTL, so
 * (number of entries / TTL) determines the tolerance against fragment loss.
 * The table can hold up to PE_FRAG_TBL_MAX_ENTRIES * RTE_LIBRTE_IP_FRAG_MAX_FRAG
 * mbufs, so keep it small enough relative to the mbuf pool size.
 * The remote end is a single node and reordering on the path is rare, so a short TTL is fine.
 */
#define PE_FRAG_TBL_BUCKET_NUM 2048
#define PE_FRAG_TBL_BUCKET_ENTRIES 16
#define PE_FRAG_TBL_MAX_ENTRIES 2048
#define PE_FRAG_TTL_MS 250
#define PE_DEATH_ROW_PREFETCH 3

struct rte_mempool *mbuf_pool = NULL;
struct rte_mempool *mbuf_pool_indirect = NULL;

struct rte_ip_frag_tbl *frag_tbl = NULL;
struct rte_ip_frag_death_row death_row;

unsigned lcoreid_main = LCORE_ID_ANY;
unsigned lcoreid_ul = LCORE_ID_ANY;
unsigned lcoreid_dl = LCORE_ID_ANY;

/*
 * Ports used as the UL and DL sides, chosen with --ul-port / --dl-port
 * (see select_ports()). The *_arg strings are the values as given on the
 * command line, NULL when not given.
 */
const char *port_ul_arg = NULL;
const char *port_dl_arg = NULL;
uint16_t port_ul = RTE_MAX_ETHPORTS;
uint16_t port_dl = RTE_MAX_ETHPORTS;

struct rte_ether_addr ethaddr_ul;
struct rte_ether_addr ethaddr_dl;

#define PE_MODE_IP4 1
#define PE_MODE_IP6 2

int pe_mode = -1;

/*
 * Remote and local tunnel endpoint addresses (network byte order): the
 * destination and source addresses of the outer IP header of packets we send.
 */
uint8_t ip4_remote_addr[4];
uint8_t ip4_local_addr[4];
struct rte_ipv6_addr ip6_remote_addr;
struct rte_ipv6_addr ip6_local_addr;

/* UL side MTU (maximum size of the outer IP packet). */
uint16_t outer_mtu = PE_DEFAULT_MTU;

/*
 * MAC address of the next hop (the destination of the outer Ethernet header).
 * Used as is when given with --nexthop-mac, and resolved with ARP (IPv4) or
 * NDP/RA (IPv6) otherwise.
 */
struct rte_ether_addr nexthop_mac;
int nexthop_static = false;
volatile int nexthop_ready = false;

#define INTERNAL_RING_SIZE 256

struct rte_ring *ring_ul2main;
struct rte_ring *ring_dl2main;

/* EtherIP header. */
struct pe_etherip_hdr {
	uint16_t ver_res;
} __attribute__((__packed__));

/* Full set of headers prepended when encapsulating (IPv4 case). */
struct pe_ip4_hdr {
	struct rte_ether_hdr eth_hdr;
	struct rte_ipv4_hdr ip4_hdr;
	struct pe_etherip_hdr etherip_hdr;
} __attribute__((__packed__, __aligned__(2)));

struct pe_ip4_hdr ip4_hdr_cork;

/* Full set of headers prepended when encapsulating (IPv6 case). */
struct pe_ip6_hdr {
	struct rte_ether_hdr eth_hdr;
	struct rte_ipv6_hdr ip6_hdr;
	struct pe_etherip_hdr etherip_hdr;
} __attribute__((__packed__, __aligned__(2)));

struct pe_ip6_hdr ip6_hdr_cork;

#define PESTATS_UNIX_SOCKET_PATH "/run/pestats.socket"

#define PE_CLIENT_MAX 4
int serverfd = -1;
int clientfds[PE_CLIENT_MAX] = { -1, -1, -1, -1, };
struct sockaddr_un serversa;
char stats_path[sizeof(serversa.sun_path)] = PESTATS_UNIX_SOCKET_PATH;

struct pestats {
	uint64_t ul_rx_packets;
	uint64_t ul_rx_bytes;
	uint64_t ul_rx_bpdus;
	uint64_t ul_tx_packets;
	uint64_t ul_tx_bytes;
	uint64_t ul_tx_errors;
	uint64_t dl_rx_packets;
	uint64_t dl_rx_bytes;
	uint64_t dl_rx_bpdus;
	uint64_t dl_tx_packets;
	uint64_t dl_tx_bytes;
	uint64_t dl_tx_errors;
	uint64_t encap_frags;		/* times a frame was fragmented while encapsulating */
	uint64_t decap_reasms;		/* times reassembly completed while decapsulating */
	uint64_t decap_reasm_drops;	/* fragments dropped without being reassembled */
	uint64_t encap_noready_drops;	/* frames dropped with the next hop unresolved */
} pestats;

/* ICMPv6 definitions (only what is needed, as in ginzado-pseudowire). */

struct icmp6_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t cksum;
} __attribute__((__packed__));

#define ICMP6_RS 133
#define ICMP6_RA 134
#define ICMP6_NS 135
#define ICMP6_NA 136

#define OPT_SOURCE_LINKADDR 1
#define OPT_TARGET_LINKADDR 2
#define OPT_PREFIX_INFORMATION 3

struct icmp6_opt_hdr {
	uint8_t opt_type;
	uint8_t opt_len;
} __attribute__((__packed__));

struct icmp6_rs {
	struct icmp6_hdr icmp6_hdr;
	uint32_t reserved;
} __attribute__((__packed__));

struct icmp6_ns {
	struct icmp6_hdr icmp6_hdr;
	uint32_t reserved;
	struct rte_ipv6_addr target;
} __attribute__((__packed__));

struct icmp6_na {
	struct icmp6_hdr icmp6_hdr;
	uint32_t flags_reserved;
	struct rte_ipv6_addr target;
} __attribute__((__packed__));

#define NA_FLAG_SOLICITED 0x40000000
#define NA_FLAG_OVERRIDE 0x20000000

struct icmp6_ra {
	struct icmp6_hdr icmp6_hdr;
	uint8_t curhoplimit;
	uint8_t flags;
	uint16_t reserved;
	uint32_t reachable;
	uint32_t retransmit;
} __attribute__((__packed__));

struct icmp6_opt_source_linkaddr {
	struct icmp6_opt_hdr icmp6_opt_hdr;
	uint8_t source_linkaddr[6];
} __attribute__((__packed__));

struct icmp6_opt_target_linkaddr {
	struct icmp6_opt_hdr icmp6_opt_hdr;
	uint8_t target_linkaddr[6];
} __attribute__((__packed__));

struct icmp6_opt_prefix_info {
	struct icmp6_opt_hdr icmp6_opt_hdr;
	uint8_t prefix_len;
	uint8_t flags_reserved;
	uint32_t valid_time;
	uint32_t preferred_time;
	uint32_t reserved2;
	struct rte_ipv6_addr prefix;
} __attribute__((__packed__));

/*
 * Update the next hop MAC address and mark the tunnel ready to transmit.
 * Called from lcore_main only. The cork headers are rewritten first and
 * nexthop_ready is raised afterwards, with a wmb in between to keep that order.
 */
static void
update_nexthop(const uint8_t *macaddr)
{
	memcpy(nexthop_mac.addr_bytes, macaddr, 6);
	memcpy(&ip4_hdr_cork.eth_hdr.dst_addr, &nexthop_mac, sizeof(struct rte_ether_addr));
	memcpy(&ip6_hdr_cork.eth_hdr.dst_addr, &nexthop_mac, sizeof(struct rte_ether_addr));
	rte_wmb();
	if (!nexthop_ready) {
		nexthop_ready = true;
		printf("#### nexthop ready (%02x:%02x:%02x:%02x:%02x:%02x) ####\n",
				macaddr[0], macaddr[1], macaddr[2],
				macaddr[3], macaddr[4], macaddr[5]);
	}
}

/*
 * ARP handling (PE_MODE_IP4).
 * Packets that lcore_ul did not classify as tunnel packets arrive here through
 * the ring, so pick out the ARP ones and handle them.
 */

static int
is_arp(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr;
	if (buf->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr))
		return false;
	eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
		return false;
	return true;
}

static void
handle_arp(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);

	if (arp_hdr->arp_hardware != rte_cpu_to_be_16(RTE_ARP_HRD_ETHER))
		return;
	if (arp_hdr->arp_protocol != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		return;
	if (arp_hdr->arp_hlen != 6 || arp_hdr->arp_plen != 4)
		return;

	/* Learn the source MAC address from ARP sent by the remote end (or by the next hop). */
	if (!nexthop_static &&
			memcmp(&arp_hdr->arp_data.arp_sip, ip4_remote_addr, 4) == 0)
		update_nexthop(arp_hdr->arp_data.arp_sha.addr_bytes);

	/* Reply to ARP requests for our own address. */
	if (arp_hdr->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST))
		return;
	if (memcmp(&arp_hdr->arp_data.arp_tip, ip4_local_addr, 4) != 0)
		return;

	struct rte_mbuf *rep_buf = rte_pktmbuf_alloc(mbuf_pool);
	if (unlikely(rep_buf == NULL))
		return;
	struct rte_ether_hdr *rep_eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_append(rep_buf,
			sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr));
	if (unlikely(rep_eth_hdr == NULL)) {
		rte_pktmbuf_free(rep_buf);
		return;
	}
	struct rte_arp_hdr *rep_arp_hdr = (struct rte_arp_hdr *)(rep_eth_hdr + 1);
	memcpy(&rep_eth_hdr->dst_addr, &arp_hdr->arp_data.arp_sha, sizeof(struct rte_ether_addr));
	memcpy(&rep_eth_hdr->src_addr, &ethaddr_ul, sizeof(struct rte_ether_addr));
	rep_eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
	rep_arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
	rep_arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	rep_arp_hdr->arp_hlen = 6;
	rep_arp_hdr->arp_plen = 4;
	rep_arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
	memcpy(&rep_arp_hdr->arp_data.arp_sha, &ethaddr_ul, sizeof(struct rte_ether_addr));
	memcpy(&rep_arp_hdr->arp_data.arp_sip, ip4_local_addr, 4);
	memcpy(&rep_arp_hdr->arp_data.arp_tha, &arp_hdr->arp_data.arp_sha, sizeof(struct rte_ether_addr));
	memcpy(&rep_arp_hdr->arp_data.arp_tip, &arp_hdr->arp_data.arp_sip, 4);
	const uint16_t nb_tx = rte_eth_tx_burst(port_ul, 1, &rep_buf, 1);
	if (unlikely(nb_tx == 0))
		rte_pktmbuf_free(rep_buf);
}

/* Send an ARP request to resolve the remote address. */
static void
send_arp_request(void)
{
	struct rte_mbuf *req_buf = rte_pktmbuf_alloc(mbuf_pool);
	if (unlikely(req_buf == NULL))
		return;
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_append(req_buf,
			sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr));
	if (unlikely(eth_hdr == NULL)) {
		rte_pktmbuf_free(req_buf);
		return;
	}
	struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
	memset(&eth_hdr->dst_addr, 0xff, sizeof(struct rte_ether_addr));
	memcpy(&eth_hdr->src_addr, &ethaddr_ul, sizeof(struct rte_ether_addr));
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
	arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
	arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	arp_hdr->arp_hlen = 6;
	arp_hdr->arp_plen = 4;
	arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
	memcpy(&arp_hdr->arp_data.arp_sha, &ethaddr_ul, sizeof(struct rte_ether_addr));
	memcpy(&arp_hdr->arp_data.arp_sip, ip4_local_addr, 4);
	memset(&arp_hdr->arp_data.arp_tha, 0, sizeof(struct rte_ether_addr));
	memcpy(&arp_hdr->arp_data.arp_tip, ip4_remote_addr, 4);
	const uint16_t nb_tx = rte_eth_tx_burst(port_ul, 1, &req_buf, 1);
	if (unlikely(nb_tx == 0))
		rte_pktmbuf_free(req_buf);
}

/* ICMPv6 (NDP) handling (PE_MODE_IP6). */

static int
is_icmp6(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv6_hdr *ip6_hdr;
	if (buf->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)
			+ sizeof(struct icmp6_hdr))
		return false;
	eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
		return false;
	ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	if (ip6_hdr->proto != PE_PROTO_ICMP6)
		return false;
	return true;
}

/*
 * Handle a received RA.
 * As in ginzado-pseudowire, learn the MAC address of the router advertising the same
 * prefix as our own address as the next hop (for topologies like NGN, where the remote
 * end is off-link and reached through a router).
 */
static void
handle_icmp6_ra(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	struct rte_ipv6_hdr *ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	struct icmp6_ra *icmp6_ra = (struct icmp6_ra *)(ip6_hdr + 1);
	struct icmp6_opt_hdr *opt_hdr = (struct icmp6_opt_hdr *)(icmp6_ra + 1);
	long remaining = buf->data_len
		- sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv6_hdr) - sizeof(struct icmp6_ra);
	struct icmp6_opt_source_linkaddr *source_linkaddr = NULL;
	struct icmp6_opt_prefix_info *prefix_info = NULL;
	if (remaining < 0)
		return;
	while (remaining >= (long)sizeof(struct icmp6_opt_hdr)) {
		if (opt_hdr->opt_len == 0)
			return;
		switch (opt_hdr->opt_type) {
		case OPT_SOURCE_LINKADDR:
			source_linkaddr = (struct icmp6_opt_source_linkaddr *)opt_hdr;
			break;
		case OPT_PREFIX_INFORMATION:
			prefix_info = (struct icmp6_opt_prefix_info *)opt_hdr;
			break;
		}
		remaining -= opt_hdr->opt_len * 8;
		opt_hdr = (struct icmp6_opt_hdr *)((char *)opt_hdr + (opt_hdr->opt_len * 8));
	}
	if (source_linkaddr == NULL || prefix_info == NULL)
		return;
	if (memcmp(&ip6_local_addr, &prefix_info->prefix, 8) != 0)
		return;
	if (nexthop_static)
		return;
	if (nexthop_ready &&
			memcmp(nexthop_mac.addr_bytes, source_linkaddr->source_linkaddr, 6) == 0)
		return;
	update_nexthop(source_linkaddr->source_linkaddr);
}

/* Handle a received NS. Reply with an NA to an NS for our own address. */
static void
handle_icmp6_ns(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	struct rte_ipv6_hdr *ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	struct icmp6_ns *icmp6_ns = (struct icmp6_ns *)(ip6_hdr + 1);
	struct icmp6_opt_hdr *opt_hdr = (struct icmp6_opt_hdr *)(icmp6_ns + 1);
	long remaining = buf->data_len
		- sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv6_hdr) - sizeof(struct icmp6_ns);
	struct icmp6_opt_source_linkaddr *source_linkaddr = NULL;
	if (remaining < 0)
		return;
	while (remaining >= (long)sizeof(struct icmp6_opt_hdr)) {
		if (opt_hdr->opt_len == 0)
			return;
		switch (opt_hdr->opt_type) {
		case OPT_SOURCE_LINKADDR:
			source_linkaddr = (struct icmp6_opt_source_linkaddr *)opt_hdr;
			break;
		}
		remaining -= opt_hdr->opt_len * 8;
		opt_hdr = (struct icmp6_opt_hdr *)((char *)opt_hdr + (opt_hdr->opt_len * 8));
	}

	if (source_linkaddr == NULL)
		return;
	if (!rte_ipv6_addr_eq(&icmp6_ns->target, &ip6_local_addr))
		return;

	struct rte_mbuf *na_buf = rte_pktmbuf_alloc(mbuf_pool);
	if (unlikely(na_buf == NULL))
		return;
	struct rte_ether_hdr *na_eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_append(na_buf,
			sizeof(struct rte_ether_hdr));
	if (unlikely(na_eth_hdr == NULL)) {
		rte_pktmbuf_free(na_buf);
		return;
	}
	memcpy(na_eth_hdr->dst_addr.addr_bytes, source_linkaddr->source_linkaddr, 6);
	memcpy(&na_eth_hdr->src_addr, &ethaddr_ul, sizeof(struct rte_ether_addr));
	na_eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	struct rte_ipv6_hdr *na_ip6_hdr = (struct rte_ipv6_hdr *)rte_pktmbuf_append(na_buf,
			sizeof(struct rte_ipv6_hdr));
	if (unlikely(na_ip6_hdr == NULL)) {
		rte_pktmbuf_free(na_buf);
		return;
	}
	na_ip6_hdr->vtc_flow = rte_cpu_to_be_32(0x60000000);
	na_ip6_hdr->payload_len = rte_cpu_to_be_16(sizeof(struct icmp6_na) + sizeof(struct icmp6_opt_target_linkaddr));
	na_ip6_hdr->proto = PE_PROTO_ICMP6;
	na_ip6_hdr->hop_limits = 255;
	na_ip6_hdr->src_addr = ip6_local_addr;
	na_ip6_hdr->dst_addr = ip6_hdr->src_addr;
	struct icmp6_na *icmp6_na = (struct icmp6_na *)rte_pktmbuf_append(na_buf, sizeof(struct icmp6_na));
	if (unlikely(icmp6_na == NULL)) {
		rte_pktmbuf_free(na_buf);
		return;
	}
	icmp6_na->icmp6_hdr.type = ICMP6_NA;
	icmp6_na->icmp6_hdr.code = 0;
	icmp6_na->icmp6_hdr.cksum = 0;
	icmp6_na->flags_reserved = rte_cpu_to_be_32(NA_FLAG_SOLICITED|NA_FLAG_OVERRIDE);
	icmp6_na->target = ip6_local_addr;
	struct icmp6_opt_target_linkaddr *na_target_linkaddr = (struct icmp6_opt_target_linkaddr *)
		rte_pktmbuf_append(na_buf, sizeof(struct icmp6_opt_target_linkaddr));
	if (unlikely(na_target_linkaddr == NULL)) {
		rte_pktmbuf_free(na_buf);
		return;
	}
	na_target_linkaddr->icmp6_opt_hdr.opt_type = OPT_TARGET_LINKADDR;
	na_target_linkaddr->icmp6_opt_hdr.opt_len = 1;
	memcpy(na_target_linkaddr->target_linkaddr, ethaddr_ul.addr_bytes, 6);
	icmp6_na->icmp6_hdr.cksum = rte_ipv6_udptcp_cksum(na_ip6_hdr, icmp6_na);
	const uint16_t nb_tx = rte_eth_tx_burst(port_ul, 1, &na_buf, 1);
	if (unlikely(nb_tx == 0))
		rte_pktmbuf_free(na_buf);
}

/*
 * Handle a received NA.
 * Learn the next hop MAC address from the reply to an NS for the remote address
 * (when the remote end is on-link).
 */
static void
handle_icmp6_na(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	struct rte_ipv6_hdr *ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	struct icmp6_na *icmp6_na = (struct icmp6_na *)(ip6_hdr + 1);
	struct icmp6_opt_hdr *opt_hdr = (struct icmp6_opt_hdr *)(icmp6_na + 1);
	long remaining = buf->data_len
		- sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv6_hdr) - sizeof(struct icmp6_na);
	struct icmp6_opt_target_linkaddr *target_linkaddr = NULL;
	if (remaining < 0)
		return;
	while (remaining >= (long)sizeof(struct icmp6_opt_hdr)) {
		if (opt_hdr->opt_len == 0)
			return;
		switch (opt_hdr->opt_type) {
		case OPT_TARGET_LINKADDR:
			target_linkaddr = (struct icmp6_opt_target_linkaddr *)opt_hdr;
			break;
		}
		remaining -= opt_hdr->opt_len * 8;
		opt_hdr = (struct icmp6_opt_hdr *)((char *)opt_hdr + (opt_hdr->opt_len * 8));
	}

	if (nexthop_static)
		return;
	if (!rte_ipv6_addr_eq(&icmp6_na->target, &ip6_remote_addr))
		return;
	if (target_linkaddr != NULL)
		update_nexthop(target_linkaddr->target_linkaddr);
	else
		update_nexthop(eth_hdr->src_addr.addr_bytes);
}

static void
handle_icmp6(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	struct rte_ipv6_hdr *ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(ip6_hdr + 1);
	switch (icmp6_hdr->type) {
	case ICMP6_RA:
		if (buf->data_len >= sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)
				+ sizeof(struct icmp6_ra))
			handle_icmp6_ra(buf);
		break;
	case ICMP6_NS:
		if (buf->data_len >= sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)
				+ sizeof(struct icmp6_ns))
			handle_icmp6_ns(buf);
		break;
	case ICMP6_NA:
		if (buf->data_len >= sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)
				+ sizeof(struct icmp6_na))
			handle_icmp6_na(buf);
		break;
	}
}

/* Send an NS to resolve the remote address (to its solicited-node multicast address). */
static void
send_ndp_ns(void)
{
	struct rte_mbuf *ns_buf = rte_pktmbuf_alloc(mbuf_pool);
	if (unlikely(ns_buf == NULL))
		return;
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_append(ns_buf,
			sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)
			+ sizeof(struct icmp6_ns) + sizeof(struct icmp6_opt_source_linkaddr));
	if (unlikely(eth_hdr == NULL)) {
		rte_pktmbuf_free(ns_buf);
		return;
	}
	struct rte_ipv6_hdr *ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	struct icmp6_ns *icmp6_ns = (struct icmp6_ns *)(ip6_hdr + 1);
	struct icmp6_opt_source_linkaddr *opt = (struct icmp6_opt_source_linkaddr *)(icmp6_ns + 1);
	/* The destination MAC for a solicited-node multicast is 33:33:ff:xx:xx:xx. */
	eth_hdr->dst_addr.addr_bytes[0] = 0x33;
	eth_hdr->dst_addr.addr_bytes[1] = 0x33;
	eth_hdr->dst_addr.addr_bytes[2] = 0xff;
	eth_hdr->dst_addr.addr_bytes[3] = ip6_remote_addr.a[13];
	eth_hdr->dst_addr.addr_bytes[4] = ip6_remote_addr.a[14];
	eth_hdr->dst_addr.addr_bytes[5] = ip6_remote_addr.a[15];
	memcpy(&eth_hdr->src_addr, &ethaddr_ul, sizeof(struct rte_ether_addr));
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	ip6_hdr->vtc_flow = rte_cpu_to_be_32(0x60000000);
	ip6_hdr->payload_len = rte_cpu_to_be_16(sizeof(struct icmp6_ns)
			+ sizeof(struct icmp6_opt_source_linkaddr));
	ip6_hdr->proto = PE_PROTO_ICMP6;
	ip6_hdr->hop_limits = 255;
	ip6_hdr->src_addr = ip6_local_addr;
	/* Solicited-node multicast address ff02::1:ffXX:XXXX. */
	rte_ipv6_solnode_from_addr(&ip6_hdr->dst_addr, &ip6_remote_addr);
	icmp6_ns->icmp6_hdr.type = ICMP6_NS;
	icmp6_ns->icmp6_hdr.code = 0;
	icmp6_ns->icmp6_hdr.cksum = 0;
	icmp6_ns->reserved = 0;
	icmp6_ns->target = ip6_remote_addr;
	opt->icmp6_opt_hdr.opt_type = OPT_SOURCE_LINKADDR;
	opt->icmp6_opt_hdr.opt_len = 1;
	memcpy(opt->source_linkaddr, ethaddr_ul.addr_bytes, 6);
	icmp6_ns->icmp6_hdr.cksum = rte_ipv6_udptcp_cksum(ip6_hdr, icmp6_ns);
	const uint16_t nb_tx = rte_eth_tx_burst(port_ul, 1, &ns_buf, 1);
	if (unlikely(nb_tx == 0))
		rte_pktmbuf_free(ns_buf);
}

/* Send an RS to solicit an RA (to the all-routers multicast address). */
static void
send_ndp_rs(void)
{
	static const struct rte_ipv6_addr allrouters = RTE_IPV6_ADDR_ALLROUTERS_LINK_LOCAL;
	struct rte_mbuf *rs_buf = rte_pktmbuf_alloc(mbuf_pool);
	if (unlikely(rs_buf == NULL))
		return;
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_append(rs_buf,
			sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)
			+ sizeof(struct icmp6_rs) + sizeof(struct icmp6_opt_source_linkaddr));
	if (unlikely(eth_hdr == NULL)) {
		rte_pktmbuf_free(rs_buf);
		return;
	}
	struct rte_ipv6_hdr *ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	struct icmp6_rs *icmp6_rs = (struct icmp6_rs *)(ip6_hdr + 1);
	struct icmp6_opt_source_linkaddr *opt = (struct icmp6_opt_source_linkaddr *)(icmp6_rs + 1);
	/* The destination MAC for the all-routers multicast ff02::2 is 33:33:00:00:00:02. */
	eth_hdr->dst_addr.addr_bytes[0] = 0x33;
	eth_hdr->dst_addr.addr_bytes[1] = 0x33;
	eth_hdr->dst_addr.addr_bytes[2] = 0x00;
	eth_hdr->dst_addr.addr_bytes[3] = 0x00;
	eth_hdr->dst_addr.addr_bytes[4] = 0x00;
	eth_hdr->dst_addr.addr_bytes[5] = 0x02;
	memcpy(&eth_hdr->src_addr, &ethaddr_ul, sizeof(struct rte_ether_addr));
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	ip6_hdr->vtc_flow = rte_cpu_to_be_32(0x60000000);
	ip6_hdr->payload_len = rte_cpu_to_be_16(sizeof(struct icmp6_rs)
			+ sizeof(struct icmp6_opt_source_linkaddr));
	ip6_hdr->proto = PE_PROTO_ICMP6;
	ip6_hdr->hop_limits = 255;
	ip6_hdr->src_addr = ip6_local_addr;
	ip6_hdr->dst_addr = allrouters;
	icmp6_rs->icmp6_hdr.type = ICMP6_RS;
	icmp6_rs->icmp6_hdr.code = 0;
	icmp6_rs->icmp6_hdr.cksum = 0;
	icmp6_rs->reserved = 0;
	opt->icmp6_opt_hdr.opt_type = OPT_SOURCE_LINKADDR;
	opt->icmp6_opt_hdr.opt_len = 1;
	memcpy(opt->source_linkaddr, ethaddr_ul.addr_bytes, 6);
	icmp6_rs->icmp6_hdr.cksum = rte_ipv6_udptcp_cksum(ip6_hdr, icmp6_rs);
	const uint16_t nb_tx = rte_eth_tx_burst(port_ul, 1, &rs_buf, 1);
	if (unlikely(nb_tx == 0))
		rte_pktmbuf_free(rs_buf);
}

/*
 * Configure and start a port with the given MTU: one RX queue, two TX queues
 * (queue 1 is used by lcore_main for ARP/NDP), promiscuous mode.
 */
static inline int
port_init(uint16_t port, uint16_t mtu)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 2;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n", port, strerror(-retval));
		return retval;
	}

	/* The port must accept packets of the given MTU. */
	if (mtu > dev_info.max_mtu) {
		printf("Error: port %u supports an MTU of at most %u, %u requested\n",
				port, dev_info.max_mtu, mtu);
		return -1;
	}
	port_conf.rxmode.mtu = mtu;
	/*
	 * Packets larger than an mbuf have to be received scattered over several
	 * mbufs, which the data path handles (reassembled packets are like that
	 * anyway). Request it when the PMD advertises the offload; PMDs that do not
	 * either scatter on their own (net_pcap) or reject the MTU when configured.
	 * The overhead allows for two VLAN tags, as the most demanding PMDs do.
	 */
	if (mtu + RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + 2 * RTE_VLAN_HLEN
			> rte_pktmbuf_data_room_size(mbuf_pool) - RTE_PKTMBUF_HEADROOM
			&& (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER))
		port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_SCATTER;

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
	/* Reassembled packets are multi-segment, so enable this offload when supported. */
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
		port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0) {
		printf("Error during configuring device (port %u, MTU %u): %s\n",
				port, mtu, strerror(-retval));
		return retval;
	}

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	if (port == port_dl) {
		retval = rte_eth_macaddr_get(port_dl, &ethaddr_dl);
		if (retval != 0)
			return retval;
	}
	if (port == port_ul) {
		retval = rte_eth_macaddr_get(port_ul, &ethaddr_ul);
		if (retval != 0)
			return retval;
	}

	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

/*
 * Strip len bytes from the head of a packet. Similar to rte_pktmbuf_adj(), but it also
 * handles the case where the first segment is shorter than len, as happens with
 * reassembled packets (segments that become empty are freed).
 * Returns the new head mbuf, or NULL without touching m when len >= pkt_len.
 */
static struct rte_mbuf *
pe_pktmbuf_strip(struct rte_mbuf *m, uint32_t len)
{
	if (unlikely(m->pkt_len <= len))
		return NULL;
	while (len > 0) {
		if (likely(m->data_len > len)) {
			m->data_off += len;
			m->data_len -= len;
			m->pkt_len -= len;
			break;
		}
		/* Remove the whole first segment. */
		struct rte_mbuf *next = m->next;
		uint32_t removed = m->data_len;
		uint32_t pkt_len = m->pkt_len;
		uint16_t nb_segs = m->nb_segs;
		m->next = NULL;
		rte_pktmbuf_free_seg(m);
		m = next;
		m->nb_segs = nb_segs - 1;
		m->pkt_len = pkt_len - removed;
		len -= removed;
	}
	return m;
}

/*
 * Loop that decapsulates packets received on the UL port and sends them out the DL port.
 *
 * Packets that are not tunnel packets (ARP, NDP and so on) are passed to lcore_main
 * through a ring for handling. Fragmented packets are reassembled with librte_ip_frag
 * before being decapsulated.
 */
static __rte_noreturn int
lcore_ul(__rte_unused void *arg)
{
	for (;;) {
		struct rte_mbuf *bufs[PE_RX_BURST];
		uint16_t i;

		/* Take a burst of packets from the UL port and handle them one by one. */
		const uint16_t nb_rx = rte_eth_rx_burst(port_ul, 0, bufs, PE_RX_BURST);
		for (i = 0; i < nb_rx; i++) {
			struct rte_mbuf *m = bufs[i];
			size_t sizeof_hdr;
			struct rte_ether_hdr *eth_hdr;

			pestats.ul_rx_packets += 1;
			pestats.ul_rx_bytes += m->pkt_len;

			if (unlikely(m->data_len < sizeof(struct rte_ether_hdr)))
				goto to_main;
			eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

			if (likely(pe_mode == PE_MODE_IP4)) {
				/* EtherIP over IPv4 mode: */
				struct rte_ipv4_hdr *ip4_hdr;
				sizeof_hdr = sizeof(struct pe_ip4_hdr);
				if (unlikely(eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)))
					goto to_main;
				if (unlikely(m->data_len < sizeof(struct rte_ether_hdr)
						+ sizeof(struct rte_ipv4_hdr)))
					goto to_main;
				ip4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
				/* Packets carrying IP options are not treated as tunnel packets. */
				if (unlikely(ip4_hdr->version_ihl != 0x45))
					goto to_main;
				/* Not the tunnel source/destination IPv4 addresses: pass to lcore_main. */
				if (unlikely(memcmp(&ip4_hdr->src_addr, ip4_remote_addr, 4) != 0))
					goto to_main;
				if (unlikely(memcmp(&ip4_hdr->dst_addr, ip4_local_addr, 4) != 0))
					goto to_main;
				/* Not the EtherIP protocol number: pass to lcore_main. */
				if (unlikely(ip4_hdr->next_proto_id != PE_PROTO_ETHERIP))
					goto to_main;
				if (unlikely(rte_ipv4_frag_pkt_is_fragmented(ip4_hdr))) {
					/* Reassemble the packet if it is fragmented. */
					struct rte_mbuf *mo;
					m->l2_len = sizeof(struct rte_ether_hdr);
					m->l3_len = sizeof(struct rte_ipv4_hdr);
					mo = rte_ipv4_frag_reassemble_packet(frag_tbl, &death_row,
							m, rte_rdtsc(), ip4_hdr);
					if (unlikely(death_row.cnt > 0)) {
						pestats.decap_reasm_drops += death_row.cnt;
						rte_ip_frag_free_death_row(&death_row, PE_DEATH_ROW_PREFETCH);
					}
					/* Move on to the next packet while fragments are still missing. */
					/* (The received packet is held in the reassembly table.) */
					if (mo == NULL)
						continue;
					/* Once reassembly completes, continue with the result as the received packet. */
					m = mo;
					pestats.decap_reasms += 1;
				}
			} else {
				/* EtherIP over IPv6 mode: */
				struct rte_ipv6_hdr *ip6_hdr;
				sizeof_hdr = sizeof(struct pe_ip6_hdr);
				if (unlikely(eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)))
					goto to_main;
				if (unlikely(m->data_len < sizeof(struct rte_ether_hdr)
						+ sizeof(struct rte_ipv6_hdr)))
					goto to_main;
				ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
				/* Not the tunnel source/destination IPv6 addresses: pass to lcore_main. */
				if (unlikely(!rte_ipv6_addr_eq(&ip6_hdr->src_addr, &ip6_remote_addr)))
					goto to_main;
				if (unlikely(!rte_ipv6_addr_eq(&ip6_hdr->dst_addr, &ip6_local_addr)))
					goto to_main;
				if (unlikely(ip6_hdr->proto == IPPROTO_FRAGMENT)) {
					/* Reassemble the packet if it is fragmented. */
					/* Only a fragment header placed directly after the IPv6 header is supported. */
					struct rte_mbuf *mo;
					struct rte_ipv6_fragment_ext *frag_hdr;
					if (unlikely(m->data_len < sizeof(struct rte_ether_hdr)
							+ sizeof(struct rte_ipv6_hdr)
							+ sizeof(struct rte_ipv6_fragment_ext)))
						goto to_main;
					frag_hdr = (struct rte_ipv6_fragment_ext *)(ip6_hdr + 1);
					if (unlikely(frag_hdr->next_header != PE_PROTO_ETHERIP))
						goto to_main;
					m->l2_len = sizeof(struct rte_ether_hdr);
					m->l3_len = sizeof(struct rte_ipv6_hdr)
						+ sizeof(struct rte_ipv6_fragment_ext);
					mo = rte_ipv6_frag_reassemble_packet(frag_tbl, &death_row,
							m, rte_rdtsc(), ip6_hdr, frag_hdr);
					if (unlikely(death_row.cnt > 0)) {
						pestats.decap_reasm_drops += death_row.cnt;
						rte_ip_frag_free_death_row(&death_row, PE_DEATH_ROW_PREFETCH);
					}
					/* Move on to the next packet while fragments are still missing. */
					/* (The received packet is held in the reassembly table.) */
					if (mo == NULL)
						continue;
					/* Once reassembly completes, continue with the result as the received packet. */
					m = mo;
					pestats.decap_reasms += 1;
					eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
					ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
					/* Check the protocol number after reassembly, just to be safe. */
					if (unlikely(ip6_hdr->proto != PE_PROTO_ETHERIP))
						goto to_main;
				} else if (unlikely(ip6_hdr->proto != PE_PROTO_ETHERIP)) {
					/* Not the EtherIP protocol number: pass to lcore_main. */
					goto to_main;
				}
			}

			/* Check the EtherIP version and drop the packet if it differs. */
			/* Right after reassembly the header can straddle a segment boundary, so read it */
			/* with rte_pktmbuf_read(), which also checks the packet length. */
			struct pe_etherip_hdr etherip_hdr_buf;
			const struct pe_etherip_hdr *etherip_hdr = rte_pktmbuf_read(m,
					sizeof_hdr - sizeof(struct pe_etherip_hdr),
					sizeof(struct pe_etherip_hdr), &etherip_hdr_buf);
			if (unlikely(etherip_hdr == NULL))
				goto to_main;
			if (unlikely((rte_be_to_cpu_16(etherip_hdr->ver_res) & 0xf000)
					!= PE_ETHERIP_VER_RES))
				goto to_main;

			/* Strip the outer headers (Ethernet + IP + EtherIP); drop the packet on failure. */
			struct rte_mbuf *stripped = pe_pktmbuf_strip(m, sizeof_hdr);
			if (unlikely(stripped == NULL))
				goto to_main;
			m = stripped;
			/* Update the UL port BPDU receive counter. */
			uint8_t bpdu_buf[2];
			const uint8_t *bpdu = rte_pktmbuf_read(m, 14, 2, bpdu_buf);
			if (bpdu != NULL && unlikely(bpdu[0] == 0x42 && bpdu[1] == 0x42))
				pestats.ul_rx_bpdus += 1;
			const uint64_t txbytes = m->pkt_len;
			/* Send one packet out the DL port. */
			const uint16_t nb_tx = rte_eth_tx_burst(port_dl, 0, &m, 1);
			/* If nothing could be sent, drop the packet. */
			if (unlikely(nb_tx == 0)) {
				pestats.dl_tx_errors += 1;
				goto to_main;
			}
			pestats.dl_tx_packets += 1;
			pestats.dl_tx_bytes += txbytes;
			continue;
to_main:
			if (unlikely(rte_ring_enqueue(ring_ul2main, m) != 0))
				rte_pktmbuf_free(m);
		}
	}
}

/*
 * Loop that encapsulates frames received on the DL port in EtherIP and sends them out
 * the UL port.
 *
 * When the outer IP packet exceeds the UL side MTU it is split with standard IP
 * fragmentation by librte_ip_frag before being sent.
 */
static __rte_noreturn int
lcore_dl(__rte_unused void *arg)
{
	uint16_t ip4_id = 0;
	uint32_t ip6_frag_id = 0;
	for (;;) {
		struct rte_mbuf *bufs[PE_RX_BURST];
		uint16_t n;

		/* Take a burst of packets from the DL port and handle them one by one. */
		const uint16_t nb_rx = rte_eth_rx_burst(port_dl, 0, bufs, PE_RX_BURST);
		for (n = 0; n < nb_rx; n++) {
			struct rte_mbuf *m = bufs[n];
			int ret;
			int i;
			struct rte_mbuf *frags[PE_ENCAP_MAX_FRAGS];
			int32_t nb_frags;

			pestats.dl_rx_packets += 1;
			pestats.dl_rx_bytes += m->pkt_len;

			/* Drop the received packet while the next hop MAC address is unresolved. */
			if (unlikely(!nexthop_ready)) {
				pestats.encap_noready_drops += 1;
				goto free;
			}

			/* Update the DL port BPDU receive counter. */
			if (m->data_len >= 16) {
				uint8_t *headp = rte_pktmbuf_mtod(m, uint8_t *);
				if (unlikely(headp[14] == 0x42 && headp[15] == 0x42))
					pestats.dl_rx_bpdus += 1;
			}

			if (likely(pe_mode == PE_MODE_IP4)) {
				/* EtherIP over IPv4 mode: */
				if (likely(sizeof(struct rte_ipv4_hdr) + sizeof(struct pe_etherip_hdr)
						+ m->pkt_len <= outer_mtu)) {
					/* No fragmentation needed: */
					/* Reserve room for the headers at the head of m; drop the packet on failure. */
					struct pe_ip4_hdr *hdr = (struct pe_ip4_hdr *)rte_pktmbuf_prepend(
							m, sizeof(struct pe_ip4_hdr));
					if (unlikely(hdr == NULL))
						goto free;
					/* Write the headers. */
					memcpy(hdr, &ip4_hdr_cork, sizeof(struct pe_ip4_hdr));
					hdr->ip4_hdr.total_length = rte_cpu_to_be_16(m->pkt_len
							- sizeof(struct rte_ether_hdr));
					hdr->ip4_hdr.packet_id = rte_cpu_to_be_16(++ip4_id);
					hdr->ip4_hdr.hdr_checksum = rte_ipv4_cksum(&hdr->ip4_hdr);
				} else {
					/* Fragmentation needed: */
					/* First prepend the headers without the outer Ethernet header */
					/* (IPv4 + EtherIP) to m to form a complete IPv4 packet. */
					struct rte_ipv4_hdr *ip4_hdr = (struct rte_ipv4_hdr *)
						rte_pktmbuf_prepend(m, sizeof(struct rte_ipv4_hdr)
								+ sizeof(struct pe_etherip_hdr));
					if (unlikely(ip4_hdr == NULL))
						goto free;
					memcpy(ip4_hdr, &ip4_hdr_cork.ip4_hdr, sizeof(struct rte_ipv4_hdr)
							+ sizeof(struct pe_etherip_hdr));
					ip4_hdr->total_length = rte_cpu_to_be_16(m->pkt_len);
					ip4_hdr->packet_id = rte_cpu_to_be_16(++ip4_id);
					/* Do standard IPv4 fragmentation with librte_ip_frag. */
					nb_frags = rte_ipv4_fragment_packet(m, frags,
							PE_ENCAP_MAX_FRAGS, outer_mtu,
							mbuf_pool, mbuf_pool_indirect);
					if (unlikely(nb_frags < 0)) {
						pestats.ul_tx_errors += 1;
						goto free;
					}
					/* Prepend the outer Ethernet header to each fragment and */
					/* compute the IPv4 header checksum. */
					for (i = 0; i < nb_frags; i++) {
						struct rte_ether_hdr *frag_eth_hdr = (struct rte_ether_hdr *)
							rte_pktmbuf_prepend(frags[i],
									sizeof(struct rte_ether_hdr));
						if (unlikely(frag_eth_hdr == NULL)) {
							for (; i < nb_frags; i++)
								rte_pktmbuf_free(frags[i]);
							pestats.ul_tx_errors += 1;
							goto free;
						}
						memcpy(frag_eth_hdr, &ip4_hdr_cork.eth_hdr,
								sizeof(struct rte_ether_hdr));
						struct rte_ipv4_hdr *frag_ip4_hdr =
							(struct rte_ipv4_hdr *)(frag_eth_hdr + 1);
						frag_ip4_hdr->hdr_checksum = rte_ipv4_cksum(frag_ip4_hdr);
					}
					pestats.encap_frags += 1;
					goto send_frags;
				}
			} else {
				/* EtherIP over IPv6 mode: */
				if (likely(sizeof(struct rte_ipv6_hdr) + sizeof(struct pe_etherip_hdr)
						+ m->pkt_len <= outer_mtu)) {
					/* No fragmentation needed: */
					/* Reserve room for the headers at the head of m; drop the packet on failure. */
					struct pe_ip6_hdr *hdr = (struct pe_ip6_hdr *)rte_pktmbuf_prepend(
							m, sizeof(struct pe_ip6_hdr));
					if (unlikely(hdr == NULL))
						goto free;
					/* Write the headers. */
					memcpy(hdr, &ip6_hdr_cork, sizeof(struct pe_ip6_hdr));
					hdr->ip6_hdr.payload_len = rte_cpu_to_be_16(m->pkt_len
							- sizeof(struct rte_ether_hdr)
							- sizeof(struct rte_ipv6_hdr));
				} else {
					/* Fragmentation needed: */
					/* First prepend the headers without the outer Ethernet header */
					/* (IPv6 + EtherIP) to m to form a complete IPv6 packet. */
					struct rte_ipv6_hdr *ip6_hdr = (struct rte_ipv6_hdr *)
						rte_pktmbuf_prepend(m, sizeof(struct rte_ipv6_hdr)
								+ sizeof(struct pe_etherip_hdr));
					if (unlikely(ip6_hdr == NULL))
						goto free;
					memcpy(ip6_hdr, &ip6_hdr_cork.ip6_hdr, sizeof(struct rte_ipv6_hdr)
							+ sizeof(struct pe_etherip_hdr));
					ip6_hdr->payload_len = rte_cpu_to_be_16(m->pkt_len
							- sizeof(struct rte_ipv6_hdr));
					/* Do standard IPv6 fragmentation with librte_ip_frag. */
					nb_frags = rte_ipv6_fragment_packet(m, frags,
							PE_ENCAP_MAX_FRAGS, outer_mtu,
							mbuf_pool, mbuf_pool_indirect);
					if (unlikely(nb_frags < 0)) {
						pestats.ul_tx_errors += 1;
						goto free;
					}
					/* librte_ip_frag leaves the fragment header ID zeroed, so write a */
					/* per-packet unique ID here. */
					ip6_frag_id++;
					/* Prepend the outer Ethernet header to each fragment. */
					for (i = 0; i < nb_frags; i++) {
						struct rte_ipv6_fragment_ext *frag_hdr =
							rte_pktmbuf_mtod_offset(frags[i],
									struct rte_ipv6_fragment_ext *,
									sizeof(struct rte_ipv6_hdr));
						frag_hdr->id = rte_cpu_to_be_32(ip6_frag_id);
						struct rte_ether_hdr *frag_eth_hdr = (struct rte_ether_hdr *)
							rte_pktmbuf_prepend(frags[i],
									sizeof(struct rte_ether_hdr));
						if (unlikely(frag_eth_hdr == NULL)) {
							for (; i < nb_frags; i++)
								rte_pktmbuf_free(frags[i]);
							pestats.ul_tx_errors += 1;
							goto free;
						}
						memcpy(frag_eth_hdr, &ip6_hdr_cork.eth_hdr,
								sizeof(struct rte_ether_hdr));
					}
					pestats.encap_frags += 1;
					goto send_frags;
				}
			}

			{
				/* Transmit path when no fragmentation was needed: */
				const uint64_t txbytes = m->pkt_len;
				/* Send one packet out the UL port. */
				const uint16_t nb_tx = rte_eth_tx_burst(port_ul, 0, &m, 1);
				/* If nothing could be sent, drop the packet. */
				if (unlikely(nb_tx == 0)) {
					pestats.ul_tx_errors += 1;
					goto free;
				}
				pestats.ul_tx_packets += 1;
				pestats.ul_tx_bytes += txbytes;
			}
			continue;

send_frags:
			{
				/* Transmit path when the packet was fragmented: */
				uint64_t txbytes = 0;
				for (i = 0; i < nb_frags; i++)
					txbytes += frags[i]->pkt_len;
				/* Send all the fragments out the UL port. */
				const uint16_t nb_tx = rte_eth_tx_burst(port_ul, 0, frags, nb_frags);
				/* If not all of them could be sent, drop the ones that failed. */
				if (unlikely(nb_tx != nb_frags)) {
					uint16_t buf;
					for (buf = nb_tx; buf < nb_frags; buf++) {
						txbytes -= frags[buf]->pkt_len;
						ret = rte_ring_enqueue(ring_dl2main, frags[buf]);
						if (unlikely(ret != 0))
							rte_pktmbuf_free(frags[buf]);
						pestats.ul_tx_errors += 1;
					}
				}
				pestats.ul_tx_packets += nb_tx;
				pestats.ul_tx_bytes += txbytes;
				/* m is not transmitted directly, so free it here. The fragments */
				/* reference its data, so it is actually released once they are */
				/* freed. */
			}
free:
			ret = rte_ring_enqueue(ring_dl2main, m);
			if (unlikely(ret != 0))
				rte_pktmbuf_free(m);
		}
	}
}

/*
 * Loop that does everything outside the data path: freeing packets to be dropped,
 * handling ARP and NDP, and serving the statistics socket.
 */
static __rte_noreturn void
lcore_main(void)
{
	uint32_t counter = 0;
	uint64_t next_probe = 0;
	for (;;) {
		int ret;
		struct rte_mbuf *buf = NULL;
		ret = rte_ring_dequeue(ring_ul2main, (void **)&buf);
		if (likely(ret == 0)) {
			if (pe_mode == PE_MODE_IP4 && is_arp(buf))
				handle_arp(buf);
			else if (pe_mode == PE_MODE_IP6 && is_icmp6(buf))
				handle_icmp6(buf);
			rte_pktmbuf_free(buf);
		}
		ret = rte_ring_dequeue(ring_dl2main, (void **)&buf);
		if (likely(ret == 0)) {
			rte_pktmbuf_free(buf);
		}
		/* While the next hop MAC address is unresolved, send an ARP request (ip4) */
		/* or an NS and an RS (ip6) roughly once a second. */
		if (unlikely(!nexthop_ready)) {
			uint64_t now = rte_get_timer_cycles();
			if (now >= next_probe) {
				if (pe_mode == PE_MODE_IP4) {
					send_arp_request();
				} else if (pe_mode == PE_MODE_IP6) {
					send_ndp_ns();
					send_ndp_rs();
				}
				next_probe = now + rte_get_timer_hz();
			}
		}
		/* Busy-polling accept() is expensive, so do it only once in a while. */
		if (likely((counter++ & 0x03ffffff) != 0))
			continue;
		ret = accept(serverfd, NULL, NULL);
		if (ret > 0) {
			int i;
			for (i = 0; i < PE_CLIENT_MAX; i++) {
				if (clientfds[i] == -1)
					break;
			}
			if (i == PE_CLIENT_MAX) {
				printf("PE_CLIENT_MAX reached\n");
				close(ret);
			} else {
				clientfds[i] = ret;
			}
		}
		for (int i = 0; i < PE_CLIENT_MAX; i++) {
			int req;
			if (clientfds[i] == -1)
				continue;
			ret = recv(clientfds[i], &req, sizeof(req), MSG_DONTWAIT);
			if (ret == 0) {
				close(clientfds[i]);
				clientfds[i] = -1;
			}
			if (ret > 0) {
				send(clientfds[i], &pestats, sizeof(pestats), MSG_DONTWAIT);
			}
		}
	}
}

/* Print the settings in effect, as the options that select them. */
static void
print_settings(void)
{
	char buf[INET6_ADDRSTRLEN];

	if (pe_mode == PE_MODE_IP4) {
		printf("mode: EtherIP over IPv4\n");
		printf("remote: %s\n", inet_ntop(AF_INET, ip4_remote_addr, buf, sizeof(buf)));
		printf("local: %s\n", inet_ntop(AF_INET, ip4_local_addr, buf, sizeof(buf)));
	} else {
		printf("mode: EtherIP over IPv6\n");
		printf("remote: %s\n", inet_ntop(AF_INET6, ip6_remote_addr.a, buf, sizeof(buf)));
		printf("local: %s\n", inet_ntop(AF_INET6, ip6_local_addr.a, buf, sizeof(buf)));
	}
	printf("mtu: %u\n", outer_mtu);
	if (nexthop_static)
		printf("nexthop-mac: " RTE_ETHER_ADDR_PRT_FMT "\n", RTE_ETHER_ADDR_BYTES(&nexthop_mac));
	else
		printf("nexthop-mac: (resolved with %s)\n", pe_mode == PE_MODE_IP4 ? "ARP" : "NDP");
	printf("stats-socket: %s\n", stats_path);
}

/* Parse n bytes out of a hex string without separators. */
static int
parse_hex_bytes(const char *s, uint8_t *out, int n)
{
	for (int i = 0; i < n; i++) {
		char buff2[3] = { '\0', '\0', '\0', };
		if (!isxdigit((unsigned char)s[i*2]) || !isxdigit((unsigned char)s[i*2+1]))
			return -1;
		buff2[0] = s[i*2];
		buff2[1] = s[i*2+1];
		out[i] = (uint8_t)strtol(buff2, NULL, 16);
	}
	return 0;
}

/* Parse an IPv4 address. Both dotted ("192.0.2.1") and 8 hex digits are accepted. */
static int
parse_ip4_addr(const char *s, uint8_t *out)
{
	if (strchr(s, '.') != NULL) {
		struct in_addr in;
		if (inet_pton(AF_INET, s, &in) != 1)
			return -1;
		memcpy(out, &in, 4);
		return 0;
	}
	if (strnlen(s, 9) != 8)
		return -1;
	return parse_hex_bytes(s, out, 4);
}

/* Parse an IPv6 address. Both colon-separated and 32 hex digits are accepted. */
static int
parse_ip6_addr(const char *s, struct rte_ipv6_addr *out)
{
	if (strchr(s, ':') != NULL) {
		struct in6_addr in6;
		if (inet_pton(AF_INET6, s, &in6) != 1)
			return -1;
		memcpy(out->a, &in6, RTE_IPV6_ADDR_SIZE);
		return 0;
	}
	if (strnlen(s, RTE_IPV6_ADDR_SIZE * 2 + 1) != RTE_IPV6_ADDR_SIZE * 2)
		return -1;
	return parse_hex_bytes(s, out->a, RTE_IPV6_ADDR_SIZE);
}

/*
 * Parse a tunnel endpoint address of either family, in the textual or the hex
 * form. Returns the mode the address family implies (PE_MODE_IP4 or PE_MODE_IP6),
 * or -1 when the string is not an address.
 */
static int
parse_ip_addr(const char *s, uint8_t *out4, struct rte_ipv6_addr *out6)
{
	if (strchr(s, ':') != NULL || strnlen(s, RTE_IPV6_ADDR_SIZE * 2 + 1) == RTE_IPV6_ADDR_SIZE * 2)
		return parse_ip6_addr(s, out6) == 0 ? PE_MODE_IP6 : -1;
	return parse_ip4_addr(s, out4) == 0 ? PE_MODE_IP4 : -1;
}

/* Parse a MAC address. Both colon-separated and 12 hex digits are accepted. */
static int
parse_mac_addr(const char *s, uint8_t *out)
{
	char buff[13];
	int j = 0;
	for (int i = 0; s[i] != '\0'; i++) {
		if (s[i] == ':' || s[i] == '-')
			continue;
		if (j >= 12)
			return -1;
		buff[j++] = s[i];
	}
	if (j != 12)
		return -1;
	buff[j] = '\0';
	return parse_hex_bytes(buff, out, 6);
}

static void
init_corks(void)
{
	/* ip4 */
	memcpy(&ip4_hdr_cork.eth_hdr.dst_addr, &nexthop_mac, sizeof(struct rte_ether_addr));
	memcpy(&ip4_hdr_cork.eth_hdr.src_addr, &ethaddr_ul, sizeof(struct rte_ether_addr));
	ip4_hdr_cork.eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	ip4_hdr_cork.ip4_hdr.version_ihl = 0x45;
	ip4_hdr_cork.ip4_hdr.type_of_service = 0;
	ip4_hdr_cork.ip4_hdr.total_length = 0;
	ip4_hdr_cork.ip4_hdr.packet_id = 0;
	ip4_hdr_cork.ip4_hdr.fragment_offset = 0;
	ip4_hdr_cork.ip4_hdr.time_to_live = 64;
	ip4_hdr_cork.ip4_hdr.next_proto_id = PE_PROTO_ETHERIP;
	ip4_hdr_cork.ip4_hdr.hdr_checksum = 0;
	memcpy(&ip4_hdr_cork.ip4_hdr.src_addr, ip4_local_addr, 4);
	memcpy(&ip4_hdr_cork.ip4_hdr.dst_addr, ip4_remote_addr, 4);
	ip4_hdr_cork.etherip_hdr.ver_res = rte_cpu_to_be_16(PE_ETHERIP_VER_RES);
	/* ip6 */
	memcpy(&ip6_hdr_cork.eth_hdr.dst_addr, &nexthop_mac, sizeof(struct rte_ether_addr));
	memcpy(&ip6_hdr_cork.eth_hdr.src_addr, &ethaddr_ul, sizeof(struct rte_ether_addr));
	ip6_hdr_cork.eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	ip6_hdr_cork.ip6_hdr.vtc_flow = rte_cpu_to_be_32(0x60000000);
	ip6_hdr_cork.ip6_hdr.payload_len = 0;
	ip6_hdr_cork.ip6_hdr.proto = PE_PROTO_ETHERIP;
	ip6_hdr_cork.ip6_hdr.hop_limits = 64;
	ip6_hdr_cork.ip6_hdr.src_addr = ip6_local_addr;
	ip6_hdr_cork.ip6_hdr.dst_addr = ip6_remote_addr;
	ip6_hdr_cork.etherip_hdr.ver_res = rte_cpu_to_be_16(PE_ETHERIP_VER_RES);
	/* Ready to transmit right away when the next hop is static. */
	if (nexthop_static) {
		rte_wmb();
		nexthop_ready = true;
	}
}

/*
 * Resolve a port given on the command line: a port ID, or a device name as
 * DPDK shows it (e.g. 0000:01:00.0 or net_pcap0). PCI addresses are also
 * accepted in the shorter forms the EAL accepts (e.g. 01:00.0).
 */
static int
parse_port(const char *str, uint16_t *port)
{
	char *endp;
	unsigned long id;
	struct rte_pci_addr pci_addr;
	char name[RTE_ETH_NAME_MAX_LEN];

	if (str[0] == '\0')
		return -1;
	if (isdigit((unsigned char)str[0])) {
		id = strtoul(str, &endp, 10);
		if (*endp == '\0') {
			if (id >= RTE_MAX_ETHPORTS || !rte_eth_dev_is_valid_port((uint16_t)id))
				return -1;
			*port = (uint16_t)id;
			return 0;
		}
	}
	if (rte_eth_dev_get_port_by_name(str, port) == 0)
		return 0;
	if (rte_pci_addr_parse(str, &pci_addr) == 0) {
		rte_pci_device_name(&pci_addr, name, sizeof(name));
		return rte_eth_dev_get_port_by_name(name, port);
	}
	return -1;
}

/*
 * Decide which port is the UL side and which is the DL side.
 * Sides not given with --ul-port / --dl-port are filled in from the available
 * ports, of which there must then be exactly two: with neither given, the
 * first port is DL and the second is UL; with one given, the other side is
 * the remaining port. With both given, any other port is left untouched.
 */
static int
select_ports(void)
{
	uint16_t ports[2];
	unsigned nb_ports = 0;
	uint16_t portid;

	if (port_ul_arg != NULL && parse_port(port_ul_arg, &port_ul) != 0) {
		printf("Error: UL port not found: %s\n", port_ul_arg);
		return -1;
	}
	if (port_dl_arg != NULL && parse_port(port_dl_arg, &port_dl) != 0) {
		printf("Error: DL port not found: %s\n", port_dl_arg);
		return -1;
	}

	if (port_ul_arg == NULL || port_dl_arg == NULL) {
		RTE_ETH_FOREACH_DEV(portid) {
			if (nb_ports < 2)
				ports[nb_ports] = portid;
			nb_ports++;
		}
		if (nb_ports != 2) {
			printf("Error: number of ports must be 2 (%u found) unless both "
					"--"OPTION_UL_PORT" and --"OPTION_DL_PORT" are given\n", nb_ports);
			return -1;
		}
		if (port_ul_arg == NULL && port_dl_arg == NULL) {
			port_dl = ports[0];
			port_ul = ports[1];
		} else if (port_ul_arg == NULL) {
			port_ul = (ports[0] == port_dl) ? ports[1] : ports[0];
		} else {
			port_dl = (ports[0] == port_ul) ? ports[1] : ports[0];
		}
	}

	if (port_ul == port_dl) {
		printf("Error: UL and DL ports must differ\n");
		return -1;
	}
	return 0;
}

static void
print_usage(const char *prgname)
{
	printf("Usage: %s [EAL options] -- --remote ADDR --local ADDR [options]\n", prgname);
	printf("  --remote ADDR         IP address of the remote tunnel endpoint (required)\n");
	printf("  --local ADDR          IP address of the local tunnel endpoint (required)\n");
	printf("                        Both IPv4 or both IPv6, which selects the mode.\n");
	printf("  --mtu N               UL-side MTU (IPv4: %d-%d, IPv6: %d-%d, default %d)\n",
			PE_MIN_MTU_IP4, PE_MAX_MTU, PE_MIN_MTU_IP6, PE_MAX_MTU, PE_DEFAULT_MTU);
	printf("  --nexthop-mac MAC     static next-hop MAC address (resolved with ARP/NDP when omitted)\n");
	printf("  --stats-socket PATH   statistics socket path (default " PESTATS_UNIX_SOCKET_PATH ")\n");
	printf("  --ul-port PORT        port used as the UL side (default: the second port)\n");
	printf("  --dl-port PORT        port used as the DL side (default: the first port)\n");
	printf("  -h, --help            print this help and exit\n");
	printf("PORT is a port ID or a device name (e.g. 0000:01:00.0 or net_pcap0).\n");
}

enum {
	OPT_REMOTE = 256,
	OPT_LOCAL,
	OPT_MTU,
	OPT_NEXTHOP_MAC,
	OPT_STATS_SOCKET,
	OPT_UL_PORT,
	OPT_DL_PORT,
	OPT_HELP,
};

/*
 * Parse the application options (those after "--") and apply them to the
 * settings. Everything is validated here except the ports, which need the
 * ethdev layer and are resolved later by select_ports().
 * Returns 0 on success, 1 when the usage was requested, -1 on error.
 */
static int
parse_args(int argc, char **argv)
{
	static const struct option lgopts[] = {
		{OPTION_REMOTE, required_argument, NULL, OPT_REMOTE},
		{OPTION_LOCAL, required_argument, NULL, OPT_LOCAL},
		{OPTION_MTU, required_argument, NULL, OPT_MTU},
		{OPTION_NEXTHOP_MAC, required_argument, NULL, OPT_NEXTHOP_MAC},
		{OPTION_STATS_SOCKET, required_argument, NULL, OPT_STATS_SOCKET},
		{OPTION_UL_PORT, required_argument, NULL, OPT_UL_PORT},
		{OPTION_DL_PORT, required_argument, NULL, OPT_DL_PORT},
		{"help", no_argument, NULL, OPT_HELP},
		{NULL, 0, NULL, 0},
	};
	const char *prgname = argv[0];
	const char *remote_arg = NULL;
	const char *local_arg = NULL;
	const char *mtu_arg = NULL;
	const char *nexthop_mac_arg = NULL;
	const char *stats_socket_arg = NULL;
	int opt, mode_remote, mode_local;
	long mtu, min_mtu;
	char *endp;

	while ((opt = getopt_long(argc, argv, "h", lgopts, NULL)) != EOF) {
		switch (opt) {
		case OPT_REMOTE:
			remote_arg = optarg;
			break;
		case OPT_LOCAL:
			local_arg = optarg;
			break;
		case OPT_MTU:
			mtu_arg = optarg;
			break;
		case OPT_NEXTHOP_MAC:
			nexthop_mac_arg = optarg;
			break;
		case OPT_STATS_SOCKET:
			stats_socket_arg = optarg;
			break;
		case OPT_UL_PORT:
			port_ul_arg = optarg;
			break;
		case OPT_DL_PORT:
			port_dl_arg = optarg;
			break;
		case 'h':
		case OPT_HELP:
			print_usage(prgname);
			return 1;
		default:
			print_usage(prgname);
			return -1;
		}
	}
	if (optind < argc) {
		printf("Error: unexpected argument: %s\n", argv[optind]);
		print_usage(prgname);
		return -1;
	}

	/* Endpoint addresses; their family selects the mode. */
	if (remote_arg == NULL || local_arg == NULL) {
		printf("Error: --" OPTION_REMOTE " and --" OPTION_LOCAL " are required\n");
		print_usage(prgname);
		return -1;
	}
	mode_remote = parse_ip_addr(remote_arg, ip4_remote_addr, &ip6_remote_addr);
	if (mode_remote < 0) {
		printf("Error: remote address invalid: %s\n", remote_arg);
		return -1;
	}
	mode_local = parse_ip_addr(local_arg, ip4_local_addr, &ip6_local_addr);
	if (mode_local < 0) {
		printf("Error: local address invalid: %s\n", local_arg);
		return -1;
	}
	if (mode_remote != mode_local) {
		printf("Error: remote and local addresses must be of the same address family\n");
		return -1;
	}
	pe_mode = mode_remote;

	/* MTU, whose lower bound depends on the mode. */
	mtu = PE_DEFAULT_MTU;
	if (mtu_arg != NULL) {
		mtu = strtol(mtu_arg, &endp, 10);
		if (mtu_arg[0] == '\0' || *endp != '\0') {
			printf("Error: mtu invalid: %s\n", mtu_arg);
			return -1;
		}
	}
	min_mtu = (pe_mode == PE_MODE_IP4) ? PE_MIN_MTU_IP4 : PE_MIN_MTU_IP6;
	if (mtu < min_mtu || mtu > PE_MAX_MTU) {
		printf("Error: mtu out of range (%ld-%d)\n", min_mtu, PE_MAX_MTU);
		return -1;
	}
	outer_mtu = (uint16_t)mtu;

	/* Static next hop, if any. */
	if (nexthop_mac_arg != NULL) {
		if (parse_mac_addr(nexthop_mac_arg, nexthop_mac.addr_bytes) != 0) {
			printf("Error: next-hop MAC address invalid: %s\n", nexthop_mac_arg);
			return -1;
		}
		nexthop_static = true;
	}

	if (stats_socket_arg != NULL) {
		if (strnlen(stats_socket_arg, sizeof(stats_path)) >= sizeof(stats_path)) {
			printf("Error: statistics socket path too long\n");
			return -1;
		}
		strcpy(stats_path, stats_socket_arg);
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	unsigned lcoreid;
	char name_ul[RTE_ETH_NAME_MAX_LEN];
	char name_dl[RTE_ETH_NAME_MAX_LEN];
	uint64_t frag_cycles;

	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid parameters\n");
	if (ret > 0) {
		/* --help */
		rte_eal_cleanup();
		return 0;
	}

	if (rte_lcore_count() != 3)
		rte_exit(EXIT_FAILURE, "Error: number of lcores must be 3\n");

	if (select_ports() < 0)
		rte_exit(EXIT_FAILURE, "Error: port selection failed\n");

	print_settings();

	ring_ul2main = rte_ring_create("UL2MAIN", INTERNAL_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ|RING_F_SC_DEQ);
	if (ring_ul2main == NULL)
		rte_exit(EXIT_FAILURE, "Error: ul2main ring create failed\n");
	ring_dl2main = rte_ring_create("DL2MAIN", INTERNAL_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ|RING_F_SC_DEQ);
	if (ring_dl2main == NULL)
		rte_exit(EXIT_FAILURE, "Error: dl2main ring create failed\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * 2 /* UL and DL */,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Pool of indirect mbufs used when fragmenting during encapsulation. */
	mbuf_pool_indirect = rte_pktmbuf_pool_create("MBUF_POOL_INDIRECT", NUM_MBUFS,
		MBUF_CACHE_SIZE, 0, 0, rte_socket_id());
	if (mbuf_pool_indirect == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create indirect mbuf pool\n");

	/* Reassembly table used when decapsulating. Only lcore_ul touches it. */
	frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * PE_FRAG_TTL_MS;
	frag_tbl = rte_ip_frag_table_create(PE_FRAG_TBL_BUCKET_NUM,
			PE_FRAG_TBL_BUCKET_ENTRIES, PE_FRAG_TBL_MAX_ENTRIES,
			frag_cycles, rte_socket_id());
	if (frag_tbl == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create fragment reassembly table\n");

	if (port_init(port_dl, PE_DL_MTU) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init DL port %"PRIu16 "\n", port_dl);
	if (port_init(port_ul, outer_mtu) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init UL port %"PRIu16 "\n", port_ul);

	if (rte_eth_dev_get_name_by_port(port_ul, name_ul) != 0)
		strcpy(name_ul, "?");
	if (rte_eth_dev_get_name_by_port(port_dl, name_dl) != 0)
		strcpy(name_dl, "?");
	printf("Port UL: %"PRIu16" (%s) MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port_ul, name_ul, RTE_ETHER_ADDR_BYTES(&ethaddr_ul));
	printf("Port DL: %"PRIu16" (%s) MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port_dl, name_dl, RTE_ETHER_ADDR_BYTES(&ethaddr_dl));

	init_corks();

	/* pestats */
	remove(stats_path);
	memset(&serversa, 0, sizeof(serversa));
	serverfd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (serverfd < 0)
		rte_exit(EXIT_FAILURE, "Error: socket failed\n");
	int flags;
	if ((flags = fcntl(serverfd, F_GETFL, 0)) < 0)
		rte_exit(EXIT_FAILURE, "F_GETFL failed\n");
	flags |= O_NONBLOCK;
	if (fcntl(serverfd, F_SETFL, flags) < 0)
		rte_exit(EXIT_FAILURE, "F_SETFL failed\n");
	serversa.sun_family = AF_LOCAL;
	strcpy(serversa.sun_path, stats_path);
	ret = bind(serverfd, (const struct sockaddr *)&serversa, sizeof(serversa));
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error: bind failed\n");
	ret = listen(serverfd, PE_CLIENT_MAX);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error: listen failed\n");

	lcoreid_main = rte_lcore_id();
	RTE_LCORE_FOREACH_WORKER(lcoreid) {
		if (lcoreid_ul == LCORE_ID_ANY) {
			lcoreid_ul = lcoreid;
			continue;
		}
		if (lcoreid_dl == LCORE_ID_ANY) {
			lcoreid_dl = lcoreid;
			continue;
		}
	}
	if (lcoreid_ul == LCORE_ID_ANY || lcoreid_dl == LCORE_ID_ANY)
		rte_exit(EXIT_FAILURE, "Error: lcores invalid\n");

	if (rte_eal_remote_launch(lcore_ul, mbuf_pool, lcoreid_ul))
		rte_exit(EXIT_FAILURE, "Error: ul remote launch failed\n");
	if (rte_eal_remote_launch(lcore_dl, mbuf_pool, lcoreid_dl))
		rte_exit(EXIT_FAILURE, "Error: dl remote launch failed\n");

	lcore_main();

	rte_eal_cleanup();

	return 0;
}
