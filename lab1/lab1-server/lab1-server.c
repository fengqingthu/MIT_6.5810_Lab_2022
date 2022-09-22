/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
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
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (port == 1 && rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Main work of application loop. 8< */
	for (;;) {
		RTE_ETH_FOREACH_DEV(port) {
			/* Get burst of RX packets, from port1 */
			if (port != 1)
				continue;

			struct rte_mbuf *bufs[BURST_SIZE];
			struct rte_mbuf *pkt;
			struct rte_ether_hdr *eth_h;
			struct rte_ipv4_hdr *ip_h;
			struct rte_icmp_hdr *icmp_h;
			struct rte_ether_addr eth_addr;
			uint16_t eth_type;
			uint32_t ip_addr;
			uint32_t cksum;
			int l2_len;
			uint8_t i;

			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			uint8_t nb_replies = 0;
			uint8_t rx_idx = 0;
			for (i = 0; i < nb_rx; i++) {
				pkt = bufs[i];
				/* FILE *fp;
				char *fname;
				sprintf(fname, "/opt/fengqing/tmp/pkt_%d", rx_idx++);
				fp = fopen(fname ,"a");*/
				printf("received:\n");
				rte_pktmbuf_dump(stdout, pkt, pkt->pkt_len);

				eth_h = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
				/* if (eth_h->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
					rte_pktmbuf_free(pkt);
					continue;
				} */

				ip_h = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, 
					sizeof(struct rte_ether_hdr));
				
				icmp_h = (struct rte_icmp_hdr *)(ip_h + 1);

				if (! ((ip_h->next_proto_id == IPPROTO_ICMP) &&
					(icmp_h->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) &&
					(icmp_h->icmp_code == 0))) {
					rte_pktmbuf_free(pkt);
					continue;
				}

				printf("start preparing echo reply\n");
				/* Swap ether addresses. */
				rte_ether_addr_copy(&eth_h->src_addr, &eth_addr);
				rte_ether_addr_copy(&eth_h->dst_addr, &eth_h->src_addr);
				rte_ether_addr_copy(&eth_addr, &eth_h->dst_addr);

				/* Assuming the ip addresses is not multicast, simply swap. */
				ip_addr = ip_h->src_addr;
				ip_h->src_addr = ip_h->dst_addr;
				ip_h->dst_addr = ip_addr;
				ip_h->hdr_checksum = 0;
				ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);
				
				icmp_h->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
				icmp_h->icmp_cksum = 0;
				icmp_h->icmp_cksum = ~rte_raw_cksum(icmp_h, sizeof(struct rte_icmp_hdr));
				/* Hard code icmp checksum, this is what I found online, 
					though looks a bit weird. */
				/* cksum = ~icmp_h->icmp_cksum & 0xffff;
				cksum += ~htons(RTE_IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
				cksum += htons(RTE_IP_ICMP_ECHO_REPLY << 8) & 0xffff;
				cksum = (cksum & 0xffff) + (cksum >> 16);
				cksum = (cksum & 0xffff) + (cksum >> 16);
				icmp_h->icmp_cksum = ~cksum & 0xffff; */
				printf("modified:\n");
				rte_pktmbuf_dump(stdout, pkt, pkt->pkt_len);
				bufs[nb_replies++] = pkt;
			}

			/* Send back echo replies. */
			uint16_t nb_tx = 0;
			if (nb_replies > 0) {
				nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_replies);
			}

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}	
		}
	}
	/* >8 End of loop. */
}
/* >8 End Basic forwarding application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (portid == 1 && port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main();
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
