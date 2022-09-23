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
const static uint32_t NUM_PING = 500000;

/* Define the mempool globally */
struct rte_mempool *mbuf_pool = NULL;

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

/* Construct the hardcoded ping packet. */
static struct rte_mbuf *
construct_ping_packet(void)
{
	struct rte_mbuf *icmpbuf  = rte_pktmbuf_alloc(mbuf_pool);
	if (!icmpbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	icmpbuf->pkt_len = 98;
	icmpbuf->data_len = 98;
	icmpbuf->buf_len = 2176;
	icmpbuf->nb_segs = 1;
	icmpbuf->ol_flags = 0x80;
	icmpbuf->port = 2;
	icmpbuf->packet_type = 0x691;
	icmpbuf->data_off = 128;
	icmpbuf->refcnt = 1;
	icmpbuf->next = NULL;
	
	uint8_t *pkt_data = rte_pktmbuf_mtod(icmpbuf, uint8_t *);
	unsigned char hardcode[] = 
		{0x0C, 0x42, 0xA1, 0x8B, 0x31, 0x60, 0x0C, 0x42, 0xA1, 0x8B, 0x31, 0x20, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x54, 0x7E, 0xEC, 0x40, 0x00, 0x40, 0x01, 0x26, 0x67, 0xC0, 0xA8, 0x0A, 0x02, 0xC0, 0xA8,
		0x0A, 0x03, 0x08, 0x00, 0x68, 0x87, 0x00, 0x57, 0x27, 0x10, 0x52, 0xCF, 0x2C, 0x63, 0x00, 0x00,
		0x00, 0x00, 0x26, 0x0C, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
		0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
		0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
		0x36, 0x37};
	rte_memcpy(pkt_data, &hardcode, 98);
	return icmpbuf;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main()
{
	uint16_t port;
	uint64_t hz = rte_get_timer_hz(); 
	uint64_t begin = rte_rdtsc_precise(); 
	uint32_t seq = 0;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
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
			if (port != 2)
				continue;
			
			struct rte_mbuf *bufs[BURST_SIZE];

			if (seq <= NUM_PING) {
				struct rte_mbuf *pkt = construct_ping_packet();
				struct rte_icmp_hdr *icmphdr = rte_pktmbuf_mtod_offset(pkt, struct rte_icmp_hdr *, 
					(sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)));
				/* Increment seq number. */
				icmphdr->icmp_seq_nb = rte_cpu_to_be_16(seq++);
				icmphdr->icmp_cksum = 0;
				icmphdr->icmp_cksum = ~rte_raw_cksum(icmphdr, pkt->pkt_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));

				/* Send ping. */
				printf("To be sent:\n");
				rte_pktmbuf_dump(stdout, pkt, pkt->pkt_len);
				bufs[0] = pkt;
				const uint16_t nb_tx = rte_eth_tx_burst(port, 0, bufs, 1);
				if (unlikely(nb_tx != 1)) {
					rte_exit(EXIT_FAILURE, "Error: fail to send initial ping pkt\n");
				}
			}
			
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			/* Free received packets. */
			uint8_t i;
			for (i = 0; i < nb_rx; i++) {
				if (rte_pktmbuf_mtod_offset(bufs[i], struct rte_icmp_hdr *, 
					(sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)))->icmp_seq_nb >= rte_cpu_to_be_16(NUM_PING)) {
						uint64_t elapsed_cycles = rte_rdtsc_precise() - begin; 
						uint64_t microseconds= elapsed_cycles * 1000000 / hz;
						printf("%d packets transmitted, rtt avg= %ld\n", NUM_PING, microseconds / NUM_PING);
				}
				rte_pktmbuf_free(bufs[i]);
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
		if (portid == 2 && port_init(portid, mbuf_pool) != 0)
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
