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

static const uint16_t PORTID = 2U;

struct rte_ether_addr client_addr = {{0,0,0,0,0,0}};
struct rte_ether_addr server_addr = {{0x0c, 0x42, 0xa1, 0x8c, 0xdc, 0x24}};
const uint64_t sector_sz = 512;

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
        if (retval != 0)
        {
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
        for (q = 0; q < rx_rings; q++)
        {
                retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
                if (retval < 0)
                        return retval;
        }

        txconf = dev_info.default_txconf;
        txconf.offloads = port_conf.txmode.offloads;
        /* Allocate and set up 1 TX queue per Ethernet port. */
        for (q = 0; q < tx_rings; q++)
        {
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

        client_addr = addr;

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
        struct rte_mbuf *pkt = rte_pktmbuf_alloc(mbuf_pool);
        if (!pkt)
	{
                printf("Allocation Error\n");
                return NULL;
	}

        void *pkt_h = rte_pktmbuf_mtod_offset(pkt, void *, 0);

        struct rte_ether_hdr eth_h;
        eth_h.ether_type = RTE_ETHER_TYPE_TEB; // Not sure which frame type
        eth_h.src_addr = client_addr;
        eth_h.dst_addr = server_addr;
        rte_memcpy(pkt_h, &eth_h, sizeof(struct rte_ether_hdr));

        char *pkt_data = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(struct rte_ether_hdr));
        int op = 1;
        rte_memcpy(pkt_data, &op, sizeof(int));
        pkt_data += sizeof(int);
        uint64_t lba = 0UL;
        rte_memcpy(pkt_data, &lba, sizeof(uint64_t));
        pkt_data += sizeof(uint64_t);

        unsigned char req_data[] = "Hello World!\n";
        rte_memcpy(pkt_data, &req_data, sizeof(req_data));
        pkt->data_len = sizeof(struct rte_ether_hdr) + sizeof(int) + sizeof(uint64_t) + sizeof(req_data);

        pkt->pkt_len = pkt->data_len;
        pkt->buf_len = 2176;
        pkt->data_off = 128;
        pkt->nb_segs = 1;
        pkt->ol_flags = 0;
        pkt->port = 2;
        pkt->refcnt = 1;
        pkt->next = NULL;
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
        uint64_t totalus = 0;
        uint64_t indpdk = 0;
        uint64_t startdpdk;
        uint32_t seq = 0;
        uint32_t rec = 0;

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
                       "not be optimal.\n",
                       port);

        printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
               rte_lcore_id());

        /* Main work of application loop. 8< */
        for (;;)
        {
                RTE_ETH_FOREACH_DEV(port)
                {
                        /* Get burst of RX packets, from port1 */
                        if (port != PORTID)
                                continue;

                        struct rte_mbuf *bufs[BURST_SIZE];

                        if (seq < 10)
                        {
                                struct rte_mbuf *pkt = construct_ping_packet();

                                /* Send ping. */
                                printf("To be sent: %d\n", seq);
                                rte_pktmbuf_dump(stdout, pkt, pkt->pkt_len);
                                bufs[0] = pkt;

                                startdpdk = rte_rdtsc_precise();
                                const uint16_t nb_tx = rte_eth_tx_burst(port, 0, bufs, 1);
                                indpdk += rte_rdtsc_precise() - startdpdk;

                                if (unlikely(nb_tx != 1))
                                {
                                        rte_exit(EXIT_FAILURE, "Error: fail to send ping pkt\n");
                                }
                                seq++;
                        }

                        startdpdk = rte_rdtsc_precise();
                        const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
                        indpdk += rte_rdtsc_precise() - startdpdk;

                        if (unlikely(nb_rx == 0))
                                continue;

                        /* Free received packets. */
                        uint8_t i;
                        for (i = 0; i < nb_rx; i++)
                        {
                                // struct rte_ipv4_hdr *ip_h = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *,
                                //                                                     sizeof(struct rte_ether_hdr));

                                // struct rte_icmp_hdr *icmp_h = rte_pktmbuf_mtod_offset(bufs[i], struct rte_icmp_hdr *,
                                //                                                       (sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)));

                                // if ((ip_h->next_proto_id == IPPROTO_ICMP) &&
                                //     (icmp_h->icmp_type == RTE_IP_ICMP_ECHO_REPLY) &&
                                //     (icmp_h->icmp_code == 0))
                                // {
                                //         rec++;
                                // }
                                // if (rec == NUM_PING)
                                // {
                                //         /* Record time stats. */
                                //         printf("%d packets transmitted, rtt avg= %ldus, spent in dpdk avg= %ldus\n",
                                //                seq, ((rte_rdtsc_precise() - begin) * 1000000 / hz) / rec, (indpdk * 1000000 / hz) / rec);
                                //         rec++;
                                // }
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

int main(int argc, char *argv[])
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
        if (portid == PORTID && port_init(portid, mbuf_pool) != 0)
                rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
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
