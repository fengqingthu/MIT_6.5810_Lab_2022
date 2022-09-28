/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <spdk/env.h>
#include <spdk/log.h>
#include <spdk/nvme.h>
#include <spdk/stdinc.h>
#include <spdk/string.h>
#include <spdk/vmd.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 8

static const uint16_t PORTID = 2U;

/* ASSUMING THERE IS ONLY ONE SENDER. */
struct rte_ether_addr client_addr = {{0,0,0,0,0,0}};
struct rte_ether_addr server_addr = {{0,0,0,0,0,0}};

/* The storage request is either reading a sector or writing a sector. */
enum opcode
{
        READ = 0,
        WRITE
};

struct req_context
{
        /* Request fields. */
        enum opcode op;
        uint64_t lba;      /* The LBA of the request. */
        uint8_t *req_data; /* The request data (valid for write requests). */

        /* Response fields. */
        int rc;             /* The return code. */
        uint8_t *resp_data; /* The response data (valid for read requests). */
};

static struct spdk_nvme_ctrlr *selected_ctrlr;
static struct spdk_nvme_ns *selected_ns;
/* Global qpair. Cannot support parallel access, will need to be thread-specific. */
static struct spdk_nvme_qpair *qpair;
/* Define the mempool globally */
struct rte_mempool *mbuf_pool = NULL;

/* For mock testing. */
int idx = 0;
int lba_pool[] = {0, 0};
enum opcode op_pool[] = {WRITE, READ};
uint8_t req[] = "Hello World!\n";
uint8_t *req_data_pool[] = {req, NULL};

struct callback_args
{
        char *buf;
        struct req_context *ctx;
};

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

        server_addr = addr;

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

/*
 * Send the response back to the client using DPDK.
 *
 * This function should be invoked by SPDK's callback functions.
 * For the first step, use a mock implementation here to test main_loop().
 */
static void send_resp_to_client(struct req_context *ctx)
{
        // struct rte_mbuf *bufs[BURST_SIZE];
        // struct rte_mbuf *pkt = rte_pktmbuf_alloc(mbuf_pool);
        // if (!pkt)
	// {
        //         printf("Allocation Error\n");
        //         free(ctx->req_data);
        //         free(ctx->resp_data);
        //         free(ctx);
        //         return;
	// }
        // bufs[0] = pkt;

        // /* Construct response pkt. */
        // struct rte_ether_hdr *eth_h;
        // eth_h->ether_type = RTE_ETHER_TYPE_TEB; // Not sure which frame type
        // eth_h->src_addr = server_addr;
        // eth_h->dst_addr = client_addr;
        
        // uint8_t *pkt_data = rte_pktmbuf_mtod_offset(pkt, uint8_t *, sizeof(struct rte_ether_hdr));
        // rte_memcpy(pkt_data, &ctx->rc, sizeof(int));
        // pkt_data += sizeof(int);

        // pkt->data_len = sizeof(int);
        // pkt->nb_segs = 1;

        // if (ctx->resp_data) {
        //         /* Get the sector size. */
        //         int sector_sz = spdk_nvme_ns_get_sector_size(selected_ns);
        //         snprintf(cb_args.buf, sector_sz, "%s", ctx->resp_data);
        //         pkt->data_len += sector_sz;
        //         // rte_memcpy(pkt_data, ctx->resp_data, sector_sz);
        // }
        

        // uint16_t nb_tx = 0;
        // while (nb_tx != 1) {
        //         nb_tx = rte_eth_tx_burst(PORTID, 0, bufs, 1);
        // }
        // free(ctx->req_data);
        // free(ctx->resp_data);
        // free(ctx);
        /* Strawman mock code. */
        if (ctx->rc != 0)
        {
                printf("error %d\n", ctx->rc);
        }
        if (ctx->op == READ)
                printf("read lba=%ld: %s\n", ctx->lba, ctx->resp_data);
        else
                printf("write lba=%ld: %s\n", ctx->lba, ctx->req_data);

        free(ctx->req_data);
        /* No need to free resp_data as it is pointing to the buf. */
        // free(ctx->resp_data);
        free(ctx);
}

/*
 * Takes in a buffer of BURST_SIZE, return the number of requests received.
 *
 */
static uint16_t recv_req_from_client(struct req_context **ctxs)
{
        struct rte_mbuf *bufs[BURST_SIZE];
        struct rte_mbuf *pkt;

        /* Retrieve burst RX packets. */
        const uint16_t nb_rx = rte_eth_rx_burst(PORTID, 0, bufs, BURST_SIZE);
        
        int nb_req = 0;
        if (nb_rx > 0) {
                printf("nb_rx= %d\n", nb_rx);
                for (int i = 0; i < nb_rx; i++)
                {
                        pkt = bufs[i];
                        printf("receive raw pkt:\n");
                        rte_pktmbuf_dump(stdout, pkt, pkt->pkt_len);

                        struct rte_ether_hdr *eth_h = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
                        /* Update client address. */
                        rte_ether_addr_copy(&eth_h->src_addr, &client_addr);
                        if (eth_h->ether_type != RTE_ETHER_TYPE_TEB) {
                                printf("not teb frame, drop pkt\n");
                                continue;
                        }
                        struct req_context *ctx = malloc(sizeof(struct req_context));
                        if (!ctx) {
                                printf("ctx malloc failure\n");
                                continue;
                        }
                        /* Parse request pkt and copy into ctx. */
                        enum opcode *op = rte_pktmbuf_mtod_offset(pkt, enum opcode *, sizeof(struct rte_ether_hdr));
                        ctx->op = *op;
                        uint64_t *lba = rte_pktmbuf_mtod_offset(pkt, uint64_t *, sizeof(struct rte_ether_hdr) + sizeof(enum opcode));
                        ctx->lba = *lba;
                        uint16_t data_len = pkt->data_len - sizeof(struct rte_ether_hdr) - sizeof(enum opcode) - sizeof(uint64_t);
                        if (*op == WRITE && data_len > 0) {
                                /* Load req_data */
                                uint8_t *data = (uint8_t *) (lba + 1);
                                ctx->req_data = malloc(data_len);
                                if (ctx->req_data == NULL) {
                                        printf("ctx.req_data malloc failure, drop pkt\n");
                                        continue;
                                }
                                rte_memcpy(ctx->req_data, data, data_len);
                        } else {
                                ctx->req_data = NULL;
                        }
                        ctx->rc = 0;
                        ctx->resp_data = NULL;
                        printf("parse ctx: op=%d, lba=%ld, req_data=%s\n", ctx->op, ctx->lba, ctx->req_data);
                        ctxs[nb_req++] = ctx;
                }
        }
        return nb_req;

        /* Strawman mock code. */
        // if (idx > 1)
        //         return NULL;
        // struct req_context *ctx = malloc(sizeof(struct req_context));
        // if (!ctx)
        //         return NULL;
        // ctx->lba = lba_pool[idx];
        // ctx->op = op_pool[idx];
        // ctx->req_data = req_data_pool[idx++];
        // return ctx;
}

/* The callback function for handling read requests. */
static void read_complete(void *args, const struct spdk_nvme_cpl *completion)
{
        struct callback_args *cb_args = args;

        /* Check if there's an error for the read request. */
        if (spdk_nvme_cpl_is_error(completion))
        {
                spdk_nvme_qpair_print_completion(
                    qpair, (struct spdk_nvme_cpl *)completion);
                fprintf(stderr, "I/O error status: %s\n",
                        spdk_nvme_cpl_get_status_string(&completion->status));
                fprintf(stderr, "Failed to read, aborting run\n");
                exit(1);
        }

        cb_args->ctx->resp_data = cb_args->buf;
        cb_args->ctx->rc = 0;
        send_resp_to_client(cb_args->ctx);
        
        /* Free the resp_data here. */
        spdk_free(cb_args->buf);
        free(cb_args);
}

/* The callback function for handling write requests. */
static void write_complete(void *args, const struct spdk_nvme_cpl *completion)
{
        struct callback_args *cb_args = args;

        /* Check if there's an error for the write request. */
        if (spdk_nvme_cpl_is_error(completion))
        {
                spdk_nvme_qpair_print_completion(
                    qpair, (struct spdk_nvme_cpl *)completion);
                fprintf(stderr, "I/O error status: %s\n",
                        spdk_nvme_cpl_get_status_string(&completion->status));
                fprintf(stderr, "Failed to write, aborting run\n");
                exit(1);
        }

        cb_args->ctx->rc = 0;
        send_resp_to_client(cb_args->ctx);
        
        spdk_free(cb_args->buf);
        free(cb_args);
}

/*
 * Try to drain the completion queue and trigger callbacks.
 */
static void spdk_process_completions()
{
        spdk_nvme_qpair_process_completions(qpair, 0);
}

/*
 * Process the read request using SPDK.
 */
static void handle_read_req(struct req_context *ctx)
{
        struct callback_args *cb_args = malloc(sizeof(struct callback_args));
        cb_args->ctx = ctx;

        /* Get the sector size. */
        int sector_sz = spdk_nvme_ns_get_sector_size(selected_ns);
        /* Allocate a DMA-safe host memory buffer. */
        cb_args->buf = spdk_zmalloc(sector_sz, sector_sz, NULL,
                                    SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
        if (!cb_args->buf)
        {
                fprintf(stderr, "Failed to allocate buffer\n");
                return;
        }

        /* Now submit a cmd to read data from the 1st sector. */
        int rc = spdk_nvme_ns_cmd_read(
            selected_ns, qpair,
            cb_args->buf,  /* The buffer to store the read data */
            ctx->lba,      /* Starting LBA to read the data */
            1,             /* Length in sectors */
            read_complete, /* Callback to invoke when the read is done. */
            cb_args,       /* Argument to pass to the callback. */
            0);
        if (rc != 0)
        {
                fprintf(stderr, "Failed to submit read cmd\n");
                ctx->rc = rc;
                spdk_free(cb_args->buf);
                send_resp_to_client(ctx);
        }
}

/*
 * Process the write request using SPDK.
 */
static void handle_write_req(struct req_context *ctx)
{
        struct callback_args *cb_args = malloc(sizeof(struct callback_args));
        cb_args->ctx = ctx;

        /* Get the sector size. */
        int sector_sz = spdk_nvme_ns_get_sector_size(selected_ns);

        /* Allocate a DMA-safe host memory buffer. */
        cb_args->buf = spdk_zmalloc(sector_sz, sector_sz, NULL,
                                    SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
        if (!cb_args->buf)
        {
                fprintf(stderr, "Failed to allocate buffer\n");
                return;
        }

        /* Write the data into the buffer.  */
        snprintf(cb_args->buf, sector_sz, "%s", ctx->req_data);

        /* Submit a cmd to write data into the 1st sector. */
        int rc = spdk_nvme_ns_cmd_write(
            selected_ns, qpair,
            cb_args->buf,   /* The data to write */
            ctx->lba,       /* Starting LBA to write the data */
            1,              /* Length in sectors */
            write_complete, /* Callback to invoke when the write is done. */
            cb_args,        /* Argument to pass to the callback. */
            0);
        if (rc != 0)
        {
                fprintf(stderr, "Failed to submit write cmd\n");
                ctx->rc = rc;
                spdk_free(cb_args->buf);
                send_resp_to_client(ctx);
        }
}

/*
 * The main application logic. With only one worker.
 */
static void main_loop(void)
{
        uint16_t port;
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

        /* Setup the SPDK queue pair (submission queue and completion queue). */
        qpair = spdk_nvme_ctrlr_alloc_io_qpair(selected_ctrlr, NULL, 0);
        if (!qpair)
        {
                fprintf(stderr, "Failed to create SPDK queue pair\n");
                return;
        }

        /* The main event loop. */
        while (1)
        {
                RTE_ETH_FOREACH_DEV(port)
                {
                        if (port != PORTID)
                                continue;

                        struct req_context *ctxs[BURST_SIZE];
                        struct req_context *ctx;

                        uint16_t nb_req = recv_req_from_client(ctxs);
                        if (nb_req > 0)
                        {
                                for (int i = 0; i < nb_req; i++) {
                                        ctx = ctxs[i];
                                        if (ctx->op == READ)
                                        {
                                                handle_read_req(ctx);
                                        }
                                        else
                                        {
                                                handle_write_req(ctx);
                                        }
                                }
                        }
                        spdk_process_completions();
                }
        }

        /* Should never reach here though. */
        spdk_nvme_ctrlr_free_io_qpair(qpair);
}

/*
 * Will be called once per NVMe device found in the system.
 */
static bool probe_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid,
                     struct spdk_nvme_ctrlr_opts *opts)
{
        if (!selected_ctrlr)
        {
                printf("Attaching to %s\n", trid->traddr);
        }

        return !selected_ctrlr;
}

/*
 * Will be called for devices for which probe_cb returned true once that NVMe
 * controller has been attached to the userspace driver.
 */
static void attach_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid,
                      struct spdk_nvme_ctrlr *ctrlr,
                      const struct spdk_nvme_ctrlr_opts *opts)
{
        int nsid;
        struct spdk_nvme_ns *ns;

        printf("Attached to %s\n", trid->traddr);
        selected_ctrlr = ctrlr;

        /*
         * Iterate through the active NVMe namespaces to get a handle.
         */
        for (nsid = spdk_nvme_ctrlr_get_first_active_ns(ctrlr); nsid != 0;
             nsid = spdk_nvme_ctrlr_get_next_active_ns(ctrlr, nsid))
        {
                ns = spdk_nvme_ctrlr_get_ns(ctrlr, nsid);
                if (!ns)
                {
                        continue;
                }
                printf("  Namespace ID: %d size: %juGB\n",
                       spdk_nvme_ns_get_id(ns),
                       spdk_nvme_ns_get_size(ns) / 1000000000);
                selected_ns = ns;
                break;
        }
}

static void cleanup(void)
{
        struct spdk_nvme_detach_ctx *detach_ctx = NULL;

        spdk_nvme_detach_async(selected_ctrlr, &detach_ctx);
        if (detach_ctx)
        {
                spdk_nvme_detach_poll(detach_ctx);
        }
}

int main(int argc, char **argv)
{
        int rc;
        struct spdk_env_opts opts;
        struct spdk_nvme_transport_id trid;

        /* Intialize SPDK's library environment. */
        spdk_env_opts_init(&opts);
        if (spdk_env_init(&opts) < 0)
        {
                fprintf(stderr, "Failed to initialize SPDK env\n");
                return 1;
        }
        printf("Initializing NVMe Controllers\n");

        /*
         * Enumerate VMDs (Intel Volume Management Device) and hook them into
         * the spdk pci subsystem.
         */
        if (spdk_vmd_init())
        {
                fprintf(stderr, "Failed to initialize VMD."
                                " Some NVMe devices can be unavailable.\n");
        }

        /*
         * Enumerate the bus indicated by the transport ID and attach the
         * userspace NVMe driver to each device found if desired.
         */
        spdk_nvme_trid_populate_transport(&trid, SPDK_NVME_TRANSPORT_PCIE);
        rc = spdk_nvme_probe(&trid, NULL, probe_cb, attach_cb, NULL);
        if (rc != 0)
        {
                fprintf(stderr, "Failed to probe nvme device\n");
                rc = 1;
                goto exit;
        }

        if (!selected_ctrlr)
        {
                fprintf(stderr, "Failed to find NVMe controller\n");
                rc = 1;
                goto exit;
        }

        printf("SPDK initialization completes.\n");

        /* DPDK initialization. */
        unsigned nb_ports;
        uint16_t portid;

        // argc -= ret;
        // argv += ret;

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

        /* Start server main loop. */
        main_loop();

        /* clean up the EAL */
        rte_eal_cleanup();
        cleanup();
        spdk_vmd_fini();

exit:
        rte_eal_cleanup();
        cleanup();
        spdk_env_fini();
        return rc;
}
