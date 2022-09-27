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

#include <spdk/env.h>
#include <spdk/log.h>
#include <spdk/nvme.h>
#include <spdk/stdinc.h>
#include <spdk/string.h>
#include <spdk/vmd.h>

static struct spdk_nvme_ctrlr *selected_ctrlr;
static struct spdk_nvme_ns *selected_ns;
static struct spdk_nvme_qpair *qpair;

struct callback_args {
	volatile bool done;
	char *buf;
};

/*
 * The callback function for the read request.
 */
static void read_complete(void *args, const struct spdk_nvme_cpl *completion) {
	struct callback_args *cb_args = args;

        /* Check if there's an error for the read request. */
        if (spdk_nvme_cpl_is_error(completion)) {
                spdk_nvme_qpair_print_completion(
                    qpair, (struct spdk_nvme_cpl *)completion);
                fprintf(stderr, "I/O error status: %s\n",
                        spdk_nvme_cpl_get_status_string(&completion->status));
                fprintf(stderr, "Failed to read, aborting run\n");
                exit(1);
        }

        /* Unblock the while loop in main_loop(). */
        cb_args->done = true;
        /*
         * Print out the string data of the first sector. Expect to see
         * "Hello world!\n".
         */
        printf("%s", cb_args->buf);
}

/*
 * The callback function for the write request.
 */
static void write_complete(void *args, const struct spdk_nvme_cpl *completion) {
        int rc;
        struct callback_args *cb_args = args;

        /* Check if there's an error for the write request. */
        if (spdk_nvme_cpl_is_error(completion)) {
                spdk_nvme_qpair_print_completion(
                    qpair, (struct spdk_nvme_cpl *)completion);
                fprintf(stderr, "I/O error status: %s\n",
                        spdk_nvme_cpl_get_status_string(&completion->status));
                fprintf(stderr, "Failed to write, aborting run\n");
                exit(1);
        }

        /* Now submit a cmd to read data from the 1st sector. */
        rc = spdk_nvme_ns_cmd_read(
            selected_ns, qpair,
            cb_args->buf,  /* The buffer to store the read data */
            0,             /* Starting LBA to read the data */
            1,             /* Length in sectors */
            read_complete, /* Callback to invoke when the read is done. */
            cb_args,       /* Argument to pass to the callback. */
	    0);
        if (rc != 0) {
                fprintf(stderr, "Failed to submit read cmd\n");
                exit(1);
        }
}

/*
 * The main application logic.
 */
static void main_loop(void) {
        int rc;
        int sector_sz;
	struct callback_args cb_args;

        /* Setup the SPDK queue pair (submission queue and completion queue). */
        qpair = spdk_nvme_ctrlr_alloc_io_qpair(selected_ctrlr, NULL, 0);
        if (!qpair) {
                fprintf(stderr, "Failed to create SPDK queue pair\n");
                return;
        }

        /* Get the sector size. */
        sector_sz = spdk_nvme_ns_get_sector_size(selected_ns);
        /* Allocate a DMA-safe host memory buffer. */
        cb_args.buf = spdk_zmalloc(sector_sz, sector_sz, NULL,
                                   SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
        if (!cb_args.buf) {
                fprintf(stderr, "Failed to allocate buffer\n");
                return;
        }
        cb_args.done = false;

        /* Write the string into the buffer.  */
        snprintf(cb_args.buf, sector_sz, "%s", "Hello world!\n");

        /* Submit a cmd to write data into the 1st sector. */
        rc = spdk_nvme_ns_cmd_write(
            selected_ns, qpair,
	    cb_args.buf,    /* The data to write */
            0,              /* Starting LBA to write the data */
            1,              /* Length in sectors */
            write_complete, /* Callback to invoke when the write is done. */
            &cb_args,       /* Argument to pass to the callback. */
            0);
        if (rc != 0) {
                fprintf(stderr, "Failed to submit write cmd\n");
                exit(1);
        }

        /* Poll for completions. */
        while (!cb_args.done) {
                /* Try to drain the completion queue and trigger callbacks. */
                spdk_nvme_qpair_process_completions(qpair, 0);
        }

        spdk_free(cb_args.buf);
        spdk_nvme_ctrlr_free_io_qpair(qpair);
}

/*
 * Will be called once per NVMe device found in the system.
 */
static bool probe_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid,
                     struct spdk_nvme_ctrlr_opts *opts) {
        if (!selected_ctrlr) {
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
                      const struct spdk_nvme_ctrlr_opts *opts) {
        int nsid;
        struct spdk_nvme_ns *ns;

        printf("Attached to %s\n", trid->traddr);
        selected_ctrlr = ctrlr;

        /*
         * Iterate through the active NVMe namespaces to get a handle.
         */
        for (nsid = spdk_nvme_ctrlr_get_first_active_ns(ctrlr); nsid != 0;
             nsid = spdk_nvme_ctrlr_get_next_active_ns(ctrlr, nsid)) {
                ns = spdk_nvme_ctrlr_get_ns(ctrlr, nsid);
                if (!ns) {
                        continue;
                }
                printf("  Namespace ID: %d size: %juGB\n",
                       spdk_nvme_ns_get_id(ns),
                       spdk_nvme_ns_get_size(ns) / 1000000000);
                selected_ns = ns;
		break;
        }
}

static void cleanup(void) {
        struct spdk_nvme_detach_ctx *detach_ctx = NULL;

        spdk_nvme_detach_async(selected_ctrlr, &detach_ctx);
        if (detach_ctx) {
                spdk_nvme_detach_poll(detach_ctx);
        }
}

int main(int argc, char **argv) {
        int rc;
        struct spdk_env_opts opts;
        struct spdk_nvme_transport_id trid;

        /* Intialize SPDK's library environment. */
        spdk_env_opts_init(&opts);
        if (spdk_env_init(&opts) < 0) {
                fprintf(stderr, "Failed to initialize SPDK env\n");
                return 1;
        }
        printf("Initializing NVMe Controllers\n");

        /*
         * Enumerate VMDs (Intel Volume Management Device) and hook them into
         * the spdk pci subsystem.
         */
        if (spdk_vmd_init()) {
                fprintf(stderr, "Failed to initialize VMD."
                                " Some NVMe devices can be unavailable.\n");
        }

        /*
         * Enumerate the bus indicated by the transport ID and attach the
         * userspace NVMe driver to each device found if desired.
         */
        spdk_nvme_trid_populate_transport(&trid, SPDK_NVME_TRANSPORT_PCIE);
        rc = spdk_nvme_probe(&trid, NULL, probe_cb, attach_cb, NULL);
        if (rc != 0) {
                fprintf(stderr, "Failed to probe nvme device\n");
                rc = 1;
                goto exit;
        }

        if (!selected_ctrlr) {
                fprintf(stderr, "Failed to find NVMe controller\n");
                rc = 1;
                goto exit;
        }

        printf("SPDK initialization completes.\n");
        main_loop();
        cleanup();
        spdk_vmd_fini();

exit:
        cleanup();
        spdk_env_fini();
        return rc;
}
