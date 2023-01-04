/*! \file osmo_io_uring.c
 * io_uring backend for osmo_io.
 *
 * (C) 2022-2023 by sysmocom s.f.m.c.
 * Author: Daniel Willmann <daniel@sysmocom.de>
 *
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

/* TODO:
 * Parameters:
 * - number of simultaneous read/write in uring for given fd
 *
 */

#include <stdio.h>
#include <talloc.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include <sys/eventfd.h>
#include <liburing.h>

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>

#include "../config.h"
#include "osmo_io_internal.h"

#define IOFD_URING_ENTRIES 4096

struct osmo_io_uring {
	struct osmo_fd event_ofd;
	struct io_uring ring;
};

static __thread struct osmo_io_uring g_ring;

int iofd_uring_poll_cb(struct osmo_fd *ofd, unsigned int what);

/*! initialize the uring */
void osmo_iofd_uring_init(void)
{
	int rc;
	rc = io_uring_queue_init(IOFD_URING_ENTRIES, &g_ring.ring, 0);
	if (rc < 0)
		OSMO_ASSERT(0);

	rc = eventfd(0, 0);
	if (rc < 0) {
		io_uring_queue_exit(&g_ring.ring);
		OSMO_ASSERT(0);
	}

	/* FIXME: This can't be done in _init because it depends on the osmo_fd constructor being run and order is unspecified */
	osmo_fd_setup(&g_ring.event_ofd, rc, OSMO_FD_READ, iofd_uring_poll_cb, &g_ring.ring, 1);
	osmo_fd_register(&g_ring.event_ofd);
		io_uring_register_eventfd(&g_ring.ring, rc);
}

static int iofd_uring_cqe(struct io_uring *ring);
int iofd_uring_poll_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct io_uring *ring = ofd->data;
	eventfd_t val;
	int rc;

	if (what & OSMO_FD_READ) {
		rc = eventfd_read(ofd->fd, &val);
		// TODO: Logging
		if (rc < 0)
			return rc;

		iofd_uring_cqe(ring);
	}
	if (what & OSMO_FD_WRITE) {
		OSMO_ASSERT(0);
	}

	return 0;
}

static void iofd_uring_submit_read(struct osmo_io_fd *iofd)
{
	struct msgb *msg;
	struct iofd_msghdr *msghdr;
	struct io_uring_sqe *sqe = io_uring_get_sqe(&g_ring.ring);
	if (!sqe)
		// FIXME
		OSMO_ASSERT(0);

	// TODO: This only works if we have one read per fd
	msg = iofd_msgb_pending_or_alloc(iofd);
	if (!msg) {
		// FIXME: complain
		return;
	}

	msghdr = iofd_msghdr_alloc(iofd, IOFD_ACT_READ, msg);
	if (!msghdr)
		return;

	msghdr->iov[0].iov_base = msgb_data(msg);
	msghdr->iov[0].iov_len = msgb_tailroom(msg);

	// Prep msgb/iov
	io_uring_prep_readv(sqe, iofd->fd, msghdr->iov, 1, 0);
	io_uring_sqe_set_data(sqe, msghdr);

	io_uring_submit(&g_ring.ring);
	iofd->u.uring.read_pending = true;
}

static void iofd_uring_submit_recvfrom(struct osmo_io_fd *iofd)
{
	struct msgb *msg;
	struct iofd_msghdr *msghdr;
	struct io_uring_sqe *sqe = io_uring_get_sqe(&g_ring.ring);
	if (!sqe)
		// FIXME
		OSMO_ASSERT(0);

	msg = iofd_msgb_pending_or_alloc(iofd);
	if (!msg) {
		// FIXME: complain
		return;
	}

	msghdr = iofd_msghdr_alloc(iofd, IOFD_ACT_RECVFROM, msg);
	if (!msghdr)
		return;

	msghdr->iov[0].iov_base = msgb_data(msg);
	msghdr->iov[0].iov_len = msgb_tailroom(msg);

	msghdr->hdr.msg_iov = &msghdr->iov[0];
	msghdr->hdr.msg_iovlen = 1;
	msghdr->hdr.msg_name = &msghdr->osa.u.sa;
	msghdr->hdr.msg_namelen = osmo_sockaddr_size(&msghdr->osa);

	// Prep msgb/iov
	io_uring_prep_recvmsg(sqe, iofd->fd, &msghdr->hdr, msghdr->flags);
	io_uring_sqe_set_data(sqe, msghdr);

	io_uring_submit(&g_ring.ring);
	iofd->u.uring.read_pending = true;
}

void iofd_uring_read_enable(struct osmo_io_fd *iofd)
{
	iofd->u.uring.read_enabled = true;

	if (iofd->u.uring.read_pending)
		return;

	switch (iofd->mode) {
	case OSMO_IO_FD_MODE_READ_WRITE:
		iofd_uring_submit_read(iofd);
		break;
	case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
		iofd_uring_submit_recvfrom(iofd);
		break;
	default:
		OSMO_ASSERT(0);
	}

}

static void iofd_uring_handle_read(struct iofd_msghdr *msghdr, int rc)
{
	struct osmo_io_fd * iofd = msghdr->iofd;
	struct msgb *msg = msghdr->msg;

	if (rc > 0)
		msgb_put(msg, rc);

	if (!iofd->closed)
		iofd_handle_segmented_read(iofd, msg, rc);

	iofd_msghdr_free(msghdr);
	if (iofd->u.uring.read_enabled && !iofd->closed) {
		iofd_uring_submit_read(iofd);
	} else {
		iofd->u.uring.read_pending = false;
	}
}

static void iofd_uring_handle_recvfrom(struct iofd_msghdr *msghdr, int rc)
{
	struct osmo_io_fd * iofd = msghdr->iofd;
	struct msgb *msg = msghdr->msg;

	if (rc > 0)
		msgb_put(msg, rc);

	if (!iofd->closed)
		// FIXME: Include flags
		iofd->io_ops.recvmsg_cb(iofd, rc, msghdr->msg, &msghdr->osa);

	iofd_msghdr_free(msghdr);

	if (iofd->u.uring.read_enabled && !iofd->closed) {
		iofd_uring_submit_recvfrom(iofd);
	} else {
		iofd->u.uring.read_pending = false;
	}
}

static int iofd_uring_submit_tx(struct osmo_io_fd *iofd);

static void iofd_uring_handle_tx(struct iofd_msghdr *msghdr, int rc)
{
	struct osmo_io_fd *iofd = msghdr->iofd;
	void (*tx_cb)(struct osmo_io_fd*, int rc, struct msgb*) = 0;

	if (msghdr->action == IOFD_ACT_WRITE)
		tx_cb = iofd->io_ops.write_cb;
	else if (msghdr->action == IOFD_ACT_SENDTO)
		tx_cb = iofd->io_ops.sendmsg_cb;
	OSMO_ASSERT(tx_cb);

	if (iofd->closed)
		goto out_free;

	if (rc < 0) {
		tx_cb(iofd, rc, msghdr->msg);
		goto out_free;
	}

	if (rc < msgb_length(msghdr->msg)) {
		iofd_txqueue_enqueue_front(iofd, msghdr);
		goto out;
	}

	tx_cb(iofd, rc, msghdr->msg);

out_free:
	msgb_free(msghdr->msg);
	iofd_msghdr_free(msghdr);

out:
	iofd->u.uring.write_pending = false;
	if (iofd->u.uring.write_enabled && !iofd->closed) {
		iofd_uring_submit_tx(iofd);
	}
}

static void iofd_uring_handle_completion(struct iofd_msghdr *msghdr, int res)
{
	struct osmo_io_fd *iofd = msghdr->iofd;

	switch (msghdr->action) {
	case IOFD_ACT_READ:
		iofd_uring_handle_read(msghdr, res);
		break;
	case IOFD_ACT_RECVFROM:
		iofd_uring_handle_recvfrom(msghdr, res);
		break;
	case IOFD_ACT_WRITE:
		/* Fallthrough */
	case IOFD_ACT_SENDTO:
		iofd_uring_handle_tx(msghdr, res);
		break;
	default:
		OSMO_ASSERT(0)
	}

	if (iofd->closed && !iofd->u.uring.read_pending && ! iofd->u.uring.write_pending)
		talloc_free(iofd);
}

static int iofd_uring_cqe(struct io_uring *ring)
{
	int rc;
	struct io_uring_cqe *cqe;
	struct iofd_msghdr *msghdr;

	do {
		/* Maybe use peek_batch? */
		rc = io_uring_peek_cqe(ring, &cqe);
		if (rc < 0)
			break;

		msghdr = io_uring_cqe_get_data(cqe);
		OSMO_ASSERT(msghdr);

		iofd_uring_handle_completion(msghdr, cqe->res);
		// FIXME: Call seen inside the handlers?
		/* Hand the entry back to the kernel */
		io_uring_cqe_seen(ring, cqe);
	} while (rc == 0);

	return 0;
}

static int iofd_uring_submit_write(struct osmo_io_fd *iofd, struct iofd_msghdr *msghdr)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&g_ring.ring);
	if (!sqe)
		// FIXME
		OSMO_ASSERT(0);

	msghdr->iov[0].iov_base = msgb_data(msghdr->msg);
	msghdr->iov[0].iov_len = msgb_length(msghdr->msg);
	msghdr->hdr.msg_iov = &msghdr->iov[0];
	msghdr->hdr.msg_iovlen = 1;

	// Prep msgb/iov
	io_uring_prep_writev(sqe, msghdr->iofd->fd, msghdr->iov, 1, 0);
	io_uring_sqe_set_data(sqe, msghdr);

	io_uring_submit(&g_ring.ring);

	return 0;
}

static int iofd_uring_submit_sendto(struct osmo_io_fd *iofd, struct iofd_msghdr *msghdr)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&g_ring.ring);
	if (!sqe)
		// FIXME
		OSMO_ASSERT(0);

	msghdr->iov[0].iov_base = msgb_data(msghdr->msg);
	msghdr->iov[0].iov_len = msgb_length(msghdr->msg);
	msghdr->hdr.msg_iov = &msghdr->iov[0];
	msghdr->hdr.msg_iovlen = 1;
	msghdr->hdr.msg_name = &msghdr->osa.u.sa;
	msghdr->hdr.msg_namelen = osmo_sockaddr_size(&msghdr->osa);

	// Prep msgb/iov
	io_uring_prep_sendmsg(sqe, msghdr->iofd->fd, &msghdr->hdr, msghdr->flags);
	io_uring_sqe_set_data(sqe, msghdr);

	io_uring_submit(&g_ring.ring);

	return 0;
}

static int iofd_uring_submit_tx(struct osmo_io_fd *iofd)
{
	int rc;
	struct iofd_msghdr *msghdr;

	msghdr = iofd_txqueue_dequeue(iofd);
	if (!msghdr)
		return -ENODATA;

	switch (msghdr->action) {
	case IOFD_ACT_WRITE:
		rc = iofd_uring_submit_write(iofd, msghdr);
		break;
	case IOFD_ACT_SENDTO:
		rc = iofd_uring_submit_sendto(iofd, msghdr);
		break;
	default:
		OSMO_ASSERT(0);
	}
	if (rc == 0)
		iofd->u.uring.write_pending = true;

	return rc;
}

void iofd_uring_write_enable(struct osmo_io_fd *iofd)
{
	iofd->u.uring.write_enabled = true;

	if (iofd->u.uring.write_pending)
		return;

	iofd_uring_submit_tx(iofd);
}

void iofd_uring_write_disable(struct osmo_io_fd *iofd)
{
	iofd->u.uring.write_enabled = false;
}

void iofd_uring_read_disable(struct osmo_io_fd *iofd)
{
	iofd->u.uring.read_enabled = false;
}

int iofd_uring_close(struct osmo_io_fd *iofd)
{
		if (iofd->u.uring.read_pending || iofd->u.uring.write_pending)
			return 0;

		close(iofd->fd);
		return 1;
}

struct iofd_backend_ops iofd_uring_ops = {
	.close = iofd_uring_close,
	.write_enable = iofd_uring_write_enable,
	.write_disable = iofd_uring_write_disable,
	.read_enable = iofd_uring_read_enable,
	.read_disable = iofd_uring_read_disable,
};
