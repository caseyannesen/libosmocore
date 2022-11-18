/*! \file osmo_io.c
 * New osmocom async I/O API.
 *
 * (C) 2022 by Harald Welte <laforge@osmocom.org>
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

enum osmo_io_fd_mode {
	/*! use read() / write() calls */
	OSMO_IO_FD_MODE_READ_WRITE,
	/*! use recvfrom() / sendto() calls */
	OSMO_IO_FD_MODE_RECVFROM_SENDTO,
	/*! emulate sctp_recvmsg() and sctp_sendmsg() */
	OSMO_IO_FD_MODE_SCTP_RECVMSG_SENDMSG,
};

struct osmo_io_fd {
	/*! linked list for internal management */
	struct llist_heads list;
	/*! actual operating-system level file decriptor */
	int fd;
	/*! bit-mask or of \ref OSMO_FD_READ, \ref OSMO_FD_WRITE and/or OSMO_FD_EXCEPT */
	unsigned int when;
	enum osmo_io_fd_mode mode;

	/*! human-readable name to associte with fd */
	const char *name;

	/*! call-back function when something was read from fd */
	void (*read_cb)(struct osmo_io_fd *, int res, struct msgb *);
	/*! call-back function when write has completed on fd */
	void (*write_cb)(struct osmo_io_fd *, int res, struct msgb *);
	/*! data pointer passed through to call-back function */
	void *data;
	/*! private number, extending \a data */
	unsigned int priv_nr;

	struct {
		/*! talloc context from which to allocate msgb when reading */
		void *ctx;
		/*! size of msgb to allocte (excluding headroom) */
		unsigned int size;
		/*! headroom to allocate when allocating msgb's */
		unsigned int headroom;
	} msgb_alloc;

	struct {
		/*! maximum length of write queue */
		unsigned int max_length;
		/*! current length of write queue */
		unsigned int current_length;
		/*! actual linked list implementing the transmit queue */
		struct llist_head msg_queue;
	} tx_queue;

	union {
		struct {
			struct osmo_fd ofd;
		} poll;
		struct {
			/* TODO: index into array of registered fd's? */
		} uring;
	} u;
};

/* serialized version of 'struct msghdr' employed by sendmsg/recvmsg */
struct serialized_msghdr {
	struct msghdr hdr;
	struct sockaddr_storage sa;
	struct iovec iov[1];
	int flags;

	struct msgb *msg;
};

static __thread void *g_msghdr_pool; // = talloc_pool(FIXME, struct serialized_msghdr);

/*! convenience wrapper to call msgb_alloc with parameters from osmo_io_fd */
static struct msgb *iofd_msgb_alloc(struct osmo_io_fd *iofd)
{
	uint16_t headroom = iofd->msgb_alloc.headroom;
#if 0
	switch (iofd->mode) {
	case OSMO_IO_FD_MODE_READ_WRITE:
		break;
	case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
		/* reserve additional headroom for storing the socket address */
		OSMO_ASSERT(headroom < 0xffff - sizeof(struct sockaddr_storage));
		/* TODO: we might actually get away by just ensuring headroom >= sizeof(sockaddr_storage) */
		headroom += sizeof(struct sockaddr_storage);
		break;
	case OSMO_IO_FD_MODE_SCTP_RECVMSG_SENDMSG:
		/* FIXME */
		break;
	}
#endif
	OSMO_ASSERT(iofd->msgb_alloc.size < 0xffff - headroom);
	return msgb_alloc_headroom_c(iofd->msgb_alloc.ctx,
				     iofd->msgb_alloc.size + headroom, headroom, iofd->name);
}


/*! Request osmo_io to write a message to given ofd.
 *  If the function returns success (0), it will take ownership of the msgb and
 *  internally call msgb_free() after the write request completes.
 *  \param[in] ofd file descriptor to which we shall write
 *  \param[in] msg message buffer that shall be written to ofd
 *  \returns 0 in case of success; negative in case of error. */
int osmo_io_write_msgb(struct osmo_io_fd *iofd, struct msgb *msg)
{
	if (iofd->tx_queue.current_length >= iofd->tex_queue.max_length) {
		LOGP(DLGLOBAL, "iofd(%s) rx_queue is full. Rejecting msgb\n", iofd->name);
		return -ENOSPC;
	}
	msgb_enqueue_count(&iofd->tx_queue.msgb_queue, msg, &iofd->tx_queue.current_length);
	/* FIXME: trigger write, if not yet pending */

	return 0;
}
/* TODO: variant with timeout using IORING_OP_LINK_TIMEOUT? */

/*! Request osmo_io to read from given ofd; call call-back function with the data that has been read.
 *  \param[in] ofd file descriptor from which we shall read
 *  \returns 0 if the read has successfully been scheduled. Negative in case of errors.*/
int osmo_io_read_msgb(struct osmo_io_fd *iofd)
{
}
/* TODO: variant with timeout using IORING_OP_LINK_TIMEOUT? */


/* Ideas:
 *  - intermediate layer de-segmentation callback for stuff like IPA header, CBSP, ...
 *
 * Problems:
 *  - in case of IPA we need to read 3 bytes header first, i.e. not all available data.... does
 *    it really make sense to do this via io_uring? Probably yes, as we have a lot of it.
 *    We have to reimplement something like ipa_msg_recv_buffered()
 *
 * Parameters:
 * - number of simultaneous read/write in uring for given fd
 *
 */


/*************************************************************************
 * backend using classic osmo_fd / poll
 *************************************************************************/

static int iofd_poll_ofd_cb_read_write(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_io_fd *iofd = ofd->data;
	struct msgb *msg;
	int rc;

	if (what & OSMO_FD_READ) {
		msg = iofd_msgb_alloc(iofd);
		if (msg) {
			rc = read(ofd->fd, msgb_data(msg), msgb_length(msg));
			/* FIXME: handle rc */
			if (rc > 0)
				msgb_put(msg, rc);

			iofd->read_cb(iofd, rc, msg);
		}
	}

	if (what & OSMO_FD_WRITE) {
		msg = msgb_dequeue_count(&iofd->tx_queue.msg_queue, &iofd->tx_queue.current_length);
		if (msg) {
			rc = write(ofd->fd, msgb_data(msg), msgb_length(msg));
			iofd->write_cb(iofd, rc, msg);
			msgb_free(msg);
		} else
			osmo_fd_write_disable(ofd);
	}

	/* TODO: FD_EXCEPT handling? However: Rarely used in existing osmo-* */
}

static int iofd_poll_ofd_cb_recvfrom_sendto(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_io_fd *iofd = ofd->data;
	struct msgb *msg;
	int rc;

	if (what & OSMO_FD_READ) {
		msg = iofd_msgb_alloc(iofd);
		if (msg) {
			struct sockaddr *sa = FIXME;
			socklen_t addrlen = sizeof(struct sockaddr_storage)

			rc = recvfrom(ofd->fd, msgb_data(msg), msgb_length(msg), 0,
				      sa, &addrlen);
			if (rc > 0)
				msgb_put(msg, rc);

			iofd->recvmsg_cb(iofd, rc, sa, addrlen);
		}
	}

	if (what & OSMO_FD_WRITE) {
		msg = msgb_dequeue_count(&iofd->tx_queue.msg_queue, &iofd->tx_queue.current_length);
		if (msg) {
			rc = sendto(ofd->fd, msgb_data(msg), msgb_length(msg), 0,
				    sa, addrlen);
			iofd->write_cb(iofd, rc, msg);
			msgb_free(msg);
		} else
			osmo_fd_write_disable(ofd);
	}

	/* TODO: FD_EXCEPT handling? However: Rarely used in existing osmo-* */
}


/*************************************************************************
 * FIXME: backend using io_uring
 *************************************************************************/

static int iofd_uring_sendmsg(struct osmo_io_fd *iofd, const struct msghdr *msg, int flags)
{
	struct serialized_msghdr *smh;

	/* check that caller doesn't use features we don't support */
	if (msg->msg_namelen > sizeof(smh->sa))
		return -EINVAL;
	if (msg->msg_iovlen > ARRAY_SIZE(smh->iov))
		return -EINVAL;
	if (msg->msg_control && msg->msg_controllen)
		return -EINVAL;

	smh = talloc_size(g_msghdr_pool, struct serialized_msghdr);
	if (smh)
		return -ENOMEM;

	memcpy(&smh->hdr, msg, sizeof(smh->hdr));
	smh->flags = flags;

	/* name (socket address), if any */
	if (msg->msg_name && msg->msg_namelen) {
		smh->hdr.msg_namelen = msg->msg_namelen;
		memcpy(&smh->sa, msg->msg_name, smh->sa_len);
		smh->hdr.msg_name = smh->sa;
	} else {
		smh->hdr.msg_name = NULL;
		smh->hdr.msg_namelen = 0;
	}

	if (msg->msg_iov && msg->msg_iovlen) {
		smh->hdr.msg_iovlen = msg->msg_iovlen;
		memcpy(&smh->iov, msg->iov, sizeof(struct iovec)*smh->hdr.msg_iovlen);
		smh->hdr.msg_iov = smh->iov;
	} else {
		smh->hdr.msg_iovlen = 0;
		smh->hdr.msg_iov = NULL;
	}

	smh->hdr.msg_control = NULL;
	smh->hdr.msg_controllen = 0;

	smh->msgb = msgb;

}


