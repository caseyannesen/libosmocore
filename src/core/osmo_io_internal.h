/*! \file osmo_io_internal.h */

#pragma once

#include <unistd.h>
#include <stdbool.h>

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>

#include "../config.h"

#define OSMO_IO_DEFAULT_MSGB_SIZE 1024
#define OSMO_IO_DEFAULT_MSGB_HEADROOM 128

extern struct iofd_backend_ops iofd_poll_ops;
#define OSMO_IO_BACKEND_DEFAULT "POLL"

#if defined(HAVE_URING)
extern struct iofd_backend_ops iofd_uring_ops;
#endif

struct iofd_backend_ops {
	int (*register_fd)(struct osmo_io_fd *iofd);
	int (*unregister_fd)(struct osmo_io_fd *iofd);
	void (*close)(struct osmo_io_fd *iofd);
	void (*write_enable)(struct osmo_io_fd *iofd);
	void (*write_disable)(struct osmo_io_fd *iofd);
	void (*read_enable)(struct osmo_io_fd *iofd);
	void (*read_disable)(struct osmo_io_fd *iofd);
};

struct osmo_io_fd {
	/*! linked list for internal management */
	struct llist_head list;
	/*! actual operating-system level file decriptor */
	int fd;
	/*! type of read/write mode to use */
	enum osmo_io_fd_mode mode;

	/*! flags to guard closing/freeing of iofd */
	bool closed;
	bool in_callback;
	bool to_free;

	bool write_enabled;
	bool read_enabled;

	/*! human-readable name to associte with fd */
	const char *name;

	/*! send/recv (msg) callback functions */
	struct osmo_io_ops io_ops;
	/*! Pending msgb to keep partial data during segmentation */
	struct msgb *pending;

	/*! data pointer passed through to call-back function */
	void *data;
	/*! private number, extending \a data */
	unsigned int priv_nr;

	struct {
		/*! talloc context from which to allocate msgb when reading */
		const void *ctx;
		/*! size of msgb to allocate (excluding headroom) */
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
			bool read_enabled;
			bool read_pending;
			bool write_pending;
			bool write_enabled;
			/* TODO: index into array of registered fd's? */
		} uring;
	} u;
};

enum iofd_msg_action {
	IOFD_ACT_READ,
	IOFD_ACT_WRITE,
	IOFD_ACT_RECVFROM,
	IOFD_ACT_SENDTO,
	// TODO: SCTP_*
};


/* serialized version of 'struct msghdr' employed by sendmsg/recvmsg */
struct iofd_msghdr {
	struct llist_head list;
	enum iofd_msg_action action;
	struct msghdr hdr;
	struct osmo_sockaddr osa;
	struct iovec iov[1];
	int flags;

	struct msgb *msg;
	struct osmo_io_fd *iofd;
};

enum iofd_seg_act {
	IOFD_SEG_ACT_HANDLE_ONE,
	IOFD_SEG_ACT_HANDLE_MORE,
	IOFD_SEG_ACT_DEFER,
};

struct iofd_msghdr *iofd_msghdr_alloc(struct osmo_io_fd *iofd, enum iofd_msg_action action, struct msgb *msg);
void iofd_msghdr_free(struct iofd_msghdr *msghdr);

struct msgb *iofd_msgb_alloc(struct osmo_io_fd *iofd);
struct msgb *iofd_msgb_pending(struct osmo_io_fd *iofd);
struct msgb *iofd_msgb_pending_or_alloc(struct osmo_io_fd *iofd);

void iofd_handle_segmented_read(struct osmo_io_fd *iofd, struct msgb *msg, int rc);

int iofd_txqueue_enqueue(struct osmo_io_fd *iofd, struct iofd_msghdr *msghdr);
void iofd_txqueue_enqueue_front(struct osmo_io_fd *iofd, struct iofd_msghdr *msghdr);
struct iofd_msghdr *iofd_txqueue_dequeue(struct osmo_io_fd *iofd);
