/*! \file osmo_io.h
 *  io(_uring) abstraction osmo fd compatibility
 */

#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/utils.h>

struct osmo_io_fd;

enum osmo_io_fd_mode {
	/*! use read() / write() calls */
	OSMO_IO_FD_MODE_READ_WRITE,
	/*! use recvfrom() / sendto() calls */
	OSMO_IO_FD_MODE_RECVFROM_SENDTO,
	/*! emulate sctp_recvmsg() and sctp_sendmsg() */
	OSMO_IO_FD_MODE_SCTP_RECVMSG_SENDMSG,
};

enum osmo_io_backend {
	OSMO_IO_BACKEND_POLL,
	OSMO_IO_BACKEND_URING,
};

extern const struct value_string osmo_io_backend_names[];
static inline const char *osmo_io_backend_name(enum osmo_io_backend val)
{ return get_value_string(osmo_io_backend_names, val); }

struct osmo_io_ops {
	/*! call-back function when something was read from fd */
	void (*read_cb)(struct osmo_io_fd *iofd, int res, struct msgb *msg);
	/*! call-back function when write has completed on fd */
	void (*write_cb)(struct osmo_io_fd *iofd, int res, struct msgb *msg);

	/*! call-back function emulating sendto */
	void (*sendmsg_cb)(struct osmo_io_fd *iofd, int res, struct msgb *msg);
	/*! call-back function emulating recvfrom */
	void (*recvmsg_cb)(struct osmo_io_fd *iofd, int res, struct msgb *msg, struct osmo_sockaddr *saddr);

	/*! call-back function to segment the data returned by read_cb */
	int (*segmentation_cb)(struct msgb *msg, int data_len);
};

void osmo_io_init(void);

struct osmo_io_fd *osmo_iofd_setup(const void *ctx, int fd, const char *name,
		  enum osmo_io_fd_mode mode, const struct osmo_io_ops *ioops, void *data);
int osmo_iofd_register(struct osmo_io_fd *iofd, int fd);
int osmo_iofd_unregister(struct osmo_io_fd *iofd);
unsigned int osmo_iofd_txqueue_len(struct osmo_io_fd *iofd);
void osmo_iofd_txqueue_clear(struct osmo_io_fd *iofd);
void osmo_iofd_close(struct osmo_io_fd *iofd);
void osmo_iofd_free(struct osmo_io_fd *iofd);
int osmo_iofd_write_msgb(struct osmo_io_fd *iofd, struct msgb *msg);
void osmo_iofd_read_enable(struct osmo_io_fd *iofd);
void osmo_iofd_read_disable(struct osmo_io_fd *iofd);
void osmo_iofd_write_enable(struct osmo_io_fd *iofd);
void osmo_iofd_write_disable(struct osmo_io_fd *iofd);

int osmo_iofd_sendto_msgb(struct osmo_io_fd *iofd, struct msgb *msg, int sendto_flags,
			  const struct osmo_sockaddr *dest);

void osmo_iofd_set_alloc_info(struct osmo_io_fd *iofd, unsigned int size, unsigned int headroom);
void *osmo_iofd_get_data(const struct osmo_io_fd *iofd);
void osmo_iofd_set_data(struct osmo_io_fd *iofd, void *data);

unsigned int osmo_iofd_get_priv_nr(const struct osmo_io_fd *iofd);
void osmo_iofd_set_priv_nr(struct osmo_io_fd *iofd, unsigned int priv_nr);

int osmo_iofd_get_fd(const struct osmo_io_fd *iofd);
const char *osmo_iofd_get_name(const struct osmo_io_fd *iofd);