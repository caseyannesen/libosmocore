/*! \file io_uring.c
 * io_uring async I/O support.
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

#include <sys/eventfd.h>
#include <liburing.h>

/* we keep the io_uring per thread, like we have per-thread select/poll */
static __thread struct io_uring t_ring;
static __thread struct osmo_fd t_eventfd;



{
	int rc;

	rc = io_uring_queue_init(URING_QUEUE_ENTRIES, &t_ring, NULL);
	if (rc)
		return -1;

	rc = eventfd(0, 0);
	if (rc < 0)
		goto err_iou_init;

	osmo_fd_setup(&t_eventfd, rc, OSMO_FD_READ, iou_eventfd_cb, NULL, 0);

	rc = io_uring_register_eventfd(&t_ring, t_eventfd.fd);
	if (rc < 0)
		goto err_fd_setup;

	rc = osmo_fd_register(&t_eventfd);
	if (rc < 0)
		goto err_unreg_eventfd;

	return 0;

err_unreg_eventfd:
	io_uring_unregister_eventfd(&t_ring);
err_fdsetup:
	close(t_eventfd.fd);
	osmo_fd_setup(&t_eventfd, -1, 0, NULL, NULL, 0);
err_iou_init:
	io_uring_queue_exit(&t_ring);

	return -1;
}
