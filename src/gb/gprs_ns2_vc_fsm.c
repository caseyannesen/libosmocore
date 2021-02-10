/*! \file gprs_ns2_vc_fsm.c
 * NS virtual circuit FSM implementation
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 * as well as its successor 3GPP TS 48.016 */

/* (C) 2020 sysmocom - s.f.m.c. GmbH
 * Author: Alexander Couzens <lynxis@fe80.eu>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* The BSS NSE only has one SGSN IP address configured, and it will use the SNS procedures
 * to communicated its local IPs/ports as well as all the SGSN side IPs/ports and
 * associated weights.  In theory, the BSS then uses this to establish a full mesh
 * of NSVCs between all BSS-side IPs/ports and SGSN-side IPs/ports */

#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/gsm/prim.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gprs/protocol/gsm_08_16.h>

#include "gprs_ns2_internal.h"
#include "osmocom/core/logging.h"

#define S(x)	(1 << (x))

#define DNS 10

struct gprs_ns2_vc_priv {
	struct gprs_ns2_vc *nsvc;
	/* how often the timer was triggered */
	int N;
	/* The initiator is responsible to UNBLOCK the VC. The BSS is usually the initiator.
	 * It can change during runtime. The side which blocks an unblocked side.*/
	bool initiator;
	bool initiate_block;
	bool initiate_reset;
	/* if blocked by O&M/vty */
	bool om_blocked;
	/* if unitdata is forwarded to the user */
	bool accept_unitdata;

	/* the alive counter is present in all states */
	struct {
		struct osmo_timer_list timer;
		enum ns2_timeout mode;
		int N;
		struct timeval timer_started;
	} alive;
};


/* The FSM covers both the VC with RESET/BLOCK and without RESET/BLOCK procedure..
 *
 * With RESET/BLOCK, the state should follow:
 * - UNCONFIGURED -> RESET -> BLOCK -> UNBLOCKED
 *
 * Without RESET/BLOCK, the state should follow:
 * - UNCONFIGURED -> RECOVERY -> UNBLOCKED
 *
 * The UNBLOCKED and TEST states are used to send ALIVE PDU using the timeout Tns-test and Tns-alive.
 * UNBLOCKED -> TEST: on expire of Tns-Test, send Alive PDU.
 * TEST -> UNBLOCKED: on receive of Alive_Ack PDU, go into UNBLOCKED.
 *
 * The RECOVERY state is used as intermediate, because a VC is only valid if it received an Alive ACK when
 * not using RESET/BLOCK procedure.
 */

enum gprs_ns2_vc_state {
	GPRS_NS2_ST_UNCONFIGURED,
	GPRS_NS2_ST_RESET,
	GPRS_NS2_ST_BLOCKED,
	GPRS_NS2_ST_UNBLOCKED, /* allows sending NS_UNITDATA */

	GPRS_NS2_ST_RECOVERING, /* only used when not using RESET/BLOCK procedure */
};

enum gprs_ns2_vc_event {
	GPRS_NS2_EV_REQ_START,

	/* received messages */
	GPRS_NS2_EV_RX_RESET,
	GPRS_NS2_EV_RX_RESET_ACK,
	GPRS_NS2_EV_RX_UNBLOCK,
	GPRS_NS2_EV_RX_UNBLOCK_ACK,
	GPRS_NS2_EV_RX_BLOCK,
	GPRS_NS2_EV_RX_BLOCK_ACK,
	GPRS_NS2_EV_RX_ALIVE,
	GPRS_NS2_EV_RX_ALIVE_ACK,
	GPRS_NS2_EV_RX_STATUS,

	GPRS_NS2_EV_RX_UNITDATA,

	GPRS_NS2_EV_REQ_FORCE_UNCONFIGURED,	/* called via vty for tests */
	GPRS_NS2_EV_REQ_OM_BLOCK,		/* vty cmd: block */
	GPRS_NS2_EV_REQ_OM_UNBLOCK,		/* vty cmd: unblock*/
};

static const struct value_string ns2_vc_event_names[] = {
	{ GPRS_NS2_EV_REQ_START, 		"REQ-START" },
	{ GPRS_NS2_EV_RX_RESET,			"RX-RESET" },
	{ GPRS_NS2_EV_RX_RESET_ACK,		"RX-RESET_ACK" },
	{ GPRS_NS2_EV_RX_UNBLOCK,		"RX-UNBLOCK" },
	{ GPRS_NS2_EV_RX_UNBLOCK_ACK,		"RX-UNBLOCK_ACK" },
	{ GPRS_NS2_EV_RX_BLOCK,			"RX-BLOCK" },
	{ GPRS_NS2_EV_RX_BLOCK_ACK,		"RX-BLOCK_ACK" },
	{ GPRS_NS2_EV_RX_ALIVE,			"RX-ALIVE" },
	{ GPRS_NS2_EV_RX_ALIVE_ACK,		"RX-ALIVE_ACK" },
	{ GPRS_NS2_EV_RX_STATUS,		"RX-STATUS" },
	{ GPRS_NS2_EV_RX_UNITDATA,		"RX-UNITDATA" },
	{ GPRS_NS2_EV_REQ_FORCE_UNCONFIGURED,	"REQ-FORCE_UNCONFIGURED" },
	{ GPRS_NS2_EV_REQ_OM_BLOCK,		"REQ-O&M-BLOCK"},
	{ GPRS_NS2_EV_REQ_OM_UNBLOCK,		"REQ-O&M-UNBLOCK"},
	{ 0, NULL }
};

static inline struct gprs_ns2_inst *ns_inst_from_fi(struct osmo_fsm_inst *fi)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;
	return priv->nsvc->nse->nsi;
}

static void start_test_procedure(struct gprs_ns2_vc_priv *priv)
{
	struct gprs_ns2_inst *nsi = priv->nsvc->nse->nsi;

	if (osmo_timer_pending(&priv->alive.timer))
		return;

	priv->alive.mode = NS_TOUT_TNS_ALIVE;
	priv->alive.N = 0;

	osmo_gettimeofday(&priv->alive.timer_started, NULL);
	ns2_tx_alive(priv->nsvc);
	osmo_timer_schedule(&priv->alive.timer, nsi->timeout[NS_TOUT_TNS_ALIVE], 0);
}

static void stop_test_procedure(struct gprs_ns2_vc_priv *priv)
{
	osmo_timer_del(&priv->alive.timer);
}

static int alive_timer_elapsed_ms(struct gprs_ns2_vc_priv *priv)
{
	struct timeval now, elapsed;
	osmo_gettimeofday(&now, NULL);
	timersub(&now, &priv->alive.timer_started, &elapsed);

	return 1000 * elapsed.tv_sec + elapsed.tv_usec / 1000;
}

static void recv_test_procedure(struct osmo_fsm_inst *fi)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;
	struct gprs_ns2_inst *nsi = ns_inst_from_fi(fi);
	struct gprs_ns2_vc *nsvc = priv->nsvc;

	/* ignoring ACKs without sending an ALIVE */
	if (priv->alive.mode != NS_TOUT_TNS_ALIVE)
		return;

	priv->alive.mode = NS_TOUT_TNS_TEST;
	osmo_timer_schedule(&priv->alive.timer, nsi->timeout[NS_TOUT_TNS_TEST], 0);
	osmo_stat_item_set(nsvc->statg->items[NS_STAT_ALIVE_DELAY],
		alive_timer_elapsed_ms(priv));
}


static void alive_timeout_handler(void *data)
{
	struct osmo_fsm_inst *fi = data;
	struct gprs_ns2_inst *nsi = ns_inst_from_fi(fi);
	struct gprs_ns2_vc_priv *priv = fi->priv;

	switch (priv->alive.mode) {
	case NS_TOUT_TNS_TEST:
		priv->alive.mode = NS_TOUT_TNS_ALIVE;
		priv->alive.N = 0;
		ns2_tx_alive(priv->nsvc);
		osmo_timer_schedule(&priv->alive.timer, nsi->timeout[NS_TOUT_TNS_ALIVE], 0);
		break;
	case NS_TOUT_TNS_ALIVE:
		rate_ctr_inc(&priv->nsvc->ctrg->ctr[NS_CTR_LOST_ALIVE]);
		priv->alive.N++;

		if (priv->alive.N <= nsi->timeout[NS_TOUT_TNS_ALIVE_RETRIES]) {
			/* retransmission */
			ns2_tx_alive(priv->nsvc);
			osmo_timer_schedule(&priv->alive.timer, nsi->timeout[NS_TOUT_TNS_ALIVE], 0);
		} else {
			/* lost connection */
			if (priv->nsvc->mode == GPRS_NS2_VC_MODE_BLOCKRESET) {
				osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_RESET, nsi->timeout[NS_TOUT_TNS_RESET], 0);
			} else {
				osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_RECOVERING, nsi->timeout[NS_TOUT_TNS_ALIVE], 0);
			}
		}
		break;
	default:
		break;
	}
}


static void ns2_st_unconfigured_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	stop_test_procedure(fi->priv);
}

static void ns2_st_unconfigured(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;
	struct gprs_ns2_inst *nsi = priv->nsvc->nse->nsi;

	priv->initiate_reset = priv->initiate_block = priv->initiator;
	priv->om_blocked = false;

	switch (event) {
	case GPRS_NS2_EV_REQ_START:
		switch (priv->nsvc->mode) {
		case GPRS_NS2_VC_MODE_ALIVE:
			osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_RECOVERING, nsi->timeout[NS_TOUT_TNS_ALIVE], NS_TOUT_TNS_ALIVE);
			break;
		case GPRS_NS2_VC_MODE_BLOCKRESET:
			osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_RESET, nsi->timeout[NS_TOUT_TNS_RESET], NS_TOUT_TNS_RESET);
			break;
		}

		break;
	default:
		OSMO_ASSERT(0);
	}
}


static void ns2_st_reset_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;

	if (old_state != GPRS_NS2_ST_RESET)
		priv->N = 0;

	priv->accept_unitdata = false;
	if (priv->initiate_reset)
		ns2_tx_reset(priv->nsvc, NS_CAUSE_OM_INTERVENTION);

	stop_test_procedure(priv);
	ns2_nse_notify_unblocked(priv->nsvc, false);
}

static void ns2_st_reset(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_ns2_inst *nsi = ns_inst_from_fi(fi);
	struct gprs_ns2_vc_priv *priv = fi->priv;

	if (priv->initiate_reset) {
		switch (event) {
		case GPRS_NS2_EV_RX_RESET:
			ns2_tx_reset_ack(priv->nsvc);
			/* fall-through */
		case GPRS_NS2_EV_RX_RESET_ACK:
			osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_BLOCKED,
						nsi->timeout[NS_TOUT_TNS_BLOCK], NS_TOUT_TNS_BLOCK);
			break;
		}
	} else {
		/* we are on the receiving end */
		switch (event) {
		case GPRS_NS2_EV_RX_RESET:
			ns2_tx_reset_ack(priv->nsvc);
			osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_BLOCKED,
						0, 0);
			break;
		}
	}
}

static void ns2_st_blocked_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;

	if (old_state != GPRS_NS2_ST_BLOCKED) {
		priv->N = 0;
		rate_ctr_inc(&priv->nsvc->ctrg->ctr[NS_CTR_BLOCKED]);
	}

	if (priv->om_blocked) {
		/* we are already blocked after a RESET */
		if (old_state == GPRS_NS2_ST_RESET) {
			osmo_timer_del(&fi->timer);
		} else {
			ns2_tx_block(priv->nsvc, NS_CAUSE_OM_INTERVENTION);
		}
	} else if (priv->initiate_block) {
		ns2_tx_unblock(priv->nsvc);
	}

	start_test_procedure(priv);
}

static void ns2_st_blocked(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;

	if (priv->om_blocked) {
		switch (event) {
		case GPRS_NS2_EV_RX_BLOCK_ACK:
			priv->accept_unitdata = false;
			osmo_timer_del(&fi->timer);
			break;
		case GPRS_NS2_EV_RX_BLOCK:
			priv->accept_unitdata = false;
			ns2_tx_block_ack(priv->nsvc);
			osmo_timer_del(&fi->timer);
			break;
		case GPRS_NS2_EV_RX_UNBLOCK:
			priv->accept_unitdata = false;
			ns2_tx_block(priv->nsvc, NS_CAUSE_OM_INTERVENTION);
			osmo_timer_add(&fi->timer);
			break;
		}
	} else if (priv->initiate_block) {
		switch (event) {
		case GPRS_NS2_EV_RX_BLOCK:
			/* TODO: BLOCK is a UNBLOCK_NACK */
			ns2_tx_block_ack(priv->nsvc);
			break;
		case GPRS_NS2_EV_RX_UNBLOCK:
			ns2_tx_unblock_ack(priv->nsvc);
			/* fall through */
		case GPRS_NS2_EV_RX_UNBLOCK_ACK:
			priv->accept_unitdata = true;
			osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_UNBLOCKED,
						0, NS_TOUT_TNS_TEST);
			break;
		}
	} else {
		/* we are on the receiving end. The initiator who sent RESET is responsible to UNBLOCK! */
		switch (event) {
		case GPRS_NS2_EV_RX_BLOCK:
			ns2_tx_block_ack(priv->nsvc);
			break;
		case GPRS_NS2_EV_RX_UNBLOCK:
			ns2_tx_unblock_ack(priv->nsvc);
			osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_UNBLOCKED,
						0, 0);
			break;
		}
	}
}

static void ns2_st_unblocked_on_enter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;
	struct gprs_ns2_vc *nsvc = priv->nsvc;
	struct gprs_ns2_nse *nse = nsvc->nse;

	if (old_state != GPRS_NS2_ST_UNBLOCKED)
		rate_ctr_inc(&nsvc->ctrg->ctr[NS_CTR_UNBLOCKED]);

	priv->accept_unitdata = true;
	ns2_nse_notify_unblocked(nsvc, true);
	ns2_prim_status_ind(nse, nsvc, 0, GPRS_NS2_AFF_CAUSE_VC_RECOVERY);
}

static void ns2_st_unblocked(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;

	switch (event) {
	case GPRS_NS2_EV_RX_UNBLOCK:
		ns2_tx_unblock_ack(priv->nsvc);
		break;
	case GPRS_NS2_EV_RX_BLOCK:
		priv->initiate_block = false;
		ns2_tx_block_ack(priv->nsvc);
		osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_BLOCKED,
					0, 2);
		break;
	}
}

static void ns2_st_alive(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_NS2_EV_RX_ALIVE_ACK:
		osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_UNBLOCKED, 0, 0);
		break;
	}
}

static void ns2_st_alive_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;
	struct gprs_ns2_inst *nsi = ns_inst_from_fi(fi);

	priv->alive.mode = NS_TOUT_TNS_TEST;
	osmo_timer_schedule(&priv->alive.timer, nsi->timeout[NS_TOUT_TNS_TEST], 0);

	if (old_state != GPRS_NS2_ST_RECOVERING)
		priv->N = 0;

	ns2_tx_alive(priv->nsvc);
	ns2_nse_notify_unblocked(priv->nsvc, false);
}

static void ns2_st_alive_onleave(struct osmo_fsm_inst *fi, uint32_t next_state)
{
	start_test_procedure(fi->priv);
}

static const struct osmo_fsm_state ns2_vc_states[] = {
	[GPRS_NS2_ST_UNCONFIGURED] = {
		.in_event_mask = S(GPRS_NS2_EV_REQ_START),
		.out_state_mask = S(GPRS_NS2_ST_RESET) | S(GPRS_NS2_ST_RECOVERING),
		.name = "UNCONFIGURED",
		.action = ns2_st_unconfigured,
		.onenter = ns2_st_unconfigured_onenter,
	},
	[GPRS_NS2_ST_RESET] = {
		.in_event_mask = S(GPRS_NS2_EV_RX_RESET_ACK) | S(GPRS_NS2_EV_RX_RESET),
		.out_state_mask = S(GPRS_NS2_ST_RESET) |
				  S(GPRS_NS2_ST_BLOCKED) |
				  S(GPRS_NS2_ST_UNCONFIGURED),
		.name = "RESET",
		.action = ns2_st_reset,
		.onenter = ns2_st_reset_onenter,
	},
	[GPRS_NS2_ST_BLOCKED] = {
		.in_event_mask = S(GPRS_NS2_EV_RX_BLOCK) | S(GPRS_NS2_EV_RX_BLOCK_ACK) |
		S(GPRS_NS2_EV_RX_UNBLOCK) | S(GPRS_NS2_EV_RX_UNBLOCK_ACK),
		.out_state_mask = S(GPRS_NS2_ST_RESET) |
				  S(GPRS_NS2_ST_UNBLOCKED) |
				  S(GPRS_NS2_ST_BLOCKED) |
				  S(GPRS_NS2_ST_UNCONFIGURED),
		.name = "BLOCKED",
		.action = ns2_st_blocked,
		.onenter = ns2_st_blocked_onenter,
	},
	[GPRS_NS2_ST_UNBLOCKED] = {
		.in_event_mask = S(GPRS_NS2_EV_RX_BLOCK) | S(GPRS_NS2_EV_RX_UNBLOCK_ACK) |
				 S(GPRS_NS2_EV_RX_UNBLOCK),
		.out_state_mask = S(GPRS_NS2_ST_RESET) | S(GPRS_NS2_ST_RECOVERING) |
				  S(GPRS_NS2_ST_BLOCKED) |
				  S(GPRS_NS2_ST_UNCONFIGURED),
		.name = "UNBLOCKED",
		.action = ns2_st_unblocked,
		.onenter = ns2_st_unblocked_on_enter,
	},

	/* ST_RECOVERING is only used on VC without RESET/BLOCK */
	[GPRS_NS2_ST_RECOVERING] = {
		.in_event_mask = S(GPRS_NS2_EV_RX_ALIVE_ACK),
		.out_state_mask = S(GPRS_NS2_ST_RECOVERING) |
				  S(GPRS_NS2_ST_UNBLOCKED) |
				  S(GPRS_NS2_ST_UNCONFIGURED),
		.name = "RECOVERING",
		.action = ns2_st_alive,
		.onenter = ns2_st_alive_onenter,
		.onleave = ns2_st_alive_onleave,
	},
};

static int ns2_vc_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gprs_ns2_inst *nsi = ns_inst_from_fi(fi);
	struct gprs_ns2_vc_priv *priv = fi->priv;

	TRACEPFSMENT(fi, "nsei=%05u", priv->nsvc->nse->nsei);
	switch (fi->state) {
	case GPRS_NS2_ST_RESET:
		if (priv->initiate_reset) {
			rate_ctr_inc(&priv->nsvc->ctrg->ctr[NS_CTR_LOST_RESET]);
			priv->N++;
			if (priv->N <= nsi->timeout[NS_TOUT_TNS_RESET_RETRIES]) {
				osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_RESET, nsi->timeout[NS_TOUT_TNS_RESET], 0);
			} else {
				priv->N = 0;
				osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_RESET, nsi->timeout[NS_TOUT_TNS_RESET], 0);
			}
		}
		break;
	case GPRS_NS2_ST_BLOCKED:
		if (priv->initiate_block) {
			priv->N++;
			if (priv->om_blocked) {
				if (priv->N <= nsi->timeout[NS_TOUT_TNS_BLOCK_RETRIES]) {
					osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_BLOCKED, nsi->timeout[NS_TOUT_TNS_BLOCK], 0);
				} else {
					/* 7.2 stop accepting data when BLOCK PDU not responded */
					priv->accept_unitdata = false;
				}
			} else {
				if (priv->N <= nsi->timeout[NS_TOUT_TNS_BLOCK_RETRIES]) {
					osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_BLOCKED, nsi->timeout[NS_TOUT_TNS_BLOCK], 0);
				} else {
					osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_RESET, nsi->timeout[NS_TOUT_TNS_RESET], 0);
				}
			}
		}
		break;
	case GPRS_NS2_ST_RECOVERING:
		if (priv->initiate_reset) {
			priv->N++;
			if (priv->N <= nsi->timeout[NS_TOUT_TNS_ALIVE_RETRIES]) {
				osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_RECOVERING, 0, 0);
			} else {
				priv->N = 0;
				osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_RECOVERING, 0, 0);
			}
			break;
		}
		break;
	}
	TRACEPFSMEXT(fi, "status=ok");
	return 0;
}

static void ns2_recv_unitdata(struct osmo_fsm_inst *fi,
				   struct msgb *msg)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;
	struct gprs_ns2_inst *nsi = ns_inst_from_fi(fi);
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	struct osmo_gprs_ns2_prim nsp = {};
	uint16_t bvci;

	TRACEPFSMENT(fi, "nsei=%05u", priv->nsvc->nse->nsei);

	if (msgb_l2len(msg) < sizeof(*nsh) + 3) {
		msgb_free(msg);
		TRACEPFSMEXT(fi, "status=error Message too small");
		return;
	}

	/* TODO: 7.1: For an IP sub-network, an NS-UNITDATA PDU
	 * for a PTP BVC may indicate a request to change the IP endpoint
	 * and/or a response to a change in the IP endpoint. */

	/* TODO: nsh->data[0] -> C/R only valid in IP SNS */
	bvci = nsh->data[1] << 8 | nsh->data[2];

	msg->l3h = &nsh->data[3];
	nsp.bvci = bvci;
	nsp.nsei = priv->nsvc->nse->nsei;

	TRACEPATTR(DNS, "bvci=%05u", bvci);
	/* 10.3.9 NS SDU Control Bits */
	if (nsh->data[0] & 0x1)
		nsp.u.unitdata.change = GPRS_NS2_ENDPOINT_REQUEST_CHANGE;

	osmo_prim_init(&nsp.oph, SAP_NS, GPRS_NS2_PRIM_UNIT_DATA,
			PRIM_OP_INDICATION, msg);
	nsi->cb(&nsp.oph, nsi->cb_data);
	TRACEPFSMEXT(fi, "status=ok");
}

static void ns2_vc_fsm_allstate_action(struct osmo_fsm_inst *fi,
					    uint32_t event,
					    void *data)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;
	struct gprs_ns2_inst *nsi = ns_inst_from_fi(fi);
	struct msgb *msg = data;

	TRACEPFSMENT(fi, "nsei=%05u", priv->nsvc->nse->nsei);

	switch (event) {
	case GPRS_NS2_EV_RX_RESET:
		if (priv->nsvc->mode != GPRS_NS2_VC_MODE_BLOCKRESET)
			break;

		/* move the FSM into reset */
		if (fi->state != GPRS_NS2_ST_RESET) {
			priv->initiate_reset = false;
			osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_RESET, nsi->timeout[NS_TOUT_TNS_RESET], NS_TOUT_TNS_RESET);
		}
		/* pass the event down into FSM action */
		ns2_st_reset(fi, event, data);
		break;
	case GPRS_NS2_EV_RX_ALIVE:
		switch (fi->state) {
		case GPRS_NS2_ST_UNCONFIGURED:
		case GPRS_NS2_ST_RESET:
			/* ignore ALIVE */
			break;
		default:
			ns2_tx_alive_ack(priv->nsvc);
		}
		break;
	case GPRS_NS2_EV_RX_ALIVE_ACK:
		/* for VCs without RESET/BLOCK/UNBLOCK, the connections comes after ALIVE_ACK unblocked */
		if (fi->state == GPRS_NS2_ST_RECOVERING)
			ns2_st_alive(fi, event, data);
		else
			recv_test_procedure(fi);
		break;
	case GPRS_NS2_EV_RX_UNITDATA:
		/* UNITDATA has to handle the release of msg.
		 * If send upwards (gprs_ns2_recv_unitdata) it must NOT free
		 * the msg, the upper layer has to do it.
		 * Otherwise the msg must be freed.
		 */
		switch (fi->state) {
		case GPRS_NS2_ST_BLOCKED:
			/* 7.2.1: the BLOCKED_ACK might be lost */
			if (priv->accept_unitdata) {
				ns2_recv_unitdata(fi, msg);
				TRACEPFSMEXT(fi, "status=ok");

				return;
			}

			ns2_tx_status(priv->nsvc,
				      NS_CAUSE_NSVC_BLOCKED,
				      0, msg);
			break;
		/* ALIVE can receive UNITDATA if the ALIVE_ACK is lost */
		case GPRS_NS2_ST_RECOVERING:
		case GPRS_NS2_ST_UNBLOCKED:
			ns2_recv_unitdata(fi, msg);
			TRACEPFSMEXT(fi, "status=ok");
			return;
		}

		msgb_free(msg);
		break;
	case GPRS_NS2_EV_REQ_FORCE_UNCONFIGURED:
		if (fi->state != GPRS_NS2_ST_UNCONFIGURED) {
			/* Force the NSVC back to its initial state */
			osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_UNCONFIGURED, 0, 0);
			TRACEPFSMEXT(fi, "status=ok");
			return;
		}
		break;
	case GPRS_NS2_EV_REQ_OM_BLOCK:
		/* vty cmd: block */
		priv->initiate_block = true;
		priv->om_blocked = true;
		osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_BLOCKED, nsi->timeout[NS_TOUT_TNS_BLOCK], 0);
		break;
	case GPRS_NS2_EV_REQ_OM_UNBLOCK:
		/* vty cmd: unblock*/
		if (!priv->om_blocked)
			return;
		priv->om_blocked = false;
		if (fi->state == GPRS_NS2_ST_BLOCKED)
			osmo_fsm_inst_state_chg(fi, GPRS_NS2_ST_BLOCKED, nsi->timeout[NS_TOUT_TNS_BLOCK], 0);
		break;
	}
	TRACEPFSMEXT(fi, "");
}

static void ns2_vc_fsm_clean(struct osmo_fsm_inst *fi,
				  enum osmo_fsm_term_cause cause)
{
	struct gprs_ns2_vc_priv *priv = fi->priv;

	osmo_timer_del(&priv->alive.timer);
}

static struct osmo_fsm ns2_vc_fsm = {
	.name = "GPRS-NS2-VC",
	.states = ns2_vc_states,
	.num_states = ARRAY_SIZE(ns2_vc_states),
	.allstate_event_mask = S(GPRS_NS2_EV_RX_UNITDATA) |
			       S(GPRS_NS2_EV_RX_RESET) |
			       S(GPRS_NS2_EV_RX_ALIVE) |
			       S(GPRS_NS2_EV_RX_ALIVE_ACK) |
			       S(GPRS_NS2_EV_REQ_FORCE_UNCONFIGURED) |
			       S(GPRS_NS2_EV_REQ_OM_BLOCK) |
			       S(GPRS_NS2_EV_REQ_OM_UNBLOCK),
	.allstate_action = ns2_vc_fsm_allstate_action,
	.cleanup = ns2_vc_fsm_clean,
	.timer_cb = ns2_vc_fsm_timer_cb,
	/* .log_subsys = DNS, "is not constant" */
	.event_names = ns2_vc_event_names,
	.pre_term = NULL,
	.log_subsys = DLNS,
};

/*!
 * \brief gprs_ns2_vc_fsm_alloc
 * \param ctx
 * \param vc
 * \param id a char representation of the virtual curcuit
 * \param initiator initiator is the site which starts the connection. Usually the BSS.
 * \return NULL on error, otherwise the fsm
 */
struct osmo_fsm_inst *ns2_vc_fsm_alloc(struct gprs_ns2_vc *nsvc,
					    const char *id, bool initiator)
{
	struct osmo_fsm_inst *fi;
	struct gprs_ns2_vc_priv *priv;

	fi = osmo_fsm_inst_alloc(&ns2_vc_fsm, nsvc, NULL, LOGL_DEBUG, id);
	if (!fi)
		return fi;

	TRACEPFSMENT(fi, "nsei=%05u", nsvc->nse->nsei);

	nsvc->fi = fi;
	priv = fi->priv = talloc_zero(fi, struct gprs_ns2_vc_priv);
	priv->nsvc = nsvc;
	priv->initiator = initiator;

	osmo_timer_setup(&priv->alive.timer, alive_timeout_handler, fi);

	TRACEPFSMEXT(fi, "status=ok");

	return fi;
}

/*! Start a NS-VC FSM.
 *  \param nsvc the virtual circuit
 *  \return 0 on success; negative on error */
int ns2_vc_fsm_start(struct gprs_ns2_vc *nsvc)
{
	/* allows to call this function even for started nsvc by gprs_ns2_start_alive_all_nsvcs */
	if (nsvc->fi->state == GPRS_NS2_ST_UNCONFIGURED)
		return osmo_fsm_inst_dispatch(nsvc->fi, GPRS_NS2_EV_REQ_START, NULL);
	return 0;
}

/*! Reset a NS-VC FSM.
 *  \param nsvc the virtual circuit
 *  \return 0 on success; negative on error */
int ns2_vc_force_unconfigured(struct gprs_ns2_vc *nsvc)
{
	return osmo_fsm_inst_dispatch(nsvc->fi, GPRS_NS2_EV_REQ_FORCE_UNCONFIGURED, NULL);
}

/*! Block a NS-VC.
 *  \param nsvc the virtual circuit
 *  \return 0 on success; negative on error */
int ns2_vc_block(struct gprs_ns2_vc *nsvc)
{
	return osmo_fsm_inst_dispatch(nsvc->fi, GPRS_NS2_EV_REQ_OM_BLOCK, NULL);
}

/*! Unblock a NS-VC.
 *  \param nsvc the virtual circuit
 *  \return 0 on success; negative on error */
int ns2_vc_unblock(struct gprs_ns2_vc *nsvc)
{
	return osmo_fsm_inst_dispatch(nsvc->fi, GPRS_NS2_EV_REQ_OM_UNBLOCK, NULL);
}

/*! entry point for messages from the driver/VL
 *  \param nsvc virtual circuit on which the message was received
 *  \param msg message that was received
 *  \param tp parsed TLVs of the received message
 *  \return 0 on success; negative on error */
int ns2_vc_rx(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	struct osmo_fsm_inst *fi = nsvc->fi;
	int rc = 0;
	uint8_t cause;
	uint16_t nsei, nsvci;

	TRACEPFSMENT(fi, "nsei=%05u span.kind=server", nsvc->nse->nsei);

	/* TODO: 7.2: on UNBLOCK/BLOCK: check if NS-VCI is correct,
	 *  if not answer STATUS with "NS-VC unknown" */
	/* TODO: handle BLOCK/UNBLOCK/ALIVE with different VCI */

	if (ns2_validate(nsvc, nsh->pdu_type, msg, tp, &cause)) {
		if (nsh->pdu_type != NS_PDUT_STATUS) {
			rc = ns2_tx_status(nsvc, cause, 0, msg);
			goto out;
		}
	}

	if (TLVP_PRESENT(tp, NS_IE_NSEI)) {
		nsei = tlvp_val16be(tp, NS_IE_NSEI);
		if (nsei != nsvc->nse->nsei) {
			/* 48.016 § 7.3.1 send, RESET_ACK to wrong NSVCI + ignore */
			if (nsh->pdu_type == NS_PDUT_RESET)
				ns2_tx_reset_ack(nsvc);

			LOGNSVC(nsvc, LOGL_ERROR, "Rx %s with wrong NSEI=%05u. Ignoring PDU.\n",
				get_value_string(gprs_ns_pdu_strings, nsh->pdu_type), nsei);
			goto out;
		}
	}

	if (nsvc->nsvci_is_valid && TLVP_PRESENT(tp,  NS_IE_VCI)) {
		nsvci = tlvp_val16be(tp, NS_IE_VCI);
		if (nsvci != nsvc->nsvci) {
			/* 48.016 § 7.3.1 send RESET_ACK to wrong NSVCI + ignore */
			if (nsh->pdu_type == NS_PDUT_RESET)
				ns2_tx_reset_ack(nsvc);

			LOGNSVC(nsvc, LOGL_ERROR, "Rx %s with wrong NSVCI=%05u. Ignoring PDU.\n",
				get_value_string(gprs_ns_pdu_strings, nsh->pdu_type), nsvci);
			goto out;
		}
	}

	switch (nsh->pdu_type) {
	case NS_PDUT_RESET:
		osmo_fsm_inst_dispatch(fi, GPRS_NS2_EV_RX_RESET, tp);
		break;
	case NS_PDUT_RESET_ACK:
		osmo_fsm_inst_dispatch(fi, GPRS_NS2_EV_RX_RESET_ACK, tp);
		break;
	case NS_PDUT_BLOCK:
		osmo_fsm_inst_dispatch(fi, GPRS_NS2_EV_RX_BLOCK, tp);
		break;
	case NS_PDUT_BLOCK_ACK:
		osmo_fsm_inst_dispatch(fi, GPRS_NS2_EV_RX_BLOCK_ACK, tp);
		break;
	case NS_PDUT_UNBLOCK:
		osmo_fsm_inst_dispatch(fi, GPRS_NS2_EV_RX_UNBLOCK, tp);
		break;
	case NS_PDUT_UNBLOCK_ACK:
		osmo_fsm_inst_dispatch(fi, GPRS_NS2_EV_RX_UNBLOCK_ACK, tp);
		break;
	case NS_PDUT_ALIVE:
		osmo_fsm_inst_dispatch(fi, GPRS_NS2_EV_RX_ALIVE, tp);
		break;
	case NS_PDUT_ALIVE_ACK:
		osmo_fsm_inst_dispatch(fi, GPRS_NS2_EV_RX_ALIVE_ACK, tp);
		break;
	case NS_PDUT_UNITDATA:
		/* UNITDATA have to free msg because it might send the msg layer upwards */
		osmo_fsm_inst_dispatch(fi, GPRS_NS2_EV_RX_UNITDATA, msg);
		TRACEPFSMEXT(fi, "status=ok");
		return 0;
	default:
		LOGPFSML(fi, LOGL_ERROR, "NSEI=%u Rx unknown NS PDU type %s\n", nsvc->nse->nsei,
			 get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));
		TRACEPFSMEXT(fi, "status=error NSEI unknown");
		return -EINVAL;
	}

out:
	msgb_free(msg);

	TRACEPFSMEXT(fi, "status=ok");

	return rc;
}

/*! is the given NS-VC unblocked? */
int ns2_vc_is_unblocked(struct gprs_ns2_vc *nsvc)
{
	return (nsvc->fi->state == GPRS_NS2_ST_UNBLOCKED);
}

/* initialize osmo_ctx on main tread */
static __attribute__((constructor)) void on_dso_load_ctx(void)
{
	OSMO_ASSERT(osmo_fsm_register(&ns2_vc_fsm) == 0);
}
