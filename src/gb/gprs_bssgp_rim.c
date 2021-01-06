/*! \file gprs_bssgp.c
 * GPRS BSSGP RIM protocol implementation as per 3GPP TS 48.018. */
/*
 * (C) 2020-2021 by sysmocom - s.f.m.c. GmbH
 * Author: Philipp Maier <pmaier@sysmocom.de>
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

#include <errno.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>
#include <osmocom/gsm/gsm0808_utils.h>

/* TVLV IEs use a variable length field. To be sure we will do all buffer
 * length checks with the maximum possible header length, which is
 * 1 octet tag + 2 octets length = 3 */
#define TVLV_HDR_MAXLEN 3

/* Usually RIM application containers and their surrounding RIM containers
 * are not likely to exceed 128 octets, so the usual header length will be 2 */
#define TVLV_HDR_LEN 2

/* The reporting cell identifier is encoded as a cell identifier IE
 * (3GPP TS 48.018, sub-clause 11.3.9) but without IE and length octets. */
#define REP_CELL_ID_LEN 8

/*! Decode a RAN Information Request Application Container for NACC (3GPP TS 48.018, section 11.3.63.1.1).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_req_app_cont_nacc(struct bssgp_ran_inf_req_app_cont_nacc *cont, const uint8_t *buf, size_t len)
{
	int rc;

	if (len < REP_CELL_ID_LEN)
		return -EINVAL;

	rc = gsm0808_decode_cell_id_u((union gsm0808_cell_id_u*)&cont->reprt_cell,
				      CELL_IDENT_WHOLE_GLOBAL_PS, buf, len);
	if (rc < 0)
		return -EINVAL;

	return 0;
}

/*! Encode a RAN Information Request Application Container for NACC (3GPP TS 48.018, section 11.3.63.1.1).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_req_app_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_ran_inf_req_app_cont_nacc *cont)
{
	int rc;
	struct gprs_ra_id *raid;

	if (len < REP_CELL_ID_LEN)
		return -EINVAL;

	raid = (struct gprs_ra_id *)&cont->reprt_cell.rai;
	rc = bssgp_create_cell_id(buf, raid, cont->reprt_cell.cell_identity);
	if (rc < 0)
		return -EINVAL;
	return rc;
}

/*! Decode a RAN Information Application Container (3GPP TS 48.018, section 11.3.63.2.1).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_app_cont_nacc(struct bssgp_ran_inf_app_cont_nacc *cont, const uint8_t *buf, size_t len)
{
	unsigned int i;
	int remaining_buf_len;
	int rc;

	/* The given buffer must at least contain a reporting cell identifer
	 * plus one octet that defines number/type of attached sysinfo messages. */
	if (len < REP_CELL_ID_LEN + 1)
		return -EINVAL;

	rc = gsm0808_decode_cell_id_u((union gsm0808_cell_id_u*)&cont->reprt_cell,
				      CELL_IDENT_WHOLE_GLOBAL_PS, buf, len);
	if (rc < 0)
		return -EINVAL;

	buf += REP_CELL_ID_LEN;

	cont->type_psi = buf[0] & 1;
	cont->num_si = buf[0] >> 1;
	buf++;

	/* The number of sysinfo messages may be zero */
	if (cont->num_si == 0)
		return 0;

	/* Check if the prospected system information messages fit in the
	 * remaining buffer space */
	remaining_buf_len = len - REP_CELL_ID_LEN - 1;
	if (remaining_buf_len <= 0)
		return -EINVAL;
	if (cont->type_psi && remaining_buf_len / BSSGP_RIM_PSI_LEN < cont->num_si)
		return -EINVAL;
	else if (remaining_buf_len / BSSGP_RIM_SI_LEN < cont->num_si)
		return -EINVAL;

	for (i = 0; i < cont->num_si; i++) {
		cont->si[i] = buf;
		if (cont->type_psi)
			buf += BSSGP_RIM_PSI_LEN;
		else
			buf += BSSGP_RIM_SI_LEN;
	}

	return 0;
}

/*! Encode a RAN Information Application Container (3GPP TS 48.018, section 11.3.63.2.1).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_app_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_ran_inf_app_cont_nacc *cont)
{
	uint8_t *buf_ptr = buf;
	int rc;
	unsigned int silen;
	unsigned int i;
	struct gprs_ra_id *raid;

	if (cont->type_psi)
		silen = BSSGP_RIM_PSI_LEN;
	else
		silen = BSSGP_RIM_SI_LEN;

	/* The buffer must accept the reporting cell id, plus 1 byte to define
	 * the type and number of sysinfo messages. */
	if (len < REP_CELL_ID_LEN + 1 + silen * cont->num_si)
		return -EINVAL;

	raid = (struct gprs_ra_id *)&cont->reprt_cell.rai;
	rc = bssgp_create_cell_id(buf_ptr, raid, cont->reprt_cell.cell_identity);
	if (rc < 0)
		return -EINVAL;
	buf_ptr += rc;

	buf_ptr[0] = 0x00;
	if (cont->type_psi)
		buf_ptr[0] |= 0x01;
	buf_ptr[0] |= (cont->num_si << 1);
	buf_ptr++;

	for (i = 0; i < cont->num_si; i++) {
		memcpy(buf_ptr, cont->si[i], silen);
		buf_ptr += silen;
	}

	return (int)(buf_ptr - buf);
}

/*! Decode a Application Error Container for NACC (3GPP TS 48.018, section 11.3.64.1).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_app_err_cont_nacc(struct bssgp_app_err_cont_nacc *cont, const uint8_t *buf, size_t len)
{
	/* The buffer must at least contain the NACC cause code, it should also
	 * contain the application container, but we won't error if it is missing. */
	if (len < 1)
		return -EINVAL;

	cont->nacc_cause = buf[0];

	if (len > 1) {
		cont->err_app_cont = buf + 1;
		cont->err_app_cont_len = len - 1;
	} else {
		cont->err_app_cont = NULL;
		cont->err_app_cont_len = 0;
	}

	return 0;
}

/*! Encode Application Error Container for NACC (3GPP TS 48.018, section 11.3.64.1).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_app_err_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_app_err_cont_nacc *cont)
{
	uint8_t *buf_ptr = buf;

	/* The buffer must accept the length of the application container and the NACC
	 * cause code, which is one octet in length. */
	if (len < cont->err_app_cont_len + 1)
		return -EINVAL;

	buf_ptr[0] = cont->nacc_cause;
	buf_ptr++;

	memcpy(buf_ptr, cont->err_app_cont, cont->err_app_cont_len);
	buf_ptr += cont->err_app_cont_len;

	return (int)(buf_ptr - buf);
}

/* The structs bssgp_ran_inf_req_rim_cont, bssgp_ran_inf_rim_cont and bssgp_ran_inf_app_err_rim_cont *cont
 * share four common fields at the beginning, we use the following struct as parameter type for the common
 * encoder/decoder functions. (See also 3GPP TS 48.018 table 11.3.62a.1.b, table 11.3.62a.2.b, and
 * table 11.3.62a.5.b) */
struct bssgp_ran_inf_x_cont {
	enum bssgp_ran_inf_app_id app_id;
	uint32_t seq_num;
	struct bssgp_rim_pdu_ind pdu_ind;
	uint8_t prot_ver;
};

static int dec_rim_cont_common(struct bssgp_ran_inf_x_cont *cont, struct tlv_parsed *tp)
{
	if (TLVP_PRES_LEN(tp, BSSGP_IE_RIM_APP_IDENTITY, sizeof(uint8_t)))
		cont->app_id = TLVP_VAL(tp, BSSGP_IE_RIM_APP_IDENTITY)[0];
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(tp, BSSGP_IE_RIM_SEQ_NR, sizeof(cont->seq_num)))
		cont->seq_num = tlvp_val32be(tp, BSSGP_IE_RIM_SEQ_NR);
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(tp, BSSGP_IE_RIM_PDU_INDICATIONS, sizeof(cont->pdu_ind)))
		memcpy(&cont->pdu_ind, TLVP_VAL(tp, BSSGP_IE_RIM_PDU_INDICATIONS), sizeof(cont->pdu_ind));
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(tp, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver)))
		cont->prot_ver = TLVP_VAL(tp, BSSGP_IE_RIM_PROTOCOL_VERSION)[0];
	else
		cont->prot_ver = 1;

	return 0;
}

static uint8_t *enc_rim_cont_common(uint8_t *buf, size_t len, const struct bssgp_ran_inf_x_cont *cont)
{

	uint32_t seq_num = osmo_htonl(cont->seq_num);
	uint8_t app_id_temp;
	uint8_t *buf_ptr = buf;

	if (len <
	    TVLV_HDR_MAXLEN * 4 + sizeof(app_id_temp) + sizeof(seq_num) + sizeof(cont->pdu_ind) +
	    sizeof(cont->prot_ver))
		return NULL;

	app_id_temp = cont->app_id;
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_APP_IDENTITY, sizeof(app_id_temp), &app_id_temp);
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_SEQ_NR, sizeof(seq_num), (uint8_t *) & seq_num);
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PDU_INDICATIONS, sizeof(cont->pdu_ind), (uint8_t *) & cont->pdu_ind);
	if (cont->prot_ver > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver), &cont->prot_ver);

	return buf_ptr;
}

/*! Decode a RAN Information Request RIM Container (3GPP TS 48.018, table 11.3.62a.1.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_req_rim_cont(struct bssgp_ran_inf_req_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	rc = dec_rim_cont_common((struct bssgp_ran_inf_x_cont *)cont, &tp);
	if (rc < 0)
		return -EINVAL;

	if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_REQ_APP_CONTAINER)) {
		switch (cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			rc = bssgp_dec_ran_inf_req_app_cont_nacc(&cont->u.app_cont_nacc,
								 TLVP_VAL(&tp, BSSGP_IE_RIM_REQ_APP_CONTAINER),
								 TLVP_LEN(&tp, BSSGP_IE_RIM_REQ_APP_CONTAINER));
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			/* TODO: add parsers for Si3, MBMS, SON, UTRA-SI app containers */
			return -EINVAL;
		default:
			return -EINVAL;
		}

		if (rc < 0)
			return rc;
	}

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID, 1)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	}

	return 0;
}

/* Dub a TLVP header into a given buffer. The value part of the IE must start
 * at the 2nd octet. Should the length field make a 3 octet TLVP header
 * necessary (unlikely, but possible) the value part is moved ahead by one
 * octet. The function returns a pointer to the end of value part. */
static uint8_t *dub_tlvp_header(uint8_t *buf, uint8_t iei, uint16_t len)
{
	uint8_t *buf_ptr = buf;

	buf_ptr[0] = iei;
	if (len <= TVLV_MAX_ONEBYTE) {
		buf_ptr[1] = (uint8_t) len;
		buf_ptr[1] |= 0x80;
		buf_ptr += TVLV_HDR_LEN;
	} else {
		memmove(buf_ptr + 1, buf_ptr, len);
		buf_ptr[1] = len >> 8;
		buf_ptr[1] = len & 0xff;
		buf_ptr += TVLV_HDR_MAXLEN;
	}
	buf_ptr += len;

	return buf_ptr;
}

/*! Encode a RAN Information Request RIM Container (3GPP TS 48.018, table 11.3.62a.1.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_req_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_req_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;
	int app_cont_len = 0;
	int remaining_buf_len;

	buf_ptr = enc_rim_cont_common(buf_ptr, len, (struct bssgp_ran_inf_x_cont *)cont);
	if (!buf_ptr)
		return -EINVAL;

	remaining_buf_len = len - (int)(buf_ptr - buf);
	if (remaining_buf_len <= 0)
		return -EINVAL;

	switch (cont->app_id) {
	case BSSGP_RAN_INF_APP_ID_NACC:
		app_cont_len =
		    bssgp_enc_ran_inf_req_app_cont_nacc(buf_ptr + TVLV_HDR_LEN, remaining_buf_len - TVLV_HDR_MAXLEN,
							&cont->u.app_cont_nacc);
		break;
	case BSSGP_RAN_INF_APP_ID_SI3:
	case BSSGP_RAN_INF_APP_ID_MBMS:
	case BSSGP_RAN_INF_APP_ID_SON:
	case BSSGP_RAN_INF_APP_ID_UTRA_SI:
		/* TODO: add encoders for Si3, MBMS, SON, UTRA-SI app containers */
		return -EINVAL;
	default:
		return -EINVAL;
	}

	if (app_cont_len < 0)
		return -EINVAL;
	buf_ptr = dub_tlvp_header(buf_ptr, BSSGP_IE_RIM_REQ_APP_CONTAINER, app_cont_len);

	remaining_buf_len = len - (int)(buf_ptr - buf);
	if (remaining_buf_len < 0)
		return -EINVAL;

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0) {
		if (remaining_buf_len < cont->son_trans_app_id_len + TVLV_HDR_MAXLEN)
			return -EINVAL;
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);
	}
	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information RIM Container (3GPP TS 48.018, table 11.3.62a.2.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_rim_cont(struct bssgp_ran_inf_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	rc = dec_rim_cont_common((struct bssgp_ran_inf_x_cont *)cont, &tp);
	if (rc < 0)
		return -EINVAL;

	if (TLVP_PRESENT(&tp, BSSGP_IE_RAN_INFO_APP_CONTAINER)) {
		switch (cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			rc = bssgp_dec_ran_inf_app_cont_nacc(&cont->u.app_cont_nacc,
							     TLVP_VAL(&tp, BSSGP_IE_RAN_INFO_APP_CONTAINER),
							     TLVP_LEN(&tp, BSSGP_IE_RAN_INFO_APP_CONTAINER));
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			/* TODO: add parsers for Si3, MBMS, SON, UTRA-SI app containers */
			return -EINVAL;
		default:
			return -EINVAL;
		}

		if (rc < 0)
			return rc;
	} else if (TLVP_PRESENT(&tp, BSSGP_IE_APP_ERROR_CONTAINER)) {
		switch (cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			rc = bssgp_dec_app_err_cont_nacc(&cont->u.app_err_cont_nacc,
							 TLVP_VAL(&tp, BSSGP_IE_APP_ERROR_CONTAINER), TLVP_LEN(&tp,
													       BSSGP_IE_APP_ERROR_CONTAINER));
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			/* TODO: add parsers for Si3, MBMS, SON, UTRA-SI app containers */
			return -EINVAL;
		default:
			return -EINVAL;
		}
		if (rc < 0)
			return rc;
		cont->app_err = true;
	}

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID, 1)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	}

	return 0;
}

/*! Encode a RAN Information RIM Container (3GPP TS 48.018, table 11.3.62a.2.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;
	int app_cont_len = 0;
	int remaining_buf_len;

	buf_ptr = enc_rim_cont_common(buf_ptr, len, (struct bssgp_ran_inf_x_cont *)cont);
	if (!buf_ptr)
		return -EINVAL;

	remaining_buf_len = len - (int)(buf_ptr - buf);
	if (remaining_buf_len <= 0)
		return -EINVAL;

	if (cont->app_err) {
		switch (cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			app_cont_len =
			    bssgp_enc_app_err_cont_nacc(buf_ptr + TVLV_HDR_LEN, remaining_buf_len - TVLV_HDR_MAXLEN,
							&cont->u.app_err_cont_nacc);
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			/* TODO: add encoders for Si3, MBMS, SON, UTRA-SI app containers */
			return -EINVAL;
		default:
			return -EINVAL;
		}
		if (app_cont_len < 0)
			return -EINVAL;
		buf_ptr = dub_tlvp_header(buf_ptr, BSSGP_IE_APP_ERROR_CONTAINER, app_cont_len);
	} else {
		switch (cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			app_cont_len =
			    bssgp_enc_ran_inf_app_cont_nacc(buf_ptr + TVLV_HDR_LEN, remaining_buf_len - TVLV_HDR_MAXLEN,
							    &cont->u.app_cont_nacc);
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			/* TODO: add encoders for Si3, MBMS, SON, UTRA-SI app containers */
			return -EINVAL;
		default:
			return -EINVAL;
		}
		if (app_cont_len < 0)
			return -EINVAL;
		buf_ptr = dub_tlvp_header(buf_ptr, BSSGP_IE_RAN_INFO_APP_CONTAINER, app_cont_len);
	}

	remaining_buf_len = len - (int)(buf_ptr - buf);
	if (remaining_buf_len < 0)
		return -EINVAL;

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0) {
		if (remaining_buf_len < cont->son_trans_app_id_len + TVLV_HDR_MAXLEN)
			return -EINVAL;
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);
	}
	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information ACK RIM Container (3GPP TS 48.018, table 11.3.62a.3.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_ack_rim_cont(struct bssgp_ran_inf_ack_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_RIM_APP_IDENTITY, sizeof(uint8_t)))
		cont->app_id = TLVP_VAL(&tp, BSSGP_IE_RIM_APP_IDENTITY)[0];
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_RIM_SEQ_NR, sizeof(cont->seq_num)))
		cont->seq_num = tlvp_val32be(&tp, BSSGP_IE_RIM_SEQ_NR);
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver)))
		cont->prot_ver = TLVP_VAL(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION)[0];
	else
		cont->prot_ver = 1;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID, 1)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	}

	return 0;
}

/*! Encode a RAN Information ACK RIM Container (3GPP TS 48.018, table 11.3.62a.3.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_ack_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_ack_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;
	uint32_t seq_num = osmo_htonl(cont->seq_num);
	uint8_t app_id_temp;

	if (len <
	    4 * TVLV_HDR_MAXLEN + sizeof(app_id_temp) + sizeof(seq_num) + sizeof(cont->prot_ver) +
	    cont->son_trans_app_id_len)
		return -EINVAL;

	app_id_temp = cont->app_id;
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_APP_IDENTITY, sizeof(app_id_temp), &app_id_temp);
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_SEQ_NR, sizeof(seq_num), (uint8_t *) & seq_num);

	if (cont->prot_ver > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver), &cont->prot_ver);

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0)
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);

	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information Error RIM Container (3GPP TS 48.018, table 11.3.62a.4.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_err_rim_cont(struct bssgp_ran_inf_err_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_RIM_APP_IDENTITY, sizeof(uint8_t)))
		cont->app_id = TLVP_VAL(&tp, BSSGP_IE_RIM_APP_IDENTITY)[0];
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_CAUSE, sizeof(cont->cause)))
		cont->cause = TLVP_VAL(&tp, BSSGP_IE_CAUSE)[0];
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver)))
		cont->prot_ver = TLVP_VAL(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION)[0];
	else
		cont->prot_ver = 1;

	if (TLVP_PRESENT(&tp, BSSGP_IE_PDU_IN_ERROR)) {
		cont->err_pdu = TLVP_VAL(&tp, BSSGP_IE_PDU_IN_ERROR);
		cont->err_pdu_len = TLVP_LEN(&tp, BSSGP_IE_PDU_IN_ERROR);
	} else {
		return -EINVAL;
	}

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID, 1)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	}

	return 0;
}

/*! Encode a RAN Information Error RIM Container (3GPP TS 48.018, table 11.3.62a.4.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_err_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_err_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;
	uint8_t app_id_temp;

	if (len <
	    TVLV_HDR_MAXLEN * 5 + sizeof(app_id_temp) + sizeof(cont->cause) + sizeof(cont->prot_ver) +
	    cont->err_pdu_len + cont->son_trans_app_id_len)
		return -EINVAL;

	app_id_temp = cont->app_id;
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_APP_IDENTITY, sizeof(app_id_temp), &app_id_temp);
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_CAUSE, sizeof(cont->cause), &cont->cause);

	if (cont->prot_ver > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver), &cont->prot_ver);

	if (cont->err_pdu && cont->err_pdu_len > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_PDU_IN_ERROR, cont->err_pdu_len, cont->err_pdu);
	else
		return -EINVAL;

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0)
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);

	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information Application Error RIM Container (3GPP TS 48.018, table 11.3.62a.5.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_app_err_rim_cont(struct bssgp_ran_inf_app_err_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	rc = dec_rim_cont_common((struct bssgp_ran_inf_x_cont *)cont, &tp);
	if (rc < 0)
		return -EINVAL;

	switch (cont->app_id) {
	case BSSGP_RAN_INF_APP_ID_NACC:
		rc = bssgp_dec_app_err_cont_nacc(&cont->u.app_err_cont_nacc,
						 TLVP_VAL(&tp, BSSGP_IE_APP_ERROR_CONTAINER), TLVP_LEN(&tp,
												       BSSGP_IE_APP_ERROR_CONTAINER));
		break;
	case BSSGP_RAN_INF_APP_ID_SI3:
	case BSSGP_RAN_INF_APP_ID_MBMS:
	case BSSGP_RAN_INF_APP_ID_SON:
	case BSSGP_RAN_INF_APP_ID_UTRA_SI:
		/* TODO: add parsers for Si3, MBMS, SON, UTRA-SI app containers */
		return -EINVAL;
	default:
		return -EINVAL;
	}
	if (rc < 0)
		return rc;

	return 0;
}

/*! Encode a RAN Information Application Error RIM Container (3GPP TS 48.018, table 11.3.62a.5.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_app_err_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_app_err_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;
	int app_cont_len = 0;
	int remaining_buf_len;

	buf_ptr = enc_rim_cont_common(buf_ptr, len, (struct bssgp_ran_inf_x_cont *)cont);
	if (!buf_ptr)
		return -EINVAL;

	remaining_buf_len = len - (int)(buf_ptr - buf);
	if (remaining_buf_len <= 0)
		return -EINVAL;

	switch (cont->app_id) {
	case BSSGP_RAN_INF_APP_ID_NACC:
		app_cont_len =
		    bssgp_enc_app_err_cont_nacc(buf_ptr + TVLV_HDR_LEN, remaining_buf_len - TVLV_HDR_MAXLEN,
						&cont->u.app_err_cont_nacc);
		break;
	case BSSGP_RAN_INF_APP_ID_SI3:
	case BSSGP_RAN_INF_APP_ID_MBMS:
	case BSSGP_RAN_INF_APP_ID_SON:
	case BSSGP_RAN_INF_APP_ID_UTRA_SI:
		/* TODO: add encoders for Si3, MBMS, SON, UTRA-SI app containers */
		return -EINVAL;
	default:
		return -EINVAL;
	}
	if (app_cont_len < 0)
		return -EINVAL;
	buf_ptr = dub_tlvp_header(buf_ptr, BSSGP_IE_APP_ERROR_CONTAINER, app_cont_len);

	return (int)(buf_ptr - buf);
}
