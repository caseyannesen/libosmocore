/*! \file codec.h */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/bits.h>

/* TS 101318 Chapter 5.1: 260 bits + 4bit sig */
#define GSM_FR_BYTES	33
/* TS 101318 Chapter 5.2: 112 bits, no sig */
#define GSM_HR_BYTES	14
/* TS 101318 Chapter 5.3: 244 bits + 4bit sig */
#define GSM_EFR_BYTES	31

/* Number of bytes of an GSM_HR RTP payload */
#define GSM_HR_BYTES_RTP_RFC5993 (GSM_HR_BYTES + 1)
#define GSM_HR_BYTES_RTP_TS101318 (GSM_HR_BYTES)

extern const uint16_t gsm610_bitorder[];	/* FR */
extern const uint16_t gsm620_unvoiced_bitorder[]; /* HR unvoiced */
extern const uint16_t gsm620_voiced_bitorder[];   /* HR voiced */
extern const uint16_t gsm660_bitorder[];	/* EFR */

extern const uint16_t gsm690_12_2_bitorder[];	/* AMR 12.2  kbits */
extern const uint16_t gsm690_10_2_bitorder[];	/* AMR 10.2  kbits */
extern const uint16_t gsm690_7_95_bitorder[];	/* AMR  7.95 kbits */
extern const uint16_t gsm690_7_4_bitorder[];	/* AMR  7.4  kbits */
extern const uint16_t gsm690_6_7_bitorder[];	/* AMR  6.7  kbits */
extern const uint16_t gsm690_5_9_bitorder[];	/* AMR  5.9  kbits */
extern const uint16_t gsm690_5_15_bitorder[];	/* AMR  5.15 kbits */
extern const uint16_t gsm690_4_75_bitorder[];	/* AMR  4.75 kbits */

extern const uint8_t osmo_gsm611_silence_frame[GSM_FR_BYTES];

extern const struct value_string osmo_amr_type_names[];

enum osmo_amr_type {
       AMR_4_75 = 0,
       AMR_5_15 = 1,
       AMR_5_90 = 2,
       AMR_6_70 = 3,
       AMR_7_40 = 4,
       AMR_7_95 = 5,
       AMR_10_2 = 6,
       AMR_12_2 = 7,
       AMR_SID = 8,
       AMR_GSM_EFR_SID = 9,
       AMR_TDMA_EFR_SID = 10,
       AMR_PDC_EFR_SID = 11,
       AMR_NO_DATA = 15,
};

static inline const char *osmo_amr_type_name(enum osmo_amr_type type)
{ return get_value_string(osmo_amr_type_names, type); }

enum osmo_amr_quality {
       AMR_BAD = 0,
       AMR_GOOD = 1
};

extern const uint8_t gsm690_bitlength[AMR_NO_DATA+1];

int osmo_amr_s_to_d(ubit_t *out, const ubit_t *in, uint16_t n_bits, enum osmo_amr_type amr_mode);
int osmo_amr_d_to_s(ubit_t *out, const ubit_t *in, uint16_t n_bits, enum osmo_amr_type amr_mode);

/*! Check if given AMR Frame Type is a speech frame
 *  \param[in] ft AMR Frame Type
 *  \returns true if AMR with given Frame Type contains voice, false otherwise
 */
static inline bool osmo_amr_is_speech(enum osmo_amr_type ft)
{
	switch (ft) {
	case AMR_4_75:
	case AMR_5_15:
	case AMR_5_90:
	case AMR_6_70:
	case AMR_7_40:
	case AMR_7_95:
	case AMR_10_2:
	case AMR_12_2:
		return true;
	default:
		return false;
	}
}

/* SID ternary classification per GSM 06.31 & 06.81 section 6.1.1 */
enum osmo_gsm631_sid_class {
       OSMO_GSM631_SID_CLASS_SPEECH  = 0,
       OSMO_GSM631_SID_CLASS_INVALID = 1,
       OSMO_GSM631_SID_CLASS_VALID   = 2,
};

bool osmo_fr_check_sid(const uint8_t *rtp_payload, size_t payload_len);
bool osmo_hr_check_sid(const uint8_t *rtp_payload, size_t payload_len);
bool osmo_efr_check_sid(const uint8_t *rtp_payload, size_t payload_len);

enum osmo_gsm631_sid_class osmo_fr_sid_classify(const uint8_t *rtp_payload);
enum osmo_gsm631_sid_class osmo_efr_sid_classify(const uint8_t *rtp_payload);

/*! Check if given FR codec frame is any kind of SID, valid or invalid
 *  \param[in] rtp_payload Buffer with RTP payload
 *  \returns true if the frame is an "accepted SID frame" in GSM 06.31
 *  definition, false otherwise.
 */
static inline bool osmo_fr_is_any_sid(const uint8_t *rtp_payload)
{
	enum osmo_gsm631_sid_class sidc;

	sidc = osmo_fr_sid_classify(rtp_payload);
	return sidc != OSMO_GSM631_SID_CLASS_SPEECH;
}

/*! Check if given EFR codec frame is any kind of SID, valid or invalid
 *  \param[in] rtp_payload Buffer with RTP payload
 *  \returns true if the frame is an "accepted SID frame" in GSM 06.81
 *  definition, false otherwise.
 */
static inline bool osmo_efr_is_any_sid(const uint8_t *rtp_payload)
{
	enum osmo_gsm631_sid_class sidc;

	sidc = osmo_efr_sid_classify(rtp_payload);
	return sidc != OSMO_GSM631_SID_CLASS_SPEECH;
}

bool osmo_fr_sid_preen(uint8_t *rtp_payload);
bool osmo_efr_sid_preen(uint8_t *rtp_payload);

void osmo_fr_sid_reset(uint8_t *rtp_payload);
void osmo_hr_sid_reset(uint8_t *rtp_payload);
void osmo_efr_sid_reset(uint8_t *rtp_payload);

int osmo_amr_rtp_enc(uint8_t *payload, uint8_t cmr, enum osmo_amr_type ft,
		     enum osmo_amr_quality bfi);
int osmo_amr_rtp_dec(const uint8_t *payload, int payload_len, uint8_t *cmr,
		     int8_t *cmi, enum osmo_amr_type *ft,
		     enum osmo_amr_quality *bfi, int8_t *sti);
