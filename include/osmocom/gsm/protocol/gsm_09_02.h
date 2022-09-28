/*! \file gsm_09_02.h
 * GSM TS 09.02  definitions (MAP). */

#pragma once

/* Section 17.7.4 */
/* SS-Status */
#define GSM0902_SS_STATUS_Q_BIT	0x08
#define GSM0902_SS_STATUS_P_BIT	0x04
#define GSM0902_SS_STATUS_R_BIT	0x02
#define GSM0902_SS_STATUS_A_BIT	0x01

/* SS-Data */
#define GSM0902_SS_DATA_SS_STATUS_TAG	0x84
#define GSM0902_SS_DATA_NBR_USER	0x85

/* SS-Info */
#define GSM0902_SS_INFO_FORW_INFO_TAG		0xA0
#define GSM0902_SS_INFO_CALL_BARR_INFO_TAG	0xA1
#define GSM0902_SS_INFO_SS_DATA_TAG		0xA3

/* InterrogateSS-Res */
#define GSM0902_SS_INTERR_SS_RES_SS_STATUS_TAG		0x80
#define GSM0902_SS_INTERR_SS_RES_BSG_LIST_TAG		0x81
#define GSM0902_SS_INTERR_SS_RES_FORW_FEAT_LIST_TAG	0x82
#define GSM0902_SS_INTERR_SS_RES_GEN_SERV_INFO_TAG	0x83

/* Section 17.7.5 */
/* Supplementary service codes */
#define GSM0902_SS_CODE_ALL_SS				0x00
#define GSM0902_SS_CODE_ALL_LINE_IDENTIFICATION_SS	0x10
#define GSM0902_SS_CODE_CLIP				0x11
#define GSM0902_SS_CODE_CLIR				0x12
#define GSM0902_SS_CODE_COLP				0x13
#define GSM0902_SS_CODE_COLR				0x14
#define GSM0902_SS_CODE_MCI				0x15
#define GSM0902_SS_CODE_ALL_NAME_IDENTIFICATION_SS	0x18
#define GSM0902_SS_CODE_CNAP				0x19
#define GSM0902_SS_CODE_ALL_FORWARDING_SS		0x20
#define GSM0902_SS_CODE_CFU				0x21
#define GSM0902_SS_CODE_ALL_COND_FORWARDING_SS		0x28
#define GSM0902_SS_CODE_CFB				0x29
#define GSM0902_SS_CODE_CFNRY				0x2A
#define GSM0902_SS_CODE_CFNRC				0x2B
#define GSM0902_SS_CODE_CD				0x24
#define GSM0902_SS_CODE_ALL_CALL_OFFERING_SS		0x30
#define GSM0902_SS_CODE_ECT				0x31
#define GSM0902_SS_CODE_MAH				0x32
#define GSM0902_SS_CODE_ALL_CALL_COMPLETION_SS		0x40
#define GSM0902_SS_CODE_CW				0x41
#define GSM0902_SS_CODE_HOLD				0x42
#define GSM0902_SS_CODE_CCBS_A				0x43
#define GSM0902_SS_CODE_CCBS_B				0x44
#define GSM0902_SS_CODE_MC				0x45
#define GSM0902_SS_CODE_ALL_MULTI_PARTY_SS		0x50
#define GSM0902_SS_CODE_MULTI_PTY			0x51
#define GSM0902_SS_CODE_ALL_COMMUNITY_OF_INTEREST_SS	0x60
#define GSM0902_SS_CODE_CUG				0x61
#define GSM0902_SS_CODE_ALL_CHARGING_SS			0x70
#define GSM0902_SS_CODE_AOCI				0x71
#define GSM0902_SS_CODE_AOCC				0x72
#define GSM0902_SS_CODE_ALL_ADDITIONAL_INFO_TRANSFER_SS	0x80
#define GSM0902_SS_CODE_UUS1				0x81
#define GSM0902_SS_CODE_UUS2				0x82
#define GSM0902_SS_CODE_UUS3				0x83
#define GSM0902_SS_CODE_ALL_BARRING_SS			0x90
#define GSM0902_SS_CODE_BARRING_OF_OUTGOING_CALLS	0x91
#define GSM0902_SS_CODE_BAOC				0x92
#define GSM0902_SS_CODE_BOIC				0x93
#define GSM0902_SS_CODE_BOIC_EX_HC			0x94
#define GSM0902_SS_CODE_BARRING_OF_INCOMING_CALLS	0x99
#define GSM0902_SS_CODE_BAIC				0x9A
#define GSM0902_SS_CODE_BIC_ROAM			0x9B
#define GSM0902_SS_CODE_ALL_PLMN_SPECIFIC_SS		0xF0
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_1		0xF1
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_2		0xF2
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_3		0xF3
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_4		0xF4
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_5		0xF5
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_6		0xF6
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_7		0xF7
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_8		0xF8
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_9		0xF9
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_A		0xFA
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_B		0xFB
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_C		0xFC
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_D		0xFD
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_E		0xFE
#define GSM0902_SS_CODE_PLMN_SPECIFIC_SS_F		0xFF
#define GSM0902_SS_CODE_ALL_CALL_PRIORITY_SS		0xA0
#define GSM0902_SS_CODE_EMLPP				0xA1
#define GSM0902_SS_CODE_ALL_LCSPRIVACY_EXCEPTION	0xB0
#define GSM0902_SS_CODE_UNIVERSAL			0xB1
#define GSM0902_SS_CODE_CALL_SESSION_RELATED		0xB2
#define GSM0902_SS_CODE_CALL_SESSION_UNRELATED		0xB3
#define GSM0902_SS_CODE_PLMNOPERATOR			0xB4
#define GSM0902_SS_CODE_SERVICE_TYPE			0xB5
#define GSM0902_SS_CODE_ALL_MOLR_SS			0xC0
#define GSM0902_SS_CODE_BASIC_SELF_LOCATION		0xC1
#define GSM0902_SS_CODE_AUTONOMOUS_SELF_LOCATION	0xC2
#define GSM0902_SS_CODE_TRANSFER_TO_THIRD_PARTY		0xC3

/* Section 17.7.9 */
/* Teleservice codes */
#define GSM0902_TS_CODE_ALL_TELESERVICES			0x00
#define GSM0902_TS_CODE_ALL_SPEECH_TRANSMISSION_SERVICES	0x10
#define GSM0902_TS_CODE_TELEPHONY				0x11
#define GSM0902_TS_CODE_EMERGENCY_CALLS				0x12
#define GSM0902_TS_CODE_ALL_SHORT_MESSAGE_SERVICES		0x20
#define GSM0902_TS_CODE_SHORT_MESSAGE_MT_PP			0x21
#define GSM0902_TS_CODE_SHORT_MESSAGE_MO_PP			0x22
#define GSM0902_TS_CODE_ALL_FACSIMILE_TRANSMISSION_SERVICES	0x60
#define GSM0902_TS_CODE_FACSIMILE_GROUP3AND_ALTER_SPEECH	0x61
#define GSM0902_TS_CODE_AUTOMATIC_FACSIMILE_GROUP3		0x62
#define GSM0902_TS_CODE_FACSIMILE_GROUP4			0x63
#define GSM0902_TS_CODE_ALL_DATA_TELESERVICES			0x70
#define GSM0902_TS_CODE_ALL_TELESERVICES_EXEPT_SMS		0x80
#define GSM0902_TS_CODE_ALL_VOICE_GROUP_CALL_SERVICES		0x90
#define GSM0902_TS_CODE_VOICE_GROUP_CALL			0x91
#define GSM0902_TS_CODE_VOICE_BROADCAST_CALL			0x92
#define GSM0902_TS_CODE_ALL_PLMN_SPECIFIC_TS			0xD0
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_1			0xD1
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_2			0xD2
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_3			0xD3
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_4			0xD4
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_5			0xD5
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_6			0xD6
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_7			0xD7
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_8			0xD8
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_9			0xD9
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_A			0xDA
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_B			0xDB
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_C			0xDC
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_D			0xDD
#define GSM0902_TS_CODE_PLMN_SPECIFIC_TS_E			0xDE
