/*
 * Copyright (c) 2012-2017, The Linux Foundation. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/* "API" level of the wcn36xx testmode interface. Bump it after every
 * incompatible interface change.
 */
#define WCN36XX_TESTMODE_VERSION_MAJOR 1

/* Bump this after every _compatible_ interface change, for example
 * addition of a new command or an attribute.
 */
#define WCN36XX_TESTMODE_VERSION_MINOR 0

#define WCN36XX_TM_DATA_MAX_LEN		5000

enum wcn36xx_tm_attr {
	__WCN36XX_TM_ATTR_INVALID	= 0,
	WCN36XX_TM_ATTR_CMD		= 1,
	WCN36XX_TM_ATTR_DATA		= 2,

	/* keep last */
	__WCN36XX_TM_ATTR_AFTER_LAST,
	WCN36XX_TM_ATTR_MAX		= __WCN36XX_TM_ATTR_AFTER_LAST - 1,
};

/* All wcn36xx testmode interface commands specified in
 * WCN36XX_TM_ATTR_CMD
 */
enum wcn36xx_tm_cmd {
	/* Returns the supported wcn36xx testmode interface version in
	 * WCN36XX_TM_ATTR_VERSION. Always guaranteed to work. User space
	 * uses this to verify it's using the correct version of the
	 * testmode interface
	 */
	WCN36XX_TM_CMD_GET_VERSION = 0,

	/* The netdev interface must be down at the
	 * time.
	 */
	WCN36XX_TM_CMD_START = 1,

	/* Puts the driver back into OFF state.
	 */
	WCN36XX_TM_CMD_STOP = 2,

	/* The command used to transmit a PTT command to the firmware.
	 * Command payload is provided in WCN36XX_TM_ATTR_DATA.
	 */
	WCN36XX_TM_CMD_PTT = 3,
};
/**************************/
#define MSG_GET_BUILD_RELEASE_NUMBER 0x32A2

struct build_release_params{
   u16 drvMjr;
   u16 drvMnr;
   u16 drvPtch;
   u16 drvBld;
   u16 pttMax;
   u16 pttMin;
   u16 fwVer;
} __attribute__((packed));

struct msg_get_build_release_number {
	struct build_release_params relParams;
} __attribute__((packed));

/***********************/
