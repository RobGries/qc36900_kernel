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

#include "wcn36xx.h"

struct ftm_rsp_msg
{
	__u16   msgId;
	__u16   msgBodyLength;
	__u32   respStatus;
	__u8    msgResponse[0];
} __packed;

/* The request buffer of FTM which contains a byte of command and the request */
struct ftm_payload {
	__u16   			ftm_cmd_type; //
	struct ftm_rsp_msg	ftm_cmd_msg;  //
} __packed;

#ifdef CONFIG_NL80211_TESTMODE

void wcn36xx_testmode_destroy(struct wcn36xx *wcn36xx);
int wcn36xx_tm_cmd(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		  void *data, int len);

#else

static inline void wcn36xx_testmode_destroy(struct wcn36xx *wcn36xx)
{
}

static inline int wcn36xx_tm_cmd(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				void *data, int len)
{
	return 0;
}

#endif
