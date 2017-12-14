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

#include <net/netlink.h>
#include <linux/firmware.h>
#include <net/cfg80211.h>
#include "wcn36xx.h"

#include "testmode.h"
#include "testmode_i.h"

static const struct nla_policy wcn36xx_tm_policy[WCN36XX_TM_ATTR_MAX + 1] = {
	[WCN36XX_TM_ATTR_CMD]		= { .type = NLA_U16 },
	[WCN36XX_TM_ATTR_DATA]		= { .type = NLA_BINARY,
					    .len = WCN36XX_TM_DATA_MAX_LEN },
};

static struct ftm {
	bool wfmEnabled;
} ftm_config;

static void ftm_init(void)
{
    ftm_config.wfmEnabled = false;

    return;
}

static int wcn36xx_tm_cmd_start(struct wcn36xx *ar)
{
	int ret = 0;

	if (!wcn36xx_testmode) {
		wcn36xx_dbg(WCN36XX_DBG_TESTMODE, "testmode cmd CANNOT start\n");
	} else {
		wcn36xx_dbg(WCN36XX_DBG_TESTMODE, "testmode cmd start\n");
		ftm_config.wfmEnabled = true;
	}

	return ret;
}

static int wcn36xx_tm_cmd_stop(struct wcn36xx *ar)
{
	int ret = 0;

	wcn36xx_dbg(WCN36XX_DBG_TESTMODE, "testmode cmd stop\n");
	ftm_config.wfmEnabled = false;

	return ret;
}

static int wcn36xx_tm_cmd_ptt(struct wcn36xx *wcn, struct ieee80211_vif *vif, struct nlattr *tb[])
{
	int ret = 0, buf_len;
	void *buf;
	struct ftm_rsp_msg *msg, *rsp;
	struct sk_buff *skb;

	wcn36xx_dbg(WCN36XX_DBG_TESTMODE, "Start %s\n", __FUNCTION__);

	if (!tb[WCN36XX_TM_ATTR_DATA]) {
		ret = -EINVAL;
		goto out;
	}

	buf = nla_data(tb[WCN36XX_TM_ATTR_DATA]);
	buf_len = nla_len(tb[WCN36XX_TM_ATTR_DATA]);
	msg = rsp = (struct ftm_rsp_msg *)buf;

	wcn36xx_dbg(WCN36XX_DBG_TESTMODE,
		   "testmode cmd wmi msg_id 0x%04X msg_len %d buf %pK buf_len %d\n",
		   msg->msgId, msg->msgBodyLength,
		   buf, buf_len);

	wcn36xx_dbg_dump(WCN36XX_DBG_TESTMODE, "REQ ", buf, buf_len);

	switch (msg->msgId) {
	default:
		break;
	}

	if (rsp == NULL) {
		rsp = msg;
		msg->msgBodyLength = 0;
		msg->respStatus = 1;
	}
	wcn36xx_dbg_dump(WCN36XX_DBG_TESTMODE, "RSP ", rsp, rsp->msgBodyLength);
	skb = cfg80211_testmode_alloc_reply_skb(wcn->hw->wiphy,
						nla_total_size(msg->msgBodyLength));
	wcn36xx_dbg(WCN36XX_DBG_TESTMODE, "cfg80211_testmode_alloc_reply_skb() size=%d", rsp->msgBodyLength);
	if (!skb) {
		ret = -ENOMEM;
		goto out;
	}

	ret = nla_put(skb, WCN36XX_TM_ATTR_DATA, rsp->msgBodyLength, rsp);
	wcn36xx_dbg(WCN36XX_DBG_TESTMODE, "nla_put() ret=%d", ret);

	if (ret) {
		kfree_skb(skb);
		goto out;
	}

	ret = cfg80211_testmode_reply(skb);
	wcn36xx_dbg(WCN36XX_DBG_TESTMODE, "cfg80211_testmode_reply() ret=%d", ret);

out:
	if (rsp != msg)
		kfree(rsp);
	return ret;
}

int wcn36xx_tm_cmd(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		  void *data, int len)
{
	struct wcn36xx *wcn = hw->priv;
	struct nlattr *tb[WCN36XX_TM_ATTR_MAX + 1];
	int ret = 0;
	unsigned short attr;
	ftm_init();

	wcn36xx_info("Start %s got data=%pK len=%d\n", __FUNCTION__, data, len);
	wcn36xx_dbg_dump(WCN36XX_DBG_TESTMODE_DUMP, "Data:", data, len);
	ret = nla_parse(tb, WCN36XX_TM_ATTR_MAX, data, len,
			wcn36xx_tm_policy);
	wcn36xx_dbg(WCN36XX_DBG_TESTMODE, "nla_parse() returned %d\n", ret);
	if (ret)
		return ret;

	if (!tb[WCN36XX_TM_ATTR_CMD])
		return -EINVAL;

	attr = nla_get_u16(tb[WCN36XX_TM_ATTR_CMD]);
	wcn36xx_dbg(WCN36XX_DBG_TESTMODE, "Got TM_ATTR_CMD=%u\n", attr);

	switch (attr) {
	case WCN36XX_TM_CMD_START:
		return wcn36xx_tm_cmd_start(wcn);
	case WCN36XX_TM_CMD_STOP:
		return wcn36xx_tm_cmd_stop(wcn);
	case WCN36XX_TM_CMD_PTT:
		return wcn36xx_tm_cmd_ptt(wcn, vif, tb);
	default:
		return -EOPNOTSUPP;
	}

	return ret;
}

void wcn36xx_testmode_destroy(struct wcn36xx *wcn)
{
	mutex_lock(&wcn->conf_mutex);

	if (!ftm_config.wfmEnabled) {
		/* Not started, nothing to do */
		goto out;
	}

	wcn36xx_tm_cmd_stop(wcn);

out:
	mutex_unlock(&wcn->conf_mutex);
}
