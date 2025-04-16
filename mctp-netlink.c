/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mctp-netlink.h"
#include <string.h>
#include "libmctp.h"
#include "libmctp-log.h"
#include <err.h>
#include <errno.h>

struct g_interface_data local_interface;
struct g_hw_info endpoint_hwinfo;

struct mctp_rtalter_msg {
	struct nlmsghdr nh;
	struct rtmsg rtmsg;
	uint8_t rta_buff[RTA_SPACE(sizeof(mctp_eid_t)) + // eid
			 RTA_SPACE(sizeof(int)) +	 // ifindex
			 100 // space for MTU, nexthop etc
	];
};

int update_interface_info(const char *ifname, const uint8_t *phy_addr,
			  const uint8_t phy_addlen, const uint8_t ifeid)
{
	if (!ifname || !phy_addr) {
		MCTP_ERR("%s invalid arg: failed to update interface data\n",
			 __func__);
		return -1;
	}
	memset(endpoint_hwinfo.phy_addr, 0x0, MAX_ADDR_LEN);
	memcpy(endpoint_hwinfo.phy_addr, phy_addr, phy_addlen);
	endpoint_hwinfo.phy_addlen = phy_addlen;
	memset(local_interface.ifname, '\0', MAX_INTERFACE_LEN);
	strncpy(local_interface.ifname, ifname, MAX_INTERFACE_LEN - 1);
	local_interface.ifeid = ifeid;
	return 0;
}

int mctp_nl_socket_init()
{
	struct {
		struct nlmsghdr nh;
		struct ifaddrmsg ifmsg;
		struct rtattr rta;
		uint8_t data[4];
	} msg = { 0 };

	mctp_eid_t eid = local_interface.ifeid;
	struct sockaddr_nl nl_addr = { 0 };
	int ifindex = 0;
	int rc = 0;

	ifindex = if_nametoindex(local_interface.ifname);
	if (ifindex <= 0) {
		MCTP_ERR("%s Invalid interface index %d\n", __func__, ifindex);
		return -1;
	}
	msg.nh.nlmsg_type = RTM_NEWADDR;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg.ifmsg.ifa_index = ifindex;
	msg.ifmsg.ifa_family = AF_MCTP;

	msg.rta.rta_type = IFA_LOCAL;
	msg.rta.rta_len = RTA_LENGTH(sizeof(eid));
	memcpy(RTA_DATA(&msg.rta), &eid, sizeof(eid));

	msg.nh.nlmsg_len =
		NLMSG_LENGTH(sizeof(msg.ifmsg)) + RTA_SPACE(sizeof(eid));
	nl_addr.nl_family = AF_NETLINK;
	nl_addr.nl_pid = 0;

	if (!local_interface.nl_sd) {
		/* Setup AF_NETLINK socket*/
		int nl_sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
		int opt = 1;
		if (nl_sd < 0) {
			MCTP_ERR("open AF_NETLINK socket failed\n");
			rc = -1;
			goto out;
		}

		if ((rc = setsockopt(nl_sd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
				     &opt, sizeof(opt))) < 0) {
			MCTP_ERR(
				"AF_NETLINK socket[%d] setsockopt failed rc[%d] %s\n",
				nl_sd, rc, strerror(errno));
			goto out;
		}

		opt = 1;
		if ((rc = setsockopt(nl_sd, SOL_NETLINK, NETLINK_EXT_ACK, &opt,
				     sizeof(opt))) < 0) {
			MCTP_ERR(
				"AF_NETLINK socket[%d] setsockopt failed rc[%d] %s\n",
				nl_sd, rc, strerror(errno));
			goto out;
		}

		local_interface.nl_sd = nl_sd;
	}
	/* Bind local eid to interface ifindex */
	if ((rc = sendto(local_interface.nl_sd, &msg.nh, msg.nh.nlmsg_len, 0,
			 (struct sockaddr *)&nl_addr, sizeof(nl_addr))) < 0) {
		MCTP_ERR(
			"%s failed to setup local EID %d for interface %s rc [%d] %s\n",
			__func__, eid, local_interface.ifname, rc,
			strerror(errno));
		goto out;
	}
	return 0;
out:
	if (local_interface.nl_sd != 0) {
		close(local_interface.nl_sd);
		local_interface.nl_sd = 0;
	}
	return rc;
}

size_t mctp_put_rtnlmsg_attr(struct rtattr **prta, size_t *rta_len,
			     unsigned short type, const void *value,
			     size_t val_len)
{
	struct rtattr *rta = *prta;
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(val_len);
	memcpy(RTA_DATA(rta), value, val_len);
	*prta = RTA_NEXT(*prta, *rta_len);
	return RTA_SPACE(val_len);
}

static int fill_rtalter_args(struct mctp_rtalter_msg *msg, struct rtattr **prta,
			     size_t *prta_len, mctp_eid_t eid)
{
	struct rtattr *rta;
	size_t rta_len;
	int ifindex = if_nametoindex(local_interface.ifname);

	rta_len = 0;
	memset(msg, 0x0, sizeof(*msg));
	msg->nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	msg->rtmsg.rtm_family = AF_MCTP;
	msg->rtmsg.rtm_type = RTN_UNICAST;
	msg->rtmsg.rtm_dst_len = 0;

	msg->nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg->rtmsg));
	rta_len = sizeof(msg->rta_buff);
	rta = (void *)msg->rta_buff;
	msg->nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len, RTA_DST,
						   &eid, sizeof(eid));
	msg->nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len, RTA_OIF,
						   &ifindex, sizeof(ifindex));

	if (prta)
		*prta = rta;
	if (prta_len)
		*prta_len = rta_len;

	return 0;
}

int mctp_nl_add_neigh(mctp_eid_t eid)
{
	struct {
		struct nlmsghdr nh;
		struct ndmsg ndmsg;
		uint8_t rta_buff[RTA_SPACE(1) + RTA_SPACE(MAX_ADDR_LEN)];
	} msg = { 0 };

	size_t rta_len = sizeof(msg.rta_buff);
	struct rtattr *rta = (void *)msg.rta_buff;
	int ifindex = if_nametoindex(local_interface.ifname);
	struct sockaddr_nl addr = { 0 };
	int rc = 0;

	msg.nh.nlmsg_type = RTM_NEWNEIGH;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg.ndmsg.ndm_ifindex = ifindex;
	msg.ndmsg.ndm_family = AF_MCTP;
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ndmsg));
	msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len, NDA_DST, &eid,
						  sizeof(eid));
	msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len, NDA_LLADDR,
						  endpoint_hwinfo.phy_addr,
						  endpoint_hwinfo.phy_addlen);

	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;

	if ((rc = sendto(local_interface.nl_sd, &msg.nh, msg.nh.nlmsg_len, 0,
			 (struct sockaddr *)&addr, sizeof(addr))) < 0) {
		MCTP_ERR("failed set neighbour for eid %d, rc[%d] %s\n", eid,
			 rc, strerror(errno));
		return rc;
	}

	return 0;
}

int mctp_nl_add_route(mctp_eid_t eid)
{
	struct mctp_rtalter_msg msg = { 0 };
	struct rtattr *rta;
	size_t rta_len;
	int rc = 0;
	struct sockaddr_nl addr = { 0 };

	rta_len = 0;
	/* Fill eid and interface index*/
	rc = fill_rtalter_args(&msg, &rta, &rta_len, eid);
	if (rc) {
		return -1;
	}
	msg.nh.nlmsg_type = RTM_NEWROUTE;
	uint32_t mtu = DEFAULT_MTU;

	if (mtu != 0) {
		/* Nested
        RTA_METRICS
            RTAX_MTU
        */
		struct rtattr *rta1;
		size_t rta_len1, space1;
		uint8_t buff1[100];

		rta1 = (void *)buff1;
		rta_len1 = sizeof(buff1);
		space1 = 0;
		space1 += mctp_put_rtnlmsg_attr(&rta1, &rta_len1, RTAX_MTU,
						&mtu, sizeof(mtu));
		msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(
			&rta, &rta_len, RTA_METRICS | NLA_F_NESTED, buff1,
			space1);
	}

	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;

	if ((rc = sendto(local_interface.nl_sd, &msg.nh, msg.nh.nlmsg_len, 0,
			 (struct sockaddr *)&addr, sizeof(addr))) < 0) {
		MCTP_ERR(
			"failed to set route for eid %d to interface %s, rc[%d] %s\n",
			eid, local_interface.ifname, rc, strerror(errno));
		return rc;
	}

	return 0;
}

int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		       int len, unsigned short flags)
{
	unsigned short type;
	type = 0;
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		MCTP_ERR("!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);

	return 0;
}
static inline char *rta_getattr_str(const struct rtattr *rta)
{
	return (char *)RTA_DATA(rta);
}

static int parse_getlink_dump(struct nlmsghdr *nlh, uint32_t len, char *ifname,
			      char *pattern)
{
	struct ifinfomsg *info;
	bool found = false;

	for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_type == NLMSG_DONE)
			return found ? 0 : 1; // 1: continue reading

		if (nlh->nlmsg_type == NLMSG_ERROR)
			return -1;

		if (NLMSG_PAYLOAD(nlh, 0) < sizeof(*info))
			return -1;

		info = NLMSG_DATA(nlh);
		if (!info->ifi_index)
			continue;

		int rlen = NLMSG_PAYLOAD(nlh, sizeof(*info));
		struct rtattr *tb[IFLA_MAX + 1];

		parse_rtattr_flags(tb, IFLA_MAX, IFLA_RTA(NLMSG_DATA(info)),
				   rlen, NLA_F_NESTED);
		if (tb[IFLA_PROP_LIST]) {
			struct rtattr *i, *proplist = tb[IFLA_PROP_LIST];
			int rem = RTA_PAYLOAD(proplist);

			for (i = RTA_DATA(proplist); RTA_OK(i, rem);
			     i = RTA_NEXT(i, rem)) {
				if (i->rta_type != IFLA_ALT_IFNAME)
					continue;
				/*Compare altname with  pattern to get interface name*/
				char *alt_name = rta_getattr_str(i);
				if (strstr(alt_name, pattern)) {
					strncpy(ifname, alt_name,
						MAX_INTERFACE_LEN - 1);
					ifname[MAX_INTERFACE_LEN - 1] = '\0';
					return 0;
				}
			}
		}
	}
	return 1; // Continue reading more messages
}

int mctp_nl_get_ifname(char *ifname, char *pattern)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifmsg;
	} msg = { 0 };
	struct sockaddr_nl addr;
	socklen_t addrlen;
	size_t buflen;
	void *buf;
	int rc;

	addrlen = 0;
	buf = NULL;
	buflen = 0;
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));
	msg.nh.nlmsg_type = RTM_GETLINK;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	msg.ifmsg.ifi_family = AF_MCTP;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	int nl_sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	rc = sendto(nl_sd, &msg.nh, msg.nh.nlmsg_len, 0,
		    (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		MCTP_ERR("failed to send GETLINK mssg: rc[%d], %s\n", rc,
			 strerror(errno));
		return rc;
	}

	addrlen = sizeof(addr);
	bool found = false;
	for (;;) {
		rc = recvfrom(nl_sd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL, NULL);
		if (rc < 0) {
			MCTP_ERR(
				"failed to find response for GETLINK: rc[%d] %s\n",
				rc, strerror(errno));
			break;
		}

		if ((size_t)rc > buflen) {
			char *tmp;
			buflen = rc;
			tmp = realloc(buf, buflen);
			if (!tmp) {
				rc = -ENOMEM;
				break;
			}
			buf = tmp;
		}

		rc = recvfrom(nl_sd, buf, buflen, 0, (struct sockaddr *)&addr,
			      &addrlen);
		if (rc < 0) {
			MCTP_ERR(
				"failed to receive GETLINK response: rc[%d] %s\n",
				rc, strerror(errno));
			break;
		}

		rc = parse_getlink_dump(buf, rc, ifname, pattern);
		if (rc < 0) {
			MCTP_ERR("failed to parse netlink response: rc[%d]\n",
				 rc);
			break;
		}
		if (rc == 0) {
			found = true;
			break;
		}
		// rc == 1 means continue reading
	}

	free(buf);
	close(nl_sd);

	return found ? 0 : -ENODEV;
}
