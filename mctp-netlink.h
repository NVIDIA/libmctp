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

#ifndef __MCTP_NETLINK_H__
#define __MCTP_NETLINK_H__

#include <linux/mctp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_INTERFACE_LEN 15 /*max length of interface name*/
#define MIN_EID		  8  /* minimum eid value per NETLINK spec*/
#define DEFAULT_MTU	  68 /*Base MTU value*/

/* Structure Definition */
struct g_interface_data {
	char ifname[MAX_INTERFACE_LEN]; /*Local interface name*/
	uint8_t nl_sd;			/*Netlink socket*/
	uint8_t ifeid;			/*Local interface EID*/
};

struct g_hw_info {
	uint8_t phy_addr[MAX_ADDR_LEN]; /*HW address of endpoint*/
	uint8_t phy_addlen;		/*HW address len*/
};

/* Function prototypes */

/**
 * @brief Open the AF_NETLINK socket interface, return success only if
 *        Socket is opened and Register with the message type.
 *
 * @param[in] ifname  Local interface name
 * @param[in] eid     Local interface eid
 *
 * @return 0 on success, -1 on failure
 */
int mctp_nl_socket_init(char *ifname, mctp_eid_t eid);

/**
 * @brief Set network route for eid to local interface 
 *
 * @param[in] eid  Endpoint eid to set route for
 *
 * @return 0 on success, -1 on failure
 */
int mctp_nl_add_route(mctp_eid_t eid);

/**
 * @brief Set network neighbour for eid to local interface 
 *
 * @param[in] eid  Endpoint eid to set route for
 *
 * @return 0 on success, -1 on failure
 */
int mctp_nl_add_neigh(mctp_eid_t eid);

/**
 * @brief Using pattern cstring extract out interface name
 *        which has alternate name substring to pattern cstring 
 *
 * @param[in] ifname   Local interface name with altname substring
 *                     to pattern cstring
 * @param[in] pattern  String which is substring to altname of
 *                     local interface
 *
 * @return 0 on success, -1 on failure
 */
int mctp_nl_get_ifname(char *ifname, char *pattern);

/**
 * @brief Update global context of local interface data and
 *        endpoint physical address for extended socket addressing
 *
 * @param[in] ifname      Local interface name
 * @param[in] phy_addr    Endpoint physical address for extended socket address
 * @param[in] phy_addlen  Length of endpoint physical address for
 *                        extended socket address
 * @param[in] ifeid       Local interface EID
 *
 * @return 0 on success, -1 on failure
 */
int update_interface_info(const char *ifname, const uint8_t *phy_addr,
			  const uint8_t phy_addlen, const uint8_t ifeid);

extern unsigned int if_nametoindex(const char *ifname);

#ifdef __cplusplus
}
#endif
#endif /* __MCTP_NETLINK_H__ */
