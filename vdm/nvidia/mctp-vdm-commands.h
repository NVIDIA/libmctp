/*
 * SPDX-FileCopyrightText: Copyright (c)  NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#ifndef __MCTP_VDM_COMMANDS_H__
#define __MCTP_VDM_COMMANDS_H__

#ifdef __cplusplus
extern "C" {
#endif

#define VERBOSE_EN	1
#define VERBOSE_DISABLE 0

int selftest(int fd, uint8_t tid, uint8_t *payload, int length,
	     uint8_t verbose);
int boot_complete_v1(int fd, uint8_t tid, uint8_t verbose);
int boot_complete_v2(int fd, uint8_t tid, uint8_t valid, uint8_t slot,
		     uint8_t verbose);
int set_heartbeat_enable(int fd, uint8_t tid, int enable, uint8_t verbose);
int heartbeat(int fd, uint8_t tid, uint8_t verbose);
int query_boot_status(int fd, uint8_t tid, uint8_t verbose, uint8_t more);
int query_boot_status_json(int fd, uint8_t tid);
int background_copy(int fd, uint8_t tid, uint8_t code, uint8_t verbose);
int background_copy_json(int fd, uint8_t tid, uint8_t code);
int download_log(int fd, uint8_t eid, char *dl_path, uint8_t verbose);
int restart_notification(int fd, uint8_t tid, uint8_t verbose);
int debug_token_erase(int fd, uint8_t tid, uint8_t verbose);
int debug_token_query(int fd, uint8_t tid, uint8_t verbose);
int debug_token_query_v2(int fd, uint8_t tid, uint8_t verbose);
int debug_token_install(int fd, uint8_t tid, uint8_t *payload, size_t length,
			uint8_t verbose);
int certificate_install(int fd, uint8_t tid, uint8_t *payload, size_t length,
			uint8_t verbose);
int in_band(int fd, uint8_t tid, uint8_t code, uint8_t verbose);
int boot_ap(int fd, uint8_t tid, uint8_t verbose);
int set_query_boot_mode(int fd, uint8_t tid, uint8_t code, uint8_t verbose);

int cak_install(int fd, uint8_t tid, uint8_t *payload, size_t length,
		uint8_t verbose);
int cak_lock(int fd, uint8_t tid, uint8_t *payload, size_t length,
	     uint8_t verbose);
int cak_test(int fd, uint8_t tid, uint8_t verbose);
int dot_disable(int fd, uint8_t tid, uint8_t *payload, size_t length,
		uint8_t verbose);
int dot_token_install(int fd, uint8_t tid, uint8_t *payload, size_t length,
		      uint8_t verbose);
int force_grant_revoke(int fd, uint8_t tid, uint8_t code, uint8_t verbose);
int reset_erot(int fd, uint8_t tid, uint8_t verbose);
int revoke_ap_otp(int fd, uint8_t tid, uint8_t code, uint8_t verbose);
#ifdef __cplusplus
}
#endif

#endif /* __MCTP_VDM_COMMANDS_H__ */
