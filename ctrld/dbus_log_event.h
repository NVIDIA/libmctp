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
#ifndef _MCTP_DBUS_LOG_EVENT_H
#define _MCTP_DBUS_LOG_EVENT_H

#define REDFISH_ARG_LEN 256

#define EVT_INFO "xyz.openbmc_project.Logging.Entry.Level.Informational"
#define EVT_WARNING "xyz.openbmc_project.Logging.Entry.Level.Warning"
#define EVT_CRITICAL "xyz.openbmc_project.Logging.Entry.Level.Critical"

extern void doLog(sd_bus *bus, char *arg0, char *arg1, char *severity,
		  char *resolution);
#endif /* _MCTP_DBUS_LOG_EVENT_H */
