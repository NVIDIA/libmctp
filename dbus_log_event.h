#ifndef _MCTP_DBUS_LOG_EVENT_H
#define _MCTP_DBUS_LOG_EVENT_H

#define EVT_INFO "xyz.openbmc_project.Logging.Entry.Level.Informational"
#define EVT_WARNING "xyz.openbmc_project.Logging.Entry.Level.Warning"
#define EVT_CRITICAL "xyz.openbmc_project.Logging.Entry.Level.Critical"

extern void doLog(sd_bus *bus, char *arg0, char *arg1, char *severity,
		  char *resolution);
#endif /* _MCTP_DBUS_LOG_EVENT_H */
