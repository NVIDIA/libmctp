#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <systemd/sd-bus.h>

#define BUFFER_LENGTH 1024

#define BUSCTL_COMMAND "busctl"
#define LOG_SERVICE "xyz.openbmc_project.Logging"
#define LOG_PATH "/xyz/openbmc_project/logging"
#define LOG_CREATE_INTERFACE "xyz.openbmc_project.Logging.Create"
#define LOG_CREATE_FUNCTION "Create"
#define LOG_CREATE_SIGNATURE "ssa{ss}"

static int logCallback(sd_bus_message *m, void *userdata,
		       sd_bus_error *ret_error)
{
	(void)userdata;
	(void)m;

	if (sd_bus_error_is_set(ret_error))
		fprintf(stderr, "Creating log entry failed: %s: %s\n",
			ret_error->name, ret_error->message);

	return 0;
}

static void createLog(sd_bus *bus, char *message, char *arg0, char *arg1,
		      char *severity, char *resolution)
{
	char args[BUFFER_LENGTH];

	snprintf(args, BUFFER_LENGTH, "%s , %s", arg0, arg1);

	if (resolution) {
		if (sd_bus_call_method_async(
			    bus, NULL, LOG_SERVICE, LOG_PATH,
			    LOG_CREATE_INTERFACE, LOG_CREATE_FUNCTION,
			    logCallback, NULL, LOG_CREATE_SIGNATURE, message,
			    severity, 4, "REDFISH_MESSAGE_ID", message,
			    "REDFISH_MESSAGE_ARGS", args,
			    "xyz.openbmc_project.Logging.Entry.Resolution",
			    resolution, "namespace", "FWUpdate") < 0) {
			fprintf(stderr, "Warning: Unable to create SDBUS log (%s) for msg: %s\n", severity, message);
		}
	}
	return;
}

void doLog(sd_bus *bus, char *arg0, char *arg1, char *severity,
	   char *resolution)
{
	createLog(bus, "ResourceEvent.1.0.ResourceErrorsDetected", arg0, arg1,
		  severity, resolution);
}
