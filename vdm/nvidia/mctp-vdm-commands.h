#ifndef __MCTP_VDM_COMMANDS_H__
#define __MCTP_VDM_COMMANDS_H__

#ifdef __cplusplus
extern "C" {
#endif

#define VERBOSE_EN 1
#define VERBOSE_DISABLE 0

int selftest(int fd, uint8_t tid, uint8_t *payload, int length,
	     uint8_t verbose);
int boot_complete_v1(int fd, uint8_t tid, uint8_t verbose);
int boot_complete_v2(int fd, uint8_t tid, uint8_t valid, uint8_t slot,
		     uint8_t verbose);
int set_heartbeat_enable(int fd, uint8_t tid, int enable, uint8_t verbose);
int heartbeat(int fd, uint8_t tid, uint8_t verbose);
int query_boot_status(int fd, uint8_t tid, uint8_t verbose);
int background_copy(int fd, uint8_t tid, uint8_t code, uint8_t verbose);
int download_log(int fd, uint8_t eid, char *dl_path, uint8_t verbose);
int restart_notification(int fd, uint8_t tid, uint8_t verbose);
int debug_token_erase(int fd, uint8_t tid, uint8_t verbose);
int debug_token_query(int fd, uint8_t tid, uint8_t verbose);
int debug_token_install(int fd, uint8_t tid, uint8_t *payload, size_t length,
			uint8_t verbose);
int certificate_install(int fd, uint8_t tid, uint8_t *payload, size_t length,
			uint8_t verbose);

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_VDM_COMMANDS_H__ */
