#ifndef __MCTP_VDM_COMMANDS_H__
#define __MCTP_VDM_COMMANDS_H__

#ifdef __cplusplus
extern "C" {
#endif

int selftest(int fd, uint8_t tid, char *payload, int length);
int boot_complete_v1(int fd, uint8_t tid);
int boot_complete_v2(int fd, uint8_t tid, uint8_t valid, uint8_t slot);
int set_heartbeat_enable(int fd, uint8_t tid, int enable);
int heartbeat(int fd, uint8_t tid);
int query_boot_status(int fd, uint8_t tid);
int background_copy(int fd, uint8_t tid, uint8_t code);
int download_log(int fd, uint8_t eid, char *dl_path, uint8_t verbose);
int restart_notification(int fd, uint8_t tid);

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_VDM_COMMANDS_H__ */
