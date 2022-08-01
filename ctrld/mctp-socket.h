#ifndef __MCTP_SOCKET_H__
#define __MCTP_SOCKET_H__

#ifdef __cplusplus
extern "C" {
#endif

mctp_requester_rc_t mctp_usr_socket_init(int *, const char *, uint8_t );

mctp_requester_rc_t mctp_client_recv(mctp_eid_t eid, int mctp_fd,
                                     uint8_t **mctp_resp_msg,
                                     size_t *resp_msg_len);

mctp_requester_rc_t mctp_client_send(mctp_eid_t dest_eid, int mctp_fd,
                                     uint8_t msgtype, const uint8_t *mctp_req_msg,
                                     size_t req_msg_len);
mctp_requester_rc_t mctp_client_send_recv(mctp_eid_t eid, int fd, uint8_t msgtype,
                                           const uint8_t *req_msg, size_t req_len,
                                           uint8_t **resp_msg, size_t *resp_len);
#ifdef __cplusplus
}
#endif

#endif /* __MCTP_SOCKET_H__ */
