/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Inert externs to satisfy the demux TU's binding table / daemon helpers.
 * Compiled in isolation (no libmctp binding headers) so the void* prototypes
 * do not clash with the real declarations; C links these by name only and
 * none are reached by the USB tx_pvt_message() path under test. */
#include <stdint.h>
#include <stdarg.h>

int sd_notify(int u, const char *s){ (void)u;(void)s; return 1; }
int sd_notifyf(int u, const char *f, ...){ (void)u;(void)f; return 1; }
int sd_listen_fds(int u){ (void)u; return 0; }

int  mctp_json_get_tokener_parse(void *a, const char *b){ (void)a;(void)b; return 1; }
int  mctp_json_get_eid_type(void *a, const char *b, void *c){ (void)a;(void)b;(void)c; return 0; }
int  mctp_json_i2c_get_common_params_mctp_demux(void *a,void*b,void*c,void*d,void*e){ (void)a;(void)b;(void)c;(void)d;(void)e; return 0; }
int  mctp_json_i2c_get_params_bridge_static_demux(void *a,void*b,void*c,void*d,void*e){ (void)a;(void)b;(void)c;(void)d;(void)e; return 0; }
int  mctp_json_i2c_get_params_static_demux(void *a,void*b,void*c,void*d){ (void)a;(void)b;(void)c;(void)d; return 0; }
int  mctp_json_i2c_get_params_pool_demux(void *a,void*b,void*c,void*d,void*e){ (void)a;(void)b;(void)c;(void)d;(void)e; return 0; }
void mctp_json_spi_get_common_params_mctp_demux(void *a,void*b,void*c){ (void)a;(void)b;(void)c; }

void *mctp_serial_init(void){ return 0; }
int   mctp_serial_open_path(void *a, const char *b){ (void)a;(void)b; return -1; }
void *mctp_binding_serial_core(void *a){ (void)a; return 0; }
int   mctp_serial_init_pollfd(void *a, void *b){ (void)a;(void)b; return 0; }
int   mctp_serial_read(void *a){ (void)a; return 0; }
void *mctp_astlpc_init_fileio(void){ return 0; }
void *mctp_binding_astlpc_core(void *a){ (void)a; return 0; }
void  mctp_astlpc_destroy(void *a){ (void)a; }
int   mctp_astlpc_init_pollfd(void *a, void *b){ (void)a;(void)b; return 0; }
int   mctp_astlpc_poll(void *a){ (void)a; return 0; }
void *mctp_astpcie_init_fileio(void){ return 0; }
void *mctp_binding_astpcie_core(void *a){ (void)a; return 0; }
void  mctp_astpcie_free(void *a){ (void)a; }
int   mctp_astpcie_init_pollfd(void *a, void *b){ (void)a;(void)b; return 0; }
int   mctp_astpcie_poll(void *a, int b){ (void)a;(void)b; return 0; }
int   mctp_astpcie_rx(void *a){ (void)a; return 0; }
void *mctp_spi_bind_init(void *a){ (void)a; return 0; }
void *mctp_binding_astspi_core(void *a){ (void)a; return 0; }
int   mctp_spi_init_pollfd(void *a, void *b){ (void)a;(void)b; return 0; }
int   mctp_spi_process(void *a){ (void)a; return 0; }
void *mctp_smbus_init(uint8_t a,uint8_t b,uint8_t c,uint8_t d,uint16_t e,uint8_t f,void*g){ (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; return 0; }
void *mctp_binding_smbus_core(void *a){ (void)a; return 0; }
int   mctp_smbus_init_pollfd(void *a, void *b){ (void)a;(void)b; return 0; }
int   mctp_smbus_poll(void *a){ (void)a; return 0; }
int   mctp_smbus_read(void *a){ (void)a; return 0; }
void *mctp_usb_init(void *cfg){ (void)cfg; return 0; }
void *mctp_binding_usb_core(void *a){ (void)a; return 0; }
int   mctp_usb_init_pollfd(void *a, void *b){ (void)a;(void)b; return 0; }
int   mctp_usb_handle_event(void *a){ (void)a; return 0; }
void  check_device_supports_mctp(void *a){ (void)a; }
void  find_and_set_pool_of_endpoints(void *a){ (void)a; }
