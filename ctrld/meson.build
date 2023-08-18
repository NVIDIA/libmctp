headers = [
  '.',
  '..'
]

sources = [
  'mctp-discovery-common.c',
  'mctp-discovery.c',
  '../mctp-json.c',
  '../mctp-socket.c',
  '../dbus_log_event.c',
  'mctp-encode.c',
  'mctp-sdbus.c',
  'mctp-spi-cmds.c',
  'mctp-ctrl-spi.c',
  'mctp-discovery-i2c.c',
  'mctp-ctrl.c',
  '../vdm/nvidia/mctp-vdm-commands.c',
  '../vdm/nvidia/mctp-vdm-encode.c',
]

comp = meson.get_compiler('c')

systemd = declare_dependency(dependencies: [comp.find_library('systemd')])
json_c = declare_dependency(dependencies: [comp.find_library('json-c')])

executable(
  'mctp-ctrl',
  sources,
  include_directories: include_directories(headers),
  dependencies: [systemd, json_c],
  link_with: libmctp,
  install: true
)
