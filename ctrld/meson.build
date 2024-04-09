headers = [
  '.',
  '..'
]

sources = [
  'mctp-discovery-common.c',
  'mctp-discovery.c',
  'mctp-encode.c',
  'mctp-sdbus.c',
  'mctp-spi-cmds.c',
  'mctp-ctrl-spi.c',
  'mctp-discovery-i2c.c',
  'mctp-ctrl.c',
  'dbus_log_event.c',
  '../vdm/nvidia/mctp-vdm-commands.c',
  '../vdm/nvidia/mctp-vdm-encode.c',
]

if get_option('enable-mockup-endpoint').enabled()
  sources += ['fsdyn-endpoint.c']
endif

if get_option('enable-fuzzctrl').enabled()
  sources += ['fuzz-test/mctp-ctrl-mockup.c']

  configure_file(
    copy: true,
    input: 'fuzz-test/config.json',
    install: false,
    output: 'mctp_test_cfg.json'
  )

  configure_file(
    copy: true,
    input: 'fuzz-test/nic_cfg.json',
    install: false,
    output: 'nic_cfg.json'
  )
endif

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
