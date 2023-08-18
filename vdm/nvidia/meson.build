headers = [
  '.',
  '..',
  '../..',
]

sources = [
  'mctp-vdm-nvda.c',
  'mctp-vdm-commands.c',
  'mctp-vdm-encode.c',
  '../../mctp-socket.c',
]

comp = meson.get_compiler('c')

systemd = declare_dependency(dependencies: [comp.find_library('systemd')])

executable(
  'nvidia-mctp-vdm-util',
  sources,
  include_directories: include_directories(headers),
  dependencies: [systemd],
  link_with: libmctp,
  install: true
)
