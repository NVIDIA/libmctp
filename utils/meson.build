headers = [
  '.',
  '..'
]

sources = [
  'mctp-demux-daemon.c',
  '../mctp-json.c'
]

comp = meson.get_compiler('c')

systemd = declare_dependency(dependencies: [comp.find_library('systemd')])
json_c = declare_dependency(dependencies: [comp.find_library('json-c')])

executable(
  'mctp-demux-daemon',
  sources,
  include_directories: include_directories(headers),
  dependencies: [systemd, json_c],
  link_with: libmctp,
  install: true
)
