headers = [
  '.',
  '..',
  '../..',
]

sources = [
  'mctp-vdm-nvda.c',
  'mctp-vdm-commands.c',
  'mctp-vdm-encode.c'
]

comp = meson.get_compiler('c')

systemd = declare_dependency(dependencies: [comp.find_library('systemd')])
json_c = declare_dependency(dependencies: [comp.find_library('json-c')])

deps = [systemd, json_c]

# Add usb to src if enabled from build env
if get_option('enable-usb').enabled()
    usb_lib = declare_dependency(dependencies: [comp.find_library('usb-1.0')])
    deps += [usb_lib]
endif

executable(
  'mctp-vdm-util',
  sources,
  include_directories: include_directories(headers),
  dependencies: deps,
  link_with: libmctp,
  install: true
)
