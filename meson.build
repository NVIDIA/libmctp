project('libmctp',
	'c',
	version: '0.0.0',
	meson_version: '>=0.58.0',
	default_options: ['warning_level=3']
)

comp = meson.get_compiler('c')

add_project_arguments('-Werror', language: ['c', 'cpp'])
add_project_arguments('-Wall', language: ['c', 'cpp'])
add_project_arguments('-DMCTP_LOG_STDERR', language: ['c', 'cpp'])
add_project_arguments('-DMCTP_HAVE_FILEIO', language: ['c', 'cpp'])
add_project_arguments('-DMCTP_HAVE_STDIO', language: ['c', 'cpp'])
add_project_arguments('-DMCTP_DEFAULT_ALLOC', language: ['c', 'cpp'])

sources = [
  'alloc.c',
  'astlpc.c',
  'astpcie.c',
  'astspi.c',
  'core.c',
  'crc32.c',
  'crc32c.c',
  'glacier-spb-ap.c',
  'log.c',
  'serial.c',
  'smbus.c',
  'mctp-json.c',
  'mctp-socket.c'
]

json_c = declare_dependency(dependencies: [comp.find_library('json-c')])

deps = [json_c]

# Add USB functionality to SRC 
if get_option('enable-usb').enabled()
    sources += 'usb.c'
    summary('enable-usb','-DENABLE_USB', section : 'Enabled Features')
    add_project_arguments('-DENABLE_USB', language: ['c', 'cpp'])
    usb_lib = declare_dependency(dependencies: [comp.find_library('usb-1.0')])
    deps += [usb_lib]

    # Check if batching is enabled
    if get_option('mctp-batch-tx').enabled()
      summary('mctp-batch-tx','-DMCTP_BATCH_TX', section : 'Enabled Features')
      add_project_arguments('-DMCTP_BATCH_TX', language: ['c', 'cpp'])
    endif

endif

if get_option('enable-mockup-endpoint').enabled()
  summary('enable-mockup-endpoint','-DMOCKUP_ENDPOINT', section : 'Enabled mockup endpoint')
  add_project_arguments('-DMOCKUP_ENDPOINT', language: ['c', 'cpp'])
endif

conf_data = configuration_data()
conf_data.set('HAVE_PCAP', get_option('capture').enabled() ? 1 : 0)

conf_data.set('USE_FUZZ_CTRL', get_option('enable-fuzzctrl').enabled() ? 1 : 0)

configure_file(
  input: 'config.h.in',
  output: 'config.h',
  configuration: conf_data,
)

libmctp = library('mctp',
  sources,
  version: meson.project_version(),
  soversion: meson.project_version(),
  include_directories: include_directories('.'),
  install: true,
  dependencies: deps
)

install_headers(
  'libmctp-externals.h'
)

systemd_system_unit_dir = dependency('systemd').get_variable(
          pkgconfig: 'systemdsystemunitdir')

configure_file(
    copy: true,
    input: 'systemd/system/mctp-pcie-demux.service',
    install: true,
    install_dir: systemd_system_unit_dir,
    output: 'mctp-pcie-demux.service',
)

configure_file(
    copy: true,
    input: 'systemd/system/mctp-pcie-demux.socket',
    install: true,
    install_dir: systemd_system_unit_dir,
    output: 'mctp-pcie-demux.socket',
)

configure_file(
    copy: true,
    input: 'systemd/system/mctp-pcie-ctrl.service',
    install: true,
    install_dir: systemd_system_unit_dir,
    output: 'mctp-pcie-ctrl.service',
)

if get_option('enable-usb').enabled()
  configure_file(
      copy: true,
      input: 'systemd/system/mctp-usb-demux.service',
      install: true,
      install_dir: systemd_system_unit_dir,
      output: 'mctp-usb-demux.service',
  )

  configure_file(
      copy: true,
      input: 'systemd/system/mctp-usb-demux.socket',
      install: true,
      install_dir: systemd_system_unit_dir,
      output: 'mctp-usb-demux.socket',
  )

  configure_file(
      copy: true,
      input: 'systemd/system/mctp-usb-ctrl.service',
      install: true,
      install_dir: systemd_system_unit_dir,
      output: 'mctp-usb-ctrl.service',
  )
endif

configure_file(
    copy: true,
    input: 'systemd/system/mctp-spi-demux.service',
    install: true,
    install_dir: systemd_system_unit_dir,
    output: 'mctp-spi-demux.service',
)

configure_file(
    copy: true,
    input: 'systemd/system/mctp-spi-demux.socket',
    install: true,
    install_dir: systemd_system_unit_dir,
    output: 'mctp-spi-demux.socket',
)

configure_file(
    copy: true,
    input: 'systemd/system/mctp-spi-ctrl.service',
    install: true,
    install_dir: systemd_system_unit_dir,
    output: 'mctp-spi-ctrl.service',
)

configure_file(
  copy: true,
  input: 'mctp-pcie-ctrl',
  install: true,
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x',
  output: 'mctp-pcie-ctrl'
)

configure_file(
  copy: true,
  input: 'mctp-spi-ctrl',
  install: true,
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x',
  output: 'mctp-spi-ctrl'
)

configure_file(
  copy: true,
  input: 'mctp-usb-ctrl',
  install: true,
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x',
  output: 'mctp-usb-ctrl'
)

subdir('utils')
subdir('ctrld')
subdir('vdm/nvidia')

subdir('tests')
