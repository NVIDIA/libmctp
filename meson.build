project('libmctp',
	'c',
	version: '0.0.0',
	meson_version: '>=0.57.0',
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
  'smbus.c'
]

conf_data = configuration_data()
conf_data.set('HAVE_PCAP', get_option('capture').enabled() ? 1 : 0)

configure_file(
  input: 'config.h.in',
  output: 'config.h',
  configuration: conf_data,
)

libmctp = library('libmctp',
  sources,
  version: meson.project_version(),
  soversion: meson.project_version(),
  include_directories: include_directories('.'),
  install: true
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

subdir('utils')
subdir('ctrld')
subdir('vdm/nvidia')

subdir('tests')
