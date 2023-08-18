project('libmctp',
	'c',
	version: '0.0.0',
	meson_version: '>=0.57.0',
	default_options: ['warning_level=3']
)

comp = meson.get_compiler('c')

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

libmctp = library('libmctp',
  sources,
  version: meson.project_version(),
  soversion: meson.project_version(),
  include_directories: include_directories('.'),
  install: true
)


subdir('utils')
subdir('ctrld')
subdir('vdm/nvidia')
