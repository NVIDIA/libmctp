tests = [
  'test_astlpc',
  'test_bridge',
  'test_cmds',
  'test_core',
  'test_eid',
  'test_seq',
  'test_serial'
]

if get_option('tests').enabled()
foreach t : tests
  test(t, executable(t.underscorify(), ['test-utils.c', t + '.c'],
                     implicit_include_directories: false,
		     build_rpath: get_option('oe-sdk').enabled() ? rpath : '',
		     link_with: libmctp,
		     include_directories: include_directories(['.', '..']),
		     ))
endforeach
endif
