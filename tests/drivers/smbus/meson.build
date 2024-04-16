message('Compiling and installing smbus mctp module - mocked SMBUS kernel driver')

compiler = meson.get_compiler('c')
message('Compiler version: ' + compiler.version())

host_result = run_command('uname', '-r', check: true)
host = host_result.stdout().strip()
message('Host machine: ' + host)

# do not compile modules on WSL
if not host.to_lower().contains('wsl')
  cur_dir = meson.current_source_dir()
  message(cur_dir)

  option_C = '-C' + cur_dir
  make_file = '-f' + cur_dir + '/Makefile'

  r = run_command('make', option_C, make_file, 'all', check: true)
  message(r.stdout().strip())
else
  message('ERROR: on WSL mocked SMBUS kernel driver cannot be installed')
endif
