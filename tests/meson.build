
tests = [
    'test_astlpc',
    'test_bridge',
    'test_cmds',
    'test_core',
    'test_eid',
    'test_seq',
    'test_serial',
]

if get_option('tests').enabled()

    if get_option('mocked-drivers').enabled()
        subdir('drivers/aspeed_mctp')
        subdir('drivers/smbus')
        subdir('drivers/spidev')
    endif

    foreach t : tests
        test(
            t,
            executable(
                t.underscorify(),
                ['test-utils.c', t + '.c'],
                implicit_include_directories: false,
                build_rpath: get_option('oe-sdk').enabled() ? rpath : '',
                link_with: libmctp,
                include_directories: include_directories(['.', '..']),
            ),
        )
    endforeach

    # AP0_RELEASE_SLOT decode in mctp-vdm-util. The test #includes
    # vdm/nvidia/mctp-vdm-commands.c and supplies its own
    # mctp_client_send_recv(), which takes precedence over the one in libmctp
    # (a shared library), so no socket is needed.
    test(
        'test_ap0_release_slot',
        executable(
            'test_ap0_release_slot',
            [
                'vdm/test_ap0_release_slot.c',
                '../vdm/nvidia/mctp-vdm-encode.c',
            ],
            implicit_include_directories: false,
            build_rpath: get_option('oe-sdk').enabled() ? rpath : '',
            link_with: libmctp,
            dependencies: [json_c],
            include_directories: include_directories(
                ['.', '..', '../vdm/nvidia'],
            ),
        ),
    )
endif
