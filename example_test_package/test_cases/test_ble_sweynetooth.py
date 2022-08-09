def test_cpc(ble_sweynetooth):
    ble_sweynetooth.interfaces.docker_host.init()
    # ble_sweynetooth.interfaces.docker_host.pre_install()
    ble_sweynetooth.interfaces.docker_host.docker_host.execute_command("ls")
    # ble_sweynetooth.interfaces.docker_host.sample_shell_execute("python2.7 --version")