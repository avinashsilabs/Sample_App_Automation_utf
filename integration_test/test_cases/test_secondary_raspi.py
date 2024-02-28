import pytest
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BTSocketRole, BTClientLinkMode


def logger():
    return get_logger(__name__)


@pytest.fixture(autouse=True)
def reset_dut():
    # override the reset_dut fixture to do nothing
    pass

@pytest.mark.bt_client("secondary_raspi_bt_client")
@pytest.mark.test_src_map_id('SM11937')
def test_secondary_raspi_shell(bt_client):
    shell = bt_client.interfaces.shell
    rc, stdout, stderr = shell.execute("ls -al")
    assert rc == 0
    assert isinstance(stdout, bytes)
    assert isinstance(stderr, bytes)
    logger().info(stdout.decode())
    logger().info(stderr.decode())

@pytest.mark.bt_client("secondary_raspi_bt_client")
@pytest.mark.test_src_map_id('SM11942')
def test_secondary_raspi_bt(bt_client):
    bt = bt_client.interfaces.bluetooth
    bt.bt_adapter.set_link_mode(BTClientLinkMode.Master)
    with bt.bt_socket(
        mode=BTSocketRole.Server
    ) as bt_server_socket:
        bt_server_socket.create_server()
