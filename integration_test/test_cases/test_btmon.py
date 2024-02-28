import time
import pytest


@pytest.mark.bt_clients(["raspi_bt_client", "secondary_raspi_bt_client"])
@pytest.mark.test_src_map_id('SM11851')
def test_bt_mon_bt_clients(bt_clients):

    assert len(bt_clients) == 2

    bt_client_1 = bt_clients[0]
    bt_client_2 = bt_clients[1]

    with bt_client_2.interfaces.bluetooth.ble_logs(
        start_collecting_logs=True,
        bt_log_path=f"reports/ble_client_2_bt_mon{int(time.time())}.log",
    ):
        with bt_client_1.interfaces.bluetooth.ble_logs(
            start_collecting_logs=True,
            bt_log_path=f"reports/ble_client_1_bt_mon{int(time.time())}.log",
        ):
            bt_client_address = bt_client_2.interfaces.bluetooth.start_spp_master(
                None, None
            )
            assert bt_client_address is not None
            time.sleep(3)

            bt_client_address = bt_client_1.interfaces.bluetooth.start_spp_master(
                None, None
            )
            assert bt_client_address is not None
            time.sleep(3)


@pytest.mark.ble_clients(["raspi_ble_client", "secondary_raspi_ble_client"])
@pytest.mark.test_src_map_id('SM11854')
def test_bt_mon_ble_clients(ble_clients):

    assert len(ble_clients) == 2

    ble_client_1 = ble_clients[0]
    ble_client_2 = ble_clients[1]

    with ble_client_2.interfaces.bluetooth.ble_logs(
        start_collecting_logs=True,
        bt_log_path=f"reports/ble_client_2_bt_mon{int(time.time())}.log",
    ):
        with ble_client_1.interfaces.bluetooth.ble_logs(
                start_collecting_logs=True,
                bt_log_path=f"reports/ble_client_1_bt_mon{int(time.time())}.log",
        ):

            ble_client_address = ble_client_2.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=None
            )
            assert ble_client_address is not None
            time.sleep(3)

            ble_client_address = ble_client_1.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=None
            )
            assert ble_client_address is not None
            time.sleep(3)
