import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes,RS9116FeatureBitMap,RS9116ConfigFeatureBitMap,RS9116TCPIPFeatureBitMap,\
    RS9116ExtTCPIPFeatureBitMap,RS9116ExtCustomFeatureBitMap,RS9116CustomFeatureBitMap,RS9116PowerSaveProcedureTypes
from utf.utils.logger import get_logger
import time
from utf.utils.time_measurer import TimeMeasurer

def logger():
    return get_logger(__name__)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_ble_start_stop_scan_1000_times_C19810(ble_dut,ble_client):
    iter_count =3

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    for count in iter_count:
        count = count+1
        logger().info(f" ======= initialize ble adv in remote device {count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address, f"ble initialization failed in remote device{count}"
        logger().info(f"ble client address of remote device {count} is {bt_client_address}")
        time.sleep(5)
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
        time.sleep(2)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_ble_continuous_scan_C19819(ble_dut,ble_client):
    with TimeMeasurer() as t:
        ble_scan_window = 70
        ble_scan_interval = 50
        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"
        t_end = time.time() + 60 * 30
        while time.time() < t_end:
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert ble_client_address, f"ble initialization failed in remote device"

            time.sleep(5)
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address,
                                                         ble_scan_interval=ble_scan_interval/0.625,
                                                         ble_scan_window=ble_scan_window/0.625, timeout=120)
        time.sleep(2)
    logger().info(f"time taken for test {t.duration}")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_ble_continuous_scan_C19820(ble_dut,ble_client):
    with TimeMeasurer() as t:
        ble_scan_window = 5
        ble_scan_interval = 100
        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"
        t_end = time.time() + 60 * 30
        while time.time() < t_end:
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert ble_client_address, f"ble initialization failed in remote device"

            time.sleep(5)
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address,
                                                         ble_scan_interval=ble_scan_interval/0.625,
                                                         ble_scan_window=ble_scan_window/0.625, timeout=120)
        time.sleep(2)
    logger().info(f"time taken for test {t.duration}")