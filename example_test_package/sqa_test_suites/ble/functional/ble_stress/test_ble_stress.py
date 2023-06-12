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
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_start_stop_scan_1000_times_C19810(ble_dut, ble_client):
    iter_count = 1000

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    for i in range(0, iter_count):
        ble_client.interfaces.bluetooth.close()
        logger().info(f" ======= initialize ble adv in remote device for iteration {i+1}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address, f"ble initialization failed in remote device for iteration{i}"
        logger().info(f"ble client address of remote device for iteration {i} is {bt_client_address}")
        time.sleep(2)
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        ble_dut.interfaces.bluetooth.ble_stop_scanning()


# Written by himaja
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_BLE_continuousscanning_for_48_hours_C19829(wifi_dut, ble_client):
    # for the time being we are advetising with only one client need to add 9 other devices to do the ask
    logger().info("start ble in dut")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    logger().info("start ble scan in rd_1")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "ble initialization failed in remote device_1"
    time.sleep(2)
    scan_results = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address,
                                                               ble_scan_interval=int(500 / 0.625),
                                                               ble_scan_window=int(400 / 0.625), timeout=120)
    time_lapse = 60 * 48
    time.sleep(60 * time_lapse)
    # Enables the wifi power save in dut
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # Enables the bt power save in dut
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    logger().info(f" scan result '{scan_results}")
    assert scan_results, "ble devices not found"
    logger().info(f"Currently we are supporting this "
                  f"Check weather the DUT is able receive adverse report in 3 channel are not using sniffer")
    logger().info(f"found BT client address of {bt_client_address}")
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)
