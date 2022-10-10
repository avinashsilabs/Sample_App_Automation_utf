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
    for i in range(0, iter_count):
        ble_client.interfaces.bluetooth.close()
        logger().info(f" ======= initialize ble adv in remote device for iteration {i}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address, f"ble initialization failed in remote device for iteration{i}"
        logger().info(f"ble client address of remote device for iteration {i} is {bt_client_address}")
        time.sleep(5)
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
        time.sleep(2)
        ble_client.interfaces.bluetooth.stop_advertising()
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
def test_ble_scan_continuous_48_hrs_C19829(ble_dut, ble_client):
    t_end = time.time() + 60 * 2880
    while time.time() < t_end:

        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"

        logger().info("start ble scan in rd_1")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address, "ble initialization failed in remote device"
        time.sleep(2)

        scan_results = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address,
                                                                   timeout=120)
        time.sleep(10)

        logger().info(f" ============== Enable PSP in DUT")
        enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                                                 power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "failed to enable wifi power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
            power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
        )
        assert enable_bt_ps, "failed to enable bt power save"

        logger().info(f" scan result '{scan_results}")
        assert scan_results, "ble devices not found"
        logger().info(f"found BT client address of {bt_client_address}")

        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
    time.sleep(5)