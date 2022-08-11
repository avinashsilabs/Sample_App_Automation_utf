import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes,RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes, \
     RS9116ExtCustomFeatureBitMap, RS9116FeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116BTFeatureBitMap
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BLEDeviceState
import time

ping_count = 10

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Author: Vishakha
"""

# BLE slave latency C19889
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19889(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19889"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status, "Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x06 0x00",
                                                                                Connection_Interval_Max="0x06 0x00",
                                                                                Max_Latency="0x05 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")


# BLE slave latency C19890
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19890(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19890"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status, "Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x0C 0x00",
                                                                                Connection_Interval_Max="0x0C 0x00",
                                                                                Max_Latency="0x05 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE disconnect successful")


# BLE slave latency C19891
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19891(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19891"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status, "Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x18 0x00",
                                                                                Connection_Interval_Max="0x18 0x00",
                                                                                Max_Latency="0x05 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")


# BLE slave latency C19892
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19892(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19892"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status, "Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x30 0x00",
                                                                                Connection_Interval_Max="0x30 0x00",
                                                                                Max_Latency="0x05 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")


# BLE slave latency C19893
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19893(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19893"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status, "Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x60 0x00",
                                                                                Connection_Interval_Max="0x60 0x00",
                                                                                Max_Latency="0x05 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")


# BLE slave latency C19894
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19894(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19894"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status, "Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0xC0 0x00",
                                                                                Connection_Interval_Max="0xC0 0x00",
                                                                                Max_Latency="0x05 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")


#BLE slave latency C19895
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19895(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19895"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x80 0x01",
                                                                                Connection_Interval_Max="0x80 0x01",
                                                                                Max_Latency="0x05 0x00",
                                                                                Supervision_Timeout="0x80 0x02",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE disconnect successful")



#BLE slave latency C19896
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19896(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19896"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x00 0x03",
                                                                                Connection_Interval_Max="0x00 0x03",
                                                                                Max_Latency="0x05 0x00",
                                                                                Supervision_Timeout="0x00 0x05",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19897
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19897(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19897"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x00 0x06",
                                                                                Connection_Interval_Max="0x00 0x06",
                                                                                Max_Latency="0x05 0x00",
                                                                                Supervision_Timeout="0x00 0x0A",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19898
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19898(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST123"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x00 0x0C",
                                                                                Connection_Interval_Max="0x00 0x0C",
                                                                                Max_Latency="0x02 0x00",
                                                                                Supervision_Timeout="0x80 0x0C",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19899
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19899(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19899"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x80 0x0C",
                                                                                Connection_Interval_Max="0x80 0x0C",
                                                                                Max_Latency="0x02 0x00",
                                                                                Supervision_Timeout="0x80 0x0C",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")




#BLE slave latency C19900
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19900(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19900"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x06 0x00",
                                                                                Connection_Interval_Max="0x06 0x00",
                                                                                Max_Latency="0x00 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")


#BLE slave latency C19901
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19901(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19901"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x0C 0x00",
                                                                                Connection_Interval_Max="0x0C 0x00",
                                                                                Max_Latency="0x00 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19902
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19902(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19902"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x18 0x00",
                                                                                Connection_Interval_Max="0x18 0x00",
                                                                                Max_Latency="0x00 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19903
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19903(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19903"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x30 0x00",
                                                                                Connection_Interval_Max="0x30 0x00",
                                                                                Max_Latency="0x00 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19904
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19904(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19904"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x60 0x00",
                                                                                Connection_Interval_Max="0x60 0x00",
                                                                                Max_Latency="0x00 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19905
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19905(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19905"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0xC0 0x00",
                                                                                Connection_Interval_Max="0xC0 0x00",
                                                                                Max_Latency="0x00 0x00",
                                                                                Supervision_Timeout="0x90 0x01",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19906
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19906(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19906"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x80 0x01",
                                                                                Connection_Interval_Max="0x80 0x01",
                                                                                Max_Latency="0x05 0x00",
                                                                                Supervision_Timeout="0x80 0x02",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19907
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19907(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19907"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x00 0x03",
                                                                                Connection_Interval_Max="0x00 0x03",
                                                                                Max_Latency="0x00 0x00",
                                                                                Supervision_Timeout="0x00 0x05",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19908
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19908(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19908"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x00 0x06",
                                                                                Connection_Interval_Max="0x00 0x06",
                                                                                Max_Latency="0x00 0x00",
                                                                                Supervision_Timeout="0x00 0x0A",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19909
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19909(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST19909"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x00 0x0C",
                                                                                Connection_Interval_Max="0x00 0x0C",
                                                                                Max_Latency="0x00 0x00",
                                                                                Supervision_Timeout="0x80 0x0C",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#BLE slave latency C19910
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_slave_latency_C19910(wifi_dut, wifi_access_point, ble_client):
    set_local_name = "BLETEST123"
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status,"Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)

    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(10)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}") as ble_logs:
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                                Connection_Handle="0x61 0x00",
                                                                                Connection_Interval_Min="0x80 0x0C",
                                                                                Connection_Interval_Max="0x80 0x0C",
                                                                                Max_Latency="0x00 0x00",
                                                                                Supervision_Timeout="0x80 0x0C",
                                                                                Min_CE_Length="0x00 0x00",
                                                                                Max_CE_Length="0x00 0x00"
                                                                                )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    #ble_logs.update_connection_logs()
    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")