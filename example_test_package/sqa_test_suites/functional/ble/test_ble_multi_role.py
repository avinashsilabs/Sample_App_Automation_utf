import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes,RS9116FeatureBitMap,RS9116ConfigFeatureBitMap,\
    RS9116TCPIPFeatureBitMap,RS9116ExtTCPIPFeatureBitMap,RS9116ExtCustomFeatureBitMap,RS9116CustomFeatureBitMap
from utf.utils.logger import get_logger
import time
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates the DUT in master Spp mode for the capability
        3. Initiates the client in slave spp with capability enables
        4. Opens Bt socket and connects to the remote client.
        5. Verifies ping after the connection.

    Author: RaviNemali
"""

# configure no of ble devices
remote_le_devices = 2

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
def test_ble_dual_role_C19911(ble_dut, ble_clients):
    assert len(ble_clients) >= remote_le_devices

    ble_advertisers = []
    for item in range(0, 2):
        ble_advertisers.append(ble_clients[item])

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    count = 0
    for ble_client in ble_advertisers:
        count = count+1
        logger().info(f" ======= initialize ble adv in remote device {count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address, f"ble initialization failed in remote device{count}"
        logger().info(f"ble client address of remote device {count} is {bt_client_address}")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
        time.sleep(2)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)
    ble_client.interfaces.bluetooth.close()

    ble_dut.interfaces.bluetooth.ble_start_advertising()
    time.sleep(5)

    logger().info(f"start ble scan in remote device{count}")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address , f"ble initialization failed in remote device {count}"
    logger().info(f"ble client address {bt_client_address} of remote device {count}")
    time.sleep(2)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f"checking, dut found in scan list of remote device {count}")
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
            device_found = True
        break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "dut is not found in scan list"

    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

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
def test_ble_dual_role_C19912(ble_dut, ble_clients):
    assert len(ble_clients) >= remote_le_devices
    ble_advertisers = []
    for item in range(0, 2):
        ble_advertisers.append(ble_clients[item])

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"

    count = 0
    for ble_client in ble_advertisers:
        count = count + 1
        logger().info(f" ======= initialize ble adv in remote device {count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address, f"ble initialization failed in remote device{count}"
        logger().info(f"ble client address of remote device {count} is {bt_client_address}")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address,
                                                             ble_scan_interval=int(500/0.625),
                                                             ble_scan_window=int(400/0.625), timeout=120)
        time.sleep(2)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)
    ble_client.interfaces.bluetooth.close()

    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=int(200/0.625),ble_adv_int_max=int(200/0.625), timeout=30)
    time.sleep(5)

    logger().info(f"start ble scan in remote device{count}")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, f"ble initialization failed in remote device {count}"
    logger().info(f"ble client address {bt_client_address} of remote device {count}")
    time.sleep(2)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f"checking, dut found in scan list of remote device {count}")
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
            device_found = True
        break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "dut is not found in scan list"

    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)


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
def test_ble_dual_role_C19913(ble_dut, ble_clients):
    assert len(ble_clients) >= remote_le_devices

    ble_advertisers = []
    for item in range(0, 2):
        ble_advertisers.append(ble_clients[item])

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    count = 0
    for ble_client in ble_advertisers:
        count = count + 1
        logger().info(f" ======= initialize ble adv in remote device {count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(bt_dut_address=bt_dut_address,
                                                                                        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                                                                                                       "0x40 0x00 "  # Advertising_Interval_Max
                                                                                                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                                                                                                       "0x00 "  # Own_Address_Type
                                                                                                       "0x00 "  # Peer_Address_Type
                                                                                                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                                                                                                       "0x07 "  # Advertising_Channel_Map
                                                                                                       "0x00"   # Advertising_Filter_Policy
                                                                                        )
        assert bt_client_address, f"ble initialization failed in remote device{count}"
        logger().info(f"ble client address of remote device {count} is {bt_client_address}")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address,
                                                             ble_scan_interval=int(1000/0.625),
                                                             ble_scan_window=int(500/0.625), timeout=120)
        time.sleep(2)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)
    ble_client.interfaces.bluetooth.close()

    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=int(500/0.625),ble_adv_int_max=int(500/0.625), timeout=30)
    time.sleep(5)

    logger().info(f"start ble scan in remote device{count}")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, f"ble initialization failed in remote device {count}"
    logger().info(f"ble client address {bt_client_address} of remote device {count}")
    time.sleep(2)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f"checking, dut found in scan list of remote device {count}")
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
            device_found = True
        break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "dut is not found in scan list"

    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

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
def test_ble_dual_role_C19914(ble_dut, ble_clients):
    assert len(ble_clients) >= remote_le_devices

    ble_advertisers = []
    for item in range(0, 2):
        ble_advertisers.append(ble_clients[item])

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    count = 0
    for ble_client in ble_advertisers:
        count = count + 1
        logger().info(f" ======= initialize ble adv in remote device {count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(bt_dut_address=bt_dut_address,
                                                                                        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                                                                                                       "0x40 0x00 "  # Advertising_Interval_Max
                                                                                                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                                                                                                       "0x00 "  # Own_Address_Type
                                                                                                       "0x00 "  # Peer_Address_Type
                                                                                                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                                                                                                       "0x07 "  # Advertising_Channel_Map
                                                                                                       "0x00"
                                                                                        # Advertising_Filter_Policy
                                                                                        )
        assert bt_client_address, f"ble initialization failed in remote device{count}"
        logger().info(f"ble client address of remote device {count} is {bt_client_address}")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address,
                                                             ble_scan_interval=int(5000/0.625),
                                                             ble_scan_window=int(3000/0.625), timeout=120)
        time.sleep(2)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)
    ble_client.interfaces.bluetooth.close()

    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=int(1000/0.625),ble_adv_int_max=int(1000/0.625), timeout=30)
    time.sleep(5)

    logger().info(f"start ble scan in remote device{count}")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, f"ble initialization failed in remote device {count}"
    logger().info(f"ble client address {bt_client_address} of remote device {count}")
    time.sleep(2)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f"checking, dut found in scan list of remote device {count}")
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
            device_found = True
        break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "dut is not found in scan list"

    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

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
def test_ble_dual_role_C19915(ble_dut, ble_clients):
    assert len(ble_clients) >= remote_le_devices

    ble_advertisers = []
    for item in range(0, 2):
        ble_advertisers.append(ble_clients[item])

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    count = 0
    for ble_client in ble_advertisers:
        count = count + 1
        logger().info(f" ======= initialize ble adv in remote device {count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(bt_dut_address=bt_dut_address,
                                                                                        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                                                                                                       "0x40 0x00 "  # Advertising_Interval_Max
                                                                                                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                                                                                                       "0x00 "  # Own_Address_Type
                                                                                                       "0x00 "  # Peer_Address_Type
                                                                                                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                                                                                                       "0x07 "  # Advertising_Channel_Map
                                                                                                       "0x00"
                                                                                        # Advertising_Filter_Policy
                                                                                        )
        assert bt_client_address, f"ble initialization failed in remote device{count}"
        logger().info(f"ble client address of remote device {count} is {bt_client_address}")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address,
                                                             ble_scan_interval=int(10240/0.625),
                                                             ble_scan_window=int(5000/0.625), timeout=120)
        time.sleep(5)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(2)
        ble_client.interfaces.bluetooth.close()
    time.sleep(5)


    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=int(10240/0.625),ble_adv_int_max=int(10240/0.625), timeout=30)
    time.sleep(5)

    logger().info(f"start ble scan in remote device{count}")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, f"ble initialization failed in remote device {count}"
    logger().info(f"ble client address {bt_client_address} of remote device {count}")
    time.sleep(2)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f"checking, dut found in scan list of remote device {count}")
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
            device_found = True
        break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "dut is not found in scan list"

    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)
    ble_client.interfaces.bluetooth()

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
def test_ble_dual_role_connection_C19916(ble_dut, ble_clients,bt_logs):
    remote_le_devices = 3
    assert len(ble_clients) >= remote_le_devices
    ble_client_1 = ble_clients[0]

    logger().info("initiating ble in dut")
    bt_dut_address = ble_dut.interfaces.wifi.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"
    ble_dut.interfaces.wifi.ble_start_advertising()

    logger().info("initiating scan in rd_1")
    bt_client_address_1 = ble_client_1.interfaces.bluetooth.start_smp_scan(bt_dut_address)
    assert bt_client_address_1,"failed to initiate ble in remote device"
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client_1.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == ble_dut.interfaces.wifi.ble_advertising_data:
            device_found = True
            break

    ble_client_1.interfaces.bluetooth.stop_scanning()
    assert device_found
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_client_1.interfaces.bluetooth.connect(dev_addr=bt_dut_address)
    time.sleep(2)
    bt_logs.device_characteristics(ble_dut.interfaces.bluetooth.ble_address)
    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    ble_client_1.interfaces.bluetooth.close()

    # change in function for ble role
    assert len(ble_clients) >= remote_le_devices

    ble_advertisers = []
    for item in range(1, 2):
        ble_advertisers.append(ble_clients[item])

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    count = 0
    for ble_client in ble_advertisers:
        count = count + 1
        logger().info(f" ======= initialize ble adv in remote device {count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(bt_dut_address=bt_dut_address,
                                                                                        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                                                                                                       "0x40 0x00 "  # Advertising_Interval_Max
                                                                                                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                                                                                                       "0x00 "  # Own_Address_Type
                                                                                                       "0x00 "  # Peer_Address_Type
                                                                                                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                                                                                                       "0x07 "  # Advertising_Channel_Map
                                                                                                       "0x00"
                                                                                        # Advertising_Filter_Policy
                                                                                        )
        assert bt_client_address, f"ble initialization failed in remote device{count}"
        logger().info(f"ble client address of remote device {count} is {bt_client_address}")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address,timeout=120)
        time.sleep(2)

        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    time.sleep(10)
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

    time.sleep(2)
    ble_client.interfaces.bluetooth.close()

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
def test_ble_dual_role_connection_C19917(ble_dut, ble_clients,bt_logs):
    remote_le_devices = 3
    assert len(ble_clients) >= remote_le_devices
    ble_client_1 = ble_clients[0]

    logger().info("initiating ble in dut")
    bt_dut_address = ble_dut.interfaces.wifi.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
    ble_dut.interfaces.wifi.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("initiating scan in rd_1")
    bt_client_address_1 = ble_client_1.interfaces.bluetooth.start_smp_scan(bt_dut_address)
    assert bt_client_address_1, "failed to initiate ble in remote device"
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client_1.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == ble_dut.interfaces.wifi.ble_advertising_data:
            device_found = True
            break

    ble_client_1.interfaces.bluetooth.stop_scanning()
    assert device_found
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_client_1.interfaces.bluetooth.connect(dev_addr=bt_dut_address)
    time.sleep(2)
    bt_logs.device_characteristics(ble_dut.interfaces.bluetooth.ble_address)
    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    ble_client_1.interfaces.bluetooth.close()

    # change in function for ble role
    assert len(ble_clients) >= remote_le_devices

    ble_advertisers = []
    for item in range(1, 2):
        ble_advertisers.append(ble_clients[item])

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    count = 0
    for ble_client in ble_advertisers:
        count = count + 1
        logger().info(f" ======= initialize ble adv in remote device {count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(bt_dut_address=bt_dut_address,
                                                                                        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                                                                                                       "0x40 0x00 "  # Advertising_Interval_Max
                                                                                                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                                                                                                       "0x00 "  # Own_Address_Type
                                                                                                       "0x00 "  # Peer_Address_Type
                                                                                                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                                                                                                       "0x07 "  # Advertising_Channel_Map
                                                                                                       "0x00"
                                                                                        # Advertising_Filter_Policy
                                                                                        )
        assert bt_client_address, f"ble initialization failed in remote device{count}"
        logger().info(f"ble client address of remote device {count} is {bt_client_address}")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
        time.sleep(2)

        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    time.sleep(10)
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

    time.sleep(2)
    ble_client.interfaces.bluetooth.close()

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
def test_ble_dual_role_connection_C19918(ble_dut, ble_clients, bt_logs):
    remote_le_devices = 3
    assert len(ble_clients) >= remote_le_devices
    ble_client_1 = ble_clients[0]

    logger().info("initiating ble in dut")
    bt_dut_address = ble_dut.interfaces.wifi.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
    ble_dut.interfaces.wifi.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("initiating scan in rd_1")
    bt_client_address_1 = ble_client_1.interfaces.bluetooth.start_smp_scan(bt_dut_address)
    assert bt_client_address_1, "failed to initiate ble in remote device"
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client_1.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == ble_dut.interfaces.wifi.ble_advertising_data:
            device_found = True
            break

    ble_client_1.interfaces.bluetooth.stop_scanning()
    assert device_found
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_client_1.interfaces.bluetooth.connect(dev_addr=bt_dut_address)
    time.sleep(2)
    bt_logs.device_characteristics(ble_dut.interfaces.bluetooth.ble_address)
    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    ble_client_1.interfaces.bluetooth.close()

    # change in function for ble role
    assert len(ble_clients) >= remote_le_devices

    ble_advertisers = []
    for item in range(1, 2):
        ble_advertisers.append(ble_clients[item])

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    count = 0
    for ble_client in ble_advertisers:
        count = count + 1
        logger().info(f" ======= initialize ble adv in remote device {count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(bt_dut_address=bt_dut_address,
                                                                                        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                                                                                                       "0x40 0x00 "  # Advertising_Interval_Max
                                                                                                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                                                                                                       "0x00 "  # Own_Address_Type
                                                                                                       "0x00 "  # Peer_Address_Type
                                                                                                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                                                                                                       "0x07 "  # Advertising_Channel_Map
                                                                                                       "0x00"
                                                                                        # Advertising_Filter_Policy
                                                                                        )
        assert bt_client_address, f"ble initialization failed in remote device{count}"
        logger().info(f"ble client address of remote device {count} is {bt_client_address}")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
        time.sleep(2)

        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    time.sleep(10)
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

    time.sleep(2)
    ble_client.interfaces.bluetooth.close()


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
def test_ble_dual_role_connection_C19919(ble_dut, ble_clients,bt_logs):
    remote_le_devices = 3
    assert len(ble_clients) >= remote_le_devices
    ble_client_1 = ble_clients[0]

    logger().info("initiating ble in dut")
    bt_dut_address = ble_dut.interfaces.wifi.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
    ble_dut.interfaces.wifi.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveModes.PowerSaveMode1)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("initiating scan in rd_1")
    bt_client_address_1 = ble_client_1.interfaces.bluetooth.start_smp_scan(bt_dut_address)
    assert bt_client_address_1, "failed to initiate ble in remote device"
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client_1.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == ble_dut.interfaces.wifi.ble_advertising_data:
            device_found = True
            break

    ble_client_1.interfaces.bluetooth.stop_scanning()
    assert device_found
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_client_1.interfaces.bluetooth.connect(dev_addr=bt_dut_address)
    time.sleep(2)
    bt_logs.device_characteristics(ble_dut.interfaces.bluetooth.ble_address)
    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    ble_client_1.interfaces.bluetooth.close()

    # change in function for ble role
    assert len(ble_clients) >= remote_le_devices

    ble_advertisers = []
    for item in range(1, 2):
        ble_advertisers.append(ble_clients[item])

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    count = 0
    for ble_client in ble_advertisers:
        count = count + 1
        logger().info(f" ======= initialize ble adv in remote device {count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(bt_dut_address=bt_dut_address,
                                                                                        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                                                                                                       "0x40 0x00 "  # Advertising_Interval_Max
                                                                                                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                                                                                                       "0x00 "  # Own_Address_Type
                                                                                                       "0x00 "  # Peer_Address_Type
                                                                                                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                                                                                                       "0x07 "  # Advertising_Channel_Map
                                                                                                       "0x00"
                                                                                        # Advertising_Filter_Policy
                                                                                        )
        assert bt_client_address, f"ble initialization failed in remote device{count}"
        logger().info(f"ble client address of remote device {count} is {bt_client_address}")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
        time.sleep(2)

        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    time.sleep(10)
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

    time.sleep(2)
    ble_client.interfaces.bluetooth.close()


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
def test_ble_scan_in_busy_environment_C19827_C19828(ble_dut, ble_clients):
    assert len(ble_clients) >= remote_le_devices

    ble_advertisers = []
    for item in range(0, remote_le_devices):
        ble_advertisers.append(ble_clients[item])

    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    count = 0
    for ble_client in ble_advertisers:
        count = count+1
        logger().info(f" ======= initialize ble adv in remote device {count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address, f"ble initialization failed in remote device{count}"
        logger().info(f"ble client address of remote device {count} is {bt_client_address}")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
        time.sleep(2)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)
    ble_client.interfaces.bluetooth.close()