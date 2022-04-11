import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes,RS9116FeatureBitMap,RS9116ConfigFeatureBitMap,RS9116TCPIPFeatureBitMap,RS9116ExtTCPIPFeatureBitMap,RS9116ExtCustomFeatureBitMap
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError
import time

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

'''=================== Ble-gap IO test cases ===================== '''



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_displayonly_C19851(bt_dut,ble_client):

    logger().info("Setting the dut IO capability to display only.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

    # Set up DUT for BLE advertising
    logger().info("Initiate ble service in DUT")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch dut bd address...."

    logger().info("Set DUT in advertise mode")
    bt_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert bt_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    logger().info("Disconnecting the bt host....")
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_display_yesno_C19852(bt_dut,ble_client):

    logger().info("Setting the dut IO capability to display yes no.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=1)

    logger().info("Initiate ble service in DUT")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None

    logger().info("Set DUT in advertise mode")
    bt_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert bt_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    logger().info("Disconnecting the bt host....")
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_keyboard_only_C19853(bt_dut,ble_client):

    logger().info("Setting the dut IO capability to keyboard only.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=2)

    logger().info("Initiate ble service in DUT")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None

    logger().info("Set DUT in advertise mode")
    bt_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert bt_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    logger().info("Disconnecting the bt host....")
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_No_input_output_C19854(bt_dut,ble_client):

    logger().info("Setting the dut IO capability to No input output.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=3)

    logger().info("Initiate ble service in DUT")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None

    logger().info("Set DUT in advertise mode")
    bt_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert bt_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    logger().info("Disconnecting the bt host....")
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

'''======================= Ble-gap IO test cases dut as initiator ====================='''
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_displayonly_C19855(bt_dut,ble_client):
    logger().info("Setting the dut IO capability to display only.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

    logger().info("Initiating ble service in dut")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch bd address of dut...."

    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to fetch client bt address..."
    time.sleep(5)

    logger().info("dut start scanning.....")
    bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    bt_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    logger().info("Disconnect from the host")
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_display_yesno_C19856(bt_dut,ble_client):
    logger().info("Setting the dut IO capability to display only.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=1)

    logger().info("Initiating ble service in dut")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch bd address of dut...."

    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to fetch client bt address..."
    time.sleep(5)

    logger().info("dut start scanning.....")
    bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    bt_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    logger().info("Disconnect from the host")
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_keyboard_only_C19857(bt_dut,ble_client):
    logger().info("Setting the dut IO capability to display only.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=2)

    logger().info("Initiating ble service in dut")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch bd address of dut...."

    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to fetch client bt address..."
    time.sleep(5)

    logger().info("dut start scanning.....")
    bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    bt_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    logger().info("Disconnect from the host")
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_no_input_output_C19858(bt_dut,ble_client):
    logger().info("Setting the dut IO capability to display only.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=3)

    logger().info("Initiating ble service in dut")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch bd address of dut...."

    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to fetch client bt address...."
    time.sleep(5)

    logger().info("dut start scanning.....")
    bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    bt_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    logger().info("Disconnect from the host")
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

"""============================ Ble-gap dut scan for adv types ============================================="""
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_scan_connectable_undirected_adv_C19805(bt_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch bd address"
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
    )
    assert bt_client_address is not None
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("verifying client addr is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_scan_connectable_directed_adv_C19806(bt_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch bd address"
    logger().info(f"bt_dut_address {bt_dut_address}")
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "
                       "0x40 0x00 "
                       "0x01 "
                       "0x00 "
                       "0x00 "
                       "0xCF 0x3A 0xc2 0x55 0xc9 0x80 " #configure the dut bt address for this param
                       "0x07 "
                       "0x00"
    )
    assert bt_client_address is not None
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result),"failed to find client bt addr in scan list...."
    logger().info("found BT client address")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_scan_non_connectable_undirected_adv_C19807(bt_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch bd address"
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "
                       "0x40 0x00 "
                       "0x03 "
                       "0x00 "
                       "0x00 "
                       "0x00 0x00 0x00 0x00 0x00 0x00 "
                       "0x07 "
                       "0x00"
    )
    assert bt_client_address is not None
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result),"failed to find client bt addr in scan list...."
    logger().info("found BT client address")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_scannable_undirected_adv_C19808(bt_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch bd address"
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "
                       "0x40 0x00 "
                       "0x02 "
                       "0x00 "
                       "0x00 "
                       "0x00 0x00 0x00 0x00 0x00 0x00 "
                       "0x07 "
                       "0x00"
    )
    assert bt_client_address is not None
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result),"failed to find client bt addr in scan list...."
    logger().info("found BT client address")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_adv_report_C19848(bt_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch bd address..."
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    time.sleep(1)
    assert bt_client_address is not None
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result),"failed to find client bt addr in scan list...."
    logger().info("found BT client address")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_adv_state_in_scan_C19840(bt_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch bd address... "
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
    )
    assert bt_client_address is not None
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    bt_dut.interfaces.bluetooth.ble_start_advertising()
    time.sleep(3)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("verifying client addr is available in scan list...")
    assert str(bt_client_address) in str(result),"failed to find client bt addr in scan list...."
    logger().info("found BT client address")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_dut_slave_connect_C19832(bt_dut,ble_client):

    logger().info("set dut in adv mode...")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch  bd address..."
    bt_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("start ble scan from remote le device...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert bt_dut.interfaces.bluetooth.ble_address in found_devices
    assert (
            found_devices[bt_dut.interfaces.wifi.ble_address]
            == bt_dut.interfaces.bluetooth.ble_advertising_data
    )
    logger().info("connect to dut from remote le device....")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    with pytest.raises(WlanError) as exc_info:
        bt_dut.interfaces.bluetooth.ble_stop_advertising()
    assert exc_info.value.error_code == 0x4E0C
    logger().info("disconnecting the dut..")
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_dut_slave_connect_C19832(bt_dut,ble_client):

    logger().info("set dut in adv mode...")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch  bd address..."
    bt_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("start ble scan from remote le device...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger().info("stopping the ble scan from remote le device...")
    ble_client.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert bt_dut.interfaces.bluetooth.ble_address in found_devices
    assert (
            found_devices[bt_dut.interfaces.wifi.ble_address]
            == bt_dut.interfaces.bluetooth.ble_advertising_data
    )
    logger().info("connect to dut from remote le device....")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    with pytest.raises(WlanError) as exc_info:
        bt_dut.interfaces.bluetooth.ble_stop_advertising()
    assert exc_info.value.error_code == 0x4E0C

    logger().info("disconnecting the dut..")
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "rejoin_max_retry": 10,
            "scan_interval": 6,
            "beacon_missed_count": 40,
            "first_time_retry": 0,
            }
        )
def test_directed_connectable_adv_C19802(bt_dut, ble_client, bt_logs):

    logger().info("start ble in dut....")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    logger().info("starting the advertisement on the Dut")
    bt_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=129) #high duty cycle
    logger().info("enabling the power save mode")
    bt_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    bt_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    logger().info("enabling the power save mode")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "unable to fetch dut bd address..."
    time.sleep(5)

    logger().info("stop bt advertising...")
    bt_dut.interfaces.bluetooth.ble_stop_advertising()
    ble_client.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert bt_dut.interfaces.bluetooth.ble_address in found_devices
    assert (
            found_devices[bt_dut.interfaces.bluetooth.ble_address]
            == bt_dut.interfaces.bluetooth.ble_advertising_data
    )
    bt_logs.device_characteristics(bt_dut.interfaces.bluetooth.ble_address)
    assert 'Connectable undirected - ADV_IND (0x81)' in bt_logs.device_adv_type

" ============ ble-gap pdu length test cases ====================== "
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
    },
)
def test_ble_scan_resp_8_bytes_C19821(bt_dut, ble_client):
    logger().info("start ble dut....")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None

    #pdu name -- automate
    logger().info("start ble client with pdu length 8 bytes....")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
    , scan_resp_name_params = "0x0a 0x09 0x09 0x61 0x75 0x74 0x6f 0x6d 0x61 0x74 0x65  "
                                "0x00 0x00 0x00 0x00 " \
                                "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
    )
    assert bt_client_address is not None
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
    },
)
def test_ble_scan_resp_20_bytes_C19822(bt_dut, ble_client):
    logger().info("start ble dut....")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None

    # pdu name -- letmeusethisaspdulen
    logger().info("start ble client with pdu length 8 bytes....")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
    , scan_resp_name_params = "0x16 0x15 0x09 0x6c 0x65 0x74 0x6d 0x65 0x75 0x73 0x65  "
                                "0x74 0x68 0x69 0x73 " \
                                "0x61 0x73 0x70 0x64 0x75 0x6c 0x65 0x6e 0x00 "
                                "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
    )
    assert bt_client_address is not None
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
    },
)
def test_ble_scan_resp_30_bytes_C19823(bt_dut, ble_client):
    logger().info("start ble dut....")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None

    # pdu name -- thisispdulengthofthirteeybytes
    logger().info("start ble client with pdu length 30 bytes....")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
    , scan_resp_name_params = "0x20 0x1f 0x09 0x74 0x68 0x69 0x73 0x69 0x73 0x70 0x64  "
                                "0x75 0x6c 0x65 0x6e " \
                                "0x67 0x74 0x68 0x6f 0x66 0x74 0x68 0x69 0x72 0x74 0x65 0x65 "
                                "0x79 0x62 0x79 0x74 0x65 0x73 0x00 0x00"

    )
    assert bt_client_address is not None
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
    },
)
def test_ble_scan_resp_32_bytes_C19824(bt_dut, ble_client):
    logger().info("NOTE: As per test rail this case is for 39 bytes due to hci command limiting to 32 bytes from RPI")
    time.sleep(5)
    logger().info("start ble dut....")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None

    # pdu name -- thisispdulengthofthirteeytobytes
    logger().info("start ble client with pdu length 30 bytes....")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
    , scan_resp_name_params = "0x22 0x21 0x09 0x74 0x68 0x69 0x73 0x69 0x73 0x70 0x64  "
                                "0x75 0x6c 0x65 0x6e " \
                                "0x67 0x74 0x68 0x6f 0x66 0x74 0x68 0x69 0x72 0x74 0x65 0x65 "
                                "0x79 0x74 0x6f 0x62 0x79 0x74 0x65 0x73"

    )
    assert bt_client_address is not None
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt address in scan list...."
    logger().info("found BT client address")