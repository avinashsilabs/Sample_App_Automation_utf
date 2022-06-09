import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes,RS9116FeatureBitMap,RS9116ConfigFeatureBitMap,RS9116TCPIPFeatureBitMap,\
    RS9116ExtTCPIPFeatureBitMap,RS9116ExtCustomFeatureBitMap,RS9116CustomFeatureBitMap,RS9116PowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError
import time
import datetime

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
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_ble_io_cap_displayonly_C19851(ble_dut,ble_client):

    logger().info("Initiate ble service in DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability= 0)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Set DUT in advertise mode")
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate ble in remote device"
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")
    connect_time=datetime.datetime.now(ble_client.interfaces.bluetooth.connect(bt_dut_address))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address,"unable to connect to the given address"
    time.sleep(30)

    #checking if the connection exists to disconnect
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  { disconnect_time}")
        assert "unable to disconnect since the connection never existed"

    logger().info(f"connection existed for {disconnect_time-connect_time}")

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
def test_ble_io_cap_display_yesno_C19852(ble_dut,ble_client):

    logger().info("Initiate ble service in DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability= 1)
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("Set DUT in advertise mode")
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate ble in remote device"
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now(ble_client.interfaces.bluetooth.connect(bt_dut_address))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(30)
    # checking if the connection exists to disconnect
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
    logger().info(f"connection existed for {disconnect_time - connect_time}")

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
def test_ble_io_cap_keyboard_only_C19853(ble_dut,ble_client):

    logger().info("Initiate ble service in DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability= 2)
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("Set DUT in advertise mode")
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate ble in remote device"
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now(ble_client.interfaces.bluetooth.connect(bt_dut_address))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(30)
    # checking if the connection exists to disconnect
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
    logger().info(f"connection existed for {disconnect_time - connect_time}")

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
def test_ble_io_cap_No_input_output_C19854(ble_dut,ble_client):

    logger().info("Initiate ble service in DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability= 3)
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("Set DUT in advertise mode")
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate ble in remote device"
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now(ble_client.interfaces.bluetooth.connect(bt_dut_address))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(30)
    # checking if the connection exists to disconnect
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
    logger().info(f"connection existed for {disconnect_time - connect_time}")

'''======================= Ble-gap IO test cases dut as initiator ====================='''
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_displayonly_C19855(ble_dut,ble_client):

    logger().info("Initiating ble service in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability= 0)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)

    logger().info("dut start scanning.....")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60

    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    connect_time = datetime.datetime.now(ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(30)

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
    logger().info(f"connection existed for {disconnect_time - connect_time}")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_display_yesno_C19856(ble_dut,ble_client):

    logger().info("Initiating ble service in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability= 1)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)

    logger().info("dut start scanning.....")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60

    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    connect_time = datetime.datetime.now(ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(30)

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
    logger().info(f"connection existed for {disconnect_time - connect_time}")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_keyboard_only_C19857(ble_dut,ble_client):

    logger().info("Initiating ble service in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability= 2)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)

    logger().info("dut start scanning.....")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60

    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    connect_time = datetime.datetime.now(
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(30)

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
    logger().info(f"connection existed for {disconnect_time - connect_time}")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_no_input_output_C19858(ble_dut,ble_client):

    logger().info("Initiating ble service in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability= 3)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote dut"
    time.sleep(5)

    logger().info("dut start scanning.....")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60

    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    connect_time = datetime.datetime.now(
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(30)

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
    logger().info(f"connection existed for {disconnect_time - connect_time}")

"""============================ Ble-gap dut scan for adv types ============================================="""
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
def test_ble_scan_connectable_undirected_adv_C19805(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
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
    assert bt_client_address,"failed to initiate ble in remote device"
    logger().info(f"ble client addr..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps,"failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps,"failed to enable bt power save"
    time.sleep(5)

    logger().info("verifying client addr is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address in dut scan list")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
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
def test_ble_scan_connectable_directed_adv_C19806(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
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
    assert bt_client_address ,"failed to initiate ble in remote device"
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result),"failed to find client bt addr in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
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
def test_ble_scan_non_connectable_undirected_adv_C19807(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to start ble in dut"
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
    assert bt_client_address,"failed to initiate ble in remote device"
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result),"failed to find client bt addr in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
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
def test_ble_scannable_undirected_adv_C19808(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to start ble in dut"
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
    assert bt_client_address,"failed to initiate ble in remote device"
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result),"failed to find client bt addr in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
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
def test_ble_adv_state_in_scan_C19840(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
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
    assert bt_client_address,"failed to initiate ble in remote device"
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    time.sleep(3)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("verifying client addr is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")
    ble_dut.interfaces.bluetooth.ble_start_advertising()
    time.sleep(3)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices,"dut is not listed in scan results"

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
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
def test_ble_dut_slave_connect_C19832(ble_dut,ble_client):

    logger().info("set dut in adv mode...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("start ble scan from remote le device...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate ble in remote device"
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices
    assert (
            found_devices[ble_dut.interfaces.wifi.ble_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
    )
    logger().info("connect to dut from remote le device....")
    connect_time = datetime.datetime.now(ble_client.interfaces.bluetooth.connect(bt_dut_address))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(30)
    with pytest.raises(WlanError) as exc_info:
        ble_dut.interfaces.bluetooth.ble_stop_advertising()
    assert exc_info.value.error_code == 0x4E0C

    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("disconnecting the dut..")
        disconnect_time = datetime.datetime.now(ble_client.interfaces.bluetooth.disconnect(bt_dut_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
    logger().info(f"connection existed for {disconnect_time - connect_time}")

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
def test_directed_connectable_adv_C19802(ble_dut, ble_client, bt_logs):

    logger().info("start ble in dut....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"
    logger().info("advertising Dut")
    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=129) #high duty cycle
    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "unable to fetch dut bd address..."
    time.sleep(5)

    logger().info("stop bt advertising...")
    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    ble_client.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client.interfaces.bluetooth.get_devices()
    logger().info("checking dut,listed in scan")
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices
    assert (
            found_devices[ble_dut.interfaces.bluetooth.ble_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
    )
    bt_logs.device_characteristics(ble_dut.interfaces.bluetooth.ble_address)
    assert 'Connectable directed - ADV_IND (0x81)' in bt_logs.device_adv_type,"device not in connectable directed mode"
    logger().info("found dut with connectable directed mode")

" ============ ble-gap pdu length test cases ====================== "
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
def test_ble_scan_resp_8_bytes_C19821(ble_dut, ble_client):
    logger().info("start ble dut....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    #pdu name -- No PDU name as address itself satisfies the 8 bytes
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
    , scan_resp_name_params = "0x00 0x09 0x09 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                              "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                              "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "

    )
    assert bt_client_address,"failed to initiate ble in remote device"
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
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
def test_ble_scan_resp_20_bytes_C19822(ble_dut, ble_client):
    logger().info("start ble dut....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    # pdu name -- automateaa
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
    , scan_resp_name_params = "0x0c 0x0b 0x09 0x61 0x75 0x74 0x6f 0x6d 0x61 0x74 0x65 0x61 "
                              "0x61 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                              "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
    )
    assert bt_client_address,"failed to initiate ble in remote device"
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
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
def test_ble_scan_resp_30_bytes_C19823(ble_dut, ble_client):
    logger().info("start ble dut....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    # pdu name -- automateaaaaaaaaaaaa
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
    , scan_resp_name_params = "0x16 0x15 0x09 0x61 0x75 0x74 0x6f 0x6d 0x61 0x74 "
                              "0x65 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 "
                              "0x61 0x61 0x61 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "

    )
    assert bt_client_address,"failed to initiate ble in remote device"
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
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
def test_ble_scan_resp_39_bytes_C19824(ble_dut, ble_client):
    logger().info("start ble dut....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    # pdu name -- automateaaaaaaaaaaaaaaaaaaaaa
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
    , scan_resp_name_params = "0x1F 0x1E 0x09 0x61 0x75 0x74 0x6f 0x6d 0x61 0x74 0x65 0x61 "
                              "0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 "
                              "0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x00 0x00 "

    )
    assert bt_client_address,"failed to initiate ble in remote device"
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt address in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
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
def test_ble_adv_report_C19848(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    time.sleep(1)
    assert bt_client_address,"failed to initiate ble in remote device"
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result),"failed to find client bt addr in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)