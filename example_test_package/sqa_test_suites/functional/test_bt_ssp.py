import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
import time

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates the DUT in master Spp mode for the capability
        3. Initiates the client in slave spp with capabilty enables
        4. Opnes Bt socket and connects to the remote client.
        5. Verifies ping after the connection.

    Author: RaviNemali
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
            {
                "oper_mode": 0,
                "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
            }
    )
]

'''=============================== DUT AS MASTER TEST CASES ================================='''

# This test case verifies the bt basic spp connection
def test_bt_physical_level_conn(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None

        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            #SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=10)
                assert addr == bt_dut_address
            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )
            # Close connection
            bt_client_socket.close()
            time.sleep(
                0.2
            )  # to overcome Unexpected response from 'at+rsibt_unbond=B8-27-EB-8E-A9-99': b'AT+RSIBT_SPPDISCONNECTED B8-27-EB-8E-A9-99\r\n\r\nOK'
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
    logger().info(f"Scan in {t.duration} seconds")


# This test case verifies the spp connection in display only mode
def test_bt_master_ssp_displayonly(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_master_ssp_display(pair_mode="1", capability="0")
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code, capability="DisplayOnly")
        assert bt_client_address is not None
        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=10)
                assert addr == bt_dut_address
            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )
            # Close connection
            bt_client_socket.close()
            time.sleep(
                0.2
            )  # to overcome Unexpected response from 'at+rsibt_unbond=B8-27-EB-8E-A9-99': b'AT+RSIBT_SPPDISCONNECTED B8-27-EB-8E-A9-99\r\n\r\nOK'
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
    logger().info(f"Scan in {t.duration} seconds")


# This test case verifies the spp connection in display YesNo mode
def test_bt_master_ssp_DisplayYesNo(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_master_ssp_display(pair_mode="1", capability="0")
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code, capability="DisplayYesNo")
        assert bt_client_address is not None
        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=10)
                assert addr == bt_dut_address
            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )
            # Close connection
            bt_client_socket.close()
            time.sleep(
                0.2
            )  # to overcome Unexpected response from 'at+rsibt_unbond=B8-27-EB-8E-A9-99': b'AT+RSIBT_SPPDISCONNECTED B8-27-EB-8E-A9-99\r\n\r\nOK'
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
    logger().info(f"Scan in {t.duration} seconds")


# This test case verifies the spp connection in keyboardonly mode
def test_bt_master_ssp_keyboardonly(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_master_ssp_display(pair_mode="1", capability="2")
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code, capability="KeyboardOnly")
        assert bt_client_address is not None
        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=10)
                assert addr == bt_dut_address
            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )
            # Close connection
            bt_client_socket.close()
            time.sleep(
                0.2
            )  # to overcome Unexpected response from 'at+rsibt_unbond=B8-27-EB-8E-A9-99': b'AT+RSIBT_SPPDISCONNECTED B8-27-EB-8E-A9-99\r\n\r\nOK'
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
    logger().info(f"Scan in {t.duration} seconds")

'''=================== Ble-gap IO test cases ===================== '''

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_displayonly_C19851(wifi_dut,ble_client,logger):

    logger.info("Setting the dut IO capability to display only.....")
    wifi_dut.interfaces.wifi.bt_set_ssp_mode(pair_mode=1, capability=0)

    # Set up DUT for BLE advertising
    logger.info("Initiate ble service in DUT")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    logger.info("Set DUT in advertise mode")
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger.info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger.info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    logger.info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices

    logger.info("Connect to the dut with mac address..")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    logger.info("Disconnecting the bt host....")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_display_yesno_C19852(wifi_dut,ble_client,logger):

    logger.info("Setting the dut IO capability to display yes no.....")
    wifi_dut.interfaces.wifi.bt_set_ssp_mode(pair_mode=1, capability=1)

    # Set up DUT for BLE advertising
    logger.info("Initiate ble service in DUT")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    logger.info("Set DUT in advertise mode")
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger.info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger.info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    logger.info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices

    logger.info("Connect to the dut with mac address..")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    logger.info("Disconnecting the bt host....")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_keyboard_only_C19853(wifi_dut,ble_client,logger):

    logger.info("Setting the dut IO capability to keyboard only.....")
    wifi_dut.interfaces.wifi.bt_set_ssp_mode(pair_mode=1, capability=2)

    # Set up DUT for BLE advertising
    logger.info("Initiate ble service in DUT")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    logger.info("Set DUT in advertise mode")
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger.info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger.info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    logger.info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices

    logger.info("Connect to the dut with mac address..")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    logger.info("Disconnecting the bt host....")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_No_input_output_C19854(wifi_dut,ble_client,logger):

    logger.info("Setting the dut IO capability to No input output.....")
    wifi_dut.interfaces.wifi.bt_set_ssp_mode(pair_mode=1, capability=3)

    # Set up DUT for BLE advertising
    logger.info("Initiate ble service in DUT")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    logger.info("Set DUT in advertise mode")
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger.info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger.info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    logger.info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices

    logger.info("Connect to the dut with mac address..")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    logger.info("Disconnecting the bt host....")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

'''======================= Ble-gap IO test cases dut as initiator ====================='''
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_displayonly_C19855(wifi_dut,ble_client):
    logger().info("Setting the dut IO capability to display only.....")
    wifi_dut.interfaces.wifi.bt_set_ssp_mode(pair_mode=1, capability=0)
    # Start DUT
    logger().info("Initiating ble service in dut")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    # Start ble client
    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    # Start scanning and connect to ble client
    logger().info("dut start scanning.....")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
    # Disconnect
    logger().info("Disconnect from the host")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_display_yesno_C19856(wifi_dut,ble_client):
    logger().info("Setting the dut IO capability to display only.....")
    wifi_dut.interfaces.wifi.bt_set_ssp_mode(pair_mode=1, capability=1)
    # Start DUT
    logger().info("Initiating ble service in dut")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    # Start ble client
    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    # Start scanning and connect to ble client
    logger().info("dut start scanning.....")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
    # Disconnect
    logger().info("Disconnect from the host")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_keyboard_only_C19857(wifi_dut,ble_client):
    logger().info("Setting the dut IO capability to display only.....")
    wifi_dut.interfaces.wifi.bt_set_ssp_mode(pair_mode=1, capability=2)
    # Start DUT
    logger().info("Initiating ble service in dut")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    # Start ble client
    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    # Start scanning and connect to ble client
    logger().info("dut start scanning.....")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
    # Disconnect
    logger().info("Disconnect from the host")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_io_cap_no_input_output_C19858(wifi_dut,ble_client):
    logger().info("Setting the dut IO capability to display only.....")
    wifi_dut.interfaces.wifi.bt_set_ssp_mode(pair_mode=1, capability=3)
    # Start DUT
    logger().info("Initiating ble service in dut")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    # Start ble client
    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    # Start scanning and connect to ble client
    logger().info("dut start scanning.....")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 60
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
    # Disconnect
    logger().info("Disconnect from the host")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

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
    assert bt_dut_address is not None
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
    assert result
    logger().info("verifying client addr is available in scan list...")
    assert str(bt_client_address) in str(result)

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
    assert bt_dut_address is not None
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  
                       "0x40 0x00 "  
                       "0x01 "  
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
    assert result
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result)

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
    assert bt_dut_address is not None
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
    assert result
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result)

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
    assert bt_dut_address is not None
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
    assert result
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result)

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
    assert bt_dut_address is not None
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    time.sleep(1)
    assert bt_client_address is not None
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = bt_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result
    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result)

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
    assert bt_dut_address is not None
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
    status = bt_dut.interfaces.bluetooth.ble_start_advertising()
    assert status is not None
    time.sleep(3)
    logger().info(f" scan result '{result}")
    assert result
    logger().info("verifying client addr is available in scan list...")
    assert str(bt_client_address) in str(result)