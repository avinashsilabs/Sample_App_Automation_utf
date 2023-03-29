import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116BTFeatureBitMap
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.stopwatch import Stopwatch
from datetime import datetime, timedelta
import time

"""Test Author = M.Harshitha

Test Steps:
    1. Initiates the DUT Coex wlan and DualBluetoothBLEmode
    2. Initiates the DUT in master SPP mode (or)slave SPP mode for the capability
    3. Initiates the Client in slave SPP (or) master SPP with capability enables
    4. Opens Bt socket and connects to the remote client.
    5. Verifies ping after the connection.
    6. Switch to Slave to Master Role (Or) Master to Slave Role
    7. Send Data transfer from Dut to BT client.

setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass| RS9116TCPIPFeatureBitMap.DHCPv4Client,
            "ext_tcpip_features": 0,
            "custom_features": RS9116CustomFeatureBitMap.Default,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
            }
        )
    ]

def logger():
    return get_logger(__name__)

#configure this to run the case for no of times in loop
iter_count = 5

#This test case is used to switch the Slave to Master Role
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_bt_spp_dut_as_slave_roleswitch_C19991(wifi_dut, bt_client):
    duration=20
    retry_count=3
    send_text = "AMFJTEJRTOLGWSGJWT"

    logger().info("configuring dut in spp slave role")
    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
    assert bt_dut_address , "failed to initialise bt in dut"
    logger().info(f"BT dut address {bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address, "Failed to initiate master in remote device"
    logger().info(f"BT Client address {bt_client_address}")

    for count in range(0, iter_count):
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=duration, retry_counts=retry_count)
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert connected, "failed to connect to bt dut"
                #Keeping 30 seconds time duration for connection stability
                time.sleep(30)
                # Initiating power save
                logger().info("======= Initiating the Power Save==========")
                if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
                    wifi_dut.interfaces.wifi.set_sleep_gpio(True)
                    logger().info("==========Enables Power Save in Wifi Mode===========")
                    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
                    logger().info("==========Enables Power Save in BT Mode===========")
                    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

                    #Ping DUT
                    ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                    logger().info(f"l2ping response {ping_response}")
                    assert ping_response, "dut is in inactive state..."

                    logger().info("Here Device role 1 is Slave Role, Device role 0 is Master Role")
                    logger().info("===========Fetch the Response of Slave Role==========")
                    # The Below api will fetch the response of Slave Role
                    result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                    logger().info(f"Device role:{result}")
                    assert result,"expected role is 1,but observed role is 0"
                    wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
                    time.sleep(10)
                    # Here we can see the final get response of role Switch
                    logger().info("============Final Role Switch Slave Role to Master Role=========")
                    final_role= wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                    assert final_role,"expected role is 0,but observed role is 1"
                    logger().info(f"Role Switch: {final_role}")

            time.sleep(30)
            # Data will transfer 60 seconds
            end_time = datetime.now() + timedelta(seconds=60)
            while datetime.now() < end_time:
                logger().info("==========Send the data from dut to bt client=========")
                wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_server_socket.recv()
                assert data is not None
                assert data.decode() == send_text
            bt_server_socket.close()
            logger().info("Disconnecting bt client address")
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
        if not found:
                logger().info("device not found")
    logger().info("exiting execution")

#This test case is used to switch the Master to Slave Role
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_bt_spp_dut_as_master_roleswitch_C19990(wifi_dut,bt_client):
    logger().info("This test case is skipped for now due to RSCDEV-9244")
    return
    send_text = "ABCDEFRGHJ12345UIOPLKJ"

    logger().info("configuring dut in spp master role")
    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
    assert bt_dut_address, "Unable to find bt dut address"
    logger().info(f"BT Dut address {bt_dut_address}")

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
    assert bt_client_address

    logger().info("Searching for the bt client address")
    device_found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                           inquiry_type=2,
                                                           inquiry_duration_ms=20000,
                                                           timeout=22,
                                                           retry_counts=3)
    if not device_found:
        logger().error(f"Dut unable to find the bt client device. The test case may fail.")
    logger().info(f"BT found device is {device_found}, found bt client address {bt_client_address}")

    with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
        logger().info("========Spp Connection=======")
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
            addr = bt_client_socket.accept(timeout=10)
            assert addr == bt_dut_address
            #"Keeping 30 seconds time duration for connection stability
            time.sleep(30)
            # Initiating power save
            logger().info("======= Initiating the Power Save==========")
            if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
                wifi_dut.interfaces.wifi.set_sleep_gpio(True)
                logger().info("==========Enables Power Save in Wifi Mode===========")
                wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
                logger().info("==========Enables Power Save in BT Mode===========")
                wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

                # Ping DUT
                ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                logger().info(f"l2ping response {ping_response}")
                assert ping_response, "dut is in inactive state..."

                logger().info("Here Device role 1 is Slave Role, Device role 0 is Master Role")
                logger().info("=========Fetch the Response of Master Role=======")
                # The Below api will fetch the response of Master Role
                result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Device role:{result}")
                assert result ,"expected role is 0,but observed role is 1"
                wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="1")
                time.sleep(10)
                # Here we can see the final get response of role Switch
                logger().info("=========Final Role Switch Master Role to Slave Role=======")
                final_role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                assert final_role,"expected role is 1,but observed role is 1"
            logger().info(f"Role Switch: {final_role}")

            time.sleep(30)
            # Data will transfer 60 seconds
            end_time = datetime.now() + timedelta(seconds=60)

            while datetime.now() < end_time:
                # Send the data from dut to bt client
                logger().info("=========Send the data from dut to bt client==========")
                wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data is not None
                assert data.decode() == send_text
            bt_client_socket.close()

        logger().info("Disconnecting bt client address")
        wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)