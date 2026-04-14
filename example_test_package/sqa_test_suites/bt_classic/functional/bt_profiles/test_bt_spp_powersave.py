import pytest
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap,RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
import time
import random
import string

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        }
    )
]

def logger():
    return get_logger(__name__)

def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

""" Author: Sirisha Ayyagari

setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Radio Server (For now running on NUC)
Step1: 1. Configuration of DUT in 2G mode
Step2: Establish SPP Connection
Step3 : Initiating power save 
Step4 : Send data from bt_client to dut
Step5 : Send data from dut to bt_client

"""
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C20043')
def test_DUT_Slave_bt_spp_Tx_and_Rx_powersave_enabled_C20043(bt_dut, bt_client):
        logger().info("Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = bt_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None, 'Could not start DUT as BT SLAVE'
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None, 'Could not start RASPI as master'
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")
        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
        ) as bt_server_socket:
            # SPP Connection
            with bt_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                logger().info(f"Connecting Raspberry PI to DUT-BT")
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert connected

            # Initiating power save
            logger().info(f"Enabling WLAN and BT power save")
            if isinstance(bt_dut.interfaces.wifi, RSSAPICommands):

                bt_dut.interfaces.wifi.power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                )
                bt_dut.interfaces.wifi.bt_power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                )
            logger().info(f"Sending data from bt_client to dut-SPP Rx for 60 sec")
            sw = Stopwatch()
            while sw.elapsed_sec < 60:
                recv_text=text_generator()
                with bt_dut.interfaces.wifi.run_bt_task():
                    sent = bt_server_socket.send(recv_text)
                assert sent, "Sending Data to the  DUT failed"
                logger().info(f"Data packets sent successfully to dut")
                logger().info(f"Validating the data received from BT Client")
                data_sent = bt_server_socket.recv()
                assert data_sent is not None
                assert data_sent.decode() == recv_text, 'Data sent by Remote is different from data received by DUT'
                logger().info(f"Data sent by Remote is  received by DUT")

            logger().info(f"Sending data from dut-SPP Tx for 60 sec")
            sw = Stopwatch()
            while sw.elapsed_sec < 60:
                send_text = text_generator()
                with bt_dut.interfaces.wifi.run_bt_task():
                    bt_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                assert sent, "Sending Data to the Client failed"
                logger().info(f"Data packets sent successfully to Client")
                logger().info(f"Validating the data sent from BT DUT")
                data_sent = bt_server_socket.recv()
                assert data_sent is not None,'Data sent by DUT is different from data received by Client'
                assert data_sent.decode() == send_text, 'Data sent is different from data received'
                logger().info(f"Data sent by DUT is data received by Client")

        logger().info("disconnecting bt host....")
        bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)

        logger().info(f"Close Socket connection")
        bt_server_socket.close()
