import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes,RS9116CertificateType
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
import time
import filecmp
import os
import random
import string
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth.bluez.ble_device import DeviceManager


""" Author: Sirisha Ayyagari
This test case aims to connect the WIFI AP in SPP mode and do data transfer about 800 bytes size
setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
    
"""
def test_bt_dut_as_slave_800bytes_data(wifi_dut, bt_client):
    send_text = "XanthomonacampestrishyacinthiLMG73915843241XanthomonacampestrishyacinthiLMG73915843241XanthomonacampestrishyacinthiLMG73915843241XanthomonacampestrishyacinthiLMG73915843241"
    with TimeMeasurer() as t:
        # DUT API
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None
        # RD API
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None
        with bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Server
        ) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert connected
        # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data is not None
            assert data.decode() == send_text
        # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )
        # Close connection
            bt_server_socket.close()
    logger().info(f"Scan in {t.duration} seconds")

