import time
import pytest
import random
import string
from retry import retry
from random import randint
from contextlib import ExitStack
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.subprocess_manager import SubprocessManager
from utf.interfaces.socket import SOCKET_TYPE_TCP
from utf.interfaces.bluetooth import BTSocketRole
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116AsyncEventType, \
    RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116FeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116BTFeatureBitMap, RS9116ExtTCPIPFeatureBitMap ,DeviceConstants, SocketOptions, RS9116CertificateType, \
    RS9116PowerSaveProcedureTypes, RS9116ConfigFeatureBitMap

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Author: Vishakha
"""

def logger():
    return get_logger(__name__)

def text_generator(size=600):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

def ping_count(utf_constants):
    return utf_constants.get("ping_count")

class powersave_pingThread(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')
        # Initiate ping from third party wifi-client to DUT
        logger().info(f"enabling wifi power save mode in DUT......")
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "failed to enable wifi power save"
        logger().info(f"enabling bt power save mode in DUT......")
        enable_bt_ps = self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "failed to enable bt power save"
        ping_count = 300
        logger().info(f"pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info(f"ping to DUT is successful....")
        return device_ip

def dut_clean_up(wifi_dut, bt_client_address=None):
    logger().info(
        "\n\n ---------------------------- Cleaning UP the DUT ----------------------------"
    )
    try:
        logger().info("BT disconnect from DUT")
        try:
            if bt_client_address:
                wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
        except:
            assert False, "DUT already disconnected from bt_client device"
        time.sleep(5)
        logger().info("Closing all sockets opened in DUT")
        wifi_dut.interfaces.wifi.close_sockets()
        logger().info("Disconnect from AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(5)
    except Exception as err:
        logger().info(
            f"******* Exception occurred while cleaning up the DUT\nException is:{err}\nRecovering the DUT using reset **********"
        )
        wifi_dut.interfaces.wifi.reset()
        time.sleep(20)
    logger().info(
        "\n ---------------------------- Cleaning UP of DUT is Completed ----------------------------"
    )

def dut_recovery(wifi_dut, error):
    recovery_error_codes = ['0xffffffe2', '0xffffffd5']
    for error_code in recovery_error_codes:
        if error_code in str(error):
            logger().info('******* Initiating DUT Recovery using Reset **********')
            wifi_dut.interfaces.wifi.reset()

class BtSppMaster_SlaveThread(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

    def run(self):
        if self.mode == "bt_slave":
            send_text = text_generator(size=20)
            recv_text = send_text

            logger().info(f"Configuring DUT as SPP Slave")
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address, "Unable to get BT DUT address"
            logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address, "Unable to get BT client address"
            logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")
            found = self.bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20,retry_counts=3)
            assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

            logger().info(f"Starting Raspberry PI as BT Server")
            bt_server_socket = self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
            # SPP Connection
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                logger().info(f"Connecting Raspberry PI to DUT-BT")
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert connected, "Unable to find BT server socket connection"
                logger().info(f" BT_CONNECT SUCCESSFUL ")
            assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address),f"Failed to ping BT client to DUT"

            # Send data from bt_client to dut
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                assert sent, "Unable to send the data"
                time.sleep(10)
                data = bt_server_socket.recv()
                logger().info(f"Connecting BT server socket")
                assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

            # Send data from dut to bt_client
            self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            logger().info(f"Connecting BT server socket")
            assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"

            # Ping dut
            assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"


# This Thread is used to sent different data
class BtSpp_role_switch(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

        if self.mode == "slave_to_master":
            logger().info(f"Configuring DUT as SPP Slave")
            bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address, "Unable to get BT DUT address"
            logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
            bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address, "Unable to get BT client address"
            logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")
            found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
            assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

            logger().info(f"Starting Raspberry PI as BT Server")
            bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                logger().info(f"Connecting Raspberry PI to DUT-BT")
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert connected, "Unable to find BT server socket connection"
                logger().info(f" BT_CONNECT SUCCESSFUL ")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address),f"Failed to ping BT client to DUT"

            result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
            logger().info(f"Device role:{result}")
            wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
            time.sleep(10)
            device_role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
            logger().info(f"Role Switch: {device_role}")

            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"

        if self.mode == "master_to_slave":
            logger().info(f"Configuring DUT as SPP MASTER")
            bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address, "Unable to get BT DUT address"
            logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
            bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address, "Unable to get BT client address"
            logger().info(f"Raspberry PI is BT-SLAVE  with MAC address {bt_client_address} ")

            logger().info(f"Starting Raspberry PI as BT Server")
            bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                logger().info(f"Connecting Raspberry PI to DUT-BT")
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=40)
                assert addr == bt_dut_address, "Unable to find BT client socket connection"
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"

            result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
            logger().info(f"Device role:{result}")
            wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
            time.sleep(10)
            device_role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
            logger().info(f"Role Switch: {device_role}")

            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"


# this thread used for wifi join
class wifiJoinThread(ThreadBase):
    def __init__(self, wifi_sniffer, wifi_dut, wifi_access_point, testcase, utf_constants, rs_helper):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.testcase = testcase
        self.utf_constants = utf_constants
        self.rs_helper = rs_helper

    def run(self):
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = self.rs_helper.check_wifi_connectivity(self.utf_constants, self.wifi_dut, self.wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '


# This Thread is used to sent different data
class BtSppMasterThread_diff_data(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode, utf_constants, tx_rx_duration=5):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode
        self.utf_constants = utf_constants
        self.tx_rx_duration = tx_rx_duration

    def run(self):
        if self.mode == "single":
            send_text = "B"
            recv_text = send_text
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address, f"Failed to get bt client address"
            time.sleep(1)
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                        inquiry_type=1,
                                                                        inquiry_duration_ms=20000,
                                                                        timeout=22,
                                                                        retry_counts=5)
            assert found, f"Dut unable to find the bt client device:{bt_client_address}"

            bt_client_socket = self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
            # SPP Connection
            logger().info(f"***** SPP Connection ****")
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(self.wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                     (bt_client_socket.accept, 20)]
                )
                assert result[1] == bt_dut_address
                logger().info(f"Result from Callable Function {result}")

            t_end = time.time() + self.tx_rx_duration
            while time.time() < t_end:
                # Send data from bt_client to dut
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                    logger().info(f"***** Send data from bt_client to dut ****")
                    assert sent, f"Failed to sent data"
                    data = bt_client_socket.recv()
                    assert data, f"Failed to send back data from SQA Agent programme"
                    assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

                # Send data from dut to bt_client
                logger().info("Send data from dut to bt_client")
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
                time.sleep(1)

                # Ping dut
                logger().info(f"**** pinging to DUT ****")
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"

        if self.mode == "numbers":
            data_length = [198,200,400,800]
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address, f"Failed to get bt client address"
            time.sleep(1)
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                        inquiry_type=1,
                                                                        inquiry_duration_ms=20000,
                                                                        timeout=22,
                                                                        retry_counts=5)
            assert found, f"Dut unable to find the bt client device:{bt_client_address}"

            bt_client_socket = self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
            # SPP Connection
            logger().info(f"***** SPP Connection ****")
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(self.wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                     (bt_client_socket.accept, 20)]
                )
                assert result[1] == bt_dut_address
                logger().info(f"Result from Callable Function {result}")

            for i in data_length:
                send_text = text_generator(size=i)
                recv_text = send_text
                iter_count = self.utf_constants.get("iter_count")
                for j in range(0, iter_count):
                    # Send data from bt_client to dut
                    with self.wifi_dut.interfaces.wifi.run_bt_task():
                        sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                        logger().info(f"***** Send data from bt_client to dut ****")
                        assert sent, f"Failed to sent data"
                        data = bt_client_socket.recv()
                        assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

                    # Send data from dut to bt_client
                    logger().info("Send data from dut to bt_client")
                    self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                    data = bt_client_socket.recv()
                    assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
                    time.sleep(1)

                    # Ping dut
                    logger().info(f"**** pinging to DUT ****")
                    assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                        f"Failed to ping BT client to DUT"
                    logger().info(f">>>>>>>>>>> iteration {j} completed for Data length {i}<<<<<<<<<<<<<<")


        if self.mode == "paragraph":
            send_text = text_generator(size=800)
            recv_text = send_text
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address, f"Failed to get bt client address"
            time.sleep(1)
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                        inquiry_type=1,
                                                                        inquiry_duration_ms=20000,
                                                                        timeout=22,
                                                                        retry_counts=5)
            assert found, f"Dut unable to find the bt client device:{bt_client_address}"

            bt_client_socket = self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
            # SPP Connection
            logger().info(f"***** SPP Connection ****")
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(self.wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                     (bt_client_socket.accept, 20)]
                )
                assert result[1] == bt_dut_address
                logger().info(f"Result from Callable Function {result}")

            # Send data from bt_client to dut
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                logger().info(f"***** Send data from bt_client to dut ****")
                assert sent, f"Failed to sent data"
                time.sleep(10)
                data = bt_client_socket.recv()
                assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

            # Send data from dut to bt_client
            logger().info("Send data from dut to bt_client")
            self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"

            # Ping dut
            logger().info(f"**** pinging to DUT ****")
            assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"

        if self.mode == "special_characters":
            send_text = "@#$%^&*()_!_)(*&^%$#@!"
            recv_text = send_text
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address, f"Failed to get bt client address"
            time.sleep(1)
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                        inquiry_type=1,
                                                                        inquiry_duration_ms=20000,
                                                                        timeout=22,
                                                                        retry_counts=5)
            assert found, f"Dut unable to find the bt client device:{bt_client_address}"

            bt_client_socket = self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
            # SPP Connection
            logger().info(f"***** SPP Connection ****")
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(self.wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                     (bt_client_socket.accept, 20)]
                )
                assert result[1] == bt_dut_address
                logger().info(f"Result from Callable Function {result}")

            t_end = time.time() + self.tx_rx_duration
            while time.time() < t_end:
                # Send data from bt_client to dut
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                    logger().info(f"***** Send data from bt_client to dut ****")
                    assert sent, f"Failed to sent data"
                    data = bt_client_socket.recv()
                    assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

                # Send data from dut to bt_client
                logger().info("Send data from dut to bt_client")
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"

                # Ping dut
                logger().info(f"**** pinging to DUT ****")
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"

        if self.mode == "different_language":
            send_text = "支那支那支那支那支那支那"
            recv_text = send_text
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address, f"Failed to get bt client address"
            time.sleep(1)
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                        inquiry_type=1,
                                                                        inquiry_duration_ms=20000,
                                                                        timeout=22,
                                                                        retry_counts=5)
            assert found, f"Dut unable to find the bt client device:{bt_client_address}"

            bt_client_socket = self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
            # SPP Connection
            logger().info(f"***** SPP Connection ****")
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(self.wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                     (bt_client_socket.accept, 20)]
                )
                assert result[1] == bt_dut_address
                logger().info(f"Result from Callable Function {result}")

            t_end = time.time() + self.tx_rx_duration
            while time.time() < t_end:
                # Send data from bt_client to dut
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                    logger().info(f"***** Send data from bt_client to dut ****")
                    assert sent, f"Failed to sent data"
                    data = bt_client_socket.recv()
                    assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"
                    logger().info(f'Data received from BT_client')

                # Send data from dut to bt_client
                logger().info("Send data from dut to bt_client")
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
                logger().info(f'Data received from dut')

                # Ping dut
                logger().info(f"**** pinging to DUT ****")
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"


class Cleanupactivity(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        self.wifi_dut.interfaces.wifi.leave()

class ServerSocketXferThread(ThreadBase):
    def __init__(self, wifi_dut, dut_socket, server_socket, num_packets, num_bytes):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.dut_socket = dut_socket
        self.server_socket = server_socket
        self.num_packets = num_packets
        self.num_bytes = num_bytes

    def run(self):
        # socket opened in DUT connects to the server
        self.wifi_dut.interfaces.wifi.connect_to_server(self.dut_socket, self.server_socket)
        for _ in range(0, self.num_packets):
            # DUT sends num_bytes bytes of data over socket
            self.wifi_dut.interfaces.wifi.send(self.dut_socket, self.num_bytes, timeout=3)

        # DUT closes the client socket
        result = self.wifi_dut.interfaces.wifi.close_socket(self.dut_socket)
        assert b"success" in result, "unable to close opened socket"
        self.server_socket.socket_close_indication(1)


def socket_connect(wifi_dut, remote_socket, socket_id, dut_ip, server_port, local_port):
    logger().info("Binding socket in DUT")
    bind_response = wifi_dut.interfaces.wifi.bind(socket_id, dut_ip, local_port)
    logger().info(f"Bind socket successfully: {bind_response}")

    logger().info("DUT is connecting to server socket")
    connect_status = False
    for count in range(3):
        try:
            wifi_dut.interfaces.wifi.connect_to_server(socket_id, remote_socket.interfaces.socket, server_port)
            connect_status = True
            break
        except:
            logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
            time.sleep(10)
    assert connect_status, "Socket connection failed in DUT"
    logger().info("Socket connection is successful")
    time.sleep(3)

@retry(Exception, delay=15, tries=3)
def run_tcp_traffic(wifi_dut, wifi_client, remote_socket, dut_ip, data_len=1461):
    interface = 'eth1'
    logger().info("Starting TCP server socket remotely")
    tcp_port = randint(6000, 6100)
    remote_socket.interfaces.socket.interface = "eth0"
    remote_socket.interfaces.socket.time_limit = 3000
    logger().info("Starting TCP Server socket at remote device")
    remote_socket.interfaces.socket.start_server(socket_type=0, port=tcp_port)
    # 0-TCP, 1-UDP
    server_port = remote_socket.interfaces.socket.server_port
    logger().info("Opening TCP client socket in DUT")
    tcp_socket_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    logger().info(f"Socket open successfully : {tcp_socket_id}")
    time.sleep(5)
    TCP_MAX_RETRY = 10
    wifi_dut.interfaces.wifi.set_socket_option(tcp_socket_id, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                TCP_MAX_RETRY)
    logger().info("Initiating TCP socket connection from DUT")
    socket_connect(wifi_dut, remote_socket, tcp_socket_id, dut_ip, server_port, tcp_port)
    for data_length in range(1, data_len):  # 1461
        data = text_generator(data_length)
    send_data_length = len(data)
    t_end = 60
    sw = Stopwatch()
    while sw.elapsed_sec <= t_end:
        wifi_dut.interfaces.wifi.send(tcp_socket_id, send_data_length)
        logger().info(f"\n\nInitiating TCP data transfer from DUT with data length:'{send_data_length}'")
        if sw.elapsed_sec in range(30, 35):
            logger().info(f"=======>>>>>Disabling the ethernet adaptor at remote side....")
            wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {interface} down")
    logger().info("Validating received data on remote server")
    data_received = remote_socket.interfaces.socket.recv_data_tcp(send_data_length)
    logger().info(f"Length of data received is: '{len(data_received)}'")
    assert send_data_length == len(data_received), "data length sent by DUT and received on remote peer is not matching"
    logger().info("data sent by DUT and received on remote peer is matching")
    return tcp_port


#Verify the BT connection in the Coex mode while WLAN is in connected state
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default |
                               RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_mode_C20088(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    bt_client_address = None
    try:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_mode_C20088')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT device"
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        iter_count = utf_constants.get("iter_count")
        for i in range(1, iter_count):
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                logger().info(f"Connecting Raspberry PI to DUT-BT")
                time.sleep(5)
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert connected, "Unable to find BT server socket connection"
                logger().info(f" BT_CONNECT SUCCESSFUL ")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address),f"Failed to ping BT client to DUT"
            logger().info(f"iteration completed: {i}")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#BT stability in the Coex mode by multiple connection and disconnection
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_mode_as_slave_C20089(wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    mode = "bt_slave"
    bt_client_address = None
    try:
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)
        t2 = BtSppMaster_SlaveThread(wifi_dut, bt_client, mode)
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            t2.start()
            time.sleep(5)
            t2.wait_for_exit(True)
            logger().info(f" iteration completed: {i} ")

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#BT Role change from master to slave in the Coex mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_mode_C20090(wifi_dut, bt_client, wifi_access_point, utf_constants, rs_helper):
    bt_client_address = None
    mode = "master_to_slave"
    try:
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)
        t1 = BtSpp_role_switch(wifi_dut, bt_client, mode)
        t1.start()
        time.sleep(5)
        t1.wait_for_exit(True)

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#BT Role change from slave to master in the Coex mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_mode_C20091(wifi_dut, bt_client, wifi_access_point, utf_constants, rs_helper):
    bt_client_address = None
    mode = "slave_to_master"
    try:
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)
        t1 = BtSpp_role_switch(wifi_dut, bt_client, mode)
        t1.start()
        time.sleep(5)
        t1.wait_for_exit(True)

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#SPP data transfer Rx in Slave mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default |
                               RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_spp_data_transfer_RX_slave_C20092(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper, tx_rx_duration=60):
    send_text = text_generator(size=20)
    recv_text = send_text
    validation = True
    bt_client_address = None
    try:
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_spp_data_transfer_RX_slave_C20092')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT device"
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            logger().info(f"Connecting Raspberry PI to DUT-BT")
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected, "Unable to find BT server socket connection"
            logger().info(f" BT_CONNECT SUCCESSFUL ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address),f"Failed to ping BT client to DUT"

        t_end = time.time() + tx_rx_duration
        while time.time() < t_end:
            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                assert sent, "Unable to send the data"
                time.sleep(10)
                data = bt_server_socket.recv()
                assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

        # Ping dut
        logger().info(f"  Ping to DUT ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"
        logger().info(f" Pinging ")

        #BD address
        local_addr = wifi_dut.interfaces.wifi.bt_get_local_address()
        logger().info(f'BT LOCAL address: {local_addr} found')
        #local name
        local_name = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f'BT LOCAL name: {local_name} found')

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#SPP data transfer TX in Slave mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default |
                               RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_spp_data_transfer_TX_slave_C20093(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper, tx_rx_duration=60):
    send_text = text_generator(size=20)
    validation = True
    bt_client_address = None
    try:
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_spp_data_transfer_TX_slave_C20093')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT device"
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            logger().info(f"Connecting Raspberry PI to DUT-BT")
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected, "Unable to find BT server socket connection"
            logger().info(f" BT_CONNECT SUCCESSFUL ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address),f"Failed to ping BT client to DUT"

        t_end = time.time() + tx_rx_duration
        while time.time() < t_end:
            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"

        # Ping dut
        logger().info(f"  Ping to DUT ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"
        logger().info(f" Pinging ")

        #BD address
        local_addr = wifi_dut.interfaces.wifi.bt_get_local_address()
        logger().info(f'BT LOCAL address: {local_addr} found')
        #local name
        local_name = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f'BT LOCAL name: {local_name} found')

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#SPP data transfer Tx in Master mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default |
                               RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_spp_data_transfer_TX_master_C20094(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper, tx_rx_duration=60):
    send_text = text_generator(size=20)
    validation = True
    bt_client_address = None
    try:
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_spp_data_transfer_TX_master_C20094')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE  with MAC address {bt_client_address} ")

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            logger().info(f"Connecting Raspberry PI to DUT-BT")
            wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
            addr = bt_client_socket.accept(timeout=40)
            assert addr == bt_dut_address, "Unable to find BT client socket connection"

        t_end = time.time() + tx_rx_duration
        while time.time() < t_end:
            # Send data from dut to bt_client
            logger().info(f'Data transfer from dut')
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
            logger().info(f'Data received from dut')

        # Ping dut
        logger().info(f"  Ping to DUT ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"
        logger().info(f" Pinging ")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



# SPP data transfer (Rx) in Master mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default |
                               RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_spp_data_transfer_RX_master_C20095(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper, tx_rx_duration=60):
    send_text = text_generator(size=20)
    recv_text = send_text
    bt_client_address = None
    try:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_spp_data_transfer_RX_master_C20095')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE  with MAC address {bt_client_address} ")

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            logger().info(f"Connecting Raspberry PI to DUT-BT")
            wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
            addr = bt_client_socket.accept(timeout=40)
            assert addr == bt_dut_address, "Unable to find BT client socket connection"
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"

        t_end = time.time() + tx_rx_duration
        while time.time() < t_end:
            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f'Data transfer from BT_client')
                sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                assert sent, "Unable to send the data"
                time.sleep(10)
                data = bt_client_socket.recv()
                assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"
                logger().info(f'Data received from BT_client')

        # Ping dut
        logger().info(f"  Ping to DUT ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"
        logger().info(f" Pinging ")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#SPP transfer by taking remote OOO
@pytest.mark.skip()
@pytest.mark.rf_attenuator('50pa500_attenuator')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_OOR_C20096(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper, rf_attenuator):
    send_text = text_generator(size=20)
    recv_text = send_text
    validation = True
    bt_client_address = None
    try:
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_OOR_C20096')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE  with MAC address {bt_client_address} ")

        logger().info(f"start bt inquiry")
        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=1,
                                                               inquiry_duration_ms=20000,
                                                               timeout=22,
                                                               retry_counts=5)
        assert found, f"Dut unable to find the bt client device:{bt_client_address}"

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                logger().info(f"Connecting Raspberry PI to DUT-BT")
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=40)
                assert addr == bt_dut_address, "Unable to find BT client socket connection"
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f'Data transfer from BT_client')
                sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                assert sent, "Unable to send the data"
                time.sleep(10)
                data = bt_client_socket.recv()
                assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"
                logger().info(f'Data received from BT_client')

            # Send data from dut to bt_client
            logger().info(f'Data transfer from dut')
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
            logger().info(f'Data received from dut')

        # Ping dut
        logger().info(f"  Ping to DUT ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"
        logger().info(f" Pinging ")

        received_authentication_failure = False
        time.sleep(1)
        events = wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    received_authentication_failure = b"4E08" in event.event_data
                    break
        assert received_authentication_failure, "Unable to receive authentication error code 4E08"

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#Validate SPP transfer by disconnecting from RD1
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default |
                               RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_SPP_data_transfer_by_disconnecting_from_RD_C20097(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    send_text = text_generator(size=20)
    recv_text = send_text
    validation = True
    bt_client_address = None
    try:
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_SPP_data_transfer_by_disconnecting_from_RD_C20097')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT device"
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            logger().info(f"Connecting Raspberry PI to DUT-BT")
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected, "Unable to find BT server socket connection"
            logger().info(f" BT_CONNECT SUCCESSFUL ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address),f"Failed to ping BT client to DUT"

        # Send data from bt_client to dut
        with wifi_dut.interfaces.wifi.run_bt_task():
            sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
            assert sent, "Unable to send data"
            time.sleep(10)
            data = bt_server_socket.recv()
            assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

        # Send data from dut to bt_client
        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
        data = bt_server_socket.recv()
        assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"

        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"

        # Close connection
        start_capture_time = time.perf_counter_ns()
        bt_server_socket.close()
        time.sleep(5)

        # cheking for disconnected event
        rsi_bt_on_spp_disconnect = False
        rsi_bt_on_disconn_event = False
        events = wifi_dut.interfaces.wifi.get_async_events(since_time=start_capture_time)
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_SPP_DISCONN:
                    rsi_bt_on_spp_disconnect = True
                if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_DISCONNECTED:
                    rsi_bt_on_disconn_event = b"4E13" in event.event_data

        assert rsi_bt_on_spp_disconnect
        assert rsi_bt_on_disconn_event

        # Send data from dut to bt_client after closing socket
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            assert exc_info.value.error_code == 0x4500, "SPP Not Connected, expected is 0x4500"

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#validate BT SPP Init and BT Deinit in Slave Mode while WLAN_STA is in connected state
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_spp_init_deinit_in_slave_C20098(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    send_text = text_generator(size=20)
    recv_text = send_text
    bt_client_address = None
    try:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_spp_init_deinit_in_slave_C20098')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            bt_pin_code = "4321"
            wifi_dut.interfaces.wifi.bt_start()
            bt_dut_address = wifi_dut.interfaces.wifi.bt_get_local_address()
            time.sleep(2)
            logger().info("configuring dut in discoverable mode...")
            wifi_dut.interfaces.wifi.bt_start_discoverable()
            time.sleep(2)
            logger().info("configuring dut in connectable mode...")
            wifi_dut.interfaces.wifi.bt_set_connectable()
            time.sleep(2)
            wifi_dut.interfaces.wifi.bt_set_slave_role()
            wifi_dut.interfaces.wifi.bt_set_ssp_mode(0, 3)
            wifi_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)
            logger().info("initialising dut in spp....")
            wifi_dut.interfaces.wifi.bt_spp_init()
            time.sleep(2)
            bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code=bt_pin_code)
            assert bt_client_address, "Unable to get BT client address"

            found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
            if not found:
                assert found, "Dut was not found during the scan by bt client. The test case may fail"
            logger().info(f"Starting Raspberry PI as BT Server")
            bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                logger().info(f"Connecting Raspberry PI to DUT-BT")
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected, "Unable to find BT server socket connection"
                logger().info(f" BT_CONNECT SUCCESSFUL ")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address),f"Failed to ping BT client to DUT"

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                assert sent, "Unable to send the data"
                time.sleep(10)
                data = bt_server_socket.recv()
                assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"

            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
            bt_server_socket.close()

            logger().info("Disabling bt radio of the DUT")
            wifi_dut.interfaces.wifi.bt_deinit()
            logger().info("Disabled bt radio of the DUT")
            time.sleep(2)
            logger().info("Enabling bt radio of the DUT")
            wifi_dut.interfaces.wifi.bt_init()
            logger().info("Enabled bt radio of the DUT")
            logger().info(f"iteration completed: {i}")

        #Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#Validate BT SPP Init and BT Deinit in Master Mode when WLAN is in connected state
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default |
                               RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_spp_init_deinit_in_master_C20099(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    send_text = text_generator(size=20)
    recv_text = send_text
    validation = True
    bt_client_address = None
    try:
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_spp_init_deinit_in_master_C20099')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            bt_pin_code = "4321"
            wifi_dut.interfaces.wifi.bt_start()
            bt_dut_address = wifi_dut.interfaces.wifi.bt_get_local_address()
            logger().info(f'BT LOCAL address: {bt_dut_address} found')
            local_name = wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info(f'BT LOCAL name: {local_name} found')
            wifi_dut.interfaces.wifi.bt_set_master_role()
            wifi_dut.interfaces.wifi.bt_set_ssp_mode(0, 3)
            wifi_dut.interfaces.wifi.bt_set_pin_code(bt_pin_code)
            logger().info("initialising dut in spp....")
            wifi_dut.interfaces.wifi.bt_spp_init()
            time.sleep(2)

            bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code=bt_pin_code)
            assert bt_client_address, "Unable to get BT client address"
            logger().info(f"Raspberry PI is BT-SLAVE  with MAC address {bt_client_address} ")

            logger().info(f"Starting Raspberry PI as BT Server")
            bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                logger().info(f"Connecting Raspberry PI to DUT-BT")
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=40)
                assert addr == bt_dut_address, "Unable to find BT client socket connection"

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f'Data transfer from BT_client')
                sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                assert sent, "Unable to send the data"
                data = bt_client_socket.recv()
                assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"
                logger().info(f'Data received from BT_client')

            # Send data from dut to bt_client
            logger().info(f'Data transfer from dut')
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
            logger().info(f'Data received from dut')

            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
            bt_client_socket.close()

            logger().info("Disabling bt radio of the DUT")
            wifi_dut.interfaces.wifi.bt_deinit()
            logger().info("Disabled bt radio of the DUT")
            time.sleep(2)
            logger().info("Enabling bt radio of the DUT")
            wifi_dut.interfaces.wifi.bt_init()
            logger().info("Enabled bt radio of the DUT")
            logger().info(f"iteration completed: {i}")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)



#EAP Connection in TTLS mode
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake |RS9116FeatureBitMap.OpenMode |RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default |RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116CertificateType.EAPClientCertificate | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "band": 0,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated" , "clear_certs"])
def test_bt_coex_eap_C20100(radius_server, wifi_sniffer, wifi_dut, wifi_access_point, bt_client, net_perf_client, wifi_client,
                            protocol, utf_constants, rs_helper, tx_rx_duration=30):
    send_text = text_generator(size=20)
    recv_text = send_text
    bt_client_address = None
    try:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_eap_C20100')
        ap_user_name = "\\\"user1\\\""
        ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
        dut_ssid = wifi_access_point.interfaces.wifi.ssid
        dut_security = wifi_access_point.interfaces.wifi.security
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        logger().info("scanning for AP")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
        logger().info(scan_results)

        # test_wifi_join
        wifi_dut.interfaces.wifi.eap_method(eap_method="TTLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"",private_key="\"\"")
        result = wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        timeout = 60
        #Run iperf as traffic_type is RX
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT device"
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        time.sleep(1)

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                              inquiry_type=1,
                                                              inquiry_duration_ms=20000,
                                                              timeout=22,
                                                              retry_counts=5)
        assert found, f"Dut unable to find the bt client device:{bt_client_address}"

        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            result = ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                (bt_client_socket.accept, 20)])
            assert result[1] == bt_dut_address, "Unable to find BT client socket connection"
            logger().info(f"Result from Callable Function {result}")

        t_end = time.time() + tx_rx_duration
        while time.time() < t_end:
            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f'Data transfer from BT_client')
                sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                assert sent, "Unable to send the data"
                data = bt_client_socket.recv()
                assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"
                logger().info(f'Data received from BT_client')

            # Send data from dut to bt_client
            logger().info(f'Data transfer from dut')
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
            logger().info(f'Data received from dut')

        # Sniffer stop
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#Inquiry in Coex Mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_inquiry_C20101(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper, tx_rx_duration=60):
    bt_client_address = None
    try:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_inquiry_C20101')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(5)

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE  with MAC address {bt_client_address} ")

        t_end = time.time() + tx_rx_duration
        while time.time() < t_end:
            logger().info(f' initialize bt inquiry ')
            found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                   inquiry_type=1,
                                                                   inquiry_duration_ms=20000,
                                                                   timeout=22,
                                                                   retry_counts=5)
            assert found, f"Dut unable to find the bt client device:{bt_client_address}"
            logger().info(f'bt inquiry successful: , {found}')

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#BT Inquiry command complete event with no remotes around
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_noremote_C20102(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    bt_client_address = None
    try:
        event_found = 0
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_noremote_C20102')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=1,
                                                               inquiry_duration_ms=20000,
                                                               max_device_cnt=1,
                                                               timeout=60,
                                                               retry_counts=1)
        assert found, f"Dut unable to find the bt client device:{bt_client_address}"

        # Get Asynchronous messages
        events = wifi_dut.interfaces.wifi.get_async_events()
        assert len(events) > 0, "Events not found"
        # Search for Inquiry Complete Event
        event_data = ''
        for event in events:
            event_data = event_data + str(event.event_data.decode())
            logger().info(f" ###### EVENT DATA ARE '{event_data}' ######")
            if 'nRSI_APP_EVENT_INQ_COMPLT' in event_data:
                logger().info(f"inquiry complete event found: {event_data}")
                break
        if bt_client_address not in event_data:
            logger().info(f" ** BT CLIENT ADDRESS NOT IN EVENT DATA *** ")
            event_found = 1
            logger().info(f" ** EVENT FOUND VALUE IS '{event_found}' *** ")
            assert True
        if event_found == 0:
            assert False, logger().info(f"inquiry complete event not found")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#BT Inquiry command cancel
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=[ 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_cancel_inquiry_C20103(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    bt_client_address = None
    try:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_cancel_inquiry_C20103')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info(f' initialize bt inquiry ')
        wifi_dut.interfaces.wifi.bt_start()
        wifi_dut.interfaces.wifi.bt_inquiry(inquiry_duration_ms=20000, max_device_cnt=9)
        logger().info(f'bt inquiry successful')
        time.sleep(1)
        # Cancel BT inquiry
        wifi_dut.interfaces.wifi.bt_cancel_inquiry()
        logger().info("Inquiry cancelled")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#slave mode by providing wrong Pin key on the RD while WLAN is in idle connection
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_wrong_pin_C20104(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    bt_client_address = None
    try:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_wrong_pin_C20104')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp(bt_pin_code="1234")
        assert bt_dut_address, f"Failed to get bt dut address"
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code="9876")
        assert bt_client_address, f"Failed to get bt client address"

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            # SPP Connection
            logger().info("**** SPP Connection ****")
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=1)
                time.sleep(1)
                assert not connected, f"Failed to connect spp connection"
            logger().info(f"iteration completed: {i}")

        logger().info(f"Keeping wlan in idle state for 5 mins")
        time.sleep(300)

        recieved_authentication_failure = False
        events = wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    recieved_authentication_failure = b"4E05" in event.event_data
                    break
        assert recieved_authentication_failure, f" Unable to receive authentication error code 4E05 "

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#MASTER when Pin-code is not entered when prompted for pin while WLAN is in connected state
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_without_pin_C20105(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    bt_client_address = None
    try:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_without_pin_C20105')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"Configuring DUT as SPP Master")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave_without_agent(bt_dut_address)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        logger().info(f' initialize bt inquiry ')
        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=1,
                                                               inquiry_duration_ms=10000,
                                                               timeout=22,
                                                               retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"
        logger().info(f' bt inquiry successful')

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        # SPP Connection
        logger().info(f'Create SPP Connection')
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            result = ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address), (bt_client_socket.accept, 60)])
            assert result[1] is None, "Unable to find BT client socket connection"
            logger().info(f'SPP Connection Completed')

        # Close connection
        logger().info(f"BT client socket connection closing")
        bt_client_socket.close()
        time.sleep(2)

        received_authentication_failure = False
        time.sleep(1)
        events = wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    received_authentication_failure = b"4E18" in event.event_data
                    break
        assert received_authentication_failure, "Unable to receive authentication error code 4E18"

    # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



# master mode by providing wrong Pin key on the RD while WLAN is in idle connection
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_without_pin_C20106(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    bt_client_address = None
    try:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_without_pin_C20106')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"Configuring DUT as SPP Master")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave_without_agent(bt_dut_address)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        logger().info(f' initialize bt inquiry ')
        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=1,
                                                               inquiry_duration_ms=10000,
                                                               timeout=22,
                                                               retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"
        logger().info(f' bt inquiry successful')

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        # SPP Connection
        logger().info(f'Create SPP Connection')
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            result = ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address), (bt_client_socket.accept, 60)])
            assert result[1] is None, "Unable to find BT client socket connection"
            logger().info(f'SPP Connection Completed')

        logger().info(f"Keeping wlan in idle state for 5 mins")
        time.sleep(300)

        # Close connection
        logger().info(f"BT client socket connection closing")
        bt_client_socket.close()
        time.sleep(2)

        received_authentication_failure = False
        time.sleep(1)
        events = wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    received_authentication_failure = b"4E18" in event.event_data
                    break
        assert received_authentication_failure, "Unable to receive authentication error code 4E18"

        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#Validate BT bond reject
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default |
                               RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_spp_remote_unpair_C20107(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, bt_dut):
    bt_client_address = None
    try:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_spp_remote_unpair_C20107')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info(f"connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info(f"enabling dhcp in DUT.......")
        for count in range(3):
            try:
                ip_config = wifi_dut.interfaces.wifi.start_ip()
                result = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
                logger().info(f"Found device ip: {result}")
                assert isinstance(ip_config, wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
                device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                logger().info(f'DUT ip {device_ip}')
                break
            except:
                logger().info(f"Getting DHCP IP failed...retry count:{count + 1}")
                time.sleep(3)

        logger().info("powersave_ping is started....")
        ping_obj = powersave_pingThread(wifi_dut)
        ping_obj.start()
        time.sleep(5)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"Configuring DUT as SPP Master")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code=-9)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=1,
                                                               inquiry_duration_ms=20000,
                                                               timeout=22,
                                                               retry_counts=5)
        assert found, f"Dut unable to find the bt client device:{bt_client_address}"

        for i in range(3):
            logger().info(
            "Send SPP Connection From DUT and reject pairing request from remote device")
            logger().info(f"Create SPP Connection attempt: {i + 1}")
            with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
                with bt_dut.interfaces.bluetooth.run_bt_task():
                    bt_client_socket.create_client()
                    time.sleep(5)
                    bt_dut.interfaces.bluetooth.bt_connect(bt_client_address)

        logger().info("powersave_ping completed....")
        ping_obj.wait_for_exit(True)
        time.sleep(1)

        received_authentication_failure = False
        events = bt_dut.interfaces.bluetooth.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    received_authentication_failure = b"4E16" in event.event_data
                    break
        assert received_authentication_failure, f"Did not receive authentication failure message"
        logger().info("Received Authentication failure message")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



# BT unbond after successful bonding
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_unbond_C20108(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    bt_client_address = None
    try:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_unbond_C20108')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        time.sleep(3)

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                   inquiry_type=1,
                                                                   inquiry_duration_ms=20000,
                                                                   timeout=22,
                                                                   retry_counts=5)
            assert found, f"Dut unable to find the bt client device:{bt_client_address}"

            logger().info(f"Connecting Raspberry PI to DUT-BT")
            wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
            time.sleep(5)

            # Close connection
            logger().info(f"disconnecting bt host....")
            result = bt_client.interfaces.bluetooth.bt_device.remove_device(bt_dut_address)
            logger().info(f"successfully disconnected device, {result}")
            time.sleep(2)
            logger().info(f"iteration completed: {i}")

        # Again start bt inquiry
        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=1,
                                                               inquiry_duration_ms=20000,
                                                               timeout=22,
                                                               retry_counts=5)
        assert found, f"Dut unable to find the bt client device:{bt_client_address}"

        logger().info(f"Connecting Raspberry PI to DUT-BT")
        wifi_dut.interfaces.wifi.bt_connect(bt_client_address)

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#RSSI value of the connected remote device
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_rssi_C20109(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    bt_client_address = None
    try:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_rssi_C20109')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client.interfaces.bluetooth.close()
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                              inquiry_type=1,
                                                              inquiry_duration_ms=20000,
                                                              timeout=22,
                                                              retry_counts=5)
        assert found, f"Dut unable to find the bt client device:{bt_client_address}"

        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            result = ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                 (bt_client_socket.accept, 20)])
            assert result[1] == bt_dut_address, "Unable to find BT client socket connection"
            logger().info(f"Result from Callable Function {result}")

        # Check if DUT(BT) device is able to issue RSSI query and getting response for the same from remote BT device.
        logger().info("Issuing rssi query from DUT")
        result = wifi_dut.interfaces.wifi.bt_get_rssi(bt_remote_dev_address=bt_client_address)
        logger().info(f"Result of rssi query from DUT is: {result}")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#To get local BD address and local name
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_BD_C20110(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    send_text = text_generator(size=20)
    recv_text = send_text
    bt_client_address = None
    try:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_BD_C20110')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            logger().info(f"Initiating BT_CONNECT ")
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected, "Unable to find BT server socket connection"
            logger().info(f" BT_CONNECT SUCCESSFUL ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address),f"Failed to ping BT client to DUT"

        # Send data from bt_client to dut
        with wifi_dut.interfaces.wifi.run_bt_task():
            sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
            assert sent, "Unable to send the data"
            data = bt_server_socket.recv()
            assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

        # Send data from dut to bt_client
        logger().info(f" Initiating BT_SPP TRANSFER ")
        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
        data = bt_server_socket.recv()
        assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"

        # Ping dut
        logger().info(f"  Ping to DUT ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"
        logger().info(f" Pinging ")

        #BD address
        local_addr = wifi_dut.interfaces.wifi.bt_get_local_address()
        logger().info(f'BT LOCAL address: {local_addr} found')
        #local name
        local_name = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f'BT LOCAL name: {local_name} found')

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#Verify the SPP data transfer with minimum data value of 1 Byte
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20111(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    mode = "single"
    testcase = "test_sta_bt_C20111"
    bt_client_address =None
    try:
        wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, utf_constants, rs_helper)
        bt_obj = BtSppMasterThread_diff_data(wifi_dut, bt_client, mode, utf_constants, 60)
        clean_obj = Cleanupactivity(wifi_dut)
        wlan_obj.start()
        time.sleep(1)
        bt_obj.start()
        time.sleep(1)
        clean_obj.start()
        time.sleep(1)
        wlan_obj.wait_for_exit()
        time.sleep(1)
        bt_obj.wait_for_exit()
        time.sleep(1)
        clean_obj.wait_for_exit()

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#Validate BT SPP data transfer with different data Lengths e.g 195Byte,200,400 & 600 bytes
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20112(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    mode = "numbers"
    testcase = "test_sta_bt_C20112"
    bt_client_address =None
    try:
        wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, utf_constants, rs_helper)
        bt_obj = BtSppMasterThread_diff_data(wifi_dut, bt_client, mode, utf_constants)
        clean_obj = Cleanupactivity(wifi_dut)
        wlan_obj.start()
        time.sleep(1)
        bt_obj.start()
        time.sleep(1)
        clean_obj.start()
        time.sleep(1)
        wlan_obj.wait_for_exit()
        time.sleep(1)
        bt_obj.wait_for_exit()
        time.sleep(1)
        clean_obj.wait_for_exit()

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#Validate SPP data transfer with max data Length
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20113(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    mode = "paragraph"
    testcase = "test_sta_bt_C20113"
    bt_client_address = None
    try:
        wlan_obj = wifiJoinThread(wifi_sniffer,wifi_dut, wifi_access_point, testcase, utf_constants, rs_helper)
        bt_obj = BtSppMasterThread_diff_data(wifi_dut, bt_client, mode, utf_constants)
        clean_obj = Cleanupactivity(wifi_dut)
        wlan_obj.start()
        time.sleep(1)
        bt_obj.start()
        time.sleep(1)
        clean_obj.start()
        time.sleep(1)
        wlan_obj.wait_for_exit()
        time.sleep(1)
        bt_obj.wait_for_exit()
        time.sleep(1)
        clean_obj.wait_for_exit()

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#Verify BT SPP data transfer with special characters
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20114(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    mode = "special_characters"
    testcase = "test_sta_bt_C20114"
    bt_client_address = None
    try:
        wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, utf_constants, rs_helper)
        bt_obj = BtSppMasterThread_diff_data(wifi_dut, bt_client, mode, utf_constants, 60)
        clean_obj = Cleanupactivity(wifi_dut)
        wlan_obj.start()
        time.sleep(1)
        bt_obj.start()
        time.sleep(1)
        clean_obj.start()
        time.sleep(1)
        wlan_obj.wait_for_exit()
        time.sleep(1)
        bt_obj.wait_for_exit()
        time.sleep(1)
        clean_obj.wait_for_exit()

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#Validate BT SPP data transfer with Numeric values and different language like Hindi, Chinese
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20115(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper):
    mode = "different_language"
    testcase = "test_sta_bt_C20115"
    bt_client_address = None
    try:
        wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, utf_constants, rs_helper)
        bt_obj = BtSppMasterThread_diff_data(wifi_dut, bt_client, mode, utf_constants, 60)
        clean_obj = Cleanupactivity(wifi_dut)
        wlan_obj.start()
        time.sleep(1)
        bt_obj.start()
        time.sleep(1)
        clean_obj.start()
        time.sleep(1)
        wlan_obj.wait_for_exit()
        time.sleep(1)
        bt_obj.wait_for_exit()
        time.sleep(1)
        clean_obj.wait_for_exit()

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#To validate SPP data transfer of Tx and Rx at same time1(WLAN is in idle connected state)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20116(wifi_sniffer,wifi_dut, wifi_access_point, bt_client, utf_constants, rs_helper, tx_rx_duration=60):
    send_text = text_generator(size=20)
    recv_text = send_text
    bt_client_address = None
    try:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_sta_bt_C20116')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, f"Failed to get bt dut address"
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, f"Failed to get bt client address"
        time.sleep(1)
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            logger().info(f"Connecting Raspberry PI to DUT-BT")
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected, "Unable to find BT server socket connection"
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address),f"Failed to ping BT client to DUT"

        t_end = time.time() + tx_rx_duration
        while time.time() < t_end:
            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                assert sent, "Unable to send the data"
                time.sleep(10)
                data = bt_server_socket.recv()
                assert data, "Unable to find BT server socket connection"
                assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
            # Ping dut
            logger().info(f"**** pinging to DUT ****")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"
            logger().info(f"Keeping wlan in idle state for 5 mins")
            time.sleep(300)

        logger().info("Checking connection status of Wi-Fi")
        events = wifi_dut.interfaces.wifi.get_async_events()
        disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
        count_disconnect = set()
        if len(disconnect_events):
            count_disconnect.add(str(disconnect_events[0]))
            logger().info(f"Disconnect Events:{count_disconnect}")
            assert False, "DUT is not connected to Wi-Fi"
        assert len(disconnect_events) == 0
        logger().info("DUT is not disconnected from Wi-Fi")

        rsi_bt_on_spp_disconnect = False
        rsi_bt_on_disconn_event = False
        events = wifi_dut.interfaces.wifi.get_async_events()
        logger().info(f"printing the events '{events}'")
        if len(events):
            for event in events:
                logger().info(f"printing the event type {event.event_type}")
                if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_SPP_DISCONN:
                    rsi_bt_on_spp_disconnect = True
                if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_DISCONNECTED:
                    rsi_bt_on_disconn_event = b"4E13" in event.event_data
            if rsi_bt_on_spp_disconnect or rsi_bt_on_disconn_event:
                logger().info("DUT is disconnected from BT")
                assert False, "DUT is disconnected from BT"
            else:
                logger().info("DUT is not disconnected from BT")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



# To validate SPP data transfer of Tx and Rx at same time2(WLAN is in connected state)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20117(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, utf_constants, rs_helper):
    send_text = "支那支那支那支那支那支那"
    recv_text = send_text
    bt_client_address = None
    try:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_sta_bt_C20117')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=1,
                                                               inquiry_duration_ms=20000,
                                                               timeout=22,
                                                               retry_counts=5)
        assert found, f"Dut unable to find the bt client device:{bt_client_address}"

        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            result = ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                 (bt_client_socket.accept, 20)])
            assert result[1] == bt_dut_address, "Unable to find BT client socket connection"
            logger().info(f"Result from Callable Function {result}")

        # Send data from bt_client to dut
        with wifi_dut.interfaces.wifi.run_bt_task():
            logger().info(f'Data transfer from BT_client')
            sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
            assert sent, "Unable to send the data"
            time.sleep(10)
            data = bt_client_socket.recv()
            assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"
            logger().info(f'Data received from BT_client')

        # Send data from dut to bt_client
        logger().info(f'Data transfer from dut')
        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
        data = bt_client_socket.recv()
        assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
        logger().info(f'Data received from dut')

        # Ping dut
        logger().info(f"  Ping to DUT ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"
        logger().info(f" Pinging ")

        # BD address
        local_addr = wifi_dut.interfaces.wifi.bt_get_local_address()
        logger().info(f'BT LOCAL address: {local_addr} found')
        # local name
        local_name = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f'BT LOCAL name: {local_name} found')

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#Data transfer on by enabling Max slots
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.parametrize("num_sockets", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "server_socket_limit": 0,
        "client_socket_limit": 10,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_data_transfer_max_slots_C20118(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, utf_constants,
                                                rs_helper, wifi_networked_dut, remote_socket_factory, num_sockets):
    send_text = text_generator(size=20)
    recv_text = send_text
    bt_client_address = None
    try:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_data_transfer_max_slots_C20118')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        device_ip = wifi_networked_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        threads = []
        start_port = 5000
        for i in range(0, num_sockets):
            port = start_port + i
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.start_server(port=port, socket_type=SOCKET_TYPE_TCP)
            dut_socket = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket()
            wifi_networked_dut.interfaces.wifi.bind(dut_socket, device_ip, port)
            num_packets = 10
            num_bytes = 50
            socket_thread = ServerSocketXferThread(wifi_networked_dut, dut_socket, server_socket, num_packets, num_bytes)
            threads.append(socket_thread)

        # start all threads and wait for exit
        with ExitStack() as thread_stack:
            for thread in threads:
                th=thread_stack.enter_context(thread)
                logger().info(f"thread : {th}")

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            logger().info(f"Initiating BT_CONNECT ")
            bt_server_socket.create_server()
            logger().info(f"Connecting Raspberry PI to DUT-BT")
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected, "Unable to find BT server socket connection"
            logger().info(f" BT_CONNECT SUCCESSFUL ")

        # Send data from bt_client to dut
        with wifi_dut.interfaces.wifi.run_bt_task():
            sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
            assert sent, "Unable to send the data"
            data = bt_server_socket.recv()
            assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

        # Send data from dut to bt_client
        logger().info(f" Initiating BT_SPP TRANSFER ")
        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
        data = bt_server_socket.recv()
        assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"


#Buffer full exception by initiating TCP packet retrials
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "set_send_feature_frame": True
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_buffer_tcp_C20119(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, bt_client,
                                   remote_socket, utf_constants, rs_helper):
    send_text = text_generator(size=20)
    recv_text = send_text
    try:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_buffer_tcp_C20119')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected, "Unable to find BT server socket connection"
            logger().info(f" BT_CONNECT SUCCESSFUL ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), f"Failed to ping BT client to DUT"

        # Send data from bt_client to dut
        with wifi_dut.interfaces.wifi.run_bt_task():
            sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
            assert sent, "Unable to send the data"
            time.sleep(10)
            data = bt_server_socket.recv()
            assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

        # Send data from dut to bt_client
        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
        data = bt_server_socket.recv()
        assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"

        logger().info("**************Run TCP traffic started****************")
        dut_ip = device_ip
        error_count = 0
        try:
            run_tcp_traffic(wifi_dut, wifi_client, remote_socket, dut_ip)
            time.sleep(30)
            logger().info("\n\n")
        except Exception as err:
            logger().error(f"********** {str(err)}********")
            if "0x9" in str(err):
                error_count += 1

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")



#Buffer full exception by initiating TCP packet retrials through rejoin failure
# @pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_buffer_tcp_rejoin_C20120(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, bt_client, remote_socket,
                                          remote_socket_factory, net_perf_client, protocol, utf_constants, rs_helper):
    interface = 'eth1'
    send_text = text_generator(size=20)
    recv_text = send_text
    bt_client_address = None
    try:
        validation = True
        wifi_dut.interfaces.wifi.reset_soft()
        wifi_dut.interfaces.wifi.init()
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_buffer_tcp_rejoin_C20120')
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        assert found, f"Dut unable to find the bt client device:{bt_dut_address}"

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            logger().info(f"Connecting Raspberry PI to DUT-BT")
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
            assert connected, "Unable to find BT server socket connection"
            logger().info(f" BT_CONNECT SUCCESSFUL ")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address),f"Failed to ping BT client to DUT"

        # Send data from bt_client to dut
        with wifi_dut.interfaces.wifi.run_bt_task():
            sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
            assert sent, "Unable to send the data"
            time.sleep(10)
            data = bt_server_socket.recv()
            assert data.decode() == recv_text, "Unable to receive data sent from bt_client to dut"

        # Send data from dut to bt_client
        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
        data = bt_server_socket.recv()
        assert data.decode() == send_text, "Unable to receive data sent from dut to bt_client"
        # Ping dut
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
            f"Failed to ping BT client to DUT"

        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()

        server_port = randint(5001, 50000)
        execute_command = ['iperf', '-s', '-i 1', '-p', str(server_port)]
        iperf_process = SubprocessManager(execute_command)
        iperf_process.start()
        sock_port = 5001
        buffer_length = 100
        socket_id = 0
        tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
        server_socket = remote_socket_factory.interfaces.socket.create_socket()
        server_socket.time_limit = 3600
        status = server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        assert sock == 0, f"socket id received is wrong, expected is 2"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
        wifi_dut.interfaces.wifi.connect_to_server(sock, server_socket, server_port=sock_port)
        logger().info("start TCP sending packets")
        send_pckt = remote_socket_factory.interfaces.socket.sockets[0].send_data_tcp(tx_buffer, use_server_socket=True)
        logger().info(f"TCP sent packets : {send_pckt}")
        time.sleep(10)
        logger().info(f"=======>>>>>Disabling the ethernet adaptor at remote side....")
        wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {interface} down")
        # time.sleep(10)
        wifi_access_point.interfaces.wifi.stop_ap()
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=socket_id,
                                                                            data_len=buffer_length)
        assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the socket id {sock} " \
                                                  f"opened in the DUT is not matched "

        time.sleep(5)
        iperf_process.stop()
        time.sleep(1)
        data_received = iperf_process.get_all_lines()

        receive_stats = 0
        for count in data_received:
            if "sec" in count:
                if ("Bytes" in count) and (not ("KBytes" in count)) and (not ("MBytes" in count)):
                    receive_stats = receive_stats + (float(count.split("Bytes")[0].split("sec")[1].strip()))
                elif "KBytes" in count:
                    receive_stats = receive_stats + (float(count.split("KBytes")[0].split("sec")[1].strip()) * 1024)
                elif "MBytes" in count:
                    receive_stats = receive_stats + (
                                float(count.split("MBytes")[0].split("sec")[1].strip()) * 1024 * 1024)
        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"



#Data transfer with different RSSI values
@pytest.mark.skip()
@pytest.mark.rf_attenuator('50pa500_attenuator')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_different_rssi_values_C20121(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, bt_client,protocol, utf_constants,
                                              rs_helper, rf_attenuator, remote_socket_factory, remote_socket, wifi_networked_dut):
    bt_client_address = None
    try:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_different_rssi_values_C20121')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(3)

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                              inquiry_type=1,
                                                              inquiry_duration_ms=10000,
                                                              timeout=22,
                                                              retry_counts=5)
        assert found, f"Dut unable to find the bt client device:{bt_client_address}"

        logger().info(f"Starting Raspberry PI as BT Server")
        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        # SPP Connection
        logger().info(f'Create SPP Connection')
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            result = ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                 (bt_client_socket.accept, 20)])
            assert result[1] == bt_dut_address, "Unable to find BT client socket connection"
            logger().info(f"Result from Callable Function {result}")

        #The below api parses DUTs IP address
        device_ip = wifi_networked_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        sock_port = 5001
        buffer_length = 100
        tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
        server_socket = remote_socket_factory.interfaces.socket.create_socket()
        server_socket.time_limit = 3600
        status = server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
        connect_status = wifi_dut.interfaces.wifi.connect_to_server(sock, server_socket, server_port=sock_port)

        db_value = 5
        att_channel = 1
        wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel, db_value)
        buffer_length_tx = remote_socket_factory.interfaces.socket.sockets[0].send_data_tcp(tx_buffer, use_server_socket=True)
        logger().info(f"sent tcp data packets : {buffer_length_tx}")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid)
        logger().info(f'\n\n{scan_results[0]}\n')
        my_str = str(scan_results[0])
        current_rssi = abs(int(my_str.strip('()').split(' ')[5]))
        logger().info(f'Current RSSI = {current_rssi}')
        db_value = 5
        wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel, db_value)
        buffer_length_tx = remote_socket_factory.interfaces.socket.sockets[0].send_data_tcp(tx_buffer, use_server_socket=True)
        logger().info(f"sent tcp data packets : {buffer_length_tx}")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid)
        logger().info(f'\n\n{scan_results[0]}\n')
        my_str = str(scan_results[0])
        current_rssi = abs(int(my_str.strip('()').split(' ')[5]))
        logger().info(f'Current RSSI = {current_rssi}')

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket"
        remote_socket.interfaces.socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "Setup Issue: RASPI-BT Failure"
        logger().info("\n got exception: {}".format(str(e)))
        dut_clean_up(wifi_dut, bt_client_address)
        assert False, "Failed"