import pytest
import time
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    RS9116AsyncEventType,
    SocketOptions,
    SocketType,
    Cipher,
    DeviceConstants,
    RS9116CustomFeatureBitMap,
)

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake
                        | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "custom_features": RS9116CustomFeatureBitMap.Default,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
                                   | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid
        }
    )
]


def logger():
    return get_logger(__name__)


# this thread used for wifi join
class wifiJoinThread(ThreadBase):
    def __init__(self, wifi_sniffer, wifi_dut, wifi_access_point, testcase):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.testcase = testcase

    def run(self):
        ping_count = 60
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        scan_results = self.wifi_dut.interfaces.wifi.scan(channel=self.wifi_access_point.interfaces.wifi.channel, ssid=None)
        logger().info(f"scan results : {scan_results}")
        # Join Wi-Fi Access Point
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"Successfully connected to AP")
        # This API Enables the DHCP in DUT
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Found device ip: {device_ip}")
        logger().info("DUT to power save in Wifi+bluetooth mode")
        logger().info("enabling wifi power save")
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.power_save(2, 1)
        assert enable_wifi_ps, 'failed to enable'
        logger().info("enabling bt power save")
        enable_bt_ps = self.wifi_dut.interfaces.wifi.bt_power_save(2, 1)
        assert enable_bt_ps, 'failed to enable'
        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        # Fetches the DUT mac address
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        self.wifi_dut.interfaces.wifi.leave()
        logger().info("Dut disconnecting form wifi")
        packet_filter3 = (
            f"!(wlan.fc.type_subtype == 0x0008) and ( wlan.addr == {dut_mac_address} and ((wlan.fc.type_subtype == 0x0000)  or "
            f" (wlan.ds.current_channel == {self.wifi_access_point.interfaces.wifi.channel}) or eapol or "
            f"(wlan.fc.type_subtype == 0x000b)))"
        )
        # Validating the ps poll frames
        packet_filter1 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'
        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapole'
        logger().info(f"Validating PS Poll frames are sent from the device with power management bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'


class Cleanupactivity(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        self.wifi_dut.interfaces.wifi.leave()


# This Thread is used to run the dut on Master mode
class BtSpp_master_thread(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        send_text = "abcdefghijklmnopqrstuvwxyABCDEFGHIJKLMNOPQRSTUVWXY"
        recv_text = "abcdefghijklmnopqrstuvwxyABCDEFGHIJKLMNOPQRSTUVWXY"
        bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None, f"Failed to get bt dut address"
        bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None, f"Failed to get bt client address"
        time.sleep(1)
        found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                    inquiry_type=2,
                                                                    inquiry_duration_ms=10000,
                                                                    timeout=22,
                                                                    retry_counts=3)
        if not found:
            logger().error(f"Dut unable to find the bt client device. The test case may fail.")
        with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
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
                sent = bt_client_socket.send(
                    recv_text
                )  # Dut is programmed to send back data
                logger().info(f"***** Send data from bt_client to dut ****")
                assert sent, f"Failed to sent data"
                time.sleep(15)
                data = bt_client_socket.recv()
                assert data is not None, f"Failed to send back data from SQA Agent programme"
                assert data.decode() == recv_text, f" Failed to decode receive data "

            # Send data from dut to bt_client
            logger().info("Send data from dut to bt_client")
            self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data is not None, f"Failed to ping BT client to DUT"
            assert data.decode() == send_text

            # Ping dut
            logger().info(f"**** pinging to DUT ****")
            assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"

            # Close connection
            logger().info(f"BT client socket connection closing")
            bt_client_socket.close()
            time.sleep(2)


# This Thread is used to run the dut on slave mode
class BtSpp_slave_thread(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        send_text = "abcdefghijklmnopqrstuvwxyABCDEFGHIJKLMNOPQRSTUVWXY"
        recv_text = "abcdefghijklmnopqrstuvwxyABCDEFGHIJKLMNOPQRSTUVWXY"
        bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None, f"Failed to get bt dut address"
        bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None, f"Failed to get bt client address"
        found = self.bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20,
                                                                               retry_counts=3)
        if not found:
            logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")
        with self.bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Server
        ) as bt_server_socket:
            # SPP Connection
            logger().info(f"**** SPP Connection ****")
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                time.sleep(30)
                assert connected, f"Failed to connect spp connection"

            # Send data from bt_client to dut
            logger().info(f"Send data from bt_client to dut")
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(recv_text)
                # SQA Agent is programmed to send back data
                logger().info(f"SQA agent is programmed to send back data")
                assert sent, f"Failed to send data from bt_client to dut"
                time.sleep(15)
                data = bt_server_socket.recv()
                assert data is not None, f"Failed to send back data from SQA Agent is programmed"
                assert data.decode() == recv_text

            # Send data from dut to bt_client
            self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data is not None, f"Failed to send data from dut to bt_client"
            assert data.decode() == send_text

            # Ping dut
            logger().info(f"Ping dut")
            assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"
            # Close connection
            logger().info(f"Close connection")
            bt_server_socket.close()
            time.sleep(2)


class Bt_spp_dut_as_master_wrong_pin(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp(bt_pin_code="1234")
        assert bt_dut_address is not None, f"Failed to get bt dut address"
        bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code="4554")
        assert bt_client_address is not None, f"Failed to get bt client address"
        self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                            inquiry_type=2,
                                                            inquiry_duration_ms=10000,
                                                            max_device_cnt=10,
                                                            timeout=22,
                                                            retry_counts=3)
        with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            # SPP Connection
            logger().info("**** SPP Connection ****")
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(self.wifi_dut.interfaces.wifi.bt_connect, bt_client_address), (bt_client_socket.accept, 60)])
                assert result[1] is None
            bt_client_socket.close()

        recieved_authentication_failure = False
        time.sleep(1)
        events = self.wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    recieved_authentication_failure = b"4E05" in event.event_data
                    break
        assert recieved_authentication_failure, f" Received authentication failure "


class Bt_spp_dut_as_slave_wrong_pin(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):

        bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_slave_spp(bt_pin_code="1234")
        assert bt_dut_address is not None, f"Failed to get bt dut address"
        bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code="9876")
        assert bt_client_address is not None, f"Failed to get bt client address"
        self.bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        with self.bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Server
        ) as bt_server_socket:
            # SPP Connection
            logger().info("**** SPP Connection ****")
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                time.sleep(1)
                assert not connected, f"Failed to connect spp connection"
            bt_server_socket.close()

        recieved_authentication_failure = False
        events = self.wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    recieved_authentication_failure = b"4E05" in event.event_data
                    break
        assert recieved_authentication_failure, f" Received authentication failure "


# This Thread is used to run the dut on slave mode
class BtSpp_role_switch(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

    def run(self):
        if self.mode == "master_to_slave":
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None, f"Failed to get bt client address"
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                        inquiry_type=2,
                                                                        inquiry_duration_ms=10000,
                                                                        max_device_cnt=10,
                                                                        timeout=22,
                                                                        retry_counts=3)
            if not found:
                logger().error(f"Dut unable to find the bt client device. The test case may fail.")
            with self.bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Client
            ) as bt_client_socket:
                # SPP Connection
                logger().info("**** SPP Connection ****")
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_client_socket.create_client()
                    result = ThreadBase.call_functions_simultaneously(
                        [(self.wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                         (bt_client_socket.accept, 30)]
                    )
                    assert result[1] == bt_dut_address
                    logger().info(f"Result from Callable Function {result}")
                # The Below api will fetch the response of Slave Role
                result = self.wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Device role:{result}")
                assert result == result
                self.wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
                time.sleep(10)
                # Here we can see the final get response of role Switch
                logger().info("============Final Role Switch Slave Role to Master Role=========")
                final_role = self.wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                assert final_role
                logger().info(f"Role Switch: {final_role}")
                if final_role == 1:
                    logger().info(f'From BT response is not found')

                # Ping dut
                logger().info(f"Ping dut")
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"

                # Close connection
                logger().info(f"Close connection")
                bt_client_socket.close()
                time.sleep(5)

        if self.mode == "slave_to_master":
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address is not None, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address is not None, f"Failed to get bt client address"
            found = self.bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20,
                                                                                   retry_counts=3)
            if not found:
                logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")
            with self.bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Server
            ) as bt_server_socket:
                # SPP Connection
                logger().info(f"**** SPP Connection ****")
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                    assert connected, f"Failed to connect spp connection"
                result = self.wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Device role:{result}")
                self.wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
                time.sleep(10)
                final_role = self.wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Role Switch: {final_role}")
                # Ping dut
                logger().info(f"Ping to dut")
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address),  \
                    f"Failed to ping BT client to DUT"
                bt_server_socket.close()
                time.sleep(5)


# This Thread is used to sent different data
class BtSppMasterThread_diff_data(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

    def run(self):
        if self.mode == "single":
            send_text = "B"
            recv_text = "B"
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None, f"Failed to get bt client address"
            time.sleep(1)
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                        inquiry_type=2,
                                                                        inquiry_duration_ms=10000,
                                                                        timeout=22,
                                                                        retry_counts=3)
            if not found:
                logger().error(f"Dut unable to find the bt client device. The test case may fail.")
            with self.bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Client
            ) as bt_client_socket:
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
                    sent = bt_client_socket.send(
                        recv_text
                    )  # Dut is programmed to send back data
                    logger().info(f"***** Send data from bt_client to dut ****")
                    assert sent, f"Failed to sent data"
                    data = bt_client_socket.recv()
                    assert data is not None, f"Failed to send back data from SQA Agent programme"
                    assert data.decode() == recv_text, f" Failed to decode receive data "

                # Send data from dut to bt_client
                logger().info("Send data from dut to bt_client")
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data is not None, f"Failed to ping BT client to DUT"
                assert data.decode() == send_text

                # Ping dut
                logger().info(f"**** pinging to DUT ****")
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"

                # Close connection
                logger().info(f"BT client socket connection closing")
                bt_client_socket.close()
                time.sleep(2)

        if self.mode == "numbers":
            send_text = "436353837"
            recv_text = "436353837"
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None, f"Failed to get bt client address"
            time.sleep(1)
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                        inquiry_type=2,
                                                                        inquiry_duration_ms=10000,
                                                                        timeout=22,
                                                                        retry_counts=3)
            if not found:
                logger().error(f"Dut unable to find the bt client device. The test case may fail.")
            with self.bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Client
            ) as bt_client_socket:
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
                    sent = bt_client_socket.send(
                        recv_text
                    )  # Dut is programmed to send back data
                    logger().info(f"***** Send data from bt_client to dut ****")
                    assert sent, f"Failed to sent data"
                    data = bt_client_socket.recv()
                    assert data is not None, f"Failed to send back data from SQA Agent programme"
                    assert data.decode() == recv_text, f" Failed to decode receive data "

                # Send data from dut to bt_client
                logger().info("Send data from dut to bt_client")
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data is not None, f"Failed to ping BT client to DUT"
                assert data.decode() == send_text

                # Ping dut
                logger().info(f"**** pinging to DUT ****")
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"

                # Close connection
                logger().info(f"BT client socket connection closing")
                bt_client_socket.close()
                time.sleep(2)

        if self.mode == "paragraph":
            send_text = "RandomtextRandomtextRandomtextRandomtextRandomtextRandomtext"
            recv_text = "RandomtextRandomtextRandomtextRandomtextRandomtextRandomtext"
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None, f"Failed to get bt client address"
            time.sleep(1)
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                        inquiry_type=2,
                                                                        inquiry_duration_ms=10000,
                                                                        timeout=22,
                                                                        retry_counts=3)
            if not found:
                logger().error(f"Dut unable to find the bt client device. The test case may fail.")
            with self.bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Client
            ) as bt_client_socket:
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
                    sent = bt_client_socket.send(
                        recv_text
                    )  # Dut is programmed to send back data
                    logger().info(f"***** Send data from bt_client to dut ****")
                    assert sent, f"Failed to sent data"
                    data = bt_client_socket.recv()
                    assert data is not None, f"Failed to send back data from SQA Agent programme"
                    assert data.decode() == recv_text, f" Failed to decode receive data "

                # Send data from dut to bt_client
                logger().info("Send data from dut to bt_client")
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data is not None, f"Failed to ping BT client to DUT"
                assert data.decode() == send_text

                # Ping dut
                logger().info(f"**** pinging to DUT ****")
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"

                # Close connection
                logger().info(f"BT client socket connection closing")
                bt_client_socket.close()
                time.sleep(2)

        if self.mode == "special_characters":
            send_text = "@#$%^&*()_!_)(*&^%$#@!"
            recv_text = "@#$%^&*()_!_)(*&^%$#@!"
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None, f"Failed to get bt client address"
            time.sleep(1)
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                        inquiry_type=2,
                                                                        inquiry_duration_ms=10000,
                                                                        timeout=22,
                                                                        retry_counts=3)
            if not found:
                logger().error(f"Dut unable to find the bt client device. The test case may fail.")
            with self.bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Client
            ) as bt_client_socket:
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
                    sent = bt_client_socket.send(
                        recv_text
                    )  # Dut is programmed to send back data
                    logger().info(f"***** Send data from bt_client to dut ****")
                    assert sent, f"Failed to sent data"
                    data = bt_client_socket.recv()
                    assert data is not None, f"Failed to send back data from SQA Agent programme"
                    assert data.decode() == recv_text, f" Failed to decode receive data "

                # Send data from dut to bt_client
                logger().info("Send data from dut to bt_client")
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data is not None, f"Failed to ping BT client to DUT"
                assert data.decode() == send_text

                # Ping dut
                logger().info(f"**** pinging to DUT ****")
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"

                # Close connection
                logger().info(f"BT client socket connection closing")
                bt_client_socket.close()
                time.sleep(2)

        if self.mode == "different_language":
            send_text = "支那支那支那支那支那支那支那支那支那"
            recv_text = "支那支那支那支那支那支那支那支那支那"
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None, f"Failed to get bt dut address"
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None, f"Failed to get bt client address"
            time.sleep(1)
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                        inquiry_type=2,
                                                                        inquiry_duration_ms=10000,
                                                                        timeout=22,
                                                                        retry_counts=3)
            if not found:
                logger().error(f"Dut unable to find the bt client device. The test case may fail.")
            with self.bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Client
            ) as bt_client_socket:
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
                    sent = bt_client_socket.send(
                        recv_text
                    )  # Dut is programmed to send back data
                    logger().info(f"***** Send data from bt_client to dut ****")
                    assert sent, f"Failed to sent data"
                    data = bt_client_socket.recv()
                    assert data is not None, f"Failed to send back data from SQA Agent programme"
                    assert data.decode() == recv_text, f" Failed to decode receive data "

                # Send data from dut to bt_client
                logger().info("Send data from dut to bt_client")
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data is not None, f"Failed to ping BT client to DUT"
                assert data.decode() == send_text

                # Ping dut
                logger().info(f"**** pinging to DUT ****")
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"

                # Close connection
                logger().info(f"BT client socket connection closing")
                bt_client_socket.close()
                time.sleep(2)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20088_C20094_C20095_C20101_C20116(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    testcase = "test_sta_bt_C20088_C20094_C20095_C20101_C20116"
    wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    bt_obj = BtSpp_master_thread(wifi_dut, bt_client)
    clean_obj= Cleanupactivity(wifi_dut)
    wlan_obj.start()
    bt_obj.start()
    clean_obj.start()
    wlan_obj.wait_for_exit()
    time.sleep(1)
    bt_obj.wait_for_exit()
    time.sleep(1)
    clean_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20092_C20093_C20110_C20117(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    testcase = "test_sta_bt_C20092_C20093_C20110_C20117"
    wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    bt_obj = BtSpp_slave_thread(wifi_dut, bt_client)
    clean_obj = Cleanupactivity(wifi_dut)
    wlan_obj.start()
    bt_obj.start()
    clean_obj.start()
    wlan_obj.wait_for_exit()
    time.sleep(1)
    bt_obj.wait_for_exit()
    time.sleep(1)
    clean_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20104(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    testcase = "test_sta_bt_C20104"
    wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    bt_obj = Bt_spp_dut_as_master_wrong_pin(wifi_dut, bt_client)
    clean_obj = Cleanupactivity(wifi_dut)
    wlan_obj.start()
    bt_obj.start()
    clean_obj.start()
    wlan_obj.wait_for_exit()
    time.sleep(1)
    bt_obj.wait_for_exit()
    time.sleep(1)
    clean_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20106(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    testcase = "test_sta_bt_C20106"
    wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    bt_obj = Bt_spp_dut_as_slave_wrong_pin(wifi_dut, bt_client)
    clean_obj = Cleanupactivity(wifi_dut)
    wlan_obj.start()
    bt_obj.start()
    clean_obj.start()
    wlan_obj.wait_for_exit()
    time.sleep(1)
    bt_obj.wait_for_exit()
    time.sleep(1)
    clean_obj.wait_for_exit()

@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20090(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    mode = "master_to_slave"
    testcase = "test_sta_bt_C20090"
    wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    bt_obj = BtSpp_role_switch(wifi_dut, bt_client, mode)
    clean_obj = Cleanupactivity(wifi_dut)
    wlan_obj.start()
    bt_obj.start()
    clean_obj.start()
    wlan_obj.wait_for_exit()
    time.sleep(1)
    bt_obj.wait_for_exit()
    time.sleep(1)
    clean_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20091(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    mode = "slave_to_master"
    testcase = "test_sta_bt_C20091"
    wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    bt_obj = BtSpp_role_switch(wifi_dut, bt_client, mode)
    clean_obj = Cleanupactivity(wifi_dut)
    wlan_obj.start()
    bt_obj.start()
    clean_obj.start()
    wlan_obj.wait_for_exit()
    time.sleep(1)
    bt_obj.wait_for_exit()
    time.sleep(1)
    clean_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20111(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    mode = "single"
    testcase = "test_sta_bt_C20111"
    wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    bt_obj = BtSppMasterThread_diff_data(wifi_dut, bt_client, mode)
    clean_obj = Cleanupactivity(wifi_dut)
    wlan_obj.start()
    bt_obj.start()
    clean_obj.start()
    wlan_obj.wait_for_exit()
    time.sleep(1)
    bt_obj.wait_for_exit()
    time.sleep(1)
    clean_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20112(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    mode = "numbers"
    testcase = "test_sta_bt_C20112"
    wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    bt_obj = BtSppMasterThread_diff_data(wifi_dut, bt_client, mode)
    clean_obj = Cleanupactivity(wifi_dut)
    wlan_obj.start()
    bt_obj.start()
    clean_obj.start()
    wlan_obj.wait_for_exit()
    time.sleep(1)
    bt_obj.wait_for_exit()
    time.sleep(1)
    clean_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20113(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    mode = "paragraph"
    testcase = "test_sta_bt_C20113"
    wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    bt_obj = BtSppMasterThread_diff_data(wifi_dut, bt_client, mode)
    clean_obj = Cleanupactivity(wifi_dut)
    wlan_obj.start()
    bt_obj.start()
    clean_obj.start()
    wlan_obj.wait_for_exit()
    time.sleep(1)
    bt_obj.wait_for_exit()
    time.sleep(1)
    clean_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C20114(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    mode = "special_characters"
    testcase = "test_sta_bt_C20114"
    wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    bt_obj = BtSppMasterThread_diff_data(wifi_dut, bt_client, mode)
    clean_obj = Cleanupactivity(wifi_dut)
    wlan_obj.start()
    bt_obj.start()
    clean_obj.start()
    wlan_obj.wait_for_exit()
    time.sleep(1)
    bt_obj.wait_for_exit()
    time.sleep(1)
    clean_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_C2015(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    mode = "different_language"
    testcase = "test_sta_bt_C2015"
    wlan_obj = wifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    bt_obj = BtSppMasterThread_diff_data(wifi_dut, bt_client, mode)
    clean_obj = Cleanupactivity(wifi_dut)
    wlan_obj.start()
    bt_obj.start()
    clean_obj.start()
    wlan_obj.wait_for_exit()
    time.sleep(1)
    bt_obj.wait_for_exit()
    time.sleep(1)
    clean_obj.wait_for_exit()