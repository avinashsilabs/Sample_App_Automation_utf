import time
import pytest
import random
import string
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BTSocketRole
from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.socket import SOCKET_TYPE_TCP
from random import randint
from contextlib import ExitStack
from utf.utils.subprocess_manager import SubprocessManager
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116AsyncEventType, \
    RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116FeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116BTFeatureBitMap, RS9116ExtTCPIPFeatureBitMap ,DeviceConstants, SocketOptions, RS9116CertificateType, \
    RS9116PowerSaveProcedureTypes, RS9116ConfigFeatureBitMap
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType

ping_count = 10
iter_cnt = 6

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
def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

# This Thread is used to wifiJoinThread
def wifiJoin(wifi_dut, wifi_access_point):
    # Join Wi-Fi Access Point
    logger().info(f"connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info(f"pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1,"DUT not responding for ping request......"
    logger().info(f"ping to DUT is successful....")

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    return device_ip

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


            logger().info(f"Starting Raspberry PI as BT Server")
            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    logger().info(f"Connecting Raspberry PI to DUT-BT")
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                    assert connected, "Unable to find BT server socket connection"
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"
                time.sleep(20)

                # Send data from bt_client to dut
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                    assert sent, "Unable to send the data"
                    data = bt_server_socket.recv()
                    logger().info(f"Connecting BT server socket")
                    assert data, "Unable to find BT server socket connection"
                    assert data.decode() == recv_text

                # Send data from dut to bt_client
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_server_socket.recv()
                logger().info(f"Connecting BT server socket")
                assert data, "Unable to find BT server socket connection"
                assert data.decode() == send_text

                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"

                # Close connection
                logger().info(f"disconnecting bt host....")
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                logger().info(f"Close Socket connection")
                bt_server_socket.close()
                time.sleep(5)


# This Thread is used to sent different data
class BtSpp_role_switch(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

        if self.mode == "bt_slave":
            logger().info(f"Configuring DUT as SPP Slave")
            bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address, "Unable to get BT DUT address"
            logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
            bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address, "Unable to get BT client address"
            logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

            logger().info(f"Starting Raspberry PI as BT Server")
            with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
                # SPP Connection
                with wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    logger().info(f"Connecting Raspberry PI to DUT-BT")
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                    assert connected, "Unable to find BT server socket connection"
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"
                time.sleep(20)

                result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Device role:{result}")
                wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
                time.sleep(10)
                device_role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Role Switch: {device_role}")

                # Ping dut
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"
                # Close connection
                logger().info(f"disconnecting bt host....")
                wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                logger().info(f"Close Socket connection")
                bt_server_socket.close()
                time.sleep(5)

        if self.mode == "bt_master":
            logger().info(f"Configuring DUT as SPP MASTER")
            bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address, "Unable to get BT DUT address"
            logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
            bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address, "Unable to get BT client address"
            logger().info(f"Raspberry PI is BT-SLAVE  with MAC address {bt_client_address} ")

            logger().info(f"Starting Raspberry PI as BT Server")
            with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
                # SPP Connection
                with wifi_dut.interfaces.wifi.run_bt_task():
                    bt_client_socket.create_client()
                    logger().info(f"Connecting Raspberry PI to DUT-BT")
                    wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                    addr = bt_client_socket.accept(timeout=40)
                    assert addr == bt_dut_address, "Unable to find BT client socket connection"
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"
                time.sleep(20)

                result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Device role:{result}")
                wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
                time.sleep(10)
                device_role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Role Switch: {device_role}")

                # Ping dut
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"
                # Close connection
                logger().info(f"disconnecting bt host....")
                wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                logger().info(f"Close Socket connection")
                bt_client_socket.close()
                time.sleep(5)

class wifi_traffic_thread(ThreadBase):
    def __init__(self, net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30):
        super().__init__()
        self.net_perf_client = net_perf_client
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.iperf_time = iperf_time

    def run(self):
        run_iperf_server(self.net_perf_client, self.wifi_dut, self.wifi_client, self.protocol, self.device_ip,
                         self.iperf_time)
        logger().info("Wi-Fi traffic thread completed")

def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)
        logger().info(f"Iperf throughput printed successfully")

def run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30):
    time.sleep(5)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Host IP: {device_ip}")

    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=iperf_time)
    global iperf_started
    iperf_started = True
    net_perf_client.interfaces.net_perf.start()
    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)


def run_iperf_server_rssi(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, iperf_time=30):
    time.sleep(5)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    time.sleep(3)
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    time.sleep(3)

    # preparing wifi_client
    if wifi_access_point != wifi_client:
        status = wifi_client.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(5)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Host IP: {device_ip}")
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) is not None

    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=iperf_time)
    global iperf_started
    iperf_started = True
    net_perf_client.interfaces.net_perf.start()
    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)

def wifi_leave(wifi_dut):
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Leave completed in {t.duration} seconds")

def ApWirelessOff(wifi_access_point, wait_time, logger):
    time.sleep(wait_time)
    logger().info(f"Disabling Wireless in AP")
    wifi_access_point.interfaces.wifi.stop_ap()
    logger().info(f"Wait for 5 seconds")
    time.sleep(5)
    logger().info(f"Enabling Wireless in AP")
    wifi_access_point.interfaces.wifi.start_ap()

def Receive_data_socket(remote_socket_factory, logger, index, no_of_pkts):
    data_length = 0
    logger.info(f"Receiving data over socket id {index}")
    for count in range(0, no_of_pkts):
        data = remote_socket_factory.interfaces.socket.sockets[index].recv_data_tcp(1000)
        data_length = data_length + len(data)
    logger.info(f"Total bytes received on socket id {index} -> {data_length}")


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
def test_bt_coex_mode_as_slave_C20089(wifi_dut,wifi_access_point,bt_client):
    mode = "bt_slave"
    logger().info("Joining into Wi-Fi")
    device_ip = wifiJoin(wifi_dut, wifi_access_point)
    assert device_ip, "Device IP fetching failed"
    time.sleep(3)
    t2 = BtSppMaster_SlaveThread(wifi_dut, bt_client, mode)
    for i in range(1,iter_cnt):
        t2.start()
        time.sleep(5)
        t2.wait_for_exit(True)
        logger().info(f" iteration completed: {i} ")
        time.sleep(10)



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
def test_bt_coex_mode_C20091(wifi_dut, bt_client, wifi_access_point):
    mode = "bt_slave"
    logger().info("Joining into Wi-Fi")
    device_ip = wifiJoin(wifi_dut, wifi_access_point)
    assert device_ip, "Device IP fetching failed"
    time.sleep(3)
    t1 = BtSpp_role_switch(wifi_dut, bt_client, mode)
    t1.start()
    time.sleep(5)
    t1.wait_for_exit(True)
    time.sleep(20)




#SPP transfer by taking remote OOO
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
def test_bt_coex_OOR_C20096(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, rf_attenuator):
    send_text = text_generator(size=50)
    recv_text = send_text
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_OOR_C20096')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE  with MAC address {bt_client_address} ")

        logger().info(f"start bt inquiry")
        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=2,
                                                               inquiry_duration_ms=20000,
                                                               timeout=22,
                                                               retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            for i in range(1, iter_cnt):
                # SPP Connection
                with wifi_dut.interfaces.wifi.run_bt_task():
                    bt_client_socket.create_client()
                    result = ThreadBase.call_functions_simultaneously(
                        [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                        (bt_client_socket.accept, 20)])
                    assert result[1] == bt_dut_address, "Unable to find BT client socket connection"
                    logger().info(f"Result from Callable Function {result}")
                    time.sleep(20)

                # Ping dut
                logger().info(f"  Ping to DUT ")
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"
                logger().info(f" Pinging ")

                # Send data from bt_client to dut
                with wifi_dut.interfaces.wifi.run_bt_task():
                    logger().info(f'Data transfer from BT_client')
                    sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                    assert sent, "Unable to send the data"
                    data = bt_client_socket.recv()
                    assert data, "Unable to find BT client socket connection"
                    assert data.decode() == recv_text
                    logger().info(f'Data received from BT_client')

                # Send data from dut to bt_client
                logger().info(f'Data transfer from dut')
                wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                assert data, "Unable to find BT client socket connection"
                assert data.decode() == send_text
                logger().info(f'Data received from dut')

                bt_client.interfaces.bluetooth.bt_adapter.set_noscan()

                # Ping dut
                logger().info(f"  Ping to DUT ")
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                    f"Failed to ping BT client to DUT"
                logger().info(f" Pinging ")

            # Close connection
            logger().info(f"disconnecting bt host....")
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
            logger().info(f"Close Socket connection")
            bt_client_socket.close()
            time.sleep(5)

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

        received_authentication_failure = False
        time.sleep(1)
        events = wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    received_authentication_failure = b"4E08" in event.event_data
                    break
        assert received_authentication_failure, "Unable to receive authentication error code 4E08"
        wifi_dut.interfaces.wifi.leave()
        logger().info(f"Scan in {t.duration} seconds")

    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



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
def test_SPP_data_transfer_by_disconnecting_from_RD_C20097(wifi_dut, wifi_access_point, bt_client, wifi_sniffer):
    send_text = text_generator(size=20)
    recv_text = send_text
    with TimeMeasurer() as t:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_SPP_data_transfer_by_disconnecting_from_RD_C20097')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT device"
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            assert found, "Dut was not found during the scan by bt client. The test case may fail"
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected, "Unable to find BT server socket connection"
                time.sleep(20)

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                assert sent, "Unable to send data"
                data = bt_server_socket.recv()
                assert data, "Unable to receive data"
                assert data.decode() == recv_text
            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data,"Unable to find BT server socket connection"
            assert data.decode() == send_text
            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"
            # Close connection
            start_capture_time = time.perf_counter_ns()
            # SPP DISCONNECTED by remote device
            bt_server_socket.close()
            time.sleep(3)
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
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



#EAP Connection in TTLS mode
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678', "radius_ip": "192.168.50.106"})
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
def test_bt_coex_eap_C20100(wifi_sniffer, wifi_dut, wifi_access_point, radius_server, bt_client, net_perf_client, wifi_client, protocol):
    send_text = text_generator(size=20)
    recv_text = send_text
    with TimeMeasurer() as t:
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
        logger().info(f"connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info(f"enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # Initiate ping from third party wifi-client to DUT
        logger().info(f'DUT ip {device_ip}')
        logger().info(f"pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info(f"ping to DUT is successful....")

        logger().info(f"enabling wifi power save mode in DUT......")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "failed to enable wifi power save"

        logger().info(f"enabling bt power save mode in DUT......")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "failed to enable bt power save"

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
        run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT device"
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        time.sleep(1)

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                              inquiry_type=2,
                                                              inquiry_duration_ms=20000,
                                                              timeout=22,
                                                              retry_counts=3)
        if not found:
            assert found, "Dut was not found during the scan by bt client. The test case may fail"

        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                    (bt_client_socket.accept, 20)])
                assert result[1] == bt_dut_address, "Unable to find BT client socket connection"
                logger().info(f"Result from Callable Function {result}")
                time.sleep(20)

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f'Data transfer from BT_client')
                sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                assert sent, "Unable to send the data"
                data = bt_client_socket.recv()
                assert data, "Unable to find BT client socket connection"
                assert data.decode() == recv_text
                logger().info(f'Data received from BT_client')

            # Send data from dut to bt_client
            logger().info(f'Data transfer from dut')
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data, "Unable to find BT client socket connection"
            assert data.decode() == send_text
            logger().info(f'Data received from dut')

        # Sniffer stop
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Test case executed in {t.duration} seconds")
    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



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
def test_bt_coex_inquiry_C20101(wifi_dut, bt_client, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_inquiry_C20101')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(5)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE  with MAC address {bt_client_address} ")

        logger().info(f' initialize bt inquiry ')
        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                       inquiry_type=2,
                                                       inquiry_duration_ms=20000,
                                                       timeout=22,
                                                       retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"
        logger().info(f'bt inquiry successful: , {found}')

    # Sniffer stop
    logger().info(f"Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validating the power management bit
    packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
    logger().info(f" Validate power management bit 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



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
def test_bt_coex_noremote_C20102(wifi_dut, wifi_access_point, bt_client,wifi_sniffer):
    event_found = 0
    validation = True
    with TimeMeasurer() as t:
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_noremote_C20102')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

        bt_client.interfaces.bluetooth.bt_adapter.set_noscan()
        #bt_client.interfaces.bluetooth.bt_adapter.bt_disable()

        logger().info(f" bt inquiry started ")
        time.sleep(10)
        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                              inquiry_type=2,
                                                              inquiry_duration_ms=20000,
                                                              timeout=40,
                                                              retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        #Get Asynchronous messages
        events = wifi_dut.interfaces.wifi.get_async_events()
        assert len(events) > 0, "Events not found"
        # Search for Inquiry Complete Event
        event_data = ''
        for event in events:
            event_data = event_data + str(event.event_data.decode())
            logger().info(f" ###### EVENT DATA ARE '{event_data}' ######")
            if 'RSI_APP_EVENT_INQ_COMPLT' in event_data:
                logger().info(f"inquiry complete event found")
                break
        if bt_client_address not in event_data:
            logger().info(f" ** BT CLIENT ADDRESS NOT IN EVENT DATA *** ")
            event_found = 1
            logger().info(f" ** EVENT FOUND VALUE IS '{event_found}' *** ")
            assert True
        if event_found == 0:
            assert False, logger().info(f"inquiry complete event not found")
    logger().info(f"Test case executed in {t.duration} seconds")

    # Sniffer stop
    logger().info(f"Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validating the power management bit
    packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
    logger().info(f" Validate power management bit 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



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
def test_bt_coex_cancel_inquiry_C20103(wifi_dut, bt_client, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_cancel_inquiry_C20103')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f' initialize bt inquiry ')
        result = wifi_dut.interfaces.wifi.bt_inquiry()
        logger().info(f'bt inquiry successful: , {result}')
        time.sleep(10)
        # Cancel BT inquiry
        bt_client.interfaces.bluetooth.bt_adapter.set_noscan()

    # Sniffer stop
    logger().info(f"Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validating the power management bit
    packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
    logger().info(f" Validate power management bit 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



# BT functionality when Pincode is not entered when prompted
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
def test_bt_coex_without_pin_C20105(wifi_dut, wifi_access_point, bt_client, wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_without_pin_C20105')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
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
                                                       inquiry_duration_ms=20000,
                                                       timeout=40,
                                                       retry_counts=6)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"
        logger().info(f' bt inquiry successful')

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            # SPP Connection
            logger().info(f'Create SPP Connection')
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address), (bt_client_socket.accept, 60)])
                assert result[1] is None, "Unable to find BT client socket connection"
                logger().info(f'SPP Connection Completed')
                time.sleep(20)
            bt_client_socket.close()

        received_authentication_failure = False
        time.sleep(1)
        events = wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    received_authentication_failure = b"4E18" in event.event_data
                    break
        assert received_authentication_failure, "Unable to receive authentication error code 4E18"
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Scan in {t.duration} seconds")

    # Sniffer stop
    logger().info(f"Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validating the power management bit
    packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
    logger().info(f" Validate power management bit 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



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
def test_bt_spp_remote_unpair_C20107(wifi_dut, wifi_access_point, bt_client, wifi_sniffer):
    send_text = text_generator(size=20)
    recv_text = send_text
    with TimeMeasurer() as t:
        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_spp_remote_unpair_C20107')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT device"
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected, "Unable to find BT server socket connection"
                time.sleep(20)

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                assert sent, "Unable to send the data"
                data = bt_server_socket.recv()
                assert data, "Unable to find BT server socket connection"
                assert data.decode() == recv_text

            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data, "Unable to find BT server socket connection"
            assert data.decode() == send_text
            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"
            # Capture the time to identify events
            start_capture_time = time.perf_counter_ns()

            # Remote device un-pairing
            bt_client.interfaces.bluetooth.bt_device.remove_device(bt_dut_address)
            time.sleep(10)
            rsi_bt_on_spp_disconnect = False
            rsi_bt_on_disconn_event = False
            rsi_bt_on_spp_disconnect_in_single_event = False
            rsi_bt_on_disconn_event_in_single_event = False

            events = wifi_dut.interfaces.wifi.get_async_events(since_time=start_capture_time)
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_SPP_DISCONN:
                        rsi_bt_on_disconn_event_in_single_event = b"4E13" in event.event_data and b"rsi_bt_on_disconn_event" in event.event_data
                        rsi_bt_on_spp_disconnect = True

                    if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_DISCONNECTED:
                        rsi_bt_on_disconn_event = b"4E13" in event.event_data
                        rsi_bt_on_spp_disconnect_in_single_event = b"4E13" in event.event_data and b"rsi_bt_on_spp_disconnect" in event.event_data

            assert rsi_bt_on_spp_disconnect == True or rsi_bt_on_spp_disconnect_in_single_event == True
            assert rsi_bt_on_disconn_event == True or rsi_bt_on_disconn_event_in_single_event == True

            # Send data from dut to bt_client after closing socket
            with pytest.raises(WlanError) as exc_info:
                wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                assert exc_info.value.error_code == 0x4500, "SPP Not Connected, expected is 0x4500"

            wifi_dut.interfaces.wifi.leave()
    logger().info(f"Scan in {t.duration} seconds")

    # Sniffer stop
    logger().info(f"Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validating the power management bit
    packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
    logger().info(f" Validate power management bit 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



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
def test_bt_coex_unbond_C20108(wifi_sniffer, wifi_dut, wifi_access_point, bt_client):
    send_text = text_generator(size=20)
    recv_text = send_text
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_unbond_C20108')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info(f"fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=2,
                                                               inquiry_duration_ms=20000,
                                                               timeout=22,
                                                               retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                     (bt_client_socket.accept, 20)])
                assert result[1] == bt_dut_address, "Unable to find BT client socket connection"
                logger().info(f"Result from Callable Function {result}")
                time.sleep(20)

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f'Data transfer from BT_client')
                sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                assert sent, "Unable to send the data"
                data = bt_client_socket.recv()
                assert data, "Unable to find BT client socket connection"
                assert data.decode() == recv_text
                logger().info(f'Data received from BT_client')

            # Send data from dut to bt_client
            logger().info(f'Data transfer from dut')
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data, "Unable to find BT client socket connection"
            assert data.decode() == send_text
            logger().info(f'Data received from dut')

            # Ping dut
            logger().info(f"  Ping to DUT ")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"
            logger().info(f" Pinging ")

            # spp rejection from DUT
            logger().info(f"  remove the Linkkey ")
            wifi_dut.interfaces.wifi.clear_linkkey()
            logger().info(f" clear linkkey ")

            # Close connection
            logger().info(f"disconnecting bt host....")
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
            time.sleep(2)

        #Again Initiate connection from DUT to RD1
        logger().info(f" Again Initiate connection from DUT to RD1 ")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=1,
                                                               inquiry_duration_ms=20000,
                                                               timeout=40,
                                                               retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



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
def test_bt_coex_rssi_C20109(wifi_sniffer, wifi_dut,wifi_access_point,bt_client):
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_rssi_C20109')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info(f"Fetches the DUT mac address")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        # Initiate ping from third party wifi-client to DUT
        logger().info(f'DUT ip {device_ip}')
        logger().info(f"pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1,"DUT not responding for ping request......"
        logger().info(f"ping to DUT is successful....")

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
                                                              timeout=40,
                                                              retry_counts=6)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"
        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            result = ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                 (bt_client_socket.accept, 20)])
            assert result[1] == bt_dut_address, "Unable to find BT client socket connection"
            logger().info(f"Result from Callable Function {result}")
            time.sleep(20)
        logger().info("BT master connection success")

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
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



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
def test_bt_coex_BD_C20110(wifi_sniffer, wifi_dut, wifi_access_point,bt_client):
    send_text = text_generator(size=20)
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_BD_C20110')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info(f"fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f"Initiating BT_CONNECT ")
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected, "Unable to find BT server socket connection"
                logger().info(f" BT_CONNECT SUCCESSFUL ")
                time.sleep(20)

            # Send data from dut to bt_client
            logger().info(f" Initiating BT_SPP TRANSFER ")
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data, "Unable to find BT server socket connection"
            assert data.decode() == send_text
            logger().info(f"  BT_SPP TRANSFER COMPELTED ")

            # Ping dut
            logger().info(f"  Ping to DUT ")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"
            logger().info(f" Pinging ")

            #BD address
            addr = wifi_dut.interfaces.wifi.bt_get_local_address()
            logger().info(f'BT LOCAL  address {addr} found')
            #local name
            addr1 = wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info(f'BT LOCAL name {addr1} found')

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



#To validate SPP data transfer of Tx and Rx at same time1(WLAN is in idle connected state)
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
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
def test_sta_bt_C20116(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    send_text = "支那支那支那支那支那支那支那支那支那"
    recv_text = "支那支那支那支那支那支那支那支那支那"
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_sta_bt_C20116')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, f"Failed to get bt dut address"
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, f"Failed to get bt client address"
        time.sleep(1)
        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                                    inquiry_type=2,
                                                                    inquiry_duration_ms=10000,
                                                                    timeout=22,
                                                                    retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                logger().info(f"Connecting Raspberry PI to DUT-BT")
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected, "Unable to find BT server socket connection"
                time.sleep(20)

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                assert sent, "Unable to send the data"
                data = bt_server_socket.recv()
                assert data, "Unable to find BT server socket connection"
                assert data.decode() == recv_text, f"Failed to decode receive data "

            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data, "Unable to find BT server socket connection"
            assert data.decode() == send_text

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

            # Close connection
            logger().info(f"BT client socket connection closing")
            bt_server_socket.close()
            time.sleep(2)

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Test case executed in {t.duration} seconds")
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



# To validate SPP data transfer of Tx and Rx at same time2(WLAN is in connected state)
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
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
def test_sta_bt_C20117(wifi_sniffer, wifi_dut, bt_client, wifi_access_point):
    send_text = "支那支那支那支那支那支那支那支那支那"
    recv_text = "支那支那支那支那支那支那支那支那支那"
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_sta_bt_C20117')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=2,
                                                               inquiry_duration_ms=20000,
                                                               timeout=22,
                                                               retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                     (bt_client_socket.accept, 20)])
                assert result[1] == bt_dut_address, "Unable to find BT client socket connection"
                logger().info(f"Result from Callable Function {result}")
                time.sleep(20)

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f'Data transfer from BT_client')
                sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                assert sent, "Unable to send the data"
                data = bt_client_socket.recv()
                assert data, "Unable to find BT client socket connection"
                assert data.decode() == recv_text
                logger().info(f'Data received from BT_client')

            # Send data from dut to bt_client
            logger().info(f'Data transfer from dut')
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data, "Unable to find BT client socket connection"
            assert data.decode() == send_text
            logger().info(f'Data received from dut')

            # Ping dut
            logger().info(f"  Ping to DUT ")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"
            logger().info(f" Pinging ")

            # Close connection
            logger().info(f"BT client socket connection closing")
            bt_client_socket.close()
            time.sleep(2)

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Test case executed in {t.duration} seconds")
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



#Data transfer on by enabling Max slots
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
def test_bt_coex_data_transfer_max_slots_C20118(wifi_sniffer,wifi_dut,wifi_access_point,bt_client,remote_socket,wifi_networked_dut,remote_socket_factory, num_sockets):
    send_text = text_generator(size=20)
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_data_transfer_max_slots_C20118')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        device_ip = wifi_networked_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        threads = []
        start_port = 5000
        for i in range(0, num_sockets):
            port = start_port + i
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.start_server(port=port, socket_type=SOCKET_TYPE_TCP)
            dut_socket = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket()
            wifi_networked_dut.interfaces.wifi.bind(dut_socket, device_ip, port)
            wifi_networked_dut.interfaces.wifi.connect_to_server(dut_socket, server_socket)
        number_of_pkts = 10

        send_list = []
        for count in range(0, 10):
            th_start = Thread(target=Receive_data_socket, args=(remote_socket_factory, logger, count, number_of_pkts), )
            send_list.append(th_start)
            th_start.start()

        wifi_networked_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=1023, data_len=1000,
                                                                               time_interval=60,
                                                                               number_of_pkts=number_of_pkts)
        time.sleep(10)
        # start all threads and wait for exit
        with ExitStack() as thread_stack:
            for thread in threads:
                thread_stack.enter_context(thread)

        #DUT closes the tcp socket
        for sock_count in range(0, 1):
            logger.info(f"Closing socket_id->{sock_count}")
            result = wifi_dut.interfaces.wifi.close_socket(sock_count)
            assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
            logger.info(f"Successfully closed socket_id->{sock_count}")
        remote_socket.interfaces.socket.socket_close_indication(1)
        time.sleep(1)

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=6)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f"Initiating BT_CONNECT ")
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=6)
                assert connected, "Unable to find BT server socket connection"
                logger().info(f" BT_CONNECT SUCCESSFUL ")
                time.sleep(20)

            # Send data from dut to bt_client
            logger().info(f" Initiating BT_SPP TRANSFER ")
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data, "Unable to find BT server socket connection"
            assert data.decode() == send_text
            logger().info(f"  BT_SPP TRANSFER COMPELTED ")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Test case executed in {t.duration} seconds")
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



#Buffer full exception by initiating TCP packet retrials
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
def test_bt_coex_buffer_tcp_C20119(wifi_sniffer,wifi_dut,wifi_access_point,bt_client,remote_socket):
    send_text = text_generator(size=20)
    recv_text = send_text
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_buffer_tcp_C20119')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected, "Unable to find BT server socket connection"
                time.sleep(20)

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                assert sent, "Unable to send the data"
                data = bt_server_socket.recv()
                assert data, "Unable to find BT server socket connection"
                assert data.decode() == recv_text

            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data, "Unable to find BT server socket connection"
            assert data.decode() == send_text
            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"
            # Capture the time to identify events
            start_capture_time = time.perf_counter_ns()

        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # tcp socket opened in DUT connects to the tcp server
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = randint(5001, 50000)
        execute_command = ['iperf', '-s', '-i 1', '-p', str(server_port)]
        iperf_process = SubprocessManager(execute_command)
        iperf_process.start()
        # DUT opens tcp client sockets
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)

        wifi_dut.interfaces.wifi.connect(sock, server_ip, server_port)
        data_length = 1460
        no_of_pkts = 1000
        bytes_triggered = (data_length * no_of_pkts)
        # DUT sends 50 bytes of data over tcp socket
        wifi_dut.interfaces.wifi.send_data_pkts(sock, data_length, no_of_pkts)
        time.sleep(3)
        iperf_process.stop()
        time.sleep(1)
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
                remote_terminate = event.event_data
            else:
                assert 1, f"Remote terminate event is not received by DUT even though tcp socket connected is closed"
        logger().info(f"Remote terminate event is received by DUT when tcp socket connected is closed")
        socket_id = int(remote_terminate.split(b",")[1].split(b":")[1])
        bytes_sent = int(remote_terminate.split(b",")[2].split(b":")[1])
        logger().info(f"Number of bytes sent on socket {socket_id}->  {bytes_sent}")
        assert bytes_triggered == bytes_sent, f"Number of bytes triggered by host and actually sent by dut  are not " \
                                              f"matched. triggered {bytes_triggered} bytes, But actually sent {bytes_sent} bytes "
        logger().info(f"Number of bytes triggered by host and actually sent by dut are matched")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Test case executed in {t.duration} seconds")
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



#Buffer full exception by initiating TCP packet retrials through rejoin failure
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
def test_bt_coex_buffer_tcp_rejoin_C20120(wifi_sniffer,wifi_dut,wifi_access_point,bt_client,remote_socket):
    send_text = text_generator(size=20)
    recv_text = send_text
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_buffer_tcp_rejoin_C20120')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, "Unable to get BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, "Unable to get BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected, "Unable to find BT server socket connection"
                time.sleep(20)

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                assert sent, "Unable to send the data"
                data = bt_server_socket.recv()
                assert data, "Unable to find BT server socket connection"
                assert data.decode() == recv_text

            # Send data from dut to bt_client
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data, "Unable to find BT server socket connection"
            assert data.decode() == send_text
            # Ping dut
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address), \
                f"Failed to ping BT client to DUT"
            # Capture the time to identify events
            start_capture_time = time.perf_counter_ns()

        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()

        server_port = randint(5001, 50000)
        execute_command = ['iperf', '-s', '-i 1', '-p', str(server_port)]
        iperf_process = SubprocessManager(execute_command)
        iperf_process.start()

        # DUT opens tcp client sockets
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock} which is expected")

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)

        wifi_dut.interfaces.wifi.connect(sock, server_ip, server_port)
        data_length = 1460
        no_of_pkts = 20000
        bytes_triggered = (data_length * no_of_pkts)
        thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 15, logger), )
        thread.start()
        wifi_dut.interfaces.wifi.send_data_pkts(sock, data_length, no_of_pkts, timeout=600)
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
        logger().info(f"Bytes sent on the DUT -> {bytes_triggered}, received on remote tcp socket {receive_stats}")

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Test case executed in {t.duration} seconds")
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



#Data transfer with different RSSI values
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
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_different_rssi_values_C20121(wifi_sniffer,wifi_dut,wifi_access_point,wifi_client,bt_client,net_perf_client, protocol,rf_attenuator):
    inq_type = 1
    duration = 10000
    max_no_dev = 10
    cod = '20121'
    event_data = ''
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_different_rssi_values_C20121')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip = wifiJoin(wifi_dut, wifi_access_point)
        assert device_ip, "Device IP fetching failed"
        time.sleep(3)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

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
                                                              timeout=40,
                                                              retry_counts=3)
        if not found:
            assert found, "Dut unable to find the bt client device. The test case may fail"

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            # SPP Connection
            logger().info(f'Create SPP Connection')
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                     (bt_client_socket.accept, 20)])
                assert result[1] == bt_dut_address, "Unable to find BT client socket connection"
                logger().info(f"Result from Callable Function {result}")
                time.sleep(20)

            logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
            run_iperf_server_rssi(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol)

            # Set COD to Raspberry Pi device
            logger().info(f"Set COD to Raspberry pi device")
            bt_client.interfaces.bluetooth.bt_adapter.set_class(cod)

            # BT initialization
            logger().info(f'******BT initialization******')
            wifi_dut.interfaces.wifi.bt_start()

            for i in range(0, 3):
                # start BT inquiry with RSSI from DUT
                logger().info(f'******Start BT inquiry with RSSI from DUT******')
                wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
                time.sleep(duration / 1000)

                # Get Asynchronous messages
                events = wifi_dut.interfaces.wifi.get_async_events()
                assert len(events) > 0

                # Search for Inquiry type and Remote BT device address
                for event in events:
                    event_data = event_data + str(event.event_data.decode())
                    if bt_client_address in event_data and 'Inquiry_type = 1' in event_data:
                        logger().info(f'Remote BT address found ==> {bt_client_address}')
                        logger().info(f'Inquiry Type ==> {inq_type}')
                        break
                # Check for Class of Device in the inquiry results and extract RSSI value from it.
                if cod in event_data:
                    test_data = event_data.split('COD = 20121')[1].strip(', RSSI :')
                    test_data = test_data.split(',')[0].strip()
                    logger().info(f'Remote device COD ==> {cod}')
                    logger().info(f'RSSI ==> {test_data}')
                    found = 1
                    break
                else:
                    logger().info(f'BT address {bt_client_address} not found')

            if found == 0:
                logger().info(f'BT address/Inquiry type/COD/RSSI are not found')
                assert False
            else:
                logger().info(f'BT address,Inquiry type,COD,RSSI are found in inquiry results')
                assert True

        # Sniffer stop
        logger().info(f"Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        logger().info(f" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '
    logger().info(f"Test case executed in {t.duration} seconds")
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)