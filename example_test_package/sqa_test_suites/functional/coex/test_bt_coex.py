import time
import pytest
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BTSocketRole
# import utf.interfaces.bluetooth.bluetooth_interface
# from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping
from utf.utils.time_measurer import TimeMeasurer
from random import randint
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.subprocess_manager import SubprocessManager
# from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116AsyncEventType, \
    RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116FeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116BTFeatureBitMap, RS9116ExtTCPIPFeatureBitMap , RS9116ConfigFeatureBitMap, DeviceConstants,SocketOptions

ping_count = 10
iter_cnt = 5

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Vishakha
"""

# This Thread is used to wifiJoinThread
class wifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point

    def run(self):
        status = self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        self.logger.info(status)
        time.sleep(15)

class BtSppMaster_SlaveThread(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

    def run(self):
        if self.mode == "bt_slave":
            send_text = "yAbdcUK0tAOSMhCT4d6U"
            recv_text = "H2D7yZKRhKULU9Xil5Yv"

            logger().info(f"Configuring DUT as SPP Slave")
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address is not None, "Unable to find BT DUT address"
            logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address is not None, "Unable to find BT client address"
            logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

            logger().info(f"enabling wifi power save mode in DUT......")
            self.wifi_dut.interfaces.wifi.power_save(2,1)

            logger().info(f"enabling bt power save mode in DUT......")
            self.wifi_dut.interfaces.wifi.bt_power_save(2,1)

            logger().info(f"Starting Raspberry PI as BT Server")
            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    logger().info(f"Connecting Raspberry PI to DUT-BT")
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                    assert connected
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                time.sleep(20)

                # Send data from bt_client to dut
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                    assert sent
                    data = bt_server_socket.recv()
                    logger().info(f"Connecting BT server socket")
                    assert data is not None, "Unable to find BT server socket connection"
                    assert data.decode() == recv_text

                # Send data from dut to bt_client
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_server_socket.recv()
                logger().info(f"Connecting BT server socket")
                assert data is not None, "Unable to find BT server socket connection"
                assert data.decode() == send_text

                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)

                # Close connection
                logger().info(f"disconnecting bt host....")
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                logger().info(f"Close Socket connection")
                bt_server_socket.close()
                time.sleep(5)

        if self.mode == "bt_master":
            # while not self.stop_requested:
            send_text = "sA0L9b1xEgGuUqN5YOlx"
            recv_text = "H2D7yZKRhKULU9Xil5Yv"

            logger().info(f"Configuring DUT as SPP MASTER")
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None, "Unable to find BT DUT address"
            logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None, "Unable to find BT client address"
            logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

            logger().info(f"enabling wifi power save mode in DUT......")
            self.wifi_dut.interfaces.wifi.power_save(2,1)

            logger().info(f"enabling bt power save mode in DUT......")
            self.wifi_dut.interfaces.wifi.bt_power_save(2,1)

            logger().info(f"Starting Raspberry PI as BT Server")
            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_client_socket.create_client()
                    self.wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                    logger().info(f"Connecting Raspberry PI to DUT-BT")
                    addr = bt_client_socket.accept(timeout=150)
                    assert addr == bt_dut_address

                # Send data from bt_client to dut
                time.sleep(20)
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    sent = bt_client_socket.send(
                        recv_text
                    )  # Dut is programmed to send back data
                    assert sent
                    data = bt_client_socket.recv()
                    logger().info(f"Connecting BT client socket")
                    assert data is not None, "Unable to find BT client socket connection"
                    assert data.decode() == recv_text

                # Send data from dut to bt_client
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_client_socket.recv()
                logger().info(f"Connecting BT client socket")
                assert data is not None, "Unable to find BT client socket connection"
                assert data.decode() == send_text

                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )

                # Close connection
                logger().info(f"disconnecting bt host....")
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                logger().info(f"Close Socket connection")
                bt_client_socket.close()
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
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address is not None, "Unable to find BT DUT address"
            logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address is not None, "Unable to find BT client address"
            logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

            logger().info(f"enabling wifi power save mode in DUT......")
            self.wifi_dut.interfaces.wifi.power_save(2,1)

            logger().info(f"enabling bt power save mode in DUT......")
            self.wifi_dut.interfaces.wifi.bt_power_save(2,1)

            logger().info(f"Starting Raspberry PI as BT Server")
            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    logger().info(f"Connecting Raspberry PI to DUT-BT")
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                    assert connected
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                time.sleep(20)

                result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Device role:{result}")
                wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
                time.sleep(10)
                final_role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Role Switch: {final_role}")

                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)

                # Close connection
                logger().info(f"disconnecting bt host....")
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                logger().info(f"Close Socket connection")
                bt_server_socket.close()
                time.sleep(5)

        if self.mode == "bt_master":
            logger().info(f"Configuring DUT as SPP MASTER")
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None, "Unable to find BT DUT address"
            logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None, "Unable to find BT client address"
            logger().info(f"Raspberry PI is BT-SLAVE  with MAC address {bt_client_address} ")

            logger().info(f"enabling wifi power save mode in DUT......")
            self.wifi_dut.interfaces.wifi.power_save(2,1)

            logger().info(f"enabling bt power save mode in DUT......")
            self.wifi_dut.interfaces.wifi.bt_power_save(2,1)

            logger().info(f"Starting Raspberry PI as BT Server")
            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_client_socket.create_client()
                    logger().info(f"Connecting Raspberry PI to DUT-BT")
                    self.wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                    addr = bt_client_socket.accept(timeout=40)
                    assert addr == bt_dut_address

                result = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Device role:{result}")
                wifi_dut.interfaces.wifi.bt_set_local_role(bt_client_address, role_flag="0")
                time.sleep(10)
                final_role = wifi_dut.interfaces.wifi.bt_get_local_role(bt_client_address)
                logger().info(f"Role Switch: {final_role}")

                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )

                # Close connection
                logger().info(f"disconnecting bt host....")
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                logger().info(f"Close Socket connection")
                bt_client_socket.close()
                time.sleep(5)


# This Thread is used to run and inquiry the BT
class BtThread_inquiry(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        self.wifi_dut.interfaces.wifi.bt_inquiry()
        time.sleep(20)


# This Thread is used to run and inquiry the BT
class BtThread_cancel_inquiry(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        self.wifi_dut.interfaces.wifi.bt_inquiry()
        time.sleep(20)

    def set_noscan(self):
        self.shell.execute(f"sudo hciconfig {self.adapter} noscan")
        # Disable scan
        self.bt_client.interfaces.bluetooth.bt_adapter.set_noscan()


class wifi_traffic_thread(Thread):
    def __init__(self, wifi_access_point, wifi_dut, bt_client, protocol, iperf_time):
        super().__init__()
        self.wifi_access_point = wifi_access_point
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.protocol = protocol
        self.iperf_time = iperf_time


    def run(self):
        run_iperf_server(self.net_perf_client, self.wifi_access_point, self.wifi_dut, self.wifi_client, self.protocol,
                         self.iperf_time)
        logger().info(f"Wi-Fi traffic thread completed")


class connect_disconnect_wifi_thread(Thread):
    def __init__(self, wifi_dut, wifi_access_point, iter_count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.iter_count = iter_count

    def run(self):
        # check whether iperf started before wifi-disconnect-connect
        global iperf_started
        error = False
        wait_time = 0
        while True:
            if iperf_started:
                break
            elif wait_time == 20:
                error = True
                break
            else:
                time.sleep(10)
                wait_time += 1

        if error:
            logger().warning("Iperf did not start after long wait...can not proceed with wifi_connect_disconnect")
            assert iperf_started is True, "Iperf did not start after long wait...can not proceed with wifi_connect_disconnect"

        for i in range(1, self.iter_count + 1):
            time.sleep(5)
            logger().info(f"Initiating W-Fi disconnection on DUT...Iteration: '{i}'")
            wifi_leave(self.wifi_dut)
            logger().info(f"Successfully disconnected Wi-Fi from DUT...Iteration: '{i}'")
            time.sleep(2)
            logger().info(f"Re-Initiating W-Fi connection on DUT...Iteration: '{i}'")
            wifi_join(self.wifi_dut, self.wifi_access_point)
            logger().info(f"DUT successfully connected to Wi-Fi...Iteration: '{i}'")
        logger().info(f"Wi-Fi Connect-Disconnect thread completed")


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)
        logger().info(f"Iperf throughput printed successfully")

def run_iperf_server(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, iperf_time=30):
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

def wifi_join(wifi_dut, wifi_access_point):
    time.sleep(5)
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"wifi_join status: {status}")
    time.sleep(5)

def ApWirelessOff(wifi_access_point, wait_time, logger):
    time.sleep(wait_time)
    logger().info(f"Disabling Wireless in AP")
    wifi_access_point.interfaces.wifi.stop_ap()
    logger().info(f"Wait for 5 seconds")
    time.sleep(5)
    logger().info(f"Enabling Wireless in AP")
    wifi_access_point.interfaces.wifi.start_ap()


#BT stability in the Coex mode by multiple connection and disconnection
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_mode_as_slave_C20089(wifi_dut,wifi_access_point,bt_client):
    mode = "bt_slave"
    with wifiJoinThread(wifi_dut, wifi_access_point):
        time.sleep(3)
    t2 = BtSppMaster_SlaveThread(wifi_dut, bt_client, mode)
    for i in range(1,iter_cnt):
        t2.start()
        time.sleep(5)
        t2.wait_for_exit(True)
        logger().info(f" iteration completed: {i} ")
        time.sleep(10)

    wifi_dut.interfaces.wifi.bt_deinit()

    mode = "bt_master"
    with wifiJoinThread(wifi_dut, wifi_access_point):
        time.sleep(3)
    t3 = BtSppMaster_SlaveThread(wifi_dut, bt_client, mode)
    for i in range(1,iter_cnt):
        t3.start()
        time.sleep(5)
        t3.wait_for_exit(True)
        logger().info(f"iteration completed: {i}")
        time.sleep(10)


#BT Role change from slave to master in the Coex mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_mode_C20091(wifi_dut, bt_client, wifi_access_point):
    mode = "bt_slave"
    with wifiJoinThread(wifi_dut, wifi_access_point), BtSpp_role_switch(wifi_dut, bt_client, mode):
        time.sleep(20)


#Inquiry in Coex Mode


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_inquiry_C20101(wifi_dut, bt_client, wifi_access_point):
    with wifiJoinThread(wifi_dut, wifi_access_point), BtThread_inquiry(wifi_dut, bt_client):
        time.sleep(20)
        logger().info(f"Initiating Wi-Fi disconnection on DUT")
        wifi_leave(wifi_dut)


#BT Inquiry command complete event with no remotes around
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_noremote_C20102(wifi_dut, wifi_access_point, bt_client):
    duration = 10000
    event_data = ''
    event_found = 0
    with TimeMeasurer() as t:
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

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None, "Unable to find BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None, "Unable to find BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

        # Disable scan
        logger().info(f'******Disable PIscan in Raspberry Pi ******')
        bt_client.interfaces.bluetooth.bt_adapter.set_noscan()

        logger().info(f" bt inquiry started ")
        status = wifi_dut.interfaces.wifi.bt_inquiry()
        logger().info(f"STATUS OF BT INQUIREY COMMAND ,'{status}'")
        time.sleep(60)

        #Get Asynchronous messages
        events = wifi_dut.interfaces.wifi.get_async_events()
        logger().info(f" ###### EVENTS ARE '{events}' ######")
        assert len(events) > 0

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
    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)



#BT Inquiry command cancel
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_cancel_inquiry_C20103(wifi_dut, bt_client, wifi_access_point):
    with wifiJoinThread(wifi_dut, wifi_access_point), BtThread_cancel_inquiry(wifi_dut, bt_client):
        time.sleep(20)
        logger().info(f"Initiating Wi-Fi disconnection on DUT")
        wifi_leave(wifi_dut)



# BT functionality when Pincode is not entered when prompted
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_without_pin_C20105(wifi_dut, wifi_access_point, bt_client):
    with TimeMeasurer() as t:
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

        logger().info(f"Configuring DUT as SPP Master")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp(bt_pin_code=1234)
        assert bt_dut_address is not None, "Unable to find BT DUT address"
        logger().info(f"DUT is BT-Master with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave_without_agent(bt_dut_address)
        assert bt_client_address is not None, "Unable to find BT client address"
        logger().info(f"Raspberry PI is BT-Slave  with MAC address {bt_client_address} ")

        logger().info(f"enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2,1)

        logger().info(f"enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2,1)

        logger().info(f' initialize bt inquiry ')
        wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                       inquiry_type=1,
                                                       inquiry_duration_ms=20000,
                                                       timeout=40,
                                                       retry_counts=6)
        logger().info(f' bt inquiry successful')

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            # SPP Connection
            logger().info(f'Create SPP Connection')
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address), (bt_client_socket.accept, 60)])
                assert result[1] is None
                logger().info(f'SPP Connection Completed')
            bt_client_socket.close()

        received_authentication_failure = False
        time.sleep(1)
        events = wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.BT_AUTH_COMPLETE:
                    received_authentication_failure = b"4E18" in event.event_data
                    break
        assert received_authentication_failure
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Scan in {t.duration} seconds")



# BT unbond after successful bonding
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_unbond_C20108(wifi_sniffer, wifi_dut, wifi_access_point, bt_client):
    send_text = "yAbdcUK0tAOSMhCT4d6U"
    recv_text = "9cDKpYOnOJeqYPsL987v"
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_unbond_C20108')

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info(f"fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

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
        wifi_dut.interfaces.wifi.power_save(2,1)

        logger().info(f"enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2,1)

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None, "Unable to find BT DUT address"

        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None, "Unable to find BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f"Initiating BT_CONNECT ")
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected
                logger().info(f" BT_CONNECT SUCCESSFUL ")

            # Send data from dut to bt_client
            logger().info(f" Initiating BT_SPP TRANSFER ")
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data is not None, "Unable to find BT server socket connection"
            assert data.decode() == send_text
            logger().info(f"  BT_SPP TRANSFER COMPELTED ")

            # Ping dut
            logger().info(f"  Ping to DUT ")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )
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
        assert bt_dut_address is not None, "Unable to find BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None, "Unable to find BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=1,
                                                               inquiry_duration_ms=20000,
                                                               timeout=40,
                                                               retry_counts=3)
        if not found:
            logger().error(f"Dut unable to find the bt client device. The test case may fail.")

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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_rssi_C20109(wifi_sniffer, wifi_dut,wifi_access_point,bt_client):
    inq_type = 1
    duration = 10000
    max_no_dev = 10
    found = 0
    cod = '20109'
    event_data = ''
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_rssi_C20109')

        logger().info(f"Scan for the AP's")
        ssid = wifi_access_point.interfaces.wifi.ssid
        channel = wifi_access_point.interfaces.wifi.channel
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info(f"Join Wi-Fi Access Point")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(5)
        logger().info(f"This API Enables the DHCP in DUT")
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
        wifi_dut.interfaces.wifi.power_save(2,1)

        logger().info(f"enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2,1)

        logger().info(f"Fetches the DUT mac address")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None, "Unable to find BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None, "Unable to find BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                              inquiry_type=1,
                                                              inquiry_duration_ms=20000,
                                                              timeout=40,
                                                              retry_counts=6)
        if not found:
            logger().error(f"Dut unable to find the bt client device. The test case may fail.")

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
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
                    test_data = event_data.split('COD = 20109')[1].strip(', RSSI :')
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
        logger().info(f"Initiating Wi-Fi disconnection on DUT")
        wifi_leave(wifi_dut)



#To get local BD address and local name
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_BD_C20110(wifi_sniffer, wifi_dut, wifi_access_point,bt_client):
    send_text = "yAbdcUK0tAOSMhCT4d6U"
    recv_text = "9cDKpYOnOJeqYPsL987v"
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_BD_C20110')

        logger().info(f"scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid, channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info(f"fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

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
        wifi_dut.interfaces.wifi.power_save(2,1)

        logger().info(f"enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2,1)

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None, "Unable to find BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None, "Unable to find BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f"Initiating BT_CONNECT ")
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected
                logger().info(f" BT_CONNECT SUCCESSFUL ")

            # Send data from dut to bt_client
            logger().info(f" Initiating BT_SPP TRANSFER ")
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data is not None, "Unable to find BT server socket connection"
            assert data.decode() == send_text
            logger().info(f"  BT_SPP TRANSFER COMPELTED ")

            # Ping dut
            logger().info(f"  Ping to DUT ")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )
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



#SPP transfer by taking remote ooo
@pytest.mark.rf_attenuator('50pa500_attenuator')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_ooo_C20096(wifi_sniffer, wifi_dut, wifi_access_point, bt_client, rf_attenuator):
    send_text = "sA0L9b1xEgGuUqN5YOlx"
    recv_text = "H2D7yZKRhKULU9Xil5Yv"
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_ooo_C20096')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

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
        wifi_dut.interfaces.wifi.power_save(2,1)

        logger().info(f"enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2,1)

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None, "Unable to find BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None, "Unable to find BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                              inquiry_type=1,
                                                              inquiry_duration_ms=20000,
                                                              timeout=40,
                                                              retry_counts=3)
        if not found:
            logger().error(f"Dut unable to find the bt client device. The test case may fail.")

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            # SPP Connection
            logger().info(f'Create SPP Connection')
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                    (bt_client_socket.accept, 20)]
                )
                assert result[1] == bt_dut_address
                logger().info(f"Result from Callable Function {result}")
                logger().info(f'SPP Connection Completed')

            # Send data from bt_client to dut
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f'Data transfer from BT_client')
                sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
                assert sent
                data = bt_client_socket.recv()
                assert data is not None, "Unable to find BT client socket connection"
                assert data.decode() == recv_text
                logger().info(f'Data received from BT_client')

            # Send data from dut to bt_client
            logger().info(f'Data transfer from dut')
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            assert data is not None, "Unable to find BT client socket connection"
            assert data.decode() == send_text
            logger().info(f'Data received from dut')

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



#Buffer full exception by initiating TCP packet retrials
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_buffer_tcp_C20119(wifi_sniffer,wifi_dut,wifi_access_point,bt_client,remote_socket):
    send_text = "yAbdcUK0tAOSMhCT4d6U"
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_buffer_tcp_C20119')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

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
        wifi_dut.interfaces.wifi.power_save(2,1)

        logger().info(f"enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2,1)

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None, "Unable to find BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None, "Unable to find BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f"Initiating BT_CONNECT ")
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected
                logger().info(f" BT_CONNECT SUCCESSFUL ")

            # Send data from dut to bt_client
            logger().info(f" Initiating BT_SPP TRANSFER ")
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data is not None, "Unable to find BT server socket connection"
            assert data.decode() == send_text
            logger().info(f"  BT_SPP TRANSFER COMPELTED ")

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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_buffer_tcp_rejoin_C20120(wifi_sniffer,wifi_dut,wifi_access_point,bt_client,remote_socket):
    send_text = "9cDKpYOnOJeqYPsL987v"
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_buffer_tcp_rejoin_C20120')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

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
        wifi_dut.interfaces.wifi.power_save(2,1)

        logger().info(f"enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2,1)

        logger().info(f"Configuring DUT as SPP Slave")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None, "Unable to find BT DUT address"
        logger().info(f"DUT is BT-SLAVE with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None, "Unable to find BT client address"
        logger().info(f"Raspberry PI is BT-MASTER  with MAC address {bt_client_address} ")

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                logger().info(f"Initiating BT_CONNECT ")
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected
                logger().info(f" BT_CONNECT SUCCESSFUL ")

            # Send data from dut to bt_client
            logger().info(f" Initiating BT_SPP TRANSFER ")
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            assert data is not None, "Unable to find BT server socket connection"
            assert data.decode() == send_text
            logger().info(f"  BT_SPP TRANSFER COMPELTED ")

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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_bt_coex_different_rssi_values_C20121(wifi_sniffer,wifi_dut,wifi_access_point,bt_client, protocol,rf_attenuator):
    inq_type = 1
    duration = 10000
    max_no_dev = 10
    found = 0
    cod = '20121'
    event_data = ''
    with TimeMeasurer() as t:
        validation = True
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bt_coex_different_rssi_values_C20121')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

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
        wifi_dut.interfaces.wifi.power_save(2,1)

        logger().info(f"enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2,1)

        logger().info(f"Configuring DUT as SPP MASTER")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None, "Unable to find BT DUT address"
        logger().info(f"DUT is BT-MASTER with MAC address {bt_dut_address} ")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None, "Unable to find BT client address"
        logger().info(f"Raspberry PI is BT-SLAVE with MAC address {bt_client_address} ")



        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                              inquiry_type=1,
                                                              inquiry_duration_ms=10000,
                                                              timeout=40,
                                                              retry_counts=3)
        if not found:
            logger().error(f"Dut unable to find the bt client device. The test case may fail.")

        logger().info(f"Starting Raspberry PI as BT Server")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            # SPP Connection
            logger().info(f'Create SPP Connection')
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                result = ThreadBase.call_functions_simultaneously(
                    [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address),
                     (bt_client_socket.accept, 20)]
                )
                assert result[1] == bt_dut_address
                logger().info(f"Result from Callable Function {result}")
                logger().info(f'SPP Connection Completed')

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
