from utf.interfaces.wifi import WlanError

from utf.interfaces.iperf.iperf_constants import IperfConstants
import pytest
from utf.utils.logger import get_logger

from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
import time
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap
from utf.interfaces.iperf.iperf_device_output_parser import Result


def logger():
    return get_logger(__name__)

"""
setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)    
Test Steps:    
        Step1 : Configuration of DUT in BT/Wlan.
        Step2 : Verify the connection to AP
        Step3 : Verify the Bleconnection

Author:
        Jyothi Nagireddy
"""

#this thread used for data throughput
class wifiDatathroughputThread(ThreadBase):
    def __init__(self, wifi_access_point, wifi_networked_dut, wifi_client, net_perf_client, mode):
        super().__init__()
        self.wifi_networked_dut = wifi_networked_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.mode = mode

    def run(self):
        time.sleep(5)
        # preparing wifi_dut
        self.wifi_networked_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        ip_config = self.wifi_networked_dut.interfaces.wifi.start_ip()
        device_ip = self.wifi_networked_dut.interfaces.wifi.get_device_ip(ip_config)

        # preparing wifi_client
        if self.wifi_access_point != self.wifi_client:
            self.wifi_client.interfaces.wifi.join_ap(self.wifi_access_point)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        assert self.wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

        # starting iperf as Server
        if (self.mode == IperfConstants.SERVER_MODE):
            self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip)
            self.net_perf_client.interfaces.net_perf.start()

            # open socket and send traffic
            self.wifi_networked_dut.interfaces.wifi.send_traffic_from_device(
                host_ip,
                device_ip,
                self.net_perf_client.interfaces.net_perf.server_port,
                self.net_perf_client.interfaces.net_perf.protocol,
                self.net_perf_client.interfaces.net_perf.client_options,
            )
        # starting iperf as Client
        else:
            self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip)
            # creating results object for sharing between host and dut
            result = Result(self.net_perf_client.interfaces.net_perf.protocol)

            # open socket and start listening
            with self.wifi_networked_dut.interfaces.wifi.start_socket_reader(
                    log_file=self.net_perf_client.interfaces.net_perf.device_log_file_handle,
                    result=result,
                    protocol=self.net_perf_client.interfaces.net_perf.protocol,
                    port=self.net_perf_client.interfaces.net_perf.client_port,
                    device_ip=device_ip,
                    data_len=self.net_perf_client.interfaces.net_perf.client_data_len,
                    time=self.net_perf_client.interfaces.net_perf.client_timeout) as obj:
                # start iperf
                self.net_perf_client.interfaces.net_perf.start()
                # capture device output
                self.wifi_networked_dut.interfaces.wifi.read_from_device(obj, self.net_perf_client.interfaces.net_perf.client_timeout)

            # get and print throughput
            tp = self.net_perf_client.interfaces.net_perf.process_output(result)

        logger().info("this is IPerf END")

# this thread used for ble connectionn as a slave/master
class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        self.logger.info('this is BLE run')
        time.sleep(5)
        if ( self.mode == "ble_master"):
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None

            # Start ble client
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None

            # Start scanning and connect to ble client
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=15)

            timeout = 120
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

            # Disconnect
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

        if ( self.mode == "ble_slave"):

        # Set up DUT for BLE advertising
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

        # Begin Scanning for BLE devices
        #     time.sleep(2)
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(3)
            self.ble_client.interfaces.bluetooth.stop_scanning()

        # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            time.sleep(3)
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                == self.wifi_dut.interfaces.wifi.ble_advertising_data
            )
            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
            time.sleep(40)

            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.config("net_perf_client",
 net_perf={
        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP
        }
    )
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#Tcp rx packet loss #tcp rx throughput in WPA2-AES mode
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_dut_tcp_rx_C20223_C20230(ble_client, wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, net_perf_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, net_perf_client, IperfConstants.CLIENT_MODE), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

@pytest.mark.config("net_perf_client",
 net_perf={
        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP
        }
    )
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#txp tx in WPA2-Mode
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_dut_tcp_tx_C20229(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, net_perf_client,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, net_perf_client, IperfConstants.SERVER_MODE), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

@pytest.mark.config("net_perf_client",
 net_perf={
        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP
        }
    )
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#udp rx in WPA2-AES mode
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_dut_udp_rx_C20230(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, net_perf_client,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, net_perf_client, IperfConstants.CLIENT_MODE), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

@pytest.mark.config("net_perf_client",
 net_perf={
        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP
        }
    )
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#udp tx in WPA2-AES mode
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_dut_udp_tx_C20229(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, net_perf_client,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, net_perf_client, IperfConstants.SERVER_MODE), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)


@pytest.mark.config("net_perf_client",
 net_perf={
        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP
        }
    )
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#rx throughput functionality in open mode
@pytest.mark.config('wifi_access_point', wifi={"security": "OPEN", "cipher": 'AES'})
def test_threading_sta_ble_dut_tcp_rx_C20203(ble_client, wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, net_perf_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, net_perf_client, IperfConstants.CLIENT_MODE), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

@pytest.mark.config("net_perf_client",
 net_perf={
        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP
        }
    )
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#tcp tx throughput functionality in open mode
@pytest.mark.config('wifi_access_point', wifi={"security": "OPEN", "cipher": 'AES'})
def test_threading_sta_ble_dut_tcp_tx_C20203(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, net_perf_client,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, net_perf_client, IperfConstants.SERVER_MODE), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

@pytest.mark.config("net_perf_client",
 net_perf={
        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP
        }
    )
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#throughput functionality in open mode
@pytest.mark.config('wifi_access_point', wifi={"security": "OPEN", "cipher": 'AES'})
def test_threading_sta_ble_dut_udp_rx_C20203(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, net_perf_client,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, net_perf_client, IperfConstants.CLIENT_MODE), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

@pytest.mark.config("net_perf_client",
 net_perf={
        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP
        }
    )
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#throughput functionality in open mode
@pytest.mark.config('wifi_access_point', wifi={"security": "OPEN", "cipher": 'AES'})
def test_threading_sta_ble_dut_udp_tx_C20203(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, net_perf_client,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, net_perf_client, IperfConstants.SERVER_MODE), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)


