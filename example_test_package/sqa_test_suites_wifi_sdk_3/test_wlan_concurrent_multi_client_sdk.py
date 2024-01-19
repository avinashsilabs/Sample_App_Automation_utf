import time
import string
import random
from utf.utils.stopwatch import Stopwatch
import pytest as pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xOperatingMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xMqttQos,
    Si91xModuleType,
    Si91xJoinFeatureBitMap,
    Si91xCertificateType,
    Si91xCertIdentifier
)
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from retry import retry
from threading import Thread
from utf_wiseconnect_3.tests.sl_status import SLStatus
from random import randint
from utf.interfaces.socket import SOCKET_TYPE_TCP
from utf.utils.thread_base import ThreadBase

"""
    setup requirement:
        1. DUT(RS9117SOC)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
    Test Steps:
        1. Configure the DUT in concurrent mode
        2. create DUT as access point and join DUT to 3rd party access point
        3. Initiate ping from the dut and vice versa
        4.Disconnect dut and connect again
    Author: CG Team
"""


def logger():
    return get_logger(__name__)


class ConcurrentMode:
    def __init__(self):
        self.dut_ap_ip = None
        self.clients_connected = False

    def connect_clients_to_dut_as_ap(self, wifi_clients, wifi_dut, count=3, ping_count=10, dut_ip=None):
        ip_dict = {}
        connected = False
        if self.clients_connected:
            logger().info(f"Disconnecting clients from DUT-AP before associating to DUT-AP")
            for client in wifi_clients:
                client.interfaces.wifi.leave()
            self.clients_connected = False
        for i in range(len(wifi_clients)):
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            if dut_ip is None:
                ip_dict['dut_ip'] = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            else:
                ip_dict['dut_ip'] = dut_ip
            logger().info(f"********* Dut as AP IP **********: {ip_dict['dut_ip']}")
            for retry_count in range(count):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{wifi_clients[i].name}' to DUT")
                    ip_dict[f'client{i + 1}_ip'] = wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client{i + 1}_ip: {ip_dict[f'client{i + 1}_ip']}")
                    rc, stdout, stderr = wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {ip_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except Exception as error:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT:\n{error}...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        self.clients_connected = True
        return ip_dict

    @staticmethod
    def print_throughput(iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run_traffic_btwn_two_clients(self, net_perf_server, net_perf_client, server_ip, client_ip, protocol,
                                     iperf_time=30):
        logger().info(f"********************** Starting Iperf Server on {net_perf_server.name} **********************")
        net_perf_server.interfaces.net_perf.init_server(protocol=protocol, host_ip=server_ip,
                                                        device_ip=client_ip, time_out=iperf_time)
        net_perf_server.interfaces.net_perf.start()
        server_port = net_perf_server.interfaces.net_perf.server_port
        time.sleep(5)

        logger().info(f"********************** Starting Iperf Client on {net_perf_client.name} **********************")
        net_perf_client.interfaces.net_perf.init_client(host_ip=client_ip, device_ip=server_ip,
                                                        protocol=protocol, time_out=iperf_time)
        client_port = net_perf_client.interfaces.net_perf.client_port
        args = net_perf_client.interfaces.net_perf.executable_arguments
        args[args.index(str(client_port))] = str(server_port)
        net_perf_client.interfaces.net_perf.start()
        time.sleep(iperf_time + 5)
        logger().info("Printing Throughput")
        tp = net_perf_server.interfaces.net_perf.process_output()
        assert tp is not None
        self.print_throughput(tp)

    @staticmethod
    @retry(Exception, delay=15, tries=3)
    def ping_from_wifi_client(wifi_client, dest_ip, ping_count=10):
        logger().info(f"Initiating wlan ping from client '{wifi_client.name}' to destination_ip:'{dest_ip}'")
        for count in range(3):
            try:
                rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ping -c {ping_count} {dest_ip}")
                assert rc == 0
                logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                return rc == 0
            except:
                time.sleep(10)

    def connect_disconnect_raspi_clients(self, wifi_clients, wifi_dut, count=3):
        for i in range(count):
            if self.clients_connected:
                logger().info(
                    f"********* Initiating 3rd party clients disconnect from DUT-AP as per test step for iteration:'{i + 1}' *********")
                for client in wifi_clients:
                    client.interfaces.wifi.leave()
                self.clients_connected = False
            logger().info(
                f"********** Initiating 3rd party clients connection for iteration:'{i + 1}' **********")
            self.dut_ap_ip = self.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=self.dut_ap_ip)['dut_ip']


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148564",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148564",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
def test_wifi_sdk_https_get_func_when_two_clients_connected_c148564(sl_collections, wifi_access_point, index_path,
                                                                    wifi_dut, wifi_clients, wifi_sniffer, http_server,
                                                                    sniffer_filter, http_client):
    """ HTTPS Get functionality-two clients connected to RSI_AP """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148564"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        dut_mac_address = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                              retry_count=3, associated=False)['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148564", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init(https_enable=True)
        logger().info("\n\n***Fetching the data on https using get method***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                    server_port=443)
        status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)
        logger().info(status_dut)
        logger().info(content_dut)
        assert content_dut == content_client, "fetched data is not same as expected data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.http_client_deinit()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148582",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148582",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_concurrent_mode_with_mqtt_c148582(wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut,
                                                    sl_collections, sniffer_filter, wifi_clients):
    """QOS1: Subscribe to MQTT server with TCP connection and publish data oversubscribed topic"""

    try:
        topic = "test_topic_mqtt"
        wifi_clients = wifi_clients[:2]
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        capture_filename = "test_c148582"

        logger().info(f"Start sniffer capture on channel 11")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        time.sleep(3)

        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        dut_mac_address = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                              retry_count=3, associated=False)['dut_mac_address']

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148582", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        con_obj = ConcurrentMode()
        con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info("DUT connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info("MQTT Client connects to MQTT server")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(3)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        time.sleep(3)
        logger().info("DUT publishes message over the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1, timeout=30)
        time.sleep(5)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"
        logger().info("MQTT messages validated successfully\n\n")

        logger().info("Unsubscribing from the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148575",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148575",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_concurrent_mode_connect_2_clients_and_run_udp_rx_c148575(sl_collections, wifi_dut, wifi_clients,
                                                                           wifi_access_point, sniffer_filter, protocol,
                                                                           wifi_sniffer, net_perf_client, wifi_client):
    """
    Connect two client to APUT & run UDP RX data transfer from STA to 3rd party AP.
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148575"
        interface = wifi_client.interfaces.wifi.config['interface']
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148575", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")

        for client in wifi_clients:
            client.interfaces.wifi.config['interface'] = "wlan0"
        con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)

        logger().info("Initiating UDP-RX traffic from DUT")
        host_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip,
                                                        protocol=protocol, time_out=60)
        logger().info(f"Host IP: {host_ip}, Dut IP: {device_ip}, Protocol: {protocol}")
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** start listening  ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1470, ttl=60, throughput_type=4, qos=0, timeout=65)

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "并发模式",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "并发模式",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_concurrent_mode_with_chinese_char_ssid_and_2_clients_c148572(sl_collections, wifi_access_point,
                                                                               net_perf_client, protocol, wifi_sniffer,
                                                                               wifi_dut, wifi_clients, sniffer_filter):
    """
    APUT SSID in chinese character , connect 2 client with APUT
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148572"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        dut_mac_addr = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                           retry_count=6, associated=False)['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="并发模式", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)
        dut_ip = ip_dict['dut_ip']
        host_ip = ip_dict['client1_ip']

        logger().info("Initiating TCP-TX traffic from DUT")
        logger().info("starting the server from Remote device")
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip, host_role="S",
                                                        protocol=protocol, time_out=60)
        net_perf_client.interfaces.net_perf.start()
        time.sleep(3)
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=dut_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=net_perf_client.interfaces.net_perf.client_options[protocol]["data_len"],
                                       ttl=60, throughput_type=1, qos=0, timeout=65)

        # logger().info("Wireless deinit in the DUT")
        # wifi_dut.interfaces.wifi.deinit()

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_addr, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "并发模式",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "并发模式",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "并发模式",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "并发模式",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_concurrent_mode_with_chinese_char_ssid_and_4_clients_c148578(sl_collections, sniffer_filter, wifi_dut,
                                                                               net_perf_client, wifi_sniffer, protocol,
                                                                               wifi_access_point, wifi_clients):
    """
    APUT SSID in chinese character , connect 4 client with APUT & run data.
    """
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148578"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        dut_mac_addr = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                           retry_count=6, associated=False)['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="并发模式", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)
        dut_ip = ip_dict['dut_ip']
        host_ip = ip_dict['client1_ip']

        logger().info("Initiating TCP-TX traffic from DUT")
        logger().info("starting the server from Remote device")
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip, host_role="S",
                                                        protocol=protocol, time_out=60)
        net_perf_client.interfaces.net_perf.start()
        time.sleep(3)
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=dut_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=net_perf_client.interfaces.net_perf.client_options[protocol]["data_len"],
                                       ttl=60, throughput_type=1, qos=0, timeout=65)

        # logger().info("Wireless deinit in the DUT")
        # wifi_dut.interfaces.wifi.deinit()

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_addr, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148585",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148585",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
    }
)
def test_wifi_sdk_connect_disconnect_sta_module_of_dut_c148585(sl_collections, wifi_access_point, sniffer_filter,
                                                               wifi_clients, wifi_dut, wifi_sniffer, utf_constants):
    """
    Checking the wifi connection stability of 3rd party clients associated to APUT in concurrent Mode when STAUT is
    doing disconnecting and reconnecting to the Configured AP Long hours Iterations
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        test_run_time = utf_constants.get('time_duration')
        capture_filename = "test_c148585"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148585", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")

        ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)
        dut_ip = ip_dict['dut_ip']
        client1_ip = ip_dict['client1_ip']
        client2_ip = ip_dict['client2_ip']

        sw = Stopwatch()
        expected_error_count = 3
        error_count = 0
        while sw.elapsed_sec <= test_run_time:
            try:
                time_left = int((test_run_time - sw.elapsed_sec) / 60)
                logger().info(f"\n\nRemaining time to complete test is '{time_left}' minutes")
                dut_mac_addr = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                                   retry_count=6, associated=False)['dut_mac_address']
                wifi_dut.interfaces.wifi.leave()
                time.sleep(30)
            except Exception as error:
                error_count += 1
                logger().warning(error)
                if "0x10002" in str(error):
                    wifi_dut.interfaces.wifi.leave()
        assert error_count <= expected_error_count, f"Number of times connect-disconnect sequence failed is {error_count}, " \
                                                    f"which is greater than expected error count {expected_error_count}"

        logger().info("\n\nChecking connection stability by pinging from RASPI to DUT as AP")
        logger().info(f"********* Dut IP **********: {dut_ip}")
        logger().info(f"********* Raspi STA1 IP **********: {client1_ip}")
        logger().info(f"********* Raspi STA2 IP **********: {client2_ip}")
        status = con_obj.ping_from_wifi_client(wifi_clients[0], dut_ip)
        assert status, f"RASPI-STA1 failed to ping to DUT as AP"
        status = con_obj.ping_from_wifi_client(wifi_clients[1], dut_ip)
        assert status, f"RASPI-STA2 failed to ping to DUT as AP"
        logger().info("RASPI-STATIONS are still connected with DUT-AP\n\n")
        logger().info(f"**************** Number of times failures observed during span of {test_run_time / 60} minutes "
                      f"test run is '{error_count}', Which is less than expected failure count {expected_error_count}."
                      f"Hence marking the testcase as PASS ****************\n")
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_addr, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148576",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148576",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_transfer_data_from_client1_to_client2_in_concurrent_mode_c148576(sl_collections, wifi_access_point,
                                                                                   wifi_dut, wifi_clients, wifi_sniffer,
                                                                                   sniffer_filter, net_perf_server,
                                                                                   net_perf_client, protocol):
    """ Transfer data from client one to client two in concurrent mode """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148576"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        dut_mac_address = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                              retry_count=3, associated=False)['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148576", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)

        client_ip = ip_dict['client1_ip']
        server_ip = ip_dict['client2_ip']
        con_obj.run_traffic_btwn_two_clients(net_perf_server, net_perf_client, server_ip, client_ip,
                                             protocol, iperf_time=60)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148573",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148573",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_transfer_udp_data_from_client1_to_client2_in_concurrent_mode_c148573(sl_collections, wifi_clients,
                                                                                       wifi_access_point, wifi_dut,
                                                                                       wifi_sniffer, net_perf_client,
                                                                                       net_perf_server, sniffer_filter,
                                                                                       protocol):
    """ UDP Transfer data from client one to client two in concurrent mode """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148573"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        dut_mac_address = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                              retry_count=3, associated=False)['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148573", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)
        client_ip = ip_dict['client1_ip']
        server_ip = ip_dict['client2_ip']
        con_obj.run_traffic_btwn_two_clients(net_perf_server, net_perf_client, server_ip, client_ip,
                                             protocol, iperf_time=60)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148588",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148588",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_rejoin_func_of_dut_sta_in_concurrent_mode_c148588(switch, sl_collections, wifi_clients, wifi_sniffer,
                                                                    wifi_access_point, wifi_dut, net_perf_client,
                                                                    protocol, net_perf_server, sniffer_filter):
    """
    Verify the STAUT Rejoin functionality in concurrent Mode when APUT is associated and TCP traffic is
    ongoing between the associated clients
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_wifi_sdk_c148588"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148588", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)
        client_ip = ip_dict['client1_ip']
        server_ip = ip_dict['client2_ip']

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 6, 40, 0],
                                                                 power_save=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")

        trf_thread = Thread(target=con_obj.run_traffic_btwn_two_clients,
                            args=(net_perf_server, net_perf_client, server_ip, client_ip, protocol, 180))
        trf_thread.start()
        time.sleep(8)
        logger().info("\n\nTurning off the AP")
        switch.interfaces.pdu_switch.turn_off(delay=20)
        # wifi_access_point.interfaces.wifi.stop_ap()
        # time.sleep(20)
        logger().info("Successfully powered off AP")

        logger().info("\n\nAgain turning on the AP")
        switch.interfaces.pdu_switch.turn_on(delay=80)
        # wifi_access_point.interfaces.wifi.start_ap()
        # time.sleep(80)
        logger().info("Successfully powered on AP")
        logger().info("Pinging to DUT to check rejoin process is completed or not")
        status = sl_collections.ping(dut_sta_ip, 30, 5)
        assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
        trf_thread.join()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA3',
        'channel': 11,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148589",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148589",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_tcp_tx_with_wpa3_and_11n_mode_in_concurrent_mode_c148589(sl_collections, wifi_dut, wifi_clients,
                                                                           wifi_access_point, sniffer_filter, protocol,
                                                                           wifi_sniffer, net_perf_client, wifi_client):
    """
    Verify the STA WLAN TCP Tx Performance with WPA3 with 11n in Concurrent Mode when two 3rd party Clients are
    connected to APUT in WPA2 Security.
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148589"
        interface = wifi_client.interfaces.wifi.config['interface']
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148589", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")

        for client in wifi_clients:
            client.interfaces.wifi.config['interface'] = "wlan0"
        con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        time.sleep(5)

        logger().info("Initiating TCP-TX traffic from DUT")
        host_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                                   device_ip=device_ip, host_ip=host_ip, timeout=60, traffic_type="TX")

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148590",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148590",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_tcp_rx_func_in_concurrent_mode_c148590(sl_collections, wifi_dut, wifi_clients,
                                                         wifi_access_point, sniffer_filter, protocol,
                                                         wifi_sniffer, net_perf_client, wifi_client):
    """
    Verify the STA WLAN TCP Rx Performance with WPA2 with 11n in Concurrent Mode when two 3rd party Clients are
    connected to APUT in WPA2 Security and Ping traffic is running between the 3rd party clients
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148590"
        interface = wifi_client.interfaces.wifi.config['interface']
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148590", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        for client in wifi_clients:
            client.interfaces.wifi.config['interface'] = "wlan0"
        con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)

        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")

        logger().info("Initiating TCP-RX traffic from DUT")
        host_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip,
                                                        protocol=protocol, time_out=60)
        logger().info(f"Host IP: {host_ip}, Dut IP: {device_ip}, Protocol: {protocol}")
        logger().info(f"***** starting iperf ******")
        trf_thread = Thread(target=net_perf_client.interfaces.net_perf.start, args=[4])
        trf_thread.start()
        logger().info(f"***** start listening  ******")
        status = wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                local_port=net_perf_client.interfaces.net_perf.client_port,
                                                local_ip=device_ip, remote_ip=host_ip,
                                                remote_port=net_perf_client.interfaces.net_perf.client_port,
                                                size=net_perf_client.interfaces.net_perf.client_options[protocol][
                                                    "data_len"],
                                                ttl=60, throughput_type=3, qos=0, timeout=65)
        trf_thread.join()
        logger().info("data transfer is successful")
        expected_status = [SLStatus.SL_STATUS_SI91X_SOCKET_TX_OR_RX_FAIL,
                           SLStatus.SL_STATUS_SI91X_TCP_SERVER_SOCKET_CLOSE_FAIL]
        if status in expected_status:
            pytest.xfail("IPERF TCP_RX is not working: https://jira.silabs.com/browse/SI91X-14462")

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148591",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148591",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        2: {
            "security": "WPA2",
            "ssid": "TEST_C148591",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        3: {
            "security": "WPA2",
            "ssid": "TEST_C148591",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_udp_tx_func_4_clients_connected_in_conc_mode_when_c148591(sl_collections, wifi_dut, wifi_clients,
                                                                            wifi_access_point, sniffer_filter,
                                                                            protocol, wifi_sniffer, net_perf_client,
                                                                            wifi_client):
    """
    Verify the STA WLAN UDP Tx Performance with WPA2 Security with 11n in Concurrent Mode when the Max No.of 3rd party
    clients are connected to APUT in WPA2 Security and ping between 4 clients.
    """
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148591"
        interface = wifi_client.interfaces.wifi.config['interface']
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148591", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        for client in wifi_clients:
            client.interfaces.wifi.config['interface'] = "wlan0"
        ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)

        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")

        thread_started = False
        host_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        trf_thread = Thread(target=sl_collections.run_traffic,
                            kwargs={'wifi_dut': wifi_dut, 'net_perf_client': net_perf_client, 'protocol': protocol,
                                    'device_ip': device_ip, 'host_ip': host_ip, 'timeout': 60, 'traffic_type': "TX"})

        logger().info("\n\nInitiating ping traffic between 3rd party clients")
        for i in range(1, len(wifi_clients)):
            client1_ip = ip_dict[f'client1_ip']
            client2_ip = ip_dict[f'client{i + 1}_ip']
            logger().info(f"************** Pinging from '{client1_ip}' to '{client2_ip}' **************")
            con_obj.ping_from_wifi_client(wifi_client, client2_ip, ping_count=15)
            if not thread_started:
                logger().info("Initiating UDP-TX traffic from DUT")
                trf_thread.start()
                thread_started = True
        trf_thread.join()

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA3',
        'channel': 11,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148592",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148592",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_udp_rx_in_wpa3_when_remote_clients_conn_disconect_in_conc_mode_c148592(sl_collections, wifi_dut,
                                                                                         wifi_clients, wifi_sniffer,
                                                                                         wifi_access_point, protocol,
                                                                                         sniffer_filter, wifi_client,
                                                                                         net_perf_client):
    """
    Verify the STA WLAN UDP Rx Performance with WPA3 Security with 11n in Concurrent Mode when the 3rd party clietns
    are connecting and disconnecting to APUT
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148592"
        interface = wifi_client.interfaces.wifi.config['interface']
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148592", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")

        for client in wifi_clients:
            client.interfaces.wifi.config['interface'] = "wlan0"
        ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        time.sleep(5)

        logger().info("************ Initiating UDP-RX traffic from DUT ************")
        host_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        trf_thread = Thread(target=sl_collections.run_traffic,
                            kwargs={'wifi_dut': wifi_dut, 'net_perf_client': net_perf_client, 'protocol': protocol,
                                    'device_ip': device_ip, 'host_ip': host_ip, 'timeout': 120, 'traffic_type': "RX"})
        trf_thread.start()
        time.sleep(1)
        for i in range(1, 6):
            logger().info(f"********** Initiating 3rd party clients connect-disconnect for iteration:'{i}' **********")
            for client in wifi_clients:
                client.interfaces.wifi.leave()
            con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, ping_count=5, dut_ip=ip_dict['dut_ip'])
        trf_thread.join()
        logger().info("************ UDP data transfer is successful ************")

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            1) | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148593",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148593",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_ssl_rx_func_when_tcp_trf_btwn_clients_in_conc_mode_c148593(sl_collections, wifi_access_point,
                                                                             wifi_dut, wifi_clients, wifi_sniffer,
                                                                             sniffer_filter, protocol, net_perf_server,
                                                                             ssl_server, net_perf_client):
    """
    Verify the STA WLAN SSL Rx Performance with WPA2 Security with 11n in Concurrent mode when the TCP traffic running
    between the 3rd party clients associated to APUT
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148593"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148593", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)
        client_ip = ip_dict['client1_ip']
        server_ip = ip_dict['client2_ip']

        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")

        trf_thread = Thread(target=con_obj.run_traffic_btwn_two_clients,
                            args=(net_perf_server, net_perf_client, server_ip, client_ip, protocol, 80))
        trf_thread.start()
        time.sleep(8)
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip
        local_port = random.randint(5001, 20000)
        sock = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)

        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger().info(f"Remote peer sending data over socket 1 and data:{tx_buffer}")
            ssl_server.interfaces.ssl.send_data(1, 1, msg_length=100, message=tx_buffer)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=30)
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} " \
                                           "in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")
        trf_thread.join()

        logger().info(f"Closing socket_id->{sock}")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        ssl_server.interfaces.ssl.stop_server()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(1),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148594",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148594",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_ssl_tx_func_when_udp_trf_btwn_clients_in_conc_mode_c148594(sl_collections, wifi_access_point,
                                                                             wifi_dut, wifi_clients, wifi_sniffer,
                                                                             sniffer_filter, protocol, net_perf_server,
                                                                             ssl_server, net_perf_client):
    """
    Verify the STA WLAN SSL Tx Performance with WPA2 Security with 11n in Concurrent mode when the UDP traffic running
    between the 3rd party clients associated to APUT.
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148594"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148594", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)
        client_ip = ip_dict['client1_ip']
        server_ip = ip_dict['client2_ip']

        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")

        trf_thread = Thread(target=con_obj.run_traffic_btwn_two_clients,
                            args=(net_perf_server, net_perf_client, server_ip, client_ip, protocol, 80))
        trf_thread.start()
        time.sleep(8)
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip
        local_port = random.randint(5001, 20000)
        sock = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)

        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger().info(f"DUT is sending data over socket {sock} and data:{data}")
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
            time.sleep(1)
            data_receive = ssl_server.interfaces.ssl.data_recv_content(1, buffer_size=len(data))
            logger().info(f"Data received on remote SSL socket is -> {data_receive.decode()}")
            assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
            logger().info("Data sent by DUT and received on remote peer is matching")
        trf_thread.join()

        logger().info(f"Closing socket_id->{sock}")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        ssl_server.interfaces.ssl.stop_server()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD
                              | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148558",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148558",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
def test_wifi_sdk_ssl_tx_with_tls_v1_2_in_when_2_clients_connected_in_conc_mode_c148558(sl_collections, sniffer_filter,
                                                                                        wifi_access_point, wifi_sniffer,
                                                                                        wifi_clients, utf_constants,
                                                                                        ssl_server, wifi_dut):
    """
    SSL with TLS1.2 - two clients connected to SAP.
    """
    sock_opened = []
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148558"
        iter_count = max(utf_constants.get('iter_count'), 2)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        for iteration in range(1, iter_count + 1):
            logger().info(f"**************** Initiating test for iteration: '{iteration}' ****************")
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                         retry_count=3, associated=False)
            device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP BSSID : {ap_bssid}")
            if iteration == 1:
                sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148558", security="WPA2", psk="Automation@123",
                                                  channel=11, dtim_beacon_count="1", beacon_interval="100")
            logger().info("DUT as an AP is started")
            con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)

            con_discon_thread = Thread(target=con_obj.connect_disconnect_raspi_clients, args=(wifi_clients, wifi_dut))
            con_discon_thread.start()
            time.sleep(10)

            port1 = ssl_server.interfaces.ssl.config['device_port1']
            ssl_server.interfaces.ssl.start_server(port=port1)
            server_ip = ssl_server.interfaces.ssl.server_ip
            local_port = random.randint(5001, 20000)
            sock = wifi_dut.interfaces.wifi.socket()
            sock_opened.append(sock)
            logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)
            time.sleep(3)

            sw = Stopwatch()
            while sw.elapsed_sec <= 100:
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger().info(f"DUT is sending data over socket {sock} and data:{data}")
                wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
                time.sleep(1)
                data_receive = ssl_server.interfaces.ssl.data_recv_content(1, buffer_size=len(data))
                logger().info(f"Data received on remote SSL socket is -> {data_receive.decode()}")
                assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                logger().info("Data sent by DUT and received on remote peer is matching")
            con_discon_thread.join()

            for sock_id in sock_opened:
                logger().info(f"Closing socket_id->{sock_id}")
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            sock_opened.clear()
            ssl_server.interfaces.ssl.stop_server()
            logger().info("Disconnecting DUT from 3rd Party AP")
            wifi_dut.interfaces.wifi.leave()
            logger().info(f"************** Iteration '{iteration}' completed **************\n\n")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        for sock_id in sock_opened:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        sock_opened.clear()
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD
                              | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148560",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148560",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
def test_wifi_sdk_ssl_tx_with_tls_v1_0_in_when_two_clients_connected_in_conc_mode_c148560(switch, sl_collections,
                                                                                          wifi_sniffer, sniffer_filter,
                                                                                          wifi_clients, wifi_client,
                                                                                          wifi_access_point, wifi_dut,
                                                                                          utf_constants, openssl):
    """
    SSL with TLS1.0-rejoin -two clients connected to SAP.
    """
    sock_opened = []
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148560"
        iter_count = max(utf_constants.get('iter_count'), 2)
        interface = wifi_client.interfaces.wifi.config['interface']

        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        for iteration in range(1, iter_count + 1):
            logger().info(f"**************** Initiating test for iteration: '{iteration}' ****************")
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                         retry_count=3, associated=False)
            device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP BSSID : {ap_bssid}")
            if iteration == 1:
                sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148560", security="WPA2", psk="Automation@123",
                                                  channel=11, dtim_beacon_count="1", beacon_interval="100")
            logger().info("DUT as an AP is started")
            for client in wifi_clients:
                client.interfaces.wifi.config['interface'] = "wlan0"
            con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)

            con_discon_thread = Thread(target=con_obj.connect_disconnect_raspi_clients, args=(wifi_clients, wifi_dut))
            con_discon_thread.start()
            time.sleep(10)

            openssl.interfaces.server.start(port=5001, tls_version="-tls1")
            server_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
            local_port = randint(5001, 60000)

            sock = wifi_dut.interfaces.wifi.socket()
            sock_opened.append(sock)
            logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_0")
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=5001)
            time.sleep(3)

            data_sent = []
            sw = Stopwatch()
            while sw.elapsed_sec < 150:
                data = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
                data_sent.append(data)
                wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
                if int(sw.elapsed_sec) in range(15, 20):
                    logger().info("\n\nTurning off the AP")
                    switch.interfaces.pdu_switch.turn_off(delay=10)
                    # wifi_access_point.interfaces.wifi.stop_ap()
                    # time.sleep(10)
                    logger().info("Successfully powered off AP")

                    logger().info("\n\nAgain turning on the AP")
                    switch.interfaces.pdu_switch.turn_on(delay=80)
                    # wifi_access_point.interfaces.wifi.start_ap()
                    # time.sleep(80)
                    logger().info("Successfully powered on AP")
                    logger().info("Pinging to DUT to check rejoin process is completed or not")
                    status = sl_collections.ping(device_ip, 15, 5)
                    assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
            tx_data = "".join(data_sent)
            rx_data = openssl.interfaces.server.get_messages(timeout=100)[-1]
            logger().info(f"\n\n*************** Total data sent from DUT ***************\n{tx_data}")
            logger().info(f"\n\n*************** data received at remote peer *************** \n{rx_data}")
            assert tx_data == rx_data, "Data received doesn't match"
            con_discon_thread.join()

            for sock_id in sock_opened:
                logger().info(f"Closing socket_id->{sock_id}")
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            sock_opened.clear()
            openssl.interfaces.server.stop()
            logger().info("Disconnecting DUT from 3rd Party AP")
            wifi_dut.interfaces.wifi.leave()
            logger().info(f"************** Iteration '{iteration}' completed **************\n\n")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        for sock_id in sock_opened:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        sock_opened.clear()
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD
                              | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148561",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148561",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "TEST_C148561",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "TEST_C148561",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
def test_wifi_sdk_ssl_rx_with_tls_v1_2_in_when_4_clients_connected_in_conc_mode_c148561(sl_collections, sniffer_filter,
                                                                                        wifi_access_point, wifi_sniffer,
                                                                                        wifi_clients, utf_constants,
                                                                                        ssl_server, wifi_dut):
    """
    SSL with TLS-1.2 Rx data transfer-four clients connected to SAP
    """
    sock_opened = []
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148561"
        iter_count = max(utf_constants.get('iter_count'), 2)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        for iteration in range(1, iter_count + 1):
            logger().info(f"**************** Initiating test for iteration: '{iteration}' ****************")
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                         retry_count=3, associated=False)
            device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP BSSID : {ap_bssid}")
            if iteration == 1:
                sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148561", security="WPA2", psk="Automation@123",
                                                  channel=11, dtim_beacon_count="1", beacon_interval="100")
            logger().info("DUT as an AP is started")
            con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)

            con_discon_thread = Thread(target=con_obj.connect_disconnect_raspi_clients,
                                       args=(wifi_clients, wifi_dut, 2))
            con_discon_thread.start()
            time.sleep(10)

            port1 = ssl_server.interfaces.ssl.config['device_port1']
            ssl_server.interfaces.ssl.start_server(port=port1)
            server_ip = ssl_server.interfaces.ssl.server_ip
            local_port = random.randint(5001, 20000)

            sock = wifi_dut.interfaces.wifi.socket()
            sock_opened.append(sock)
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)
            time.sleep(3)

            buffer_length = 100
            sw = Stopwatch()
            while sw.elapsed_sec <= 60:
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
                logger().info(f"Sending data from remote peer, data --> '{tx_buffer}'")
                ssl_server.interfaces.ssl.send_data(sock + 1, 1, buffer_length, tx_buffer)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
                logger().info("Data sent by remote peer and received at DUT is matching")
                time.sleep(1)
            con_discon_thread.join()

            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            for sock_id in sock_opened:
                logger().info(f"Closing socket_id->{sock_id}")
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            sock_opened.clear()
            ssl_server.interfaces.ssl.stop_server()
            logger().info("Disconnecting DUT from 3rd Party AP")
            wifi_dut.interfaces.wifi.leave()
            logger().info(f"************** Iteration '{iteration}' completed **************\n\n")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        for sock_id in sock_opened:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        sock_opened.clear()
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD
                              | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148562",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148562",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
def test_wifi_sdk_ssl_tx_with_rejoin_when_2_clients_connected_in_conc_mode_c148562(switch, sl_collections, wifi_clients,
                                                                                   sniffer_filter, wifi_access_point,
                                                                                   wifi_sniffer, utf_constants,
                                                                                   ssl_server, wifi_dut):
    """
    SSL with TLS1.2-rejoin -two clients connected to SAP
    """
    sock_opened = []
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148562"
        iter_count = max(utf_constants.get('iter_count'), 2)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        for iteration in range(1, iter_count + 1):
            logger().info(f"**************** Initiating test for iteration: '{iteration}' ****************")
            result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0],
                                                                     power_save=False)
            dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP BSSID : {ap_bssid}")
            if iteration == 1:
                sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148562", security="WPA2", psk="Automation@123",
                                                  channel=11, dtim_beacon_count="1", beacon_interval="100")
            logger().info("DUT as an AP is started")
            con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)

            con_discon_thread = Thread(target=con_obj.connect_disconnect_raspi_clients, args=(wifi_clients, wifi_dut))
            con_discon_thread.start()
            time.sleep(10)

            port1 = ssl_server.interfaces.ssl.config['device_port1']
            ssl_server.interfaces.ssl.start_server(port=port1)
            server_ip = ssl_server.interfaces.ssl.server_ip

            local_port = random.randint(5001, 20000)
            sock = wifi_dut.interfaces.wifi.socket()
            sock_opened.append(sock)
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_sta_ip, server_port=local_port, timeout=15)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)

            sw = Stopwatch()
            while sw.elapsed_sec <= 150:
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger().info(f"DUT is sending data over socket {sock} and data:{data}")
                wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
                time.sleep(1)
                data_receive = ssl_server.interfaces.ssl.data_recv_content(1, buffer_size=len(data))
                logger().info(f"Data received on remote SSL socket is -> {data_receive.decode()}")
                assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                logger().info("Data sent by DUT and received on remote peer is matching")

                if int(sw.elapsed_sec) in range(15, 20):
                    logger().info("\n\nTurning off the AP")
                    switch.interfaces.pdu_switch.turn_off(delay=10)
                    # wifi_access_point.interfaces.wifi.stop_ap()
                    # time.sleep(10)
                    logger().info("Successfully powered off AP")

                    logger().info("\n\nAgain turning on the AP")
                    switch.interfaces.pdu_switch.turn_on(delay=80)
                    # wifi_access_point.interfaces.wifi.start_ap()
                    # time.sleep(80)
                    logger().info("Successfully powered on AP")
                    logger().info("Pinging to DUT to check rejoin process is completed or not")
                    status = sl_collections.ping(dut_sta_ip, 15, 5)
                    assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
            con_discon_thread.join()

            for sock_id in sock_opened:
                logger().info(f"Closing socket_id->{sock_id}")
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            sock_opened.clear()
            ssl_server.interfaces.ssl.stop_server()
            logger().info("Disconnecting DUT from 3rd Party AP")
            wifi_dut.interfaces.wifi.leave()
            logger().info(f"************** Iteration '{iteration}' completed **************\n\n")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        for sock_id in sock_opened:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        sock_opened.clear()
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD
                              | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},

    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148563",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148563",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
def test_wifi_sdk_https_post_func_when_2_clients_connected_in_conc_mode_c148563(sl_collections, sniffer_filter,
                                                                                wifi_access_point, wifi_sniffer,
                                                                                http_server, wifi_dut, index_path,
                                                                                wifi_clients, utf_constants):
    """
    HTTPS Post functionality with d/f port numbers- two clients connected to RSI_AP.
    """
    try:

        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148563"
        iter_count = max(utf_constants.get('iter_count'), 2)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        for iteration in range(1, iter_count + 1):
            logger().info(f"**************** Initiating test for iteration: '{iteration}' ****************")
            result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0],
                                                                     power_save=False)
            dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP BSSID : {ap_bssid}")
            if iteration == 1:
                sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148563", security="WPA2", psk="Automation@123",
                                                  channel=11, dtim_beacon_count="1", beacon_interval="100")
            logger().info("DUT as an AP is started")
            con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)

            con_discon_thread = Thread(target=con_obj.connect_disconnect_raspi_clients,
                                       args=(wifi_clients, wifi_dut, 2))
            con_discon_thread.start()
            time.sleep(15)
            wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
            if iteration == 1:
                wifi_dut.interfaces.wifi.http_client_init(https_enable=False)
            for i in range(5):
                logger().info("\n\n***Posting data using http post request***\n\n")
                post_data = ''.join(
                    random.choices(string.ascii_uppercase + string.digits, k=utf_constants.get('generate_bytes')))
                status_dut, content_dut = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, index_path,
                                                                             post_data=post_data)
                assert not status_dut, "failed to post http data"
                logger().info(f"HTTP Post Status:{status_dut}")
                time.sleep(5)
            con_discon_thread.join()
            logger().info("Disconnecting DUT from 3rd Party AP")
            wifi_dut.interfaces.wifi.leave()
            logger().info(f"************** Iteration '{iteration}' completed **************\n\n")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148579",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148579",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "TEST_C148579",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_mqtt_with_qos0_when_3_clients_connected_in_conc_mode_c148579(wifi_sniffer, mqtt_server, mqtt_client,
                                                                               wifi_access_point, sl_collections,
                                                                               wifi_dut, sniffer_filter,
                                                                               wifi_clients, utf_constants):
    """
    MQTT with QOS0-three clients connected to SAP.
    """
    con_discon_thread = None
    try:
        con_obj = ConcurrentMode()
        topic = "test_mqtt_topic"
        client_id = "Si91x_client579"
        capture_filename = "test_c148579"
        wifi_clients = wifi_clients[:3]
        messages = []
        for _ in range(5):
            messages.append(''.join(random.choices(string.ascii_uppercase, k=15)))

        iter_count = max(utf_constants.get('iter_count'), 2)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        for iteration in range(1, iter_count + 1):
            logger().info(f"**************** Initiating test for iteration: '{iteration}' ****************")
            result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0],
                                                                     power_save=False)
            dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP BSSID : {ap_bssid}")
            if iteration == 1:
                sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148579", security="WPA2", psk="Automation@123",
                                                  channel=11, dtim_beacon_count="1", beacon_interval="100")
            logger().info("DUT as an AP is started")
            con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)

            con_discon_thread = Thread(target=con_obj.connect_disconnect_raspi_clients, args=(wifi_clients, wifi_dut))
            con_discon_thread.start()
            time.sleep(15)

            wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id=client_id, qos=0)
            logger().info("DUT connects to MQTT server")
            wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            logger().info("MQTT Client connects to MQTT server")
            mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)

            logger().info("DUT subscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS0)
            logger().info("MQTT Client subscribes to the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS0)
            time.sleep(5)
            for message in messages:
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                mqtt_client.interfaces.mqtt.received_messages.clear()
                logger().info(f"DUT publishes message:'{message}' over the topic '{topic}'")
                wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS0,
                                                             timeout=30)
                time.sleep(5)
                msgs = []
                sw = Stopwatch()
                while sw.elapsed_sec < 10:
                    time.sleep(0.1)
                    msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                    if len(msgs) >= 1:
                        break
                assert len(msgs) >= 1, "No message is received by mqtt-client"
                assert msgs[-1].topic == topic, "No message received by mqtt-client on subscribed topic"
                assert msgs[-1].qos == Si91xMqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS1"
                assert msgs[
                           -1].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                            "message received is wrong"
                logger().info(f"Received MQTT message:'{msgs[0].payload.decode()}' and QOS:'{msgs[0].qos}'")
                logger().info("MQTT message validated successfully")
            logger().info("Unsubscribing from the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
            logger().info("Disconnecting from the mqtt server")
            wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
            mqtt_client.interfaces.mqtt.mqtt_client_close()
            con_discon_thread.join()
            logger().info("Disconnecting DUT from 3rd Party AP")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            wifi_dut.interfaces.wifi.leave()
            logger().info(f"************** Iteration '{iteration}' completed **************\n\n")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        if con_discon_thread.is_alive():
            con_discon_thread.join()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148580",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148580",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "TEST_C148580",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_mqtt_with_qos1_when_3_clients_connected_in_conc_mode_c148580(wifi_sniffer, mqtt_server, mqtt_client,
                                                                               wifi_access_point, sl_collections,
                                                                               wifi_dut, sniffer_filter,
                                                                               wifi_clients, utf_constants):
    """
    MQTT with QOS1-three clients connected to SAP
    """
    con_discon_thread = None
    try:
        con_obj = ConcurrentMode()
        topic = "test_mqtt_topic"
        client_id = "Si91x_mqtt_client"
        capture_filename = "test_c148580"
        wifi_clients = wifi_clients[:3]
        messages = []
        for _ in range(5):
            messages.append(''.join(random.choices(string.ascii_uppercase, k=15)))

        iter_count = max(utf_constants.get('iter_count'), 2)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        for iteration in range(1, iter_count + 1):
            logger().info(f"**************** Initiating test for iteration: '{iteration}' ****************")
            result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0],
                                                                     power_save=False)
            dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP BSSID : {ap_bssid}")
            if iteration == 1:
                sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148580", security="WPA2", psk="Automation@123",
                                                  channel=11, dtim_beacon_count="1", beacon_interval="100")
            logger().info("DUT as an AP is started")
            con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)

            con_discon_thread = Thread(target=con_obj.connect_disconnect_raspi_clients, args=(wifi_clients, wifi_dut))
            con_discon_thread.start()
            time.sleep(15)
            wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id=client_id, qos=1)
            logger().info("DUT connects to MQTT server")
            wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            logger().info("MQTT Client connects to MQTT server")
            mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)
            logger().info("DUT subscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
            logger().info("MQTT Client subscribes to the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
            time.sleep(5)
            for message in messages:
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                mqtt_client.interfaces.mqtt.received_messages.clear()
                logger().info(f"DUT publishes message:'{message}' over the topic '{topic}'")
                wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                             timeout=30)
                time.sleep(5)
                msgs = []
                sw = Stopwatch()
                while sw.elapsed_sec < 10:
                    time.sleep(0.1)
                    msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                    if len(msgs) >= 1:
                        break
                assert len(msgs) >= 1, "No message is received by mqtt-client"
                assert msgs[-1].topic == topic, "No message received by mqtt-client on subscribed topic"
                assert msgs[-1].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
                assert msgs[
                           -1].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                            "message received is wrong"
                logger().info(f"Received MQTT message:'{msgs[0].payload.decode()}' and QOS:'{msgs[0].qos}'")
                logger().info("MQTT message validated successfully")
            logger().info("Unsubscribing from the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
            logger().info("Disconnecting from the mqtt server")
            wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
            mqtt_client.interfaces.mqtt.mqtt_client_close()
            con_discon_thread.join()
            logger().info("Disconnecting DUT from 3rd Party AP")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            wifi_dut.interfaces.wifi.leave()
            logger().info(f"************** Iteration '{iteration}' completed **************\n\n")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        if con_discon_thread.is_alive():
            con_discon_thread.join()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148569",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148569",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "TEST_C148569",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "TEST_C148569",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_tcp_tx_when_4_clients_connected_in_conc_mode_c148569(sl_collections, sniffer_filter, wifi_sniffer,
                                                                       wifi_access_point, wifi_clients, utf_constants,
                                                                       remote_socket, wifi_dut):
    """
    TCP as a Client - Four client connect to APUT & TX data transfer.
    """
    sock_opened = []
    con_discon_thread = None
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148569"
        iter_count = max(utf_constants.get('iter_count'), 2)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        for iteration in range(1, iter_count + 1):
            logger().info(f"**************** Initiating test for iteration: '{iteration}' ****************")
            result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0],
                                                                     power_save=False)
            dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP BSSID : {ap_bssid}")
            if iteration == 1:
                sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148569", security="WPA2", psk="Automation@123",
                                                  channel=11, dtim_beacon_count="1", beacon_interval="100")
            logger().info("DUT as an AP is started")
            con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)

            con_discon_thread = Thread(target=con_obj.connect_disconnect_raspi_clients, args=(wifi_clients, wifi_dut))
            con_discon_thread.start()
            time.sleep(15)

            logger().info("Starting TCP server socket remotely")
            server_port = 5001
            local_port = randint(5001, 5100)
            remote_socket.interfaces.socket.stop()
            remote_socket.interfaces.socket.time_limit = 3000
            logger().info("Starting TCP Server socket at remote device")
            remote_socket.interfaces.socket.start_server(socket_type=SOCKET_TYPE_TCP, port=server_port)
            server_ip = remote_socket.interfaces.socket.server_ip
            time.sleep(2)
            sock = wifi_dut.interfaces.wifi.socket()
            sock_opened.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_sta_ip, server_port=local_port, timeout=15)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
            time.sleep(3)
            sw = Stopwatch()
            while sw.elapsed_sec <= 80:
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger().info(f"DUT is sending data over TCP socket_no 1 and data --> {data}")
                wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
                time.sleep(1)
                data = remote_socket.interfaces.socket.recv_data_tcp(len(data))
                logger().info(f"Total bytes received on remote TCP socket is -> {len(data)}")
                logger().info("Data sent by DUT and received on server is matching\n\n")

            remote_socket.interfaces.socket.stop()
            for sock_id in sock_opened:
                logger().info(f"Closing socket_id->{sock_id}")
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            sock_opened.clear()
            con_discon_thread.join()

            logger().info("Disconnecting DUT from 3rd Party AP")
            wifi_dut.interfaces.wifi.leave()
            logger().info(f"************** Iteration '{iteration}' completed **************\n\n")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        for sock_id in sock_opened:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        sock_opened.clear()
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        if con_discon_thread.is_alive():
            con_discon_thread.join()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148571",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148571",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "TEST_C148571",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "TEST_C148571",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_tcp_rx_when_4_clients_connected_in_conc_mode_c148571(sl_collections, sniffer_filter, wifi_sniffer,
                                                                       wifi_access_point, wifi_clients, utf_constants,
                                                                       remote_socket_factory, wifi_dut):
    """
    TCP as a client - RX data from all 4 clients to APUT.
    """
    sock_opened = []
    con_discon_thread = None
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148571"
        iter_count = max(utf_constants.get('iter_count'), 2)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        for iteration in range(1, iter_count + 1):
            logger().info(f"**************** Initiating test for iteration: '{iteration}' ****************")
            result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0],
                                                                     power_save=False)
            dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP BSSID : {ap_bssid}")
            if iteration == 1:
                sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148571", security="WPA2", psk="Automation@123",
                                                  channel=11, dtim_beacon_count="1", beacon_interval="100")
            logger().info("DUT as an AP is started")
            con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)

            con_discon_thread = Thread(target=con_obj.connect_disconnect_raspi_clients, args=(wifi_clients, wifi_dut))
            con_discon_thread.start()
            time.sleep(15)

            server_port = randint(5001, 5100)
            remote_socket_factory.interfaces.socket.close_all()
            remote_socket_factory.interfaces.socket.sockets = []
            sock = wifi_dut.interfaces.wifi.socket()
            sock_opened.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_sta_ip, server_port=server_port, timeout=15,
                                          asynch=0)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=0, asynch=0)
            time.sleep(3)
            client_socket = remote_socket_factory.interfaces.socket.create_socket()
            ThreadBase.call_functions_simultaneously([(client_socket.connect_client_tcp, dut_sta_ip, server_port),
                                                      (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 0)],
                                                     timeout=30)
            sw = Stopwatch()
            while sw.elapsed_sec <= 60:
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                tx_buffer = ''.join(random.choices(string.ascii_uppercase, k=100))
                logger().info(f"Remote peer is sending data over socket 1 and data:{tx_buffer}")
                trf_thread = Thread(target=client_socket.send_data_tcp, args=(tx_buffer,))
                trf_thread.start()
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock} opened in the DUT is not matched"
                logger().info("Data sent by remote peer and received on DUT is matching")
                trf_thread.join()
            for sock_id in sock_opened:
                logger().info(f"Closing socket_id->{sock_id}")
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            sock_opened.clear()
            remote_socket_factory.interfaces.socket.close_all()
            remote_socket_factory.interfaces.socket.sockets = []
            con_discon_thread.join()

            logger().info("Disconnecting DUT from 3rd Party AP")
            wifi_dut.interfaces.wifi.leave()
            logger().info(f"************** Iteration '{iteration}' completed **************\n\n")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        for sock_id in sock_opened:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        sock_opened.clear()
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        if con_discon_thread.is_alive():
            con_discon_thread.join()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.skip("Testcase is not stable --> Not announced")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                    | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(1),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148581",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148581",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end("wifi_dut", wifi=['clear_certs'])
def test_wifi_sdk_concurrent_mode_with_mqtt_connect_disconnect_for_30_times_c148581(wifi_sniffer, mqtt_server,
                                                                                    mqtt_client, wifi_access_point,
                                                                                    wifi_dut, sl_collections,
                                                                                    sniffer_filter, wifi_clients):
    """
    Check the Host MQTT Functionality of STAUT in concurrent Mode when APUT is associated to 3rd party clients and
    disconnecting and reconnection
    """
    try:
        topic = "test_topic_mqtt"
        capture_filename = "test_c148581"
        con_obj = ConcurrentMode()
        logger().info(f"Start sniffer capture on channel 11")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        time.sleep(3)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        dut_mac_address = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                              retry_count=3, associated=False)['dut_mac_address']
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148581", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")

        connected = False
        error_count = 0
        expected_error_count = 3

        for iter_count in range(30):
            iter_count = iter_count + 1
            try:
                message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
                logger().info(f"\n\n************* Initiating test for iteration:{iter_count} *************")
                con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)

                wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
                wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id=f"Si91x_mqtt_{iter_count}",
                                                                                connect_timeout=15, is_retained=False,
                                                                                keep_alive_interval=1200)
                logger().info("DUT connects to MQTT server")
                wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
                logger().info("MQTT Client connects to MQTT server")
                mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
                connected = True
                time.sleep(5)
                logger().info("DUT subscribes to the topic")
                wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS0)
                logger().info("DUT publishes message over the topic")
                time.sleep(3)
                logger().info("MQTT Client subscribes to the topic")
                mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS0)

                mqtt_client.interfaces.mqtt.received_messages.clear()
                wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS0,
                                                             timeout=30)
                msgs = []
                sw = Stopwatch()
                while sw.elapsed_sec < 10:
                    time.sleep(0.1)
                    msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                    if len(msgs):
                        break
                assert msgs[-1].topic == topic, "No message received by mqtt-client on subscribed topic"
                assert msgs[-1].qos == Si91xMqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS1"
                assert msgs[
                           -1].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                            "message received is wrong"
                logger().info(f"Received message:{message}, topic:{topic}, QOS:{Si91xMqttQos.QOS0}")
                logger().info("MQTT messages validated successfully\n\n")

                logger().info("Unsubscribing from the topic")
                wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)

                logger().info("Disconnecting from the mqtt server")
                wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
                mqtt_client.interfaces.mqtt.mqtt_client_close()
                connected = False

                for client in wifi_clients:
                    logger().info(f"Disconnecting RASPI-STA:'{client.name}' from DUT-AP")
                    client.interfaces.wifi.leave()
                time.sleep(10)
                logger().info(f"************* Iteration:{iter_count} Completed *************")
            except Exception as error:
                error_count += 1
                logger().warning(f"Error Observed in Iteration:{iter_count}\n\nError:{error}")
                if connected:
                    wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
                    mqtt_client.interfaces.mqtt.mqtt_client_close()

        assert error_count <= expected_error_count, f"Number of times connect-disconnect sequence failed is {error_count}, " \
                                                    f"which is greater than expected error count {expected_error_count}"
        logger().info(f"**************** Number of times failures observed in 30 iteration is '{error_count}', "
                      f"Which is less than expected failure count {expected_error_count}.Hence marking the testcase as "
                      f"PASS ****************\n")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.skip("http_put is not working --> Not announced")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD
                              | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148565",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148565",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
def test_wifi_sdk_http_put_func_when_2_clients_connected_in_conc_mode_c148565(sl_collections, sniffer_filter,
                                                                              wifi_access_point, wifi_sniffer,
                                                                              http_server, wifi_dut, index_path,
                                                                              wifi_clients, utf_constants):
    """
    HTTP Put functionality with exact data buffer size - two clients connected to RSI_AP.
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148566"
        iter_count = max(utf_constants.get('iter_count'), 1)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        for iteration in range(1, iter_count + 1):
            logger().info(f"**************** Initiating test for iteration: '{iteration}' ****************")
            result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0],
                                                                     power_save=False)
            dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP BSSID : {ap_bssid}")
            if iteration == 1:
                sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148565", security="WPA2", psk="Automation@123",
                                                  channel=11, dtim_beacon_count="1", beacon_interval="100")
            logger().info("DUT as an AP is started")
            con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)

            con_discon_thread = Thread(target=con_obj.connect_disconnect_raspi_clients,
                                       args=(wifi_clients, wifi_dut, 2))
            con_discon_thread.start()
            time.sleep(15)
            wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
            if iteration == 1:
                wifi_dut.interfaces.wifi.http_client_init(https_enable=False)
                logger().info("\n\n***Put data using http put request***\n\n")
                status_dut, content_dut = wifi_dut.interfaces.http.http_put(http_server.interfaces.http, index_path,
                                                                            put_data_length=10)
                assert not status_dut, "failed to put http data"
                logger().info(f"HTTP Put Status:{status_dut}")
                time.sleep(5)
            con_discon_thread.join()
            logger().info("Disconnecting DUT from 3rd Party AP")
            wifi_dut.interfaces.wifi.leave()
            logger().info(f"************** Iteration '{iteration}' completed **************\n\n")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
