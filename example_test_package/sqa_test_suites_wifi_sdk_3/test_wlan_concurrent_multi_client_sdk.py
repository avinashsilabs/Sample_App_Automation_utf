import time
import string
import random
from utf.utils.stopwatch import Stopwatch
import pytest as pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xMqttQos
from utf.utils.iperf.iperf_utils import print_dict
from retry import retry

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
    @staticmethod
    def connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, count=3, ping_count=10):
        ip_dict = {}
        connected = False
        for i in range(len(wifi_clients)):
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            ip_dict['dut_ip'] = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {ip_dict['dut_ip']}")
            for count in range(count):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{wifi_clients[i].name}' to DUT")
                    ip_dict[f'client_ip{i + 1}'] = wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client_ip{i + 1}: {ip_dict[f'client_ip{i + 1}']}")
                    rc, stdout, stderr = wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {ip_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout}\n")
                    connected = True
                    break
                except Exception as error:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT:\n{error}...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        return ip_dict

    @staticmethod
    def print_throughput(iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run_traffic_btwn_two_clients(self, net_perf_client1, net_perf_client2, server_ip, client_ip, protocol,
                                     iperf_time=30):
        logger().info("***** preparing wifi_client1 as iperf_server *****")
        net_perf_client1.interfaces.net_perf.init_server(host_ip=server_ip, device_ip=client_ip, protocol=protocol,
                                                         time_out=iperf_time)
        logger().info(f"***** preparing wifi_client2 as iperf_client *****")
        net_perf_client2.interfaces.net_perf.init_client(host_ip=server_ip, device_ip=client_ip, protocol=protocol,
                                                         time_out=iperf_time)
        time.sleep(3)
        logger().info("***** start iperf on wifi_client1 --> server *****")
        net_perf_client1.interfaces.net_perf.start()
        time.sleep(10)
        logger().info("***** start iperf on wifi_client2 --> client *****")
        net_perf_client2.interfaces.net_perf.start()

        logger().info("***** Adding 5 sec sleep before printing throughput *****")
        time.sleep(15)
        logger().info("***** get and print throughput *****")
        tp = net_perf_client1.interfaces.net_perf.process_output()
        assert tp is not None, 'Unable to retrieve the Throughput information'
        self.print_throughput(tp)

    @staticmethod
    @retry(Exception, delay=15, tries=3)
    def ping_from_wifi_client(wifi_client, dut_ip, ping_count=10):
        logger().info(f"Initiating wlan ping from client '{wifi_client.name}' to DUT")
        for count in range(3):
            try:
                rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ping -c {ping_count} {dut_ip}")
                assert rc == 0
                logger().info(f"\n{stdout}\n")
                return rc == 0
            except:
                time.sleep(10)


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
                                                                    utf_constants, sniffer_filter, http_client):
    """ HTTPS Get functionality-two clients connected to RSI_AP """
    try:
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

# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": Si91xOperatingMode.ConcurrentMode,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.Default,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
#         "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
#     }
# )
# @pytest.mark.config(
#     'wifi_access_point',
#     wifi={
#         'security': 'WPA2',
#         'channel': 11,
#     }
# )
# @pytest.mark.config(
#     "wifi_clients",
#     wifi={
#         0: {
#             "security": "WPA2",
#             "ssid": "TEST_C148585",
#             "passphrase": "Automation@123",
#             "channel": 11,
#             "interface": "wlan0",
#         },
#         1: {
#             "security": "WPA2",
#             "ssid": "TEST_C148585",
#             "passphrase": "Automation@123",
#             "channel": 11,
#             "interface": "wlan0",
#         },
#     }
# )
# def test_connect_disconnect_sta_module_of_dut_c148585(sl_collections, wifi_access_point, wifi_dut, wifi_clients,
#                                                       wifi_sniffer, utf_constants, sniffer_filter):
#     """
#     Checking the wifi connection stability of 3rd party clients associated to APUT in concurrent Mode when STAUT is
#     doing disconnecting and reconnecting to the Configured AP Long hours Iterations
#     """
#     try:
#         con_obj = ConcurrentMode()
#         capture_filename = "test_148585"
#         logger().info("********** configuring the sniffer with access point channel **********")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=11)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#
#         sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
#                                                   static_gateway="192.168.100.76")
#         wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148585", security="WPA2", psk="Automation@123", channel=11,
#                                           dtim_beacon_count="1", beacon_interval="100")
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger().info(f"AP BSSID : {ap_bssid}")
#
#         ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)
#         dut_ip = ip_dict['dut_ip']
#         client1_ip = ip_dict['client_ip1']
#         client2_ip = ip_dict['client_ip2']
#
#         sw = Stopwatch()
#         test_run_time = 1800
#         while sw.elapsed_sec <= test_run_time:
#             time_left = int((test_run_time - sw.elapsed_sec) / 60)
#             logger().info(f"Remaining time to complete test is '{time_left}' minutes")
#             dut_mac_address = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
#                                                                   retry_count=6, associated=False)['dut_mac_address']
#             wifi_dut.interfaces.wifi.leave()
#             logger().info(f"********* Dut IP **********: {dut_ip}")
#             logger().info(f"********* Raspi STA1 IP **********: {client1_ip}")
#             logger().info(f"********* Raspi STA2 IP **********: {client2_ip}")
#             logger().info("Checking connection stability by pinging from RASPI to DUT as AP")
#             status = con_obj.ping_from_wifi_client(wifi_clients[0], dut_ip)
#             assert status, f"RASPI-STA1 failed to ping to DUT as AP"
#             status = con_obj.ping_from_wifi_client(wifi_clients[1], dut_ip)
#             assert status, f"RASPI-STA2 failed to ping to DUT as AP"
#
#         logger().info("Stopping sniffer capture")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
#                                                sniffer_filter, power_save=False)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#     finally:
#         wifi_dut.interfaces.wifi.stop_ap()
