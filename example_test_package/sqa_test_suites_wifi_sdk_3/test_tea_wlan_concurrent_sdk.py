import re
import threading
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
from threading import Thread
from random import randint
from utf.interfaces.socket import SOCKET_TYPE_TCP

lock = threading.Lock()

"""
    setup requirement:
        1. DUT(Si917SOC)
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
    def tcp_data_transfer(wifi_dut, remote_socket, sock=0, duration=80, traffic="TX", sleep_time=1):
        sw = Stopwatch()
        while sw.elapsed_sec <= duration:
            tx_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
            if not lock.locked():
                with lock:
                    if traffic.upper() == 'TX':
                        wifi_dut.interfaces.wifi.bsdSocketSend(sock, tx_data)
                        time.sleep(1)
                        rx_data = remote_socket.interfaces.socket.recv_data_tcp(len(tx_data))
                        logger().info(f"Data received at remote TCP socket is -> {rx_data}")
                        assert tx_data == rx_data, "Data sent by DUT and received at server is not matching"
                        logger().info("Data sent by DUT and received on server is matching\n")
                    else:
                        logger().info(f"Remote peer sending data --> {tx_data}")
                        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                        remote_socket.interfaces.socket.send_data_tcp(tx_data, True)
                        time.sleep(1)
                        rx_data = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=60)
                        assert tx_data == rx_data, (f"buffer length sent by remote peer and received on the "
                                                    f"socket id {sock} opened in the DUT is not matched")
                        logger().info("Data sent by remote peer and received at DUT is matching\n")
            time.sleep(sleep_time)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT |
                              Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
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
            "ssid": "TEST_C122789",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C122789",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_sta_mqtt_tx_and_ap_tcp_tx_in_conc_mode_c122789(wifi_sniffer, mqtt_server, mqtt_client, wifi_clients,
                                                                 wifi_access_point, sl_collections, sniffer_filter,
                                                                 wifi_dut, remote_socket):
    """
    Verify MQTT Tx in STA Mode and TCP_Tx data transfer in AP Mode-Concurrent scenario
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        topic = "mqtt_topic"
        capture_filename = "test_c148789"
        messages = []
        for _ in range(5):
            messages.append(''.join(random.choices(string.ascii_uppercase, k=15)))

        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0],
                                                                 power_save=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C122789", security="WPA2", psk="Automation@123",
                                          channel=11, dtim_beacon_count="1", beacon_interval="100")
        logger().info("DUT as an AP is started")
        dut_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)['dut_ip']

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt, timeout=30)
        time.sleep(20)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=0)
        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=0)
        time.sleep(3)

        logger().info("Starting TCP server socket remotely")
        server_port = randint(5001, 5100)
        local_port = randint(5001, 60000)
        remote_socket.interfaces.socket.stop()
        logger().info("Starting TCP Server socket at remote device")
        remote_socket.interfaces.socket.interface = "wlan0"
        remote_socket.interfaces.socket.start_server(socket_type=SOCKET_TYPE_TCP, port=server_port)
        server_ip = remote_socket.interfaces.socket.server_ip
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_ap_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)

        remote_socket.interfaces.socket.set_recv_timeout(timeout=120)
        trf_thread = Thread(target=con_obj.tcp_data_transfer, args=(wifi_dut, remote_socket, sock))
        trf_thread.start()
        for message in messages:
            mqtt_client.interfaces.mqtt.received_messages.clear()
            logger().info(f"DUT publishes message:'{message}' over the topic '{topic}'")
            sw = Stopwatch()
            while sw.elapsed_sec < 60:
                if not lock.locked():
                    with lock:
                        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message,
                                                                     qos=Si91xMqttQos.QOS0, timeout=60)
                    break
            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 20:
                time.sleep(1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) >= 1:
                    break
            assert len(msgs) >= 1, "No message is received by mqtt-client"
            assert msgs[-1].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[-1].qos == Si91xMqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS1"
            assert msgs[-1].payload.decode() == message, ("No message is received by mqtt-client on subscribed "
                                                          "topic or message received is wrong")
            logger().info(f"Received MQTT message:'{message}' and QOS:'{msgs[0].qos}'")
            logger().info("MQTT message validated successfully")
        trf_thread.join()

        logger().info("Unsubscribing from the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        logger().info("Disconnecting from the mqtt server")
        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
        mqtt_client.interfaces.mqtt.mqtt_client_close()
        remote_socket.interfaces.socket.stop()
        logger().info(f"Closing socket_id->{sock}")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)

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
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT |
                              Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
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
            "ssid": "TEST_C122801",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C122801",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_sta_mqtt_tx_with_rejoin_and_ap_tcp_tx_in_conc_mode_c122801(wifi_access_point, wifi_dut, remote_socket,
                                                                             wifi_clients, sl_collections, mqtt_client,
                                                                             mqtt_server, wifi_sniffer, sniffer_filter,
                                                                             switch):
    """
    Verify MQTT Reconnection with Rx data transfer in Concurrent Mode
    """
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        topic = "mqtt_topic"
        capture_filename = "test_c122801"
        messages = []
        for _ in range(10):
            messages.append(''.join(random.choices(string.ascii_uppercase, k=15)))
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0],
                                                                 power_save=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C122801", security="WPA2", psk="Automation@123",
                                          channel=11, dtim_beacon_count="1", beacon_interval="100")
        logger().info("DUT as an AP is started")
        dut_ap_ip = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, dut_ip=con_obj.dut_ap_ip)['dut_ip']

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt, timeout=30)
        time.sleep(20)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=0)
        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=0)
        time.sleep(3)
        server_port = random.randint(5001, 5020)
        local_port = random.randint(40001, 60000)
        remote_socket.interfaces.socket.interface = "wlan0"
        remote_socket.interfaces.socket.time_limit = 600
        remote_socket.interfaces.socket.start_server(port=server_port)
        server_ip = remote_socket.interfaces.socket.server_ip
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_ap_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)

        trf_thread = Thread(target=con_obj.tcp_data_transfer, args=(wifi_dut, remote_socket, sock, 275, 'RX', 2))
        trf_thread.start()
        ap_power_off = 0
        for count, message in enumerate(messages):
            if count == 5: ap_power_off = 1
            if ap_power_off:
                with lock:
                    logger().info("Turning off the AP")
                    switch.interfaces.pdu_switch.turn_off(delay=20)
                    # wifi_access_point.interfaces.wifi.stop_ap()
                    # time.sleep(20)
                    logger().info("Successfully powered off AP")

                    logger().info("Again turning on the AP")
                    switch.interfaces.pdu_switch.turn_on(delay=20)
                    # wifi_access_point.interfaces.wifi.start_ap()
                time.sleep(60)
                ap_power_off = 0
                logger().info("Successfully powered on AP")
                logger().info("Pinging to DUT to check rejoin process is completed or not")
                status = sl_collections.ping(dut_sta_ip, 20, 5)
                assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
            mqtt_client.interfaces.mqtt.received_messages.clear()
            logger().info(f"DUT publishes message:'{message}' over the topic '{topic}'")
            sw = Stopwatch()
            while sw.elapsed_sec < 60:
                if not lock.locked():
                    with lock:
                        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message,
                                                                     qos=Si91xMqttQos.QOS0, timeout=60)
                    break
            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 20:
                time.sleep(1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) >= 1:
                    break
            assert len(msgs) >= 1, "No message is received by mqtt-client"
            assert msgs[-1].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[-1].qos == Si91xMqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS1"
            assert msgs[-1].payload.decode() == message, ("No message is received by mqtt-client on subscribed "
                                                          "topic or message received is wrong")
            logger().info(f"Received MQTT message:'{message}' and QOS:'{msgs[0].qos}'")
            logger().info("MQTT message validated successfully")
            time.sleep(1)
        trf_thread.join()

        logger().info("Unsubscribing from the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        logger().info("Disconnecting from the mqtt server")
        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
        mqtt_client.interfaces.mqtt.mqtt_client_close()
        remote_socket.interfaces.socket.stop()
        logger().info(f"Closing socket_id->{sock}")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
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
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_socket_func_when_network_is_not_stable_c37577(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                    logger, sl_collections, sniffer_filter):
    """
    SSL Socket Functionality when the User Turn OFF/ON the Network.
    """
    try:
        ap_wan_interface = wifi_access_point.interfaces.wifi.config.get('wan_interface')
        assert ap_wan_interface, "Please mention wan_interface in ap section of harness file"
        domain_name = "a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"
        capture_filename = "test_wifi_sdk_ssl_socket_func_c37577"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [20, 6, 40, 0],
                                                                 power_save=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        shell = wifi_access_point.interfaces.wifi._create_shell()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        time.sleep(10)

        socks = []
        error_code = 0
        server_port = 8883
        for count in range(2):
            local_port = random.randint(40001, 60000)
            server_ip = wifi_dut.interfaces.wifi.dns_get(domain_name, query_timeout=120000, timeout=60).strip().decode()
            logger.info(f"aws_server_ip --> {server_ip}")
            sock = wifi_dut.interfaces.wifi.socket()
            socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            if count == 1:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
                logger.info("Successfully connected to aws server")
            else:
                logger.info("**************** Turning off AP's internet ****************")
                shell.execute(f'ifconfig {ap_wan_interface} down', wifi_access_point.interfaces.wifi.prompt)
                time.sleep(5)
                try:
                    wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                              server_port=server_port, timeout=30)
                except Exception as err:
                    error_match = re.search("status:(.*)", str(err))
                    if error_match: error_code = error_match.group()
                    logger.info(f"error_code: {error_code}")
                assert error_code, ("DUT did not send error code when trying to connect aws server when internet is "
                                    "turned off, which is not expected")
                logger.info("DUT sent error code when trying to connect aws server when internet is turned off,"
                            " which is expected as per the test step\n")
                logger.info("**************** Turning on AP's internet again ****************")
                shell.execute(f'ifconfig {ap_wan_interface} up', wifi_access_point.interfaces.wifi.prompt)
                time.sleep(30)
        for sock_id in socks:
            logger.info(f"Closing socket_id --> {sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

