import random
import string
import time
import pytest
from random import randint
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xAwsQos,
    DefaultCipher,
    DeviceConstants,
    SocketOptions,
    Cipher,
    Si91xModuleType,
    Si91xCertificateType,
    Si91xCertIdentifier
)

"""
The testcases added in this file run below test steps for DUT-Si91x
        1. Configuration of DUT in 2G/5G : BGN
        2. Load ssl certificates in the DUT
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Create a new TCP/IP socket over ssl 
        6. Bind the socket with DUT ip address
        7. Connect the client with server socket as specified port number.
        8. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
        9. Analyze the cipher list sent in the tls-client-hello ssl packet and compare with the cipher list selected in
        the dut
    setup requirement:
        1. DUT(Si91x)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC Wifi Sniffer
"""


def logger():
    return get_logger(__name__)


class ssl_connection:
    """
    Class to configure SSL and Rejoin parameters in DUT along with WLAN and SSL Socket Connection.
    """

    def __init__(self, wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, request, sl_collections,
                 cipher_list, mode=0, sniffer_filter=None, wifi_client=None, server_cert=None, server_key=None,
                 test_run_time=60):
        self.mode = mode
        self.wifi_dut = wifi_dut
        self.ssl_server = ssl_server
        self.cipher_list = cipher_list
        self.wifi_sniffer = wifi_sniffer
        self.test_run_time = test_run_time
        self.sl_collections = sl_collections
        self.capture_filename = request.node.name
        self.wifi_access_point = wifi_access_point
        self.sniffer_filter = sniffer_filter
        self.wifi_client = wifi_client
        self.server_cert = server_cert
        self.server_key = server_key

    def join_get_ip(self, sniff_capture=True):
        if sniff_capture:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        result = self.sl_collections.join_to_wifi_network_with_rejoin(self.wifi_dut, self.wifi_access_point,
                                                                      [0, 6, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        return dut_ip, dut_mac_address

    def ssl_connection_tx_rx(self, wlan=False):
        expected_cipher = DefaultCipher.cipher_list
        if len(self.cipher_list):
            cipher = self.select_cipher_list(self.cipher_list)
            self.wifi_dut.interfaces.wifi.set_ssl_cipher(cipher_list=cipher)
            expected_cipher = self.cipher_list
        device_ip, dut_mac = self.join_get_ip()
        ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")

        count = 1
        sw = Stopwatch()
        while sw.elapsed_sec <= self.test_run_time:
            logger().info(f"********************** Initiating test for iteration: '{count}' **********************")
            server_port = randint(5001, 5100)
            local_port = randint(5001, 60000)
            self.ssl_server.interfaces.ssl.start_server(port=server_port)
            server_ip = self.ssl_server.interfaces.ssl.server_ip
            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            sock = self.wifi_dut.interfaces.wifi.socket()
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            self.wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
            self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                               timeout=15, asynch=0)
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
            time.sleep(3)

            timer = Stopwatch()
            while timer.elapsed_sec <= 30:
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                tx_buffer = "".join(random.choices(string.ascii_uppercase, k=100))
                if self.mode == 1:
                    # if mode is set to 1, socket open, rx over the socket test will be initiated
                    logger().info(f"Remote peer sending data over socket 1 and data:{tx_buffer}")
                    self.ssl_server.interfaces.ssl.send_data(1, 1, msg_length=100, message=tx_buffer)
                    self.wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                    buffer_rx = self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=30)
                    assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} " \
                                                   "in the DUT is not matched"
                    logger().info("Data sent by remote peer and received on DUT is matching")
                else:
                    # if mode is set to 1, socket open, tx over the socket test will be initiated
                    logger().info(f"DUT is sending data over socket {sock} and data:{tx_buffer}")
                    self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=tx_buffer)
                    time.sleep(1)
                    data_receive = self.ssl_server.interfaces.ssl.data_recv_content(1, buffer_size=len(tx_buffer))
                    logger().info(f"Data received on remote SSL socket is -> {data_receive.decode()}")
                    assert tx_buffer == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                    logger().info("Data sent by DUT and received on remote peer is matching")

            logger().info(f"Closing socket_id->{sock}")
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            self.ssl_server.interfaces.ssl.stop_server()
            if wlan:
                logger().info("Disconnecting from 3rd party AP")
                self.wifi_dut.interfaces.wifi.leave()
                device_ip, dut_mac = self.join_get_ip(sniff_capture=False)
            logger().info(f"********************** Iteration '{count}' Completed **********************\n\n")
            count += 1


        logger().info("Stop Sniffer finally")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer, dut_mac,
                                                    ap_bssid, self.sniffer_filter)
        decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION_KEY --> {decryption_key}")
        logger().info("SSL Packet Decryption is going to start, This may take some time")
        cipher_suite = self.sl_collections.ssl_packet_decryption(self.wifi_sniffer, decryption_key, dut_mac, ["tls"],
                                                                 self.capture_filename, ap_bssid, self.mode,
                                                                 get_cipher=True)['cipher']
        if not len(cipher_suite):
            logger().info(
                f"tls client hello packet is not captured or one of the wifi 4-way handshake pkt is not captured")
        assert len(cipher_suite) > 0, (f"tls client hello packet is not captured or one of the wifi 4-way handshake "
                                       f"packet is not captured")
        logger().info(f"'{len(cipher_suite)}' times tls client hello message captured on sniffer log")
        cipher_suite_cmp = None
        for cipher in cipher_suite:
            cipher_suite_cmp = cipher[1]
            assert cipher_suite_cmp == expected_cipher, (f"Cipher Suite Mismatched, Expected is '{expected_cipher}'\n"
                                                         f"But Observed '{cipher_suite_cmp}'")
        logger().info(f"****** As per sniffer capture cipher suite advertised by device {dut_mac} --> "
                      f"{cipher_suite_cmp} *******")

    @staticmethod
    def select_cipher_list(cipher_list):
        cipher = 0
        for cipher_name in cipher_list:
            for cipher_mem in Cipher:
                if cipher_name in str(cipher_mem):
                    cipher = cipher | cipher_mem.value
        return cipher


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                              | Si91xTCPIPFeatureBitMap.Ping,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                                   | Si91xExtCustomFeatureBitMap.IEEE802_11W,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                                  | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD
                                  | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                               | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
            "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
        }
    ),
    pytest.mark.config('wifi_access_point', wifi={'channel': 3})
]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "set_default_ssl_cipher", "set_default_extended_ssl_cipher"])
@pytest.mark.parametrize("cipher_list", [[]])
def test_advertise_all_ciphers_ssl_tx_regression_c19618(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
                                                        cipher_list, request, utf_constants, sniffer_filter,
                                                        sl_collections):
    try:
        test_run_time = max(utf_constants.get('time_duration'), 100)
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, request, sl_collections,
                                 cipher_list, sniffer_filter=sniffer_filter, mode=0, test_run_time=test_run_time)
        ssl_obj.ssl_connection_tx_rx()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "set_default_ssl_cipher", "set_default_extended_ssl_cipher"])
@pytest.mark.parametrize("cipher_list", [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_specific_ciphers_ssl_tx_regression_c19620(wifi_sniffer, wifi_access_point, wifi_dut,
                                                             ssl_server, cipher_list, request, utf_constants,
                                                             sniffer_filter, sl_collections):
    try:
        test_run_time = max(utf_constants.get('time_duration'), 100)
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, request, sl_collections,
                                 cipher_list, sniffer_filter=sniffer_filter, mode=0, test_run_time=test_run_time)
        ssl_obj.ssl_connection_tx_rx()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.check
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [[]])
def test_advertise_all_ciphers_wlan_ssl_rx_regression_c19619(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
                                                             cipher_list, request, utf_constants, sl_collections,
                                                             sniffer_filter):
    try:
        test_run_time = max(utf_constants.get('time_duration'), 100)
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, request, sl_collections,
                                 cipher_list, sniffer_filter=sniffer_filter, mode=1, test_run_time=test_run_time)
        ssl_obj.ssl_connection_tx_rx(wlan=True)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.check
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_specific_ciphers_wlan_ssl_rx_regression_c19621(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
                                                                  cipher_list, request, utf_constants, sl_collections,
                                                                  sniffer_filter):
    try:
        test_run_time = max(utf_constants.get('time_duration'), 100)
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, request, sl_collections,
                                 cipher_list, sniffer_filter=sniffer_filter, mode=1, test_run_time=test_run_time)
        ssl_obj.ssl_connection_tx_rx(wlan=True)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.firmware_app("load_ta_and_m4")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=[ "close_sockets", "disassociated"]
)

def test_wifi_sdk_verify_ssl_connect_disconnect_for_30_min_c725813(firmware_loader, wifi_dut, wifi_access_point, wifi_sniffer, ssl_server, sl_collections, request, sniffer_filter):
    """
        Test case to verify SSL connect and disconnect functionality for 30 minutes.

        Steps:
        1. Configure the Wi-Fi sniffer to capture packets on the same channel as the access point.
        2. Start packet capture and name the capture file based on the test request.
        3. Join the DUT (Device Under Test) to the Wi-Fi network and enable power save mode.
        4. Retrieve the DUT's MAC address and IP address after joining the network.
        5. Run a loop for 30 minutes to:
           a. Start the SSL server on a specified port.
           b. Create a socket on the DUT and configure it for TLS 1.2.
           c. Bind the socket to the DUT's IP address and a random local port.
           d. Connect the DUT's socket to the SSL server.
           e. Wait for 5 seconds to simulate data exchange or connection stability.
           f. Close the socket on the DUT and stop the SSL server.
        6. Ensure all operations complete without errors.

        Parameters:
        - firmware_loader: Fixture to load the firmware on the DUT.
        - wifi_dut: The Wi-Fi Device Under Test (DUT).
        - wifi_access_point: The Wi-Fi access point used for the test.
        - wifi_sniffer: The Wi-Fi sniffer used to capture packets.
        - ssl_server: The SSL server used for the test.
        - sl_collections: Collection of utility functions for Wi-Fi operations.
        - request: Pytest request object for test metadata.
        - sniffer_filter: Filter configuration for the Wi-Fi sniffer.

        Assertions:
        - Ensures the socket is successfully created on the DUT.
        - Verifies that the SSL connection is established and closed without errors.
        """
    wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(request.node.name)

    dut_dict = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, associated=wifi_dut.interfaces.wifi.associated, power_save=True)
    device_ip = dut_dict['device_ip']

    sw = Stopwatch()
    while sw.elapsed_sec < 1800:
        port = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port)
        server_ip = ssl_server.interfaces.ssl.server_ip
        logger().info(f"The Server IP Address is {server_ip}")

        socket_id = wifi_dut.interfaces.wifi.socket()
        assert socket_id > -1, "Couldn't open Socket on DUT"

        wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_id, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bind(socket_fd=socket_id, device_ip=device_ip, server_port=randint(5000, 20000), timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=socket_id, server_ip=server_ip, server_port=port)
        time.sleep(5)
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        ssl_server.interfaces.ssl.stop_server()
