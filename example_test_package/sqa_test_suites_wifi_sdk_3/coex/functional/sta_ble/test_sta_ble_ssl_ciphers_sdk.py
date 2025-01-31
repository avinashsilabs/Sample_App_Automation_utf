import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xCertificateType,
    Si91xCertIdentifier,
    DefaultCipher,
    Cipher,
)
from utf.utils import get_tls_certificate_dir
from utf.utils.stopwatch import Stopwatch
import random
import string
from utf.utils.logger import get_logger
from random import randint
from test_sta_ble_sdk import BleThreadFunctionality, SnifferValidationProcess, ScanTime_JoinTime, WifiJoinThread
from test_sta_ble_multi_raspi_sdk import BleDualRoleThreadFunctionality



def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point -dlink (Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point(tkip) and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. set Region ,scan ,connect, data transfer
        6. BLE slave/master connection
        7. BLE scan
        8. BLE Advertise

    Author: Swathi.Chinthala

"""



class wifi_ssl_connection:
    """
    Class to configure SSL and Rejoin parameters in DUT along with WLAN and SSL Socket Connection.
    """

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, wifi_dut=None, ssl_server=None, request=None,
                 sl_collections=None, cipher_list=None, mode="TX", sniffer_filter=None, wifi_client=None,
                 server_cert=None, server_key=None,
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
        self.device_ip, self.dut_mac_address, self.ap_bssid, expected_cipher = None, None, None, None

    def join_get_ip(self):

        result = self.sl_collections.join_to_wifi_network_with_rejoin(self.wifi_dut, self.wifi_access_point,
                                                                      [0, 6, 40, 0])
        self.device_ip, self.dut_mac_address = result['device_ip'], result['dut_mac_address']
        self.ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {self.ap_bssid}")

    def set_cipher(self, ca_cert=None):

        if ca_cert is not None:
            self.wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath(ca_cert)),
                                                              Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                              Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START,
                                                              cert_index=0)
        self.expected_cipher = DefaultCipher.cipher_list
        if len(self.cipher_list):
            cipher = self.select_cipher_list(self.cipher_list)
            self.wifi_dut.interfaces.wifi.set_ssl_cipher(cipher_list=cipher)
            self.expected_cipher = self.cipher_list

    def ssl_connection_tx_rx(self):

        self.join_get_ip()
        server_port = randint(5001, 5100)
        local_port = randint(5001, 60000)
        if "openssl" in self.ssl_server.name.lower():
            server_port = 5001
            self.ssl_server.interfaces.server.start(port=server_port, tls_version="-tls1_2")
            server_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        else:
            if self.server_cert is None:
                self.ssl_server.interfaces.ssl.start_server(port=server_port)
            else:
                self.ssl_server.interfaces.ssl.start_server(port=server_port, server_cert=self.server_cert,
                                                            server_key=self.server_key)
            server_ip = self.ssl_server.interfaces.ssl.server_ip

        sock = self.wifi_dut.interfaces.wifi.socket()
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        self.wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
        self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.device_ip, server_port=local_port,
                                           timeout=15, asynch=0)
        self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)

        if self.mode == "RX":
            # if mode is set to 1, socket open, rx over the socket test will be initiated
            sw = Stopwatch()
            while sw.elapsed_sec <= self.test_run_time:
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                tx_buffer = "".join(random.choices(string.ascii_uppercase, k=100))
                logger().info(f"Remote peer sending data over socket 1 and data:{tx_buffer}")
                if "openssl" in self.ssl_server.name.lower():
                    self.ssl_server.interfaces.server.subprocess.send_input(tx_buffer, line_feed=False)
                    time.sleep(5)
                    rx_buffer = self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(sock, timeout=30)
                    assert len(tx_buffer) == len(
                        rx_buffer), "Date received on dut does not match the data sent from host"
                else:
                    self.ssl_server.interfaces.ssl.send_data(1, 1, msg_length=100, message=tx_buffer)
                    self.wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                    buffer_rx = self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=30)
                    assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} " \
                                                   "in the DUT is not matched"
                    logger().info("Data sent by remote peer and received on DUT is matching")
        else:
            # if mode is set to 1, socket open, tx over the socket test will be initiated
            if "openssl" in self.ssl_server.name.lower():
                data_sent = []
                sw = Stopwatch()
                while sw.elapsed_sec < self.test_run_time:
                    data = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
                    data_sent.append(data)
                    self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
                tx_data = "".join(data_sent)
                rx_data = self.ssl_server.interfaces.server.get_messages(timeout=100)[-1]
                logger().info(f"\n\n*************** Total data sent from DUT ***************\n{tx_data}")
                logger().info(f"\n\n*************** data received *************** \n{rx_data}")
                assert tx_data == rx_data, "Data received doesn't match"
            else:
                sw = Stopwatch()
                while sw.elapsed_sec < self.test_run_time:
                    data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                    logger().info(f"DUT is sending data over socket {sock} and data:{data}")
                    self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
                    time.sleep(1)
                    data_receive = self.ssl_server.interfaces.ssl.data_recv_content(1, buffer_size=len(data))
                    logger().info(f"Data received on remote SSL socket is -> {data_receive.decode()}")
                    assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                    logger().info("Data sent by DUT and received on remote peer is matching")

        logger().info(f"Closing socket_id->{sock}")
        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        if "openssl" in self.ssl_server.name.lower():
            self.ssl_server.interfaces.server.stop()
        else:
            self.ssl_server.interfaces.ssl.stop_server()


    def sniffer_validation_ssl(self):
        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer, self.dut_mac_address,
                                                    self.ap_bssid, self.sniffer_filter)
        decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION_KEY --> {decryption_key}")
        logger().info("SSL Packet Decryption is going to start, This may take some time")
        cipher_suite = self.sl_collections.ssl_packet_decryption(self.wifi_sniffer, decryption_key, self.dut_mac_address, ["tls"],
                                                                 self.capture_filename, self.ap_bssid, self.mode,
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
            assert cipher_suite_cmp == self.expected_cipher, (f"Cipher Suite Mismatched, Expected is '{self.expected_cipher}'\n"
                                                         f"But Observed '{cipher_suite_cmp}'")
        logger().info(f"****** As per sniffer capture cipher suite advertised by device {self.dut_mac_address} --> "
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
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
                        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                                  | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                                  | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                                  | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                                  | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                                  | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD
                                  | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
            "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                                   | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                                   | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
            "ble_features": Si91xBLEFeatureBitMap.Default
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                       | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                       | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                               | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 3584},
                "ble": {"count": 1, "stack_len": 3584},

            # "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
            },
        },
    )
]

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "set_default_ssl_cipher", "set_default_extended_ssl_cipher"])
@pytest.mark.parametrize("cipher_list", [['TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256']])
@pytest.mark.parametrize("ca_cert", ["ca-chain.cert.pem"])

def test_Coex_sdk_ssl_tx_cipher_C575153(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ssl_server,
        cipher_list,
        ca_cert
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Conenct DUT as BLE slave
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    ble_dut_addr = ""
    try:
        test_name = request.node.name

        time_duration = utf_constants.get("time_duration")
        logger().info(f"time_duration set in harness:{time_duration}")
        duration = time_duration if time_duration > 60 else 120
        logger().info("If time duration is less than 60 in harness ,"
                      " it will take by default as 120s")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ssl_obj = wifi_ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, request, sl_collections,
                                      cipher_list, sniffer_filter=sniffer_filter, mode="TX", test_run_time=duration)
        ssl_obj.set_cipher(ca_cert=ca_cert)
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ssl_obj.ssl_connection_tx_rx()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        ssl_obj.sniffer_validation_ssl()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)





@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "set_default_ssl_cipher", "set_default_extended_ssl_cipher"])
@pytest.mark.parametrize("cipher_list", [['TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256']])
@pytest.mark.parametrize("cert", [("ca_ecdsa.crt", "server_ecdsa.crt", "server_ecdsa.key")])
def test_Coex_sdk_ssl_tx_cipher_C575154(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ssl_server,
        cipher_list,
        cert
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Conenct DUT as BLE slave
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    ble_dut_addr = ""
    try:
        test_name = request.node.name
        time_duration = utf_constants.get("time_duration")
        logger().info(f"time_duration set in harness:{time_duration}")
        duration = time_duration if time_duration > 60 else 120
        logger().info("If time duration is less than 60 in harness ,"
                      " it will take by default as 120s")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ssl_obj = wifi_ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, request, sl_collections,
                                      cipher_list, sniffer_filter=sniffer_filter,
                                      server_cert=cert[1], server_key=cert[2],
                                      mode="TX", test_run_time=duration)
        ssl_obj.set_cipher(ca_cert=cert[0])
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="advertise",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ssl_obj.ssl_connection_tx_rx()
        ble_client.interfaces.bluetooth.close()
        sl_collections.scan_from_remote_device(wifi_dut=wifi_dut, ble_client=ble_client,
                                               ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        wifi_sniffer.interfaces.capture.stop_capture()
        ssl_obj.sniffer_validation_ssl()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)




@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "set_default_ssl_cipher", "set_default_extended_ssl_cipher"])
@pytest.mark.parametrize("cipher_list", [['TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384']])
@pytest.mark.parametrize("cert", [("ca_ecdsa.crt", "server_ecdsa.crt", "server_ecdsa.key")])
def test_Coex_sdk_ssl_tx_cipher_C575155(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ssl_server,
        cipher_list,
        cert
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Conenct DUT as BLE slave
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    ble_dut_addr = ""
    try:
        test_name = request.node.name
        time_duration = utf_constants.get("time_duration")
        logger().info(f"time_duration set in harness:{time_duration}")
        duration = time_duration if time_duration > 60 else 120
        logger().info("If time duration is less than 60 in harness ,"
                      " it will take by default as 120s")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ssl_obj = wifi_ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, request, sl_collections,
                                      cipher_list, sniffer_filter=sniffer_filter,
                                      server_cert=cert[1], server_key=cert[2],
                                      mode="TX", test_run_time=duration)
        ssl_obj.set_cipher(ca_cert=cert[0])
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ssl_obj.ssl_connection_tx_rx()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        ssl_obj.sniffer_validation_ssl()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)




@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "set_default_ssl_cipher", "set_default_extended_ssl_cipher"])
@pytest.mark.parametrize("cipher_list", [['TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256']])
@pytest.mark.parametrize("cert", [("ca_ecdsa.crt", "server_ecdsa.crt", "server_ecdsa.key")])
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4365")
def test_Coex_sdk_ssl_tx_cipher_dual_role_C575156(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_clients,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ssl_server,
        cipher_list,
        cert
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Conenct DUT as BLE slave
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    ble_dut_addr = ""
    try:
        test_name = request.node.name
        time_duration = utf_constants.get("time_duration")
        logger().info(f"time_duration set in harness:{time_duration}")
        duration = time_duration if time_duration > 60 else 120
        logger().info("If time duration is less than 60 in harness ,"
                      " it will take by default as 120s")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ssl_obj = wifi_ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, request, sl_collections,
                                      cipher_list, sniffer_filter=sniffer_filter,
                                      server_cert=cert[1], server_key=cert[2],
                                      mode="TX", test_run_time=duration)
        ssl_obj.set_cipher(ca_cert=cert[0])
        ble_obj = BleDualRoleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_test_type="slave_and_master",
            testcase=test_name,
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ssl_obj.ssl_connection_tx_rx()
        ble_obj.dual_role_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        ssl_obj.sniffer_validation_ssl()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_clients[0].interfaces.bluetooth.close()
        ble_clients[1].interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients[0],
                                       ble_client_address=ble_obj.ble_clients_address[0],
                                       ble_dut_address=ble_obj.ble_dut_address)



@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "set_default_ssl_cipher", "set_default_extended_ssl_cipher"])
@pytest.mark.parametrize("cipher_list", [['TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256']])
@pytest.mark.parametrize("cert", [("ca_ecdsa.crt", "server_ecdsa.crt", "server_ecdsa.key")])
def test_Coex_sdk_ssl_tx_cipher_C575157(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        ssl_server,
        cipher_list,
        cert
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Conenct DUT as BLE slave
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
    """
    ble_dut_addr = ""
    try:
        test_name = request.node.name
        time_duration = utf_constants.get("time_duration")
        logger().info(f"time_duration set in harness:{time_duration}")
        duration = time_duration if time_duration > 60 else 120
        logger().info("If time duration is less than 60 in harness ,"
                      " it will take by default as 120s")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ssl_obj = wifi_ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, request, sl_collections,
                                      cipher_list, sniffer_filter=sniffer_filter,
                                      server_cert=cert[1], server_key=cert[2],
                                      mode="TX", test_run_time=duration)
        ssl_obj.set_cipher(ca_cert=cert[0])
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            ble_pairing=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ssl_obj.ssl_connection_tx_rx()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_sniffer.interfaces.capture.stop_capture()
        ssl_obj.sniffer_validation_ssl()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


