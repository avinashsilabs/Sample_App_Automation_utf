import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xCertificateType, Si91xCertIdentifier, Cipher, Si91xModuleType, \
    Si91xCustomSyncSockOptParms
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from random import randint
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan & coex mode for 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. Initiate the connection with third party Access Point.
        4. Start SSL Server 
        4. Run the traffic TCP TX & RX.
        5. Verify the throughput of values TCP TX & RX values.  

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer.K@silabs
"""


def logger():
    return get_logger(__name__)


def wifi_dut_marker(ca_cert=None, opermode=0, stack_len=None, thread_no=None, pmf_enable=False, priority=0):
    """
    Pytest marker for wifi_dut configuration.
    Args:
        ca_cert: Optional CA certificate tuple.
        opermode: Optional operating mode (e.g., Si91xOperatingMode.EAPWiFiClient). Defaults to 0.
        stack_len: Optional stack length for thread configuration. Defaults to 3584 if not specified.
        thread_no: Optional number of threads to configure. Defaults to 1 if not specified.
        pmf_enable: Optional flag to enable Protected Management Frames. Defaults to False.
    """
    # Initialize the base configuration
    config = {
        "thread_config": {"wifi": {"count": thread_no if thread_no is not None else 1,
                                   "stack_len": stack_len if stack_len is not None else 3584, "priority": priority}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.SL_SI91X_TCP_IP_FEAT_DTLS_THREE_SOCKETS,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                (Si91xExtCustomFeatureBitMap.IEEE802_11W if pmf_enable else 0)),
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "set_send_feature_frame": True,
        "ca_cert": ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    return pytest.mark.config("wifi_dut", wifi=config)


def wifi_dut_marker1(ca_cert=None, opermode=0, stack_len=None, thread_no=None, pmf_enable=False, priority=0):
    """
    Pytest marker for wifi_dut configuration.
    Args:
        ca_cert: Optional CA certificate tuple.
        opermode: Optional operating mode (e.g., Si91xOperatingMode.EAPWiFiClient). Defaults to 0.
        stack_len: Optional stack length for thread configuration. Defaults to 3584 if not specified.
        thread_no: Optional number of threads to configure. Defaults to 1 if not specified.
        pmf_enable: Optional flag to enable Protected Management Frames. Defaults to False.
    """
    # Initialize the base configuration
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.SL_SI91X_TCP_IP_FEAT_DTLS_THREE_SOCKETS,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                (Si91xExtCustomFeatureBitMap.IEEE802_11W if pmf_enable else 0)),
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "set_send_feature_frame": True,
        "ca_cert": ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    return pytest.mark.config("wifi_dut", wifi=config)


class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""

    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, openssl=None, sl_collections=None,
                 sniffer_filter=None, bt_dut=None, ble_data_transfer=None, testcase=None, bt_client_address=None,
                 dtls_version=None, wifi_client=None, ble_conn=None, utf_constants=None, ble_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.openssl = openssl
        self.testcase = testcase
        self.server_ip = None
        self.local_port1 = None
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.bt_dut = bt_dut
        self.ble_client = ble_client
        self.ble_data_transfer = ble_data_transfer
        self.dut_mac_address = None
        self.dut_addr = None
        self.dtls_version = dtls_version
        self.wifi_client = wifi_client
        self.ble_conn = ble_conn
        self.utf_constants = utf_constants
        self.bt_client_address = bt_client_address

    def run(self):
        logger().info("starting the sniffer again")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        if self.ble_conn:
            conn_params = {
                "min_conn_interval": self.utf_constants.get("min_conn_interval"),
                "max_conn_interval": self.utf_constants.get("max_conn_interval"),
                "conn_latency": 0,
                "supervision_timeout": self.utf_constants.get("supervision_timeout")}
            logger().info("Initiate ble service in DUT")
            bt_dut_address = self.bt_dut.interfaces.bluetooth.ble_start()
            assert bt_dut_address, "unable to fetch dut bd address...."

            logger().info("Set DUT in advertise mode")
            self.bt_dut.interfaces.bluetooth.ble_start_advertising()

            logger().info("Start smp scan from the remote device")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(5)
            logger().info("stop scanning ....")
            self.ble_client.interfaces.bluetooth.stop_scanning()

            # See that we found our device
            logger().info("Check the dut is listed...")
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert self.bt_dut.interfaces.bluetooth.ble_address in found_devices

            self.ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                         min_conn_interval=conn_params["min_conn_interval"],
                                                         max_conn_interval=conn_params["max_conn_interval"],
                                                         conn_latency=conn_params["conn_latency"],
                                                         supervision_timeout=conn_params["supervision_timeout"])

            assert bt_dut_address, "unable to connect to the given address"
            time.sleep(5)

        if self.ble_data_transfer:
            logger().info(f"BLE Data Transfer going to start")
            service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
            char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

            logger().info("================== Start BLE in DUT ====================")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address, "failed to initialize ble in dut"
            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F)

            logger().info("=============== Start BLE ADV in DUT ====================")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            logger().info("============== start scanning in remote ble device ======================")
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert self.ble_client_address, "failed to start scan in remote device"

            device_found = False
            sw = Stopwatch()
            while sw.elapsed_sec < 30:
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                if bt_dut_address in found_devices and \
                        found_devices[bt_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data:
                    device_found = True
                    break

            self.ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "no device found"

            logger().info("============== connect to ble dut =========================")
            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
            time.sleep(10)

            logger().info("======= get connection state")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"

            servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"

            char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid,
                char_uid=char_uid)
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"

            self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            # subscribe to notifications
            self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                         char_uid=char_uid)

        dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                            wifi_access_point=self.wifi_access_point,
                                                            associated=self.wifi_dut.interfaces.wifi.associated,
                                                            retry_count=3, ping_after_power_save=False,
                                                            power_save=False)
        # self.wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)
        if self.ble_data_transfer:
            logger().info(f"BLE Data Transfer is going to start")
            ble_data = ble_notify(self.wifi_dut, self.ble_client_address)
            ble_data.start()
        self.local_port1 = randint(5001, 60000)
        self.openssl.interfaces.server.start(port=self.local_port1, dtls_version="-dtls1_2")
        cert_index = 8200
        option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_2_ENABLE
        max_retries = 5
        for retry in range(max_retries):
            if self.openssl.interfaces.server.is_running():
                logger().info(f"OpenSSL server confirmed running on port {self.local_port1}")
                break
            logger().warning(f"OpenSSL server not running, retry {retry + 1}/{max_retries}")
            time.sleep(1)
        else:
            raise RuntimeError(f"Failed to start OpenSSL server after {max_retries} retries for {self.test_name}")

        assert self.openssl.interfaces.server.is_running() is True, f"OpenSSL server failed to start for {self.test_name}"
        time.sleep(2)
        self.server_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        time.sleep(2)
        self.sock1 = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM",
                                                          protocol="IPPROTO_UDP")
        self.wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
            self.sock1,
            option_level="SOL_SOCKET",
            option_name=option_name,
            cert_index=cert_index
        )
        pkt_count = 20000
        buffer_length = 1360
        with TimeMeasurer() as t:
            result = self.wifi_dut.interfaces.wifi.send_data_pkts(self.sock1, buffer_length, pkt_count,
                                                                  server_ip=self.server_ip,
                                                                  server_port=self.local_port1)
            bytes_sent = result
            logger().info(f"Number of packets send {bytes_sent}")
        logger().info(f"Time taken to send data {t.duration} seconds")
        time_taken = t.duration
        # data = int(bytes_sent)
        # data = data*8
        # logger().info(f"DTLS TX throughput ->  {((int(bytes_sent)*8) / time_taken * 1000) / 1000} Kbps")
        logger().info((f"DTLS TX throughput ->  {((int(bytes_sent) * 8) / (time_taken * 1000)) / 1000} Mbps"))
        time.sleep(10)
        logger().info(f"Closing socket_id->{self.sock1}")
        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock1)
        self.openssl.interfaces.server.stop()
        time.sleep(1)
        if self.ble_conn:
            self.bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
            time.sleep(2)
        if self.ble_data_transfer:
            data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdata"
            logger().info(f"unsubcribing the ble notifications")
            self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            time.sleep(1)

            logger().info("====================== Validate Data ===========================")
            notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
            logger().info(f' *********************** Notification is {notifications} ***********************')
            assert len(notifications) > 0, "received data is empty"
            assert notifications[0] == data, "failed to fetch data"

            logger().info("******************** ble_remove_service ***********************")
            self.wifi_dut.interfaces.wifi.ble_remove_service()

            logger().info("================== Disconnecting from DUT ========================")
            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
            self.ble_client.interfaces.bluetooth.close()
        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        self.wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)


class ble_notify(WifiJoinThread):
    def __init__(self, wifi_dut, ble_client_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client_address = ble_client_address

    def run(self):
        data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdata"
        sw = Stopwatch()
        while sw.elapsed_sec < 35:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data, ble_remote_dev_address=self.ble_client_address)
            time.sleep(0.5)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
@pytest.mark.test_src_map_id('C768255')
def test_wifi_sdk_dtls_standalone_tx_C768255(wifi_access_point, sniffer_filter, sl_collections, wifi_dut,
                                             openssl, wifi_sniffer, request, wifi_client):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, openssl=openssl,
                              wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker1()
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
@pytest.mark.test_src_map_id('C768257')
def test_wifi_sdk_dtls_tx_with_ble_connected_C768257(wifi_access_point, sniffer_filter, sl_collections, wifi_dut,
                                                     utf_constants, openssl, wifi_sniffer, request, wifi_client,
                                                     ble_client, bt_dut):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, openssl=openssl, bt_dut=bt_dut,
                              wifi_client=wifi_client, ble_client=ble_client, ble_conn=True,
                              utf_constants=utf_constants)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker1()
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
@pytest.mark.test_src_map_id('C768259')
def test_wifi_sdk_dtls_tx_ble_conn_with_data_C768259(wifi_access_point, sniffer_filter, sl_collections, wifi_dut,
                                                     utf_constants, openssl, wifi_sniffer, request, wifi_client,
                                                     ble_client, bt_dut):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, openssl=openssl, bt_dut=bt_dut,
                              wifi_client=wifi_client, ble_client=ble_client, ble_data_transfer=True,
                              utf_constants=utf_constants)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
