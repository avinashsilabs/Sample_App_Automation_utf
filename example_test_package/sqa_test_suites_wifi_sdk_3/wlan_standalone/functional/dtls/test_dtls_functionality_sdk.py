import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomSyncSockOptParms,  # <-- add this import
)
from utf_wiseconnect_3.tests.sl_status import SLStatus
import random
import string
import time
from random import randint

"""This Test plan is validating DTLS functionality in SDK 3.0

        1. Configuration of DUT in 2G : BGNAX
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Stop the sniffer

    setup requirement:
        1. soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)
        5. OpenSSL server

    Author: SHOBHA RANI JOGU
"""


def wifi_dut_marker(ca_cert=None):
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.SL_SI91X_TCP_IP_FEAT_DTLS_THREE_SOCKETS,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    return pytest.mark.config("wifi_dut", wifi=config)


class WlanThread:
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections, sniffer_filter, test_name, dtls_version):
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wifi_client = wifi_client
        self.openssl = openssl
        self.logger = logger
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.test_name = test_name
        self.device_ip = None
        self.dut_mac_address = None
        self.server_ip = None
        self.local_port1 = None
        self.sock1 = None
        self.sent_data = []
        self.dtls_version = dtls_version

    def jointoap(self):
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.test_name}.pcap")
        result = self.sl_collections.join_to_wifi_network_with_rejoin(
            self.wifi_dut, self.wifi_access_point, ping_count=10, retry_count=3,
            rejoin_params=[0, 4, 40, 0], associated=False, power_save=True, ping_after_ps=True
        )
        self.device_ip, self.dut_mac_address = result['device_ip'], result['dut_mac_address']


    def dtlsclientfunctionality(self):
        self.local_port1 = randint(5001, 60000)
        # Use DTLS 1.0 if specified, else default to DTLS 1.2
        if self.dtls_version == "-dtls1":
            self.openssl.interfaces.server.start(port=self.local_port1, dtls_version="-dtls1")
            cert_index = 8196   #BIT(13)|BIT(2) i-e enable_dtls = SL_SI91X_ENABLE_DTLS | SL_SI91X_DTLS_V_1_0
            option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_0_ENABLE
        else:
            self.openssl.interfaces.server.start(port=self.local_port1, dtls_version="-dtls1_2")
            cert_index = 8200  #BIT(13)|BIT(3) i-e enable_dtls = SL_SI91X_ENABLE_DTLS | SL_SI91X_DTLS_V_1_2
            option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_2_ENABLE
        time.sleep(1)
        assert self.openssl.interfaces.server.is_running() is True
        self.server_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self.sock1 = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
        self.wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
            self.sock1,
            option_level="SOL_SOCKET",
            option_name=option_name,
            cert_index=cert_index
        )
        self.wifi_dut.interfaces.wifi.set_dtls_extensions(
            self.sock1,
            tls_extension_sni_type=1,
            tls_extension_alpn_type=2,
            tls_sni_extension="example.com",
            tls_alpn_extension="http/1.1"
        )
        for i in range(10):
            tx_data = f"{i + 1}-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
            retry = 0
            while retry < 3:
                try:
                    # self. wifi_dut.interfaces.wifi.bsdSocketSendTo(socket_fd=self.sock1, data=tx_data,
                    #                                                ip_addr=self.server_ip,
                    #                                                ip_len=4, port=self.local_port1)
                    self.wifi_dut.interfaces.wifi.dtlsSocketSendTo(
                        socket_fd=self.sock1,
                        port=self.local_port1,
                        data=tx_data,
                        ip_addr=self.server_ip
                    )
                    self.sent_data.append(tx_data)
                    break
                except Exception as e:
                    if hasattr(e, 'status') and e.status == SLStatus.SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAIL:
                        self.logger().info(
                            f"\n **** Status Received: {SLStatus.SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAIL}, retrying sendto...")
                        retry += 1
                        time.sleep(1)
                        continue
                    else:
                        raise
            else:
                self.logger().error(f"Failed to send message after retries: {tx_data}")
                raise RuntimeError(f"DTLS sendto failed after retries for message: {tx_data}")
        rx_data = self.openssl.interfaces.server.get_messages(10)
        self.logger.info(f"Sent: {self.sent_data}, Received: {rx_data}")
        if isinstance(rx_data, list):
            filtered = [line for line in rx_data if line.strip() not in ("Using default temp DH parameters", "ACCEPT")]
            received_concat = filtered[0].strip() if filtered else ""
        else:
            received_concat = rx_data.strip()
        sent_concat = "".join(self.sent_data)
        assert received_concat == sent_concat, (
            f"Data received doesn't match what was sent: {received_concat} != {sent_concat}")
        self.logger.info(f"Closing socket_id->{{self.sock1}}")
        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock1)
        self.openssl.interfaces.server.stop()
        time.sleep(1)
        self.wifi_dut.interfaces.wifi.leave()
        self.logger.info("Stop Sniffer finally")
        self.wifi_sniffer.interfaces.capture.stop_capture()

        if self.dtls_version == "-dtls1":
            filtername = "dtls1_0"
        elif self.dtls_version == "-dtls1_2":
            filtername = "dtls1_2"
        else:
            filtername = "dtls"

        dtls_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.device_ip,
            da_addr=self.server_ip,
            port=self.local_port1,
            filter_name=filtername,
        )
        if filtername != "dtls":
            dtls_filter_generic = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.device_ip,
                da_addr=self.server_ip,
                port=self.local_port1,
                filter_name="dtls",
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=dtls_filter_generic)['packet_count'],\
                f"Unable to find dtls Packet in Sniffer Capture for version {self.dtls_version} (checked dtls)"
        # --- Enhanced sniffer filter and validation for DTLS 1.0, 1.2, and generic DTLS ---
        # packet_filters = [dtls_filter, dtls_filter_generic]
        # found = False
        # for pf in packet_filters:
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=dtls_filter)['packet_count'],\
            f"Unable to find dtls Packet in Sniffer Capture for version {self.dtls_version} (checked  dtls1_0 or dtls1_2)"


@wifi_dut_marker()
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_handshake_client_server_c766258(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point, openssl,
                                                       logger, sl_collections, sniffer_filter):
    ''' DTLS Protocol handshakes and Verify exchanges between server and client sockets during connection establishment'''
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections, sniffer_filter, test_name="test_c766258", dtls_version="-dtls1_2")
    try:
        dtls_thread.jointoap()
        dtls_thread.dtlsclientfunctionality()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_1_0_c766259(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point, openssl,
                                                       logger, sl_collections, sniffer_filter):
    '''Verify the DUT functionality by opening client socket with DTLS1.0 version and do data transfer.'''
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections, sniffer_filter, test_name="test_c766259", dtls_version="-dtls1")
    try:
        dtls_thread.jointoap()
        dtls_thread.dtlsclientfunctionality()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_1_2_c766260(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point, openssl,
                                                       logger, sl_collections, sniffer_filter):
    '''Verify the DUT functionality by opening client socket with DTLS1.2 version and do data transfer.'''
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections, sniffer_filter, test_name="test_c766260", dtls_version="-dtls1_2")
    try:
        dtls_thread.jointoap()
        dtls_thread.dtlsclientfunctionality()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



