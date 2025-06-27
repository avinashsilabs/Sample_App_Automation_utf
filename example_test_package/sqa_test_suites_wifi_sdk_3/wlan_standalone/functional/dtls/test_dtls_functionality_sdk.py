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
import threading
import re

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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    return pytest.mark.config("wifi_dut", wifi=config)


class WlanThread:
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections,
                 sniffer_filter, test_name, dtls_version):
        self.interfaces = None
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
            cert_index = 8196  # BIT(13)|BIT(2) i-e enable_dtls = SL_SI91X_ENABLE_DTLS | SL_SI91X_DTLS_V_1_0
            option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_0_ENABLE
        elif self.dtls_version == "-dtls1_2":
            self.openssl.interfaces.server.start(port=self.local_port1, dtls_version="-dtls1_2")
            cert_index = 8200  # BIT(13)|BIT(3) i-e enable_dtls = SL_SI91X_ENABLE_DTLS | SL_SI91X_DTLS_V_1_2
            option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_2_ENABLE
        else:
            self.openssl.interfaces.server.start(port=self.local_port1, dtls_version="-dtls")
            cert_index = 8200
            option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_2_ENABLE
        time.sleep(1)
        assert self.openssl.interfaces.server.is_running() is True
        self.server_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self.sock1 = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM",                                                   protocol="IPPROTO_UDP")
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
                            f"\n **** Status Received: {SLStatus.SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAIL}"
                            f", retrying sendto...")
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

    def sniffer_dtls_validate(self):

        # --- Add SSL packet decryption for DTLS traffic (like ssl_client_legacy) ---
        # Set decryption_key and ap_bssid as per your testbed configuration
        decryption_key = getattr(self, 'decryption_key', None)
        if not decryption_key:
            # Try to get from AP or DUT if available, else set manually
            try:
                passphrase = self.wifi_access_point.interfaces.wifi.passphrase
                ssid = self.wifi_access_point.interfaces.wifi.ssid
                decryption_key = f"{passphrase}:{ssid}"

            except Exception:
                decryption_key = "passphrase:ssid"  # <-- Set your default or test value here
        capture_filename = f"{self.test_name}.pcap"
        ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        result = self.sl_collections.ssl_packet_decryption(
            self.wifi_sniffer,
            decryption_key,
            self.dut_mac_address,
            ["dtls"],
            capture_filename,
            ap_bssid
        )
        self.logger.info(f"DTLS Result: {result}")
        # Only check for the protocols requested in decrypt_layers (here, 'dtls' or 'tls')
        decrypt_layers = ["dtls"]
        for key in decrypt_layers:
            if key in result and not result[key]:
                raise RuntimeError(f"Failed to decrypt DTLS packets for {key} with decryption key: {decryption_key}")
            if key in result:
                self.logger.info(f"Decryption successful for key: {key}, value: {result[key]}")
                match = re.search(r"Version:\s*DTLS\s*([0-9.]+)", str(result[key]))
                if match:
                    dtls_ver = match.group(1)
                    self.logger.info(f"dtls_version: **********{dtls_ver}***********")

    def sniffer_validate(self):
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
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=dtls_filter_generic)[
                'packet_count'], \
                (f"Unable to find dtls Packet in Sniffer Capture for version {self.dtls_version} "
                 f"(checked dtls)")

        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=dtls_filter)['packet_count'], \
            (f"Unable to find dtls Packet in Sniffer Capture for version {self.dtls_version}"
             f" (checked  dtls1_0 or dtls1_2)")


def dtls_sendto_loop(wifi_dut, sock1, server_ip, local_port1, duration_sec=250, logger=None):
    """Repeatedly send DTLS data for the specified duration (seconds) on the given socket."""
    start_time = time.time()
    i = 0
    while (time.time() - start_time) < duration_sec:
        tx_data = f"{i + 1}-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
        retry = 0
        while retry < 3:
            try:
                wifi_dut.interfaces.wifi.dtlsSocketSendTo(
                    socket_fd=sock1,
                    port=local_port1,
                    data=tx_data,
                    ip_addr=server_ip
                )
                if logger:
                    logger.info(f"DTLS sendto iteration {i + 1} complete.")
                break
            except Exception as e:
                if hasattr(e, 'status') and e.status == SLStatus.SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAIL:
                    if logger:
                        logger.info(
                            f"\n **** Status Received: {SLStatus.SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAIL},"
                            f" retrying sendto...")
                    retry += 1
                    time.sleep(1)
                    continue
                else:
                    raise
        else:
            if logger:
                logger.error(f"Failed to send message after retries: {tx_data}")
            raise RuntimeError(f"DTLS sendto failed after retries for message: {tx_data}")
        i += 1
        time.sleep(2)  # Spread out sends to overlap with renewal


def dtls_send_with_long_duration(dtls_thread, wifi_dut, wifi_client, openssl,
                                 wifi_access_point, wifi_sniffer, sl_collections, logger):
    """Setup OpenSSL server, create socket, set socket options, and repeatedly send DTLS data for 250s, then decrypt."""
    dtls_thread.local_port1 = randint(5001, 60000)

    # Start OpenSSL server for DTLS
    openssl.interfaces.server.start(port=dtls_thread.local_port1, dtls_version="-dtls1_2")
    time.sleep(1)  # Give server time to start
    assert openssl.interfaces.server.is_running() is True
    # Get server IP (optionally specify interface)
    dtls_thread.server_ip = wifi_client.interfaces.wifi.get_ip_address()
    dtls_thread.sock1 = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM",
                                                        protocol="IPPROTO_UDP")
    wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
        dtls_thread.sock1,
        option_level="SOL_SOCKET",
        option_name=Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_2_ENABLE,
        cert_index=8200
    )
    wifi_dut.interfaces.wifi.set_dtls_extensions(
        dtls_thread.sock1,
        tls_extension_sni_type=1,
        tls_extension_alpn_type=2,
        tls_sni_extension="example.com",
        tls_alpn_extension="http/1.1"
    )
    logger.info("Starting DTLS sendto loop for DHCP renewal overlap test.")
    dtls_sendto_loop(
        wifi_dut=wifi_dut,
        sock1=dtls_thread.sock1,
        server_ip=dtls_thread.server_ip,
        local_port1=dtls_thread.local_port1,
        duration_sec=250,
        logger=logger
    )
    # Close socket and stop server after sending
    wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=dtls_thread.sock1)
    openssl.interfaces.server.stop()
    logger.info("DTLS sendto loop and server stop complete.")


@wifi_dut_marker()
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_handshake_client_server_c766258(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point, openssl,
                                                       logger, sl_collections, sniffer_filter):
    ''' DTLS Protocol handshakes and Verify exchanges between server and client sockets
    during connection establishment'''
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections,
                             sniffer_filter, test_name="test_c766258", dtls_version="-dtls")
    try:
        dtls_thread.jointoap()
        dtls_thread.dtlsclientfunctionality()
        dtls_thread.sniffer_validate()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_1_0_c766259(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point, openssl,
                                   logger, sl_collections, sniffer_filter):
    '''Verify the DUT functionality by opening client socket with DTLS1.0 version and do data transfer.'''
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections,
                             sniffer_filter, test_name="test_c766259", dtls_version="-dtls1")
    try:
        dtls_thread.jointoap()
        dtls_thread.dtlsclientfunctionality()
        dtls_thread.sniffer_validate()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_1_2_c766260(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point, openssl,
                                   logger, sl_collections, sniffer_filter):
    '''Verify the DUT functionality by opening client socket with DTLS1.2 version and do data transfer.'''
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections,
                             sniffer_filter, test_name="test_c766260", dtls_version="-dtls1_2")
    try:
        dtls_thread.jointoap()
        dtls_thread.dtlsclientfunctionality()
        dtls_thread.sniffer_validate()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_client_socket_creation_send_data_close_regression_c766273(wifi_sniffer, wifi_client, wifi_dut,
                                                                                 wifi_access_point, openssl,
                                                                                 logger, sl_collections,
                                                                                 sniffer_filter):
    '''Verify DTLS client socket connection, data send (10 times), and socket close regression
    (loop: socket creation-send data-close) for 10 iterations. Sniffer validation is not performed
    in this regression test.'''
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections,
                             sniffer_filter, test_name="test_c766273", dtls_version="-dtls1_2")
    dtls_thread.jointoap()
    for i in range(5):
        logger.info(f"Iteration {i + 1}/10: Creating socket, sending data 10 times, and closing socket.")
        dtls_thread.local_port1 = randint(5001, 60000)
        dtls_thread.sent_data = []
        # Start OpenSSL server for each iteration
        openssl.interfaces.server.start(port=dtls_thread.local_port1, dtls_version="-dtls1_2")
        time.sleep(1)
        assert openssl.interfaces.server.is_running() is True
        dtls_thread.server_ip = wifi_client.interfaces.wifi.get_ip_address()
        dtls_thread.sock1 = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM",
                                                            protocol="IPPROTO_UDP")
        wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
            dtls_thread.sock1,
            option_level="SOL_SOCKET",
            option_name=Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_2_ENABLE,
            cert_index=8200
        )
        wifi_dut.interfaces.wifi.set_dtls_extensions(
            dtls_thread.sock1,
            tls_extension_sni_type=1,
            tls_extension_alpn_type=2,
            tls_sni_extension=" SNIshjogushjogushjogushjogushjogushjoguSNI.com",
            tls_alpn_extension="ALPNJSRJSRJSRJSRJSRJSRJSRJSRJSRJSRJSRJSRJSRJSRALPN/1.1"
        )
        # Send data 10 times per socket
        for j in range(10):
            tx_data = f"{i + 1}-{j + 1}-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
            wifi_dut.interfaces.wifi.dtlsSocketSendTo(
                socket_fd=dtls_thread.sock1,
                port=dtls_thread.local_port1,
                data=tx_data,
                ip_addr=dtls_thread.server_ip
            )
            dtls_thread.sent_data.append(tx_data)
        rx_data = openssl.interfaces.server.get_messages(10)
        logger.info(f"Iteration {i + 1}: Sent: {dtls_thread.sent_data}, Received: {rx_data}")
        if isinstance(rx_data, list):
            filtered = [line for line in rx_data if line.strip() not in ("Using default temp DH parameters", "ACCEPT")]
            received_concat = filtered[0].strip() if filtered else ""
        else:
            received_concat = rx_data.strip()
        sent_concat = "".join(dtls_thread.sent_data)
        assert received_concat == sent_concat, (
            f"Iteration {i + 1}: Data received doesn't match what was sent: {received_concat} != {sent_concat}")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=dtls_thread.sock1)
        openssl.interfaces.server.stop()
        time.sleep(0.5)
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    # DTLS packet decryption
    dtls_thread.sniffer_dtls_validate()


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_client_data_transfer_with_sni_feature_c766278(wifi_sniffer, wifi_client, wifi_dut,
                                                                     wifi_access_point, openssl,
                                                                     logger, sl_collections, sniffer_filter):
    '''Verify DTLS client data transfer with SNI feature in SSL.'''
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections,
                             sniffer_filter, test_name="test_c766278", dtls_version="-dtls1_2")
    # Patch the SNI extension for this test only
    orig_set_dtls_extensions = dtls_thread.wifi_dut.interfaces.wifi.set_dtls_extensions

    def set_dtls_extensions_with_long_sni(sock, tls_extension_sni_type, tls_extension_alpn_type, tls_sni_extension,
                                          tls_alpn_extension):
        sni_extension = "sni-" + "x" * 100  # 200 bytes
        return orig_set_dtls_extensions(sock, tls_extension_sni_type, tls_extension_alpn_type, sni_extension,
                                        tls_alpn_extension)

    dtls_thread.wifi_dut.interfaces.wifi.set_dtls_extensions = set_dtls_extensions_with_long_sni
    try:
        dtls_thread.jointoap()
        dtls_thread.dtlsclientfunctionality()

        dtls_thread.sniffer_validate()

        # --- Sniffer filter validation for SNI extension ---
        dtls_sni_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dtls_thread.device_ip,
            da_addr=dtls_thread.server_ip,
            port=dtls_thread.local_port1,
            filter_name="dtls_sni",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=dtls_sni_filter)['packet_count'], \
            f"Unable to find dtls_sni Packet in Sniffer Capture for SNI test"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_client_data_transfer_with_alpn_feature_c766279(wifi_sniffer, wifi_client, wifi_dut,
                                                                      wifi_access_point, openssl,
                                                                      logger, sl_collections, sniffer_filter):
    '''Verify DTLS client data transfer with ALPN feature in SSL.'''
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections,
                             sniffer_filter, test_name="test_c766279", dtls_version="-dtls1_2")
    # Patch the ALPN extension for this test only
    orig_set_dtls_extensions = dtls_thread.wifi_dut.interfaces.wifi.set_dtls_extensions

    def set_dtls_extensions_with_long_alpn(sock, tls_extension_sni_type, tls_extension_alpn_type, tls_sni_extension,
                                           tls_alpn_extension):
        alpn_extension = "alpn-" + "y" * 195  # 200 bytes
        return orig_set_dtls_extensions(sock, tls_extension_sni_type, tls_extension_alpn_type, tls_sni_extension,
                                        tls_alpn_extension)

    dtls_thread.wifi_dut.interfaces.wifi.set_dtls_extensions = set_dtls_extensions_with_long_alpn
    try:
        dtls_thread.jointoap()
        dtls_thread.dtlsclientfunctionality()
        dtls_thread.sniffer_validate()

        # --- Sniffer filter validation for ALPN extension --
        dtls_alpn_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dtls_thread.device_ip,
            da_addr=dtls_thread.server_ip,
            port=dtls_thread.local_port1,
            filter_name="dtls_alpn",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=dtls_alpn_filter)['packet_count'], \
            f"Unable to find dtls_alpn Packet in Sniffer Capture for ALPN test"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize("dhcp_lease", [120])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "120", "security": "Open", })
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_functionality_with_dhcp_renewal_c766294(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point,
                                                               openssl,
                                                               logger, sl_collections, sniffer_filter, dhcp_lease):
    '''Verify DTLS data transfer while DHCP renewal occurs (120s lease), with sniffer and DHCP renewal validation.'''
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, logger, sl_collections,
                             sniffer_filter, test_name="test_c766294", dtls_version="-dtls1_2")
    dtls_thread.jointoap()
    # --- Sniffer filter validation before renewal ---
    logger.info("Starting DTLS data transfer and DHCP renewal overlap test.")

    # Start DTLS send in a thread

    dtls_send_thread = threading.Thread(target=dtls_send_with_long_duration, args=(
        dtls_thread, wifi_dut, wifi_client, openssl, wifi_access_point, wifi_sniffer, sl_collections, logger))
    dtls_send_thread.start()
    # Wait to overlap DHCP renewal (simulate 120s lease, renewal at ~120s)
    logger.info("Waiting for DHCP renewal to occur during DTLS transfer...")
    time.sleep(240)  # Start DHCP renewal about halfway through DTLS sends
    # --- DHCP renewal sniffer validation ---
    device_address = {'sa_addr': dtls_thread.dut_mac_address, 'da_addr': wifi_access_point.interfaces.wifi.bssid,
                      'wlan_addr': dtls_thread.dut_mac_address}
    filters_name = {1: 'power_mgmt_bit', 2: 'dhcp'}
    output_1 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                    device_address, filters_name=filters_name)
    logger.info(f'OUTPUT 1 = {output_1}')
    assert all(output_1.values()), 'Unable to find expected filter (power_mgmt_bit, dhcp)'
    filters_name_1 = {1: 'dhcp_renewal'}
    packet_filter2 = '        DHCP: Request (3)'
    output_2 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                    device_address, filters_name=filters_name_1,
                                                                    packet_filter2=packet_filter2)
    logger.info(f'OUTPUT 2 = {output_2}')
    assert all(output_2.values()), 'Unable to find expected filter (dhcp_renewal)'
    # Wait for DTLS sends to finish
    dtls_send_thread.join()
    openssl.interfaces.server.stop()
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    dtls_thread.sniffer_validate()

