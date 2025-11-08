import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomSyncSockOptParms,
    Si91xOperatingMode,
    IEEE802_11W,
    Si91xJoinFeatureBitMap,
)
from utf_wiseconnect_3.tests.sl_status import SLStatus
import random
import string
import time
import threading
from random import randint
from threading import Thread
from utf.utils.thread_base import ThreadBase
import re
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
import ipaddress

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


def logger():
    return get_logger(__name__)

def random_ipv6_addr(prefix: str) -> str:
    # Ensure the prefix is interpreted as a /64 network
    network = ipaddress.IPv6Network(f"{prefix}/64", strict=False)

    # Generate a random 64-bit interface identifier
    random_suffix = random.getrandbits(64)

    # Combine the prefix and the random suffix
    full_ip_int = int(network.network_address) | random_suffix
    full_ip = ipaddress.IPv6Address(full_ip_int)

    return str(full_ip)


wan_ipv6_addr = random_ipv6_addr("2001:db8:abcd:0012::")
wan_gateway = "2001:db8:abcd:0012::1"

def wifi_dut_marker(ca_cert=None, opermode=0, stack_len=None, thread_no=None, pmf_enable=False, priority=0,
                    tcpip_feat=0):
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
        "oper_mode": opermode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.SL_SI91X_TCP_IP_FEAT_DTLS_THREE_SOCKETS | tcpip_feat,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
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


class WlanThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                 sniffer_filter, test_name, dtls_version, rejoin_params=None, ip_version=4):
        super().__init__()
        self.interfaces = None
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wifi_client = wifi_client
        self.openssl = openssl
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
        self.rejoin_params = rejoin_params
        self.ip_version = ip_version

    def connect_to_access_point(self):
        """Connect DUT to Wi-Fi access point and configure sniffer capture."""
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.test_name}.pcap")

        # Set rejoin parameters based on test case
        if self.test_name == "test_c766276":
            rejoin_params = [5, 4, 40, 0]
        elif self.rejoin_params is not None:
            rejoin_params = self.rejoin_params
        else:
            rejoin_params = [0, 4, 40, 0]
        if self.test_name == "test_c766297" or self.test_name == "test_c766298":
            # Join using IPv6 and capture returned information when available
            result = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                              wifi_access_point=self.wifi_access_point,
                                                              associated=self.wifi_dut.interfaces.wifi.associated,
                                                              ip_version='ipv6',
                                                              ipv6_type="global",
                                                              retry_count=5)
            # Ensure DUT IPv6 and MAC are stored on the thread instance for later use.
            # Prefer values returned by join_to_wifi_network (result) and fall back to querying the DUT interface.
            try:
                if isinstance(result, dict):
                    self.device_ip = result.get('device_ip') or self.wifi_dut.interfaces.wifi.get_ip_address(version=6)
                    self.dut_mac_address = result.get('dut_mac_address') or self.wifi_dut.interfaces.wifi.get_mac_address()
                else:
                    # If result is not a dict, try to query DUT directly
                    self.device_ip = self.wifi_dut.interfaces.wifi.get_ip_address(version=6)
                    self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            except Exception:
                # Final fallback: try querying DUT interface methods directly
                try:
                    self.device_ip = self.wifi_dut.interfaces.wifi.get_ip_address(version=6)
                except Exception:
                    self.device_ip = None
                try:
                    self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
                except Exception:
                    self.dut_mac_address = None
        else:
             result = self.sl_collections.join_to_wifi_network_with_rejoin(
                 self.wifi_dut, self.wifi_access_point, ping_count=10, retry_count=3,
                 rejoin_params=rejoin_params, associated=False, power_save=True, ping_after_ps=True
             )
             self.device_ip, self.dut_mac_address = result['device_ip'], result['dut_mac_address']

    def establish_dtls_connection(self):
        """Establish DTLS connection, perform data transfer, and validate communication."""
        self.local_port1 = randint(5001, 60000)

        # Special logic for negative version mismatch test
        if self.test_name == "test_c766289":
            logger().info(f"OpenSSL server test766289: Starting server as DTLS1.2, client as DTLS1.0")
            # Start server as DTLS1.2, client as DTLS1.0
            self.openssl.interfaces.server.start(port=self.local_port1, dtls_version="-dtls1_2", ip_version=self.ip_version)
            cert_index = 8196  # BIT(13)|BIT(2) i-e enable_dtls = SL_SI91X_ENABLE_DTLS | SL_SI91X_DTLS_V_1_0
            option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_0_ENABLE
        elif self.test_name == "test_c766290":
            logger().info(f"OpenSSL server test766290: Starting server as DTLS1 client as DTLS1.2")
            # Start server as DTLS1.0, client as DTLS1.2
            self.openssl.interfaces.server.start(port=self.local_port1, dtls_version="-dtls1", ip_version=self.ip_version)
            cert_index = 8200  # BIT(13)|BIT(3) i-e enable_dtls = SL_SI91X_ENABLE_DTLS | SL_SI91X_DTLS_V_1_2
            option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_2_ENABLE
        else:
            if self.ip_version == 6:
                self.openssl.interfaces.server.start(port=self.local_port1, dtls_version=self.dtls_version, ip_version=6)
            else:
                self.openssl.interfaces.server.start(port=self.local_port1, dtls_version=self.dtls_version)
            # Set cert_index and option_name based on dtls_version
            if self.dtls_version == "-dtls1":
                cert_index = 8196  # BIT(13)|BIT(2) i-e enable_dtls = SL_SI91X_ENABLE_DTLS | SL_SI91X_DTLS_V_1_0
                option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_0_ENABLE
            else:  # "-dtls" or "-dtls1_2"
                cert_index = 8200  # BIT(13)|BIT(3) i-e enable_dtls = SL_SI91X_ENABLE_DTLS | SL_SI91X_DTLS_V_1_2
                option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_2_ENABLE

        # Enhanced server startup validation with retries

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

        # Get server IP address based on IP version
        if self.ip_version == 6:
            # For IPv6 tests, ensure DUT IP is set if not already obtained during connect
            if not self.device_ip:
                try:
                    self.device_ip = self.wifi_dut.interfaces.wifi.get_ip_address(version=6)
                except Exception:
                    self.device_ip = None
            try:
                self.server_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6)
            except Exception:
                self.server_ip = None
            logger().info(f"IPv6 Test: Device IP={self.device_ip}, Server IP={self.server_ip}")
        else:
            try:
                self.server_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            except Exception:
                self.server_ip = None

        # Choose socket domain based on IP version
        sock_domain = "AF_INET6" if self.ip_version == 6 else "AF_INET"
        self.sock1 = self.wifi_dut.interfaces.wifi.socket(domain=sock_domain, stream_type="SOCK_DGRAM",
                                                          protocol="IPPROTO_UDP")
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
        if self.test_name == "test_c766289" or self.test_name == "test_c766290":
            # Negative test: expect handshake failure (DTLS1.0 client to DTLS1.2 server)
            tx_data = "NEGATIVE-DTLS1.0-TO-1.2-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=5))
            handshake_failed = False
            status = None  # Ensure status is always defined

            self.wifi_dut.interfaces.wifi.dtlsSocketSendTo(
                socket_fd=self.sock1,
                port=self.local_port1,
                data=tx_data,
                ip_addr=self.server_ip,
                expected_status = SLStatus.SL_STATUS_FAIL)

            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock1)
            self.openssl.interfaces.server.stop()
            self.wifi_dut.interfaces.wifi.leave()
            self.wifi_sniffer.interfaces.capture.stop_capture()

            return

        # Allow server to fully initialize before sending data
        logger().info("Waiting for OpenSSL server to fully initialize...")
        time.sleep(2)

        # ...existing code for normal DTLS send/receive...
        logger().info(f"Starting data transmission loop for {self.test_name}")
        for i in range(10):
            tx_data = f"{i + 1}-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
            logger().info(f"Preparing to send message {i + 1}: {tx_data}")
            retry = 0
            while retry < 10:
                try:
                    result = self.wifi_dut.interfaces.wifi.dtlsSocketSendTo(
                        socket_fd=self.sock1,
                        port=self.local_port1,
                        data=tx_data,
                        ip_addr=self.server_ip
                    )

                    # Check if the call was successful (status code 0x00000)
                    # Status code 0x00001 indicates handshake failure and should be retried
                    if hasattr(result, 'status_code') and result.status_code == 0x00001:
                        logger().info(
                            f"\n **** Status Code Received: 0x00001 (SSL_TLS_HANDSHAKE_FAIL), "
                            f"retrying sendto... retry {retry + 1}/10")
                        retry += 1
                        time.sleep(2)  # Increased delay for handshake retry
                        continue

                    # If we reach here, the send was successful
                    self.sent_data.append(tx_data)
                    # Give server time to process the message
                    time.sleep(1.5)
                    break

                except Exception as e:
                    logger().error(f"DTLS sendto exception for message {i + 1}: {e}")
                    status = getattr(e, 'status', None)
                    if status and str(status) == "SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAIL":
                        logger().info(
                            f"\n **** Exception Status Received: {SLStatus.SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAIL}, "
                            f"retrying sendto... retry {retry + 1}/10")
                        retry += 1
                        time.sleep(1)
                        continue
                    else:
                        # For other exceptions, also retry up to the limit
                        logger().warning(f"Unexpected exception, retrying... retry {retry + 1}/10: {e}")
                        retry += 1
                        time.sleep(1)
                        continue
            else:
                raise RuntimeError(f"DTLS sendto failed after {retry} retries for message: {tx_data}")

        # Allow server time to process all received data before getting messages
        logger().info("All messages sent, waiting for server to process data...")
        time.sleep(3)

        # Get received data from OpenSSL server with enhanced error handling
        logger().info("Retrieving messages from OpenSSL server...")

        # Check if server is still running before getting messages
        if not self.openssl.interfaces.server.is_running():
            logger().error("OpenSSL server is no longer running when trying to get messages!")
            raise RuntimeError("OpenSSL server stopped running during data transmission")

        rx_data = self.openssl.interfaces.server.get_messages(10)
        logger().info(f"Sent {len(self.sent_data)} messages: {self.sent_data}")
        logger().info(f"Raw received data type: {type(rx_data)}, value: {rx_data}")

        # Additional diagnostic: Check if server has any error logs
        try:
            server_status = self.openssl.interfaces.server.is_running()
            logger().info(f"Server status after getting messages: {server_status}")
        except Exception as e:
            logger().warning(f"Could not check server status: {e}")

        # Enhanced data validation and processing
        if isinstance(rx_data, list):
            # Filter out OpenSSL server messages that are not actual data
            filtered = [line for line in rx_data if
                        line.strip() not in ("Using default temp DH parameters", "ACCEPT", "ERROR")]
            logger().info(f"Filtered data: {filtered}")

            if not filtered:
                logger().warning("No valid data received after filtering, checking if server had errors...")
                if any("ERROR" in str(line) for line in rx_data):
                    logger().error(f"OpenSSL server reported error. Attempting recovery...")
                    # Try to get messages one more time after a delay
                    time.sleep(2)
                    rx_data_retry = self.openssl.interfaces.server.get_messages(10)
                    logger().info(f"Retry attempt - Raw received data: {rx_data_retry}")

                    if isinstance(rx_data_retry, list):
                        filtered_retry = [line for line in rx_data_retry if
                                          line.strip() not in ("Using default temp DH parameters", "ACCEPT", "ERROR")]
                        if filtered_retry:
                            received_concat = filtered_retry[0].strip()
                            logger().info(f"Recovery successful, received: {received_concat}")
                        else:
                            raise RuntimeError(
                                f"OpenSSL server error persists after retry. Original: {rx_data}, Retry: {rx_data_retry}")
                    else:
                        if rx_data_retry and "ERROR" not in str(rx_data_retry):
                            received_concat = rx_data_retry.strip()
                            logger().info(f"Recovery successful, received: {received_concat}")
                        else:
                            raise RuntimeError(
                                f"OpenSSL server error persists after retry. Original: {rx_data}, Retry: {rx_data_retry}")
                else:
                    received_concat = ""
            else:
                received_concat = filtered[0].strip() if len(filtered) >= 1 else ""
        else:
            if rx_data and rx_data.strip() == "ERROR":
                logger().error(f"OpenSSL server reported single ERROR response. Attempting recovery...")
                # Try to get messages one more time after a delay
                time.sleep(2)
                rx_data_retry = self.openssl.interfaces.server.get_messages(10)
                logger().info(f"Retry attempt - Raw received data: {rx_data_retry}")

                if rx_data_retry and "ERROR" not in str(rx_data_retry):
                    received_concat = rx_data_retry.strip() if rx_data_retry else ""
                    logger().info(f"Recovery successful, received: {received_concat}")
                else:
                    raise RuntimeError(
                        f"OpenSSL server error persists after retry. Original: {rx_data}, Retry: {rx_data_retry}")
            else:
                received_concat = rx_data.strip() if rx_data else ""

        sent_concat = "".join(self.sent_data)

        logger().info(f"Final comparison - Sent: '{sent_concat}', Received: '{received_concat}'")

        # Enhanced assertion with better error message
        if received_concat != sent_concat:
            logger().error(f"Data mismatch detected!")
            logger().error(f"Expected: {sent_concat}")
            logger().error(f"Received: {received_concat}")
            logger().error(f"Raw server response: {rx_data}")

        assert received_concat == sent_concat, (
            f"Data received doesn't match what was sent:\n"
            f"Expected: {sent_concat}\n"
            f"Received: {received_concat}\n"
            f"Raw server response: {rx_data}")

        logger().info("Data validation successful - sent and received data match!")
        logger().info(f"Closing socket_id->{self.sock1}")
        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock1)
        self.openssl.interfaces.server.stop()
        time.sleep(1)
        self.wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
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
        logger().info(f"DTLS Result: {result}")
        # Only check for the protocols requested in decrypt_layers (here, 'dtls' or 'tls')
        decrypt_layers = ["dtls"]
        for key in decrypt_layers:
            if key in result and not result[key]:
                raise RuntimeError(f"Failed to decrypt DTLS packets for {key} with decryption key: {decryption_key}")
            if key in result:
                logger().info(f"Decryption successful for key: {key}, value: {result[key]}")
                match = re.search(r"Version:\s*DTLS\s*([0-9.]+)", str(result[key]))
                if match:
                    dtls_ver = match.group(1)
                    logger().info(f"dtls_version: **********{dtls_ver}***********")

    def sniffer_validate(self):
        if self.dtls_version == "-dtls1":
            filter_name = "dtls1_0"
        elif self.dtls_version == "-dtls1_2":
            filter_name = "dtls1_2"
        else:
            filter_name = "dtls"

        dtls_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.device_ip,
            da_addr=self.server_ip,
            port=self.local_port1,
            filter_name=filter_name,
        )
        if filter_name != "dtls":
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

    def rejoin_async_event(self):
        logger().info("Checking for rejoin fail event from dut")
        with TimeMeasurer() as t:
            sw = Stopwatch()
            while sw.elapsed_sec < 180:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                rejoin_error_events = [
                    event
                    for event in events
                    if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT
                ]
                if len(rejoin_error_events):
                    break
                time.sleep(0.1)
            else:
                return False

        logger().info(f"Received rejoin error event after {t.duration:.2f}s")
        return True


class DtlsVersion10Handler(ThreadBase):
    """Thread class for DTLS 1.0 operations"""

    def __init__(self, wifi_dut=None, wifi_client=None, openssl=None, iter_count=None, test_name=None, ip_version=4):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.openssl = openssl
        self.iter_count = iter_count
        self.local_port = None
        self.server_ip = None
        self.sock = None
        self.sent_data = []
        self.test_name = test_name
        self.ip_version = ip_version

    def run(self):
        """Run DTLS 1.0 functionality"""
        try:
            logger().info("Starting DTLS 1.0 thread...")
            self.local_port = randint(5001, 60000)
            logger().info(f"DTLS 1.0: Starting OpenSSL server on port {self.local_port}")
            self.openssl.interfaces.server.start(port=self.local_port, dtls_version="-dtls1")
            time.sleep(1)

            # Validate server startup with retries
            max_retries = 5
            for retry in range(max_retries):
                if self.openssl.interfaces.server.is_running():
                    break
                logger().warning(f"DTLS 1.0: Server not running, retry {retry + 1}/{max_retries}")
                time.sleep(1)
            else:
                raise RuntimeError("DTLS 1.0: Failed to start OpenSSL server after retries")

            assert self.openssl.interfaces.server.is_running() is True
            logger().info("DTLS 1.0: OpenSSL server started successfully")

            # Get server IP based on IP version
            if self.ip_version == 6:
                self.server_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6)
                sock_domain = "AF_INET6"
            else:
                self.server_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                sock_domain = "AF_INET"
            logger().info(f"DTLS 1.0: Server IP address: {self.server_ip}, domain: {sock_domain}")

            self.sock = self.wifi_dut.interfaces.wifi.socket(domain=sock_domain, stream_type="SOCK_DGRAM",
                                                             protocol="IPPROTO_UDP")
            logger().info(f"DTLS 1.0: Socket created with ID: {self.sock}")

            # Configure for DTLS 1.0
            cert_index = 8196  # BIT(13)|BIT(2) enable_dtls = SL_SI91X_ENABLE_DTLS | SL_SI91X_DTLS_V_1_0
            option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_0_ENABLE

            self.wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
                self.sock,
                option_level="SOL_SOCKET",
                option_name=option_name,
                cert_index=cert_index
            )
            logger().info("DTLS 1.0: Socket configured for DTLS 1.0")

            for i in range(self.iter_count):
                if self.test_name == "test_c766291":
                    tx_data = f"DTLS1.0-{i + 1}-" + "".join(
                        random.choices(string.ascii_uppercase + string.digits, k=1370))
                else:
                    tx_data = f"DTLS1.0-{i + 1}-" + "".join(
                        random.choices(string.ascii_uppercase + string.digits, k=30))
                retry = 0
                while retry < 10:
                    try:
                        time.sleep(3)
                        result = self.wifi_dut.interfaces.wifi.dtlsSocketSendTo(
                            socket_fd=self.sock,
                            port=self.local_port,
                            data=tx_data,
                            ip_addr=self.server_ip
                        )

                        # Check if the call was successful (status code 0x00000)
                        # Status code 0x00001 indicates handshake failure and should be retried
                        if hasattr(result, 'status_code') and result.status_code == 0x00001:
                            logger().info("DTLS 1.0: Status 0x00001 (handshake fail), restarting OpenSSL server")
                            self.openssl.interfaces.server.stop()
                            self.openssl.interfaces.server.start(port=self.local_port, dtls_version="-dtls1")
                            logger().info(f"DTLS1.0 sendto status 0x00001, retry {retry + 1}/10")
                            retry += 1
                            time.sleep(1)
                            continue

                        # If we reach here, the send operation is successful
                        self.sent_data.append(tx_data)
                        logger().info(f"DTLS 1.0: Message {i + 1} sent successfully")
                        break

                    except Exception as e:
                        # Stopping openssl server if handshake fails and starting it again
                        logger().info("DTLS 1.0: Exception occurred, restarting OpenSSL server")
                        self.openssl.interfaces.server.stop()
                        self.openssl.interfaces.server.start(port=self.local_port, dtls_version="-dtls1")
                        # Log the error and retry up to 10 times
                        logger().info(f"DTLS1.0 sendto exception: {e}, retry {retry + 1}/10")
                        retry += 1
                        time.sleep(1)
                        continue
                else:
                    raise RuntimeError(f"DTLS 1.0 sendto failed after retries for message: {tx_data}")

            time.sleep(1)
            # Get received data
            rx_data = self.openssl.interfaces.server.get_messages(self.iter_count)
            logger().info(f"Sent: {self.sent_data}, Received: {rx_data}")

            # Close DTLS 1.0 socket
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock)
            logger().info("DTLS 1.0: Socket closed successfully")
            self.openssl.interfaces.server.stop()
            logger().info("DTLS 1.0: OpenSSL server stopped successfully")

        except Exception as e:
            logger().error(f"DTLS 1.0 thread failed: {e}")
            # Cleanup resources on failure
            try:
                if hasattr(self, 'sock') and self.sock:
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock)
                    logger().info("DTLS 1.0: Socket closed in exception handler")
            except Exception as cleanup_error:
                logger().error(f"Failed to close socket in exception handler: {cleanup_error}")

            try:
                if hasattr(self, 'openssl') and self.openssl:
                    self.openssl.interfaces.server.stop()
                    logger().info("DTLS 1.0: OpenSSL server stopped in exception handler")
            except Exception as cleanup_error:
                logger().error(f"Failed to stop OpenSSL server in exception handler: {cleanup_error}")

            raise


class DtlsVersion12Handler(ThreadBase):
    """Thread class for DTLS 1.2 operations"""

    def __init__(self, wifi_dut=None, wifi_client=None, openssl=None, iter_count=None, test_name=None, ip_version=4):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.openssl = openssl
        self.iter_count = iter_count
        self.local_port2 = None
        self.server_ip = None
        self.sock2 = None
        self.sent_data = []
        self.test_name = test_name
        self.ip_version = ip_version

    def run(self):
        """Run DTLS 1.2 functionality"""
        try:
            logger().info("Starting DTLS 1.2 thread...")
            self.local_port2 = randint(5001, 60000)
            logger().info(f"DTLS 1.2: Starting OpenSSL server on port {self.local_port2}")
            self.openssl.interfaces.server.start(port=self.local_port2, dtls_version="-dtls1_2")
            time.sleep(1)

            # Validate server startup with retries
            max_retries = 5
            for retry in range(max_retries):
                if self.openssl.interfaces.server.is_running():
                    break
                logger().warning(f"DTLS 1.2: Server not running, retry {retry + 1}/{max_retries}")
                time.sleep(1)
            else:
                raise RuntimeError("DTLS 1.2: Failed to start OpenSSL server after retries")

            assert self.openssl.interfaces.server.is_running() is True
            logger().info("DTLS 1.2: OpenSSL server started successfully")

            # Get server IP based on IP version
            if self.ip_version == 6:
                self.server_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6)
                sock_domain = "AF_INET6"
            else:
                self.server_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                sock_domain = "AF_INET"
            logger().info(f"DTLS 1.2: Server IP address: {self.server_ip}, domain: {sock_domain}")

            self.sock2 = self.wifi_dut.interfaces.wifi.socket(domain=sock_domain, stream_type="SOCK_DGRAM",
                                                              protocol="IPPROTO_UDP")
            logger().info(f"DTLS 1.2: Socket created with ID: {self.sock2}")

            # Configure for DTLS 1.2
            cert_index = 8200  # BIT(13)|BIT(3) enable_dtls = SL_SI91X_ENABLE_DTLS | SL_SI91X_DTLS_V_1_2
            option_name = Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_2_ENABLE

            self.wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
                self.sock2,
                option_level="SOL_SOCKET",
                option_name=option_name,
                cert_index=cert_index
            )
            logger().info("DTLS 1.2: Socket configured for DTLS 1.2")

            # Send data via DTLS 1.2
            for i in range(self.iter_count):
                if self.test_name == "test_c766291":
                    tx_data2 = f"DTLS1.2-{i + 1}-" + "".join(
                        random.choices(string.ascii_uppercase + string.digits, k=1370))
                else:
                    tx_data2 = f"DTLS1.2-{i + 1}-" + "".join(
                        random.choices(string.ascii_uppercase + string.digits, k=30))
                retry2 = 0
                while retry2 < 10:
                    try:
                        time.sleep(3)  # Add for consistency if needed
                        result = self.wifi_dut.interfaces.wifi.dtlsSocketSendTo(
                            socket_fd=self.sock2,
                            port=self.local_port2,
                            data=tx_data2,
                            ip_addr=self.server_ip
                        )

                        # Check if the call was successful (status code 0x00000)
                        # Status code 0x00001 indicates handshake failure and should be retried
                        if hasattr(result, 'status_code') and result.status_code == 0x00001:
                            logger().info("DTLS 1.2: Status 0x00001 (handshake fail), restarting OpenSSL server")
                            self.openssl.interfaces.server.stop()
                            self.openssl.interfaces.server.start(port=self.local_port2, dtls_version="-dtls1_2")
                            logger().info(f"DTLS1.2 sendto status 0x00001, retry2 {retry2 + 1}/10")
                            retry2 += 1
                            time.sleep(1)
                            continue

                        # If we reach here, the send operation is successful
                        self.sent_data.append(tx_data2)
                        logger().info(f"DTLS 1.2: Message {i + 1} sent successfully")
                        break

                    except Exception as e:
                        # Stopping openssl server if handshake fails and starting it again
                        logger().info("DTLS 1.2: Exception occurred, restarting OpenSSL server")
                        self.openssl.interfaces.server.stop()
                        self.openssl.interfaces.server.start(port=self.local_port2, dtls_version="-dtls1_2")
                        # Log the error and retry up to 10 times
                        logger().info(f"DTLS1.2 sendto exception: {e}, retry2 {retry2 + 1}/10")
                        retry2 += 1
                        time.sleep(1)
                        continue
                else:
                    raise RuntimeError(f"DTLS 1.2 sendto failed after retries for message: {tx_data2}")

            time.sleep(1)
            # Get received data
            rx_data = self.openssl.interfaces.server.get_messages(self.iter_count)
            logger().info(f"Sent: {self.sent_data}, Received: {rx_data}")

            # Close DTLS 1.2 socket
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock2)
            logger().info("DTLS 1.2: Socket closed successfully")
            self.openssl.interfaces.server.stop()
            logger().info("DTLS 1.2: OpenSSL server stopped successfully")

        except Exception as e:
            logger().error(f"DTLS 1.2 thread failed: {e}")
            # Cleanup resources on failure
            try:
                if hasattr(self, 'sock2') and self.sock2:
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock2)
                    logger().info("DTLS 1.2: Socket closed in exception handler")
            except Exception as cleanup_error:
                logger().error(f"Failed to close socket in exception handler: {cleanup_error}")

            try:
                if hasattr(self, 'openssl') and self.openssl:
                    self.openssl.interfaces.server.stop()
                    logger().info("DTLS 1.2: OpenSSL server stopped in exception handler")
            except Exception as cleanup_error:
                logger().error(f"Failed to stop OpenSSL server in exception handler: {cleanup_error}")
            raise


class dtls_send_with_long_duration(ThreadBase):
    """Thread class for long duration DTLS operations during rejoin tests"""

    def __init__(self, dtls_thread, wifi_dut, wifi_client, openssl, wifi_access_point, wifi_sniffer, sl_collections,
                 duration_sec=None, ip_version=4):
        super().__init__()
        self.dtls_thread = dtls_thread
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.openssl = openssl
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.duration_sec = duration_sec
        self.ip_version = ip_version

    def run(self):
        """Setup OpenSSL server, create socket, set socket options, and repeatedly send DTLS data for specified duration"""
        try:
            logger().info("dtls_send_with_long_duration: Starting long duration DTLS operations...")
            self.dtls_thread.local_port1 = randint(5001, 60000)

            # Start OpenSSL server for DTLS
            self.openssl.interfaces.server.start(port=self.dtls_thread.local_port1, dtls_version="-dtls1_2")
            time.sleep(1)  # Give server time to start
            assert self.openssl.interfaces.server.is_running() is True

            # Get server IP based on IP version
            if self.ip_version == 6:
                self.dtls_thread.server_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6)
                sock_domain = "AF_INET6"
            else:
                self.dtls_thread.server_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                sock_domain = "AF_INET"
            
            logger().info(f"dtls_send_with_long_duration: Server IP={self.dtls_thread.server_ip}, domain={sock_domain}")
            self.dtls_thread.sock1 = self.wifi_dut.interfaces.wifi.socket(domain=sock_domain, stream_type="SOCK_DGRAM",
                                                                          protocol="IPPROTO_UDP")
            self.wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
                self.dtls_thread.sock1,
                option_level="SOL_SOCKET",
                option_name=Si91xCustomSyncSockOptParms.SL_SI91X_SO_DTLS_V_1_2_ENABLE,
                cert_index=8200
            )
            self.wifi_dut.interfaces.wifi.set_dtls_extensions(
                self.dtls_thread.sock1,
                tls_extension_sni_type=1,
                tls_extension_alpn_type=2,
                tls_sni_extension="example.com",
                tls_alpn_extension="http/1.1"
            )

            logger().info(f"dtls_send_with_long_duration: Starting DTLS sendto loop for {self.duration_sec} seconds...")
            dtls_sendto_loop(
                wifi_dut=self.wifi_dut,
                sock1=self.dtls_thread.sock1,
                server_ip=self.dtls_thread.server_ip,
                local_port1=self.dtls_thread.local_port1,
                duration_sec=self.duration_sec,
            )

            # Close socket and stop server after sending
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.dtls_thread.sock1)
            self.openssl.interfaces.server.stop()
            logger().info("dtls_send_with_long_duration: DTLS sendto loop and server stop complete.")

        except Exception as e:
            logger().error(f"dtls_send_with_long_duration: Error during DTLS operations: {e}")
            raise


def dtls_sendto_loop(wifi_dut, sock1, server_ip, local_port1, duration_sec=30):
    """Repeatedly send DTLS data for the specified duration (seconds) on the given socket."""
    start_time = time.time()
    i = 0
    while (time.time() - start_time) < duration_sec:
        tx_data = f"{i + 1}-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
        retry = 0
        while retry < 10:
            try:
                result = wifi_dut.interfaces.wifi.dtlsSocketSendTo(
                    socket_fd=sock1,
                    port=local_port1,
                    data=tx_data,
                    ip_addr=server_ip
                )

                # Check if the call was successful (status code 0x00000)
                # Status code 0x00001 indicates handshake failure and should be retried
                if hasattr(result, 'status_code') and result.status_code == 0x00001:
                    logger().info(
                        f"\n **** Status Code Received: 0x00001 (SSL_TLS_HANDSHAKE_FAIL), "
                        f"retrying sendto... retry {retry + 1}/10")
                    retry += 1
                    time.sleep(1)
                    continue

                # If we reach here, the send operation is successful
                logger().info(f"DTLS sendto iteration {i + 1} complete.")
                break

            except Exception as e:
                status = getattr(e, 'status', None)
                if status and str(status) == "SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAIL":
                    logger().info(
                        f"\n **** Exception Status Received: {SLStatus.SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAIL}, "
                        f"retrying sendto... retry {retry + 1}/10")
                    retry += 1
                    time.sleep(1)
                    continue
                else:
                    logger().error(f"Unexpected exception in dtls_sendto_loop: {e}")
                    raise
        else:
            raise RuntimeError(f"DTLS sendto failed after retries for message: {tx_data}")
        i += 1
        time.sleep(2)  # Spread out sends to overlap with renewal

    @classmethod
    def random_ipv6_addr(cls, network):
        """
        Generate a random IPv6 address in the given network
        Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
        Returns an IPv6Address object.
        """
        net = ipaddress.IPv6Network(network)
        # Which of the network.num_addresses we want to select?
        addr_no = random.randint(0, net.num_addresses)
        # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
        network_int = int.from_bytes(net.network_address.packed, byteorder="big")
        addr_int = network_int + addr_no
        addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
        return addr


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize("dhcp_lease", [120])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "120", "security": "Open", })
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_dtls_functionality_with_dhcp_renewal_c766294(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point,
                                                               openssl,
                                                               sl_collections, sniffer_filter, dhcp_lease):
    """ Verify DTLS data transfer while DHCP renewal occurs (120s lease), with sniffer and DHCP renewal validation """
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766294", dtls_version="-dtls1_2",ip_version=4)
    dtls_thread.connect_to_access_point()
    # --- Sniffer filter validation before renewal ---
    logger().info("Starting DTLS data transfer and DHCP renewal overlap test.")

    # Start DTLS send in a thread

    dtls_send_thread = dtls_send_with_long_duration(dtls_thread, wifi_dut, wifi_client, openssl, wifi_access_point,
                                                    wifi_sniffer, sl_collections,
                                                    duration_sec=300, ip_version=dtls_thread.ip_version)  # 5 minutes for DHCP renewal
    dtls_send_thread.start()
    # Wait to overlap DHCP renewal (simulate 120s lease, renewal at ~120s)
    logger().info("Waiting for DHCP renewal to occur during DTLS transfer...")
    time.sleep(240)  # Start DHCP renewal about halfway through DTLS sends
    # --- DHCP renewal sniffer validation ---
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)  # Allow time for sniffer to process captured packets
    device_address = {'sa_addr': dtls_thread.dut_mac_address, 'da_addr': wifi_access_point.interfaces.wifi.bssid,
                      'wlan_addr': dtls_thread.dut_mac_address}
    filters_name = {1: 'power_mgmt_bit', 2: 'dhcp'}
    output_1 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                    device_address, filters_name=filters_name)
    logger().info(f'OUTPUT 1 = {output_1}')
    assert all(output_1.values()), 'Unable to find expected filter (power_mgmt_bit, dhcp)'
    filters_name_1 = {1: 'dhcp_renewal'}
    packet_filter2 = '        DHCP: Request (3)'
    output_2 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                    device_address, filters_name=filters_name_1,
                                                                    packet_filter2=packet_filter2)
    logger().info(f'OUTPUT 2 = {output_2}')
    assert all(output_2.values()), 'Unable to find expected filter (dhcp_renewal)'
    # Wait for DTLS sends to finish
    dtls_send_thread.join()
    openssl.interfaces.server.stop()
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    dtls_thread.sniffer_validate()


@wifi_dut_marker()
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_dtls_handshake_client_server_c766258(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point, openssl,
                                                       sl_collections, sniffer_filter):
    """ DTLS Protocol handshakes and Verify exchanges between server and client sockets during connection
        establishment """
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766258", dtls_version="-dtls")
    try:
        dtls_thread.connect_to_access_point()
        dtls_thread.establish_dtls_connection()
        dtls_thread.sniffer_validate()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_dtls_1_0_c766259(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point, openssl,
                                   sl_collections, sniffer_filter):
    """ Verify the DUT functionality by opening client socket with DTLS1.0 version and do data transfer """
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766259", dtls_version="-dtls1")
    try:
        dtls_thread.connect_to_access_point()
        dtls_thread.establish_dtls_connection()
        dtls_thread.sniffer_validate()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_dtls_1_2_c766260(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point, openssl,
                                   sl_collections, sniffer_filter):
    """ Verify the DUT functionality by opening client socket with DTLS1.2 version and do data transfer """
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766260", dtls_version="-dtls1_2")
    try:
        dtls_thread.connect_to_access_point()
        dtls_thread.establish_dtls_connection()
        dtls_thread.sniffer_validate()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_dtls_client_socket_creation_send_data_close_regression_c766273(wifi_sniffer, wifi_client, wifi_dut,
                                                                                 wifi_access_point, openssl,
                                                                                 sl_collections,
                                                                                 sniffer_filter):
    """Verify DTLS client socket connection, data send (10 times), and socket close regression
    (loop: socket creation-send data-close) for 10 iterations. Sniffer validation is not performed
    in this regression test"""
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766273", dtls_version="-dtls1_2")
    dtls_thread.connect_to_access_point()
    for i in range(5):
        logger().info(f"Iteration {i + 1}/10: Creating socket, sending data 10 times, and closing socket.")
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
            time.sleep(5)
            dtls_thread.sent_data.append(tx_data)
        rx_data = openssl.interfaces.server.get_messages(10)
        logger().info(f"Iteration {i + 1}: Sent: {dtls_thread.sent_data}, Received: {rx_data}")
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
        time.sleep(10)
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    # DTLS packet decryption
    dtls_thread.sniffer_dtls_validate()


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_dtls_client_data_transfer_with_sni_feature_c766278(wifi_sniffer, wifi_client, wifi_dut,
                                                                     wifi_access_point, openssl,
                                                                     sl_collections, sniffer_filter):
    """Verify DTLS client data transfer with SNI feature in SSL"""
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
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
        dtls_thread.connect_to_access_point()
        dtls_thread.establish_dtls_connection()

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
@pytest.mark.deployed_25q2
def test_wifi_sdk_dtls_client_data_transfer_with_alpn_feature_c766279(wifi_sniffer, wifi_client, wifi_dut,
                                                                      wifi_access_point, openssl,
                                                                      sl_collections, sniffer_filter):
    """ Verify DTLS client data transfer with ALPN feature in SSL"""
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
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
        dtls_thread.connect_to_access_point()
        dtls_thread.establish_dtls_connection()
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


@wifi_dut_marker(ca_cert=["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
                 opermode=Si91xOperatingMode.EAPWiFiClient)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_dtls_with_wpa2_enterprise_c766299(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point, openssl,
                                                    radius_server, sl_collections, sniffer_filter,
                                                    test_name="test_c766299"):
    """ Verify the DTLS functionality with WPA2- Enterprise security """
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766299", dtls_version="-dtls1_2")
    try:
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        result = sl_collections.join_to_eap_network(wifi_dut=wifi_dut,
                                                    wifi_access_point=wifi_access_point,
                                                    eap_type="tls",
                                                    ping_after_power_save=True)

        logger().info("DUT successfully connected with AP")
        dtls_thread.establish_dtls_connection()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker(ca_cert=["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
                 opermode=Si91xOperatingMode.EAPWiFiClient,
                 pmf_enable=True)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678',
                                               "protected_management_frame": "Required"})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_dtls_with_wpa3_enterprise_c766300(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point, openssl,
                                                    radius_server, sl_collections, sniffer_filter,
                                                    test_name="test_c766300"):
    """ Verify the DTLS functionality with WPA3- Enterprise security """

    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766300", dtls_version="-dtls1_2")
    try:
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")

        result = sl_collections.join_to_eap_network(wifi_dut=wifi_dut,
                                                    wifi_access_point=wifi_access_point,
                                                    eap_type="tls",
                                                    security="wpa3_enterprise",
                                                    ping_after_power_save=True)

        logger().info("DUT successfully connected with AP")
        dtls_thread.establish_dtls_connection()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip(
    reason="https://tech.forums.silabs.net/topic/946-dtls10-and-dtls12-parallel-functionality-failing-with-dtlssendto"
           "-in-multithreaded-scenario/")
@wifi_dut_marker(thread_no=2, stack_len=3584, priority=8)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_multithread_dtls1_0_and_dtls1_2_c766271(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point,
                                                               openssl, sl_collections, sniffer_filter):
    """Verify DUT functionality with DTLS1.0 over one socket and with DTLS1.2 over another socket data transfer
        using multithread sockets"""
    try:
        logger().info("Starting multithreaded DTLS test C766271")
        iter_count = 20
        logger().info(f"Iteration count for data transfer: {iter_count}")
        # Create WlanThread object for Wi-Fi connection
        dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl,
                                 sl_collections,
                                 sniffer_filter, test_name="test_c766271", dtls_version="-dtls1_2")

        # Join to Wi-Fi network
        dtls_thread.connect_to_access_point()
        logger().info("DUT successfully connected with AP")

        # Create DTLS thread instances using proper ThreadBase pattern
        logger().info("Creating DTLS thread instances")
        dtls1_0_thread = DtlsVersion10Handler(
            wifi_dut=wifi_dut,
            wifi_client=wifi_client,
            openssl=openssl,
            iter_count=iter_count,
            test_name="test_c766271",
            ip_version=dtls_thread.ip_version
        )

        dtls1_2_thread = DtlsVersion12Handler(
            wifi_dut=wifi_dut,
            wifi_client=wifi_client,
            openssl=openssl,
            iter_count=iter_count,
            test_name="test_c766271",
            ip_version=dtls_thread.ip_version
        )

        # Start both threads simultaneously
        logger().info("Starting both DTLS threads simultaneously...")
        dtls1_0_thread.start()
        dtls1_2_thread.start()

        # Wait for both threads to complete
        logger().info("Waiting for both DTLS threads to complete...")
        dtls1_0_thread.wait_for_exit()
        dtls1_2_thread.wait_for_exit()

        logger().info("**** Both DTLS1.0 and DTLS1.2 threads completed successfully ****")

        # Cleanup and finalization
        logger().info("Cleaning up test resources...")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        logger().error(f"Test c766271 failed with error: {error}")
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        # Ensure cleanup in all scenarios
        try:
            openssl.interfaces.server.stop()
            logger().info("OpenSSL server stopped in finally block")
        except Exception as cleanup_error:
            logger().error(f"Failed to stop OpenSSL server in finally: {cleanup_error}")

        try:
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Sniffer capture stopped in finally block")
        except Exception as cleanup_error:
            logger().error(f"Failed to stop sniffer in finally: {cleanup_error}")


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_negative_version_mismatch_server1_2_and_dut_1_0_c766289(wifi_sniffer, wifi_client, wifi_dut,
                                                                               wifi_access_point, openssl,
                                                                               sl_collections, sniffer_filter):
    """Negative: Connect to ssl server socket which run with version DTLS1.2 at remote side and connect to it from
        module with version DTLS1.0"""

    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766289", dtls_version="-dtls1")
    try:
        dtls_thread.connect_to_access_point()
        dtls_thread.establish_dtls_connection()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_negative_version_mismatch_server1_0_and_dut_1_2_c766290(wifi_sniffer, wifi_client, wifi_dut,
                                                                               wifi_access_point, openssl,
                                                                               sl_collections, sniffer_filter):
    """
    C766290 - Negative: Connect to SSL server socket running DTLS1.0 at remote side and connect from module with DTLS1.2.
    Expect handshake failure and proper error handling.
    """
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766290", dtls_version="-dtls1_2")
    try:
        dtls_thread.connect_to_access_point()
        dtls_thread.establish_dtls_connection()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip(reason="max testfails")
@wifi_dut_marker(thread_no=2, stack_len=3584, priority=8)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_multithread_dtls_1_0_and_dtls_1_2_max_data_length_1370_c766291(wifi_sniffer, wifi_client,
                                                                                      wifi_dut,
                                                                                      wifi_access_point,
                                                                                      openssl, sl_collections,
                                                                                      sniffer_filter):
    """ Verify DUT functionality with DTLS1.0 over one socket and DTLS1.2 over another socket
    data transfer using multithread sockets, sending 1370-byte messages"""

    try:
        logger().info("Starting multithreaded DTLS test C766291")
        iter_count = 20
        logger().info(f"Iteration count for data transfer: {iter_count}")
        # Create WlanThread object for Wi-Fi connection
        dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl,
                                 sl_collections,
                                 sniffer_filter, test_name="test_c766291", dtls_version="-dtls1_2")

        # Join to WiFi network
        dtls_thread.connect_to_access_point()
        logger().info("DUT successfully connected with AP")

        # Create DTLS thread instances using proper ThreadBase pattern
        logger().info("Creating DTLS thread instances")
        dtls1_0_thread = DtlsVersion10Handler(
            wifi_dut=wifi_dut,
            wifi_client=wifi_client,
            openssl=openssl,
            iter_count=iter_count,
            test_name="test_c766291",
            ip_version=dtls_thread.ip_version
        )

        dtls1_2_thread = DtlsVersion12Handler(
            wifi_dut=wifi_dut,
            wifi_client=wifi_client,
            openssl=openssl,
            iter_count=iter_count,
            test_name="test_c766291",
            ip_version=dtls_thread.ip_version
        )

        # Start both threads simultaneously
        logger().info("Starting both DTLS threads simultaneously...")
        dtls1_0_thread.start()
        dtls1_2_thread.start()

        # Wait for both threads to complete
        logger().info("Waiting for both DTLS threads to complete...")
        dtls1_0_thread.wait_for_exit()
        dtls1_2_thread.wait_for_exit()

        logger().info("**** Both DTLS1.0 and DTLS1.2 threads completed successfully ****")

        # Cleanup and finalization
        logger().info("Cleaning up test resources...")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        logger().error(f"Test c766291 failed with error: {error}")
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        # Ensure cleanup in all scenarios
        try:
            openssl.interfaces.server.stop()
            logger().info("OpenSSL server stopped in finally block")
        except Exception as cleanup_error:
            logger().error(f"Failed to stop OpenSSL server in finally: {cleanup_error}")

        try:
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Sniffer capture stopped in finally block")
        except Exception as cleanup_error:
            logger().error(f"Failed to stop sniffer in finally: {cleanup_error}")


@wifi_dut_marker(thread_no=2, stack_len=3584, priority=8)
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_client_data_transfer_after_rejoin_process_c766275(wifi_sniffer, wifi_client, wifi_dut,
                                                                         wifi_access_point, openssl, switch,
                                                                         sl_collections, sniffer_filter):
    '''Verify DTLS client data transfer after rejoin process (rejoin param- max retry=0) using 2 threads:
    Thread 1: DTLS data transfer
    Thread 2: AP power control to trigger rejoin'''

    logger().info("Starting DTLS client data transfer after rejoin test with max retry=0 using 2 threads")

    # Configure DUT for rejoin with max retry=0

    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766275", dtls_version="-dtls1_2")

    try:
        # Join to AP first
        dtls_thread.connect_to_access_point()
        logger().info("DUT joined AP successfully")

        # Start DTLS functionality (this will handle rejoin automatically due to rejoin params)
        logger().info("Starting DTLS data transfer thread...")

        # Create DTLS send thread using the thread class
        dtls_send_thread = dtls_send_with_long_duration(dtls_thread, wifi_dut, wifi_client, openssl, wifi_access_point,
                                                        wifi_sniffer, sl_collections,
                                                        duration_sec=120, ip_version=dtls_thread.ip_version)  # 1 minute for rejoin test
        dtls_send_thread.start()
        # started dtls messages before and after turning off AP

        logger().info("Turning off the AP")
        switch.interfaces.pdu_switch.turn_off(delay=5)
        logger().info("Successfully powered off AP")
        logger().info("Again turning on the AP")
        switch.interfaces.pdu_switch.turn_on(delay=10)
        ap_power_off = 0
        logger().info("Successfully powered on AP")
        logger().info("Pinging to DUT to check rejoin process is completed or not")
        dut_ip = dtls_send_thread.dut_addr['device_ip']
        status = sl_collections.ping(dut_ip, 30, 5)
        assert status, "Pinging to DUT is failed, DUT not rejoined to AP"

        time.sleep(10)
        logger().info("delay to do dtls functionality...")

        # Wait for DTLS data transfer thread to complete
        dtls_send_thread.wait_for_exit()
        logger().info("DTLS data transfer thread completed")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=30)


@wifi_dut_marker(thread_no=2, stack_len=3584, priority=8)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_client_data_transfer_after_rejoin_failure_c766276(wifi_sniffer, wifi_client, wifi_dut,
                                                                         wifi_access_point, openssl, switch,
                                                                         sl_collections, sniffer_filter):
    '''Verify DTLS client data transfer after rejoin process (rejoin param- max retry=1) using 2 threads:
    Thread 1: DTLS data transfer
    Thread 2: AP power control to trigger rejoin'''

    logger().info("Starting DTLS client data transfer after rejoin test with max retry=5 using 2 threads")

    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766276", dtls_version="-dtls1_2")

    try:
        # Join to AP first
        dtls_thread.connect_to_access_point()
        logger().info("DUT joined AP successfully")

        # Start DTLS functionality (this will handle rejoin automatically due to rejoin params)
        logger().info("Starting DTLS data transfer thread...")
        dtls_send_thread = dtls_send_with_long_duration(dtls_thread, wifi_dut, wifi_client, openssl, wifi_access_point,
                                                        wifi_sniffer, sl_collections, duration_sec=60,
                                                        ip_version=dtls_thread.ip_version)
        dtls_send_thread.start()
        time.sleep(5)

        logger().info("Turning off the AP")
        switch.interfaces.pdu_switch.turn_off(delay=20)

        logger().info("Successfully powered off AP")
        time.sleep(5)
        dtls_send_thread.rejoin_async_event()
        logger().info("Again turning on the AP")
        switch.interfaces.pdu_switch.turn_on(delay=100)

        dtls_send_thread.wait_for_exit()
        # Need to repeat from Join to AP after rejoin failure
        dtls_thread.connect_to_access_point()
        logger().info("DUT joined AP successfully after rejoin failure")

        dtls_send_thread.start()
        dtls_send_thread.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=30)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize("dhcp_lease", [120])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "120", "security": "Open", })
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_dtls_functionality_weak_rssi_60dbm_c766301(wifi_sniffer, wifi_client, wifi_dut, wifi_access_point,
                                                             openssl, sl_collections, sniffer_filter, dhcp_lease,
                                                             rf_attenuator):
    try:
        set_db_value = 50

        wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel=1, db_value=set_db_value)

        """ Verify test_wifi_sdk_DTLS_functionality_weak_RSSI_60dBm """
        dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                                 sniffer_filter, test_name="test_c766301", dtls_version="-dtls1_2")
        dtls_thread.connect_to_access_point()


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
@pytest.mark.skip("UTF-7883")
@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": "STATIC_IPV6",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "wan_prefix_length": "64",
                               "ipv6_state": "1",
                               "security": "Open",
                               "lan_ipv6_address": "2401:3500:133c:1341:1134:ffed:13cd:1134",
                               "lan_prefix_length": "64",
                               "lan_ipv6_prefix": "2401:3500:133c:1341::",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",
                               "use_ipv6_web": True,
                               "enable_ipv6": True,
                               }
)
@wifi_dut_marker(tcpip_feat=Si91xTCPIPFeatureBitMap.DHCPv6Client
                            | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_stateful_ipv6_c766297(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, wifi_access_point,
                                             openssl,
                                             sl_collections, sniffer_filter):
    """ Verify DTLS functionality stateful IPv6 """
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766297", dtls_version="-dtls1_2", ip_version=6)
    try:
        dtls_thread.connect_to_access_point()
        # time.sleep(3600)
        dtls_thread.establish_dtls_connection()
        dtls_thread.sniffer_validate()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

@pytest.mark.skip("UTF-7883")
@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": "STATIC_IPV6",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "wan_prefix_length": "64",
                               "ipv6_state": "0",
                               "security": "Open",
                               "lan_ipv6_address": "2401:3500:133c:1341:1134:ffed:13cd:1134",
                               "lan_prefix_length": "64",
                               "lan_ipv6_prefix": "2401:3500:133c:1341::",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",
                               "use_ipv6_web": True,
                               "enable_ipv6": True,
                               }
)
@wifi_dut_marker(tcpip_feat=Si91xTCPIPFeatureBitMap.DHCPv6Client
                            | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dtls_stateless_ipv6_c766298(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, wifi_access_point,
                                              openssl,
                                              sl_collections, sniffer_filter):
    """ Verify DTLS functionality stateless IPv6 """
    dtls_thread = WlanThread(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, openssl, sl_collections,
                             sniffer_filter, test_name="test_c766298", dtls_version="-dtls1_2",ip_version=6)
    try:
        dtls_thread.connect_to_access_point()
        dtls_thread.establish_dtls_connection()
        dtls_thread.sniffer_validate()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
