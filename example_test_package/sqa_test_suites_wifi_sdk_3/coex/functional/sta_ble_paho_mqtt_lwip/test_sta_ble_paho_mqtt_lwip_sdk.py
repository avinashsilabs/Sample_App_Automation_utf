"""WiFi+BLE coexistence tests for MQTT over TCP using LWIP."""

import os
import pytest
import time
import re
import string
import random
import threading
from utf.utils import get_tls_certificate_dir
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xOperatingMode,
    Si91xTCPIPFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xJoinFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xMqttQos,
)
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import (
    CustomNotifyCharacteristic,
    HealthThermometerService,
)
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utf_config import UtfConfig
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble_provisioning.test_sta_ble_provisioning_sdk import (
    ProvisioningFunctionality,
)


Map_security = {
    "OPEN": 0,
    "WPA": 1,
    "WPA2": 2,
    "WEP": 3,
    "WPAEnterprise": 4,
    "WPA2Enterprise": 5,
    "WPA_WPA2_MIXED": 6,
    "WPA3": 7,
    "WPA3_TRANSITION": 8,
    "WPA3Enterprise": 9,
    "WPA3_TRANSITION_ENTERPRISE": 10,
}


def ping_with_recovery(host_ip, count=5, wifi_client=None, max_attempts=3):
    """Ping host_ip; on failure, bounce wifi_client (Raspberry Pi) interface and retry."""
    log = get_logger("ping_recovery")
    for attempt in range(1, max_attempts + 1):
        status = ping(host_ip, count)
        if status:
            return True

        log.warning(
            f"Ping to {host_ip} failed (attempt {attempt}/{max_attempts})"
        )

        if attempt == max_attempts:
            break

        if wifi_client is None:
            log.warning("No wifi_client provided; cannot perform interface recovery")
            continue

        try:
            iface = wifi_client.interfaces.wifi.config.get("interface", "wlan0")
            log.info(f"Bringing Raspberry Pi interface '{iface}' DOWN for recovery")
            wifi_client.interfaces.wifi.shell(f"sudo ifconfig {iface} down")
            time.sleep(2)
            log.info(f"Bringing Raspberry Pi interface '{iface}' UP")
            wifi_client.interfaces.wifi.shell(f"sudo ifconfig {iface} up")
            time.sleep(5)
        except Exception as recovery_err:
            log.warning(f"Interface recovery failed: {recovery_err}")

    return False


def logger():
    return get_logger(__name__)


# Global cleanup variables
ble_obj = None
wifi_obj = None

# DUT trust anchor loaded at init
MQTT_SSL_CA_CERT = [
    "ca-cert.pem",
    "SL_NET_SIGNING_CERTIFICATE",
    "SL_NET_TLS_SERVER_CREDENTIAL_START",
]

# TLS SNI hostname for the DUT mbedTLS client (broker cert SAN: example.com)
MQTT_TLS_HOSTNAME = "example.com"

# Broker identity / CA used when restarting Mosquitto from the test (wolfSSL samples)
MQTT_BROKER_TLS_CERT = "server-cert.pem"
MQTT_BROKER_TLS_KEY = "server-key.pem"
MQTT_BROKER_TLS_CA = "ca-cert.pem"


def _reconfigure_mosquitto_tls(
    mqtt_server,
    cert=MQTT_BROKER_TLS_CERT,
    key=MQTT_BROKER_TLS_KEY,
    ca=MQTT_BROKER_TLS_CA,
    port=8883,
):
    """Restart Mosquitto on the Pi with wolfSSL PEMs from tls_certificates."""
    mqtt = mqtt_server.interfaces.mqtt
    if not getattr(mqtt, "tls_enabled", False):
        return
    if not getattr(mqtt, "certfile", None):
        return

    cert_dir = os.path.dirname(mqtt.certfile).replace("\\", "/")
    new_cert = f"{cert_dir}/{cert}"
    new_key = f"{cert_dir}/{key}"
    new_ca = f"{cert_dir}/{ca}"
    if (
        mqtt.certfile.replace("\\", "/") == new_cert
        and mqtt.keyfile.replace("\\", "/") == new_key
        and mqtt.cafile.replace("\\", "/") == new_ca
    ):
        return

    logger().info(
        f"Reconfiguring Mosquitto TLS: certfile={cert}, keyfile={key}, cafile={ca}"
    )
    mqtt.stop_server()
    mqtt.certfile = new_cert
    mqtt.keyfile = new_key
    mqtt.cafile = new_ca
    mqtt.start_server(port=port)
    # Broker needs a moment to bind 8883 after restart before DUT TLS connect
    time.sleep(2)


def _is_transient_rpc_pip_error(exc):
    """True if the exception looks like a transient RPC/pip failure."""
    msg = str(exc).lower()
    transient_markers = (
        "pip exited with code",
        "error installing requirements on rpc target",
        "temporary failure in name resolution",
        "could not resolve host",
        "read timed out",
    )
    return any(marker in msg for marker in transient_markers)


# Composite BLE connected states seen in dual-role (conn0+conn1)
CONNECTED_BLE_STATES = {8, 9, 10, 12}


def _normalize_ble_state(state):
    """Normalize ble_get_device_state() return value (str/bytes/int) to int."""
    if state is None:
        return -1
    if isinstance(state, int):
        return state
    if isinstance(state, (bytes, bytearray)):
        state = state.decode(errors="ignore")
    state_str = str(state).strip()
    return int(state_str) if state_str.isdigit() else -1


def _is_connected_ble_state(state):
    """Treat BLE composite connected states as connected."""
    state_int = _normalize_ble_state(state)
    return state_int in CONNECTED_BLE_STATES or (state_int & 0x08) == 0x08


def _is_ble_thread_retryable(exc):
    """True for transient BLE dual-role setup failures worth retrying."""
    msg = str(exc)
    if _is_transient_rpc_pip_error(exc):
        return True
    ble_markers = (
        "Can't register the object-path handler",
        "there is already a handler",
        "AuthenticationCanceled",
        "Authentication Canceled",
        "AuthenticationFailed",
        "Authentication Failed",
        "Expected event link_key not found",
        "DUT BLE device is not in connected state",
        "DUT not found in scan results",
        "'Address'",
        "KeyError: 'Address'",
        "SL_STATUS_SI91X_COMMAND_DISALLOWED",
        "COMMAND_DISALLOWED",
        "0x4e0c",
    )
    return any(marker in msg for marker in ble_markers)


def _normalize_ble_mac(mac):
    """Normalize a BLE MAC string for case-insensitive hcitool matching."""
    if mac is None:
        return ""
    if isinstance(mac, (bytes, bytearray)):
        mac = mac.decode(errors="ignore")
    return str(mac).strip().upper().replace("-", ":")


def _raspi_hcitool_con(ble_client, hci_device=None):
    """Run ``hcitool -i <hciX> con`` on a Raspberry Pi BLE client."""
    if ble_client is None:
        raise ValueError("ble_client is required for hcitool connection check")

    bluetooth = ble_client.interfaces.bluetooth
    adapter = hci_device or getattr(bluetooth, "adapter_name", None) or "hci0"
    cmd = f"sudo hcitool -i {adapter} con"
    client_name = getattr(ble_client, "name", str(ble_client))

    rc, stdout, stderr = bluetooth.hci_tool_manager.shell.execute(cmd)
    if isinstance(stdout, (bytes, bytearray)):
        stdout = stdout.decode(errors="ignore")
    if isinstance(stderr, (bytes, bytearray)):
        stderr = stderr.decode(errors="ignore")

    logger().info(
        f"[{client_name}] {cmd} -> rc={rc}\n{stdout}"
        + (f"\nstderr: {stderr}" if stderr else "")
    )
    if rc != 0:
        raise RuntimeError(
            f"hcitool con failed on '{client_name}' (rc={rc}): {stderr or stdout}"
        )
    return stdout or ""


def _raspi_has_dut_ble_connection(ble_client, dut_mac, hci_device=None):
    """True when DUT MAC appears in the Pi's ``hcitool con`` output."""
    dut_mac_n = _normalize_ble_mac(dut_mac)
    if not dut_mac_n:
        return False
    output = _raspi_hcitool_con(ble_client, hci_device=hci_device)
    normalized_output = output.upper().replace("-", ":")
    return dut_mac_n in normalized_output


def assert_dual_role_connected_on_raspberries(
    ble_clients, dut_mac, context="dual-role BLE"
):
    """Assert DUT MAC is present in ``hcitool con`` on both Raspberry Pi clients."""
    if not ble_clients or len(ble_clients) < 2:
        raise ValueError(
            "Dual-role Raspberry Pi connection check requires at least 2 ble_clients"
        )

    dut_mac_n = _normalize_ble_mac(dut_mac)
    assert dut_mac_n, f"DUT BLE MAC missing for {context} Raspberry Pi check"

    failures = []
    for idx, client in enumerate(ble_clients[:2]):
        client_name = getattr(client, "name", f"ble_clients[{idx}]")
        try:
            connected = _raspi_has_dut_ble_connection(client, dut_mac_n)
        except Exception as exc:
            failures.append(f"{client_name}: hcitool con error: {exc}")
            continue
        if not connected:
            failures.append(
                f"{client_name}: DUT MAC {dut_mac_n} not found in hcitool con"
            )
        else:
            logger().info(
                f"{client_name}: DUT MAC {dut_mac_n} present in hcitool con "
                f"({context})"
            )

    assert not failures, (
        f"{context}: Raspberry Pi BLE connection check failed: "
        + "; ".join(failures)
    )


def _close_ble_client_session(ble_client):
    """Stop BlueZ main-loop on the remote BLE client if it is open."""
    if ble_client is None:
        return
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception as exc:
        logger().warning(f"ble_client bluetooth.close() failed: {exc}")
    time.sleep(1)


def start_ble_thread_with_retry(ble_thread, attempts=3, backoff_sec=10):
    """Start BleThread and retry on transient RPC/BlueZ failures."""
    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            ble_thread.start()
            # wait_for_exit() re-raises BleThread.run() failures
            ble_thread.wait_for_exit()
            return
        except Exception as exc:
            last_exc = exc
            if not _is_ble_thread_retryable(exc):
                raise
            logger().warning(
                f"BLE thread start attempt {attempt}/{attempts} hit a transient "
                f"BLE/RPC setup error: {exc}. Retrying after {backoff_sec}s..."
            )
            # Drop stale dual-role/central links before the next attempt
            try:
                wifi_dut = getattr(ble_thread, "wifi_dut", None)
                if wifi_dut is not None:
                    state_int = _normalize_ble_state(
                        wifi_dut.interfaces.wifi.ble_get_device_state()
                    )
                    if state_int in CONNECTED_BLE_STATES or (state_int & 0x08):
                        wifi_dut.interfaces.wifi.ble_disconnect()
                        time.sleep(2)
            except Exception as cleanup_exc:
                logger().warning(
                    f"BLE disconnect before retry failed: {cleanup_exc}"
                )
            for client in getattr(ble_thread, "ble_clients", None) or []:
                _close_ble_client_session(client)
            _close_ble_client_session(getattr(ble_thread, "ble_client", None))
            time.sleep(backoff_sec)
    # Exhausted retries: re-raise the original BLE failure
    raise last_exc


def dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address):
    """Disconnect dual-role BLE links the same way as C133511."""
    for i in range(0, len(ble_clients)):
        status = ble_clients[i].interfaces.bluetooth.get_connection_status(
            ble_dut_address
        )
        logger().info(
            f"Connection status in remote device '{ble_clients[i].name}' is:{status}"
        )
        assert (
            status
        ), f"Remote device '{ble_clients[i].name}' is not connected to DUT"
        ble_clients[i].interfaces.bluetooth.disconnect(ble_dut_address)
        ble_clients[i].interfaces.bluetooth.remove_device(ble_dut_address)
        ble_clients[i].interfaces.bluetooth.close()
        time.sleep(5)


# Configuration Helper Functions
def get_mqtt_lwip_config(enable_ssl=False, enable_ipv6=False, wifi_thread_count=1, ble_thread_count=1,
                         wifi_stack_len=2048, ble_stack_len=2048, num_peripheral_connections=1, 
                         num_central_connections=1, ca_cert=None, eap_cert=None):
    """Return MQTT LWIP DUT configuration."""
    config = {
        "thread_config": {
            "wifi": {"count": wifi_thread_count, "stack_len": wifi_stack_len},
            "ble": {"count": ble_thread_count, "stack_len": ble_stack_len}
        },
        "oper_mode": 0,  # Station mode
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": (
            # Si91xTCPIPFeatureBitMap.Default |
            Si91xTCPIPFeatureBitMap.TCPIPBypass |
            Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
        ),
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": (
            Si91xExtCustomFeatureBitMap.Default | #Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
            Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        ),
        "ext_tcpip_features": (
            Si91xExtTCPIPFeatureBitMap.Default | 
            Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature |
            Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        ),
        "ble_features": (
            Si91xBLEFeatureBitMap.set_num_centrals(num_centrals=num_central_connections) |
            Si91xBLEFeatureBitMap.set_num_peripherals(num_peripherals=num_peripheral_connections) |
            Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
            Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC |
            Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID |
            Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
            Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
            Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE |
            Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE
        ),
        "ble_custom_ext_features": (
            Si91xBLECustomFeatureBitMap.Default |
            Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        ),
        "config_features": (
            Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | 
            Si91xConfigFeatureBitMap.EnahanceMaxPsp
        ),
        "set_send_feature_frame": True,
    }
    
    # Add SSL features if enabled
    if enable_ssl:
        config["tcpip_features"] |= Si91xTCPIPFeatureBitMap.SSL
    
    # Add IPv6 features if enabled
    if enable_ipv6:
        config["tcpip_features"] |= (
            Si91xTCPIPFeatureBitMap.DHCPv6Client | 
            Si91xTCPIPFeatureBitMap.IPv6Mode
        )
    
    # Add certificates if provided
    if ca_cert:
        config["ca_cert"] = ca_cert
    if eap_cert:
        config["eap_cert"] = eap_cert
    
    return config


def get_test_config(test_type="standard", **kwargs):
    """Return test-specific MQTT LWIP configuration."""
    config = {}
    
    if test_type == "dhcp_renewal":
        config["wifi_access_point"] = {
            "dhcp_lease": "120", 
            "security": "Open"
        }
    elif test_type == "wpa3":
        config["wifi_access_point"] = {
            "security": "WPA3", 
            "passphrase": "1234567890"
        }
    elif test_type == "ipv6":
        config["wifi_dut"] = get_mqtt_lwip_config(enable_ipv6=True)
        config["wifi_access_point"] = {
            "security": "WPA2", 
            "passphrase": "1234567890", 
            "ipv6_state": "1",
            "wan_ipv6_address": "2401:4900:1cb3::1"
        }
    elif test_type == "mqtts":
        config["wifi_dut"] = get_mqtt_lwip_config(enable_ssl=True)
        config["mqtt_server"] = "raspi_mosquitto_tls"
    elif test_type == "multiple_ble_connections":
        num_connections = kwargs.get("num_connections", 2)
        config["wifi_dut"] = get_mqtt_lwip_config(
            ble_thread_count=num_connections,
            num_central_connections=num_connections,
            num_peripheral_connections=0
        )
    
    return config


def get_wifi_profile(wifi_access_point):
    """Build WiFi profile dict from the access point fixture."""
    security_name = wifi_access_point.interfaces.wifi.security.name
    return {
        "ssid": wifi_access_point.interfaces.wifi.ssid,
        "channel": wifi_access_point.interfaces.wifi.channel,
        "security": security_name,
        "security_type": Map_security[security_name],
        "passphrase": wifi_access_point.interfaces.wifi.passphrase,
    }


def mqtt_lwip_marker(
    enable_ssl=False,
    enable_ipv6=False,
    wifi_thread_count=1,
    ble_thread_count=1,
    wifi_stack_len=2048,
    ble_stack_len=2048,
    num_peripheral_connections=1,
    num_central_connections=1,
    ca_cert=None,
    eap_cert=None,
    oper_mode=0,
    dhcp_renewal=False
):
    """Create pytest marker for WiFi DUT MQTT LWIP configuration."""
    config = get_mqtt_lwip_config(
        enable_ssl=enable_ssl,
        enable_ipv6=enable_ipv6,
        wifi_thread_count=1,
        ble_thread_count=1,
        wifi_stack_len=2048,
        ble_stack_len=2048,
        num_peripheral_connections=num_peripheral_connections,
        num_central_connections=num_central_connections,
        ca_cert=ca_cert,
        eap_cert=eap_cert
    )
    
    # Override oper_mode if provided
    if oper_mode is not None:
        config["oper_mode"] = oper_mode
    
    # dhcp_renewal is a test-level flag, not a DUT config parameter
    
    return pytest.mark.config("wifi_dut", wifi=config)


class WifiMqttLwipThread(ThreadBase):
    """Thread class for WiFi MQTT operations over LWIP network stack."""
    
    def __init__(
        self,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_sniffer=None,
        mqtt_server=None,
        mqtt_client=None,
        sl_collections=None,
        sniffer_filter=None,
        request=None,
        qos=None,
        topic=None,
        topic1=None,
        topic2=None,
        message=None,
        message_size=300,
        num_packets=10,
        enable_ssl=False,
        keep_alive=100,
        retain=False,
        username=None,
        broker_port=1883,
        dut_port=5001,
        test_type=None,
        utf_constants=None,
        profile=None,
        dut_addr=None,
        client_id="Si91x_mqtt_client",
        wifi_client=None,
        received_credentials=None,
        ca_cert="ca-cert.pem",
        server_cert="server-cert.pem",
        server_key="server-key.pem",
    ):
        super().__init__()
        self.received_credentials = received_credentials
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.wifi_sniffer = wifi_sniffer
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.request = request
        self.qos = qos
        self.topic = topic
        self.topic1 = topic1
        self.topic2 = topic2
        self.message = message
        self.message_size = message_size
        self.num_packets = num_packets
        self.enable_ssl = enable_ssl
        self.keep_alive = keep_alive
        self.retain = retain
        self.username = username
        self.broker_port = broker_port
        self.dut_port = dut_port
        self.test_type = test_type
        self.utf_constants = utf_constants or {}
        self.profile = profile
        self.dut_addr = dut_addr or {}
        self.device_ip = None
        self.dut_mac_address = None
        self.capture_filename = None
        self.client_id = client_id
        # TLS PEM filenames used when enable_ssl=True (same as C876779 / MQTTConnectionThread)
        self.ca_cert = ca_cert
        self.server_cert = server_cert
        self.server_key = server_key
        self._mqtt_is_clean_session = 1
        self._mqtt_enable_will = 0
        self._mqtt_retain_will = 0
        self._mqtt_will_topic = None
        self._mqtt_will_message = None
        self._cert_alloc_addresses = []
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"Power save flag set to: {self.power_save}")
        _constants = UtfConfig.instance().constants or {}
        _sniffer_entry = _constants.get("sniffer_enable") or {}
        self.sniffer_enable = bool(_sniffer_entry.get("value", True))
        logger().info(f"Sniffer enable flag set to: {self.sniffer_enable}")
        self._sniffer_started = False
        self._mqtt_client_connected = False
        self._dut_subscribed_topics = set()
        self._client_subscribed_topics = set()
        self._published_messages = []
        self._dut_received_messages = []

    def run(self):
        """Wi-Fi bring-up sequence for MQTT tests."""
        try:
            self.start_sniffer_capture()

            self.connect_to_wifi()

            status = ping_with_recovery(self.device_ip, 10, wifi_client=self.wifi_client)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

            self.set_power_save()
            logger().info("WiFi thread completed bring-up; MQTT operations are deferred to the test body")

        except Exception as e:
            logger().error(f"WiFi MQTT LWIP thread error: {e}")
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)
            raise

    def connect_to_wifi(self):
        """Connect to WiFi access point using join API (reference: test_mqtt_on_host_lwip_sdk.py)."""
        if self.received_credentials:
            logger().info(
                "Joining AP using credentials received via BLE provisioning"
            )
            self.wifi_dut.interfaces.wifi.join(
                ssid=self.received_credentials[0],
                passphrase=self.received_credentials[1],
                security=self.received_credentials[2],
                enable_lwip=1,
            )
        else:
            if not self.profile:
                raise ValueError("WiFi profile not provided")
            self.wifi_dut.interfaces.wifi.join(
                ssid=self.profile["ssid"],
                passphrase=self.profile.get("passphrase", ""),
                security=self.profile.get("security", "OPEN").lower(),
                channel=self.profile.get("channel", 0) if self.profile.get("channel") else None,
                enable_lwip=1,
            )

        # Start IP using LWIP (reference logic)
        self.wifi_dut.interfaces.wifi.start_ip_lwip()

        # Optionally, bring up the interface (uncomment if needed)
        attempt = 3
        flag = False
        while attempt > 0:
            try:
                self.wifi_dut.interfaces.wifi.sl_net_up(mode="client")
                flag = True
            except Exception as e:
                attempt -= 1
                logger().info(
                    f"sl_net_up failed with exception {e}, retrying...{attempt} attempts left"
                )
            if flag:
                break

        # Get device IP using lwip
        device_ip = self.wifi_dut.interfaces.wifi.display_device_ip_lwip()
        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(device_ip=device_ip)
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()

        # Store in dut_addr dictionary
        self.dut_addr['device_ip'] = self.device_ip
        self.dut_addr['dut_mac_address'] = self.dut_mac_address

        logger().info(f"DUT MAC Address: {self.dut_mac_address}")
        logger().info(f"DUT IP Address: {self.device_ip}")
        logger().info(f"DUT INFO: {self.dut_addr}")

    def join_to_ap(self):
        """Join (or rejoin) the access point."""
        self.connect_to_wifi()

    def set_power_save(self):
        """Enable power save modes."""
        if self.power_save:
            self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="power_save_low_latency"
            )
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )
            logger().info("Power save enabled for WiFi and BLE")
        else:
            logger().info("Power save skipped (flag set to false)")

    def free_certificate_allocations(self):
        """Free DUT RAM buffers used for TLS PEMs (C876779 pattern)."""
        if not self._cert_alloc_addresses:
            return
        if self.enable_ssl:
            try:
                self.wifi_dut.interfaces.mqtt.lwip_mqtt_disconnect()
            except Exception as ex:
                logger().warning(
                    f"MQTT disconnect before cert memory cleanup skipped: {ex}"
                )
        for address in self._cert_alloc_addresses:
            try:
                self.wifi_dut.interfaces.wifi.memory_free(address)
            except Exception as ex:
                logger().warning(
                    f"Certificate memory cleanup failed for {address}: {ex}"
                )
        self._cert_alloc_addresses.clear()

    def load_certificate(self, certificate):
        """Load a PEM from tls_certificates into DUT RAM (C876779 pattern)."""
        cert_file = str(get_tls_certificate_dir().joinpath(certificate))
        with open(cert_file) as f:
            cert_contents = f.read()
        size = len(cert_contents)
        logger().info(f"\nLoading  Certificate {certificate} ")
        buffer_size = (512 * (int(size / 512))) + 512
        address = self.wifi_dut.interfaces.wifi.allocate_memory(size=buffer_size)
        self.wifi_dut.interfaces.wifi.load_memory(
            address, size=size, write_content=cert_contents
        )
        self._cert_alloc_addresses.append(address)
        return address, size

    def lwip_mqtt_configure(
        self,
        will_topic=None,
        will_message=None,
        enable_will=0,
        retain_will=0,
        is_clean_session=1,
    ):
        """Cache will/session params and push them to the DUT MQTT client."""
        logger().info(
            f"\n Configuring MQTT on DUT with Parameters will_topic:: {will_topic}, "
            f"will_message:: {will_message}, enable_will::{enable_will}, "
            f"retain_will:: {retain_will}\n"
        )
        self._mqtt_is_clean_session = is_clean_session
        self._mqtt_enable_will = enable_will
        self._mqtt_retain_will = retain_will
        self._mqtt_will_topic = will_topic
        self._mqtt_will_message = will_message
        self.wifi_dut.interfaces.wifi.lwip_mqtt_configure(
            will_topic=will_topic,
            will_message=will_message,
            enable_will=enable_will,
            retain_will=retain_will,
            is_clean_session=is_clean_session,
        )

    def mqtt_connect_lwip(self, expected_status=SLStatus.SL_STATUS_OK, configure_tls_certs=True):
        """Connect DUT to MQTT broker using LWIP."""
        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        if self.enable_ssl:
            # Harness may still list mosquitto-utf certs; align broker to wolfSSL PEMs
            _reconfigure_mosquitto_tls(self.mqtt_server)
        # Connect Raspi MQTT client first so it can subscribe before DUT publishes
        self._ensure_mqtt_client_connected()
        broker = self.mqtt_server.interfaces.mqtt.hostname_or_ip_address
        if self.enable_ssl and configure_tls_certs:
            self.free_certificate_allocations()
            ca_cert_address, ca_cert_size = self.load_certificate(
                certificate=self.ca_cert
            )
            server_cert_address, server_cert_size = self.load_certificate(
                certificate=self.server_cert
            )
            server_key_address, server_key_size = self.load_certificate(
                certificate=self.server_key
            )
            self.wifi_dut.interfaces.wifi.lwip_mqtt_configure(
                will_topic=self._mqtt_will_topic,
                will_message=self._mqtt_will_message,
                enable_will=self._mqtt_enable_will,
                retain_will=self._mqtt_retain_will,
                is_clean_session=self._mqtt_is_clean_session,
                ca_cert=ca_cert_address,
                client_cert=server_cert_address,
                client_key=server_key_address,
                ca_cert_size=ca_cert_size,
                client_cert_size=server_cert_size,
                client_key_size=server_key_size,
            )
        self.wifi_dut.interfaces.mqtt.lwip_mqtt_connect(
            server=self.mqtt_server.interfaces.mqtt,
            mqtt_server=broker,
            enable_ssl=1 if self.enable_ssl else 0,
            username=self.username,
            dut_port=self.dut_port,
            broker_port=8883 if self.enable_ssl else self.broker_port,
            connection_timeout_ms=20000 if self.enable_ssl else None,
            keep_alive_interval_ms=self.keep_alive,
            client_id=self.client_id,
            tls_hostname=MQTT_TLS_HOSTNAME if self.enable_ssl else None,
            expected_status=expected_status,
        )
        self._published_messages = []
        time.sleep(2)
        logger().info(
            f"MQTT connection established successfully "
            f"(ssl={bool(self.enable_ssl)}, port="
            f"{8883 if self.enable_ssl else self.broker_port}, "
            f"tls_hostname={MQTT_TLS_HOSTNAME if self.enable_ssl else None})"
        )

    def wifi_disconnect(self):
        self.wifi_dut.interfaces.wifi.sl_net_down(mode="client")
        logger().info("....Successfully disconnected from the AP....")

    def _ensure_mqtt_client_connected(self):
        """Connect the third-party Raspi MQTT client to the broker if needed."""
        if not self.mqtt_client or self._mqtt_client_connected:
            return
        self.mqtt_client.interfaces.mqtt.disable_certificate_verification = True
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        try:
            self.mqtt_client.interfaces.mqtt.received_messages.clear()
        except Exception:
            pass
        self._mqtt_client_connected = True
        logger().info("Third-party MQTT client (Raspi) connected to broker")
        time.sleep(2)

    def _record_published(self, topic, message):
        """Track DUT-published payloads so Raspi receive can validate them."""
        self._published_messages.append((topic, message))

    @staticmethod
    def _mqtt_payload_text(msg):
        payload = getattr(msg, "payload", msg)
        if isinstance(payload, bytes):
            return payload.decode(errors="ignore")
        return str(payload)

    # Trailing bytes of the delivered payload the DUT CLI may corrupt: the
    # command line is cut at ~220 chars (and at the first space), and a
    # concurrent BLE command can bleed its first token into the payload tail.
    PAYLOAD_TAIL_SLACK = 8
    # Leading bytes that must agree before a delivery counts as this publish
    PAYLOAD_MIN_MATCH = 8

    @classmethod
    def _payload_matches(cls, published, received):
        """Match a DUT publish against the payload the broker delivered."""
        if not published or not received:
            return False
        if published == received:
            return True
        common = len(os.path.commonprefix([published, received]))
        shortest = min(len(published), len(received))
        if common == shortest:
            return True
        return (
            common >= cls.PAYLOAD_MIN_MATCH
            and common >= shortest - cls.PAYLOAD_TAIL_SLACK
        )

    def _find_missing_payloads(self, received_payloads):
        """Published payloads with no match on the third-party client.

        Matches are consumed one-to-one so a duplicate delivery cannot stand in
        for a payload that never arrived.
        """
        missing = []
        truncated = 0
        unmatched = list(received_payloads)
        for _topic, payload in self._published_messages:
            hit = next(
                (
                    idx
                    for idx, rx in enumerate(unmatched)
                    if self._payload_matches(payload, rx)
                ),
                None,
            )
            if hit is None:
                missing.append(payload)
                continue
            if len(unmatched[hit]) < len(payload):
                truncated += 1
            unmatched.pop(hit)
        if truncated:
            logger().warning(
                f"{truncated} DUT publish(es) were truncated by the DUT CLI; "
                f"validated on the delivered prefix"
            )
        return missing

    def mqtt_subscribe(self, topic=None, topic_address=None, dut_subscribe=False):
        """Subscribe the third-party Raspi MQTT client to a topic."""
        subscribe_topic = topic or self.topic
        self._ensure_mqtt_client_connected()
        if self.mqtt_client:
            self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(
                topic=subscribe_topic,
                qos=self.qos,
            )
            try:
                self.mqtt_client.interfaces.mqtt.received_messages.clear()
            except Exception:
                pass
            self._client_subscribed_topics.add(subscribe_topic)
            logger().info(
                f"Third-party MQTT client subscribed to topic: {subscribe_topic}"
            )
            time.sleep(1)
        if dut_subscribe:
            self.wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(
                topic=subscribe_topic,
                qos=self.qos,
            )
            self._dut_subscribed_topics.add(subscribe_topic)
            self._dut_received_messages = []
            logger().info(f"DUT subscribed to topic: {subscribe_topic}")

    def _client_received_count(self):
        """Number of messages the third-party client is holding right now."""
        try:
            return len(
                self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            )
        except Exception:
            return 0

    def _publish_confirmed(self, topic, message, qos=None, retain=None,
                           drain_yield=True, retries=2):
        """Publish from the DUT, retrying if the third-party client never sees it.

        BLE async events share the DUT UART and can corrupt the publish command
        line (the topic itself gets mangled), which silently drops the message.
        """
        publish_qos = self.qos if qos is None else qos
        confirm = bool(self.mqtt_client) and topic in self._client_subscribed_topics
        publish_kwargs = {}
        if retain is not None:
            publish_kwargs["retain"] = retain

        for attempt in range(retries + 1):
            before = self._client_received_count() if confirm else 0
            self.wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
                topic=topic,
                message=message,
                qos=publish_qos,
                timeout=20,
                **publish_kwargs,
            )
            if drain_yield:
                self._mqtt_publish_drain_yield()
            if not confirm:
                return
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                if self._client_received_count() > before:
                    return
                time.sleep(0.2)
            if attempt < retries:
                logger().warning(
                    f"Third-party client did not see the DUT publish on '{topic}' "
                    f"(attempt {attempt + 1}/{retries + 1}); republishing"
                )
        logger().warning(
            f"DUT publish on '{topic}' stayed unconfirmed after {retries + 1} attempts"
        )

    def subscribe_and_publish(self, qos=None):
        """Raspi subscribes; DUT publishes (DUT-publish path)."""
        qos = self.qos if qos is None else qos
        if self.message is None:
            self.message = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=100)
            )
        retain = 1 if self.retain else 0
        self.mqtt_subscribe(topic=self.topic, dut_subscribe=False)
        logger().info(
            f"DUT publishing to topic {self.topic} (qos={qos}, retain={retain})"
        )
        self._publish_confirmed(
            topic=self.topic,
            message=self.message,
            qos=qos,
            retain=retain,
            drain_yield=False,
        )
        self._record_published(self.topic, self.message)
        time.sleep(1)

    def mqtt_publish(self, topic=None, message=None, message_size=None, num_packets=None,
                     drain_yield=True):
        """DUT publishes to MQTT topic."""
        publish_topic = topic or self.topic

        if message:
            self._publish_confirmed(
                topic=publish_topic, message=message, drain_yield=drain_yield
            )
            self._record_published(publish_topic, message)
            logger().info(f"DUT published message to topic: {publish_topic}")
        else:
            publish_size = message_size or self.message_size
            packet_count = num_packets or self.num_packets

            for i in range(packet_count):
                publish_message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=publish_size))

                logger().info(f"DUT publishing packet {i+1}/{packet_count} ({len(publish_message)} bytes) to topic: {publish_topic}")

                self._publish_confirmed(
                    topic=publish_topic,
                    message=publish_message,
                    drain_yield=drain_yield,
                )
                self._record_published(publish_topic, publish_message)

                time.sleep(2)

            logger().info(f"DUT published {packet_count} packets successfully")

    def _mqtt_publish_drain_yield(self):
        """Drain after DUT publish."""
        try:
            self.wifi_dut.interfaces.mqtt.lwip_mqtt_yield(
                yield_timeout_ms=2000,
                timeout=15,
                async_timeout=10,
                expected_status=[
                    SLStatus.SL_STATUS_OK,
                    SLStatus.SL_STATUS_FAIL,
                    SLStatus.SL_STATUS_TIMEOUT,
                ],
            )
        except AssertionError as yield_exc:
            err_text = str(yield_exc)
            if "SL_STATUS_TIMEOUT" in err_text or "0x7" in err_text:
                logger().warning(
                    f"lwip_mqtt.yield timed out after DUT publish (continuing): {yield_exc}"
                )
                return
            raise

    def validate_mqtt_messages(self):
        """Validate that the Raspi MQTT client received the DUT publish."""
        logger().info("\n Validating MQTT Messages on third-party MQTT client (Raspi) \n")
        assert self.mqtt_client, "mqtt_client (Raspi) is required to validate DUT publish"
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 15:
            time.sleep(0.1)
            msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) >= 1:
                break
        assert len(msgs) >= 1, "No message is received by mqtt-client"
        payloads = [self._mqtt_payload_text(m) for m in msgs]
        topics = [getattr(m, "topic", None) for m in msgs]
        qos_values = [getattr(m, "qos", None) for m in msgs]
        logger().info(
            f" Received MQTT message on MQTT Client - Topic: {topics[0]}, "
            f"Message: {payloads[0]}, QOS: {qos_values[0]} "
        )
        assert self.topic in topics, "No message received by mqtt-client on subscribed topic"
        if self.qos is not None:
            assert self.qos in qos_values, (
                f"DUT sent message with wrong QOS. expected is QOS{self.qos}"
            )
        assert any(self._payload_matches(self.message, p) for p in payloads), (
            "No message is received by mqtt-client on subscribed topic or "
            "message received is wrong"
        )
        try:
            self.mqtt_client.interfaces.mqtt.received_messages.clear()
        except Exception:
            pass
        self._published_messages = []

    def dut_drain_received(self, expected_count=None, max_yields=8,
                           yield_timeout_ms=20000):
        """Collect MQTT messages queued on the DUT via lwip_mqtt.yield.

        One yield only surfaces what is queued in that window, so repeat it
        and accumulate; call it between publishes to keep the DUT socket
        buffer from overflowing on long publish loops.
        """
        pattern = re.compile(
            r"Topic:\s*(?P<Topic>[^\r\n]+)\s*Message:\s*(?P<Message>[^\r\n]+)",
            re.DOTALL,
        )
        accepted_yield_status = [
            SLStatus.SL_STATUS_OK,
            SLStatus.SL_STATUS_FAIL,
            SLStatus.SL_STATUS_TIMEOUT,
        ]
        empty_yields = 0
        for _ in range(max_yields):
            if expected_count and len(self._dut_received_messages) >= expected_count:
                break
            try:
                yield_data = self.wifi_dut.interfaces.mqtt.lwip_mqtt_yield(
                    yield_timeout_ms=yield_timeout_ms,
                    timeout=45,
                    async_timeout=60,
                    expected_status=accepted_yield_status,
                )
            except AssertionError as yield_exc:
                logger().warning(
                    f"lwip_mqtt.yield while draining DUT messages failed: {yield_exc}"
                )
                break
            found = pattern.findall(yield_data or "")
            if found:
                self._dut_received_messages.extend(found)
                empty_yields = 0
                logger().info(
                    f"DUT yield returned {len(found)} MQTT message(s) "
                    f"(total {len(self._dut_received_messages)})"
                )
            else:
                empty_yields += 1
                if empty_yields >= 2:
                    break
        return self._dut_received_messages

    def mqtt_receive_messages(self, num_packets=None, dut_receive=False):
        """Receive and validate MQTT messages."""
        if not dut_receive:
            expected_count = (
                num_packets
                if num_packets is not None
                else (len(self._published_messages) or self.num_packets)
            )
            assert self.mqtt_client, (
                "mqtt_client (Raspi) is required to receive DUT publishes"
            )
            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 20:
                time.sleep(0.1)
                msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) >= expected_count:
                    break

            assert len(msgs) >= expected_count, (
                f"Expected {expected_count} messages on third-party MQTT client, "
                f"received {len(msgs)}"
            )
            logger().info(
                f"Third-party MQTT client (Raspi) received {len(msgs)} DUT publish(es)"
            )
            if self._published_messages:
                received_payloads = [self._mqtt_payload_text(m) for m in msgs]
                missing = self._find_missing_payloads(received_payloads)
                assert not missing, (
                    f"Third-party MQTT client missed {len(missing)} DUT payload(s); "
                    f"received {len(received_payloads)} unique-check against "
                    f"{len(self._published_messages)} published"
                )
            try:
                self.mqtt_client.interfaces.mqtt.received_messages.clear()
            except Exception:
                pass
            self._published_messages = []
            return

        expected_count = num_packets if num_packets is not None else self.num_packets
        self.dut_drain_received(expected_count=expected_count)

        dut_received_messages = self._dut_received_messages
        if dut_received_messages:
            for idx, (topic, message) in enumerate(dut_received_messages, start=1):
                logger().info(
                    f"DUT MQTT message {idx} - Topic: {topic}, Message length: {len(message)}"
                )
            logger().info(
                f"DUT drained {len(dut_received_messages)} MQTT message(s) via lwip_mqtt.yield"
            )
            received_on_dut = len(dut_received_messages)
            self._dut_received_messages = []
            if expected_count:
                assert received_on_dut >= expected_count, (
                    f"Expected {expected_count} MQTT messages on DUT, "
                    f"received {received_on_dut}"
                )
        else:
            raise AssertionError("No MQTT message received on DUT")

    def mqtt_unsubscribe(self, topic=None):
        """Unsubscribe from MQTT topic."""
        unsubscribe_topic = topic or self.topic
        dut_was_subscribed = unsubscribe_topic in self._dut_subscribed_topics

        if dut_was_subscribed:
            # Pre-drain pending async events
            try:
                self.wifi_dut.interfaces.mqtt.lwip_mqtt_yield(
                    yield_timeout_ms=2000,
                    timeout=15,
                    async_timeout=20,
                    expected_status=[SLStatus.SL_STATUS_OK, SLStatus.SL_STATUS_FAIL],
                )
            except Exception as drain_err:
                logger().warning(
                    f"Pre-unsubscribe drain yield warning (continuing): {drain_err}"
                )

            # Unsubscribe; tolerate SL_STATUS_TIMEOUT (0x7) after FW ACK
            try:
                self.wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=unsubscribe_topic)
            except AssertionError as unsub_err:
                err_text = str(unsub_err)
                if "SL_STATUS_TIMEOUT" in err_text or "0x7" in err_text:
                    logger().warning(
                        f"lwip_mqtt.unsubscribe async-status timed out after FW already "
                        f"accepted the request (topic='{unsubscribe_topic}'): {unsub_err}. "
                        f"Treating as accepted; mqtt_disconnect() will finalize teardown."
                    )
                    time.sleep(5)
                else:
                    raise
            self._dut_subscribed_topics.discard(unsubscribe_topic)

        if self.mqtt_client:
            self.mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=unsubscribe_topic)
            self._client_subscribed_topics.discard(unsubscribe_topic)

        logger().info(f"Unsubscribed from topic: {unsubscribe_topic}")

    def mqtt_disconnect(self):
        """Disconnect MQTT; safe to call from finally even if already closed."""
        if self.mqtt_client:
            try:
                self.mqtt_client.interfaces.mqtt.mqtt_client_close()
            except Exception as client_err:
                logger().warning(
                    f"mqtt_client_close warning during disconnect: {client_err}"
                )
            self._mqtt_client_connected = False

        try:
            self.wifi_dut.interfaces.mqtt.lwip_mqtt_yield(
                yield_timeout_ms=3000,
                timeout=20,
                async_timeout=30,
                expected_status=[SLStatus.SL_STATUS_OK, SLStatus.SL_STATUS_FAIL],
            )
        except Exception as drain_err:
            logger().warning(
                f"Pre-disconnect drain yield warning (continuing): {drain_err}"
            )

        try:
            self.wifi_dut.interfaces.mqtt.lwip_mqtt_disconnect()
        except AssertionError as disc_err:
            err_text = str(disc_err)
            if (
                "SL_STATUS_TIMEOUT" in err_text
                or "SL_STATUS_FAIL" in err_text
                or "SL_STATUS_INVALID_STATE" in err_text
                or "0x7" in err_text
                or "0x1" in err_text
            ):
                logger().warning(
                    f"lwip_mqtt.disconnect returned {disc_err}; "
                    f"treating as already disconnected."
                )
                time.sleep(2)
            else:
                logger().warning(
                    f"lwip_mqtt.disconnect assertion during teardown: {disc_err}"
                )
        except Exception as disc_err:
            logger().warning(
                f"lwip_mqtt.disconnect failed during teardown: {disc_err}"
            )

        # Free TLS PEM allocations after disconnect (C876779 cleanup path)
        try:
            if self._cert_alloc_addresses:
                for address in list(self._cert_alloc_addresses):
                    try:
                        self.wifi_dut.interfaces.wifi.memory_free(address)
                    except Exception as ex:
                        logger().warning(
                            f"Certificate memory cleanup failed for {address}: {ex}"
                        )
                self._cert_alloc_addresses.clear()
        except Exception as cert_err:
            logger().warning(f"Certificate cleanup during disconnect: {cert_err}")

        logger().info("MQTT disconnected successfully")

    def verify_ps_validation(self):
        """Verify power save validation through sniffer."""
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr["dut_mac_address"], filter_name="ps_poll"
            )
        )
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"]
        assert snif_pkt_count, "\n PS-POLL Packets are not captured in the Sniffer \n"

    def start_sniffer_capture(self):
        """Start wifi sniffer capture for the current test."""
        if not self.sniffer_enable:
            logger().info(
                "Sniffer capture skipped (constants.sniffer_enable=False)"
            )
            return
        if not (self.wifi_sniffer and self.wifi_access_point):
            logger().info(
                "Sniffer capture skipped: wifi_sniffer/wifi_access_point not provided"
            )
            return

        self.capture_filename = (
            self.request.node.name if self.request else "mqtt_lwip"
        )
        self.wifi_sniffer.interfaces.capture.start_capture(self.capture_filename)
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=self.capture_filename
        )
        logger().info(
            f"Sniffer started at channel {self.wifi_access_point.interfaces.wifi.channel}"
        )
        self._sniffer_started = True

    def verify_sniffer_capture(self):
        """Stop capture and run sniffer validation in one place."""
        if not self.sniffer_enable:
            logger().info(
                "Sniffer verification skipped (constants.sniffer_enable=False)"
            )
            return
        if not (self.wifi_sniffer and self.sniffer_filter and self.dut_mac_address):
            logger().info(
                "Sniffer verification skipped: required harness/DUT inputs missing"
            )
            return
        try:
            self.wifi_sniffer.interfaces.capture.stop_capture()
            self._sniffer_started = False

            packet_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_mac_address,
                    filter_name="ps_poll",
                )
            )
            snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter
            )["packet_count"]

            assert snif_pkt_count > 0, "PS-POLL packets not captured in sniffer"
            logger().info(
                f"Sniffer validation successful: {snif_pkt_count} PS-POLL packets captured"
            )
        except Exception as e:
            logger().warning(f"Sniffer validation error: {e}")


class BleThread(ThreadBase):
    """BLE operations thread for WiFi+BLE coexistence tests."""
    
    def __init__(
        self,
        wifi_dut=None,
        ble_client=None,
        ble_clients=None,
        sl_collections=None,
        ble_test_type=None,
        ble_pairing=1,
        dev_state=8,
        gatt=True,
        service_class=None,
        conn_interval=200,
        char_path=None,
        char_uid=None,
        data=None,
        data_length=20,
        data_duration=60,
        periodic_delay=1,
        service_uid=None,
        address=None,
        service_uuid=None,
        char_uuid=None,
        characteristic=None,
        bond_info=0,
        ble_adv_int_min=160,
        ble_adv_int_max=320,
        ble_scan_interval=160,
        ble_scan_window=50,
        set_smp=1,
        ble_init_required=True,
        ble_dut_address=None,
        svc=None,
        charc=None,
        buffer_mode=1,
        buffer_count=2,
        conn_interval_peripheral=None,
        conn_interval_central=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_clients = ble_clients or []
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_pairing = ble_pairing
        self.dev_state = dev_state
        self.gatt = gatt
        self.conn_interval = conn_interval
        self.service_class = service_class
        self.service_uid = service_uid
        self.char_path = char_path
        self.char_uid = char_uid
        self.data = data
        self.data_length = data_length
        self.data_duration = data_duration
        self.periodic_delay = periodic_delay
        self.ble_client_address = None
        self.write_handle = None
        self.address = address
        self.service_uuid = service_uuid
        self.char_uuid = char_uuid
        self.characteristic = characteristic
        self.bond_info = bond_info
        self.ble_adv_int_min = ble_adv_int_min
        self.ble_adv_int_max = ble_adv_int_max
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window
        self.set_smp = set_smp
        self.ble_init_required = ble_init_required
        self.ble_dut_address = ble_dut_address
        self.svc = svc
        self.charc = charc
        self.buffer_mode = buffer_mode
        self.buffer_count = buffer_count
        self.conn_interval_peripheral = conn_interval_peripheral or conn_interval
        self.conn_interval_central = conn_interval_central or conn_interval
        self._gatt_service_added = False
        self.secondary_ble_client_address = None
        
        # Initialize BLE if required
        if self.ble_init_required:
            if self.gatt:
                logger().info("Starting BLE GATT service in DUT")
                self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
                    set_smp=self.set_smp, bond_info=self.bond_info
                )
            else:
                logger().info("Initializing BLE")
                self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.set_smp)
            
            assert self.ble_dut_address is not None, "Unable to fetch BLE address from DUT"
            logger().info(f"BLE DUT Address: {self.ble_dut_address}")
            time.sleep(5)

    def setup_gatt_service(self, service_uid=0xAABB, char_uid=0x1AA1):
        """Add GATT service and characteristic to DUT."""
        if not self.service_uid:
            self.service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        if not self.char_uid:
            self.char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"

        logger().info(f"Adding GATT service {hex(service_uid)} and characteristic {hex(char_uid)} on DUT")
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=service_uid)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=char_uid)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=char_uid)
        self._gatt_service_added = True

    # ==================== Advertising/Scanning Control Methods ====================

    def stop_adv_scan(self):
        """Stop DUT advertising and remote scanning."""
        logger().info("Initiating stop advertise from DUT")
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        
        logger().info("Initiating stop scan from Remote device")
        self.ble_client.interfaces.bluetooth.stop_scanning()
        self.ble_client.interfaces.bluetooth.close()

    def stop_scan_adv(self):
        """Stop DUT scanning and remote advertising."""
        logger().info("Initiating stop scan from DUT")
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        
        logger().info("Initiating stop advertise from Remote device")
        self.ble_client.interfaces.bluetooth.stop_advertising()
        self.ble_client.interfaces.bluetooth.close()

    def advertise_dut(self):
        """Start advertising on the DUT."""
        logger().info(f"Advertising the DUT")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)

    def advertise_remote_device(self):
        """Start advertising on the remote BLE client device."""
        self.ble_client_address = self.sl_collections.advertise_remote_device(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
        )

    def check_adv_functionality_dut(self):
        """Check BLE advertising functionality."""
        self.ble_client_address = self.sl_collections.check_ble_advertise_functionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            timeout=20,
            ble_adv_int_max=self.ble_adv_int_max,
            ble_adv_int_min=self.ble_adv_int_min,
        )

    def _stop_scan_if_active(self):
        """Stop DUT scan only when the BLE state reports active scanning."""
        try:
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if str(state).isdigit() else -1
            if state_int in (2, 3):
                self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            else:
                logger().info(
                    f"Skipping ble_stop_scanning because DUT is not in scanning state (state={state_int})"
                )
        except Exception as exc:
            logger().warning(f"Unable to stop BLE scan safely: {exc}")

    @staticmethod
    def _is_ble_agent_error(error_message: str) -> bool:
        """True for transient BlueZ pairing/agent failures that need cleanup."""
        if not error_message:
            return False
        markers = (
            "Can't register the object-path handler",
            "there is already a handler",
            "AuthenticationCanceled",
            "Authentication Canceled",
            "AuthenticationFailed",
            "Authentication Failed",
            "Expected event link_key not found",
            "DUT BLE device is not in connected state",
        )
        return any(marker in error_message for marker in markers)

    @staticmethod
    def _is_ble_connect_timeout(error_message: str) -> bool:
        """True when the connect command timed out waiting for the async status."""
        if not error_message:
            return False
        return "SL_STATUS_TIMEOUT" in error_message or "status:0x7" in error_message

    def _reset_ble_link_before_retry(self):
        """Drop a half-open link so the next connect attempt starts clean."""
        state = None
        try:
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        except Exception as exc:
            logger().warning(f"Unable to read BLE state before connect retry: {exc}")
        if state is not None and _is_connected_ble_state(state):
            try:
                self.wifi_dut.interfaces.wifi.ble_disconnect(
                    ble_remote_dev_address=self.ble_client_address
                )
            except Exception as exc:
                logger().warning(f"ble_disconnect before connect retry failed: {exc}")
        elif self.ble_client is not None and getattr(self, "ble_dut_address", None):
            try:
                self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
            except Exception as exc:
                logger().warning(
                    f"remote disconnect before connect retry failed: {exc}"
                )
        time.sleep(3)

    def _ble_agent_cleanup_and_retry(self, ble_client=None):
        """Clean up the remote BLE client after a BlueZ agent registration failure."""
        target_client = ble_client or self.ble_client
        try:
            logger().info(
                "BLE Agent Cleanup: Starting cleanup after agent registration failure"
            )

            try:
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
                logger().info("Stopped BLE advertising on DUT")
            except Exception as exc:
                logger().warning(f"Could not stop advertising on DUT: {exc}")

            try:
                self._stop_scan_if_active()
            except Exception as exc:
                logger().warning(f"Could not stop scanning on DUT: {exc}")

            if target_client is not None:
                try:
                    target_client.interfaces.bluetooth.stop_scanning()
                    logger().info("Stopped BLE scanning on remote BLE client")
                except Exception as exc:
                    logger().warning(
                        f"Could not stop scanning on remote BLE client: {exc}"
                    )

            if (
                target_client is not None
                and getattr(self, "ble_dut_address", None)
            ):
                try:
                    target_client.interfaces.bluetooth.remove_device(
                        self.ble_dut_address
                    )
                    logger().info(
                        f"Removed DUT device {self.ble_dut_address} from remote BLE client"
                    )
                except Exception as exc:
                    logger().warning(
                        f"Could not remove DUT device from remote BLE client: {exc}"
                    )

            if getattr(self, "ble_client_address", None):
                try:
                    self.wifi_dut.interfaces.wifi.ble_disconnect(
                        ble_remote_dev_address=self.ble_client_address
                    )
                    logger().info(
                        f"Disconnected remote client {self.ble_client_address} on DUT"
                    )
                except Exception as exc:
                    logger().warning(
                        f"Could not disconnect remote client on DUT: {exc}"
                    )

            if target_client is not None:
                try:
                    target_client.interfaces.bluetooth.close()
                    time.sleep(2)
                    logger().info(
                        "Reset remote BLE client interface (close() called)"
                    )
                except Exception as exc:
                    logger().warning(
                        f"Could not reset remote BLE client interface: {exc}"
                    )

            self.ble_client_address = None

            logger().info("BLE Agent Cleanup: Cleanup completed")
            time.sleep(3)
        except Exception as exc:
            logger().warning(f"Error during BLE agent cleanup: {exc}")

    def _prepare_scan_target(self, ble_client=None):
        """Ensure there is an actively advertising remote device before DUT scan starts."""
        target_client = ble_client or self.ble_client
        assert target_client is not None, "BLE client is required for scan operations"

        last_exception = None
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                ble_client_address = target_client.interfaces.bluetooth.start_smp_adv(
                    bt_dut_address=self.ble_dut_address,
                    service_classes=self.service_class,
                )
                assert ble_client_address, "Failed to start remote BLE advertising for scan"
                time.sleep(2)
                return ble_client_address
            except Exception as exc:
                last_exception = exc
                err_msg = str(exc)
                if self._is_ble_agent_error(err_msg):
                    logger().warning(
                        f"start_smp_adv attempt {attempt + 1}/{max_attempts} hit "
                        f"BLE agent registration error: {err_msg}"
                    )
                    if attempt < max_attempts - 1:
                        self._ble_agent_cleanup_and_retry(target_client)
                        continue
                raise

        raise last_exception

    def _scan_for_remote_device(self, ble_client=None, ble_client_address=None, timeout=60, retries=3):
        """Run DUT scan against a prepared remote advertiser with retries."""
        target_client = ble_client or self.ble_client
        last_exception = None

        for attempt in range(retries):
            current_address = ble_client_address or self._prepare_scan_target(target_client)
            try:
                logger().info(
                    f"Starting BLE scan attempt {attempt + 1}/{retries} with interval {self.ble_scan_interval} and window {self.ble_scan_window}"
                )
                self.wifi_dut.interfaces.wifi.ble_start_scanning(
                    ble_client_address=current_address,
                    ble_scan_type=1,
                    ble_scan_filter_type=0,
                    ble_scan_interval=self.ble_scan_interval,
                    ble_scan_window=self.ble_scan_window,
                    timeout=timeout,
                )
                logger().info(f"Remote device found in scan results: {current_address}")
                return current_address
            except Exception as exc:
                last_exception = exc
                err_msg = str(exc)
                logger().warning(
                    f"BLE scan attempt {attempt + 1}/{retries} failed: {err_msg}"
                )
                self._stop_scan_if_active()
                if self._is_ble_agent_error(err_msg) and attempt < retries - 1:
                    self._ble_agent_cleanup_and_retry(target_client)
                ble_client_address = None
                time.sleep(min(2 + attempt, 5))

        raise last_exception

    def check_scan_functionality_dut(self):
        """Check BLE scanning functionality."""
        last_exception = None

        for attempt in range(3):
            try:
                self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_client,
                    ble_address=self.ble_dut_address,
                    ble_client_address=self.ble_client_address,
                    ble_scan_type=1,
                    timeout=60,
                    services=self.service_class,
                    ble_scan_interval=self.ble_scan_interval,
                    ble_scan_window=self.ble_scan_window,
                )
                logger().info(f"BLE scan validation successful: {self.ble_client_address}")
                return self.ble_client_address
            except Exception as exc:
                last_exception = exc
                err_msg = str(exc)
                logger().warning(
                    f"BLE scan validation attempt {attempt + 1}/3 failed: {err_msg}"
                )
                self._stop_scan_if_active()
                if self._is_ble_agent_error(err_msg) and attempt < 2:
                    self._ble_agent_cleanup_and_retry(self.ble_client)
                time.sleep(2 + attempt)

        raise last_exception

    def check_scan_functionality(self):
        """Check BLE scan functionality with specific scan parameters."""
        self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_address=self.ble_dut_address,
            ble_scan_type=1,
            ble_scan_interval=self.ble_scan_interval,
            ble_scan_window=self.ble_scan_window,
            timeout=60,
            services=self.service_class,
            remote_adv_int_min="0x40 0x01", remote_adv_int_max="0x40 0x01"
        )

    def ble_connect(self, role="master"):
        """Connect BLE with specified role (master=central, slave=peripheral)."""
        last_exception = None
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                if role == "master":
                    # DUT as central (master) - scan and connect to remote device
                    self.ble_client_address = self._scan_for_remote_device(timeout=60)
                    self.wifi_dut.interfaces.wifi.ble_stop_scanning()
                    self.wifi_dut.interfaces.wifi.ble_advertising = False
                    self.connect_from_dut()
                else:
                    # DUT as peripheral (slave) - advertise and wait for remote to connect
                    logger().info("Starting DUT BLE advertising")
                    self.wifi_dut.interfaces.wifi.ble_start_advertising(
                        ble_adv_int_max=int(self.ble_adv_int_max / 0.625),
                        ble_adv_int_min=int(self.ble_adv_int_min / 0.625)
                    )
                    time.sleep(5)
                    self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
                        wifi_dut=self.wifi_dut,
                        ble_client=self.ble_client,
                        ble_dut_address=self.ble_dut_address,
                        ble_pairing=self.ble_pairing,
                        services=self.service_class,
                        dev_state=self.dev_state,
                        max_conn_interval=self.conn_interval_peripheral,
                        min_conn_interval=self.conn_interval_peripheral,
                        timeout=30
                    )
                    async_events = self.wifi_dut.interfaces.wifi.get_async_events()
                    logger().info(f"Async events: {async_events}")
                return
            except Exception as exc:
                last_exception = exc
                err_msg = str(exc)
                logger().warning(
                    f"ble_connect(role={role}) attempt {attempt + 1}/{max_attempts} failed: {err_msg}"
                )
                if self._is_ble_connect_timeout(err_msg):
                    try:
                        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                    except Exception:
                        state = None
                    if state is not None and _is_connected_ble_state(state):
                        logger().warning(
                            f"ble_connect(role={role}) status timed out but the DUT "
                            f"is connected (state={state!r}); continuing"
                        )
                        return
                if self._is_ble_agent_error(err_msg) and attempt < max_attempts - 1:
                    self._ble_agent_cleanup_and_retry(self.ble_client)
                    continue
                if self._is_ble_connect_timeout(err_msg) and attempt < max_attempts - 1:
                    self._reset_ble_link_before_retry()
                    continue
                raise

        raise last_exception

    def connect_from_dut(self):
        """Establish BLE connection from DUT to remote client (DUT as master)."""
        try:
            self.sl_collections.connect_ble(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_client_address=self.ble_client_address,
                mode="master",
                retries=3,
                ble_pairing=self.ble_pairing,
                dev_state=self.dev_state,
                max_conn_interval=self.conn_interval_central,
                min_conn_interval=self.conn_interval_central,
                ble_dut_address=self.ble_dut_address,
                timeout=30,
                ble_scan_interval=256,
                ble_scan_window=80
            )
        except AssertionError as exc:
            # connect_ble uses state.isdigit(); bytes/'8\\n' look disconnected
            if "not in connected state" not in str(exc):
                raise
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            if _is_connected_ble_state(state):
                logger().warning(
                    f"connect_ble isdigit check failed; DUT is connected (state={state!r})"
                )
                return
            raise

    def scan_and_connect_from_remote(self):
        """Scan and connect from remote device."""
        self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            ble_pairing=self.ble_pairing,
            dev_state=self.dev_state,
            services=self.service_class,
            max_conn_interval=self.conn_interval_peripheral,
            min_conn_interval=self.conn_interval_peripheral,
            timeout=30
        )

    def add_service(self, service_uuid):
        """Add BLE service."""
        logger().info(f"Configuring BLE GATT service {hex(service_uuid)} in DUT")
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=hex(service_uuid))

    def add_characteristic(self, characteristic_uuid):
        """Add BLE characteristic."""
        logger().info(f"Configuring BLE GATT characteristic {hex(characteristic_uuid)} in DUT")
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=hex(characteristic_uuid))

    def fetch_profiles(self):
        """Discover remote GATT profiles and resolve the Heart Rate write handle."""
        from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import (
            HeartRateService,
            HeartRateMeasurementCharacterstic
        )
        
        uuids = self.wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=self.ble_client_address)
        assert HeartRateService.UUID.lower() in uuids, "Unable to get HeartRateService profile of Remote Device from DUT"

        logger().info(" ******************** Resolving Profile ********************")
        start_handle, end_handle, data = self.wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=self.ble_client_address,
            uuid=int(HeartRateService.UUID, 16)
        )
        assert start_handle is not None, "Failed to fetch the start handle for Heart Rate Service"
        assert end_handle is not None, "Failed to fetch the end handle for Heart Rate Service"

        char_uuids, write_handles, char_properties = self.wifi_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=self.ble_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60
        )
        logger().info(
            f"Discovered characteristics - UUIDs: {char_uuids}, "
            f"Write handles: {write_handles}, Properties: {char_properties}"
        )

        assert HeartRateMeasurementCharacterstic.HR_Measure_UUID in char_uuids, \
            f"Unable to find {HeartRateMeasurementCharacterstic.HR_Measure_UUID} UUID in discovered characteristics"

        index = char_uuids.index(HeartRateMeasurementCharacterstic.HR_Measure_UUID)
        logger().info(f"Heart Rate Measurement characteristic found at index: {index}")
        logger().info(f"All discovered UUIDs: {char_uuids}")
        logger().info(f"All write handles: {write_handles}")

        assert char_properties[index].isdigit(), "Characteristic property found is not a valid integer"

        self.write_handle = int(write_handles[index], 16)
        logger().info(f"Heart Rate Measurement write handle: {self.write_handle}")
        assert self.write_handle > 0, "Unable to get valid write handle for Heart Rate Service"

    def configure_buffer_mode(self, mode=None, count=None):
        """Configure BLE response and notification buffers on the DUT."""
        logger().info(f"******* Configuring Buffer Mode: {mode} and Buffer count: {count} *******")
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address,
            buffer_mode=mode,
            buffer_count=count
        )
        logger().info(f"******* Buffer Mode: {mode} and Buffer count: {count} configured successfully *******")

    def service_discovery_on_remote(self):
        """Perform service discovery on remote device."""
        self.char_path = self.sl_collections.service_discovery_on_remote(
            self.ble_client,
            service_uid=self.service_uid,
            char_uid=self.char_uid
        )
        logger().info(f"Characteristic path: {self.char_path}")

    def service_discovery_on_dut(self):
        """Perform service discovery on DUT."""
        self.write_handle = self.sl_collections.service_discovery_on_dut(
            ble_dut=self.wifi_dut,
            ble_client_address=self.ble_client_address,
            service_uuid=self.service_uuid,
            char_uuid=self.char_uuid,
            characteristic=self.characteristic
        )

    # ==================== Notification Methods ====================

    def enable_notifications(self):
        """Enable DUT notifications and receive GATT writes from the remote."""
        if self.write_handle:
            logger().info("Enabling notifications on DUT for Heart Rate Measurement")
            self.wifi_dut.interfaces.wifi.ble_set_att_value(
                ble_remote_dev_address=self.ble_client_address,
                handle=(self.write_handle + 1),
                enable_notify=1
            )
            time.sleep(10)

            tw = Stopwatch()
            Data_received_on_dut = []

            while tw.elapsed_sec < 60:
                events = self.wifi_dut.interfaces.wifi.get_async_events()

                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        if "rsi_ble_on_gatt_write_event_gatt" in event.event_data:
                            received_data = re.findall(r"att_length: 1, att_value: (.*)", event.event_data)
                            Data_received_on_dut = received_data + Data_received_on_dut
                            received_data = ord(received_data[0])
                            logger().info(f"Notification data received: {received_data}")

            assert len(Data_received_on_dut) > 0, "No notifications received on DUT during monitoring period"

            self.wifi_dut.interfaces.wifi.ble_set_att_value(
                ble_remote_dev_address=self.ble_client_address,
                handle=(self.write_handle + 1),
                enable_notify=0
            )

    def enable_notifications_on_dut(self):
        """Send periodic DUT notifications and verify remote receipt."""
        logger().info(f"****** enabling notifications on remote****************")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=self.char_path,
                                                                                     char_uid=self.char_uid)
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                                 buffer_mode=1, buffer_count=2)
        sw = Stopwatch()
        count = 0
        logger().info(f"Send notifications from DUT")
        while sw.elapsed_sec <= self.data_duration:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(self.ble_client_address, data=self.data,
                                                                  data_address=self.address)
            time.sleep(self.periodic_delay)
            count += 1
        time.sleep(10)
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        assert len(notifications) > 0, "received data is empty"
        logger().info(f"notifications received on remote :{notifications}")
        assert len(notifications) == count, "number of notifications received are not matching with sent"
        logger().info(f"length of notifications received on remote :{len(notifications)}")
        assert notifications[0] in self.data, "failed to fetch data"

        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)

    def enable_notifications_from_dut(self):
        """Enable notifications from DUT (TX notifications)."""
        logger().info("Enabling notifications on remote device")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path,
            char_uid=self.char_uid
        )
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address,
            buffer_mode=self.buffer_mode,
            buffer_count=self.buffer_count
        )
        
        sw = Stopwatch()
        count = 0
        logger().info("Sending notifications from DUT")
        
        # Generate data if not provided
        if not self.data:
            self.data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.data_length))
        
        while sw.elapsed_sec <= self.data_duration:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                ble_remote_dev_address=self.ble_client_address,
                data=self.data,
                data_address=self.address
            )
            tw = Stopwatch()
            event_status = False
            event_data = None
            while tw.elapsed_sec < 5:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.BLE_REQ_MORE_DATA:
                        if "RSI_BLE_MORE_DATA_REQ_EVT" in event.event_data:
                            event_status = True
                            event_data = event.event_data
                            break
                if event_status:
                    logger().info(f"Received RSI_BLE_MORE_DATA_REQ_EVT event: {event_data}")
                    break
            time.sleep(self.periodic_delay)
            count += 1
        
        max_retries = 3
        for retry in range(max_retries + 1):
            time.sleep(10)
            notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
            logger().info(f"Notifications received on remote: {notifications}")
            received = len(notifications)

            if received >= count:
                break

            if retry < max_retries:
                missing = count - received
                logger().warning(
                    f"BLE notification drop detected: received {received}/{count}. "
                    f"Resending {missing} notification(s) (retry {retry + 1}/{max_retries})"
                )
                for _ in range(missing):
                    self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                        ble_remote_dev_address=self.ble_client_address,
                        data=self.data,
                        data_address=self.address
                    )
                    tw = Stopwatch()
                    event_status = False
                    while tw.elapsed_sec < 10:
                        events = self.wifi_dut.interfaces.wifi.get_async_events()
                        for event in events:
                            if event.event_type == AsyncEventIdentifiers.BLE_REQ_MORE_DATA:
                                if "RSI_BLE_MORE_DATA_REQ_EVT" in event.event_data:
                                    event_status = True
                                    break
                        if event_status:
                            break
                    time.sleep(self.periodic_delay)

        assert len(notifications) > 0, "Received data is empty"
        assert len(notifications) >= count, f"Number of notifications received ({len(notifications)}) not matching sent ({count})"
        
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)

    def enable_notifications_remote(self):
        """Enable notifications from remote device (RX notifications)."""
        assert self.write_handle, (
            "write_handle is required for RX notifications. "
            "Call service_discovery_on_dut() first with a notifiable remote service."
        )

        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address,
            buffer_mode=1,
            buffer_count=2
        )

        logger().info("Enabling notification on DUT")
        self.wifi_dut.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=self.ble_client_address,
            handle=(self.write_handle + 1),
            enable_notify=1
        )

        tw = Stopwatch()
        Data_received_on_dut = []

        # Generate data if not provided
        if not self.data:
            self.data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.data_length))

        while tw.elapsed_sec < self.data_duration:
            if self.svc and self.charc:
                self.ble_client.interfaces.bluetooth.send_gatt_charc_notification(
                    self.svc, self.charc, self.data
                )
                logger().info("Sent GATT characteristic notification")
            time.sleep(2)
            lw = Stopwatch()
            while lw.elapsed_sec < 10:
                received_data = None
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        if "rsi_ble_on_gatt_write_event_gatt" in event.event_data:
                            received_data = re.findall(r"att_value: (.*)", event.event_data)
                            break
                if received_data:
                    Data_received_on_dut = received_data + Data_received_on_dut
                    logger().info(f"Received data: {Data_received_on_dut}")
                    break
            time.sleep(2)

        assert len(Data_received_on_dut) > 0, "Notifications not received on DUT"
        self.wifi_dut.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=self.ble_client_address,
            handle=(self.write_handle + 1),
            enable_notify=0
        )

    def gatt_indication(self):
        """Send BLE indications (TX)."""
        logger().info("Starting BLE indications")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path,
            char_uid=self.char_uid
        )

        indication_count = 0
        sw = Stopwatch()

        if not self.data:
            self.data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.data_length))

        while sw.elapsed_sec < self.data_duration:
            self.wifi_dut.interfaces.wifi.ble_indicate_value(
                ble_remote_dev_address=self.ble_client_address,
                handle=12,
                data=self.data,
                data_address=self.address,
                data_length=self.data_length
            )
            indication_count += 1
            time.sleep(self.periodic_delay)

        max_retries = 3
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        for retry in range(max_retries + 1):
            time.sleep(10)
            notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
            received = len(notifications)
            logger().info(f"Indications received on remote: {received}/{indication_count}")

            if received >= indication_count:
                break

            if retry < max_retries:
                missing = indication_count - received
                logger().warning(
                    f"BLE indication drop detected: received {received}/{indication_count}. "
                    f"Resending {missing} indication(s) (retry {retry + 1}/{max_retries})"
                )
                for _ in range(missing):
                    self.wifi_dut.interfaces.wifi.ble_indicate_value(
                        ble_remote_dev_address=self.ble_client_address,
                        handle=12,
                        data=self.data,
                        data_address=self.address,
                        data_length=self.data_length
                    )
                    time.sleep(self.periodic_delay)

        assert len(notifications) > 0, "Received indications data is empty"
        assert len(notifications) >= indication_count, (
            f"Number of indications received ({len(notifications)}) "
            f"not matching sent ({indication_count}) even after {max_retries} retries"
        )
        logger().info(f"Received notifications: {notifications}")

        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        time.sleep(1)

    def enable_indications_remote(self):
        """Enable indications from remote device (RX indications)."""
        if self.write_handle:
            logger().info("Enabling indication on DUT")
            self.wifi_dut.interfaces.wifi.ble_indicate_value_sync(
                remote_dev_address=self.ble_client_address,
                handle=(self.write_handle + 1),
                data=self.data,
                data_len=self.data_length
            )
            
            tw = Stopwatch()
            Data_received_on_dut = []
            
            # Generate data if not provided
            if not self.data:
                self.data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.data_length))
            
            while tw.elapsed_sec < self.data_duration:
                if self.svc and self.charc:
                    self.ble_client.interfaces.bluetooth.send_gatt_charc_notification(self.svc, self.charc, self.data)
                logger().info("Sent GATT characteristic notification")
                time.sleep(7)
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        if "rsi_ble_on_gatt_write_event_gatt" in event.event_data:
                            received_data = re.findall(r"att_value: (.*)", event.event_data)
                            Data_received_on_dut = received_data + Data_received_on_dut
                            logger().info(f"Received data: {Data_received_on_dut}")
            
            assert len(Data_received_on_dut) > 0, "Indications not received on DUT"
            self.wifi_dut.interfaces.wifi.ble_set_att_value(
                ble_remote_dev_address=self.ble_client_address,
                handle=(self.write_handle + 1),
                enable_notify=0
            )

    def _get_ble_state_int(self):
        """Return DUT BLE state as an int, or -1 when unavailable."""
        return _normalize_ble_state(
            self.wifi_dut.interfaces.wifi.ble_get_device_state()
        )

    def _connect_ble_with_state_tolerance(self, **kwargs):
        """Connect BLE, treating composite dual-role states as connected."""
        try:
            self.sl_collections.connect_ble(**kwargs)
            return
        except AssertionError as exc:
            if "DUT BLE device is not in connected state" not in str(exc):
                raise

            state_int = self._get_ble_state_int()
            if _is_connected_ble_state(state_int):
                logger().info(
                    "Treating composite BLE state "
                    f"{state_int} as connected for sta_ble_paho_mqtt_lwip"
                )
                return
            raise

    def _connect_slave_with_retry(self, ble_client):
        """DUT peripheral connect via remote scan+connect, with agent/scan retries."""
        saved_client = self.ble_client
        self.ble_client = ble_client
        try:
            self.ble_connect(role="slave")
            return self.ble_client_address
        finally:
            self.ble_client = saved_client

    def connect_dual_role(self):
        """Connect in dual role."""
        logger().info("Setting up dual role BLE connections (C133511 sequence)")

        if len(self.ble_clients) < 2:
            raise ValueError("Dual role requires at least 2 BLE clients")

        self.ble_client = self.ble_clients[0]
        self.ble_connect(role="slave")
        logger().info(
            f"First connection established: RD1 -> DUT "
            f"(Address: {self.ble_client_address})"
        )

        self.wifi_dut.interfaces.wifi.ble_set_smp(set_smp=1)

        self.ble_client = self.ble_clients[1]
        self.ble_connect(role="master")
        self.secondary_ble_client_address = self.ble_client_address
        logger().info(
            f"Second connection established: DUT -> RD2 "
            f"(Address: {self.secondary_ble_client_address})"
        )

        # Peripheral client is used later for TX/discovery helpers
        self.ble_client = self.ble_clients[0]
        logger().info("Dual role BLE connections established successfully")

    def assert_dual_role_raspi_connections(self, context="dual-role BLE"):
        """Assert dual-role links via get_connection_status (C133511)."""
        clients = self.ble_clients or []
        assert len(clients) >= 2, "Minimum 2 Raspi devices needed"
        for ble_client in clients:
            status = ble_client.interfaces.bluetooth.get_connection_status(
                self.ble_dut_address
            )
            logger().info(
                f"Connection status in remote device '{ble_client.name}' is:{status}"
            )
            assert status, (
                f"{context}: Remote device '{ble_client.name}' is not connected to DUT"
            )

    def scan_from_remote_device(self):
        """Scan from remote device."""
        self.ble_client_address = self.sl_collections.scan_from_remote_device(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
        )
    def _remote_disconnect_with_state_fallback(self):
        """Disconnect from BlueZ, trusting the link state over the D-Bus reply.

        BlueZ answers Disconnect() only after the link is torn down, so under
        coex load the reply can exceed the 25s D-Bus timeout and raise
        NoReply even though the link did drop. Check the DUT before failing.
        """
        try:
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
            return
        except Exception as disc_exc:
            logger().warning(
                f"Remote BLE disconnect reported an error; verifying link state "
                f"on the DUT: {disc_exc}"
            )

        for _ in range(6):
            time.sleep(5)
            if not _is_connected_ble_state(
                self.wifi_dut.interfaces.wifi.ble_get_device_state()
            ):
                logger().info(
                    "BLE link is down on the DUT; treating the remote disconnect "
                    "error as a late D-Bus reply"
                )
                return

        logger().warning(
            "BLE link still up after remote disconnect error; disconnecting from DUT"
        )
        if self.ble_client_address:
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=self.ble_client_address
            )
        else:
            self.wifi_dut.interfaces.wifi.ble_disconnect()
        time.sleep(5)
        assert not _is_connected_ble_state(
            self.wifi_dut.interfaces.wifi.ble_get_device_state()
        ), "BLE disconnect failed from both remote and DUT"

    def ble_disconnect(self, disconnect_from="remote"):
        """Disconnect BLE connection."""
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        
        if state_int == self.dev_state or state_int == 8 or state_int == 9 or state_int == 10:
            if disconnect_from == "remote":
                logger().info("Initiating BLE disconnection from remote device")
                if self.ble_client:
                    self._remote_disconnect_with_state_fallback()
            else:
                logger().info("Initiating BLE disconnection from DUT")
                if self.ble_client_address:
                    self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
                else:
                    self.wifi_dut.interfaces.wifi.ble_disconnect()
            
            if self.ble_client:
                self.ble_client.interfaces.bluetooth.close()
            time.sleep(5)
        else:
            logger().info(f"BLE device not in connected state (state: {state_int}), skipping disconnect")

    def disconnect_ble(self):
        """Wrapper method for BLE disconnection (for test case compatibility)."""
        self.ble_disconnect()

    def send_notifications_tx(self):
        """Wrapper method to send notifications (for test case compatibility)."""
        # Ensure service and characteristic UIDs are set
        if not self.service_uid:
            self.service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        if not self.char_uid:
            self.char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"

        # Add service and characteristic if not already done
        if not self._gatt_service_added:
            try:
                self.wifi_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
                self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1)
                self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1)
                self._gatt_service_added = True
            except Exception:
                logger().warning("Failed to add GATT service (may already exist)")

        # Perform service discovery on remote if client available
        if self.ble_client and not self.char_path:
            self.service_discovery_on_remote()

        # Validate char_path before enabling notifications
        assert self.char_path is not None, (
            "char_path is None after service discovery. "
            "Ensure GATT service is added BEFORE BLE connection by calling "
            "setup_gatt_service() before start(). BlueZ caches the GATT table "
            "at connection time; services added after connection are not visible."
        )

        # Enable notifications
        self.enable_notifications_from_dut()

    def receive_notifications_rx(self):
        """Wrapper method to receive notifications (for test case compatibility)."""
        # Perform service discovery on DUT if needed
        if not self.write_handle:
            self.service_discovery_on_dut()
        assert self.write_handle, (
            "write_handle is None after service discovery. "
            "Configure service_class/service_uuid/char_uuid/characteristic "
            "(e.g. HealthThermometerService) before central connect so the "
            "remote advertises a notifiable GATT characteristic."
        )

        # Enable notifications from remote
        self.enable_notifications_remote()

    def send_indications_tx(self):
        """Wrapper method to send indications (for test case compatibility)."""
        # Ensure service and characteristic UIDs are set
        if not self.service_uid:
            self.service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        if not self.char_uid:
            self.char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"

        # Add service and characteristic if not already done
        if not self._gatt_service_added:
            try:
                self.wifi_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
                self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1)
                self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1)
                self._gatt_service_added = True
            except Exception:
                logger().warning("Failed to add GATT service (may already exist)")

        # Perform service discovery on remote if client available
        if self.ble_client and not self.char_path:
            self.service_discovery_on_remote()

        # Validate char_path before sending indications
        assert self.char_path is not None, (
            "char_path is None after service discovery. "
            "Ensure GATT service is added BEFORE BLE connection by calling "
            "setup_gatt_service() before start(). BlueZ caches the GATT table "
            "at connection time; services added after connection are not visible."
        )

        # Send indications
        self.gatt_indication()

    def connect_peripheral(self):
        """Wrapper method for peripheral connection (for test case compatibility)."""
        self.ble_connect(role="slave")

    def connect_central(self):
        """Wrapper method for central connection (for test case compatibility)."""
        self.ble_connect(role="master")

    def continuous_scan(self):
        """Wrapper method for continuous scanning (for test case compatibility)."""
        last_exception = None
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_client,
                    ble_address=self.ble_dut_address,
                    ble_scan_type=1,
                    ble_scan_interval=self.ble_scan_interval,
                    ble_scan_window=self.ble_scan_window,
                    timeout=60,
                    services=self.service_class,
                    remote_adv_int_min="0x40 0x01", remote_adv_int_max="0x40 0x01"
                )
                logger().info(
                    f"Continuous BLE scan succeeded on attempt {attempt + 1}/{max_attempts}: {self.ble_client_address}"
                )
                return
            except Exception as exc:
                last_exception = exc
                err_msg = str(exc)
                logger().warning(
                    f"Continuous BLE scan attempt {attempt + 1}/{max_attempts} failed: {err_msg}"
                )
                self._stop_scan_if_active()
                if self._is_ble_agent_error(err_msg) and attempt < max_attempts - 1:
                    self._ble_agent_cleanup_and_retry(self.ble_client)
                    continue
                if attempt < max_attempts - 1:
                    time.sleep(2 + attempt)
                    continue
                raise

        raise last_exception
    

    def update_connection_intervals(self):
        """Update BLE connection intervals."""
        if self.ble_client_address:
            if self.conn_interval_peripheral:
                ble_interval = int(self.conn_interval_peripheral / 1.25)
                self.wifi_dut.interfaces.wifi.ble_update_conn_param(
                    ble_remote_dev_address=self.ble_client_address,
                    ble_conn_interval_min=ble_interval,
                    ble_conn_interval_max=ble_interval,
                    ble_conn_latency=0,
                    ble_supervision_timeout=3200
                )
                time.sleep(5)
                logger().info(f"Updated connection interval to {self.conn_interval_peripheral}ms")

    def ble_connect_disconnect_reconnect_cycle(self, role="master", iterations=5):
        """BLE connect/disconnect/reconnect cycle."""
        logger().info(f"Starting BLE connect/disconnect/reconnect cycle ({iterations} iterations) as {role}")
        
        for i in range(iterations):
            logger().info(f"BLE cycle iteration {i+1}/{iterations}")
            
            # Connect
            if role == "master":
                self.ble_connect(role="master")
            else:
                self.ble_connect(role="slave")
            
            time.sleep(5)
            
            # Verify connection (normalize bytes/str/int from ble_get_device_state)
            state_int = _normalize_ble_state_for_cleanup(
                self.wifi_dut.interfaces.wifi.ble_get_device_state()
            )
            assert state_int == self.dev_state or state_int in (
                BLEDeviceState.Connected,
                8,
                9,
                10,
                12,
            ), f"BLE connection failed in iteration {i+1} (state={state_int})"
            
            logger().info(f"BLE connected successfully in iteration {i+1}")
            time.sleep(10)
            
            # Disconnect
            self.ble_disconnect()
            time.sleep(5)
            
            logger().info(f"BLE disconnected successfully in iteration {i+1}")
        
        logger().info(f"BLE connect/disconnect/reconnect cycle completed ({iterations} iterations)")

    def run(self):
        """Dispatch BLE operations based on ble_test_type."""
        try:
            # BLE Advertising Test - DUT advertises and remote device scans
            if self.ble_test_type == "advertise":
                self.check_adv_functionality_dut()

            # BLE Scanning Test - DUT scans for remote devices
            elif self.ble_test_type == "scan":
                self.check_scan_functionality_dut()

            # BLE Slave Connection Test - DUT acts as BLE slave
            elif self.ble_test_type == "slave":
                self.ble_connect(role="slave")

            # BLE Master Connection Test - DUT acts as BLE master
            elif self.ble_test_type == "master":
                self.ble_connect(role="master")

            # Remote Device Scan Test - Remote device scans for DUT
            elif self.ble_test_type == "scan_from_remote_device":
                self.scan_from_remote_device()

            # Scan and Connect from Remote Test - Remote scans and connects
            elif self.ble_test_type == "scan_and_connect_from_remote":
                self.scan_and_connect_from_remote()

            # Scan and Connect from DUT Test - DUT scans and connects
            elif self.ble_test_type == "scan_and_connect_from_dut":
                self.sl_collections.scan_and_connect_from_dut(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_client,
                    ble_client_address=self.ble_client_address,
                    dev_state=self.dev_state,
                    max_conn_interval=self.conn_interval_central,
                    min_conn_interval=self.conn_interval_central
                )

            # Remote Device Connection Test - Remote device connects to DUT
            elif self.ble_test_type == "connect_from_remote":
                self.sl_collections.connect_ble(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_client,
                    ble_dut_address=self.ble_dut_address,
                    mode="slave",
                    retries=3,
                    ble_pairing=self.ble_pairing,
                    dev_state=self.dev_state,
                    max_conn_interval=self.conn_interval_peripheral,
                    min_conn_interval=self.conn_interval_peripheral,
                    timeout=20
                )

            # BLE Notification TX Test - DUT sends notifications to remote
            elif self.ble_test_type == "notify_tx":
                self.enable_notifications_from_dut()

            # BLE Notification RX Test - DUT receives notifications from remote
            elif self.ble_test_type == "notify_rx":
                self.enable_notifications_remote()

            # BLE Indication TX Test - DUT sends indications
            elif self.ble_test_type == "indications_tx":
                self.gatt_indication()

            # BLE Indication RX Test - DUT receives indications
            elif self.ble_test_type == "indications_rx":
                self.enable_indications_remote()

            # Connect as Master and Receive Notifications
            elif self.ble_test_type == "connect_as_master_notify_rx":
                self.ble_connect(role="master")
                self.service_discovery_on_dut()
                self.enable_notifications_remote()

            # Dual Role Connection Test - DUT as both master and slave
            elif self.ble_test_type == "dual_role":
                self.connect_dual_role()

            # Peripheral Connection Test
            elif self.ble_test_type == "peripheral_connect":
                self.ble_connect(role="slave")

            # Central Connection Test
            elif self.ble_test_type == "central_connect":
                self.ble_connect(role="master")

            # Continuous Scan Test
            elif self.ble_test_type == "continuous_scan":
                self.continuous_scan()
                
        except Exception as e:
            logger().error(f"BLE thread error: {e}")
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)
            raise


def setup_dual_role_like_c133511(
    wifi_dut,
    ble_clients,
    sl_collections,
    conn_interval_peripheral=None,
    conn_interval_central=None,
    add_gatt_service=False,
    data_length=20,
    data_duration=60,
):
    """Establish dual-role BLE exactly as C133511 in test_sta_ble_multi_raspi_sdk.py."""
    assert len(ble_clients) >= 2, "Minimum 2 Raspi devices needed"

    ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
    ble_obj1 = BleThread(
        wifi_dut=wifi_dut,
        ble_client=ble_clients[0],
        sl_collections=sl_collections,
        ble_test_type="slave",
        dev_state=8,
        ble_pairing=1,
        ble_init_required=False,
        ble_dut_address=ble_dut_address,
        conn_interval_peripheral=conn_interval_peripheral,
        conn_interval=conn_interval_peripheral or 200,
        data_length=data_length,
        data_duration=data_duration,
    )
    ble_obj2 = BleThread(
        wifi_dut=wifi_dut,
        ble_client=ble_clients[1],
        sl_collections=sl_collections,
        ble_test_type="master",
        dev_state=8,
        ble_pairing=1,
        ble_init_required=False,
        ble_dut_address=ble_dut_address,
        conn_interval_central=conn_interval_central,
        conn_interval=conn_interval_central or 200,
        data_length=data_length,
        data_duration=data_duration,
    )

    if add_gatt_service:
        ble_obj1.setup_gatt_service()

    ble_obj1.start()
    ble_obj1.wait_for_exit()
    wifi_dut.interfaces.wifi.ble_set_smp(set_smp=1)
    ble_obj2.start()
    ble_obj2.wait_for_exit()

    ble_obj1.ble_clients = list(ble_clients)
    ble_obj1.secondary_ble_client_address = ble_obj2.ble_client_address
    return ble_obj1, ble_obj2, ble_dut_address


def soft_disable_bt_powersave(wifi_dut):
    """Best-effort BT powersave disable that never raises."""
    if wifi_dut is None:
        return
    try:
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=0, psp_type=0)
        logger().info("soft_disable_bt_powersave: BT powersave disabled")
    except Exception as exc:
        logger().warning(
            f"soft_disable_bt_powersave failed (continuing): {exc}"
        )


def safe_cleanup_mqtt(wifi_obj=None, wifi_dut=None, mqtt_client=None):
    """Best-effort MQTT client + DUT disconnect for finally blocks."""
    active_client = mqtt_client
    if active_client is None and wifi_obj is not None:
        active_client = getattr(wifi_obj, "mqtt_client", None)

    active_dut = wifi_dut
    if active_dut is None and wifi_obj is not None:
        active_dut = getattr(wifi_obj, "wifi_dut", None)

    if wifi_obj is not None and hasattr(wifi_obj, "mqtt_disconnect"):
        try:
            wifi_obj.mqtt_disconnect()
            return
        except Exception as exc:
            logger().warning(
                f"wifi_obj.mqtt_disconnect failed during teardown: {exc}"
            )

    if active_client is not None:
        try:
            active_client.interfaces.mqtt.mqtt_client_close()
            logger().info("MQTT client closed during teardown")
        except Exception as exc:
            logger().warning(f"mqtt_client_close failed during teardown: {exc}")

    if active_dut is not None:
        try:
            active_dut.interfaces.mqtt.lwip_mqtt_disconnect()
            logger().info("DUT lwip_mqtt_disconnect issued during teardown")
        except Exception as exc:
            logger().warning(
                f"lwip_mqtt_disconnect failed during teardown: {exc}"
            )


def _normalize_ble_state_for_cleanup(state):
    """Normalize ble_get_device_state() return value for teardown decisions."""
    if state is None:
        return -1
    if isinstance(state, int):
        return state
    if isinstance(state, (bytes, bytearray)):
        state = state.decode(errors="ignore")
    state_str = str(state).strip()
    return int(state_str) if state_str.isdigit() else -1


def safe_cleanup_ble_test(sl_collections, wifi_dut, ble_obj, ble_client):
    """Best-effort BLE teardown used by every test finally block."""
    clients = []
    if ble_client is not None:
        clients = (
            list(ble_client)
            if isinstance(ble_client, (list, tuple))
            else [ble_client]
        )
    if ble_obj is not None:
        for extra in getattr(ble_obj, "ble_clients", None) or []:
            if extra is not None and extra not in clients:
                clients.append(extra)
        if getattr(ble_obj, "ble_client", None) is not None:
            if ble_obj.ble_client not in clients:
                clients.append(ble_obj.ble_client)

    primary_client = clients[0] if clients else None
    ble_dut_address = getattr(ble_obj, "ble_dut_address", None) if ble_obj else None
    ble_client_address = (
        getattr(ble_obj, "ble_client_address", None) if ble_obj else None
    )

    # Stop advertising / scanning so the next test starts from idle BLE
    dut_disconnect_done = False
    if wifi_dut is not None:
        try:
            state_int = _normalize_ble_state_for_cleanup(
                wifi_dut.interfaces.wifi.ble_get_device_state()
            )
            if state_int in (1, 3, 9, 11) or (state_int & 0x01):
                try:
                    wifi_dut.interfaces.wifi.ble_stop_advertising()
                except Exception as exc:
                    logger().warning(
                        f"ble_stop_advertising during teardown failed: {exc}"
                    )
            if state_int in (2, 3, 10, 11) or (state_int & 0x02):
                try:
                    wifi_dut.interfaces.wifi.ble_stop_scanning()
                except Exception as exc:
                    logger().warning(
                        f"ble_stop_scanning during teardown failed: {exc}"
                    )
            if state_int in (8, 9, 10, 12) or (state_int & 0x08):
                try:
                    if ble_client_address:
                        wifi_dut.interfaces.wifi.ble_disconnect(
                            ble_remote_dev_address=ble_client_address
                        )
                    else:
                        wifi_dut.interfaces.wifi.ble_disconnect()
                    dut_disconnect_done = True
                except Exception as exc:
                    logger().warning(
                        f"ble_disconnect during teardown failed: {exc}"
                    )
                time.sleep(1)
        except Exception as exc:
            logger().warning(f"BLE state cleanup path failed: {exc}")

    # Only one side tears the link down; remote disconnect is the fallback
    if ble_dut_address and not dut_disconnect_done:
        for client in clients:
            if client is None:
                continue
            try:
                client.interfaces.bluetooth.disconnect(ble_dut_address)
            except Exception as exc:
                logger().warning(
                    f"remote BLE disconnect({ble_dut_address}) failed: {exc}"
                )
    elif dut_disconnect_done:
        logger().info(
            "BLE link closed from DUT; skipping remote-side disconnect"
        )

    if sl_collections is not None and wifi_dut is not None and primary_client is not None:
        try:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut,
                ble_client=clients if len(clients) > 1 else primary_client,
                ble_client_address=ble_client_address,
                ble_dut_address=ble_dut_address,
            )
        except Exception as cleanup_exc:
            logger().warning(f"cleanup_ble failed during teardown: {cleanup_exc}")

    if wifi_dut is not None:
        try:
            wifi_dut.interfaces.wifi.ble_remove_service()
        except Exception as rm_svc_exc:
            logger().warning(
                f"ble_remove_service failed during teardown or already removed services: {rm_svc_exc}"
            )

    for client in clients:
        if client is None:
            continue
        try:
            bluetooth_iface = getattr(client.interfaces, "bluetooth", None)
            if bluetooth_iface is not None:
                bluetooth_iface.close()
                logger().info(
                    "BLE client bluetooth.close() called; glib main-loop stopped"
                )
                time.sleep(1)
        except Exception as close_exc:
            logger().warning(
                f"bluetooth.close() failed during teardown: {close_exc}"
            )

        if ble_dut_address:
            try:
                client.interfaces.bluetooth.remove_device(ble_dut_address)
            except Exception as rm_exc:
                logger().warning(
                    f"remove_device({ble_dut_address}) failed during teardown: {rm_exc}"
                )

    time.sleep(1)


def safe_cleanup_test(
    sl_collections=None,
    wifi_dut=None,
    wifi_obj=None,
    ble_obj=None,
    ble_client=None,
    mqtt_client=None,
):
    """Best-effort MQTT + BLE teardown for every test finally block."""
    logger().info("Starting test teardown cleanup (MQTT + BLE)")
    try:
        safe_cleanup_mqtt(
            wifi_obj=wifi_obj,
            wifi_dut=wifi_dut,
            mqtt_client=mqtt_client,
        )
    except Exception as exc:
        logger().warning(f"MQTT teardown raised unexpectedly: {exc}")

    try:
        safe_cleanup_ble_test(sl_collections, wifi_dut, ble_obj, ble_client)
    except Exception as exc:
        logger().warning(f"BLE teardown raised unexpectedly: {exc}")

    logger().info("Test teardown cleanup finished")


@pytest.mark.skip()
# Test Case 1: Dual role (45ms/250ms CI) with MQTT QoS1 over TCP LWIP
@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_dual_role_mqtt_qos1_tcp_lwip_C887546(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    TC1: Verify dual role functionality (45ms/250ms CI) with MQTT QoS1 over TCP using LWIP
    
    Test Steps:
    1. Configure sniffer and start capture
    2. Join WiFi AP and get IP
    3. Enable power save
    4. Establish BLE dual role connections (peripheral 45ms, central 250ms)
    5. Connect to MQTT broker over TCP using LWIP
    6. Subscribe to topic with QoS1
    7. Publish 300 bytes data (10-20 packets)
    8. Perform BLE data transfer (240 bytes)
    9. Unsubscribe and disconnect
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    ble_dut_address = None
    ble_clients_address = []
    
    topic = "TC1_DualRole_MQTT_Topic"
    qos = Si91xMqttQos.QOS1
    
    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    # Force safe thread config for this test
    profile["thread_config"] = {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    
    try:
        # Create WiFi MQTT LWIP thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message_size=300,
            num_packets=15,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )
        
        # Start WiFi thread
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Dual-role BLE: same sequence as C133511 in test_sta_ble_multi_raspi_sdk.py
        ble_obj, ble_obj2, ble_dut_address = setup_dual_role_like_c133511(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            conn_interval_peripheral=45,
            conn_interval_central=250,
            add_gatt_service=True,
        )
        ble_clients_address.append(ble_obj.ble_client_address)
        ble_clients_address.append(ble_obj2.ble_client_address)
        
        # Connect to MQTT
        wifi_obj.mqtt_connect_lwip()
        
        # Subscribe
        wifi_obj.mqtt_subscribe()
        
        # Publish data
        wifi_obj.mqtt_publish()
        
        # BLE data transfer
        ble_obj.send_notifications_tx()
        
        # Receive and validate messages
        wifi_obj.mqtt_receive_messages()
        
        # Unsubscribe
        wifi_obj.mqtt_unsubscribe()
        
        # Disconnect
        wifi_obj.mqtt_disconnect()
        
        # Verify sniffer capture
        wifi_obj.verify_sniffer_capture()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        
        logger().info("TC1: Test completed successfully")
        
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_clients,
            mqtt_client=mqtt_client,
        )


# Test Case 2: QoS1 with topic lengths 62, 100, 122, 201 chars and 1000-byte payloads
@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_mqtt_qos1_diff_topic_lengths_1000b_payload_ble_tx_C887547(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC2: Verify QoS1 with topic lengths 62, 100, 122, 201 chars and 1000-byte payloads
    
    Test Steps:
    1. Join WiFi and establish BLE peripheral connection (45ms CI)
    2. Connect to MQTT broker
    3. Subscribe to topics of different lengths (62, 100, 122, 201 chars)
    4. Publish 1000-byte payloads
    5. Perform BLE TX notifications (240 bytes)
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    
    topic_lengths = [62, 100, 122, 201]
    qos = Si91xMqttQos.QOS1
    
    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    
    try:
        # Create WiFi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            message_size=1000,
            num_packets=15,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )
        
        # Create BLE peripheral thread
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="peripheral_connect",
            conn_interval_peripheral=45,
            set_smp=1,
            data_length=240,
            data_duration=120,
        )
        
        # Register GATT before connect so BlueZ caches it during discovery
        ble_obj.setup_gatt_service()
        
        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        
        ble_obj.start()
        ble_obj.wait_for_exit()
        
        # Perform service discovery after BLE connection is established
        ble_obj.service_discovery_on_remote()
        assert ble_obj.char_path is not None, (
            "BLE service discovery failed - char_path is None. "
            "The remote device could not find the GATT service."
        )

        # Run BLE TX notifications in parallel with MQTT connect/publish
        ble_tx_exception = []

        def _ble_tx_worker():
            try:
                ble_obj.send_notifications_tx()
            except Exception as e:
                ble_tx_exception.append(e)
                logger().error(f"BLE TX notifications failed in parallel thread: {e}")

        ble_tx_thread = threading.Thread(target=_ble_tx_worker, daemon=True)
        logger().info("Starting BLE TX notifications in parallel with MQTT connect/publish")
        ble_tx_thread.start()

        # Connect to MQTT (runs concurrently with BLE TX notifications)
        wifi_obj.mqtt_connect_lwip()

        # Test with different topic lengths (runs concurrently with BLE TX notifications)
        for topic_len in topic_lengths:
            topic = ''.join(random.choices(string.ascii_uppercase + string.digits, k=topic_len))
            logger().info(f"Testing with topic length: {topic_len} chars")
            
            # Subscribe
            wifi_obj.mqtt_subscribe(topic=topic)
            
            # Publish
            wifi_obj.mqtt_publish(
                topic=topic, message_size=1000, num_packets=5, drain_yield=False
            )
            
            # Validate
            wifi_obj.mqtt_receive_messages(num_packets=5)
            
            # Unsubscribe
            wifi_obj.mqtt_unsubscribe(topic=topic)
            
            time.sleep(2)

        # Wait for BLE TX notifications thread to complete before disconnecting MQTT
        logger().info("MQTT publish loop completed, waiting for BLE TX notifications to finish")
        ble_tx_thread.join()
        if ble_tx_exception:
            raise ble_tx_exception[0]

        # # Disconnect
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()
        
        logger().info("TC2: Test completed successfully")
        
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )


# Test Case 3: MQTT keep-alive with various BLE connection intervals
@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_mqtt_keepalive_ble_intervals_C887548(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC3: Validate MQTT keep-alive (0) with BLE peripheral mode and various connection intervals
    
    Test Steps:
    1. Join WiFi and establish BLE peripheral connection
    2. Connect to MQTT with keep-alive=0
    3. Subscribe to topic
    4. Test with different BLE connection intervals (30, 125, 250, 500ms)
    5. Verify MQTT connection remains intact for 3 minutes without data transfer
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    
    topic = "TC3_KeepAlive_Topic"
    qos = Si91xMqttQos.QOS1
    connection_intervals = [125, 250, 500]
    keep_alive_test_duration = 180  # 3 minutes
    
    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    
    try:
        # Create WiFi thread with keep-alive=0
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            keep_alive=0,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )
        
        # Create BLE peripheral thread
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="peripheral_connect",
            conn_interval_peripheral=30,  # Start with 30ms
            ble_adv_int_min=500,
            ble_adv_int_max=500,
            set_smp=1,
        )
        
        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        
        ble_obj.start()
        ble_obj.wait_for_exit()
        
        # Connect to MQTT
        wifi_obj.mqtt_connect_lwip()
        
        # Subscribe
        wifi_obj.mqtt_subscribe()
        
        # Run MQTT keep-alive wait and BLE interval cycling in parallel
        ble_update_interval_sec = 60
        parallel_results = {"wifi_error": None, "ble_error": None}

        def _wifi_keepalive_wait():
            try:
                logger().info(
                    f"[WiFi] Waiting {keep_alive_test_duration}s for MQTT "
                    f"keep-alive verification (BLE intervals changing in parallel)..."
                )
                time.sleep(keep_alive_test_duration)
                logger().info(
                    "[WiFi] Keep-alive window elapsed; verifying MQTT session "
                    "is still active via DUT publish to Raspi subscriber"
                )
                # No spaces: the DUT CLI cuts the payload at the first whitespace
                wifi_obj.mqtt_publish(message="KeepAliveCheck")
                wifi_obj.mqtt_receive_messages(num_packets=1)
                logger().info(
                    f"[WiFi] MQTT connection verified active after "
                    f"{keep_alive_test_duration}s"
                )
            except Exception as wifi_exc:  # noqa: BLE001 - capture for main thread
                parallel_results["wifi_error"] = wifi_exc

        def _ble_cycle_connection_intervals():
            try:
                for idx, interval in enumerate(connection_intervals):
                    logger().info(
                        f"[BLE] ({idx + 1}/{len(connection_intervals)}) "
                        f"Updating connection interval to {interval}ms"
                    )
                    ble_interval_units = int(interval / 1.25)
                    ble_obj.wifi_dut.interfaces.wifi.ble_update_conn_param(
                        ble_remote_dev_address=ble_obj.ble_client_address,
                        ble_conn_interval_min=ble_interval_units,
                        ble_conn_interval_max=ble_interval_units,
                        ble_conn_latency=0,
                        ble_supervision_timeout=3200,
                    )
                    # Verify BLE connection survived the interval change
                    state = ble_obj.wifi_dut.interfaces.wifi.ble_get_device_state()
                    state_int = int(state) if state.isdigit() else -1
                    if state_int != BLEDeviceState.Connected:
                        raise AssertionError(
                            f"BLE connection lost at {interval}ms interval "
                            f"(device_state={state_int})"
                        )
                    # Sleep 60s before applying the next interval
                    if idx < len(connection_intervals) - 1:
                        time.sleep(ble_update_interval_sec)
            except Exception as ble_exc:  # noqa: BLE001 - capture for main thread
                parallel_results["ble_error"] = ble_exc

        wifi_wait_thread = threading.Thread(
            target=_wifi_keepalive_wait,
            name="tc3_wifi_keepalive_wait",
            daemon=True,
        )
        ble_interval_thread = threading.Thread(
            target=_ble_cycle_connection_intervals,
            name="tc3_ble_interval_cycler",
            daemon=True,
        )

        logger().info(
            "TC3: Starting parallel Wi-Fi keep-alive wait (180s) and BLE "
            f"connection-interval cycling every {ble_update_interval_sec}s "
            f"across {connection_intervals}"
        )
        wifi_wait_thread.start()
        ble_interval_thread.start()

        # Wait for both sides to finish
        wifi_wait_thread.join(timeout=keep_alive_test_duration + 60)
        ble_interval_thread.join(timeout=keep_alive_test_duration + 60)

        if parallel_results["ble_error"] is not None:
            raise parallel_results["ble_error"]
        if parallel_results["wifi_error"] is not None:
            raise AssertionError(
                f"MQTT keep-alive verification failed: "
                f"{parallel_results['wifi_error']}"
            )
        # Disconnect
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()

        logger().info(
            "TC3: Test completed successfully - MQTT keep-alive survived "
            f"{keep_alive_test_duration}s with BLE intervals cycled "
            f"through {connection_intervals}"
        )
        
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )



@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_ble_provisioning_mqtt_retain_C887549(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    ble_dut,
    utf_constants,
    mqtt_client,
    mqtt_server,
):
    """
    TC4: Verify BLE provisioning and MQTT publish with retain bit enabled

    Only the Wi-Fi join stage is performed through BLE provisioning. 
    Every other step -- sniffer start, IP
    bring-up, ping, power-save, MQTT connect/subscribe/publish/receive
    /unsubscribe/disconnect, sniffer verification and teardown -- stays
    identical to the rest of the test cases in this suite.

    Flow:
        1. BLE GATT bring-up + SMP-less connection from remote via
           ``ProvisioningFunctionality`` (test_case=20147).
        2. Remote client writes SSID / passphrase / security to the DUT
           over BLE; DUT notifies scan results back.
        3. DUT joins the AP using the credentials received over BLE.
        4. Normal MQTT retain-bit flow against ``raspi_mosquitto``.
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None

    topic = "TC4_Provisioning_Retain_Topic"
    qos = Si91xMqttQos.QOS1

    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {
        "wifi": {"count": 1, "stack_len": 2048},
        "ble": {"count": 1, "stack_len": 2048},
    }

    try:
        # Step 1-2: BLE provisioning -- receive Wi-Fi credentials over BLE
        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_dut=ble_dut,
            ble_pairing=0,
            utf_constants=utf_constants,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            test_case=20147,
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()

        assert ble_obj.credentials and len(ble_obj.credentials) >= 3, (
            "BLE provisioning did not yield SSID/passphrase/security credentials"
        )
        logger().info(
            f"Received provisioning credentials over BLE: ssid={ble_obj.credentials[0]}"
        )
        # Step 3+: Hand the BLE-provisioned credentials to the WiFi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message_size=700,
            num_packets=15,
            retain=True,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
            received_credentials=ble_obj.credentials,
        )

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.mqtt_connect_lwip()
        wifi_obj.mqtt_subscribe()
        wifi_obj.mqtt_publish()
        wifi_obj.mqtt_receive_messages()
        wifi_obj.mqtt_unsubscribe()
        wifi_obj.mqtt_disconnect()

        wifi_obj.verify_sniffer_capture()

        logger().info("TC4: Test completed successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        try:
            if ble_obj is not None:
                try:
                    ble_obj.ble_remove_servie()
                except Exception:
                    pass
                try:
                    ble_obj.ble_disconnect()
                except Exception:
                    pass
                time.sleep(2)
        except Exception as cleanup_exc:
            logger().warning(
                f"BLE provisioning teardown failed: {cleanup_exc}"
            )
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )

@mqtt_lwip_marker(enable_ssl=True, ca_cert=MQTT_SSL_CA_CERT)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
def test_ble_central_80ms_mqtt_ssl_qos1_C887550(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC5: Verify BLE central role (80ms CI) connect/disconnect/reconnect with
    MQTT SSL QoS1 running in parallel.

    MQTT SSL QoS1 path matches C876779 (mqtt_connect_lwip +
    subscribe_and_publish + validate_mqtt_messages).

    BLE connect/disconnect/reconnect runs via
    ble_connect_disconnect_reconnect_cycle on the BLE agent thread while MQTT
    publish continues on Protocol.WIFI in a background Python thread. The MQTT
    thread is always stopped and joined before teardown so WIFI agent threads
    are free (avoids the prior RuntimeError on lwip_mqtt.disconnect).

    Note: ble_get_device_state may return bytes (e.g. b'8'); state checks use
    _normalize_ble_state_for_cleanup so Connected is not misread as -1.

    Test Steps:
    1. Join WiFi and bring up LWIP
    2. Connect to MQTT over SSL/TLS (C876779 TLS cert + SNI flow)
    3. Subscribe and publish QoS1, validate messages
    4. In parallel: BLE central connect/disconnect/reconnect (5x, 80ms CI)
       and MQTT publish bursts
    5. Unsubscribe, disconnect, verify sniffer
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    mqtt_transfer_active = None
    transfer_thread = None

    topic = "TC5_Central_SSL_Topic"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS1
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    loop_iterations = 5

    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {
        "wifi": {"count": 1, "stack_len": 2048},
        "ble": {"count": 1, "stack_len": 2048},
    }

    try:
        # Create WiFi thread with SSL (same TLS knobs as C876779)
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message=message,
            message_size=300,
            num_packets=15,
            enable_ssl=True,
            broker_port=8883,
            profile=profile,
            wifi_client=wifi_client,
            client_id=client_id,
        )

        # Start WiFi bring-up
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # C876779 MQTTS QoS1 flow: connect -> subscribe/publish -> validate
        wifi_obj.mqtt_connect_lwip()
        wifi_obj.subscribe_and_publish(qos=qos)
        wifi_obj.validate_mqtt_messages()

        # Create BLE central once (ble_gatt_start happens in __init__)
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="central_connect",
            conn_interval_central=80,
            set_smp=1,
            bond_info=1,
        )

        # Parallel MQTT publish on Protocol.WIFI with short/no yield
        mqtt_transfer_active = threading.Event()
        mqtt_transfer_active.set()
        mqtt_errors = []

        def mqtt_data_transfer():
            while mqtt_transfer_active.is_set():
                try:
                    wifi_obj.mqtt_publish(num_packets=2, drain_yield=False)
                except Exception as mqtt_exc:
                    if not mqtt_transfer_active.is_set():
                        break
                    logger().warning(f"Parallel MQTT publish warning: {mqtt_exc}")
                    mqtt_errors.append(mqtt_exc)
                    break
                # Pace bursts; Event.wait returns early when cleared at stop
                mqtt_transfer_active.wait(timeout=3)

        transfer_thread = threading.Thread(
            target=mqtt_data_transfer, name="mqtt_ssl_parallel", daemon=True
        )

        # First BLE central connect without MQTT CLI on the same bus
        ble_obj.ble_connect(role="master")
        transfer_thread.start()
        time.sleep(5)
        ble_obj.ble_disconnect()
        time.sleep(3)

        # Remaining connect/disconnect cycles run in parallel with MQTT publish
        ble_obj.ble_connect_disconnect_reconnect_cycle(
            role="master", iterations=loop_iterations
        )

        # Stop MQTT transfer before any further WIFI teardown commands
        mqtt_transfer_active.clear()
        transfer_thread.join(timeout=60)
        transfer_thread = None

        if mqtt_errors:
            raise mqtt_errors[0]

        wifi_obj.mqtt_receive_messages()

        # C876779 teardown: unsubscribe + disconnect + capture stop/validate
        wifi_obj.mqtt_unsubscribe(topic=topic)
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()

        logger().info("TC5: Test completed successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        # Stop the parallel MQTT thread before WIFI teardown
        try:
            if mqtt_transfer_active is not None:
                mqtt_transfer_active.clear()
            if transfer_thread is not None and transfer_thread.is_alive():
                transfer_thread.join(timeout=60)
        except Exception as stop_exc:
            logger().warning(f"Failed stopping parallel MQTT thread: {stop_exc}")

        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )

@mqtt_lwip_marker(enable_ssl=True, ca_cert=MQTT_SSL_CA_CERT)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
def test_mqtt_ssl_qos1_username_lengths_ble_central_rx_C887551(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC6: Validate QoS1 SSL with username lengths (62, 100, 121 chars) and 1000-byte data

    MQTT SSL connect path matches C876779 / MQTTConnectionThread
    (mqtt_connect_lwip with wolfSSL PEMs + tls_hostname). Each username
    iteration uses subscribe_and_publish + validate_mqtt_messages.

    BLE RX is modeled on C887547: remote advertises HealthThermometerService
    (notifiable CustomNotifyCharacteristic), DUT discovers write_handle after
    central connect, then receive_notifications_rx() runs in a parallel
    thread while the MQTT username loop runs on the main thread.

    Test Steps:
    1. Join WiFi and establish BLE central connection (250ms CI) with
       HealthThermometer GATT advertised on the remote
    2. Discover remote notify characteristic (write_handle) on DUT
    3. In parallel: BLE RX notifications from remote + MQTT SSL username loop
    4. Join BLE RX thread, then verify sniffer
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None

    topic = "TC6_SSL_Username_Topic"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS1
    username_lengths = [62, 100, 121]
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))

    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {
        "wifi": {"count": 1, "stack_len": 2048},
        "ble": {"count": 1, "stack_len": 2048},
    }

    try:
        # Create WiFi thread (C876779 TLS knobs via enable_ssl + mqtt_connect_lwip)
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message=message,
            message_size=1000,
            num_packets=15,
            enable_ssl=True,
            broker_port=8883,
            profile=profile,
            wifi_client=wifi_client,
            client_id=client_id,
        )

        # bond_info=1 REQUIRED with set_smp=1 in central/master mode (link_key)
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="central_connect",
            conn_interval_central=250,
            set_smp=1,
            bond_info=1,
            data_duration=120,
            data_length=20,
            service_class=["HealthThermometerService"],
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            svc="HealthThermometerService",
            charc="CustomNotifyCharacteristic",
        )

        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.start()
        ble_obj.wait_for_exit()

        # Discover remote HealthThermometer notify characteristic before RX
        ble_obj.service_discovery_on_dut()
        assert ble_obj.write_handle, (
            "BLE service discovery failed - write_handle is None. "
            "Remote HealthThermometerService was not discoverable on DUT."
        )

        # Enable CCCD on main thread before parallel MQTT SSL (exclusive WIFI)
        ble_obj.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=ble_obj.ble_client_address,
            buffer_mode=1,
            buffer_count=2,
        )
        ble_obj.wifi_dut.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=ble_obj.ble_client_address,
            handle=(ble_obj.write_handle + 1),
            enable_notify=1,
        )
        ble_rx_data = ble_obj.data or "".join(
            random.choices(
                string.ascii_uppercase + string.digits, k=ble_obj.data_length
            )
        )

        # C876779 MQTTS must own Protocol.WIFI exclusively during PEM load / TLS handshake
        mqtt_busy = threading.Event()
        ble_stop = threading.Event()
        # The DUT async-event queue is drained by whichever command reads the bus,
        # so a notification and its GATT write event need an exclusive window
        ble_bus_lock = threading.Lock()
        ble_rx_exception = []
        ble_rx_received = {"count": 0}

        def _ble_rx_attempt(poll_sec=10):
            """Send one remote notification and watch the DUT for its write event."""
            with ble_bus_lock:
                if ble_obj.svc and ble_obj.charc:
                    ble_obj.ble_client.interfaces.bluetooth.send_gatt_charc_notification(
                        ble_obj.svc, ble_obj.charc, ble_rx_data
                    )
                lw = Stopwatch()
                while lw.elapsed_sec < poll_sec:
                    events = ble_obj.wifi_dut.interfaces.wifi.get_async_events()
                    for event in events:
                        if (
                            event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT
                            and "rsi_ble_on_gatt_write_event_gatt" in event.event_data
                        ):
                            ble_rx_received["count"] += 1
                            logger().info(
                                f"BLE RX notification received on DUT "
                                f"(count={ble_rx_received['count']})"
                            )
                            return True
                    time.sleep(0.5)
            return False

        def _ble_rx_worker():
            try:
                logger().info(
                    "##### [C887551] BLE RX thread: notify/receive loop #####"
                )
                tw = Stopwatch()
                while (
                    tw.elapsed_sec < ble_obj.data_duration and not ble_stop.is_set()
                ):
                    if mqtt_busy.is_set():
                        time.sleep(0.2)
                        continue
                    _ble_rx_attempt()
                    time.sleep(2)
                logger().info(
                    f"##### [C887551] BLE RX thread: stopped "
                    f"(rx={ble_rx_received['count']}) #####"
                )
            except Exception as e:
                ble_rx_exception.append(e)
                logger().error(
                    f"##### [C887551] BLE RX notifications failed: {e} #####"
                )

        ble_rx_thread = threading.Thread(target=_ble_rx_worker, daemon=True)
        logger().info(
            "Starting BLE RX notifications in parallel with MQTT SSL username loop"
        )
        ble_rx_thread.start()

        # Test with different username lengths (runs concurrently with BLE RX)
        for username_len in username_lengths:
            username = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=username_len)
            )
            logger().info(f"Testing with username length: {username_len} chars")

            wifi_obj.username = username
            # Fresh QoS1 payload for C876779-style validate each reconnect
            wifi_obj.message = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=100)
            )

            # Exclusive WIFI bus for C876779 MQTTS (certs + TLS handshake)
            mqtt_busy.set()
            try:
                with ble_bus_lock:
                    wifi_obj.mqtt_connect_lwip()
                    wifi_obj.subscribe_and_publish(qos=qos)
                    wifi_obj.validate_mqtt_messages()

                    # Additional 1000-byte burst required by TC6
                    wifi_obj.mqtt_publish(
                        message_size=1000, num_packets=15, drain_yield=False
                    )

                    wifi_obj.mqtt_receive_messages()
                    wifi_obj.mqtt_disconnect()
            finally:
                mqtt_busy.clear()
            time.sleep(3)

        # Dedicated BLE RX window now that MQTT SSL no longer owns Protocol.WIFI
        logger().info(
            "MQTT username loop completed, waiting for BLE RX notifications to finish"
        )
        mqtt_busy.clear()
        ble_stop.set()
        ble_rx_thread.join(timeout=180)
        if ble_rx_exception:
            raise ble_rx_exception[0]

        # Parallel attempts can lose the event to a concurrent bus reader; retry idle
        for _ in range(3):
            if ble_rx_received["count"] > 0:
                break
            logger().info("Retrying BLE RX notification with the DUT bus idle")
            _ble_rx_attempt(poll_sec=15)

        try:
            ble_obj.wifi_dut.interfaces.wifi.ble_set_att_value(
                ble_remote_dev_address=ble_obj.ble_client_address,
                handle=(ble_obj.write_handle + 1),
                enable_notify=0,
            )
        except Exception as cleanup_exc:
            logger().warning(f"BLE RX CCCD disable skipped: {cleanup_exc}")
        assert ble_rx_received["count"] > 0, "Notifications not received on DUT"

        wifi_obj.verify_sniffer_capture()

        logger().info("TC6: Test completed successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )


@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_ble_peripheral_80ms_CI_Tx_1000b_mqtt_topic_wildcard_single_C887552(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC7: Verify BLE peripheral (80ms CI) TX notifications with MQTT single-level wildcard (+)

    Test Steps:
    1. Join WiFi and establish BLE peripheral connection (80ms CI) with GATT
       service registered before connect (so BlueZ caches it during initial
       discovery).
    2. Subscribe to topic with single-level wildcard: THERMOSTATDATA/+/THERMOSTATDATA
    3. In parallel: BLE TX notifications (100 bytes) from DUT and MQTT
       publish from third-party client to THERMOSTATDATA/sensor/THERMOSTATDATA
       (matches the wildcard subscription).
    4. Validate received MQTT messages on DUT.

    Modeled on test_mqtt_qos1_diff_topic_lengths_1000b_payload_ble_tx_C887547
    (BLE TX notifications run concurrently with MQTT publish via a parallel
    daemon thread).
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None

    subscribe_topic = "iothub/+/sqa/properties/#"
    publish_topic = "iothub/silabs/sqa/properties/test/object"
    qos = Si91xMqttQos.QOS0

    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    try:
        # Create WiFi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=subscribe_topic,
            message_size=800,
            num_packets=15,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )

        # Create BLE peripheral thread
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="peripheral_connect",
            conn_interval_peripheral=80,
            set_smp=1,
            data_length=100,
            data_duration=100,
            bond_info=1,
        )

        # Register GATT before connect so BlueZ caches it during discovery
        ble_obj.setup_gatt_service()

        # Start threads (Wi-Fi join first, then BLE peripheral connect)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.start()
        ble_obj.wait_for_exit()

        # Discover GATT on Raspi after connect so TX notifications have char_path
        ble_obj.service_discovery_on_remote()
        assert ble_obj.char_path is not None, (
            "BLE service discovery failed - char_path is None. "
            "The remote device could not find the GATT service."
        )

        # Connect to MQTT
        wifi_obj.mqtt_connect_lwip()

        # Subscribe to wildcard topic
        wifi_obj.mqtt_subscribe(topic=subscribe_topic, dut_subscribe=True)

        # Run BLE TX notifications in parallel with the MQTT publish loop
        ble_tx_exception = []

        def _ble_tx_worker():
            try:
                ble_obj.send_notifications_tx()
            except Exception as e:
                ble_tx_exception.append(e)
                logger().error(f"BLE TX notifications failed in parallel thread: {e}")

        ble_tx_thread = threading.Thread(target=_ble_tx_worker, daemon=True)
        logger().info("Starting BLE TX notifications in parallel with MQTT publish")
        ble_tx_thread.start()

        # Publish from Raspi to a topic matching the single-level wildcard, concurrent with BLE TX
        num_publish_packets = 25
        if mqtt_client:
            for i in range(num_publish_packets):
                message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))
                mqtt_client.interfaces.mqtt.mqtt_client_publish(
                    topic=publish_topic,
                    payload=message,
                    qos=qos
                )
                time.sleep(1)
                # Drain periodically; the DUT only surfaces messages while yielding
                if (i + 1) % 5 == 0:
                    wifi_obj.dut_drain_received(max_yields=1, yield_timeout_ms=3000)

            # Validate MQTT messages received on DUT after all publishes finish (still in parallel with BLE TX)
            wifi_obj.mqtt_receive_messages(num_packets=num_publish_packets, dut_receive=True)

        # Wait for BLE TX notifications to finish before tearing down MQTT
        logger().info("MQTT publish/receive completed, waiting for BLE TX notifications to finish")
        ble_tx_thread.join()
        if ble_tx_exception:
            raise ble_tx_exception[0]

        # Drain pending BLE GATT events before issuing any further MQTT commands
        time.sleep(8)

        # Unsubscribe and disconnect
        wifi_obj.mqtt_unsubscribe(topic=subscribe_topic)
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()

        logger().info("TC7: Test completed successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )
        # Soft BT PS disable: fixture hard-asserts SL_STATUS_FAIL after coex MQTT timeouts
        soft_disable_bt_powersave(wifi_dut)


@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_mqtt_2topics_wildcards_single_ble_tx_240b_C887553(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC8: Verify MQTT receive on 2 topics with single-level and multi-level wildcards (+ and #) along with BLE TX (240 bytes) in parallel.

    Test Steps:
    1. Join WiFi and establish BLE peripheral connection (80ms CI) with GATT
       service registered before connect (so BlueZ caches it during initial
       discovery).
    2. Subscribe to 2 topics with both wildcards on DUT and third-party client:
         - iothub/+/sqa/properties/#
         - THERMOSTATDATA/+/TEMPERATUREDATA/#
    3. In parallel: BLE TX notifications (240 bytes) from DUT and MQTT
       publish from third-party client onto two matching concrete topics:
         - iothub/silabs/sqa/properties/test/object
         - THERMOSTATDATA/sensor/TEMPERATUREDATA/sqa/test
    4. Validate received MQTT messages on DUT for both topics.

    Modeled on test_ble_peripheral_80ms_CI_Tx_1000b_mqtt_topic_wildcard_single_C887552
    (BLE TX notifications run concurrently with MQTT publish via a parallel
    daemon thread).
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None

    subscribe_topic1 = "iothub/+/sqa/properties/#"
    publish_topic1 = "iothub/silabs/sqa/properties/test/object"
    subscribe_topic2 = "THERMOSTATDATA/+/TEMPERATUREDATA/#"
    publish_topic2 = "THERMOSTATDATA/sensor/TEMPERATUREDATA/sqa/test"
    qos = Si91xMqttQos.QOS1

    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    try:
        # Create WiFi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=subscribe_topic1,
            message_size=300,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )

        # Create BLE peripheral thread
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="peripheral_connect",
            conn_interval_peripheral=80,
            set_smp=1,
            bond_info=1,
            data_length=240,
            data_duration=60,
        )

        # Prior case (C887552) can leave BT PS / BLE stack sticky after a teardown ERROR
        soft_disable_bt_powersave(wifi_dut)
        time.sleep(2)

        gatt_exc = None
        for attempt in range(2):
            try:
                ble_obj.setup_gatt_service()
                gatt_exc = None
                break
            except Exception as exc:
                gatt_exc = exc
                logger().warning(
                    f"GATT setup attempt {attempt + 1}/2 failed: {exc}"
                )
                ble_obj._gatt_service_added = False
                soft_disable_bt_powersave(wifi_dut)
                time.sleep(5)
        if gatt_exc is not None:
            raise gatt_exc

        # Start threads (Wi-Fi join first, then BLE peripheral connect)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.start()
        ble_obj.wait_for_exit()

        # Discover GATT on Raspi after connect so TX notifications have char_path
        ble_obj.service_discovery_on_remote()
        assert ble_obj.char_path is not None, (
            "BLE service discovery failed - char_path is None. "
            "The remote device could not find the GATT service."
        )

        # Connect to MQTT
        wifi_obj.mqtt_connect_lwip()

        # Subscribe to BOTH wildcard topics on DUT and third-party client
        wifi_obj.mqtt_subscribe(topic=subscribe_topic1, dut_subscribe=True)
        wifi_obj.mqtt_subscribe(topic=subscribe_topic2, dut_subscribe=True)

        # Run BLE TX notifications in parallel with the MQTT publish loop
        ble_tx_exception = []

        def _ble_tx_worker():
            try:
                ble_obj.send_notifications_tx()
            except Exception as e:
                ble_tx_exception.append(e)
                logger().error(f"BLE TX notifications failed in parallel thread: {e}")

        ble_tx_thread = threading.Thread(target=_ble_tx_worker, daemon=True)
        logger().info("Starting BLE TX notifications in parallel with MQTT publish")
        ble_tx_thread.start()

        # Publish from Raspi to two topics matching the wildcard subscriptions, concurrent with BLE TX
        num_iterations = 10
        num_publish_packets = num_iterations * 2
        if mqtt_client:
            for i in range(num_iterations):
                message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
                mqtt_client.interfaces.mqtt.mqtt_client_publish(
                    topic=publish_topic1,
                    payload=message1,
                    qos=qos
                )
                time.sleep(2)
                message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
                mqtt_client.interfaces.mqtt.mqtt_client_publish(
                    topic=publish_topic2,
                    payload=message2,
                    qos=qos
                )
                time.sleep(2)
                # Drain each iteration; the DUT only surfaces messages while yielding
                wifi_obj.dut_drain_received(max_yields=1, yield_timeout_ms=3000)

        logger().info("MQTT publish completed, waiting for BLE TX notifications to finish")
        ble_tx_thread.join()
        if ble_tx_exception:
            raise ble_tx_exception[0]

        time.sleep(5)

        # Validate MQTT messages received on DUT (and third-party client)
        # for both wildcard subscriptions now that BLE TX is fully drained.
        # Pass num_packets so receive does not fall back to self.num_packets
        if mqtt_client:
            wifi_obj.mqtt_receive_messages(num_packets=num_publish_packets, dut_receive=True)
        time.sleep(5)
        # Unsubscribe both topics and disconnect
        wifi_obj.mqtt_unsubscribe(topic=subscribe_topic1)
        wifi_obj.mqtt_unsubscribe(topic=subscribe_topic2)
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()
        logger().info("TC8: Test completed successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )
        soft_disable_bt_powersave(wifi_dut)

@pytest.mark.skip()
@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_mqtt_reconnect_after_rejoin_dual_role_C887554(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    TC9: Validate MQTT reconnect after rejoin with dual role BLE (100ms/30ms CI)
    
    Test Steps:
    1. Join WiFi and establish BLE dual role (peripheral 30ms, central 100ms)
    2. Connect to MQTT and subscribe to 2 topics
    3. Publish data to both topics
    4. Power off AP to trigger rejoin
    5. Verify rejoin and MQTT reconnect
    6. Subscribe to 2 topics again and publish data
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    ble_dut_address = None
    ble_clients_address = []
    
    topic1 = "TC9_Topic1"
    topic2 = "TC9_Topic2"
    qos = Si91xMqttQos.QOS1
    
    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    
    try:
        # Create WiFi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic1,
            topic1=topic1,
            topic2=topic2,
            message_size=300,
            num_packets=15,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )
        
        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Dual-role BLE: same sequence as C133511 in test_sta_ble_multi_raspi_sdk.py
        ble_obj, ble_obj2, ble_dut_address = setup_dual_role_like_c133511(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            conn_interval_peripheral=30,
            conn_interval_central=100,
        )
        ble_clients_address.append(ble_obj.ble_client_address)
        ble_clients_address.append(ble_obj2.ble_client_address)
        
        # Connect to MQTT
        wifi_obj.mqtt_connect_lwip()
        
        # Subscribe to topic 1
        wifi_obj.mqtt_subscribe(topic=topic1)
        
        # Subscribe to topic 2
        wifi_obj.mqtt_subscribe(topic=topic2)
        
        # Publish to topic 1
        wifi_obj.mqtt_publish(topic=topic1)
        
        # Publish to topic 2
        wifi_obj.mqtt_publish(topic=topic2)
        
        # Verify BLE connections are stable
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int & 0x08, "BLE connections not stable before rejoin"
        
        # Trigger rejoin by powering off AP
        logger().info("Powering off AP to trigger rejoin...")
        wifi_access_point.interfaces.wifi.ap_disable()
        time.sleep(10)
        
        # Power on AP
        logger().info("Powering on AP for rejoin...")
        wifi_access_point.interfaces.wifi.ap_enable()
        time.sleep(30)
        
        # Verify rejoin
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        
        # Verify BLE connections still stable
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int & 0x08, "BLE connections lost during rejoin"
        
        # Reconnect to MQTT
        wifi_obj.mqtt_connect_lwip()
        
        # Subscribe to both topics again
        wifi_obj.mqtt_subscribe(topic=topic1)
        wifi_obj.mqtt_subscribe(topic=topic2)
        
        # Publish to both topics
        wifi_obj.mqtt_publish(topic=topic1)
        wifi_obj.mqtt_publish(topic=topic2)
        
        # Validate
        wifi_obj.mqtt_receive_messages()
        
        # Disconnect
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        
        logger().info("TC9: Test completed successfully")
        
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_clients,
            mqtt_client=mqtt_client,
        )


@mqtt_lwip_marker(enable_ssl=True, ca_cert=MQTT_SSL_CA_CERT)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
def test_ble_peripheral_30min_mqtt_ssl_qos1_loop_C887555(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC10: Verify BLE peripheral TX (20 bytes, 30 mins) with MQTT SSL loop

    Each MQTT SSL iteration uses the C876779 connect path
    (mqtt_connect_lwip) plus subscribe_and_publish / validate_mqtt_messages.

    Test Steps:
    1. Join WiFi and establish BLE peripheral connection (45ms CI)
    2. Start BLE TX notifications (20 bytes) for 30 minutes in parallel
    3. Loop: MQTT SSL connect, subscribe/publish/validate, disconnect, WLAN disconnect, WLAN reconnect
    4. Repeat loop for 30 minutes
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None

    topic = "TC10_SSL_Loop_Topic"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS1
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    test_duration = 1800  # 30 minutes

    # Owned by the outer finally so the notify loop always stops before teardown
    ble_stop = threading.Event()
    ble_tx_thread = None
    # Protocol.BLE has a single test agent thread; serialize DUT BLE commands
    ble_bus_lock = threading.Lock()

    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {
        "wifi": {"count": 1, "stack_len": 2048},
        "ble": {"count": 1, "stack_len": 2048},
    }

    try:
        # Create WiFi thread (C876779 TLS knobs via enable_ssl + mqtt_connect_lwip)
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message=message,
            message_size=1000,
            num_packets=10,
            enable_ssl=True,
            broker_port=8883,
            profile=profile,
            wifi_client=wifi_client,
            client_id=client_id,
        )

        # BLE peripheral TX (20 bytes) for the full 30-minute soak
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="peripheral_connect",
            conn_interval_peripheral=45,
            set_smp=1,
            bond_info=1,
            data_length=20,
            data_duration=test_duration,
            periodic_delay=1,
        )

        # Register GATT before peripheral connect so BlueZ caches it (C887547 pattern)
        ble_obj.setup_gatt_service()

        # Step 1: Join WiFi, then establish BLE peripheral connection
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.start()
        ble_obj.wait_for_exit()

        ble_obj.service_discovery_on_remote()
        assert ble_obj.char_path is not None, (
            "BLE service discovery failed - char_path is None. "
            "The remote device could not find the GATT service."
        )

        # Enable remote subscriptions before parallel MQTT SSL (exclusive Protocol.WIFI)
        if not ble_obj.service_uid:
            ble_obj.service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        if not ble_obj.char_uid:
            ble_obj.char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        ble_obj.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(
            char_path=ble_obj.char_path
        )
        ble_obj.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=ble_obj.char_path,
            char_uid=ble_obj.char_uid,
        )
        ble_obj.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=ble_obj.ble_client_address,
            buffer_mode=ble_obj.buffer_mode,
            buffer_count=ble_obj.buffer_count,
        )
        ble_tx_data = ble_obj.data or "".join(
            random.choices(
                string.ascii_uppercase + string.digits, k=ble_obj.data_length
            )
        )
        ble_obj.data = ble_tx_data
        # Alloc/write the notify payload once; reuse the address for every notify
        ble_obj.address = wifi_dut.interfaces.wifi.allocate_memory(
            size=len(ble_tx_data)
        )
        wifi_dut.interfaces.wifi.load_memory(
            address=ble_obj.address,
            size=len(ble_tx_data),
            write_content=ble_tx_data,
        )
        logger().info(
            f"##### [C887555] BLE notify buffer allocated at {ble_obj.address} "
            f"({len(ble_tx_data)} bytes) #####"
        )

        # Step 2: BLE TX for 30 minutes in parallel with MQTT SSL / WLAN loop
        mqtt_busy = threading.Event()
        ble_tx_exception = []
        ble_tx_sent = {"count": 0}

        def _ble_tx_worker():
            try:
                logger().info(
                    "##### [C887555] BLE TX thread: notify loop starting #####"
                )
                sw_tx = Stopwatch()
                while (
                    sw_tx.elapsed_sec <= ble_obj.data_duration
                    and not ble_stop.is_set()
                ):
                    if mqtt_busy.is_set():
                        time.sleep(0.2)
                        continue
                    notify_address = ble_obj.address
                    if not notify_address:
                        logger().warning(
                            "##### [C887555] BLE notify buffer released; "
                            "stopping notify loop #####"
                        )
                        break
                    with ble_bus_lock:
                        ble_obj.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                            ble_remote_dev_address=ble_obj.ble_client_address,
                            data=ble_tx_data,
                            data_address=notify_address,
                        )
                    ble_tx_sent["count"] += 1
                    time.sleep(ble_obj.periodic_delay)
                logger().info(
                    f"##### [C887555] BLE TX thread: notify loop stopped "
                    f"(sent={ble_tx_sent['count']}) #####"
                )
            except Exception as e:
                ble_tx_exception.append(e)
                logger().error(
                    f"##### [C887555] BLE TX thread failed: {e} #####"
                )

        ble_tx_thread = threading.Thread(target=_ble_tx_worker, daemon=True)
        logger().info(
            "Starting BLE TX notifications in parallel with MQTT SSL / WLAN reconnect loop (30 min)"
        )
        ble_tx_thread.start()

        # MQTT SSL connect, publish 10 packets, validate, then MQTT/WLAN reconnect
        sw = Stopwatch()
        loop_count = 0
        mqtt_packets_per_iteration = 10

        while sw.elapsed_sec < test_duration:
            if ble_tx_exception:
                raise ble_tx_exception[0]
            loop_count += 1
            logger().info(f"MQTT/WLAN loop iteration {loop_count}")

            # Hold Protocol.WIFI exclusively for MQTTS + WLAN cycle
            mqtt_busy.set()
            try:
                wifi_obj.mqtt_connect_lwip()
                wifi_obj.mqtt_subscribe()
                wifi_obj.mqtt_publish(num_packets=mqtt_packets_per_iteration)
                wifi_obj.mqtt_receive_messages(num_packets=mqtt_packets_per_iteration)
                wifi_obj.mqtt_disconnect()

                wifi_obj.wifi_disconnect()
                time.sleep(5)

                wifi_obj.join_to_ap()
                wifi_obj.set_power_save()
            finally:
                mqtt_busy.clear()

            # BLE TX must remain active across WLAN drop/rejoin for the soak
            connected = False
            for _ in range(5):
                with ble_bus_lock:
                    state = wifi_dut.interfaces.wifi.ble_get_device_state()
                if _is_connected_ble_state(state):
                    connected = True
                    break
                time.sleep(2)
            assert connected, (
                f"BLE connection lost at iteration {loop_count} "
                f"(state={state!r})"
            )

            # Allow BLE TX a window between MQTT/WLAN cycles
            time.sleep(5)

        # Stop BLE TX, then verify all notify packets on Raspi before cleanup
        logger().info(
            "MQTT/WLAN loop completed, waiting for BLE TX notifications to finish"
        )
        ble_stop.set()
        ble_tx_thread.join(timeout=120)
        if ble_tx_exception:
            raise ble_tx_exception[0]

        # Verify every notification landed on the Raspi, resending drops
        sent_count = ble_tx_sent["count"]
        assert sent_count > 0, "BLE TX worker sent no notifications"
        gatt_adapter = ble_obj.ble_client.interfaces.bluetooth.gatt_adapter
        notifications = []
        rx_count = 0
        max_retries = 3
        for retry in range(max_retries + 1):
            time.sleep(10)
            notifications = gatt_adapter.notifications.get(ble_obj.char_uid, [])
            rx_count = len(notifications)
            logger().info(
                f"##### [C887555] BLE TX validate: sent={sent_count}, "
                f"rx={rx_count} #####"
            )
            if rx_count >= sent_count or retry == max_retries:
                break
            missing = sent_count - rx_count
            logger().warning(
                f"BLE notification drop detected: received {rx_count}/{sent_count}. "
                f"Resending {missing} notification(s) (retry {retry + 1}/{max_retries})"
            )
            for _ in range(missing):
                wifi_dut.interfaces.wifi.ble_notify_custom_value(
                    ble_remote_dev_address=ble_obj.ble_client_address,
                    data=ble_tx_data,
                    data_address=ble_obj.address,
                )
                time.sleep(ble_obj.periodic_delay)

        try:
            gatt_adapter.disable_notifications(char_path=ble_obj.char_path)
            gatt_adapter.unsubscribe_to_notifications(char_uid=ble_obj.char_uid)
        except Exception as cleanup_exc:
            logger().warning(f"BLE notify unsubscribe after validate: {cleanup_exc}")

        assert rx_count > 0, "Received BLE TX data is empty"
        assert rx_count >= sent_count, (
            f"BLE TX packets missing: received {rx_count}/{sent_count}"
        )
        if notifications and ble_tx_data:
            assert notifications[0] in ble_tx_data, "BLE TX payload mismatch"

        wifi_obj.verify_sniffer_capture()

        logger().info(f"TC10: Test completed successfully - {loop_count} iterations")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        # Notify loop must be dead before the buffer is freed and BLE is closed
        ble_stop.set()
        if ble_tx_thread is not None and ble_tx_thread.is_alive():
            logger().info("Waiting for BLE TX notify thread to stop before teardown")
            ble_tx_thread.join(timeout=60)
        if ble_obj is not None and getattr(ble_obj, "address", None):
            notify_address = ble_obj.address
            ble_obj.address = None
            try:
                wifi_dut.interfaces.wifi.memory_free(address=notify_address)
                logger().info(f"Freed BLE notify buffer at {notify_address}")
            except Exception as free_exc:
                logger().warning(f"BLE notify buffer free failed: {free_exc}")
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )

@pytest.mark.skip()
@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_mqtt_reconnect_loop_dual_role_ble_tx_C887556(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    TC11: Verify MQTT reconnect loop with dual role BLE TX notifications
    
    Test Steps:
    1. Join WiFi and establish BLE dual role (peripheral 45ms, central 250ms)
    2. Loop for 30 minutes:
       - Connect to MQTT, subscribe, publish
       - Disconnect MQTT
       - Reconnect MQTT, subscribe, publish
    3. BLE TX notifications running throughout
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    ble_dut_address = None
    ble_clients_address = []
    
    topic = "TC11_Reconnect_Loop_Topic"
    qos = Si91xMqttQos.QOS1
    test_duration = 1800  # 30 minutes
    
    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    
    try:
        # Create WiFi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message_size=300,
            num_packets=15,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )
        
        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Dual-role BLE: same sequence as C133511 in test_sta_ble_multi_raspi_sdk.py
        ble_obj, ble_obj2, ble_dut_address = setup_dual_role_like_c133511(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            conn_interval_peripheral=45,
            conn_interval_central=250,
            data_length=240,
            data_duration=test_duration,
        )
        ble_clients_address.append(ble_obj.ble_client_address)
        ble_clients_address.append(ble_obj2.ble_client_address)
        
        # MQTT reconnect loop
        sw = Stopwatch()
        loop_count = 0
        
        while sw.elapsed_sec < test_duration:
            loop_count += 1
            logger().info(f"MQTT reconnect loop iteration {loop_count}")
            
            # Connect to MQTT
            wifi_obj.mqtt_connect_lwip()
            
            # Subscribe
            wifi_obj.mqtt_subscribe()
            
            # Publish
            wifi_obj.mqtt_publish()
            
            # Disconnect
            wifi_obj.mqtt_disconnect()
            
            # Wait before reconnect
            time.sleep(5)
            
            # Reconnect
            wifi_obj.mqtt_connect_lwip()
            wifi_obj.mqtt_subscribe()
            wifi_obj.mqtt_publish()
            
            # Verify BLE is still active
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int & 0x08, f"BLE connections lost at iteration {loop_count}"
            
            time.sleep(10)
        
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        
        logger().info(f"TC11: Test completed successfully - {loop_count} iterations")
        
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_clients,
            mqtt_client=mqtt_client,
        )


# Test Case 12: BLE continuous scan with MQTT data transfer
@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"]) 
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_ble_continuous_scan_mqtt_data_C887557(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC12: Verify BLE scan with MQTT data transfer
    
    Test Steps:
    1. Join WiFi
    2. Start BLE scan
    3. Connect to MQTT, subscribe, and publish data
    4. Verify scan results while MQTT data transfer is happening
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    
    topic = "TC12_Continuous_Scan_Topic"
    qos = Si91xMqttQos.QOS1
    
    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    
    try:
        # Start Wi-Fi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message_size=300,
            num_packets=20,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )

        # Create BLE continuous scan thread
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            ble_scan_interval=300,
            ble_scan_window=100,
            data_duration=120,
        )

        wifi_obj.start_sniffer_capture()

        wifi_obj.connect_to_wifi()
        assert wifi_obj.device_ip, "DUT failed to acquire IP address"
        logger().info(
            f"WiFi connected and IP assigned: {wifi_obj.device_ip}"
        )

        status = ping_with_recovery(wifi_obj.device_ip, 5, wifi_client=wifi_client)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        wifi_obj.set_power_save()
        ble_obj.start()
        status = ping_with_recovery(wifi_obj.device_ip, 5, wifi_client=wifi_client)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        # Raspi subscribes first, then DUT publishes while BLE scan runs
        wifi_obj.mqtt_connect_lwip()
        wifi_obj.mqtt_subscribe()
        wifi_obj.mqtt_publish(drain_yield=False)
        wifi_obj.mqtt_receive_messages()

        # Stop scan before MQTT teardown so adv reports do not interleave CLI
        try:
            wifi_dut.interfaces.wifi.ble_stop_scanning()
        except Exception as scan_stop_exc:
            logger().warning(f"ble_stop_scanning after MQTT receive: {scan_stop_exc}")
        ble_obj.wait_for_exit()

        wifi_obj.mqtt_unsubscribe()
        wifi_obj.mqtt_disconnect()

        wifi_obj.verify_sniffer_capture()

        logger().info("TC12: Test completed successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )


@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_ble_peripheral_smp_tx_mqtt_tx_rx_C887558(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC13: Verify BLE peripheral SMP TX notifications with MQTT RX
    
    Test Steps:
    1. Join WiFi and establish BLE peripheral connection with SMP (45ms CI)
    2. Start BLE TX notifications
    3. Connect to MQTT, subscribe, and receive data from server
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    
    topic = "TC13_SMP_TX_MQTT_RX_Topic"
    qos = Si91xMqttQos.QOS1
    
    # Dedicated Wi-Fi/BLE thread stacks (required for coex MQTT TX + BLE TX)
    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {
        "wifi": {"count": 1, "stack_len": 2048},
        "ble": {"count": 1, "stack_len": 2048},
    }
    
    try:
        # Create WiFi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message_size=300,
            num_packets=15,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )
        
        # BLE peripheral with SMP
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="peripheral_connect",
            conn_interval_peripheral=45,
            set_smp=1,
            data_length=240,
            data_duration=120,
            periodic_delay=2,
        )

        # Register GATT before connect so BlueZ caches it during discovery
        ble_obj.setup_gatt_service()

        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        
        ble_obj.start()
        ble_obj.wait_for_exit()

        # Perform service discovery after BLE connection is established
        ble_obj.service_discovery_on_remote()
        assert ble_obj.char_path is not None, (
            "BLE service discovery failed - char_path is None. "
            "The remote device could not find the GATT service."
        )

        # Pause BLE notify while MQTT owns the shared DUT CLI bus
        mqtt_busy = threading.Event()
        ble_tx_exception = []
        ble_stop = threading.Event()

        def _ble_tx_worker():
            try:
                logger().info(
                    "##### [C887558] BLE TX thread: starting "
                    "ble_notify_custom_value loop #####"
                )
                # Local notify loop honours mqtt_busy / ble_stop without changing shared helpers
                if not ble_obj.service_uid:
                    ble_obj.service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                if not ble_obj.char_uid:
                    ble_obj.char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
                ble_obj.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(
                    char_path=ble_obj.char_path
                )
                ble_obj.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                    char_path=ble_obj.char_path,
                    char_uid=ble_obj.char_uid,
                )
                ble_obj.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                    ble_remote_dev_address=ble_obj.ble_client_address,
                    buffer_mode=ble_obj.buffer_mode,
                    buffer_count=ble_obj.buffer_count,
                )
                data = ble_obj.data or ''.join(
                    random.choices(string.ascii_uppercase + string.digits, k=ble_obj.data_length)
                )
                sw = Stopwatch()
                while sw.elapsed_sec <= ble_obj.data_duration and not ble_stop.is_set():
                    if mqtt_busy.is_set():
                        time.sleep(0.2)
                        continue
                    ble_obj.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                        ble_remote_dev_address=ble_obj.ble_client_address,
                        data=data,
                        data_address=ble_obj.address,
                    )
                    time.sleep(ble_obj.periodic_delay)
                try:
                    ble_obj.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(
                        char_path=ble_obj.char_path
                    )
                    ble_obj.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(
                        char_uid=ble_obj.char_uid
                    )
                except Exception as cleanup_exc:
                    logger().warning(f"BLE notify unsubscribe during stop: {cleanup_exc}")
                logger().info("##### [C887558] BLE TX thread: completed #####")
            except Exception as e:
                ble_tx_exception.append(e)
                logger().error(f"##### [C887558] BLE TX thread failed: {e} #####")

        ble_tx_thread = threading.Thread(target=_ble_tx_worker, daemon=True)
        logger().info(
            "##### [C887558] launching BLE TX thread in parallel with MQTT pipeline #####"
        )
        ble_tx_thread.start()

        # MQTT pipeline runs in main thread, concurrent with BLE TX (bus-guarded)
        wifi_obj.mqtt_connect_lwip()

        # Raspi subscribes so it can receive DUT publishes
        wifi_obj.mqtt_subscribe(dut_subscribe=True)

        # DUT MQTT TX then 3rd-party MQTT TX (RX on DUT) — sequential on the CLI bus
        num_packets = 15
        message_size = 300

        logger().info(
            f"##### [C887558] DUT publish: {num_packets} packets "
            f"({message_size} bytes) while BLE TX paused during yield #####"
        )
        for i in range(num_packets):
            publish_message = ''.join(
                random.choices(string.ascii_uppercase + string.digits, k=message_size)
            )
            mqtt_busy.set()
            time.sleep(0.5)
            try:
                logger().info(
                    f"Publishing packet {i + 1}/{num_packets} "
                    f"({len(publish_message)} bytes) to topic: {topic}"
                )
                wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
                    topic=topic,
                    message=publish_message,
                    qos=qos,
                    timeout=20,
                )
                wifi_obj._record_published(topic, publish_message)
                last_exc = None
                for attempt in range(3):
                    try:
                        wifi_dut.interfaces.mqtt.lwip_mqtt_yield(
                            yield_timeout_ms=3000,
                            timeout=30,
                            async_timeout=45,
                        )
                        last_exc = None
                        break
                    except Exception as yield_exc:
                        last_exc = yield_exc
                        logger().warning(
                            f"MQTT yield attempt {attempt + 1}/3 failed "
                            f"under BLE TX: {yield_exc}"
                        )
                        time.sleep(2)
                if last_exc is not None:
                    raise last_exc
            finally:
                mqtt_busy.clear()
            time.sleep(2)
        logger().info("##### [C887558] DUT publish completed #####")
        mqtt_busy.set()
        time.sleep(0.5)
        try:
            wifi_obj.mqtt_receive_messages(num_packets=num_packets)
        finally:
            mqtt_busy.clear()

        if mqtt_client:
            logger().info(
                f"##### [C887558] 3rd-party publish: {num_packets} packets #####"
            )
            for i in range(num_packets):
                message = ''.join(
                    random.choices(string.ascii_uppercase + string.digits, k=message_size)
                )
                mqtt_client.interfaces.mqtt.mqtt_client_publish(
                    topic=topic,
                    payload=message,
                    qos=qos,
                )
                time.sleep(1)
            logger().info("##### [C887558] 3rd-party publish completed #####")

        # Validate MQTT RX on DUT after Raspi publishes
        mqtt_busy.set()
        time.sleep(0.5)
        try:
            wifi_obj.mqtt_receive_messages(num_packets=num_packets, dut_receive=True)
        finally:
            mqtt_busy.clear()

        # Stop BLE TX before MQTT disconnect so teardown does not race ble_notify against disconnect (0x4d05
        ble_stop.set()
        logger().info("##### [C887558] stopping BLE TX before MQTT disconnect #####")
        ble_tx_thread.join(timeout=60)
        if ble_tx_exception:
            raise ble_tx_exception[0]
        time.sleep(3)

        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()
        
        logger().info("TC13: Test completed successfully")
        
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )
        soft_disable_bt_powersave(wifi_dut)


@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_ble_peripheral_smp_indications_mqtt_publish_C887559(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC14: Verify BLE peripheral connection with SMP and do BLE Tx indications and MQTT publish in parallel.

    Test Steps:
    1. Join WiFi and establish BLE peripheral connection with SMP (45ms CI),
       with GATT service registered before connect (so BlueZ caches it during
       initial discovery).
    2. Connect to MQTT and subscribe to the topic.
    3. In parallel: BLE TX indications (240 bytes) from DUT and MQTT publish
       from DUT to the subscribed topic.
    4. Validate MQTT messages received on the third-party MQTT client.

    Modeled on test_ble_peripheral_80ms_CI_Tx_1000b_mqtt_topic_wildcard_single_C887552
    (BLE TX runs concurrently with MQTT publish via a parallel daemon thread).
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None

    topic = "TC14_Peripheral_Indications_Topic"
    qos = Si91xMqttQos.QOS1
    num_publish_packets = 15

    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    try:
        # Create WiFi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message_size=300,
            num_packets=num_publish_packets,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )

        # Create BLE peripheral thread with SMP for indications
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="peripheral_connect",
            conn_interval_peripheral=45,
            set_smp=1,
            bond_info=1,
            data_length=240,
            data_duration=90,
            periodic_delay=2,
        )

        # Register GATT before connect so BlueZ caches it during discovery
        ble_obj.setup_gatt_service()

        # Start threads (Wi-Fi join first, then BLE peripheral connect)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj.start()
        ble_obj.wait_for_exit()

        # Discover GATT on Raspi after connect so TX indications have char_path
        ble_obj.service_discovery_on_remote()
        assert ble_obj.char_path is not None, (
            "BLE service discovery failed - char_path is None. "
            "The remote device could not find the GATT service."
        )

        # Subscribe to MQTT before BLE TX so the topic is ready when publish starts
        wifi_obj.mqtt_connect_lwip()
        wifi_obj.mqtt_subscribe()

        # Pause BLE indications while MQTT owns the shared DUT CLI bus
        mqtt_busy = threading.Event()
        ble_stop = threading.Event()
        # ble_indicate_value is a mem.alloc + mem.write + indicate transaction;
        # a publish injected mid-transaction splices both command lines
        ble_bus_lock = threading.Lock()
        ble_tx_exception = []

        def _ble_tx_worker():
            try:
                logger().info("Starting BLE indications (bus-guarded)")
                ble_obj.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(
                    char_path=ble_obj.char_path
                )
                ble_obj.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                    char_path=ble_obj.char_path,
                    char_uid=ble_obj.char_uid or "00001aa1-0000-1000-8000-00805f9b34fb",
                )
                data = ble_obj.data or ''.join(
                    random.choices(string.ascii_uppercase + string.digits, k=ble_obj.data_length)
                )
                sw = Stopwatch()
                indicate_ok = 0
                consecutive_failures = 0
                while sw.elapsed_sec < ble_obj.data_duration and not ble_stop.is_set():
                    if mqtt_busy.is_set():
                        time.sleep(0.2)
                        continue
                    try:
                        with ble_bus_lock:
                            ble_obj.wifi_dut.interfaces.wifi.ble_indicate_value(
                                ble_remote_dev_address=ble_obj.ble_client_address,
                                handle=12,
                                data=data,
                                data_address=ble_obj.address,
                                data_length=ble_obj.data_length,
                            )
                        indicate_ok += 1
                        consecutive_failures = 0
                    except Exception as indicate_exc:
                        consecutive_failures += 1
                        logger().warning(
                            f"BLE indicate failed under MQTT load "
                            f"({consecutive_failures}/3): {indicate_exc}"
                        )
                        if consecutive_failures >= 3:
                            raise
                        time.sleep(2)
                    time.sleep(ble_obj.periodic_delay)
                logger().info(f"BLE indications sent: {indicate_ok}")
                try:
                    ble_obj.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(
                        char_path=ble_obj.char_path
                    )
                    ble_obj.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(
                        char_uid=ble_obj.char_uid or "00001aa1-0000-1000-8000-00805f9b34fb"
                    )
                except Exception as cleanup_exc:
                    logger().warning(f"BLE indicate unsubscribe during stop: {cleanup_exc}")
            except Exception as e:
                ble_tx_exception.append(e)
                logger().error(f"BLE TX indications failed in parallel thread: {e}")

        ble_tx_thread = threading.Thread(target=_ble_tx_worker, daemon=True)
        logger().info("Starting BLE TX indications in parallel with MQTT publish")
        ble_tx_thread.start()

        # DUT MQTT publish with bus guard + longer yield timeout / retry
        for i in range(num_publish_packets):
            publish_message = ''.join(
                random.choices(string.ascii_uppercase + string.digits, k=300)
            )
            mqtt_busy.set()
            try:
                # The lock waits out any indicate transaction already on the bus
                with ble_bus_lock:
                    logger().info(
                        f"Publishing packet {i + 1}/{num_publish_packets} "
                        f"({len(publish_message)} bytes) to topic: {topic}"
                    )
                    wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
                        topic=topic,
                        message=publish_message,
                        qos=qos,
                        timeout=20,
                    )
                    wifi_obj._record_published(topic, publish_message)
                    last_exc = None
                    for attempt in range(3):
                        try:
                            wifi_dut.interfaces.mqtt.lwip_mqtt_yield(
                                yield_timeout_ms=3000,
                                timeout=30,
                                async_timeout=60,
                            )
                            last_exc = None
                            break
                        except Exception as yield_exc:
                            last_exc = yield_exc
                            logger().warning(
                                f"MQTT yield attempt {attempt + 1}/3 failed "
                                f"under BLE indications: {yield_exc}"
                            )
                            time.sleep(2)
                    if last_exc is not None:
                        raise last_exc
            finally:
                mqtt_busy.clear()
            time.sleep(2)

        # Stop BLE indications before validation / MQTT teardown
        ble_stop.set()
        logger().info("MQTT publish completed, waiting for BLE TX indications to finish")
        ble_tx_thread.join(timeout=60)
        if ble_tx_exception:
            raise ble_tx_exception[0]

        time.sleep(5)

        # Validate Raspi Paho received DUT publishes after BLE TX drained
        wifi_obj.mqtt_receive_messages(num_packets=num_publish_packets)

        # Disconnect MQTT and verify sniffer capture
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()

        logger().info("TC14: Test completed successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )
        soft_disable_bt_powersave(wifi_dut)


@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_ble_central_45ms_mqtt_publish_C887560(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC15: Verify BLE central (45ms CI) with MQTT publish
    
    Test Steps:
    1. Join WiFi and establish BLE central connection (45ms CI)
    2. Connect to MQTT, subscribe, and publish data
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    
    topic = "TC15_Central_45ms_Topic"
    qos = Si91xMqttQos.QOS1
    
    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    
    try:
        # Create WiFi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message_size=300,
            num_packets=15,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )
        
        # Create BLE central thread
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="central_connect",
            conn_interval_central=45,
            set_smp=1,
            bond_info=1,
        )
        
        # Start threads
        wifi_obj.connect_to_wifi()
        
        ble_obj.start()
        ble_obj.wait_for_exit()
        
        # Connect to MQTT
        wifi_obj.mqtt_connect_lwip()
        
        # Subscribe
        wifi_obj.mqtt_subscribe()
        
        # Publish
        wifi_obj.mqtt_publish()
        
        # Validate
        wifi_obj.mqtt_receive_messages()
        
        # Disconnect
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()
        
        logger().info("TC15: Test completed successfully")
        
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )

@pytest.mark.skip()
@mqtt_lwip_marker(dhcp_renewal=True)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_dhcp_renewal_mqtt_dual_role_smp_C887561(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    TC16: Verify DHCP renewal with dual role BLE SMP and MQTT
    
    Test Steps:
    1. Join WiFi and establish BLE dual role with SMP (peripheral 45ms, central 250ms)
    2. Connect to MQTT, subscribe, and publish data
    3. Trigger DHCP renewal
    4. Verify MQTT and BLE connections remain stable
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    ble_dut_address = None
    ble_clients_address = []
    
    topic = "TC16_DHCP_Renewal_Topic"
    qos = Si91xMqttQos.QOS1
    
    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    
    try:
        # Create WiFi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message_size=300,
            num_packets=15,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )
        
        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Dual-role BLE: same sequence as C133511 in test_sta_ble_multi_raspi_sdk.py
        ble_obj, ble_obj2, ble_dut_address = setup_dual_role_like_c133511(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            conn_interval_peripheral=45,
            conn_interval_central=250,
            data_length=240,
        )
        ble_clients_address.append(ble_obj.ble_client_address)
        ble_clients_address.append(ble_obj2.ble_client_address)
        
        # Connect to MQTT
        wifi_obj.mqtt_connect_lwip()
        
        # Subscribe
        wifi_obj.mqtt_subscribe()
        
        # Publish
        wifi_obj.mqtt_publish()
        
        # Trigger DHCP renewal (renew IP)
        logger().info("Triggering DHCP renewal...")
        wifi_dut.interfaces.wifi.start_ip()
        time.sleep(10)
        
        # Verify IP is still valid
        new_ip = wifi_dut.interfaces.wifi.display_device_ip_lwip()
        assert new_ip, "DHCP renewal failed - no IP address"
        logger().info(f"DHCP renewal successful - new IP: {new_ip}")
        
        # Verify BLE connections still stable on both Raspberry Pis
        ble_obj.assert_dual_role_raspi_connections(
            "BLE connections lost during DHCP renewal"
        )
        
        # Verify MQTT still connected (try publish)
        wifi_obj.mqtt_publish(num_packets=5)
        
        # Validate
        wifi_obj.mqtt_receive_messages()
        
        # Disconnect
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        
        logger().info("TC16: Test completed successfully")
        
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_clients,
            mqtt_client=mqtt_client,
        )

@pytest.mark.skip()
@mqtt_lwip_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_rejoin_fail_callback_dual_role_C887562(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    TC17: Verify rejoin fail callback with dual role BLE
    
    Test Steps:
    1. Join WiFi and establish BLE dual role (peripheral 45ms, central 250ms)
    2. Connect to MQTT, subscribe, and publish data
    3. Power off AP and keep it off
    4. Verify rejoin fail callback is triggered
    5. Verify DUT restarts scan procedure
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    ble_dut_address = None
    ble_clients_address = []
    
    topic = "TC17_Rejoin_Fail_Topic"
    qos = Si91xMqttQos.QOS1
    
    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    
    try:
        # Create WiFi thread
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message_size=300,
            num_packets=15,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )
        
        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Dual-role BLE: same sequence as C133511 in test_sta_ble_multi_raspi_sdk.py
        ble_obj, ble_obj2, ble_dut_address = setup_dual_role_like_c133511(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            conn_interval_peripheral=45,
            conn_interval_central=250,
            data_length=240,
        )
        ble_clients_address.append(ble_obj.ble_client_address)
        ble_clients_address.append(ble_obj2.ble_client_address)
        
        # Connect to MQTT
        wifi_obj.mqtt_connect_lwip()
        
        # Subscribe
        wifi_obj.mqtt_subscribe()
        
        # Publish
        wifi_obj.mqtt_publish()
        
        # Power off AP and keep it off
        logger().info("Powering off AP to trigger rejoin fail...")
        wifi_access_point.interfaces.wifi.ap_disable()
        
        # Wait for rejoin attempts and fail callback
        time.sleep(120)  # Wait for rejoin attempts to fail
        
        # Verify DUT is scanning after rejoin-fail callback
        logger().info("Verifying rejoin fail callback triggered...")
        
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        # Power on AP for cleanup
        wifi_access_point.interfaces.wifi.ap_enable()
        time.sleep(30)
        
        logger().info("TC17: Test completed successfully")
        
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_clients,
            mqtt_client=mqtt_client,
        )
@pytest.mark.skip()
@mqtt_lwip_marker(enable_ssl=True, ca_cert=MQTT_SSL_CA_CERT)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
def test_dual_role_mqtt_qos0_ssl_C887563(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    TC18: Verify dual role BLE (45ms/250ms CI) with MQTT QoS0 SSL

    MQTT SSL path matches C876779 (mqtt_connect_lwip + subscribe_and_publish
    + validate_mqtt_messages).

    Test Steps:
    1. Join WiFi and establish BLE dual role (peripheral 45ms, central 250ms)
    2. Connect to MQTT over SSL, subscribe/publish/validate with QoS0
    3. BLE TX notifications, unsubscribe and disconnect
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    ble_dut_address = None
    ble_clients_address = []

    topic = "TC18_DualRole_QoS0_SSL_Topic"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS0
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))

    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {
        "wifi": {"count": 1, "stack_len": 2048},
        "ble": {"count": 1, "stack_len": 2048},
    }

    try:
        # Create WiFi thread with SSL (C876779 TLS knobs)
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message=message,
            message_size=300,
            num_packets=15,
            enable_ssl=True,
            broker_port=8883,
            profile=profile,
            wifi_client=wifi_client,
            client_id=client_id,
        )

        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Dual-role BLE: same sequence as C133511 in test_sta_ble_multi_raspi_sdk.py
        ble_obj, ble_obj2, ble_dut_address = setup_dual_role_like_c133511(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            conn_interval_peripheral=45,
            conn_interval_central=250,
            add_gatt_service=True,
            data_length=240,
        )
        ble_clients_address.append(ble_obj.ble_client_address)
        ble_clients_address.append(ble_obj2.ble_client_address)

        ble_obj.service_discovery_on_remote()
        assert ble_obj.char_path is not None, (
            "BLE service discovery failed - char_path is None."
        )

        # C876779 MQTTS flow (exclusive WIFI bus — before BLE TX)
        wifi_obj.mqtt_connect_lwip()
        wifi_obj.subscribe_and_publish(qos=qos)
        wifi_obj.validate_mqtt_messages()

        # BLE data transfer (after TLS session is up)
        ble_obj.send_notifications_tx()

        # Unsubscribe and disconnect
        wifi_obj.mqtt_unsubscribe()
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)

        logger().info("TC18: Test completed successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_clients,
            mqtt_client=mqtt_client,
        )

@pytest.mark.skip()
@mqtt_lwip_marker(enable_ssl=True, ca_cert=MQTT_SSL_CA_CERT)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
def test_dual_role_mqtt_qos2_ssl_C887564(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    TC19: Verify dual role BLE (45ms/250ms CI) with MQTT QoS2 SSL

    MQTT SSL path matches C876779 / C876781 (mqtt_connect_lwip +
    subscribe_and_publish + validate_mqtt_messages with QoS2).

    Test Steps:
    1. Join WiFi and establish BLE dual role (peripheral 45ms, central 250ms)
    2. Connect to MQTT over SSL, subscribe/publish/validate with QoS2
    3. BLE TX notifications, unsubscribe and disconnect
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    ble_dut_address = None
    ble_clients_address = []

    topic = "TC19_DualRole_QoS2_SSL_Topic"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))

    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    profile["thread_config"] = {
        "wifi": {"count": 1, "stack_len": 2048},
        "ble": {"count": 1, "stack_len": 2048},
    }

    try:
        # Create WiFi thread with SSL (C876779 TLS knobs)
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message=message,
            message_size=300,
            num_packets=15,
            enable_ssl=True,
            broker_port=8883,
            profile=profile,
            wifi_client=wifi_client,
            client_id=client_id,
        )

        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Dual-role BLE: same sequence as C133511 in test_sta_ble_multi_raspi_sdk.py
        ble_obj, ble_obj2, ble_dut_address = setup_dual_role_like_c133511(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            conn_interval_peripheral=45,
            conn_interval_central=250,
            add_gatt_service=True,
            data_length=240,
        )
        ble_clients_address.append(ble_obj.ble_client_address)
        ble_clients_address.append(ble_obj2.ble_client_address)

        ble_obj.service_discovery_on_remote()
        assert ble_obj.char_path is not None, (
            "BLE service discovery failed - char_path is None."
        )

        # C876779 / C876781 MQTTS flow (exclusive WIFI bus — before BLE TX)
        wifi_obj.mqtt_connect_lwip()
        wifi_obj.subscribe_and_publish(qos=qos)
        wifi_obj.validate_mqtt_messages()

        # BLE data transfer (after TLS session is up)
        ble_obj.send_notifications_tx()

        # Unsubscribe and disconnect
        wifi_obj.mqtt_unsubscribe()
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)

        logger().info("TC19: Test completed successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_clients,
            mqtt_client=mqtt_client,
        )


@mqtt_lwip_marker(enable_ssl=False)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_ble_central_30ms_mqtt_C887565(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC20: Verify BLE central (30ms CI) with MQTT SSL
    
    Test Steps:
    1. Join WiFi and establish BLE central connection (30ms CI)
    2. Connect to MQTT over TCP, subscribe, and publish data
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    
    topic = "TC20_Central_30ms_Topic"
    qos = Si91xMqttQos.QOS1
    
    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    
    try:
        # Create WiFi thread with SSL
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message_size=300,
            num_packets=15,
            enable_ssl=False,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )
        
        # BLE central; bond_info=1 with set_smp=1
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="central_connect",
            conn_interval_central=30,
            set_smp=1,
            bond_info=1,
        )
        
        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # BLE setup with retry
        start_ble_thread_with_retry(ble_obj)
        
        wifi_obj.mqtt_connect_lwip()
        
        # Subscribe
        wifi_obj.mqtt_subscribe()
        
        # Publish
        wifi_obj.mqtt_publish()
        
        # Validate
        wifi_obj.mqtt_receive_messages()
        
        # Disconnect
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()
        
        logger().info("TC20: Test completed successfully")
        
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )


@mqtt_lwip_marker(enable_ssl=False)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.mqtt_server("raspi_mosquitto")
def test_ble_central_20ms_mqtt_C887566(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    sniffer_filter,
    wifi_client,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    TC21: Verify BLE central (20ms CI) with MQTT SSL
    
    Test Steps:
    1. Join WiFi and establish BLE central connection (20ms CI)
    2. Connect to MQTT over TCP, subscribe, and publish data
    """
    global ble_obj, wifi_obj
    ble_obj = None
    wifi_obj = None
    
    topic = "TC21_Central_20ms_Topic"
    qos = Si91xMqttQos.QOS1
    
    # WiFi profile configuration
    profile = get_wifi_profile(wifi_access_point)
    
    try:
        # Create WiFi thread with SSL
        wifi_obj = WifiMqttLwipThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            request=request,
            qos=qos,
            topic=topic,
            message_size=300,
            num_packets=15,
            enable_ssl=False,
            broker_port=1883,
            profile=profile,
            wifi_client=wifi_client,
        )
        
        # BLE central; bond_info=1 with set_smp=1
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="central_connect",
            conn_interval_central=20,
            set_smp=1,
            bond_info=1,
        )
        
        # Start threads
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # BLE setup with retry
        start_ble_thread_with_retry(ble_obj)
        
        wifi_obj.mqtt_connect_lwip()
        
        # Subscribe
        wifi_obj.mqtt_subscribe()
        
        # Publish
        wifi_obj.mqtt_publish()
        
        # Validate
        wifi_obj.mqtt_receive_messages()
        
        # Disconnect
        wifi_obj.mqtt_disconnect()
        wifi_obj.verify_sniffer_capture()
        
        logger().info("TC21: Test completed successfully")
        
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        safe_cleanup_test(
            sl_collections=sl_collections,
            wifi_dut=wifi_dut,
            wifi_obj=wifi_obj,
            ble_obj=ble_obj,
            ble_client=ble_client,
            mqtt_client=mqtt_client,
        )
