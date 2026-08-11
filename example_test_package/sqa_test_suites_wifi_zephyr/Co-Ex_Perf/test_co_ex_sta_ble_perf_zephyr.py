"""
Zephyr WLAN STA + BLE connected coexistence performance cases.

Reference traffic flow (structure):
  test_wlan_standalone_perf_11ax_zephyr.py  (TCP TX / TCP RX / UDP TX / UDP RX)

Reference co-ex BLE data + WLAN traffic:
  test_throughput_co_ex_sdk.py  (wlan_ble_conn_data_* cases)

BLE connection / notify (Zephyr APIs):
  test_agent_zephyr COMMANDS_BT.md — static GATT 0xfff0 / notify slot 3 (0xfff4)

Uses Zephyr DUT APIs from zephyr_wifi_test_agent_cli.py:
  ble_start / bt_set_local_name / ble_start_advertising / ble_get_device_state /
  ble_notify_custom_value (bt gatt_notify) / join / iperf / leave

Cases:
  1-4. STA + BLE connected + TCP/UDP TX/RX (assert BLE still connected after traffic)
  5-8. STA + BLE connected + BLE GATT notify data + TCP/UDP TX/RX

Author: Benazeer K
"""

import time
from threading import Thread

import pytest

from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utf_config import UtfConfig
from utf.utils import print_dict
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase


def logger():
    return get_logger(__name__)


def _print_throughput(throughput):
    if throughput is not None:
        print_dict("##     ", throughput)


def _common_zephyr_coex_dut_config():
    return {
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    }


class device_scan_result:
    def check_for_devices_in_scanned_results(self, ble_client, bt_dut_address, adv_data=None):
        """Find DUT in BlueZ scan by BD_ADDR (Zephyr AD is FLAGS-only)."""
        sw = Stopwatch()
        previously_found_devices = {}
        dut = (bt_dut_address or "").upper().replace("-", ":")
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices() or {}
            if previously_found_devices != found_devices:
                logger().info(f"BLE scan results :{found_devices}")
                previously_found_devices = found_devices

            for key, reported in found_devices.items():
                key_norm = str(key).upper().replace("-", ":")
                if key_norm != dut:
                    continue
                logger().info(
                    f"DUT {dut} found in scan (reported={reported!r}, adv_data={adv_data!r})"
                )
                return True
        return False


def setup_ble_connection(wifi_dut, ble_client, zephyr_wifi_collections):
    """Advertise DUT and connect from remote BLE client.

    Returns:
        (bt_dut_address, bt_client_address)
    """
    wifi = wifi_dut.interfaces.wifi
    conn_params = {
        "min_conn_interval": 0xA0,
        "max_conn_interval": 0xA0,
        "conn_latency": 0,
        "supervision_timeout": 3200,
    }

    logger().info("Initializing BLE")
    bt_dut_address = wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
    logger().info("configure bt local name....")
    wifi.bt_set_local_name(bt_local_name="Silabsautomation")
    logger().info("fetch the local name")
    wifi.bt_get_local_name()
    # Clear stale ADV from a prior case (err -120 if already advertising)
    try:
        wifi.ble_stop_advertising()
        time.sleep(1)
    except Exception as e:
        logger().info(f"ble_stop_advertising before start (best-effort): {e}")
    logger().info("Advertising DUT (connectable, public identity)")
    wifi.ble_start_advertising(
        ble_adv_type=128,
        ble_adv_int_min=160,
        ble_adv_int_max=240,
        ble_adv_channel_map=7,
    )

    logger().info("Initiating scan from remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
    )
    assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"

    device_found = device_scan_result().check_for_devices_in_scanned_results(
        ble_client=ble_client,
        bt_dut_address=bt_dut_address,
        adv_data=None,
    )
    assert device_found, "DUT not found in scan results"

    logger().info("initiating stop scanning")
    ble_client.interfaces.bluetooth.stop_scanning()
    time.sleep(2)

    logger().info("Initiating connection from remote device")
    ble_client.interfaces.bluetooth.connect(
        dev_addr=bt_dut_address,
        min_conn_interval=conn_params["min_conn_interval"],
        max_conn_interval=conn_params["max_conn_interval"],
        conn_latency=conn_params["conn_latency"],
        supervision_timeout=conn_params["supervision_timeout"],
    )
    time.sleep(10)

    logger().info("Checking connection status of BLE")
    state = wifi.ble_get_device_state()
    state_int = int(state) if str(state).isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
    logger().info(f"BLE connected: DUT={bt_dut_address}, peer={bt_client_address}")
    return bt_dut_address, bt_client_address


def assert_ble_connected_after_traffic(wifi_dut):
    """Confirm BLE link survived WLAN traffic (co-ex still healthy)."""
    logger().info("Checking BLE connection state after WLAN traffic")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if str(state).isdigit() else -1
    logger().info(f"BLE device state after traffic: {state} ({state_int})")
    assert state_int == BLEDeviceState.Connected, (
        f"BLE disconnected after WLAN traffic (state={state}); co-ex failed"
    )
    logger().info("BLE still connected after WLAN traffic — co-ex OK")


def cleanup_ble_connection(wifi_dut, ble_client=None, bt_dut_address=None, ble_client_address=None):
    """Best-effort BLE teardown so the next case can advertise/scan cleanly."""
    wifi = wifi_dut.interfaces.wifi
    try:
        if ble_client is not None and bt_dut_address:
            ble_client.interfaces.bluetooth.disconnect(dev_addr=bt_dut_address)
    except Exception as e:
        logger().info(f"ble_client disconnect (best-effort): {e}")
    try:
        if ble_client_address:
            wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
    except Exception as e:
        logger().info(f"DUT ble_disconnect (best-effort): {e}")
    try:
        wifi.ble_stop_advertising()
    except Exception as e:
        logger().info(f"ble_stop_advertising (best-effort): {e}")


class CoexWifiJoin(ThreadBase):
    """Join AP (and optionally start TX iperf) while BLE stays connected."""

    TRAFFIC_TCP_TX = "TCP_TX"
    TRAFFIC_TCP_RX = "TCP_RX"
    TRAFFIC_UDP_TX = "UDP_TX"
    TRAFFIC_UDP_RX = "UDP_RX"

    def __init__(
        self,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_sniffer=None,
        net_perf_client=None,
        wifi_client=None,
        protocol=None,
        capture_filename=None,
        zephyr_wifi_collections=None,
        traffic=None,
        qos=0,
        traffic_type=None,
        run_tx_in_thread=True,
        power_save=False,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.traffic = traffic
        self.qos = qos
        self.traffic_type = traffic_type
        self.run_tx_in_thread = run_tx_in_thread
        self.power_save = power_save
        self.dut_addr = None
        self.host_ip = None
        self.ap_mac_address = None
        self.iperf_throughput = None

    def print_throughput(self):
        _print_throughput(self.iperf_throughput)

    def run(self):
        try:
            if self.wifi_sniffer is not None:
                logger().info(
                    f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}"
                )
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel
                )
                self.wifi_sniffer.interfaces.capture.start_capture(
                    capture_file=f"{self.capture_filename}"
                )

            self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                self.wifi_dut,
                self.wifi_access_point,
                associated=self.wifi_dut.interfaces.wifi.associated,
                retry_count=3,
                power_save=self.power_save,
                ping_after_power_save=True,
            )
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"******** AP MAC ADDRESS is {self.ap_mac_address} *******")
            self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"***** Host IP Address is {self.host_ip} ******")

            if not self.run_tx_in_thread:
                return

            if self.traffic_type == self.TRAFFIC_TCP_TX:
                self._run_tcp_tx()
            elif self.traffic_type == self.TRAFFIC_UDP_TX:
                self._run_udp_tx()

        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
            raise

    def _run_tcp_tx(self):
        self.net_perf_client.interfaces.net_perf.init_server(
            host_ip=self.host_ip,
            device_ip=self.dut_addr["device_ip"],
            protocol=self.protocol,
            tos_value=self.traffic,
        )
        logger().info(
            f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, "
            f"Protocol: {self.protocol}, tos_value: {self.traffic}"
        )
        logger().info("***** starting iperf (TCP TX) ******")
        self.net_perf_client.interfaces.net_perf.start()
        logger().info("***** send traffic ******")
        self.wifi_dut.interfaces.wifi.iperf(
            family=2,
            transfer_type=1,
            protocol=6,
            local_port=self.net_perf_client.interfaces.net_perf.server_port,
            local_ip=self.dut_addr["device_ip"],
            remote_ip=self.host_ip,
            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
            size=1460,
            ttl=30,
            throughput_type=1,
            qos=self.qos,
        )
        logger().info("***** get and print throughput ******")
        self.iperf_throughput = self.net_perf_client.interfaces.net_perf.process_output()
        assert self.iperf_throughput, "failed to get throughput..."
        self.print_throughput()
        logger().info("data transfer is successful")

    def _run_udp_tx(self):
        self.net_perf_client.interfaces.net_perf.init_server(
            host_ip=self.host_ip,
            device_ip=self.dut_addr["device_ip"],
            protocol=self.protocol,
            tos_value=self.traffic,
        )
        logger().info(
            f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, "
            f"Protocol: {self.protocol}, tos_value: {self.traffic}"
        )
        logger().info("***** starting iperf (UDP TX) ******")
        self.net_perf_client.interfaces.net_perf.start()
        logger().info("***** send traffic ******")
        self.wifi_dut.interfaces.wifi.iperf(
            family=2,
            transfer_type=2,
            protocol=17,
            local_port=self.net_perf_client.interfaces.net_perf.server_port,
            local_ip=self.dut_addr["device_ip"],
            remote_ip=self.host_ip,
            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
            size=1460,
            ttl=30,
            throughput_type=2,
            qos=self.qos,
        )
        logger().info("***** get and print throughput ******")
        self.iperf_throughput = self.net_perf_client.interfaces.net_perf.process_output()
        assert self.iperf_throughput, "failed to get throughput..."
        self.print_throughput()
        logger().info("data transfer is successful")

    def stop_sniffer_and_leave(self):
        time.sleep(2)
        logger().info("Dut going to leave the AP")
        self.wifi_dut.interfaces.wifi.leave()
        if self.wifi_sniffer is not None:
            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop Sniffer finally")


def _run_tcp_rx(wifi_dut, net_perf_client, wifi_obj, protocol):
    host_ip = wifi_obj.host_ip
    net_perf_client.interfaces.net_perf.init_client(
        host_ip=host_ip,
        device_ip=wifi_obj.dut_addr["device_ip"],
        protocol=protocol,
    )
    logger().info(
        f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}"
    )

    def start_client():
        time.sleep(3)
        logger().info("***** Connect to server  ******")
        net_perf_client.interfaces.net_perf.start()

    client_thread = Thread(target=start_client, args=())
    client_thread.start()

    logger().info("***** Start listening (TCP RX) ******")
    wifi_dut.interfaces.wifi.iperf(
        family=2,
        transfer_type=1,
        protocol=6,
        local_port=net_perf_client.interfaces.net_perf.client_port,
        local_ip=wifi_obj.dut_addr["device_ip"],
        remote_ip=host_ip,
        remote_port=net_perf_client.interfaces.net_perf.client_port,
        size=1470,
        ttl=30,
        throughput_type=3,
        qos=0,
    )
    client_thread.join()
    logger().info("data transfer is successful")


def _run_udp_rx(wifi_dut, net_perf_client, wifi_obj, protocol):
    net_perf_client.interfaces.net_perf.init_client(
        host_ip=wifi_obj.host_ip,
        device_ip=wifi_obj.dut_addr["device_ip"],
        protocol=protocol,
        bandwidth="68M",
    )
    logger().info(
        f"Host IP: {wifi_obj.host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, "
        f"Protocol: {protocol}"
    )
    logger().info("***** starting iperf (UDP RX) ******")
    net_perf_client.interfaces.net_perf.start()
    logger().info("***** send traffic  ******")
    wifi_dut.interfaces.wifi.iperf(
        family=2,
        transfer_type=2,
        protocol=17,
        local_port=net_perf_client.interfaces.net_perf.client_port,
        local_ip=wifi_obj.dut_addr["device_ip"],
        remote_ip=wifi_obj.host_ip,
        remote_port=net_perf_client.interfaces.net_perf.client_port,
        size=1470,
        ttl=30,
        throughput_type=4,
    )
    logger().info("data transfer is successful")


# ********************************************************************************************************************
# Case 1: STA + BLE connected + TCP TX
# ********************************************************************************************************************
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_coex_dut_config())
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=["init", "ap_enabled"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [("0xc8", 0)])
def test_coex_sta_ble_tcp_tx_zephyr(
    wifi_sniffer,
    net_perf_client,
    wifi_access_point,
    wifi_dut,
    request,
    wifi_client,
    ble_client,
    protocol,
    zephyr_wifi_collections,
    traffic,
    qos,
):
    """Zephyr co-ex: STA + BLE connected, TCP TX traffic (ref: 11ax C148311)."""
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"**** power_save flag from harness = {power_save} ****")
    bt_dut_address = ble_client_address = None
    wifi_obj = None
    try:
        with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_coex_sta_ble_tcp_tx_zephyr_{int(time.time())}.log",
        ):
            bt_dut_address, ble_client_address = setup_ble_connection(
                wifi_dut, ble_client, zephyr_wifi_collections
            )

        wifi_obj = CoexWifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            traffic=traffic,
            qos=qos,
            traffic_type=CoexWifiJoin.TRAFFIC_TCP_TX,
            run_tx_in_thread=True,
            power_save=False,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        assert_ble_connected_after_traffic(wifi_dut)
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        cleanup_ble_connection(
            wifi_dut, ble_client, bt_dut_address, ble_client_address
        )
        if wifi_obj is not None:
            wifi_obj.stop_sniffer_and_leave()


# ********************************************************************************************************************
# Case 2: STA + BLE connected + TCP RX
# ********************************************************************************************************************
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_coex_dut_config())
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=["init", "ap_enabled"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_coex_sta_ble_tcp_rx_zephyr(
    wifi_sniffer,
    net_perf_client,
    wifi_access_point,
    wifi_dut,
    request,
    wifi_client,
    ble_client,
    protocol,
    zephyr_wifi_collections,
):
    """Zephyr co-ex: STA + BLE connected, TCP RX traffic (ref: 11ax C148320)."""
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"**** power_save flag from harness = {power_save} ****")
    bt_dut_address = ble_client_address = None
    wifi_obj = None
    try:
        with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_coex_sta_ble_tcp_rx_zephyr_{int(time.time())}.log",
        ):
            bt_dut_address, ble_client_address = setup_ble_connection(
                wifi_dut, ble_client, zephyr_wifi_collections
            )

        wifi_obj = CoexWifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            traffic_type=CoexWifiJoin.TRAFFIC_TCP_RX,
            run_tx_in_thread=False,
            power_save=False,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        time.sleep(2)
        _run_tcp_rx(wifi_dut, net_perf_client, wifi_obj, protocol)
        assert_ble_connected_after_traffic(wifi_dut)
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        cleanup_ble_connection(
            wifi_dut, ble_client, bt_dut_address, ble_client_address
        )
        if wifi_obj is not None:
            wifi_obj.stop_sniffer_and_leave()


# ********************************************************************************************************************
# Case 3: STA + BLE connected + UDP TX
# ********************************************************************************************************************
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_coex_dut_config())
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=["init", "ap_enabled"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos", [("0xc8", 0)])
def test_coex_sta_ble_udp_tx_zephyr(
    wifi_sniffer,
    net_perf_client,
    wifi_access_point,
    wifi_dut,
    request,
    wifi_client,
    ble_client,
    protocol,
    zephyr_wifi_collections,
    traffic,
    qos,
):
    """Zephyr co-ex: STA + BLE connected, UDP TX traffic (ref: 11ax C148316)."""
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"**** power_save flag from harness = {power_save} ****")
    bt_dut_address = ble_client_address = None
    wifi_obj = None
    try:
        with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_coex_sta_ble_udp_tx_zephyr_{int(time.time())}.log",
        ):
            bt_dut_address, ble_client_address = setup_ble_connection(
                wifi_dut, ble_client, zephyr_wifi_collections
            )

        wifi_obj = CoexWifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            traffic=traffic,
            qos=qos,
            traffic_type=CoexWifiJoin.TRAFFIC_UDP_TX,
            run_tx_in_thread=True,
            power_save=False,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        assert_ble_connected_after_traffic(wifi_dut)
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        cleanup_ble_connection(
            wifi_dut, ble_client, bt_dut_address, ble_client_address
        )
        if wifi_obj is not None:
            wifi_obj.stop_sniffer_and_leave()


# ********************************************************************************************************************
# Case 4: STA + BLE connected + UDP RX
# ********************************************************************************************************************
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_coex_dut_config())
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=["init", "ap_enabled"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_coex_sta_ble_udp_rx_zephyr(
    wifi_sniffer,
    net_perf_client,
    wifi_access_point,
    wifi_dut,
    request,
    wifi_client,
    ble_client,
    protocol,
    zephyr_wifi_collections,
):
    """Zephyr co-ex: STA + BLE connected, UDP RX traffic (ref: 11ax C148320 UDP)."""
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"**** power_save flag from harness = {power_save} ****")
    bt_dut_address = ble_client_address = None
    wifi_obj = None
    try:
        with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_coex_sta_ble_udp_rx_zephyr_{int(time.time())}.log",
        ):
            bt_dut_address, ble_client_address = setup_ble_connection(
                wifi_dut, ble_client, zephyr_wifi_collections
            )

        wifi_obj = CoexWifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            traffic_type=CoexWifiJoin.TRAFFIC_UDP_RX,
            run_tx_in_thread=False,
            power_save=False,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        _run_udp_rx(wifi_dut, net_perf_client, wifi_obj, protocol)
        assert_ble_connected_after_traffic(wifi_dut)
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        cleanup_ble_connection(
            wifi_dut, ble_client, bt_dut_address, ble_client_address
        )
        if wifi_obj is not None:
            wifi_obj.stop_sniffer_and_leave()


# ********************************************************************************************************************
# BLE GATT notify helpers (Zephyr static service 0xfff0 / char 0xfff4 = notify slot 3)
# Ref: test_throughput_co_ex_sdk.py ble_data_transfer path + COMMANDS_BT.md §6
# ********************************************************************************************************************
ZEPHYR_GATT_SVC_UUID = "0000fff0-0000-1000-8000-00805f9b34fb"
ZEPHYR_GATT_NTF_CHAR_UUID = "0000fff4-0000-1000-8000-00805f9b34fb"
BLE_NOTIFY_PAYLOAD = (
    "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdata"
)


class BleNotifyThread(ThreadBase):
    """Periodic GATT notifications from DUT while WLAN traffic runs (SDK ble_notify)."""

    def __init__(self, wifi_dut, ble_client_address=None, duration_sec=35, interval_sec=0.5):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client_address = ble_client_address
        self.duration_sec = duration_sec
        self.interval_sec = interval_sec
        self.notify_count = 0

    def run(self):
        sw = Stopwatch()
        while sw.elapsed_sec < self.duration_sec:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                data=BLE_NOTIFY_PAYLOAD,
                ble_remote_dev_address=self.ble_client_address,
                slot=3,
            )
            self.notify_count += 1
            time.sleep(self.interval_sec)
        logger().info(f"BLE notify thread done: sent {self.notify_count} notifications")


def setup_ble_gatt_notify_subscribe(wifi_dut, ble_client, ble_client_address):
    """Discover 0xfff0/0xfff4 + enable notifications on BlueZ peer.

    BlueZ typically completes ATT MTU exchange on connect (often 247). Calling
    DUT `gatt_mtu_exchange` again is optional and can TIMEOUT waiting for a
    duplicate async event — only attempt it best-effort.
    """
    logger().info("Ensuring ATT MTU for BLE notify payload (best-effort)")
    try:
        mtu = wifi_dut.interfaces.wifi.ble_set_mtu(
            ble_remote_dev_address=ble_client_address
        )
        logger().info(f"ATT MTU after ensure: {mtu}")
    except Exception as e:
        logger().info(f"ble_set_mtu skipped/failed (BlueZ may already have MTU): {e}")
    time.sleep(1)

    logger().info("Resolving Zephyr GATT services/characteristics on peer")
    servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
    assert len(servs) > 0, "no GATT services fetched from DUT"
    assert len(chars) > 0, "GATT characteristics empty"

    char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
        services=servs,
        service_uid=ZEPHYR_GATT_SVC_UUID,
        char_uid=ZEPHYR_GATT_NTF_CHAR_UUID,
    )
    assert char_path, "notify characteristic 0xfff4 not found on DUT"
    assert len(char_props) > 0, "notify characteristic props empty"

    ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
    ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
    # Ensure a fresh notification buffer for this run
    try:
        ble_client.interfaces.bluetooth.gatt_adapter.clear_notifications()
    except Exception:
        pass
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
        char_path=char_path, char_uid=ZEPHYR_GATT_NTF_CHAR_UUID
    )
    logger().info(f"Subscribed to DUT notify char {ZEPHYR_GATT_NTF_CHAR_UUID} path={char_path}")
    return char_path, ZEPHYR_GATT_NTF_CHAR_UUID


def _bluez_encode_notification_payload(payload: str) -> str:
    """Match BlueZ GATT adapter storage: ''.join(str(byte) for byte in data if byte != 0)."""
    return "".join(str(b) for b in payload.encode("utf-8") if b != 0)


def _notification_matches_payload(received, expected_payload: str) -> bool:
    if received is None:
        return False
    if isinstance(received, (bytes, bytearray)):
        try:
            received = received.decode("utf-8", errors="replace")
        except Exception:
            received = str(received)
    received = str(received)
    if received == expected_payload:
        return True
    if received == _bluez_encode_notification_payload(expected_payload):
        return True
    # Truncation / partial match under co-ex load
    if expected_payload and expected_payload in received:
        return True
    encoded = _bluez_encode_notification_payload(expected_payload)
    if encoded and encoded in received:
        return True
    return False


def teardown_ble_gatt_notify(
    ble_client,
    char_path,
    char_uid,
    expect_notifications=True,
    expected_payload=BLE_NOTIFY_PAYLOAD,
    sent_count=None,
    min_remote_count=1,
):
    """Unsubscribe on BlueZ and verify DUT notifications were received remotely (SDK Validate Data)."""
    logger().info("Unsubscribing remote BLE notifications")
    try:
        ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
    except Exception as e:
        logger().info(f"BLE notify teardown warning: {e}")
    time.sleep(1)

    if not expect_notifications:
        return

    logger().info("====================== Validate remote BLE notification data ======================")
    gatt = ble_client.interfaces.bluetooth.gatt_adapter
    notifications = gatt.notifications.get(char_uid) or gatt.get_all_notifications(char_uid) or []
    logger().info(
        f"*********************** Remote notifications count={len(notifications)} "
        f"(DUT sent≈{sent_count}) ***********************"
    )
    for i, ntf in enumerate(notifications[:8]):
        preview = repr(ntf)
        if len(preview) > 120:
            preview = preview[:120] + "..."
        logger().info(f"  remote_notify[{i}]={preview}")

    assert len(notifications) >= min_remote_count, (
        f"No BLE GATT notifications received on remote peer "
        f"(got {len(notifications)}, need >= {min_remote_count})"
    )
    assert _notification_matches_payload(notifications[0], expected_payload), (
        f"failed to fetch matching BLE notify data on remote: "
        f"got {notifications[0]!r}, expected payload {expected_payload!r}"
    )
    # Prefer seeing a meaningful fraction of what DUT sent (co-ex may drop some)
    if sent_count and sent_count > 0:
        ratio = len(notifications) / float(sent_count)
        logger().info(
            f"Remote BLE notify delivery: received={len(notifications)} sent={sent_count} "
            f"ratio={ratio:.2f}"
        )
        assert len(notifications) >= max(min_remote_count, min(3, sent_count // 10)), (
            f"Too few remote notifications vs DUT sends "
            f"(received={len(notifications)}, sent={sent_count})"
        )
    logger().info("Remote BLE notification validation PASSED")


def _run_coex_with_ble_data(
    *,
    wifi_dut,
    ble_client,
    zephyr_wifi_collections,
    wifi_sniffer,
    net_perf_client,
    wifi_access_point,
    wifi_client,
    protocol,
    capture_filename,
    traffic_type,
    traffic=None,
    qos=0,
    run_tx_in_thread=True,
    rx_runner=None,
):
    """BLE connect + GATT subscribe + WLAN join/traffic with concurrent BLE notify.

    Mirrors test_throughput_co_ex_sdk.py ble_data_transfer path with Zephyr UUIDs/slots.
    """
    char_path = char_uid = None
    wifi_obj = None
    ble_data = None
    bt_dut_address = bt_client_address = None

    try:
        with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/{capture_filename}_{int(time.time())}.log",
        ):
            bt_dut_address, bt_client_address = setup_ble_connection(
                wifi_dut, ble_client, zephyr_wifi_collections
            )
            char_path, char_uid = setup_ble_gatt_notify_subscribe(
                wifi_dut, ble_client, bt_client_address
            )

        wifi_obj = CoexWifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            traffic=traffic,
            qos=qos,
            traffic_type=traffic_type,
            run_tx_in_thread=run_tx_in_thread,
            power_save=False,
        )

        # SDK: start ble_notify after join; here notify runs concurrent with join+iperf
        ble_data = BleNotifyThread(
            wifi_dut=wifi_dut,
            ble_client_address=bt_client_address,
            duration_sec=50,
            interval_sec=0.5,
        )
        ble_data.start()

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        if rx_runner is not None:
            rx_runner(wifi_dut, net_perf_client, wifi_obj, protocol)

        ble_data.wait_for_exit()
        assert_ble_connected_after_traffic(wifi_dut)
        teardown_ble_gatt_notify(
            ble_client,
            char_path,
            char_uid,
            expect_notifications=True,
            expected_payload=BLE_NOTIFY_PAYLOAD,
            sent_count=ble_data.notify_count,
            min_remote_count=1,
        )
        logger().info(
            f"Co-ex BLE-data case done (DUT BLE addr={bt_dut_address}, peer={bt_client_address})"
        )
    finally:
        if ble_data is not None and ble_data._thread is not None and ble_data._thread.is_alive():
            ble_data.wait_for_exit(raise_exceptions=False)
        cleanup_ble_connection(
            wifi_dut, ble_client, bt_dut_address, bt_client_address
        )
        if wifi_obj is not None:
            wifi_obj.stop_sniffer_and_leave()


# ********************************************************************************************************************
# Case 5: STA + BLE connected + BLE notify data + TCP TX  (ref: C401619)
# ********************************************************************************************************************
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_coex_dut_config())
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=["init", "ap_enabled"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [("0xc8", 0)])
def test_coex_sta_ble_data_tcp_tx_zephyr(
    wifi_sniffer,
    net_perf_client,
    wifi_access_point,
    wifi_dut,
    request,
    wifi_client,
    ble_client,
    protocol,
    zephyr_wifi_collections,
    traffic,
    qos,
):
    """Zephyr co-ex: STA + BLE GATT notify + TCP TX (ref: test_throughput_co_ex_sdk C401619)."""
    try:
        _run_coex_with_ble_data(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            zephyr_wifi_collections=zephyr_wifi_collections,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=request.node.name,
            traffic_type=CoexWifiJoin.TRAFFIC_TCP_TX,
            traffic=traffic,
            qos=qos,
            run_tx_in_thread=True,
        )
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


# ********************************************************************************************************************
# Case 6: STA + BLE connected + BLE notify data + TCP RX  (ref: C401620)
# ********************************************************************************************************************
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_coex_dut_config())
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=["init", "ap_enabled"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_coex_sta_ble_data_tcp_rx_zephyr(
    wifi_sniffer,
    net_perf_client,
    wifi_access_point,
    wifi_dut,
    request,
    wifi_client,
    ble_client,
    protocol,
    zephyr_wifi_collections,
):
    """Zephyr co-ex: STA + BLE GATT notify + TCP RX (ref: test_throughput_co_ex_sdk C401620)."""
    try:
        _run_coex_with_ble_data(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            zephyr_wifi_collections=zephyr_wifi_collections,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=request.node.name,
            traffic_type=CoexWifiJoin.TRAFFIC_TCP_RX,
            run_tx_in_thread=False,
            rx_runner=_run_tcp_rx,
        )
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


# ********************************************************************************************************************
# Case 7: STA + BLE connected + BLE notify data + UDP TX  (ref: C401621)
# ********************************************************************************************************************
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_coex_dut_config())
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=["init", "ap_enabled"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos", [("0xc8", 0)])
def test_coex_sta_ble_data_udp_tx_zephyr(
    wifi_sniffer,
    net_perf_client,
    wifi_access_point,
    wifi_dut,
    request,
    wifi_client,
    ble_client,
    protocol,
    zephyr_wifi_collections,
    traffic,
    qos,
):
    """Zephyr co-ex: STA + BLE GATT notify + UDP TX (ref: test_throughput_co_ex_sdk C401621)."""
    try:
        _run_coex_with_ble_data(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            zephyr_wifi_collections=zephyr_wifi_collections,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=request.node.name,
            traffic_type=CoexWifiJoin.TRAFFIC_UDP_TX,
            traffic=traffic,
            qos=qos,
            run_tx_in_thread=True,
        )
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


# ********************************************************************************************************************
# Case 8: STA + BLE connected + BLE notify data + UDP RX  (ref: C401622)
# ********************************************************************************************************************
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_coex_dut_config())
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=["init", "ap_enabled"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_coex_sta_ble_data_udp_rx_zephyr(
    wifi_sniffer,
    net_perf_client,
    wifi_access_point,
    wifi_dut,
    request,
    wifi_client,
    ble_client,
    protocol,
    zephyr_wifi_collections,
):
    """Zephyr co-ex: STA + BLE GATT notify + UDP RX (ref: test_throughput_co_ex_sdk C401622)."""
    try:
        _run_coex_with_ble_data(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            zephyr_wifi_collections=zephyr_wifi_collections,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=request.node.name,
            traffic_type=CoexWifiJoin.TRAFFIC_UDP_RX,
            run_tx_in_thread=False,
            rx_runner=_run_udp_rx,
        )
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
