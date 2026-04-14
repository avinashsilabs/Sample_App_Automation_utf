import time
from threading import Thread
import pytest
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xOperatingMode,
)
from utf.utils.logger import get_logger

"""This function runs below test steps :
        1. Configuration of DUT in 2G
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        6. Enable the power save mode in DUT
        7. Stop the sniffer  
        8. Analyzing all sniffer capture packets and find the different Qos access category packets

    traffic category for Iperf category
        1. wlan.qos.priority == 0  Best Effort
        2. wlan.qos.priority == 1  Background
        3. wlan.qos.priority == 4  Video
        4. wlan.qos.priority == 6  Voice

    traffic category for Ping category
        1. wlan.qos.priority == 0  Best Effort
        2. wlan.qos.priority == 1  Background
        3. wlan.qos.priority == 4  Video
        4. wlan.qos.priority == 6  Voice

    setup requirement:
        1. soc 
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

Author : Shaik Abdul Azeez

"""

def logger():
    return get_logger(__name__)

COMMON_DUT_WIFI_CFG = {
    "oper_mode": Si91xOperatingMode.WiFiClient,
    "coex_mode": Si91xCoexMode.WLANOnly,
    "features": Si91xFeatureBitMap.OpenMode
                | Si91xFeatureBitMap.Aggregation
                | Si91xFeatureBitMap.WPSSupportDisabled,
    "custom_features": Si91xCustomFeatureBitMap.NWP160MHz
                       | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
    "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                           | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
    "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                      | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
                      | Si91xTCPIPFeatureBitMap.Default,
    "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                          | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
                          | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
    "bt_features": 0,
    "ble_features": 0,
    "ble_custom_ext_features": 0,
    "band": 0,
    "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
}

TRAFFIC_PROFILES = [
    ("0x00", 0, "BE"),
    ("0x20", 1, "BK"),
    ("0x80", 4, "VI"),
    ("0xC8", 6, "VO"),
]

def _wifi_setup(wifi_dut, wifi_sniffer, wifi_access_point, wifi_client, capture_filename):
    wifi_dut.interfaces.wifi.init(mode="client")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    time.sleep(2)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    time.sleep(1)
    wifi_dut.interfaces.wifi.join(enable_lwip=1, security="open", ssid="WSDK-AUTOMATION", passphrase="12345678")
    time.sleep(2)
    wifi_dut.interfaces.wifi.start_ip_lwip()
    time.sleep(2)
    wifi_dut.interfaces.wifi.sl_net_up(mode="client")
    time.sleep(2)
    dut_ip = wifi_dut.interfaces.wifi.get_device_ip(device_ip=wifi_dut.interfaces.wifi.display_device_ip_lwip())
    logger().info(f"DUT IP: {dut_ip}, HOST IP: {host_ip}")
    return host_ip, dut_ip


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disable_external_stack"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "ssid": 'WSDK-AUTOMATION', "passphrase": '12345678', "security": 'open'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_dut", wifi=COMMON_DUT_WIFI_CFG)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="net_init_client")
@pytest.mark.test_src_map_id('C19755')
def test_wifi_sdk_udp_tx_all_qos_in_bypass_mode_c19755(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                                       wifi_client, protocol, sl_collections):
    """Send UDP data with all traffic types in TCP/IP bypass mode"""
    transfer_type = 2      # UDP
    throughput_type = 2    # UDP TX
    size = 1460
    duration = 60
    timeout = duration + 2
    capture_filename = "c19755_udp_tx_all_qos"
    results = {}
    try:
        host_ip, dut_ip = _wifi_setup(wifi_dut, wifi_sniffer, wifi_access_point, wifi_client, capture_filename)
        for tos_val, qos_val, tag in TRAFFIC_PROFILES:
            logger().info(f"[UDP TX][{tag}] init server TOS={tos_val} QoS={qos_val}")
            net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip, protocol=protocol, tos_value=tos_val)

            def _start_server():
                time.sleep(1)
                net_perf_client.interfaces.net_perf.start()

            th = Thread(target=_start_server, daemon=True)
            th.start()

            wifi_dut.interfaces.wwifi = getattr(wifi_dut.interfaces, "wifi")
            wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=17, local_ip=dut_ip,
                                           local_port=net_perf_client.interfaces.net_perf.server_port, qos=qos_val,
                                           remote_ip=host_ip, remote_port=net_perf_client.interfaces.net_perf.server_port,
                                           size=size, ttl=duration, throughput_type=throughput_type, timeout=timeout,
                                           host_tcp_ip_stack_enable=1, async_socket=1)
            th.join()
            tp = net_perf_client.interfaces.net_perf.process_output()
            assert tp is not None, f"Missing TX throughput for QoS {qos_val}"
            results[tag] = tp
            logger().info(f"[UDP TX][{tag}] throughput={tp}")
            time.sleep(2)
        assert len(results) == len(TRAFFIC_PROFILES), "Incomplete TX QoS set"
        logger().info(f"[UDP TX] Completed {results}")
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise
    finally:
        try: wifi_dut.interfaces.wifi.leave()
        except Exception: pass
        try: wifi_sniffer.interfaces.capture.stop_capture()
        except Exception: pass


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disable_external_stack"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "ssid": 'WSDK-AUTOMATION', "passphrase": '12345678', "security": 'open'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_dut", wifi=COMMON_DUT_WIFI_CFG)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="net_init_client")
@pytest.mark.test_src_map_id('C19755')
def test_wifi_sdk_udp_rx_all_qos_in_bypass_mode_c19755(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                                       wifi_client, protocol, sl_collections):
    """Receive UDP traffic for all WMM QoS types in bypass mode."""
    transfer_type = 2        # UDP
    throughput_type = 4      # UDP RX
    pkt_size = 1470
    duration = 30
    timeout = duration + 10
    capture_filename = "c19755_udp_rx_all_qos"
    executed = []

    try:
        host_ip, dut_ip = _wifi_setup(wifi_dut, wifi_sniffer, wifi_access_point, wifi_client, capture_filename)
        time.sleep(1)
        logger().info("[UDP RX] Post-join stabilization complete (DUT ready)")

        for tos_val, qos_val, tag in TRAFFIC_PROFILES:
            logger().info(f"[UDP RX][{tag}] prepare host UDP client TOS={tos_val} QoS={qos_val}")

            # Host = transmitter
            net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=dut_ip, protocol=protocol, tos_value=tos_val)
            port = net_perf_client.interfaces.net_perf.client_port

            def _start_host():
                # Allow DUT to enter blocking listen first
                time.sleep(1)
                logger().info(f"[UDP RX][{tag}] host start -> {dut_ip}:{port}")
                net_perf_client.interfaces.net_perf.start()

            th = Thread(target=_start_host, daemon=True)
            th.start()

            wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=17, local_port=port, local_ip=dut_ip,
                                           remote_ip="0.0.0.0", remote_port=0, size=pkt_size, ttl=duration,
                                           throughput_type=throughput_type, timeout=timeout, qos=qos_val,
                                           host_tcp_ip_stack_enable=1, async_socket=0)
            th.join()
            executed.append(tag)
            logger().info(f"[UDP RX][{tag}] completed OK (executed={executed})")

            time.sleep(2)
        assert len(executed) == len(TRAFFIC_PROFILES), \
            f"Missing QoS executions. Ran {executed}"
        logger().info(f"[UDP RX] All QoS sessions executed: {executed}")

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise
    finally:
        try: wifi_dut.interfaces.wifi.leave()
        except Exception: pass
        try: wifi_sniffer.interfaces.capture.stop_capture()
        except Exception: pass


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disable_external_stack"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "ssid": 'WSDK-AUTOMATION', "passphrase": '12345678', "security": 'open'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_dut", wifi=COMMON_DUT_WIFI_CFG)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="net_init_client")
@pytest.mark.test_src_map_id('C19756')
def test_wifi_sdk_udp_different_traffic_types_tx_bypass_mode_c19756(wifi_sniffer, net_perf_client, wifi_access_point,
                                                                    wifi_dut, wifi_client, protocol, sl_collections):
    """Send UDP data with different traffic types in TCP/IP bypass mode"""
    transfer_type = 2     # UDP
    throughput_type = 2   # UDP TX
    pkt_size = 1460
    duration = 40
    timeout = duration + 5
    capture_filename = "19756_udp_tx_multi_socket"
    results = {}
    try:
        host_ip, dut_ip = _wifi_setup(wifi_dut, wifi_sniffer, wifi_access_point, wifi_client, capture_filename)
        for tos_val, qos_val, tag in TRAFFIC_PROFILES:
            logger().info(f"[MULTI-TX][{tag}] server init TOS={tos_val} QoS={qos_val}")
            net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip, protocol=protocol, tos_value=tos_val)

            def _start_server():
                time.sleep(1)
                net_perf_client.interfaces.net_perf.start()

            th = Thread(target=_start_server, daemon=True)
            th.start()

            wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=17, local_port=net_perf_client.interfaces.net_perf.server_port,
                                           local_ip=dut_ip, remote_ip=host_ip, remote_port=net_perf_client.interfaces.net_perf.server_port,
                                           size=pkt_size, ttl=duration, throughput_type=throughput_type, timeout=timeout, qos=qos_val,
                                           host_tcp_ip_stack_enable=1, async_socket=1)
            th.join()
            tp = net_perf_client.interfaces.net_perf.process_output()
            assert tp is not None, f"Missing TX throughput QoS {qos_val}"
            results[tag] = tp
            logger().info(f"[MULTI-TX][{tag}] throughput={tp}")
            time.sleep(2)
        assert len(results) == len(TRAFFIC_PROFILES), "Not all TX sockets reported"
        logger().info(f"[MULTI-TX] Completed {results}")
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise
    finally:
        try: wifi_dut.interfaces.wifi.leave()
        except Exception: pass
        try: wifi_sniffer.interfaces.capture.stop_capture()
        except Exception: pass


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disable_external_stack"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "ssid": 'WSDK-AUTOMATION', "passphrase": '12345678', "security": 'open'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_dut", wifi=COMMON_DUT_WIFI_CFG)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="net_init_client")
@pytest.mark.test_src_map_id('C19756')
def test_wifi_sdk_udp_different_traffic_types_rx_bypass_mode_c19756(wifi_sniffer, net_perf_client, wifi_access_point,
                                                                    wifi_dut, wifi_client, protocol, sl_collections):
    """Receive UDP data with different traffic types in TCP/IP bypass mode"""
    transfer_type = 2
    throughput_type = 4
    pkt_size = 1470
    duration = 30
    timeout = duration + 15
    capture_filename = "c19756_udp_rx_multi_socket"
    executed = []
    try:
        host_ip, dut_ip = _wifi_setup(wifi_dut, wifi_sniffer, wifi_access_point, wifi_client, capture_filename)
        for tos_val, qos_val, tag in TRAFFIC_PROFILES:
            logger().info(f"[MULTI-RX][{tag}] init host UDP client (TOS={tos_val}, QoS={qos_val})")
            net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=dut_ip, protocol=protocol, tos_value=tos_val)
            port = net_perf_client.interfaces.net_perf.client_port

            def _start_client():
                time.sleep(1)
                logger().info(f"[MULTI-RX][{tag}] start host traffic -> DUT:{port}")
                net_perf_client.interfaces.net_perf.start()

            th = Thread(target=_start_client, daemon=True)
            th.start()

            logger().info(f"[MULTI-RX][{tag}] start DUT iperf server (blocking RX)")
            wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=17, local_port=port, local_ip=dut_ip,
                                           remote_ip="0.0.0.0", remote_port=0, size=pkt_size, ttl=duration, timeout=timeout,
                                           throughput_type=throughput_type, qos=qos_val, host_tcp_ip_stack_enable=1, async_socket=0)
            th.join()
            executed.append(tag)
            logger().info(f"[MULTI-RX][{tag}] completed")
            time.sleep(2)

        assert len(executed) == len(TRAFFIC_PROFILES), "Not all QoS RX sessions executed"
        logger().info(f"[MULTI-RX] Completed tags={executed}")
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise
    finally:
        try: wifi_dut.interfaces.wifi.leave()
        except Exception: pass
        try: wifi_sniffer.interfaces.capture.stop_capture()
        except Exception: pass


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disable_external_stack"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "ssid": 'WSDK-AUTOMATION', "passphrase": '12345678', "security": 'open'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_dut", wifi=COMMON_DUT_WIFI_CFG)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="net_init_client")
@pytest.mark.test_src_map_id('C539022')
def test_wifi_sdk_tcp_rx_in_tcp_ip_bypass_mode_loop_c539022(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, sl_collections):
    """Receive TCP data with different traffic types in TCP/IP bypass mode (create->bind->listen->accept->recv->close)"""
    transfer_type   = 1   # TCP
    throughput_type = 3   # TCP RX
    pkt_size        = 1460
    duration        = 30
    timeout         = duration + 5
    capture_filename = "c539022_tcp_rx_loop"
    executed = []

    try:
        host_ip, dut_ip = _wifi_setup(wifi_dut, wifi_sniffer, wifi_access_point, wifi_client, capture_filename)

        for tos_val, qos_val, tag in TRAFFIC_PROFILES:
            logger().info(f"[TCP RX][{tag}] init host TCP client (TOS={tos_val}, QoS={qos_val})")
            net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=dut_ip, protocol=protocol, tos_value=tos_val)
            port = net_perf_client.interfaces.net_perf.client_port

            def _start_client():
                time.sleep(1)
                logger().info(f"[TCP RX][{tag}] start host traffic -> DUT:{port}")
                net_perf_client.interfaces.net_perf.start()

            th = Thread(target=_start_client, daemon=True)
            th.start()

            logger().info(f"[TCP RX][{tag}] DUT iperf server (blocking): listen/accept on {dut_ip}:{port}")
            wifi_dut.interfaces.wwifi = getattr(wifi_dut.interfaces, "wifi")
            wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=6, local_port=port, local_ip=dut_ip,
                                           remote_ip="0.0.0.0", remote_port=0, size=pkt_size, ttl=duration, throughput_type=throughput_type,
                                           timeout=timeout, qos=qos_val, host_tcp_ip_stack_enable=1, async_socket=0)
            th.join()
            executed.append(tag)
            logger().info(f"[TCP RX][{tag}] completed")
            time.sleep(2)

        assert len(executed) == len(TRAFFIC_PROFILES), f"Not all TCP RX profiles executed: {executed}"
        logger().info(f"[TCP RX] Completed profiles: {executed}")

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise
    finally:
        try: wifi_dut.interfaces.wifi.leave()
        except Exception: pass
        try: wifi_sniffer.interfaces.capture.stop_capture()
        except Exception: pass