from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes
import time
import pytest
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)

@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])

def test_tcpdata_tx_with_vo_vi_be_bk_c19752(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
    traffic_category_list = ['0x00', '0xC8', '0x80', '0x20']
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcpdata_tx_with_vo_vi_be_bk')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    #Start get IP address
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1
    for traffic in traffic_category_list:

        # starting iperf
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                        tos_value=traffic)
        net_perf_client.interfaces.net_perf.start()

        # open socket and send traffic
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
        )

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None
        __print_throughput(tp)

    wifi_sniffer.interfaces.capture.stop_capture()
    # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    # Validating packets for background
    packet_filter1 = f'(wlan.qos.priority == 1) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for best effort
    packet_filter2 = f'(wlan.qos.priority == 0) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for video
    packet_filter3 = f'(wlan.qos.priority == 5) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for voice
    packet_filter4 = f'(wlan.qos.priority == 6) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)

@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])

def test_udpdata_tx_with_vo_vi_be_bk_c19753(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
    traffic_category_list = ['0x00', '0xC8', '0x80', '0x20']
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udpdata_tx_with_vo_vi_be_bk')
    time.sleep(2)

    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # preparing wifi_client
    # if wifi_access_point != wifi_client:
    #     wifi_client.interfaces.wifi.join_ap(wifi_access_point)

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1
    for traffic in traffic_category_list:

        # starting iperf
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                        tos_value=traffic)
        net_perf_client.interfaces.net_perf.start()

        # open socket and send traffic
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
        )

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None
        __print_throughput(tp)

    wifi_sniffer.interfaces.capture.stop_capture()
    # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    # Validating packets for background
    packet_filter1 = f'(wlan.qos.priority == 1) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for video
    packet_filter2 = f'(wlan.qos.priority == 5) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for voice
    packet_filter3 = f'(wlan.qos.priority == 6) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for best effort
    packet_filter4 = f'(wlan.qos.priority == 0) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)

@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])

def test_tcpdata_rx_with_vo_vi_be_bk_c22115(net_perf_client,wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, protocol):
    traffic_category_list = ['0x00', '0xC8', '0x80', '0x20']
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcpdata_rx_with_vo_vi_be_bk')
    time.sleep(2)

    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    for traffic in traffic_category_list:
        # preparing iperf
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                        tos_value=traffic)

        # creating results object for sharing between host and dut
        result = Result(net_perf_client.interfaces.net_perf.protocol)
        # open socket and start listening
        with wifi_dut.interfaces.wifi.start_socket_reader(
                log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
                result=result,
                protocol=net_perf_client.interfaces.net_perf.protocol,
                port=net_perf_client.interfaces.net_perf.client_port,
                device_ip=device_ip,
                data_len=net_perf_client.interfaces.net_perf.client_data_len,
                time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
            # start iperf
            net_perf_client.interfaces.net_perf.start()
            # capture device output
            wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None
        __print_throughput(tp)

    wifi_sniffer.interfaces.capture.stop_capture()

    # Validating packets for background
    packet_filter1 = f'(wlan.qos.priority == 1) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for video
    packet_filter2 = f'(wlan.qos.priority == 5) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for voice
    packet_filter3 = f'(wlan.qos.priority == 6) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for best effort
    packet_filter4 = f'(wlan.qos.priority == 0) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)

@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])

def test_udpdata_rx_with_vo_vi_be_bk_c22116(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, protocol):
    traffic_category_list = ['0x00', '0xC8', '0x80', '0x20']
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udpdata_rx_with_vo_vi_be_bk')
    time.sleep(2)

    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    for traffic in traffic_category_list:
        # preparing iperf
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                        tos_value=traffic)

        # creating results object for sharing between host and dut
        result = Result(net_perf_client.interfaces.net_perf.protocol)
        # open socket and start listening
        with wifi_dut.interfaces.wifi.start_socket_reader(
                log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
                result=result,
                protocol=net_perf_client.interfaces.net_perf.protocol,
                port=net_perf_client.interfaces.net_perf.client_port,
                device_ip=device_ip,
                data_len=net_perf_client.interfaces.net_perf.client_data_len,
                time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
            # start iperf
            net_perf_client.interfaces.net_perf.start()
            # capture device output
            wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None
        __print_throughput(tp)

    wifi_sniffer.interfaces.capture.stop_capture()
    # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

    # Validating packets for background
    packet_filter1 = f'(wlan.qos.priority == 1) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for video
    packet_filter2 = f'(wlan.qos.priority == 5) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for voice
    packet_filter3 = f'(wlan.qos.priority == 6) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    # Validating packets for best effort
    packet_filter4 = f'(wlan.qos.priority == 0) && (wlan.sa == {dut_mac_address})'
    logger().info("Stop Sniffer finally")

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
def test_ping_from_ap_to_module_ip_with_four_traffics_c19754(wifi_sniffer, wifi_dut, wifi_access_point):

    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_ping_from_ap_to_module_ip_with_four_traffics_c19754')
    time.sleep(5)

    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Actual MAC_Address: {mac_address}")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current Version: {result}")

    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} '
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(2)
    wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)