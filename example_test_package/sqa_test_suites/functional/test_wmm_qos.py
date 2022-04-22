from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping

from utf_wifi.utf_core.src.utf.utils.iperf.iperf_utils import ping_qos

"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        6. Enable the power save mode in DUT
        7. Stop the sniffer  
        8. Analyzing all sniffer capture packets and find the different Qos access category packets
       
    
    traffic category for Iperf category
        1. wlan.qos.priority == 0  Best Effort
        2. wlan.qos.priority == 1  Background
        3. wlan.qos.priority == 5  Video
        4. wlan.qos.priority == 6  Voice
        
    traffic category for Ping category
        1. wlan.qos.priority == 0  Best Effort
        2. wlan.qos.priority == 1  Background
        3. wlan.qos.priority == 4  Video
        4. wlan.qos.priority == 6  Voice
                   
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)
        
    Author: Shaik Abdul Azeez
"""

def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)

def logger():
    return get_logger(__name__)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
    },
)
def test_tcpdata_tx_with_vo_vi_be_bk_c19752(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                            protocol):
    traffic_category_list = ['0x00', '0x20', '0x80', '0xC8']
    traffic_category_name = ['Best Effort', 'Background', 'Video', 'Voice']

    validation = True
    i = 0
    counter = 0

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='all_traffic_cat_c19752')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    packet_filter1 = f'(wlan.qos.priority == 0) && (wlan.sa == {dut_mac_address})'
    packet_filter2 = f'(wlan.qos.priority == 1) && (wlan.sa == {dut_mac_address})'
    packet_filter3 = f'(wlan.qos.priority == 5) && (wlan.sa == {dut_mac_address})'
    packet_filter4 = f'(wlan.qos.priority == 6) && (wlan.sa == {dut_mac_address})'
    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF TX, TCP traffic for all Qos services ********************\n\n')

    for traffic in traffic_category_list:
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                        tos_value=traffic)

        logger().info(f"tos_value: {traffic}")

        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** open socket and send traffic  ******")
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
        )
        logger().info(f"***** get and print throughput ******")
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp, "failed to get throughtput..."
        __print_throughput(tp)
        time.sleep(5)
        i = i + 1

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        logger().info(f"***** Validating packets for {traffic_category_name[counter]}******")
        packet_filter = f'packet_filter{i}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, eval(packet_filter))['packet_count'], \
            f'Unable to find {traffic_category_name[counter]} packet from the DUT side'
        counter = counter + 1


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
    },
)
def test_udp_data_tx_with_vo_vi_be_bk_c19753(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                            protocol):
    traffic_category_list = ['0x00', '0x20', '0x80', '0xC8']
    traffic_category_name = ['Best Effort', 'Background', 'Video', 'Voice']

    validation = True
    i = 0
    counter = 0

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='all_traffic_cat_c19753')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    packet_filter1 = f'(wlan.qos.priority == 0) && (wlan.sa == {dut_mac_address})'
    packet_filter2 = f'(wlan.qos.priority == 1) && (wlan.sa == {dut_mac_address})'
    packet_filter3 = f'(wlan.qos.priority == 5) && (wlan.sa == {dut_mac_address})'
    packet_filter4 = f'(wlan.qos.priority == 6) && (wlan.sa == {dut_mac_address})'
    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF TX, UDP traffic for all Qos services ********************\n\n')
    for traffic in traffic_category_list:
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                        tos_value=traffic)
        logger().info(f"tos_value: {traffic}")

        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** open socket and send traffic  ******")
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
        )
        logger().info(f"***** get and print throughput ******")
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp, "failed to get throughtput..."
        __print_throughput(tp)
        time.sleep(5)
        i = i + 1

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        logger().info(f"***** Validating packets for {traffic_category_name[counter]}******")
        packet_filter = f'packet_filter{i}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, eval(packet_filter))['packet_count'], \
            f'Unable to find {traffic_category_name[counter]} packet from the DUT side'
        counter = counter + 1


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
    },
)
def test_tcpdata_rx_with_vo_vi_be_bk_c22115(net_perf_client,wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, protocol):
    traffic_category_list = ['0x00', '0x20', '0x80', '0xC8']
    traffic_category_name = ['Best Effort', 'Background', 'Video', 'Voice']

    validation = True
    i = 0
    counter = 0

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='all_traffic_cat_c22115')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    packet_filter1 = f'(wlan.qos.priority == 0) && (wlan.sa == {dut_mac_address})'
    packet_filter2 = f'(wlan.qos.priority == 1) && (wlan.sa == {dut_mac_address})'
    packet_filter3 = f'(wlan.qos.priority == 5) && (wlan.sa == {dut_mac_address})'
    packet_filter4 = f'(wlan.qos.priority == 6) && (wlan.sa == {dut_mac_address})'
    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF RX, TCP traffic for all Qos services ********************\n\n')
    for traffic in traffic_category_list:
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                        tos_value=traffic)

        # creating results object for sharing between host and dut
        result = Result(net_perf_client.interfaces.net_perf.protocol)
        logger().info(f"***** open socket and start listening ******")
        with wifi_dut.interfaces.wifi.start_socket_reader(
                log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
                result=result,
                protocol=net_perf_client.interfaces.net_perf.protocol,
                port=net_perf_client.interfaces.net_perf.client_port,
                device_ip=device_ip,
                data_len=net_perf_client.interfaces.net_perf.client_data_len,
                time=net_perf_client.interfaces.net_perf.client_timeout) as obj:

            logger().info(f"***** start iperf  ******")
            net_perf_client.interfaces.net_perf.start()

            logger().info(f"***** capture device output  ******")
            wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

        logger().info(f"***** get and print throughput   ******")
        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp, "failed to get throughtput..."
        __print_throughput(tp)
        time.sleep(5)

        i = i + 1

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        logger().info(f"***** Validating packets for {traffic_category_name[counter]}******")
        packet_filter = f'packet_filter{i}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, eval(packet_filter))['packet_count'], \
            f'Unable to find {traffic_category_name[counter]} packet from the DUT side'
        counter = counter + 1

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
    },
)
def test_udp_data_rx_with_vo_vi_be_bk_c22115(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                            protocol):
    traffic_category_list = ['0x00', '0x20', '0x80', '0xC8']
    traffic_category_name = ['Best Effort', 'Background', 'Video', 'Voice']

    validation = True
    i = 0
    counter = 0

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='all_traffic_cat_c22115')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    packet_filter1 = f'(wlan.qos.priority == 0) && (wlan.sa == {dut_mac_address})'
    packet_filter2 = f'(wlan.qos.priority == 1) && (wlan.sa == {dut_mac_address})'
    packet_filter3 = f'(wlan.qos.priority == 5) && (wlan.sa == {dut_mac_address})'
    packet_filter4 = f'(wlan.qos.priority == 6) && (wlan.sa == {dut_mac_address})'
    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF RX, UDP traffic for all Qos services ********************\n\n')
    for traffic in traffic_category_list:
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                        tos_value=traffic)

        # creating results object for sharing between host and dut
        result = Result(net_perf_client.interfaces.net_perf.protocol)
        logger().info(f"***** open socket and start listening ******")
        with wifi_dut.interfaces.wifi.start_socket_reader(
                log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
                result=result,
                protocol=net_perf_client.interfaces.net_perf.protocol,
                port=net_perf_client.interfaces.net_perf.client_port,
                device_ip=device_ip,
                data_len=net_perf_client.interfaces.net_perf.client_data_len,
                time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
            logger().info(f"***** start iperf  ******")
            net_perf_client.interfaces.net_perf.start()

            logger().info(f"***** capture device output  ******")
            wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

        logger().info(f"***** get and print throughput   ******")
        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp,"failed to get throughtput..."
        __print_throughput(tp)
        time.sleep(5)

        i = i + 1

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        logger().info(f"***** Validating packets for {traffic_category_name[counter]}******")
        packet_filter = f'packet_filter{i}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, eval(packet_filter))['packet_count'], \
            f'Unable to find {traffic_category_name[counter]} packet from the DUT side'
        counter = counter + 1


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
    },
)
def test_ping_from_ap_to_module_ip_with_four_traffics_c19754(wifi_sniffer, wifi_dut, wifi_access_point):
    traffic_category_list = ['0x00', '0xC8', '0x80', '0x20']
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='all_traffic_cat_c19754')
    time.sleep(5)

    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info(f"***** Start get IP address ******")
    ip_config = wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"***** device_IP :{device_ip} ******")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current Version: {result}")

    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    logger().info(f"***** Initiate ping from third party wifi-client to DUT ******")
    for qos_category in traffic_category_list:
        status = ping_qos(device_ip, 20, qos_category=qos_category)
        assert status == 1, "Ping failed"

        time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    packet_filter1 = f'(wlan.qos.priority == 1) && (wlan.sa == {dut_mac_address})'
    packet_filter2 = f'(wlan.qos.priority == 0) && (wlan.sa == {dut_mac_address})'
    packet_filter3 = f'(wlan.qos.priority == 4) && (wlan.sa == {dut_mac_address})'
    packet_filter4 = f'(wlan.qos.priority == 6) && (wlan.sa == {dut_mac_address})'
        #
    logger().info(f"***** Validating packets for background ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'],\
        'Unable to find Background packet from the DUT side'
    logger().info(f"***** Validating packets for best effort ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'],\
        'Unable to find Best effort packet from the DUT side'
    logger().info(f"***** Validating packets for video ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'],\
        'Unable to find Video packet from the DUT side'
    logger().info(f"***** Validating packets for voice ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4) ['packet_count'],\
        'Unable to find Voice packet from the DUT side'