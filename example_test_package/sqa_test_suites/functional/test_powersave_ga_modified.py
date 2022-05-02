import pytest
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                                            RS9116CustomFeatureBitMap,
                                            RS9116ConfigFeatureBitMap,
                                            RS9116TCPIPFeatureBitMap,
                                            RS9116ExtCustomFeatureBitMap,
                                            RS9116ExtTCPIPFeatureBitMap,
                                            RS9116SecurityMode,
                                            RS9116OperatingMode, RS9116ULPModes
                                            )
from utf.interfaces import wifi
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
import time

"""This function runs below test steps for DUT-RS9116
    Step1: 1. Configuration of DUT in 2G mode
    Step2 : Do Scan the AP
    Step3: Connect to the AP
    Step4 :Initiate the different powersave modes and check the connectivity 
    Step7 : Issue init,scan and connect to the AP
    Need to use separate .hex files for lp and ulp msb_based and gpio based cases.

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)

    Author: Sirisha
"""


def logger():
    return get_logger(__name__)

def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connect_and_disconnect_when_module_is_in_power_save_mode_C19485(wifi_dut, wifi_access_point, wifi_sniffer):
    # for i in range(1,10):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C3990')
    # Connect to the AP
    result = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result is not None, "Could not connect to the AP"
    logger().info(f"This API Enables the DHCP in DUT")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping dut failed..."
    logger().info("ping to dut is successful...")
    logger().info(f"*****Enable Power save in DUT******")
    # Initiating power save
    result = wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result is not None, "Device did not go to power save2"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    time.sleep(30)
    # Add disconnect.leave api
    wifi_dut.interfaces.wifi.leave()
    # Issuing de-init command
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(5)

    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP Found"
    # Connect to the AP
    result = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result is not None, "Could not connect to the AP"

    # validate NULL data frame with PM bit set to '1'

    logger().info.("Vefirying powersave mode 2 bit")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes": RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_TCP_Rx_data_transfer_in_powersave_mode1_C19486(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19486.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    time.sleep(2)
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info("Fetched the device ip address",{device_ip})
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(1, 0)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
    )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

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

        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None, "Throughput not found"
        __print_throughput(tp)
        logger().info(f"Iperf data transfer completed successfully")

        # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                        f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
        # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features":RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_UDP_Rx_data_transfer_in_powersave_mode1_C19486(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19486.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    time.sleep(2)
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info("Fetched the device ip address", {device_ip})
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(1, 0)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
    )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

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

        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None, "Throughput not found"
        __print_throughput(tp)
        logger().info(f"Iperf data transfer completed successfully")

        # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features":RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_TCP_Tx_data_transfer_in_powersave_mode2_C19488(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19488.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    time.sleep(2)
    # Connect to the AP
    logger().info("Connecting to the Access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping dut failed..."
    logger().info("ping to dut is successful...")
    # preparing wifi_client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save2
    result = wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result is not None, "Device did not go to power save mode2"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info("validate NULL data frame with PM bit set to 1")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features":RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_UDP_Tx_data_transfer_in_powersave_mode2_C19488(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19488.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    time.sleep(2)
    # Connect to the AP
    logger().info("Connecting to the Access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping dut failed..."
    logger().info("ping to dut is successful...")
    # preparing wifi_client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save2
    result = wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result is not None, "Device did not go to power save mode2"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info("validate NULL data frame with PM bit set to 1")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features":RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_TCP_Rx_data_transfer_in_powersave_mode2_C19489(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19486.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    time.sleep(2)
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info("Fetched the device ip address", {device_ip})
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

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

        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None, "Throughput not found"
        __print_throughput(tp)
        logger().info(f"Iperf data transfer completed successfully")

        # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features":RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_UDP_Rx_data_transfer_in_powersave_mode2_C19489(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19489.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    time.sleep(2)
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info("Fetched the device ip address", {device_ip})
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

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

        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None, "Throughput not found"
        __print_throughput(tp)
        logger().info(f"Iperf data transfer completed successfully")

        # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features":RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_TCP_Tx_data_transfer_in_powersave_mode3_C19491(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19491.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    time.sleep(2)
    # Connect to the AP
    logger().info("Connecting to the Access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping dut failed..."
    logger().info("ping to dut is successful...")
    # preparing wifi_client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save3
    result = wifi_dut.interfaces.wifi.power_save(3, 0)
    assert result is not None, "Device did not go to power save mode3"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )
    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info("validate NULL data frame with PM bit set to 1")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features":RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_UDP_Tx_data_transfer_in_powersave_mode3_C19491(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19488.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    time.sleep(2)
    # Connect to the AP
    logger().info("Connecting to the Access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping dut failed..."
    logger().info("ping to dut is successful...")
    # preparing wifi_client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save3
    result = wifi_dut.interfaces.wifi.power_save(3, 0)
    assert result is not None, "Device did not go to power save mode3"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )
    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info("validate NULL data frame with PM bit set to 1")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes": RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_TCP_Tx_data_transfer_in_powersave_mode3_C19495(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19495.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    time.sleep(2)
    # Connect to the AP
    logger().info("Connecting to the Access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping dut failed..."
    logger().info("ping to dut is successful...")
    # preparing wifi_client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save3
    result = wifi_dut.interfaces.wifi.power_save(3, 0)
    assert result is not None, "Device did not go to power save mode3"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )
    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info("validate NULL data frame with PM bit set to 1")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features":RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_UDP_Tx_data_transfer_in_powersave_mode3_C19495(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19495.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    time.sleep(2)
    # Connect to the AP
    logger().info("Connecting to the Access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping dut failed..."
    logger().info("ping to dut is successful...")
    # preparing wifi_client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save3
    result = wifi_dut.interfaces.wifi.power_save(3, 0)
    assert result is not None, "Device did not go to power save mode3"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )
    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info("validate NULL data frame with PM bit set to 1")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features":RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_TCP_Rx_data_transfer_in_powersave_mode3_C19496(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19496.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    time.sleep(2)
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info("Fetched the device ip address", {device_ip})
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save3
    result = wifi_dut.interfaces.wifi.power_save(3, 0)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

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

        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None, "Throughput not found"
        __print_throughput(tp)
        logger().info(f"Iperf data transfer completed successfully")

        # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "security": RS9116SecurityMode.Open,
        "tcpip_features":RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
        "band": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_UDP_Rx_data_transfer_in_powersave_mode3_C19496(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                           protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19496.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    time.sleep(2)
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info("Fetched the device ip address", {device_ip})
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save3
    result = wifi_dut.interfaces.wifi.power_save(3, 0)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

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

        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None, "Throughput not found"
        __print_throughput(tp)
        logger().info(f"Iperf data transfer completed successfully")

        # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
         "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "security": RS9116SecurityMode.Open,
             "tcpip_features":RS9116TCPIPFeatureBitMap.DHCPv4Server,
             "ext_custom_features":RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
             "lp_ulp_modes":RS9116ULPModes.ULPModeWithRAMRetention,
             "band": 0
         }
     )
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_powersave_disable_functionality_case1_C19501(wifi_access_point, wifi_dut, wifi_sniffer):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C19501.txt')
    logger().info(f"Fetches the DUT mac address")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
      #scan the AP
    result_ap = wifi_dut.interfaces.wifi.scan()
    assert result_ap is not None, "No AP Found"
      #Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
      #Get IP over DHCP
    wifi_dut.interfaces.wifi.start_ip()
       #Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(1, 0)
    logger().info(f"*****Enable Powersave1 in  DUT******")
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
        )
    assert result is not None, "Device didnot enable in powersave mode1"
    time.sleep(30)
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
         "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "security": RS9116SecurityMode.Open,
             "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
             "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
             "lp_ulp_modes": RS9116ULPModes.ULPModeWithRAMRetention,
             "band": 0
         }
     )
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_powersave_disable_functionality_case2_C19501(wifi_access_point, wifi_dut, wifi_sniffer):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C19501.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    # bssid = wifi_access_point.interfaces.wifi.bssid
      #scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP Found"
      #Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
      #Get IP over DHCP
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Powersave2 in  DUT******")
       #Initiating power save2
    result = wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result is not None
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
    time.sleep(30)
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()

