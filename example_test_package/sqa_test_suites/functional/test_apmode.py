import pytest
import time
from utf.interfaces.cli import CLITransportException
from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116Band
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict

"""Test Author = Rakesh Nayini

        1. Start the sniffer before connection
        2. Required A7 EVK(DUT) board 
        3. Stop the sniffer
        4. Initiate ping from the dut
        5. Analyizing all sniffer capture packets and find the arp announcement packet

setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "set_region": True,
        "region_config": 0,
        "region_code": "US",
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.parametrize("beacon", [100])
@pytest.mark.parametrize("channel", [11])
def test_wifi_start_ap_in_US_region_C19454(wifi_sniffer, wifi_dut, wifi_client, beacon, channel, wifi_access_point):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_start_ap_in_US_region_C19454')
    logger().info(" ********** DUT works as a Ap mode ********")
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=beacon, channel=channel)
    logger().info("The country US is enabled as per the region params in beacon frame")
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=1, module_type=1)
    logger().info(
        "This command is added to terminate existing wlan0 if it is already there. If it is not there it will throw warning please ignore below error")
    wifi_client.interfaces.wifi.join()
    time.sleep(30)
    assert wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip) < 0.1
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'(wlan.ds.current_channel == {wifi_access_point.interfaces.wifi.channel}) and ' \
                     f'(wlan.country_info.code == "US") and wlan.addr == {mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "set_region": True,
        "region_config": 0,
        "region_code": "EU",
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 11
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 11}
)
@pytest.mark.parametrize("beacon", [100])
@pytest.mark.parametrize("channel", [11])
def test_wifi_start_ap_in_EU_region_C19455(wifi_sniffer, wifi_dut, wifi_client, beacon, channel, wifi_access_point):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    validation = True
    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_start_ap_in_EU_region_C19455')
    logger().info(" ********** DUT works as a Ap mode ********")
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=beacon, channel=channel)
    logger().info("The country EU is enabled as per the region params in beacon frame")
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
    logger().info(
        "This command is added to terminate existing wlan0 if it is already there. If it is not there it will throw warning please ignore below error")
    wifi_client.interfaces.wifi.join()
    time.sleep(30)
    assert wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip) < 0.1
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'(wlan.ds.current_channel == {wifi_access_point.interfaces.wifi.channel}) and ' \
                     f'(wlan.country_info.code == "EU") and wlan.addr == {mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "set_region": True,
        "region_config": 0,
        "region_code": "JP",
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "standard": "Standard.n", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "standard": "Standard.n", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.parametrize("beacon", [100])
@pytest.mark.parametrize("channel", [11])
def test_wifi_start_ap_in_JP_region_C19456(wifi_sniffer, wifi_dut, wifi_client, beacon, channel, wifi_access_point):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    validation = True
    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_start_ap_in_JP_region_C19456')
    logger().info(" ********** DUT works as a Ap mode ********")
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=beacon, channel=channel)
    logger().info("The country JP is enabled as per the region params in beacon frame")
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)
    logger().info(
        "This command is added to terminate existing wlan0 if it is already there. If it is not there it will throw warning please ignore below error")
    wifi_client.interfaces.wifi.join()
    time.sleep(30)
    assert wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip) < 0.1
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'(wlan.ds.current_channel == {wifi_access_point.interfaces.wifi.channel}) and ' \
                     f'(wlan.country_info.code == "JP") and wlan.addr == {mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "set_region": True,
        "region_config": 0,
        "region_code": "JP",
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "beacon": 100
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
def test_unsupported_channel_JP_region_C19457(wifi_dut, wifi_client):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)
    logger().info("Setting JP region to DUT as Ap...........")
    with pytest.raises(CLITransportException) as exc_info:
        logger().info(" ********** DUT works as a Ap mode ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=236)
    assert "0xA" in str(exc_info)
    logger().info("observed error as 0xA because we are trying to configered in invalid channel so which is expected")


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "set_region": True,
        "region_config": 0,
        "region_code": "EU",
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "beacon": 100
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
def test_unsupported_channel_EU_region_C19458(wifi_dut, wifi_client):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
    logger().info("Setting EU region to DUT as Ap...........")
    with pytest.raises(CLITransportException) as exc_info:
        logger().info(" ********** DUT works as a Ap mode ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=236)
    assert "0xA" in str(exc_info)
    logger().info("observed error as 0xA because we are trying to configered in invalid channel so which is expected")


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 11
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 11}
)
def test_wifi_AP_mode_C19435(wifi_dut, wifi_client):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    with pytest.raises(AssertionError) as exc_info:
        wifi_dut.interfaces.wifi.start_ap()
        logger().info(" ********** DUT works as a Ap mode ********* ")
    assert "Device must be initialized for the correct band" in str(exc_info)
    logger().info(f"Device must be initialized for the correct band")


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [36, 40, 48, 149, 168])
@pytest.mark.parametrize("beacon", [100])
def test_multi_channel_APUT_C19434_C19436(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, beacon, channel,
                                          protocol,
                                          wifi_access_point):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    validation = True
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_multi_channel_APUT_C19434_C19436')
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=beacon, channel=channel)
    logger().info(
        "This command is added to terminate existing wlan0 if it is already there. If it is not there it will throw warning please ignore below error")
    wifi_client.interfaces.wifi.join()
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUTMAC_Address:{dut_mac_address}")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    # preparing iperf
    logger().info('********** preparing iperf **********')
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    logger().info('********** creating results object for sharing between host and dut **********')
    result = Result(net_perf_client.interfaces.net_perf.protocol)

    # open socket and start listening
    logger().info('********** open socket and start listening **********')
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        logger().info('********** start iperf **********')
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        logger().info('********** capture device output **********')
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    # get and print throughput
    logger().info('********** get and print throughput **********')
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    __print_throughput(tp)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "dtim": 6
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "dtim": 6}
)
@pytest.mark.parametrize("beacon", [100, 200, 600])
@pytest.mark.parametrize("channel", [36])
def test_beacon_interval_APUT_C19443(wifi_sniffer, wifi_dut, wifi_client, beacon, channel, wifi_access_point):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    validation = True
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_beacon_interval_APUT_C19443')
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=beacon, channel=channel)
    logger().info(
        "This command is added to terminate existing wlan0 if it is already there. If it is not there it will throw warning please ignore below error")
    wifi_client.interfaces.wifi.join()
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUTMAC_Address:{dut_mac_address}")
    time.sleep(2)
    assert wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip) < 0.1
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.parametrize("beacon", [100])
@pytest.mark.parametrize("dtim", [1, 2, 3, 6, 10])
@pytest.mark.parametrize("channel", [36])
def test_DTIM_intervals_C19444(wifi_sniffer, wifi_dut, wifi_client, beacon, dtim, channel, wifi_access_point):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    validation = True
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DTIM_intervals_C19444')
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=beacon, dtim_period=dtim, channel=channel)
    logger().info(
        "This command is added to terminate existing wlan0 if it is already there. If it is not there it will throw warning please ignore below error")
    wifi_client.interfaces.wifi.join()
    assert wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip) < 0.1
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUTMAC_Address:{dut_mac_address}")
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36}
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "abcdefghij", "channel": 36
    }
)
def test_wrong_PSK_C19437(wifi_dut, wifi_client):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    logger().info(f'************* Configuring Static IP *************')
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    with pytest.raises(RuntimeError) as exc_info:
        logger().info(" ********** DUT works as a Ap mode ********* ")
        wifi_dut.interfaces.wifi.start_ap()
        logger().info(
            "This command is added to terminate existing wlan0 if it is already there. If it is not there it will throw warning please ignore below error")
        wifi_client.interfaces.wifi.join()
    assert "Wi-Fi client connection failed" in str(exc_info)
    logger().info(f'***********STA trying to connect to AP with wrong PSK*************')
