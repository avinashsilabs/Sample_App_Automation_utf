from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116PowerSaveModes,
    RS9116TCPIPFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116PowerSaveProcedureTypes
)
import time
import pytest
from utf.utils.logger import get_logger

from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, logger


# from utf_wifi.utf_pytest.utf.devices.rs911x import RS9116TCPIPFeatureBitMap


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer K

"""

ping_count = 10


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_verify_static_ip_allocation_to_dut_c19292(
        wifi_sniffer, wifi_dut, wifi_access_point
):
    """=============================Verify Static IP allocation to DUT=========================="""
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file="test_verify_static_ip_allocation_to_dut"
    )
    time.sleep(3)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            scan_fail = 0
            break
        except:
            logger().info(
                f"Scanning to the Wifi Access Point is failed. retry count -> {count}"
            )
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    time.sleep(2)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip_in_static_mode()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
    logger().info(f"Device is {device_ip}")

    packet_filter1 = f"dhcp.hw.mac_addr == {mac_address}"

    packet_filter3 = f"((wlan.addr == {mac_address}) && (wlan.fc.type_subtype == 0x0024)) && (wlan.fc.pwrmgt == 1)"

    logger().info(f"*****Initiating power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)

    status = ping(device_ip, ping_count)
    assert (
            status is True
    ), "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")

    time.sleep(15)
    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Sniffer validation for dhcp packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter1
    ), ["packet_count"]
    logger().info("Sniffer validation for ps poll and null packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter3
    ), ["packet_count"]


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "120"})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_dhcp_renewal_time_to_2_min_renewal_func_c19293(
        wifi_sniffer, wifi_dut, wifi_access_point
):
    """============Configure DHCP renewal time to 2 min and verify DHCP renewal functionality============="""
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file="test_dhcp_renewal_time_to_2_min_renewal_func"
    )
    time.sleep(3)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            scan_fail = 0
            break
        except:
            logger().info(
                f"Scanning to the Wifi Access Point is failed. retry count -> {count}"
            )
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    time.sleep(2)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    wifi_access_point.interfaces.wifi.enable_dhcp_ap()
    logger().info(f"Enabling DHCP lease time")

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
    logger().info(f"Device is {device_ip}")

    packet_filter1 = f"dhcp.hw.mac_addr == {mac_address}"

    packet_filter3 = f"dhcp.ip.client == {device_ip}"

    logger().info(f"*****Initiating power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(5)

    status = ping(device_ip, ping_count)
    assert (
            status is True
    ), "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    logger().info(f"***####30 minutes duration***###")
    time.sleep(1800)
    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()

    wifi_access_point.interfaces.wifi.disable_dhcp_ap()
    logger().info(f"Disable the dhcp lease time")

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for dhcp packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter1
    ), ["packet_count"]

    logger().info("Sniffer validation for dhcp renewal request packet")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter3
    ), ["packet_count"]


### still some enchancements has to done for it, because dut has not sending IP change notification.
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dhcp_start": "192.168.50.60", "dhcp_end": "192.168.50.90", "dhcp_lease": "120"})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        # "band": 0
    }
)
def test_dhcp_ip_change_notification_c19294(wifi_sniffer, wifi_dut, wifi_access_point):
    """============Configure DHCP renewal time to 2 min and verify DHCP renewal functionality============="""
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_dhcp_ip_change_notification')
    time.sleep(3)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            scan_fail = 0
            break
        except:
            logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    time.sleep(2)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')

    packet_filter1 = f'dhcp.hw.mac_addr == {mac_address}'

    logger().info(f"*****Initiating power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)

    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")

    wifi_dut.interfaces.wifi.get_async_events()
    logger().info(f"enabling async_events")

    wifi_access_point.interfaces.wifi.enable_dhcp_ap()
    logger().info(f"Enabling DHCP lease time")
    time.sleep(180)
    # logger().info('***** Disable the AP radio *****')
    # wifi_access_point.interfaces.wifi.stop_ap()
    # time.sleep(10)
    # wifi_access_point.interfaces.wifi.start_ap()
    # time.sleep(255)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'Device is {device_ip}')
    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()

    wifi_access_point.interfaces.wifi.disable_dhcp_ap()
    logger().info(f"Disable the dhcp lease time")

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for dhcp packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "120"})
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_tcp_tx_functionality_while_dhcp_renewal_c19295(
        wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol
):
    """============Verify TCP-Tx functionality while DHCP renewal============="""
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file="test_tcp_tx_functionality_while_dhcp_renewal"
    )
    time.sleep(3)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            scan_fail = 0
            break
        except:
            logger().info(
                f"Scanning to the Wifi Access Point is failed. retry count -> {count}"
            )
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    time.sleep(2)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    wifi_access_point.interfaces.wifi.enable_dhcp_ap()
    logger().info(f"Enabling DHCP lease time")

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    time.sleep(5)
    logger().info(f"*****Initiating power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(10)
    status = ping(device_ip, ping_count)
    assert (
            status is True
    ), "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(10)

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert (
            wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 10
    ), "fail to ping host"
    logger().info("Ping successful to host")
    time.sleep(10)
    logger().info(f"****starting iperf*****")
    net_perf_client.interfaces.net_perf.init_server(
        host_ip=host_ip, device_ip=device_ip, protocol=protocol
    )
    net_perf_client.interfaces.net_perf.client_options["time"] = 70
    net_perf_client.interfaces.net_perf.start()

    logger().info(f"*******open socket and send traffic********")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    logger().info(f"******get and print throughput****")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)

    packet_filter1 = f"dhcp.hw.mac_addr == {mac_address}"

    packet_filter3 = f"dhcp.ip.client == {device_ip}"

    time.sleep(10)

    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()

    wifi_access_point.interfaces.wifi.disable_dhcp_ap()
    logger().info(f"Disable the dhcp lease time")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info("Sniffer validation for dhcp packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter1
    ), ["packet_count"]

    logger().info("Sniffer validation for dhcp renewal request packet")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter3
    ), ["packet_count"]


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "120"})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_tcp_rx_functionality_while_dhcp_renewal_c19296(
        wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol
):
    """============Verify TCP-Tx functionality while DHCP renewal============="""
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file="test_tcp_tx_functionality_while_dhcp_renewal"
    )
    time.sleep(3)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            scan_fail = 0
            break
        except:
            logger().info(
                f"Scanning to the Wifi Access Point is failed. retry count -> {count}"
            )
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    time.sleep(2)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    wifi_access_point.interfaces.wifi.enable_dhcp_ap()
    logger().info(f"Enabling DHCP lease time")

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Initiating power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(10)
    status = ping(device_ip, ping_count)
    assert (
            status is True
    ), "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(10)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert (
            wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 10
    ), "fail to ping host"
    logger().info("Ping successful to host")
    time.sleep(10)
    logger().info(f"*******##preparing iperf***")
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
        net_perf_client.interfaces.net_perf.client_options["time"] = 70
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    __print_throughput(tp)

    packet_filter1 = f"dhcp.hw.mac_addr == {mac_address}"

    packet_filter3 = f"dhcp.ip.client == {device_ip}"

    time.sleep(10)

    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()

    wifi_access_point.interfaces.wifi.disable_dhcp_ap()
    logger().info(f"Disable the dhcp lease time")

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for dhcp packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter1
    ), ["packet_count"]

    logger().info("Sniffer validation for dhcp renewal request packet")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter3
    ), ["packet_count"]
