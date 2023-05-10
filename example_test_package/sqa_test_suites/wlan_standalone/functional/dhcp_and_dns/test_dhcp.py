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
from datetime import datetime
import uuid
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, logger


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


class validation_sniffer:
    """ Method to verify dhcp renewal by checking the time difference b/w successive dhcp requests
    is lease_time/2 or 87.5% of lease time and also verifies null frames with powersave"""

    def dhcp_renewal(self, wifi_access_point, wifi_sniffer, dut_mac_address, capture_filename, dhcp_lease):

        validation = True
        pwrsave_filter = f"((wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype == 0x0024)) && (wlan.fc.pwrmgt == 1)"

        logger().info("passing passphrase and ssid to decrypt dhcp packets")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info("DHCP decryption is in progress : Validating the DORA process")

        logger().info("Sniffer validation for dhcp packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, pwrsave_filter)["packet_count"], \
            'Unable to find the power save sniffer packets'
        packet_filter = f"wlan.addr == {dut_mac_address} && dhcp"
        logger().info("calling the method from tshark filter_time_stamp")
        current_time = time.time()
        updated_capture_file = 'filter_' + capture_filename + '_' + str(
            datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        file_name = f'./reports/{updated_capture_file}.pcap'
        local_capture_file = file_name
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
        packet_filter1 = f'((wlan.addr == {dut_mac_address}) && (!(ip.dst == 255.255.255.255) && (dhcp.option.dhcp == ' \
                         f'3))) && wlan.fc.retry == 0 '

        wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
            f"frame.number -w "
            f"{wlan_filter_file}")
        with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
            sftp.get(wlan_filter_file, local_capture_file)
        result = wifi_sniffer.interfaces.capture.fetch_packet_time_stamp(packet_filter,
                                                                         wlan_filter_file)
        assert result, f"Unable to find the time stamp for the {packet_filter}"
        logger().info(f"DHCP request packet list {result}")
        result.pop(0)  # Pop the first element because always the reference packet will be set to 0
        count = 0
        if len(result) >= 2:
            diff_time_dhcp_request = [float(result[i + 1]) - float(result[i]) for i in range(0, len(result) - 1)]
            logger().info(f"time difference between successive dhcp requests :{diff_time_dhcp_request}")
            for i in range(0, len(diff_time_dhcp_request)):
                logger().info(f"time diff {float(diff_time_dhcp_request[i])}")
                if float((dhcp_lease / 2) - 10) < (float(diff_time_dhcp_request[i])) <= float((dhcp_lease / 2) + 10):
                    logger().info(
                        f"DHCP request packet found for {float(dhcp_lease / 2)} seconds lease time and the dhcp request "
                        f"packet time is {float(diff_time_dhcp_request[i])}")
                    count = count+1
                elif float((dhcp_lease / 2) - 5) < (float(diff_time_dhcp_request[i])) <= float((dhcp_lease * 87.5) / 100):
                    logger().info(
                        f"DHCP request packet found for 87.5% of lease time time and the dhcp request packet time "
                        f"difference is {float(diff_time_dhcp_request[i])}")
                    count = count+1
                else:
                    rangelist = [x for x in range(int((dhcp_lease / 2) - 10), int((dhcp_lease / 2) + 10))]
                    logger().info(f"expected packet should be in :{rangelist}")
                    for j in rangelist:
                        logger().info(f"**{diff_time_dhcp_request[i]}*{j}**{float(diff_time_dhcp_request[i]) % float(j)}*")
                        if float(diff_time_dhcp_request[i]) % float(j) <= 2:
                            logger().info(f"observed pkt diff is multiple of lease time:{diff_time_dhcp_request[i]}"
                                          f" multiple of {j}")
                            count = count + 1
            assert (float(count/len(diff_time_dhcp_request))*100) >= 80, "expected pkts are not found with the given lease time"
        else:
            assert False, "DHCP list doesnot contain two request time stamps to compare"




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
        wifi_sniffer, wifi_dut, wifi_access_point, utf_constants
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

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip_in_static_mode()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
    logger().info(f"Device is {device_ip}")

    packet_filter3 = f"((wlan.addr == {mac_address}) && (wlan.fc.type_subtype == 0x0024)) && (wlan.fc.pwrmgt == 1)"

    logger().info(f"*****Initiating power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)

    status = ping(device_ip, utf_constants.get("ping_count"))
    assert (
            status is True
    ), "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")

    time.sleep(15)
    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Sniffer validation for ps poll and null packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)["packet_count"], \
        'Unable to find sniffer packets for power save'


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
@pytest.mark.parametrize("dhcp_lease", [120])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "120", "security": 'OPEN'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_dhcp_renewal_time_to_2_min_renewal_func_c19293(
        wifi_sniffer, wifi_dut, wifi_access_point, dhcp_lease, rs_helper, utf_constants
):
    """============Configure DHCP renewal time to 2 min and verify DHCP renewal functionality============="""
    validation = True
    capture_filename = "test_dhcp_renewal_time_to_2_min_renewal_func"
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=capture_filename
    )
    time.sleep(3)
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    wifi_access_point.interfaces.wifi.enable_dhcp_ap()
    logger().info(f"Enabling DHCP lease time")

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    logger().info(f"***####30 minutes duration***###")
    time.sleep(1800)
    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    validation_sniffer_obj = validation_sniffer()
    validation_sniffer_obj.dhcp_renewal(wifi_access_point, wifi_sniffer, dut_mac_address, capture_filename, dhcp_lease)


# still some enchancements has to done for it, because dut has not sending IP change notification.
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dhcp_start": "192.168.50.2", "dhcp_end": "192.168.50.60", "dhcp_lease": "120",
                          "security": 'OPEN'})
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
    }
)
def test_dhcp_ip_change_notification_c19294(wifi_sniffer, wifi_dut, wifi_access_point,
                                            utf_constants, rs_helper):
    """============Configure DHCP renewal time to 2 min and verify DHCP renewal functionality============="""
    validation = True
    capture_filename = 'test_dhcp_ip_change_notification'
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    time.sleep(3)

    wifi_access_point.interfaces.wifi.enable_dhcp_ap()
    logger().info(f"Enabling DHCP lease time")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.100", dhcp_end="192.168.50.240")
    logger().info(f"Enabling DHCP lease time")
    time.sleep(180)

    wifi_dut.interfaces.wifi.get_async_events()
    logger().info(f"enabling async_events")

    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter1 = f"((wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype == 0x0024)) && (wlan.fc.pwrmgt == 1)"

    logger().info("Sniffer validation for dhcp packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find the dhcp sniffer packets'


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "100", "security": 'OPEN'})
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("dhcp_lease", [100])
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
        wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol,
        dhcp_lease, rs_helper, utf_constants
):
    """============Verify TCP-Tx functionality while DHCP renewal============="""
    validation = True
    capture_filename = "test_tcp_tx_functionality_while_dhcp_renewal"
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=capture_filename
    )
    time.sleep(3)
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    wifi_access_point.interfaces.wifi.enable_dhcp_ap()
    logger().info(f"Enabling DHCP lease time")

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    timeout = 90
    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")
    logger().info(f"For validating the time difference between two request packets adding the sleep for 200 seconds to "
                  f"achieve the lease time of {dhcp_lease} seconds")
    time.sleep(200)

    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    validation_sniffer_obj = validation_sniffer()
    validation_sniffer_obj.dhcp_renewal(wifi_access_point, wifi_sniffer, dut_mac_address, capture_filename, dhcp_lease)


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
@pytest.mark.parametrize("dhcp_lease", [100])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "100", "security": 'OPEN'})
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
        wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, dhcp_lease,
        rs_helper, utf_constants
):
    """============Verify TCP-Tx functionality while DHCP renewal============="""

    capture_filename = "test_tcp_rx_functionality_while_dhcp_renewal_c19296"

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    time.sleep(3)

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    wifi_access_point.interfaces.wifi.enable_dhcp_ap()
    logger().info(f"Enabling DHCP lease time")

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    timeout = 90
    logger().info(f"*******##preparing iperf***")
    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")

    time.sleep(200)

    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    validation_sniffer_obj = validation_sniffer()
    validation_sniffer_obj.dhcp_renewal(wifi_access_point, wifi_sniffer, dut_mac_address, capture_filename, dhcp_lease)
