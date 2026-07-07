import pytest
import time
from datetime import datetime
from utf.interfaces.shell.ssh_shell import SSHShell
from utf.utils.logger import get_logger
from utf_wifi_zephyr.utils.sl_status import SLStatus
from utf.utf_config import UtfConfig

"""
    setup requirement:
        1. DUT(Si917_SDK)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan mode and enable rts threshold
        2. Join the access point and enable the dhcp
        4. Initiate ping from the dut
        5. Check for rts, cts, data packets in sniffer capture

    Author: Vinod.G
"""


def logger():
    return get_logger(__name__)


def rts_cts_data_sequence_check(wifi_sniffer, dut_mac, ap_bssid, rts_threshold, test_case, data_len_check=True):
    snf_shell = wifi_sniffer.interfaces.capture.shell
    remote_cap_file = wifi_sniffer.interfaces.capture.remote_capture_file
    logger().info(f"capture file is:{remote_cap_file}")

    filter_files = "/tmp/filter_files"
    snf_shell(f"sudo rm -rf {filter_files}; sudo mkdir {filter_files}; sudo chmod +777 {filter_files};")
    rts_cts_file = f'{filter_files}/{test_case}_rts_cts.txt'
    data_filter = f'wlan.fc.type_subtype == 0x0028 && data.len > {rts_threshold}' if data_len_check else 'wlan.fc.type_subtype == 0x0028'
    rts_cts_filter = (f'tshark -r {remote_cap_file} -Tfields -e "frame.number" -e "wlan.fc.subtype" -Y '
                      f'"(wlan.ta == {dut_mac} && ({data_filter}) || (wlan.fc.type_subtype == 0x001b)) || '
                      f'(wlan.ra == {dut_mac} && wlan.fc.type_subtype == 0x001c)"')
    snf_shell(f'{rts_cts_filter} > {rts_cts_file}')

    if isinstance(snf_shell, SSHShell):
        with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp_main:
            time_stamp = datetime.fromtimestamp(time.time()).strftime('%m_%d_%Y-%H_%M_%S')
            out_file = f"./reports/{test_case}_rts_cts_{time_stamp}.txt"
            sftp_main.get(rts_cts_file, out_file)
            sftp_main.close()

    logger().info("************ Checking RTS, CTS, DATA Packets Sequence in Sniffer ************")
    frames_dict = {}
    with open(out_file, "r") as fd:
        for line in fd.readlines():
            frames_dict[line.split()[0]] = line.split()[1]

    status = False
    rts = cts = 0
    for frame_num, frame_type in frames_dict.items():
        if frame_type == '11':
            rts = int(frame_num)
        elif frame_type == '12' and rts:
            cts = int(frame_num)
        elif frame_type == '8' and cts:
            data = int(frame_num)
            message = (f"Found Sequence [RTS--->CTS--->DATA] with frame numbers {list((rts, cts, data))} and "
                       f"data length greater than rts_threshold value '{rts_threshold}'")
            if not data_len_check:
                message = f"Found Sequence [RTS--->CTS--->DATA] with frame numbers {list((rts, cts, data))}"
            logger().info(message)
            rts = cts = 0
            status = True
        else:
            rts = cts = 0
    return status


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
def test_zephyr_verify_rts_threshold_256_c996260(wifi_dut, wifi_access_point, wifi_sniffer, zephyr_wifi_collections,
                                                request, sniffer_filter):
    """
    Verify whether DUT is not sending any RTS packet for every data packet if we configure RTS Threshold as '256'
    """
    try:
        capture_filename = request.node.name
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"Configuring the sniffer with access point channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(3)

        result = zephyr_wifi_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True,
                                                              ping_count=10,
                                                              associated=False, retry_count=3, ping_after_power_save=True)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        set_rts_threshold_value = wifi_dut.interfaces.wifi.wifi_rts_threshold(threshold_value=256)
        get_rts_threhold_value = wifi_dut.interfaces.wifi.wifi_get_rts_threshold()

        assert set_rts_threshold_value == get_rts_threhold_value, "The RTS threshold value set via wifi_rts_threshold does not match the value returned by wifi_get_rts_threshold"

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        ping_status = zephyr_wifi_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=300)
        assert ping_status, "DUT is not responding to ping request"
        logger().info("ping to DUT is successful....")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("\n\nValidating RTS,CTS,DATA Packets in sniffer capture")
        status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, ap_bssid, rts_threshold=256,
                                             test_case="test_C996260")
        assert status, "Unable to find sequence RTS--->CTS--->DATA packets with data length more than rts_threshold value"
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_bssid,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as err:
        zephyr_wifi_collections.exception_handling(wifi_dut, err)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
def test_zephyr_verify_rts_threshold_0_c996259(wifi_dut, wifi_access_point, wifi_sniffer, zephyr_wifi_collections,
                                              request, sniffer_filter):
    """
    Verify whether DUT is sending RTS packets for every data packet if we configure RTS Threshold as '0'
    """
    try:
        capture_filename = request.node.name
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"Configuring the sniffer with access point channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(3)

        result = zephyr_wifi_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True,
                                                              ping_count=10,
                                                              associated=False, retry_count=3, ping_after_power_save=True)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        set_rts_threshold_value = wifi_dut.interfaces.wifi.wifi_rts_threshold(threshold_value=0)
        get_rts_threhold_value = wifi_dut.interfaces.wifi.wifi_get_rts_threshold()

        assert set_rts_threshold_value == get_rts_threhold_value, "The RTS threshold value set via wifi_rts_threshold does not match the value returned by wifi_get_rts_threshold"

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        ping_status = zephyr_wifi_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=10)
        assert ping_status, "DUT is not responding to ping request"
        logger().info("ping to DUT is successful....")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("\n\nValidating RTS,CTS,DATA Packets in sniffer capture")
        status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, ap_bssid, rts_threshold=0,
                                             test_case="test_C996259")
        assert status, "Unable to find sequence RTS--->CTS--->DATA packets with data length more than rts_threshold value"
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_bssid,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as err:
        zephyr_wifi_collections.exception_handling(wifi_dut, err)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
def test_zephyr_verify_rts_threshold_2347_c996261(wifi_dut, wifi_access_point, wifi_sniffer, zephyr_wifi_collections,
                                                 request, sniffer_filter):
    """
    Verify whether DUT is not sending any RTS packet for every data packet if we configure RTS Threshold as '2347'
    """
    try:
        capture_filename = request.node.name
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"Configuring the sniffer with access point channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(3)

        result = zephyr_wifi_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True,
                                                              ping_count=10,
                                                              associated=False, retry_count=3, ping_after_power_save=True)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        set_rts_threshold_value = wifi_dut.interfaces.wifi.wifi_rts_threshold(threshold_value=2347)
        get_rts_threhold_value = wifi_dut.interfaces.wifi.wifi_get_rts_threshold()

        assert set_rts_threshold_value == get_rts_threhold_value, "The RTS threshold value set via wifi_rts_threshold does not match the value returned by wifi_get_rts_threshold"

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        ping_status = zephyr_wifi_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=10)
        assert ping_status, "DUT is not responding to ping request"
        logger().info("ping to DUT is successful....")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("\n\nValidating RTS,CTS,DATA Packets in sniffer capture")
        status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, ap_bssid, rts_threshold=2347,
                                             test_case="test_c996261")
        assert not status, "Found sequence RTS--->CTS--->DATA packets with data length more than rts_threshold value which is not expected"
        logger().info("DUT did not send RTS packets which is expected as per the testcase")
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_bssid,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as err:
        zephyr_wifi_collections.exception_handling(wifi_dut, err)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
def test_zephyr_invalid_rts_c996263(wifi_dut, wifi_access_point, wifi_sniffer, zephyr_wifi_collections, request):
    """
    Verify DUT is throwing error or not by setting Invalid RTS threshold.
    """
    try:
        capture_filename = request.node.name
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"Configuring the sniffer with access point channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(3)

        result = zephyr_wifi_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                              ping_count=10,
                                                              associated=False, retry_count=3)
        wifi_dut.interfaces.wifi.wifi_rts_threshold(threshold_value=2348, expected_status=SLStatus.SL_STATUS_FAIL)
        logger().info(f"DUT throws error when rts threshold value is set to 2348 which is expected behavior")

    except Exception as err:
        zephyr_wifi_collections.exception_handling(wifi_dut, err)
