import pytest
import re
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes
import time
from datetime import datetime
from utf.interfaces.shell.ssh_shell import SSHShell

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut

    Author: Aravind,Himaja,Vishakha
"""


def logger():
    return get_logger(__name__)


class FilterPacket:
    def find_time_stamp(self):
        packet_filter1 = "Arrival Time:"
        count = 0
        time_diff_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter1 in x:
                result = re.search(r'\d+:\d+:\d+.\d+', x)
                logger().info(f"year : {result}")
                time_stamp = result.group(1).strip()
                logger().info(f'time_stamp={time_stamp}')
                time_diff_list.append(time_stamp)

        filter_file.close()
        return time_diff_list


def rts_cts_data_sequence_check(wifi_sniffer, dut_mac, ap_bssid, rts_threshold=0, test_case='test'):
    snf_shell = wifi_sniffer.interfaces.capture.shell
    remote_cap_file = wifi_sniffer.interfaces.capture.remote_capture_file
    logger().info(f"capture file is:{remote_cap_file}")

    filter_files = "/tmp/filter_files"
    filter_file = f'{filter_files}/{test_case}_filter.pcap'
    snf_shell(f"sudo rm -rf {filter_files}; sudo mkdir {filter_files}; sudo chmod +777 {filter_files};")

    logger().info("Creating filter file which consists of packets related to our DUT and AP")
    packets_filter = f'tshark -r {remote_cap_file} -Y "(wlan.addr eq {dut_mac}) or (wlan.addr eq {ap_bssid})" -w {filter_file}'
    snf_shell(packets_filter)

    rts_cts_file = f'{filter_files}/{test_case}_rts_cts.txt'
    rts_cts_filter = f'tshark -r {filter_file} -Tfields -e "frame.number" -e "wlan.fc.subtype" -Y ' \
                     f'"(wlan.ta == {dut_mac} && (wlan.fc.type_subtype == 0x0028 && data.len > {rts_threshold}) || ' \
                     f' (wlan.fc.type_subtype == 0x001b)) ||(wlan.ra == {dut_mac} && wlan.fc.type_subtype == 0x001c)"'
    snf_shell(f'{rts_cts_filter} > {rts_cts_file}')

    if isinstance(snf_shell, SSHShell):
        with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp_main:
            time_stamp = datetime.fromtimestamp(time.time()).strftime('%m_%d_%Y-%H_%M_%S')
            sftp_main.get(filter_file, f"./reports/{test_case}_filter_{time_stamp}.pcap")
            out_file = f"./reports/{test_case}_rts_cts_{time_stamp}.txt"
            sftp_main.get(rts_cts_file, out_file)
            sftp_main.close()

    logger().info("\nChecking RTS, CTS, DATA Packets Sequence in Sniffer")
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
            logger().info(f"Found Sequence [RTS--->CTS--->DATA] with frame numbers {list((rts, cts, data))} and "
                          f"data length greater than rts_threshold value '{rts_threshold}'")
            rts = cts = 0
            status = True
        else:
            rts = cts = 0
    return status


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.config('wifi_dut', wifi={"rts_config": 1, "rts_threshold": 256})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.firmware_app("test_wlan_rts")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_rts_c19511(firmware_loader, wifi_dut, wifi_access_point, wifi_sniffer, net_perf_client, wifi_client,
                    rs_helper):
    validation = True
    wifi_dut.interfaces.wifi.set_rts_cmd(1, 256)

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rts_c19511')

    logger().info("scan for the ap's.....")
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("enabling the power save modes ")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    # Validating the power management bit
    packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
    logger().info("Checking the rts and cts packet along with data packet")
    packet_filter2 = f'(wlan.ta == {dut_mac_address} && (wlan.fc.type_subtype == 0x0028 || wlan.fc.type_subtype == 0x001b)) ' \
                     f'|| (wlan.ra == {dut_mac_address} && wlan.fc.type_subtype == 0x001c)'

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    ping_status = rs_helper.ping_with_custom_size(device_ip, ping_counts=20, byte_size=300)
    assert ping_status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    # preparing wifi client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip)

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating power management bit in sniffer capture")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer'

    logger().info("\n\nValidating RTS,CTS,DATA Packets in sniffer capture")
    status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, ap_bssid, 256, test_case="test_C19511")
    assert status, "Unable to find sequence RTS--->CTS--->DATA packets with data length more than rts_threshold value"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.config('wifi_dut', wifi={"rts_config": 1, "rts_threshold": 0})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.firmware_app("test_wlan_rts")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_rts_c19512(firmware_loader, wifi_dut, wifi_access_point, wifi_sniffer, net_perf_client, wifi_client,
                    rs_helper):
    validation = True
    wifi_dut.interfaces.wifi.set_rts_cmd(1, 0)

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rts_c19512')

    logger().info("scan for the ap's.....")
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("enabling the power save modes ")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    # Validating the power management bit
    packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
    logger().info("Checking the rts and cts packet along with data packet")
    packet_filter2 = f'(wlan.ta == {dut_mac_address} && (wlan.fc.type_subtype == 0x0028 || wlan.fc.type_subtype == 0x001b)) ' \
                     f'|| (wlan.ra == {dut_mac_address} && wlan.fc.type_subtype == 0x001c)'

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    ping_status = rs_helper.ping_with_custom_size(device_ip, ping_counts=20, byte_size=10)
    assert ping_status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    # preparing wifi client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip)

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating power management bit in sniffer capture")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer'

    logger().info("\n\nValidating RTS,CTS,DATA Packets in sniffer capture")
    status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, ap_bssid, test_case="test_C19512")
    assert status, "Unable to find sequence RTS--->CTS--->DATA packets with data length more than rts_threshold value"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.config('wifi_dut', wifi={"rts_config": 1, "rts_threshold": 2347})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.firmware_app("test_wlan_rts")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_rts_c19513(firmware_loader, wifi_dut, wifi_access_point, wifi_sniffer, net_perf_client, wifi_client,
                    rs_helper):
    validation = True
    wifi_dut.interfaces.wifi.set_rts_cmd(1, 2347)

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rts_c19513')

    logger().info("scan for the ap's.....")
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("enabling the power save modes ")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    # Validating the power management bit
    packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
    logger().info("Checking the rts and cts packet along with data packet")
    packet_filter2 = f'(wlan.ta == {dut_mac_address} && (wlan.fc.type_subtype == 0x001b)) ' \
                     f'|| (wlan.ra == {dut_mac_address} && wlan.fc.type_subtype == 0x001c)'

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    ping_status = rs_helper.ping_with_custom_size(device_ip, ping_counts=20, byte_size=256)
    assert ping_status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    # preparing wifi client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip)

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating power management bit in sniffer capture")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer'

    logger().info("\n\nValidating RTS,CTS,DATA Packets in sniffer capture")
    status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, ap_bssid, 2347, test_case="test_C195113")
    assert not status, "Found sequence RTS--->CTS--->DATA packets with data length more than rts_threshold value which is not expected"
    logger().info("DUT did not send RTS packets which is expected as per the testcase")
