import pytest
import re
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes

def logger():
    return get_logger(__name__)

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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_rts_c19511(wifi_dut, wifi_access_point, wifi_sniffer, net_perf_client, wifi_client, rs_helper):
    validation = True
    wifi_dut.interfaces.wifi.set_rts_cmd(1, 256)

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rts_c19511')

    logger().info("scan for the ap's.....")
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
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

    #preparing wifi client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip)

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer'

    logger().info("Validate RTS and CTS Packet")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find rts and cts packets in sniffer'


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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_rts_c19512(wifi_dut, wifi_access_point, wifi_sniffer, net_perf_client, wifi_client, rs_helper):
    validation = True
    wifi_dut.interfaces.wifi.set_rts_cmd(1, 0)

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rts_c19512')

    logger().info("scan for the ap's.....")
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
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

    #preparing wifi client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip)

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer'

    logger().info("Validate RTS and CTS Packet")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find rts and cts packets in sniffer'


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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_rts_c19513(wifi_dut, wifi_access_point, wifi_sniffer, net_perf_client, wifi_client, rs_helper):
        validation = True
        wifi_dut.interfaces.wifi.set_rts_cmd(1, 2347)

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rts_c19513')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
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

        #preparing wifi client
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        assert wifi_client.interfaces.wifi.ping(server_ip=device_ip)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer'

        logger().info("Validate RTS and CTS Packet")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'rts and cts packets is not expected in sniffer, But still seeing the mentioned packets'
