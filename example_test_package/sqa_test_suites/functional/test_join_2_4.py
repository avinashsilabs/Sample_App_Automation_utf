import pytest
import time
import re
from datetime import datetime, date
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap

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

    Author: RaviNemali
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
                result = re.search('2022(.*)IST', x)
                time_stamp = result.group(1).strip()
                logger().info(f'time_stamp={time_stamp}')
                time_diff_list.append(time_stamp)

        filter_file.close()
        return time_diff_list

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    ),
    pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
]
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
def test_Connectivity_with_11n_only_mode_AP_C19707(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Connectivity_with_11n_only_mode_AP_C19707')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None,channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2)

        logger().info("enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        # Validating the power management bit
        packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

        # Validate dhcp
        packet_filter4 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

        logger().info(" Validate dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find dhcp in sniffer '

    logger().info(f"Associated and ping in {t.duration} seconds")

@pytest.mark.config('wifi_access_point', wifi={"ssid": "TEST-ASUS-hidden","broadcast_ssid": False})
def test_Connectivity_with_hidden_mode_AP_C19708(wifi_dut, wifi_access_point, wifi_sniffer):
        validation = True

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Connectivity_with_hidden_mode_AP_C19708')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid='TEST-ASUS-hidden',channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(10)
        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        # Validating the power management bit
        packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

        # Validate hidden mode
        packet_filter4 = f'(wlan.ssid == "") and (wlan.sa == {ap_bssid})'

        # Validate dhcp
        packet_filter5 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

        packet_filter6 = f'dhcp.hw.mac_addr == {dut_mac_address}'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

        logger().info(" Validate hidden ssid, authentication and association keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find hidden in sniffer '

        logger().info(" Validate all data packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find dhcp in sniffer '

        logger().info(" Validate dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
            'packet_count'], 'Unable to find dhcp in sniffer '

@pytest.mark.config('wifi_access_point', wifi={"ssid": "testingpmk", "passphrase": 'Testing_pmk', "security": 'WPA2'})
def test_Joining_time_PMK_C19711(wifi_dut, wifi_access_point,wifi_sniffer):
        validation = True
        packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
        time_obj = FilterPacket()

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Joining_time_PMK_C19711')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None,channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("connecting to access point with pmk.....")
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,
                                          wifi_access_point.interfaces.wifi.passphrase)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2)

        logger().info("enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        # Validating the power management bit
        packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

        # Validate the eapol 4 key
        packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                         f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

        # Validate dhcp
        packet_filter5 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        time.sleep(10)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

        logger().info(" Validate dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find dhcp in sniffer '

        logger().info("Validating time between two packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)
        time_stamp_list = time_obj.find_time_stamp()
        logger().info(f'time stamp list ={time_stamp_list}')

        # Calculating the unicast probe req time
        time_str1 = time_stamp_list[0]
        time_str1 = time_str1[:-3]
        time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
        logger().info(f'probe req time {time_object1}')
        # Calcuting the reponse time of eapol4
        time_str2 = time_stamp_list[1]
        time_str2 = time_str2[:-3]
        time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
        logger().info(f'eapol key time {time_object2}')
        date1 = date(1, 1, 1)
        datetime1 = datetime.combine(date1, time_object1)
        datetime2 = datetime.combine(date1, time_object2)
        time_taken = datetime2 - datetime1
        time_taken = time_taken.total_seconds()
        assert time_taken <= 60
        logger().info(f"time taken to connect is: {time_taken}")

@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
def test_Join_time_providing_PSK_C19712(wifi_dut, wifi_access_point, wifi_sniffer):
        validation = True
        packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
        time_obj = FilterPacket()

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Join_time_providing_PSK_C19712')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None,channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2)

        logger().info("enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        # Validating the power management bit
        packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

        # Validate the eapol 4 key
        packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                         f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

        # Validate dhcp
        packet_filter5 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

        logger().info(" Validate dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find dhcp in sniffer '

        logger().info("Validating time between two packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)

        time_stamp_list = time_obj.find_time_stamp()
        logger().info(f'time stamp list ={time_stamp_list}')

        # Calculating the unicast probe req time
        time_str1 = time_stamp_list[0]
        time_str1 = time_str1[:-3]
        time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
        logger().info(f'probe req time {time_object1}')
        # Calcuting the reponse time of eapol4
        time_str2 = time_stamp_list[1]
        time_str2 = time_str2[:-3]
        time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
        logger().info(f'eapol key time {time_object2}')
        date1 = date(1, 1, 1)
        datetime1 = datetime.combine(date1, time_object1)
        datetime2 = datetime.combine(date1, time_object2)
        time_taken = datetime2 - datetime1
        time_taken = time_taken.total_seconds()
        assert time_taken <= 60
        logger().info(f"time taken to connect is: {time_taken}")

@pytest.mark.config('wifi_access_point', wifi={"passphrase": 'test123@random'})
def test_Joining_by_rsi_psk_command_C19714(wifi_dut, wifi_access_point, wifi_sniffer):
        validation = True

        logger().info(" ====== configuring the sniffer with access point channel ======")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Joining_by_rsi_psk_command_C19714')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None,channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2)

        logger().info("enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        # Validating the power management bit
        packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

        # Validate dhcp
        packet_filter4 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

        logger().info(" Validate dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find dhcp in sniffer '

@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
def test_Join_providing_PMK_C19715(wifi_dut, wifi_access_point, wifi_sniffer):
        validation = True

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Join_providing_PMK_C19715')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None,channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,
                                          wifi_access_point.interfaces.wifi.passphrase)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2)

        logger().info("enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        # Validating the power management bit
        packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

        # Validate dhcp
        packet_filter4 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

        logger().info(" Validate dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find dhcp in sniffer '

@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "pmkwithwrongpsk", "passphrase": 'thisisatestnetwork', "security": 'WPA2'})
def test_Joining_to_PMK_in_module_by_wrong_PSK_C19716(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Joining_to_PMK_in_module_by_wrong_PSK_C19716')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None,channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        with pytest.raises(WlanError) as exc_info:
            logger().info("connecting to access point with wrong psk.....")
            wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid, "12345678")
        assert exc_info.value.error_code == 0x0008
        logger().info(f"Dut Tried to connect to ap with wrong password, observed error code 0x0008 which is expected")

        # Validate de-auth packet
        packet_filter1 = f'(wlan.fc.type_subtype == 12)'

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(" Validate de-auth packet in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find deauth packet'

    logger().info(f"test executed in {t.duration} seconds")

@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testwithnossid", "passphrase": 'Testing_pmk', "security": "WPA2"})
def test_wifi_join_PMK_without_SSID_C19717(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        with pytest.raises(WlanError) as exc_info:
            # This API connects STA to the third party AP with the pmk generated
            wifi_dut.interfaces.wifi.join_pmk("\"\"", wifi_access_point.interfaces.wifi.passphrase)
            assert exc_info.value.error_code == 0x0003
            logger().info(f"Dut Tried to connect to ap with wrong password, observed error code 0x0003 which is expected")
    logger().info(f"test executed in {t.duration} seconds")

@pytest.mark.skip()
@pytest.mark.config('wifi_access_point', wifi={"ssid": "redpine", "passphrase": 'Testing_pmk', "security": "WPA2"})
def test_wifi_join_pmk_with_space_before_redpine_ssid_C19718(wifi_dut, wifi_access_point, wifi_sniffer):
        validation = True

        logger().info(" ============== THIS TEST CASE SUPPORTS ONLY WITH ASUS AP ============== ")
        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_join_pmk_with_space_before_redpine_ssid_C19718')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        ssid = " redpine"

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_pmk(ssid, "thisisatestnetwork")

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2)

        logger().info("enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        # Validating the power management bit
        packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

        # Validate dhcp
        packet_filter4 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

        logger().info(" Validate dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find dhcp in sniffer '

@pytest.mark.config('wifi_access_point', wifi=
{"ssid": "Testssid", "passphrase": "1234567890qwertyuioplkjhgfdsazxcvbnmkloirgrgrtyuio1234567890o", "security": "WPA2"})
def test_psk_with_64_different_characters_C19719(wifi_dut, wifi_access_point, wifi_sniffer):
        validation = True

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_psk_with_64_different_characters_C19719')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None,channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2)

        logger().info("enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        # Validating the power management bit
        packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

        # Validate dhcp
        packet_filter4 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

        logger().info(" Validate dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find dhcp in sniffer '

@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                                               "passphrase": "123456789qwertyuio123456789qwertyuio123456789zxcvbnm123456789zx",
                                               "security": "WPA2"})
def test_join_pmk_with_64_characters_psk_32_characters_ssid_C19720(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_join_pmk_with_64_characters_psk_32_characters_ssid_C19720')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None,channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,wifi_access_point.interfaces.wifi.passphrase)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2)

        logger().info("enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        # Validating the power management bit
        packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

        # Validate dhcp
        packet_filter4 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

        logger().info(" Validate dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find dhcp in sniffer '

    logger().info(f"Associated and ping in {t.duration} seconds")

@pytest.mark.config('wifi_access_point', wifi={"ssid": 'testing', "security": 'WPA2', "channel": 7})
def test_Init_Scan_Join_Disconnect_30min_C19710(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        t_end = time.time() + 60 * 30
        while time.time() < t_end:
            validation = True

            logger().info(" ====== configuring the sniffer with the access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Init_Scan_Join_Disconnect_30min_C19710')

            logger().info("scan for the ap's.....")
            ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None,channel=wifi_access_point.interfaces.wifi.channel)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')

            logger().info("connecting to access point.....")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

            logger().info("enabling dhcp in DUT.......")
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

            logger().info("enabling wifi power save mode in DUT......")
            wifi_dut.interfaces.wifi.power_save(2)

            logger().info("enabling bt power save mode in DUT......")
            wifi_dut.interfaces.wifi.bt_power_save(2)

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
            packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                             f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                             f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

            # Validating the power management bit
            packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

            # Validate dhcp
            packet_filter4 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'

            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, 10)
            assert status == 1

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                                 'in sniffer'

            logger().info(" Validate power management bit 1")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

            logger().info(" Validate dhcp")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                  'packet_count'], 'Unable to find dhcp in sniffer '
    logger().info(f"Associated and ping in {t.duration} seconds")