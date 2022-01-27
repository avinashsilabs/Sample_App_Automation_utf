import pytest
import re
from datetime import datetime
from utils.time_measurer import TimeMeasurer
from utils.logger import get_logger
from utils.iperf.iperf_utils import ping
from interfaces.wifi import WlanError
from devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap

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
    )
]
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
# The test case checks whether the DUT connection works fine in Access point 11n mode
def test_Connectivity_with_11n_only_mode_AP_C19707(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        packet_filter2 = False

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Connectivity_with_11n_only_mode_AP_C19707')

        # Scan for the AP's
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        # This API connects STA to the third party AP
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # This API Enables the wifi power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating Unicast Probe request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid}'

        # Validating Broadcast Probe request
        packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

        # Validating the power management bit
        packet_filter5 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

        # Validate 11n capability, authentication ,association
        packet_filter4 = f'(wlan.tag.number == 45 ) && (wlan.fc.type_subtype == 0x0000)'

        # Validate EAPOL keys
        packet_filter6 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                         f'wlan.da == {dut_mac_address} and eapol'

        # Validate auth key
        packet_filter7 = f'wlan.addr == {dut_mac_address} && (wlan.fc.type_subtype == 0x000b)'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Unicast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find Unicast Probe request packet in sniffer'
        logger().info("Validating Broadcast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
            'packet_count'], 'Unable to find Broadcast Probe request packet in sniffer'
        logger().info(" Validate 11n capability, authentication and association keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
            'packet_count'], 'Unable to find 11n capability, authentication and association in sniffer '
        logger().info(" Validating the power management bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(" Validating the EAPOL keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6, packet_filter2)[
            'packet_count'], 'Unable to find eapol keys in sniffer'
        logger().info(" Validating auth key in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7, packet_filter2)[
            'packet_count'], 'Unable to auth key in sniffer'
    logger().info(f"Associated and ping in {t.duration} seconds")

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"broadcast_ssid": False})
# The test case checks whether the DUT connection works with AP hidden mode
def test_Connectivity_with_hidden_mode_AP_C19708(wifi_dut, wifi_access_point, wifi_sniffer):
        validation = True
        packet_filter2 = False

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Connectivity_with_hidden_mode_AP_C19708')

        # Scan for the AP's
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        # This API connects STA to the third party AP
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # This API Enables the wifi power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating Unicast Probe request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid}'

        # Validating Broadcast Probe request
        packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

        # Validating the power management bit
        packet_filter5 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

        # Validate hidden mode, authentication ,association
        packet_filter4 = f'(wlan.tag.number == 4 ) && (wlan.fc.type_subtype == 0x0000)'

        # Validate EAPOL keys
        packet_filter6 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.da == {dut_mac_address} and eapol'

        # Validate auth key
        packet_filter7 = f'wlan.addr == {dut_mac_address} && (wlan.fc.type_subtype == 0x000b)'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Unicast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find Unicast Probe request packet in sniffer'
        logger().info("Validating Broadcast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
            'packet_count'], 'Unable to find Broadcast Probe request packet in sniffer'
        logger().info(" Validate hidden ssid, authentication and association keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
            'packet_count'], 'Unable to find hidden, authentication and association in sniffer '
        logger().info(" Validating the power management bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(" Validating the EAPOL keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6, packet_filter2)[
            'packet_count'], 'Unable to find eapol keys in sniffer'
        logger().info(" Validating auth key in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7, packet_filter2)[
            'packet_count'], 'Unable to find auth key in sniffer'

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "testingpmk", "passphrase": 'Testing_pmk', "security": 'WPA2'})
# The test case checks whether the DUT connects to Access point with the generated pmk with user given ssid and password
def test_Joining_time_PMK_C19711(wifi_dut, wifi_access_point,wifi_sniffer):
        validation = True
        packet_filter2 = False
        time_obj = FilterPacket()
        packet_filter8 = 'Type/Subtype: Probe Request (0x0004)'

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Joining_time_PMK_C19711')

        # Scan for the AP's
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        # This API connects STA to the third party AP with the pmk generated
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,
                                          wifi_access_point.interfaces.wifi.passphrase)

        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # This API Enables the wifi power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating Unicast Probe request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid}'

        # Validating Broadcast Probe request
        packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

        # Validating the power management bit
        packet_filter5 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

        # Validate authentication ,association
        packet_filter4 = f'(wlan.tag.number == 45 ) && (wlan.fc.type_subtype == 0x0000)'

        # Validate EAPOL keys
        packet_filter6 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                         f'wlan.da == {dut_mac_address} and eapol'

        # Validate auth key
        packet_filter7 = f'wlan.addr == {dut_mac_address} && (wlan.fc.type_subtype == 0x000b)'

        # Validate the eapol 4 key
        packet_filter9 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                         f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating time between two packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter8, packet_filter9)
        time_stamp_list = time_obj.find_time_stamp()
        logger().info(f'time stamp list ={time_stamp_list}')

        # Calculating the unicast probe req time
        time_str1 = time_stamp_list[0]
        time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()

        # Calcuting the reponse time of eapol4
        time_str2 = time_stamp_list[1]
        time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
        date = datetime.date(1, 1, 1)
        datetime1 = datetime.datetime.combine(date, time_object1)
        datetime2 = datetime.datetime.combine(date, time_object2)
        time_taken = datetime1 - datetime2
        assert time_taken >= 60
        logger().info(f"time taken to connect is: {time_taken}")

        logger().info("Validating Unicast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find Unicast Probe request packet in sniffer'
        logger().info("Validating Broadcast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
            'packet_count'], 'Unable to find Broadcast Probe request packet in sniffer'
        logger().info(" Validate authentication and association keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
            'packet_count'], 'Unable to find authentication and association in sniffer '
        logger().info(" Validating the power management bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(" Validating the EAPOL keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6, packet_filter2)[
            'packet_count'], 'Unable to find eapol keys in sniffer'
        logger().info(" Validating auth key in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7, packet_filter2)[
            'packet_count'], 'Unable to find auth key in sniffer'

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
# The test case checks whether the DUT connection Time on the joining the AP
def test_Join_time_providing_PSK_C19712(wifi_dut, wifi_access_point, wifi_sniffer):
        validation = True
        packet_filter2 = False
        time_obj = FilterPacket()
        packet_filter8 = 'Type/Subtype: Probe Request (0x0004)'

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Join_time_providing_PSK_C19712')

        # Scan for the AP's
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        # This API connects STA to the third party AP
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # This API Enables the wifi power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating Unicast Probe request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid}'

        # Validating Broadcast Probe request
        packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

        # Validating the power management bit
        packet_filter5 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

        # Validate authentication ,association
        packet_filter4 = f'(wlan.tag.number == 45 ) && (wlan.fc.type_subtype == 0x0000)'

        # Validate EAPOL keys
        packet_filter6 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                         f'wlan.da == {dut_mac_address} and eapol'

        # Validate auth key
        packet_filter7 = f'wlan.addr == {dut_mac_address} && (wlan.fc.type_subtype == 0x000b)'

        # Validate the eapol 4 key
        packet_filter9 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                         f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating time between two packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter8, packet_filter9)
        time_stamp_list = time_obj.find_time_stamp()
        logger().info(f'time stamp list ={time_stamp_list}')

        # Calculating the probe req time
        time_str1 = time_stamp_list[0]
        time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()

        # Calculating the probe response time
        time_str2 = time_stamp_list[1]
        time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
        date = datetime.date(1, 1, 1)
        datetime1 = datetime.datetime.combine(date, time_object1)
        datetime2 = datetime.datetime.combine(date, time_object2)
        time_taken = datetime1 - datetime2
        assert time_taken >= 60
        logger().info(f"time taken to connect is: {time_taken}")

        logger().info("Validating Unicast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find Unicast Probe request packet in sniffer'
        logger().info("Validating Broadcast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
            'packet_count'], 'Unable to find Broadcast Probe request packet in sniffer'
        logger().info(" Validate authentication and association keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
            'packet_count'], 'Unable to find authentication and association in sniffer '
        logger().info(" Validating the power management bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(" Validating the EAPOL keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6, packet_filter2)[
            'packet_count'], 'Unable to find eapol keys in sniffer'
        logger().info(" Validating auth key in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7, packet_filter2)[
            'packet_count'], 'Unable to find auth key in sniffer'

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"passphrase": 'test123@random'})
# The test case checks whether the DUT connection works fine on giving the random passphrase
def test_Joining_by_rsi_psk_command_C19714(wifi_dut, wifi_access_point, wifi_sniffer):
        validation = True
        packet_filter2 = False

        logger().info(" ====== configuring the sniffer with access point channel ======")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Joining_by_rsi_psk_command_C19714')

        # Scan for the AP's
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        # This API connects STA to the third party AP
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # This API Enables the wifi power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating Unicast Probe request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid}'

        # Validating Broadcast Probe request
        packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

        # Validating the power management bit
        packet_filter5 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

        # Validate  authentication ,association
        packet_filter4 = f'(wlan.tag.number == 45 ) && (wlan.fc.type_subtype == 0x0000)'

        # Validate EAPOL keys
        packet_filter6 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                         f'wlan.da == {dut_mac_address} and eapol'

        # Validate dhcp
        packet_filter7 = f'wlan.addr == {dut_mac_address} && (wlan.fc.type_subtype == 0x000b)'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Unicast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find Unicast Probe request packet in sniffer'
        logger().info("Validating Broadcast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
            'packet_count'], 'Unable to find Broadcast Probe request packet in sniffer'
        logger().info(" Validate authentication and association keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
            'packet_count'], 'Unable to find  authentication and association in sniffer '
        logger().info(" Validating the power management bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(" Validating the EAPOL keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6, packet_filter2)[
            'packet_count'], 'Unable to find eapol keys in sniffer'
        logger().info(" Validating auth key in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7, packet_filter2)[
            'packet_count'], 'Unable to find auth key in sniffer'

@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
# The test case checks whether the DUT connection Time on the joining the AP with pmk
def test_Join_providing_PMK_C19715(wifi_dut, wifi_access_point, wifi_sniffer):
        validation = True
        packet_filter2 = False

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Join_providing_PMK_C19715')

        # Scan for the AP's
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        # This API connects STA to the third party AP with the pmk generated
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,
                                          wifi_access_point.interfaces.wifi.passphrase)

        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # This API Enables the wifi power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating Unicast Probe request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid}'

        # Validating Broadcast Probe request
        packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

        # Validating the power management bit
        packet_filter5 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

        # Validate authentication ,association
        packet_filter4 = f'(wlan.tag.number == 45 ) && (wlan.fc.type_subtype == 0x0000)'

        # Validate EAPOL keys
        packet_filter6 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                         f'wlan.da == {dut_mac_address} and eapol'

        # Validate dhcp
        packet_filter7 = f'wlan.addr == {dut_mac_address} && (wlan.fc.type_subtype == 0x000b)'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Unicast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find Unicast Probe request packet in sniffer'
        logger().info("Validating Broadcast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
            'packet_count'], 'Unable to find Broadcast Probe request packet in sniffer'
        logger().info(" Validate  authentication and association keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
            'packet_count'], 'Unable to find authentication and association in sniffer '
        logger().info(" Validating the power management bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(" Validating the EAPOL keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6, packet_filter2)[
            'packet_count'], 'Unable to find eapol keys in sniffer'
        logger().info(" Validating auth key in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7, packet_filter2)[
            'packet_count'], 'Unable to find auth key in sniffer'

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "pmkwithwrongpsk", "passphrase": 'thisisatestnetwork', "security": 'WPA2'})
# The test case checks whether the DUT connection fails with the wrong psk
def test_Joining_to_PMK_in_module_by_wrong_PSK_C19716(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        packet_filter2 = False

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Joining_to_PMK_in_module_by_wrong_PSK_C19716')

        # Scan for the AP's
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        with pytest.raises(WlanError) as exc_info:
            # This API connects STA to the third party AP with the pmk generated
            wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid, "12345678")
        assert exc_info.value.error_code == 0x0008
        logger().info(f"Dut Tried to connect to ap with wrong password, observed error code 0x0008 which is expected")

        # Validating Unicast Probe request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid}'

        # Validating Broadcast Probe request
        packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

        # Validate de-auth packet
        packet_filter4 = f'(wlan.fc.type_subtype == 12)'

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Unicast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find Unicast Probe request packet in sniffer'
        logger().info("Validating Broadcast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
            'packet_count'], 'Unable to find Broadcast Probe request packet in sniffer'
        logger().info(" Validate de-auth packet in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
            'packet_count'], 'Unable to find deauth packet'

    logger().info(f"test executed in {t.duration} seconds")

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testwithnossid", "passphrase": 'Testing_pmk', "security": "WPA2"})
# The test case checks whether the DUT connection fails with empty ssid in pmk
def test_wifi_join_PMK_without_SSID_C19717(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        with pytest.raises(WlanError) as exc_info:
            # This API connects STA to the third party AP with the pmk generated
            wifi_dut.interfaces.wifi.join_pmk("\"\"", wifi_access_point.interfaces.wifi.passphrase)
            assert exc_info.value.error_code == 0x0003
            logger().info(f"Dut Tried to connect to ap with wrong password, observed error code 0x0003 which is expected")
    logger().info(f"test executed in {t.duration} seconds")

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "redpine", "passphrase": 'Testing_pmk', "security": "WPA2"})
# The test case checks whether the DUT connection fails with space before the redpine ssid in pmk
def test_wifi_join_pmk_with_space_before_redpine_ssid_C19718(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        packet_filter2 = False

        logger().info(" ============== THIS TEST CASE SUPPORTS ONLY WITH ASUS AP ============== ")
        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_join_pmk_with_space_before_redpine_ssid_C19718')

        # Scan for the AP's
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        ssid = " redpine"

        # This API connects STA to the third party AP with the pmk generated
        wifi_dut.interfaces.wifi.join_pmk(ssid, "thisisatestnetwork")

        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # This API Enables the wifi power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating Unicast Probe request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid}'

        # Validating Broadcast Probe request
        packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

        # Validating the power management bit
        packet_filter5 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

        # Validate authentication ,association
        packet_filter4 = f'(wlan.tag.number == 45 ) && (wlan.fc.type_subtype == 0x0000)'

        # Validate EAPOL keys
        packet_filter6 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.da == {dut_mac_address} and eapol'

        # Validate auth key
        packet_filter7 = f'wlan.addr == {dut_mac_address} && (wlan.fc.type_subtype == 0x000b)'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Unicast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find Unicast Probe request packet in sniffer'
        logger().info("Validating Broadcast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
            'packet_count'], 'Unable to find Broadcast Probe request packet in sniffer'
        logger().info(" Validate authentication and association keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
            'packet_count'], 'Unable to find  authentication and association in sniffer '
        logger().info(" Validating the power management bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(" Validating the EAPOL keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6, packet_filter2)[
            'packet_count'], 'Unable to find eapol keys in sniffer'
        logger().info(" Validating auth key in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7, packet_filter2)[
            'packet_count'], 'Unable to find auth key in sniffer'

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi=
{"ssid": "Testssid", "passphrase": "1234567890qwertyuioplkjhgfdsazxcvbnmkloirgrgrtyuio1234567890o", "security": "WPA2"}
                    )
# The test case checks whether the DUT connection works with 64 characters of passphrase in pmk
def test_psk_with_64_different_characters_C19719(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        packet_filter2 = False

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_psk_with_64_different_characters_C19719')

        # Scan for the AP's
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        # This API connects STA to the third party AP
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # This API Enables the wifi power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating Unicast Probe request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid}'

        # Validating Broadcast Probe request
        packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

        # Validating the power management bit
        packet_filter5 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

        # Validate authentication ,association
        packet_filter4 = f'(wlan.tag.number == 45 ) && (wlan.fc.type_subtype == 0x0000)'

        # Validate EAPOL keys
        packet_filter6 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                         f'wlan.da == {dut_mac_address} and eapol'

        # Validate auth key
        packet_filter7 = f'wlan.addr == {dut_mac_address} && (wlan.fc.type_subtype == 0x000b)'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Unicast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find Unicast Probe request packet in sniffer'
        logger().info("Validating Broadcast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
            'packet_count'], 'Unable to find Broadcast Probe request packet in sniffer'
        logger().info(" Validate  authentication and association keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
            'packet_count'], 'Unable to find authentication and association in sniffer '
        logger().info(" Validating the power management bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(" Validating the EAPOL keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6, packet_filter2)[
            'packet_count'], 'Unable to find eapol keys in sniffer'
        logger().info(" Validating auth key in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7, packet_filter2)[
            'packet_count'], 'Unable to find auth key in sniffer'
    logger().info(f"Associated and ping in {t.duration} seconds")

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                                               "passphrase": "123456789qwertyuio123456789qwertyuio123456789zxcvbnm123456789zx",
                                               "security": "WPA2"})
# The test case checks whether the DUT connection works with 64 bytes of passphrase and 32 bytes of ssid in pmk
def test_join_pmk_with_64_characters_psk_32_characters_ssid_C19720(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        packet_filter2 = False

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_join_pmk_with_64_characters_psk_32_characters_ssid_C19720')

        # Scan for the AP's
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        # This API connects STA to the third party AP with the pmk generated
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,wifi_access_point.interfaces.wifi.passphrase)

        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # This API Enables the wifi power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating Unicast Probe request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid}'

        # Validating Broadcast Probe request
        packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

        # Validating the power management bit
        packet_filter5 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

        # Validate authentication ,association
        packet_filter4 = f'(wlan.tag.number == 45 ) && (wlan.fc.type_subtype == 0x0000)'

        # Validate EAPOL keys
        packet_filter6 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                         f'wlan.da == {dut_mac_address} and eapol'

        # Validate dhcp
        packet_filter7 = f'wlan.addr == {dut_mac_address} && (wlan.fc.type_subtype == 0x000b)'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Unicast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find Unicast Probe request packet in sniffer'
        logger().info("Validating Broadcast Probe request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
            'packet_count'], 'Unable to find Broadcast Probe request packet in sniffer'
        logger().info(" Validate authentication and association keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
            'packet_count'], 'Unable to find authentication and association in sniffer '
        logger().info(" Validating the power management bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(" Validating the EAPOL keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6, packet_filter2)[
            'packet_count'], 'Unable to find eapol keys in sniffer'
        logger().info(" Validating auth key in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7, packet_filter2)[
            'packet_count'], 'Unable to find auth key in sniffer'
    logger().info(f"Associated and ping in {t.duration} seconds")

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'testing', "security": 'WPA2', "channel": 7})
# The test case checks whether the DUT connection and disconnection  to AP for 30 iterations
def test_Init_Scan_Join_Disconnect_30min_C19710(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        for iteration in range(0, 30):
            validation = True
            packet_filter2 = False

            logger().info(" ====== configuring the sniffer with the access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Init_Scan_Join_Disconnect_30min_C19710')

            # Scan for the AP's
            ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')

            # This API connects STA to the third party AP
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

            # This API Enables the DHCP in DUT
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

            # This API Enables the wifi power save mode in DUT
            wifi_dut.interfaces.wifi.power_save(2)

            # This API Enables the bt power save mode in DUT
            wifi_dut.interfaces.wifi.bt_power_save(2)

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating Unicast Probe request
            packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid}'

            # Validating Broadcast Probe request
            packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

            # Validating the power management bit
            packet_filter5 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

            # Validate connection and association
            packet_filter4 = f'(wlan.tag.number == 45 ) && (wlan.fc.type_subtype == 0x0000)'

            # Validate EAPOL keys
            packet_filter6 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                             f'wlan.da == {dut_mac_address} and eapol'

            # Validate auth key
            packet_filter7 = f'wlan.addr == {dut_mac_address} && (wlan.fc.type_subtype == 0x000b)'

            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, 10)
            assert status == 1

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validating Unicast Probe request")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
                'packet_count'], 'Unable to find Unicast Probe request packet in sniffer'
            logger().info("Validating Broadcast Probe request")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
                'packet_count'], 'Unable to find Broadcast Probe request packet in sniffer'
            logger().info(" Validate authentication and association keys")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
                'packet_count'], 'Unable to find authentication and association in sniffer '
            logger().info(" Validating the power management bit")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
                'packet_count'], 'Unable to find power management bit in sniffer'
            logger().info(" Validating the EAPOL keys")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6, packet_filter2)[
                'packet_count'], 'Unable to find eapol keys in sniffer'
            logger().info(" Validating auth key in sniffer")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7, packet_filter2)[
                'packet_count'], 'Unable to find auth key in sniffer'
    logger().info(f"Associated and ping in {t.duration} seconds")