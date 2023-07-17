import pytest
import time
import re
from datetime import datetime, date
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes
from utf import UtfDatabaseProperties

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

    Author: Ayush Agarwal
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
            for x in line:
                count = count + 1
                if packet_filter1 in x:
                    result = re.search(r'\d+:\d+:\d+.\d+', x)
                    logger().info(f" RESULT {result}")
                    time_stamp = result.group()
                    logger().info(f'time_stamp={time_stamp}')
                    time_diff_list.append(time_stamp)

        filter_file.close()
        return time_diff_list

# configure ping_count to ping dut
ping_count = 10

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        }
    )
]


@pytest.mark.config('wifi_access_point', wifi={"ssid": "testingpmk", "passphrase": 'Testing_pmk', "security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_Joining_time_PMK_C19711(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
        validation = True
        packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
        time_obj = FilterPacket()
        wifi_dut.interfaces.wifi.associated = False

        ping_count = utf_constants.get("ping_count")

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_sdk_Joining_time_PMK_C19711')

        logger().info("scan for the ap's.....")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("connecting to access point with pmk.....")
        wifi_dut.interfaces.wifi.get_pairwise_master_key(wifi_access_point.interfaces.wifi.ssid,
                                                         wifi_access_point.interfaces.wifi.passphrase)

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=True, associated=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC : {ap_mac}")

        time.sleep(10)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)

        # Validate the eapol 4 key
        packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                         f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_mac})'

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
        assert time_taken <= 0.4
        logger().info(f"time taken to connect is: {time_taken}")


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_Join_providing_PMK_C19715(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):

        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_sdk_Join_providing_PMK_C19715')

        logger().info("scan for the ap's.....")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.get_pairwise_master_key(wifi_access_point.interfaces.wifi.ssid,
                                                         wifi_access_point.interfaces.wifi.passphrase)

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=True, associated=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC : {ap_mac}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)


@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "pmkwithwrongpsk", "passphrase": 'thisisatestnetwork', "security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_Joining_to_PMK_in_module_by_wrong_PSK_C19716(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        wifi_dut.interfaces.wifi.associated = False

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_sdk_Joining_to_PMK_in_module_by_wrong_PSK_C19716')

        logger().info("scan for the ap's.....")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)

        with pytest.raises(WlanError) as exc_info:
            logger().info("connecting to access point with wrong psk.....")
            wifi_dut.interfaces.wifi.get_pairwise_master_key(wifi_access_point.interfaces.wifi.ssid, "12345678")
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_wifi_join_PMK_without_SSID_C19717(wifi_dut, wifi_access_point):
    wifi_dut.interfaces.wifi.associated = False
    with TimeMeasurer() as t:
        with pytest.raises(WlanError) as exc_info:
            # This API connects STA to the third party AP with the pmk generated
            wifi_dut.interfaces.wifi.get_pairwise_master_key("\"\"", wifi_access_point.interfaces.wifi.passphrase)
            assert exc_info.value.error_code == 0x0003
            logger().info(f"Dut Tried to connect to ap with wrong password, observed error code 0x0003 which is expected")
    logger().info(f"test executed in {t.duration} seconds")


@pytest.mark.skip()
@pytest.mark.config('wifi_access_point', wifi={"ssid": " redpine", "passphrase": 'Testing_pmk', "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_wifi_join_pmk_with_space_before_redpine_ssid_C19718(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper,
                                                             utf_constants):
        validation = True
        wifi_dut.interfaces.wifi.associated = False

        logger().info(" ============== THIS TEST CASE SUPPORTS ONLY WITH ASUS AP ============== ")
        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_sdk_wifi_join_pmk_with_space_before_redpine_ssid_C19718')

        logger().info("scan for the ap's.....")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)

        ssid = " redpine"
        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.get_pairwise_master_key(ssid, "thisisatestnetwork")

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=True, associated=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC : {ap_mac}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)


@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                          "passphrase": "123456789qwertyuio123456789qwertyuio123456789zxcvbnm123456789zx",
                          "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_join_pmk_with_64_characters_psk_32_characters_ssid_C19720(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper,
                                                                    utf_constants):
    with TimeMeasurer() as t:
        validation = True
        wifi_dut.interfaces.wifi.associated = False

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_sdk_join_pmk_with_64_characters_psk_32_characters_ssid_C19720')

        logger().info("scan for the ap's.....")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.get_pairwise_master_key(wifi_access_point.interfaces.wifi.ssid,
                                          wifi_access_point.interfaces.wifi.passphrase)

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=True, associated=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC : {ap_mac}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)

    logger().info(f"Associated and ping in {t.duration} seconds")
