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

# configure ping_count to ping dut
ping_count = 10


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                      test_case_name='test_Connectivity_with_11n_only_mode_AP_C19707',
                                                      test_case_id='C19707',
                                                      notes='test notes'))
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Connectivity_with_11n_only_mode_AP_C19707(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):

    validation = True

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Connectivity_with_11n_only_mode_AP_C19707')

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC : {ap_mac}")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)



pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_Connectivity_with_hidden_mode_AP_C19708',
                                                       test_case_id='C19708',
                                                       notes='test notes'))
@pytest.mark.config('wifi_access_point', wifi={"ssid": "TEST-ASUS-hidden","broadcast_ssid": False})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Connectivity_with_hidden_mode_AP_C19708(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
        validation = True

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Connectivity_with_hidden_mode_AP_C19708')

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC : {ap_mac}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)

        # Validate hidden mode
        packet_filter4 = f'(wlan.ssid == "") and (wlan.fc.type_subtype == 0x0008 and (wlan.sa == {ap_mac}) )'

        logger().info(" Validate hidden ssid, authentication and association keys")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find hidden in sniffer '


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_Joining_time_PMK_C19711',
                                                       test_case_id='C19711',
                                                       notes='test notes'))
@pytest.mark.config('wifi_access_point', wifi={"ssid": "testingpmk", "passphrase": 'Testing_pmk', "security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Joining_time_PMK_C19711(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
        validation = True
        packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
        time_obj = FilterPacket()
        wifi_dut.interfaces.wifi.associated = False

        ping_count = utf_constants.get("ping_count")

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Joining_time_PMK_C19711')

        logger().info("scan for the ap's.....")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("connecting to access point with pmk.....")
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,
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


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_Join_time_providing_PSK_C19712',
                                                       test_case_id='C19712',
                                                       notes='test notes'))
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Join_time_providing_PSK_C19712(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
        validation = True
        packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
        time_obj = FilterPacket()

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Join_time_providing_PSK_C19712')

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC : {ap_mac}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validate the eapol 4 key
        packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                         f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {wifi_access_point.interfaces.wifi.bssid})'

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


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_Joining_by_rsi_psk_command_C19714',
                                                       test_case_id='C19714',
                                                       notes='test notes'))
@pytest.mark.config('wifi_access_point', wifi={"passphrase": 'test123@random'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Joining_by_rsi_psk_command_C19714(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
        validation = True

        logger().info(" ====== configuring the sniffer with access point channel ======")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Joining_by_rsi_psk_command_C19714')

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC : {ap_mac}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_Join_providing_PMK_C19715',
                                                       test_case_id='C19715',
                                                       notes='test notes'))
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Join_providing_PMK_C19715(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):

        validation = True
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Join_providing_PMK_C19715')

        logger().info("scan for the ap's.....")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,
                                          wifi_access_point.interfaces.wifi.passphrase)

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=True, associated=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC : {ap_mac}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_Joining_to_PMK_in_module_by_wrong_PSK_C19716',
                                                       test_case_id='C19716',
                                                       notes='test notes'))
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "pmkwithwrongpsk", "passphrase": 'thisisatestnetwork', "security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Joining_to_PMK_in_module_by_wrong_PSK_C19716(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        wifi_dut.interfaces.wifi.associated = False

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Joining_to_PMK_in_module_by_wrong_PSK_C19716')

        logger().info("scan for the ap's.....")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)

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


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_wifi_join_PMK_without_SSID_C19717',
                                                       test_case_id='C19717',
                                                       notes='test notes'))
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testwithnossid", "passphrase": 'Testing_pmk', "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_join_PMK_without_SSID_C19717(wifi_dut, wifi_access_point):
    wifi_dut.interfaces.wifi.associated = False
    with TimeMeasurer() as t:
        with pytest.raises(WlanError) as exc_info:
            # This API connects STA to the third party AP with the pmk generated
            wifi_dut.interfaces.wifi.join_pmk("\"\"", wifi_access_point.interfaces.wifi.passphrase)
            assert exc_info.value.error_code == 0x0003
            logger().info(f"Dut Tried to connect to ap with wrong password, observed error code 0x0003 which is expected")
    logger().info(f"test executed in {t.duration} seconds")


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_wifi_join_pmk_with_space_before_redpine_ssid_C19718',
                                                       test_case_id='C19718',
                                                       notes='test notes'))
@pytest.mark.skip()
@pytest.mark.config('wifi_access_point', wifi={"ssid": " redpine", "passphrase": 'Testing_pmk', "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_join_pmk_with_space_before_redpine_ssid_C19718(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper,
                                                             utf_constants):
        validation = True
        wifi_dut.interfaces.wifi.associated = False

        logger().info(" ============== THIS TEST CASE SUPPORTS ONLY WITH ASUS AP ============== ")
        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_join_pmk_with_space_before_redpine_ssid_C19718')

        logger().info("scan for the ap's.....")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)

        ssid = " redpine"
        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_pmk(ssid, "thisisatestnetwork")

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=True, associated=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC : {ap_mac}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_psk_with_64_different_characters_C19719',
                                                       test_case_id='C19719',
                                                       notes='test notes'))
@pytest.mark.config('wifi_access_point', wifi=
{"ssid": "Testssid", "passphrase": "1234567890qwertyuioplkjhgfdsazxcvbnmkloirgrgrtyuio1234567890o", "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_psk_with_64_different_characters_C19719(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
        validation = True

        wifi_dut.interfaces.wifi.associated = False

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_psk_with_64_different_characters_C19719')

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC : {ap_mac}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_join_pmk_with_64_characters_psk_32_characters_ssid_C19720',
                                                       test_case_id='C19720',
                                                       notes='test notes'))
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                                               "passphrase": "123456789qwertyuio123456789qwertyuio123456789zxcvbnm123456789zx",
                                               "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_pmk_with_64_characters_psk_32_characters_ssid_C19720(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper,
                                                                    utf_constants):
    with TimeMeasurer() as t:
        validation = True
        wifi_dut.interfaces.wifi.associated = False

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_join_pmk_with_64_characters_psk_32_characters_ssid_C19720')

        logger().info("scan for the ap's.....")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,
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


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_Init_Scan_Join_Disconnect_30min_C19710',
                                                       test_case_id='C19710',
                                                       notes='test notes'))
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'testing', "security": 'WPA2', "channel": 7})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Init_Scan_Join_Disconnect_30min_C19710(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
    with TimeMeasurer() as t:
        t_end = time.time() + 60 * 30
        while time.time() < t_end:
            validation = True
            logger().info(" ====== configuring the sniffer with the access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Init_Scan_Join_Disconnect_30min_C19710')

            wifi_dut.interfaces.wifi.associated = False

            device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
            logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

            ap_mac = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP MAC : {ap_mac}")

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)

            logger().info("disconnecting to ap.....")
            wifi_dut.interfaces.wifi.leave()
            time.sleep(5)

    logger().info(f"Associated and ping in {t.duration} seconds")
