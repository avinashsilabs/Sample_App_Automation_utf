import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Points (Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Initiate the Scan from DUT
        3. Verify the scan results

    Author: Aravind
"""

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            }
)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
             'ssid': 'Codecom123',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 1
        },
        1: {
             'ssid': 'Codecom123',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 1
        }
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_same_2aps_same_security_c19065(wifi_dut, wifi_access_points):
    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    # enables the rejoin in dut
    logger().info(" Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin()
    logger().info(" scan initiated...")
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    time.sleep(20)
    logger().info(scan_results)
    scan_list = list(scan_results)
    ssid_count = 0
    logger().info(f"scan_list : {scan_list}")
    logger().info("Validating the scan list...")
    for item in scan_list:
        ssid = str(item).split(" ")[9]
        if (ssid == wifi_access_points[0].interfaces.wifi.ssid) or (ssid == wifi_access_points[1].interfaces.wifi.ssid):
           ssid_count = ssid_count + 1
    logger().info(f"ssid count:{ssid_count}")
    assert ssid_count == 2, "Two aps are not scanned "
    logger().info(f'2 Aps with same ssid: {wifi_access_points[0].interfaces.wifi.ssid} are scanned successfully')

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
             'ssid': 'TESTTESTTEST2',
             'security': 'WPA2',
             'passphrase': '123123123',
              'channel': 11,
              'region': 'US'

        },
        1: {
             'ssid': 'TESTTESTTEST2',
             'security': 'WPA',
             'passphrase': '123123123',
             'channel': 1,
             'region': 'US'
        }
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_same_2aps_diff_security_c19066(wifi_dut, wifi_access_points):
    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    # enables the rejoin in dut
    logger().info(" Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin()
    logger().info(" scan initiated...")
    time.sleep(20)
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)
    scan_list = list(scan_results)

    ssid_count = 0
    logger().info(f"scan_list : {scan_list}")
    logger().info("Validating the scan list...")
    for item in scan_list:
        security = str(item).split(" ")[3]
        ssid = str(item).split(" ")[9]
        if (ssid == wifi_access_points[0].interfaces.wifi.ssid) or (ssid == wifi_access_points[1].interfaces.wifi.ssid):
            ssid_count = ssid_count + 1
    logger().info(f"ssid count:{ssid_count}")
    assert ssid_count == 2, "Two aps are not scanned "
    logger().info(f'2 aps with same ssid :{wifi_access_points[1].interfaces.wifi.ssid}and different password :WPA2 and '
                  f'WPA scanned successfully')

#####19069###
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'TESTTESTTEST2',
        'security': 'WPA2',
        'passphrase': '123123123',
        'region': 'Europe'
    }
)
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 0,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_and_connect_in_EU_domain_c19069(wifi_dut, wifi_access_point, wifi_sniffer):
    validation = True
    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    # enables the rejoin in dut
    logger().info(" Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin()
    channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    # channel_list = [2]
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    logger().info(" ***** Configuring DUT in world domain region ***** ")
    # wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    for channel in channel_list:
        logger().info("Starting access point with custom channel...")
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)
        logger().info("Initiating scan...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_scan_and_connect_in_EU_domain_c19069')
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        logger().info(scan_results)
        time.sleep(30)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter8 = f'(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address}' \
                         f'  and wlan.da == ff:ff:ff:ff:ff:ff)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter8)[
            'packet_count'], 'Unable to find Probe req packet  in sniffer'
        logger().info(f'probe request is success in channel : {channel}')

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
             'ssid': 'EU_TEST',
             'security': 'WPA2',
             'passphrase': '123123123',
              'channel': 13,
              'region': 'Europe'

        },
        1: {
             'ssid': 'TESTTESTTEST2',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 6,
             'region': 'US'
        }
    }
)
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 0,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_and_connect_in_world_domain_c19075(wifi_dut, wifi_access_points, wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info(" Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        validation = True
        channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        logger().info(" ***** Configuring DUT in world domain region ***** ")
        # wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_points[0].interfaces.wifi.start_ap(channel=channel)
            logger().info("Initiating scan...")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_scan_and_connect_in_world_domain_c19075')
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
            logger().info(scan_results)
            time.sleep(20)
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter8 = f'(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address}' \
                             f'  and wlan.da == ff:ff:ff:ff:ff:ff)'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter8)[
                'packet_count'], 'Unable to find Probe req packet  in sniffer'
            logger().info(f'probe response is success in channel : {channel}')

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_scan_and_connect_in_world_domain_c19075')

        ap_mac = wifi_dut.interfaces.wifi.scan(channel=6, ssid=wifi_access_points[1].interfaces.wifi.ssid)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        # This API connects STA to the third party AP
        wifi_dut.interfaces.wifi.join_ap(wifi_access_points[1])

        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"

        # This API Enables the wifi power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Validating Association response
        packet_filter3 = f'wlan.fc.type_subtype == 0 or wlan.fc.type_subtype == 1 or eapol'

        # Validating Qos null data packets with power managment set to 1
        packet_filter5 = f' wlan.addr == {dut_mac_address} or wlan.fc.type_subtype == 0x0024'

        # validating ps poll with power managment bit set to 1
        packet_filter6 = f'wlan.addr == {dut_mac_address} or wlan.fc.type_subtype == 0x001a'

        time.sleep(20)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req")

        logger().info("validating Association response")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find Association response packet  in sniffer'

        logger().info("validating qos null data packets with power management bit set  packets ")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find Qos null data packets with power management set to 1  in sniffer'

        logger().info("validating ps-poll packets with power management bit set  packets ")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
            'packet_count'], 'Unable to find ps poll with power management bit set to 1 packet  in sniffer'

    logger().info(f"Associated and ping in {t.duration} seconds")


###################19078#####################
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
)
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 0,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 6, "standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_and_connect_in_world_domain_c19078(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info(" Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()

        validation = True

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_scan_and_connect_in_world_domain_c19078')

        # logger().info(" ***** Configuring DUT in world domain region ***** ")
        # wifi_dut.interfaces.wifi.set_region(region=1, region_code=4, module_type=1)

        logger().info("DUT initiated broadcast probe equest ")
        scan_result = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)

        logger().info(f'scan_result is  :{scan_result}')
        # Scan for the AP's
        logger().info("DUT initiated unicast probe request to fetch ap mac")
        time.sleep(10)
        ap_mac = wifi_dut.interfaces.wifi.scan(channel=6, ssid=wifi_access_point.interfaces.wifi.ssid)
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

        status = ping(device_ip, 10)
        assert status == 1

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        #Validate probe request
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) and wlan.sa == {dut_mac_address} and ' \
                         f'(wlan.da == ff:ff:ff:ff:ff:ff)'
        #Validating Association response
        packet_filter3 = f'wlan.fc.type_subtype == 0 or wlan.fc.type_subtype == 1 or eapol'

        #Validating Qos null data packets with power managment set to 1
        packet_filter5 = f' wlan.addr == {dut_mac_address} or wlan.fc.type_subtype == 0x0024'

        #validating ps poll with power managment bit set to 1
        packet_filter6 = f'wlan.addr == {dut_mac_address} or wlan.fc.type_subtype == 0x001a'

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
             'packet_count'], 'Unable to find Probe req packet  in sniffer'

        logger().info("validating Association response")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
             'packet_count'], 'Unable to find Association response packet  in sniffer'

        logger().info("validating qos null data packets with power managment bit set  packets ")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
             'packet_count'], 'Unable to find Qos null data packets with power management set to 1  in sniffer'

        logger().info("validating ps-poll packets with power managment bit set  packets ")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
             'packet_count'], 'Unable to find ps poll with power management bit set to 1 packet  in sniffer'

    logger().info(f"Associated and ping in {t.duration} seconds")



