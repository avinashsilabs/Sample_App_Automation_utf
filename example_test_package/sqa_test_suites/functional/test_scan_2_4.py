import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import RS9116PowerSaveModes

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
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiate the Scan from DUT
        4. Verify the scan results

    Author: RaviNemali
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
# This test case verifies All Channels Scan in 2.4 Ghz by giving channel number as Zero
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_scan_c19056(wifi_sniffer, wifi_dut, wifi_access_point):
    testcase = "test_scan_c19056"
    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    channels_list_2g = [1,2,3,4,5,6,7,8,9,10,11]
    validation = True

    # Fetches the DUT mac address
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

    for channel in channels_list_2g:

        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_ch_{channel}")

        time.sleep(2)

        for i in range(0,3):
            # enables the scan in dut on channel 0
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            assert (len(scan_results) >= 1),"Scan failed"
            logger().info(scan_results)
            time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], f'Unable to find Probe req(Broadcast) in channel:{channel}'
        logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
        logger().info("DUT scan successfully in all channels")


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
# This test case verifies the scan Response Based on RSSI
def test_scan_check_rssi_c19060(wifi_dut, wifi_access_point):
    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    # enables the scan in dut on channel 0
    logger().info("Initiating scan from DUT...")
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)
    scan_count = len(scan_results)
    assert scan_count > 0,"Scan results not found"
    previous_rssi = 0
    for count in scan_results:
        assert previous_rssi >= count.rssi, "scan result is not based on the rssi"
        previous_rssi = count.rssi
        logger().info("scan results are based on rssi")

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
def test_scan_ssid_32bytes_c19064(wifi_sniffer, wifi_dut, wifi_access_point):
    testcase = "test_scan_ssid_32bytes_c19064"
    validation = True
    # Fetches the DUT mac address
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

    logger().info(f"configuring the Sniffer with the channel : {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    time.sleep(5)

    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    ssid_list = ['test123test123test123test123test', 'test1*@test1*#test1*@test1*$test', 'test12.test12.test12.test12.test',\
                 '了是不了是不了是不了']

    for ssid in ssid_list:

        # initiates the access point with channel given in list
        logger().info(f"Setting access point with ssid {ssid}...")
        wifi_access_point.interfaces.wifi.start_ap(ssid=ssid)
        time.sleep(10)
        logger().info(f"Initiating the scan from DUT with ssid {ssid}..")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=ssid)
        logger().info(scan_results)
        assert len(scan_results) >= 1, f"32 bytes ssid not found in scan results"
    logger().info(f"Validate Probe req(Broadcast)")
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], f'Unable to find Probe req(Broadcast) in channel:{wifi_access_point.interfaces.wifi.channel}'
    logger().info(f"found Probe req(Broadcast) in channel:{wifi_access_point.interfaces.wifi.channel}'")


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
def test_scan_selective_channel_c19058(wifi_sniffer, wifi_dut, wifi_access_point):
    testcase = "test_scan_selective_channel_c19058"
    validation = True
    # Fetches the DUT mac address
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    channel_list = [1, 6, 8]
    channel_bitmap_2_4 = 0
    scan_expected_time = 0
    for count in channel_list:
        channel_bitmap_2_4 += 1 << (count - 1)
        scan_expected_time += 100

    channel_bitmap_5 = 0
    scan_feature_extend = 0
    for channel in channel_list:

        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_ch_{channel}")

        # initiates the access point with channel given in list
        logger().info("Setting access point with custom channel...")
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)

        time.sleep(5)

        for i in range(0,3):
            # enables the scan in DUT with the given channel bitmap value
            logger().info("Initiating selective channel scan in DUT...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=channel_bitmap_2_4,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            time.sleep(5)
            logger().info(scan_results)
            assert len(scan_results) >= 1,"scan results not found"
            for count in scan_results:
                assert (count.rf_channel in channel_list),f"Scan should happen only in selected channels"



        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], f'Unable to find Probe req(Broadcast) in channel:{channel}'
        logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
    logger().info("DUT scan successfully in selected channels")


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
# Verifies the scan functionality with the channel 1,3,6,11
def test_scan_selective_channel_c19059(wifi_sniffer, wifi_dut, wifi_access_point):

    testcase = "test_scan_selective_channel_c19059"
    validation = True

    # Fetches the DUT mac address
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    channel_list = [1, 3, 6, 11]
    channel_bitmap_2_4 = 0
    scan_expected_time = 0
    for count in channel_list:
        channel_bitmap_2_4 += 1 << (count - 1)
        scan_expected_time += 100

    channel_bitmap_5 = 0
    scan_feature_extend = 0
    for channel in channel_list:

        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_ch_{channel}")

        # initiates the access point with channel given in list
        logger().info("Starting access point with custom channel...")
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)

        time.sleep(5)

        for i in range(0,2):

            # enables the scan in DUT with the given channel bitmap value
            logger().info("Initiating the selective channel scan in dut...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=channel_bitmap_2_4,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            time.sleep(5)

            logger().info(scan_results)
            assert len(scan_results) >= 1,"Scan results not found"
            for count in scan_results:
                assert (count.rf_channel in channel_list), "Scan should happen only in selected channels"



        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], f'Unable to find Probe req(Broadcast) in channel:{channel}'
        logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
    logger().info("DUT scan successfully in all channels")


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
# This test case verifies the scan functionality for channles 1-11
def test_scan_selective_channel_c19057(wifi_sniffer, wifi_dut, wifi_access_point):

        testcase = "test_scan_selective_channel_c19057"
        validation = True

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

        # Enables the wifi power save in DUT
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

        # Enables the bt power save in DUT
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

            channel_bitmap_5 = 0
            scan_feature_extend = 0

        for channel in channel_list:

            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_ch_{channel}")

            # initiates the access point with channel given in list
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(5)

            for i in range(0,2):

                # enables the scan in DUT with the given channel bitmap value
                logger().info("Initiating selective channel scan from dut...")
                scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                               scan_bitmap_2_4=channel_bitmap_2_4,
                                                                               scan_bitmap_5=channel_bitmap_5,
                                                                               scan_feature=scan_feature_extend)
                time.sleep(10)
                logger().info(scan_results)
                assert len(scan_results) >= 1,"Scan results not found"
                channel_selected = 0
                for count in scan_results:
                    assert (count.rf_channel in channel_list), "Scan should happen only in selected channels"


            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info(f"Validate Probe req(Broadcast)")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], f'Unable to find Probe req(Broadcast) in channel:{channel}'
            logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
        logger().info("DUT scans successfully in selected channels")


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 0,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# Verifies the scan functionality in us region
def test_scan_us_region_2_4_c19067(wifi_sniffer, wifi_dut, wifi_access_point):

    logger().info("Configured DUT in US region")

    testcase = "test_scan_us_region_2_4_c19067"
    channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    validation = True

    # Fetches the DUT mac address
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

    for channel in channels_list_2g:
        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_ch_{channel}")

        for i in range(0,2):
            # enables the scan in dut on channel 0
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(10)
            assert (len(scan_results) >= 1),"scan failed"
            logger().info(scan_results)

        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], f'Unable to find Probe req(Broadcast) in channel:{channel}'
        logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
        logger().info("DUT scan successfull in all channels in US region")


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
# This test case verifies the scan functionality with max scan of dut
def test_scan_max_aps_c19061(wifi_dut, wifi_access_point):
    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # enables the rejoin in dut
    logger().info(" Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin()
    channel = 0
    channel_bitmap_2_4 = 0
    scan_feature_extend = 0

    # enables the scan in DUT with the given channel bitmap value
    logger().info("Initiating the selective channel scan ...")
    scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=channel,ssid=None,scan_bitmap_2_4=channel_bitmap_2_4,scan_feature=scan_feature_extend)
    logger().info(scan_results)
    assert len(scan_results) <= 11,"Dut should scan max upto 11 APs only"

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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',wifi ={"ssid": 'test_ssid', "broadcast_ssid": False})
# This case verifies the scan in hidden mode of AP for all channels
def test_hidden_scan_all_channels_c19062(wifi_sniffer,wifi_dut,wifi_access_point):

    testcase = "test_hidden_scan_all_channels_c19062"

    validation = True

    # Fetches the DUT mac address
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

    logger().info(f"configuring the Sniffer with the channel : {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the rejoin feature on DUT
    logger().info("Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin()

    for i in range(0,3):
        # enables the scan in DUT with the given channel bitmap value
        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0,ssid=wifi_access_point.interfaces.wifi.ssid)
        logger().info(scan_results)
        time.sleep(10)
        assert len(scan_results) >= 1,"scan failed"
        for count in scan_results:
                assert count.ssid == wifi_access_point.interfaces.wifi.ssid
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info(f"Validate Probe req(Broadcast)")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], f'Unable to find Probe req(Broadcast) in channel:{wifi_access_point.interfaces.wifi.channel}'
    logger().info(f"found Probe req(Broadcast) in channel:{wifi_access_point.interfaces.wifi.channel}'")


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
@pytest.mark.config('wifi_access_point',wifi ={"ssid":"hidden_ssid", "broadcast_ssid": False})
# Verifies the scan in selected channels with the ap set in hidden mode
def test_hidden_scan_sel_chan_c19063(wifi_sniffer,wifi_dut,wifi_access_point):

    testcase = "test_hidden_scan_sel_chan_c19063"

    validation = True

    # Fetches the DUT mac address
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the rejoin feature on DUT
    logger().info("Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin()
    channel = [1,5,9]
    channel_list = [1,5,9]
    channel_bitmap_2_4 = 0
    scan_expected_time = 0
    for count in channel_list:
        channel_bitmap_2_4 += 1 << (count - 1)
        scan_expected_time += 100
    scan_feature_extend = 0

    for channel in channel_list:

        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_ch_{channel}")

        logger().info("Starting the access point with custom channel...")
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)
        # enables the scan in DUT with the given channel bitmap value
        time.sleep(5)

        for i in range(0,2):
            logger().info("Initiating Scan...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=channel, ssid=wifi_access_point.interfaces.wifi.ssid,\
                                                                           scan_bitmap_2_4=channel_bitmap_2_4,scan_feature=scan_feature_extend)
            time.sleep(5)
            logger().info(scan_results)
            assert len(scan_results) >= 1
            for count in scan_results:
                assert count.ssid == wifi_access_point.interfaces.wifi.ssid
            channel_selected = 0
            for count1 in scan_results:
                assert (count1.rf_channel in channel_list), "Scan should happen only in selected channels"

        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], f'Unable to find Probe req(Broadcast) in channel:{channel}'
        logger().info(f"found Probe req(Broadcast) in channel:{channel}'")


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 0,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan in us region with cahnnels 12,13,14
def test_scan_in_US_region_for_channel_12_13_14_c19068(wifi_dut):
    logger().info(" ***** Configuring the dut in US region *****")

    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the rejoin feature on DUT
    logger().info("Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin()
    channel_list =[12,13,14]
    channel_bitmap_2_4 = 0
    scan_expected_time = 0
    scan_feature_extend = 0
    for count in channel_list:
        channel_bitmap_2_4 += 1 << (count - 1)
        scan_expected_time += 100

    with pytest.raises(WlanError) as exc_info:
        # enables the scan in DUT with the given channel bitmap value
        logger().info("Initiating Scan...")
        wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                   scan_bitmap_2_4=channel_bitmap_2_4,
                                                                   scan_feature=scan_feature_extend)
    assert exc_info.value.error_code == 0xA,"Observing wrong error expected error code is 0xA"



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
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
def test_scan_all_channels_in_EU_region_c19070(wifi_dut, wifi_sniffer, wifi_client):
    testcase = "test_scan_all_channels_in_EU_region_c19070"

    logger().info("DUT region is set to Europe")

    channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    validation = True

    # Fetches the DUT mac address
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

    for channel in channels_list_2g:
        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_ch_{channel}")

        time.sleep(2)
        for i in range(0,2):
            # enables the scan in dut on channel 0
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(10)
            assert (len(scan_results) >= 1),"scan failed"
            logger().info(scan_results)

        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], f'Unable to find Probe req(Broadcast) in channel:{channel}'
        logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
        logger().info("DUT scan successfully in all channels")

    logger().info("dut is able to scan successfully in Europe region")




@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 0,
        "region": 1,
        "region_code": 3,
        "module_type": 1,
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_all_channels_in_japan_region_c19071(wifi_dut, wifi_sniffer, wifi_client):
    testcase = "test_scan_all_channels_in_japan_region_c19071"
    logger().info("DUT region is set to Japan")

    channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
    validation = True
    # Fetches the DUT mac address
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

    for channel in channels_list_2g:
        if channel == 14:
            logger().info(f"channel : {channel} not supported by NUC,skipping the channel")
            continue
        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_ch_{channel}")
        time.sleep(2)
        for i in range(0,3):
            # enables the scan in dut on channel 0
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(15)
            assert (len(scan_results) >= 1),"Scan Failed"
            logger().info(scan_results)

        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], f'Unable to find Probe req(Broadcast) in channel:{channel}'
        logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
        logger().info("DUT scan successfully in all channels")
    logger().info("dut is able to scan successfully in Japan region")


