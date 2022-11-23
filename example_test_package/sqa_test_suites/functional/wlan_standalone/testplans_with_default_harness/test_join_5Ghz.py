import time
import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 5Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut

    Author: RaviNemali
"""

""" ********* READ DESCRIPTION AT LINE-29,FOR HARNESS CHANGES AND CONFIG'S ********** """
"""
    ++++++++ Harness Changes & test limites ++++++++

    Harness configs:
                 CONFIG1: configure DUT type  -- rs9116_sapi in default section of harness.
                 CONFIG2: Ap details -- IP addr, Port,login details in ap section of harness.
                 CONFIG3: Default Ap -- Set your ap name as default ap for tests in harness.
                 CONFIG4: Sniffer -- Set IP addr,login details of NUC in airpcap fields of harness.
    Test Limits: This test plan limits to the 5ghz band of dut for DFS and Non-DFS channels.
    AP Configs: Access point is configured from 36 - 64, above that ap support ends.

"""

# configure the ping count for dut
ping_count = 10


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 1
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 36})
def test_join_5ghz_mode_C19388(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        validation = True

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_join_5ghz_mode_C19388')

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("Joining the AP")
        status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        assert status, 'Unable to join ap '

        logger().info("Starting dhcp")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("enabling bt power save mode in DUT......")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, 'failed to enable'

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # validating data rates in 11n mode connection
        packet_filter1 = f'(wlan.addr=={dut_mac_address}) and (wlan.fc.type_subtype == 0x0028) or (radiotap.datarate == 54) or ' \
                         f'(radiotap.datarate == 48) or (radiotap.datarate == 36)'

        logger().info("pinging to dut ip")
        status = ping(device_ip, ping_count)
        assert status == 1, "ping dut failed..."
        logger().info("ping to dut is successful...")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find 11n data rates packets in sniffer'

        logger().info("disconnecting from ap....")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
    logger().info(f"test completed in {t.duration} seconds")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "channel": 52})
def test_join_5ghz_dfs_channel_C19389(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        validation = True

        logger().info(" ====== configuring the sniffer with the access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Init_Scan_Join_Disconnect_30min_C19710')

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)
        # added this sleep for DFS channel beaconning to start in access point after setting the channel in ap
        time.sleep(70)
        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("Joining the AP")
        status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        assert status, 'Unable to join ap '

        logger().info("Starting dhcp")
        result = wifi_dut.interfaces.wifi.start_ip()

        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("enabling bt power save mode in DUT......")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, 'failed to enable'

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

        # initiates the ping in dut
        logger().info("pinging to dut ip")
        status = ping(device_ip, ping_count)
        assert status == 1, "Failed to ping DUT..."
        logger().info("ping to dut is successful...")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

        time.sleep(10)
    logger().info(f"test completed in {t.duration} seconds")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
def test_join_5ghz_dfs_channels_100_and_140_C19390(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info("Using the channels 52-64 instead of 100-140 as limitation from AP")
        channel_list = [52, 56, 60, 64]
        for channel in channel_list:
            rejoin_max = 10
            scan_interval = 6
            beacon_missedcount = 40
            first_time_retry = 0
            timeout = 10
            validation = True

            logger().info("Starting AP...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(70)

            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_join_5ghz_dfs_channels_100_and_140_C19390')

            logger().info("Enabling rejoin...")
            wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                            beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                            timeout=timeout)
            logger().info("scan for the ap's.....")
            ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')

            logger().info("Joining the AP")
            status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            assert status, 'failed to join ap '

            logger().info("Starting dhcp")
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

            logger().info("enabling wifi power save mode in DUT......")
            enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_wifi_ps, 'failed to enable'

            logger().info("enabling bt power save mode in DUT......")
            enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                  RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_bt_ps, 'failed to enable'

            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the power management bit
            packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'

            logger().info("pinging to dut ip")
            status = ping(device_ip, ping_count)
            assert status == 1, "ping to dut failed..."
            logger().info("ping to dut is successful...")

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info(" Validate power management bit 1")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

            logger().info("disconnecting from ap...")
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)
    logger().info(f"Associated and ping in {t.duration} seconds")