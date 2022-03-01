import pytest
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116StoreConfiguration, RS9116Region, RS9116RegionCode, RS9116ModuleType, \
    RS9116CustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap
import time
from utf.utils.logger import get_logger
# from utf.interfaces.wifi import WlanError

from utf.interfaces.cli import CLITransportException

"""setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""
def logger():
    return get_logger(__name__)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        #"first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut",
                      wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])

def test_store_config_open_testcase1(wifi_access_point, wifi_dut):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Ping to dut from third party device
    status = ping(device_ip, 10)
    assert status == 1, "DUT is not responding to ping request from third party device before store configuration"

    # Save the wireless configuration in the flash
    wifi_dut.interfaces.wifi.config_save()
    # Enable the wireless configuration in the flash
    wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
    #deinit
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(5)
    #init
    wifi_dut.interfaces.wifi.wireless_init()
    time.sleep(10)
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Ping to dut from third party device
    status = ping(device_ip, 10)
    assert status == 1, "DUT is not responding to ping request from third party device after store configuration"
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 1
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "passphrase": 'STORE_CONFIG_TEST', "security": 'WPA2',
                          "channel": 36})
def test_store_config_band_5_WPA2_testcase21(wifi_access_point , wifi_dut):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Ping to dut from third party device
    status = ping(device_ip, 10)
    assert status == 1, "DUT is not responding to ping request from third party device before store configuration"

    # Save the wireless configuration in the flash
    wifi_dut.interfaces.wifi.config_save()
    # Enable the wireless configuration in the flash
    wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
    wifi_dut.interfaces.wifi.reset_soft()
    wifi_dut.interfaces.wifi.wireless_init()
    time.sleep(10)
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Ping to dut from third party device
    status = ping(device_ip, 10)
    assert status == 1, "DUT is not responding to ping request from third party device after store configuration"
    time.sleep(5)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.parametrize("channel_list", [[11, 12, 14]])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point1", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "passphrase": 'STORE_CONFIG_TEST', "security": 'WPA2'})
def test_store_config_region_testcase31(wifi_access_point,wifi_dut, channel_list):
    for channel in channel_list:
        wifi_dut.interfaces.wifi.reset_soft()
        wifi_dut.interfaces.wifi.init()
        if channel == 11:
            # Set the region to US in DUT
            wifi_dut.interfaces.wifi.set_region(RS9116Region.FromUser, RS9116RegionCode.US,
                                                RS9116ModuleType.WithoutOnboardAntenna)
            region = "US"
        if channel == 12:
            if not (wifi_access_point.interfaces.wifi.config['type'] == "wifi.access_points.dlink810_a1_1_01"):
                logger.info("The channel 12 is supported only in dlink810-a1 access point. Plese use dlink810-a1 "
                            "access point to verify the feature")
                continue
            # Set the region to EUROPE in DUT
            wifi_dut.interfaces.wifi.set_region(RS9116Region.FromUser, RS9116RegionCode.Europe,
                                                RS9116ModuleType.WithoutOnboardAntenna)
            region = "EUROPE"
        if channel == 14:
            # Set the region to JAPAN in DUT
            wifi_dut.interfaces.wifi.set_region(RS9116Region.FromUser, RS9116RegionCode.Japan,
                                                RS9116ModuleType.WithoutOnboardAntenna)
            region = "JAPAN"
            continue
        # Configures the Access point with the channel selected
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        # Ping to dut from third party device
        status = ping(device_ip, 10)
        assert status == 1, f"DUT is not responding to ping request from third party device before store " \
                            f"configuration when running test  with channel {channel} in region {region}"

        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
        wifi_dut.interfaces.wifi.reset_soft()
        wifi_dut.interfaces.wifi.wireless_init()
        time.sleep(10)
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # Ping to dut from third party device
        status = ping(device_ip, 10)
        assert status == 1, f"DUT is not responding to ping request from third party device after store " \
                            f"configuration when running test  with channel {channel} in region {region}"
        time.sleep(5)
        wifi_dut.interfaces.wifi.leave()
        # Disable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 2
        }
    )
@pytest.mark.parametrize("channel_list", [[1, 36]])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "passphrase": 'STORE_CONFIG_TEST', "security": 'WPA2'})
def test_store_config_band_dual_testcase41(wifi_dut, wifi_access_point, logger, channel_list):
    dut_connected_to_ap = 0
    for channel in channel_list:
        # Configures the Access point with the channel selected
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)
        if dut_connected_to_ap == 0:
            # DUT connects to AP after join_ap API is executed
            # wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            wifi_dut.interfaces.wifi.join(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid,
                                          security=wifi_access_point.interfaces.wifi.security,
                                          passphrase=wifi_access_point.interfaces.wifi.passphrase)
            # DUT gets ipaddress through DHCP process after start_ip API is executed
            wifi_dut.interfaces.wifi.start_ip()
            # The below api parses DUTs IP address
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            # Ping to dut from third party device
            status = ping(device_ip, 10)
            assert status == 1, f"DUT is not responding to ping request from third party device before store " \
                                f"configuration when running test  with channel {channel}"
            dut_connected_to_ap = 1

            # Save the wireless configuration in the flash
            wifi_dut.interfaces.wifi.config_save()
            # Enable the wireless configuration in the flash
            wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
        wifi_dut.interfaces.wifi.reset_soft()
        wifi_dut.interfaces.wifi.wireless_init()
        time.sleep(10)
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # Ping to dut from third party device
        status = ping(device_ip, 10)
        assert status == 1, f"DUT is not responding to ping request from third party device after store " \
                            f"configuration when running test  with channel {channel}"
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        # Note that SSL cert bypass is required to avoid SSL handshake error.
        # It is unclear if this is a bug in the AWS SAPI network wrapper
        # or in the 9116 firmware
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.SSLCertBypass | RS9116ExtTCPIPFeatureBitMap.Default,
        },
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "passphrase": 'STORE_CONFIG_TEST', "security": 'WPA2'})
def test_store_config_AWS_connection_testcase22(wifi_dut, wifi_access_point, logger):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Ping to dut from third party device
    status = ping(device_ip, 10)
    assert status == 1, "DUT is not responding to ping request from third party device before store configuration"
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Save the wireless configuration in the flash
    wifi_dut.interfaces.wifi.config_save()
    # Enable the wireless configuration in the flash
    wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

    for count in range(1, 6):
        wifi_dut.interfaces.wifi.reset_soft()
        wifi_dut.interfaces.wifi.init()
        time.sleep(10)

        # Ping to dut from third party device
        status = ping(device_ip, 10)
        assert status == 1, "DUT is not responding to ping request from third party device after store configuration"

        # Disable power save in the DUT
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled)

        # Enable listen interval based power save in the DUT
        wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                            listen_interval=1000 + (count * 100))
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        topic_1 = "sdk/test/Python"
        message = '{"message": "my payload"}'

        wifi_dut.interfaces.wifi.aws_iot_connect()
        time.sleep(2)
        wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, 0)

        wifi_dut.interfaces.wifi.aws_iot_publish(
            topic_1, message, 0
            )
        time.sleep(10)
        events = wifi_dut.interfaces.wifi.get_async_events()

        if len(events):
            for event in events:
                assert topic_1 == event.event_data.topic, "message is not received on subscribed topic"
                assert message == event.event_data.payload, "sent and received messages are not matching"
        wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1)
        wifi_dut.interfaces.wifi.aws_iot_disconnect()
        time.sleep(1)


@pytest.mark.end_state("wifi_dut",
                      wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_error_handling_in_SCFG_by_turning_off_AP_TC2380(wifi_dut,wifi_access_point):
    #when join_ap is enabled it connects to AP
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    #get ip through dhcp
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(result, wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
    wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    #below api save the AP configuration
    wifi_dut.interfaces.wifi.config_save()
    #below api enables the auto configuration
    wifi_dut.interfaces.wifi.config_enable(1, 0)
    #below api is used to turn off AP
    wifi_access_point.interfaces.wifi.stop_ap()
    # below api is used to reset the AP

    #de_init
    wifi_dut.interfaces.wifi.reset_soft()
    with pytest.raises(CLITransportException) as ex:
        wifi_dut.interfaces.wifi.wireless_init()
        assert "Error Code : 0x3" in str(ex)


# #testcase id:2.1.21.13
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 0,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "eap_cert": "wifi-user.pem",
    }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
#@pytest.mark.config('wifi_access_point', wifi={"channel": '3'})
def test_verify_rejoin_func_with_specific_channel_using_SCFG_TC2398(wifi_sniffer,wifi_dut,wifi_access_point):
    validation = True
    packet_filter2 = False
    channel_bitmap_2_4 = 1057
    channel_bitmap_5 = 0
    scan_feature_extend = 0
    channel_list = [1, 6, 11]

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid,
                                                    scan_bitmap_2_4=channel_bitmap_2_4,
                                                    scan_bitmap_5=channel_bitmap_5,
                                                    scan_feature=scan_feature_extend)
    wifi_dut.interfaces.wifi.join(bgscan_flag=True)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Save the wireless configuration in the flash
    wifi_dut.interfaces.wifi.config_save()
    # Enable the wireless configuration in the flash
    wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

    logger().info(f"*****Enable Max PSP in DUT******")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    # below api is used to turn off AP
    wifi_access_point.interfaces.wifi.stop_ap()

    time.sleep(1)
    for channel in channel_list:
        wifi_sniffer.interfaces.capture.configure_interface(channel)

        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_primary_channel_2g')
        packet_filter1 = f'wlan_radio.channel == {channel} and wlan.sa == {dut_mac_address} ' \
                         f'and wlan.fc.type_subtype == 0x0004 ' \
                         f'and wlan.da == ff:ff:ff:ff:ff:ff '
        wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(10)

        with pytest.raises(CLITransportException) as ex:
            wifi_dut.interfaces.wifi.wireless_init()
            assert "Error Code : 0x3" in str(ex)

        time.sleep(30)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)

