import pytest
from utils.iperf.iperf_utils import ping
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116StoreConfiguration, RS9116Region, RS9116RegionCode, RS9116ModuleType, \
    RS9116CustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap
import time

"""setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
def test_store_config_open_testcase1(wifi_dut, wifi_access_point, logger):
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
def test_store_config_band_5_WPA2_testcase21(wifi_dut, wifi_access_point, logger):
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
def test_store_config_region_testcase31(wifi_dut, wifi_access_point, logger, channel_list):
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
