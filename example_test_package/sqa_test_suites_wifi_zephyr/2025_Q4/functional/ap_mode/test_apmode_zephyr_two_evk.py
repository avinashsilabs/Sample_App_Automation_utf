import time
import pytest
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes, \
    Si91xExtCustomFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xRegion, Si91xRegionCode, \
    Si91xModuleType, Si91xJoinFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xBSDSocketParams, Si91xIpVersion

"""Test Author = Vinod.G
        1. Start the sniffer before connection
        2. Initiate connection from Wifi client(Raspberry) and Silabs DUT
        4. Initiate ping from the wifi client and Silabs DUT
        5. Disconnect the wifi client and Silabs DUT
        6. Stop the sniffer capture 
        7. Analysing all sniffer capture packets.
setup requirement:
        1. 2 DUTs(Soc917)
        2. Raspberry PI4 - 1                                                        
        3. Sniffer(NUC)
"""


def logger():
    return get_logger(__name__)


class IperfThraed(ThreadBase):

    def __init__(self, wifi_dut=None, sl_collections=None,
                 traffic_type=None, protocol=None, net_perf_client=None, timeout=60,
                 device_ip=None, remote_ip=None, async_socket=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.device_ip = device_ip
        self.remote_ip = remote_ip
        self.async_socket = async_socket

    def run_traffic(self):

        self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                        protocol=self.protocol, device_ip=self.device_ip,
                                        host_ip=self.remote_ip, timeout=self.timeout,
                                        traffic_type="TX")

    def run(self):
        self.run_traffic()


class IperfThraedSdk(ThreadBase):

    def __init__(self, wifi_dut=None, local_port=None, remote_port=None, local_ip=None, remote_ip=None, size=1400,
                 timeout=60):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.local_port = local_port
        self.remote_port = remote_port
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.size = size
        self.timeout = timeout

    def run_traffic(self):
        self.wifi_dut.interfaces.sapi.iperf(family=Si91xBSDSocketParams.AF_INET,
                                            transfer_type=Si91xBSDSocketParams.SOCK_DGRAM,
                                            protocol=Si91xBSDSocketParams.IPPROTO_UDP, local_port=self.local_port,
                                            local_ip=self.local_ip, remote_ip=self.remote_ip,
                                            remote_port=self.remote_port, size=self.size, ttl=self.timeout,
                                            expected_status=0, timeout=self.timeout + 20,
                                            throughput_type=4, qos=0, async_socket=1,
                                            ip_version=Si91xIpVersion.SL_IPV4_VERSION,
                                            )

    def run(self):
        self.run_traffic()


@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ssid": "sliabs_ap", "passphrase": "Automation@123",
        "region": 1,
        "region_code": "japan",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
def test_wifi_sdk_sta_japan_region_aput_c551266(wifi_dut,
                                                sl_collections, zephyr_wifi_collections, remote_wiseconnect3):
    """Verify APUT beacon with region JP, WPA2 security, Channel 14"""
    try:
        wifi_dut.interfaces.wifi.mode_change()
        set_region_code = "JP"
        wifi_dut.interfaces.wifi.wifi_reg_domain(country_code=set_region_code)
        region_code = wifi_dut.interfaces.wifi.wifi_get_reg_domain()
        assert set_region_code == region_code, "region code set, and the region code received using wifi_get_reg_domain is not same"
        logger().info("Initiating scan from dut...")
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=14)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        state, ssid, bssid, band, channel, iface_mode, link_mode, wpa3_ent_type, security, mfp, rssi, dtim_period, beacon_interval, twt_capable, current_phy_tx_rate = wifi_dut.interfaces.wifi.get_wifi_operational_stats(
            timeout=15)
        assert int(state) == 9, "DUT is not in connected state"
        assert ssid == "SILABS_AP_MODE", "SSID details retrieved using WIFI_IFACE_STATUS API are wrong"
        assert int(channel) == 14, "Channel info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(security) == 1, "Security info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(
            dtim_period) == 3, "DTIM period set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        assert int(
            beacon_interval) == 100, "Beacon interval set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        assert int(iface_mode) == 2, "iface_mode retrieved using WIFI_IFACE_STATUS API is not valid. Expected is 2 "
        assert int(link_mode) == 1, "link_mode retrieved using WIFI_IFACE_STATUS API is not valid. Expected is 1"
        logger().info(f"DUT is configured in soft AP mode.  Wait for 5 seconds to connect client")
        time.sleep(5)
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.join(ssid="SILABS_AP_MODE",
                                                 security="wpa2",
                                                 passphrase="Automation@123",
                                                 channel=14, timeout=60)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.start_ip(timeout=60)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip="192.168.100.76", num_ping_attempts=30,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)

        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(2)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        remote_wiseconnect3.interfaces.sapi.reset()


@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.OpenMode,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.end_state("wifi_dut", wifi="reset")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
def test_wifi_zephyr_AP_connect_ps_enabled_device_c19460(wifi_sniffer, wifi_dut,
                                                         zephyr_wifi_collections,
                                                         remote_wiseconnect3, sl_collections,
                                                         sniffer_filter, request):
    """AP behavior when power save enabled STA connected to AP"""
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with APUT channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        wifi_dut.interfaces.wifi.mode_change()

        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")

        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.join(ssid="SILABS_AP_MODE",
                                                 security="wpa2",
                                                 passphrase="Automation@123",
                                                 channel=11, timeout=60)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.start_ip(timeout=60)
        remote_wiseconnect3.interfaces.wifi.set_performance_profile('power_save', 0, 0, 0, 0)
        # remote_wiseconnect3.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
        #                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip="192.168.100.76", num_ping_attempts=30,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)

        sa_addr = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"STA mac address: {sa_addr}")

        da_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"AP MAC: {da_addr}")

        time.sleep(2)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the power management save sniffer packets'

        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(2)



    except Exception as Ex:
        remote_wiseconnect3.interfaces.sapi.reset()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ssid": "sliabs_ap", "passphrase": "Automation@123",

    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
def test_wifi_sta_connectivity_in_wpa_c551266(wifi_dut,
                                              sl_collections, zephyr_wifi_collections, remote_wiseconnect3, request,
                                              wifi_sniffer):
    """Verify STA connectivity in WPA security mode"""
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with APUT channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA", psk="Automation@123", channel=11)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")

        logger().info(f"DUT is configured in soft AP mode.  Wait for 5 seconds to connect client")
        time.sleep(5)
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.join(ssid="SILABS_AP_MODE",
                                                 security="wpa",
                                                 passphrase="Automation@123",
                                                 channel=11, timeout=60)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.start_ip(timeout=60)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip="192.168.100.76", num_ping_attempts=30,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)

        remote_wiseconnect3.interfaces.sapi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        remote_wiseconnect3.interfaces.sapi.reset()


@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ssid": "sliabs_ap", "passphrase": "Automation@123",

    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_verify_ap_mode_zephyr_UDP_tx_two_clients_multithread_C689597(wifi_sniffer, wifi_dut,
                                                                      utf_constants, zephyr_wifi_collections,
                                                                      wifi_client,
                                                                      sniffer_filter, request, remote_wiseconnect3,
                                                                      protocol, net_perf_client):
    """HT CAP Functionality ,High through put capabilities in AP mode"""
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11)
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2, passphrase="Automation@123",
                                         country="US")
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.join(ssid="SILABS_AP_MODE",
                                                 security="wpa2",
                                                 passphrase="Automation@123",
                                                 channel=11, timeout=60)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.start_ip(timeout=60)
        remote_wiseconnect3.interfaces.sapi.get_ip_address()
        client_ip2 = remote_wiseconnect3.interfaces.sapi.ping(server_ip="192.168.100.76", num_ping_attempts=30,
                                                              ping_timeout=10, ip_version='ipv4', ping_size=64)

        # zephyr_wifi_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client,
        #                                     protocol=protocol, device_ip=dut_ip,
        #                                     host_ip=client_ip, timeout=40,
        #                                     traffic_type="TX")
        ipv4_obj_zephyr = IperfThraed(wifi_dut=wifi_dut,
                                      sl_collections=zephyr_wifi_collections, traffic_type="TX", protocol="UDP",
                                      net_perf_client=net_perf_client,
                                      timeout=60,
                                      device_ip=dut_ip, remote_ip=client_ip,
                                      )

        ipv4_obj_sdk = IperfThraedSdk(wifi_dut=remote_wiseconnect3, local_port=7001, remote_port=7001,
                                      local_ip=client_ip2, remote_ip=dut_ip, size=1000,
                                      timeout=60)

        # remote_wiseconnect3.interfaces.sapi.iperf(family=Si91xBSDSocketParams.AF_INET,
        #                                           transfer_type=Si91xBSDSocketParams.SOCK_DGRAM,
        #                                           protocol=Si91xBSDSocketParams.IPPROTO_UDP, local_port='7001',
        #                                           local_ip=client_ip2, remote_ip=dut_ip,
        #                                           remote_port=7001, size=1000, ttl=30, expected_status=0, timeout=40,
        #                                           throughput_type=4, qos=0, async_socket=1,
        #                                           ip_version=Si91xIpVersion.SL_IPV4_VERSION,
        #                                           )

        ipv4_obj_zephyr.start()
        ipv4_obj_sdk.start()
        time.sleep(1)

        wifi_dut.interfaces.wifi.iperf(family=Si91xBSDSocketParams.AF_INET,
                                       transfer_type=Si91xBSDSocketParams.SOCK_DGRAM,
                                       protocol=Si91xBSDSocketParams.IPPROTO_UDP, local_port='7001',
                                       local_ip=dut_ip, remote_ip=client_ip2,
                                       remote_port=7001, size=1000, ttl=30, expected_status=0, timeout=60,
                                       throughput_type=2, qos=0, async_socket=0,
                                       ip_version=Si91xIpVersion.SL_IPV4_VERSION)

        ipv4_obj_zephyr.wait_for_exit()
        ipv4_obj_sdk.wait_for_exit()
        time.sleep(5)

        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
