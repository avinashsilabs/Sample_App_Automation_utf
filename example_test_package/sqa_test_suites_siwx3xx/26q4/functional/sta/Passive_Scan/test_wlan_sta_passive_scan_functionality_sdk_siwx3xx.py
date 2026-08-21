# Description: This script is used to test the passive scan functionality by enabling passive scan bit in scan request.
"""
    setup requirement:
        1. DUT(Si917_SDK)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode and enable passive scan feature in DUT.
           SiWx3xx start_state uses net_init_client (required by current join API: -z / sl_net_up).
        2. Verify passive scan duration taken by DUT is within the expected threshold value.
        2. Join the access point and enable the dhcp.
        3. Enable the wlan and bt power save mode in dut after the connection.
        4. Initiate ping from the dut.
        5. Check for unicast probe request, power management bit and association request with HE information

    Author: Venkatesulu Ekambaram
"""

import time
import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.wifi.siwx3xx.tests.devices.siwx3xx import (
    Siwx3xxRegion,
    Siwx3xxCoexMode,
    Siwx3xxRegionCode,
    Siwx3xxModuleType,
    Siwx3xxFeatureBitMap,
    Siwx3xxOperatingMode,
    Siwx3xxPowerSaveModes,
    Siwx3xxTCPIPFeatureBitMap,
    Siwx3xxConfigFeatureBitMap,
    Siwx3xxCustomFeatureBitMap,
    Siwx3xxExtTCPIPFeatureBitMap,
    Siwx3xxExtCustomFeatureBitMap,
    Siwx3xxPowerSaveProcedureTypes
)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.wifi.siwx3xx.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


def wifi_dut_marker(region=None, region_code=None, **overrides):
    """
    Si3xx wifi_dut config template (same baseline as test_scan_2_4_si3xx.py).
    Pass overrides for test-specific keys (e.g. enable_timeout_config, dwell time, region).
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
    if region is not None:
        config["region"] = region
    if region_code is not None:
        config["region_code"] = region_code
    config.update(overrides)
    return pytest.mark.config("wifi_dut", wifi=config)


class PassiveScanFunctionality:
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections, request,
                 dwell_time, scan_type, lp_mode=0, measure_scan_time=1, ap_bssid=None):
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.siwx3xx_collections = siwx3xx_collections
        self.dwell_time = dwell_time
        self.lp_mode = lp_mode
        self.scan_type = scan_type
        self.measure_scan_time = measure_scan_time
        self.test_name = request.node.name
        self.ap_bssid = ap_bssid if ap_bssid else self.wifi_access_point.interfaces.wifi.bssid
        self.dut_mac = None

    def scan(self, all_ch_scan=True, test_id=''):
        self.dut_mac = self.wifi_dut.interfaces.wifi.get_mac_address()
        channel = 0 if all_ch_scan else self.wifi_access_point.interfaces.wifi.channel
        if self.scan_type == 1:
            scan_time_threshold = (11 * self.dwell_time + 100) / 1000 if all_ch_scan else (self.dwell_time + 100) / 1000
            logger().info(f"Configuring the sniffer with channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"unicast_probe_check_{test_id}")
            time.sleep(5)
            scan_time = 0
            logger().info(f"*********** Starting passive scan by enabling passive scan bit in scan request ***********")
            for count in range(3):
                try:
                    scan_time = self.wifi_dut.interfaces.wifi.scan(measure_scan_time=self.measure_scan_time,
                                                                   scan_type=self.scan_type, lp_mode=self.lp_mode,
                                                                   channel=channel)[-1]
                    scan_time = float(scan_time.split(':')[-1])
                    break
                except Exception as err:
                    logger().info("..........Scan_Retry..........")
                    if count == 2: raise err
            assert scan_time <= scan_time_threshold, (f"Observed passive scan time is more than expected value:"
                                                      f"{scan_time_threshold} Seconds")
            logger().info(f"\n\n******** Time taken for passive scan is --> '{scan_time}' seconds, which is within the "
                          f"expected threshold value '{scan_time_threshold}' seconds ********")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("******** Checking for unicast probe request packet in sniffer capture ********")
            packet_filter1 = f"(wlan.fc.type_subtype == 4) && (wlan.sa == {self.dut_mac}) && (wlan.da == {self.ap_bssid})"
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
                "Found unicast probe request packet in sniffer capture, which is not expected"
        else:
            logger().info(f"************ Starting active scan from DUT ************")
            self.wifi_dut.interfaces.wifi.scan(scan_type=self.scan_type, channel=channel,
                                               measure_scan_time=self.measure_scan_time)

    def join_to_ap(self, ping_count=120, ps_enable=True):
        logger().info(f"\n\nConfiguring the sniffer with channel {self.wifi_access_point.interfaces.wifi.channel}")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
        time.sleep(3)
        # Everest/Si3xx template: TCPIPBypass — skip on-chip DHCP/ping; host stack owns IP
        self.siwx3xx_collections.join_to_wifi_network(
            self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            power_save=ps_enable,
            mode="power_save_low_latency",
            ping_count=ping_count,
            ping_after_power_save=False,
            ping_before_power_save=False,
            retry_count=3,
            tcp_ip_bypass=True,
            associated=self.wifi_dut.interfaces.wifi.associated,
        )

    def sniffer_validation(self):
        logger().info("Stop sniffer capture finally")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.dut_mac,
                                                                                             da_addr=self.ap_bssid,
                                                                                             filter_name='power_mgmt_bit')
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.dut_mac,
                                                                                             da_addr=self.ap_bssid,
                                                                                             filter_name='association_request')
        logger().info("******** Checking for power management bit in sniffer capture ********")
        status = self.wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter2)['packet_count']
        if not status: logger().info("Unable to find power management bit 1 in sniffer")
        logger().info("******** Validating Assoc Req with HE information ********")
        status = self.wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter3)['packet_count']
        if not status: logger().info('Unable to find Assoc Req  with HE capability in sniffer')


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "passive_chan_scan_timeout_value": 400,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551130')
def test_wsdk_siwx3xx_passive_scan_with_dwell_time_400ms_c551130(wifi_access_point, wifi_sniffer, wifi_dut, request,
                                                         sniffer_filter, siwx3xx_collections):
    """
    Verify Passive scan functionality by enabling passive scan bit.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=400, scan_type=1, lp_mode=0)
        wlan_obj.scan(test_id='C551130')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551131')
def test_wsdk_siwx3xx_passive_scan_with_dwell_time_110ms_c551131(wifi_access_point, wifi_sniffer, wifi_dut, request,
                                                         sniffer_filter, siwx3xx_collections):
    """
    Verify Passive scan functionality by enabling dwell time to minimum value of 110ms.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=0)
        wlan_obj.scan(test_id='c551131')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['deinit'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("dwell_time", [200, 400, 600, 800])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551133')
def test_wsdk_siwx3xx_passive_scan_for_diff_dwell_time_lp_chain_enabled_c551133(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                        request, sniffer_filter, siwx3xx_collections,
                                                                        dwell_time):
    """
    Verify Passive scan functionality by enabling dwell time to different values like 200ms,400ms,600ms,800ms and
    LP chain enabled.
    """
    try:
        # Align with current join API: net.init client before connect/-z/sl_net_up
        wifi_dut.interfaces.wifi.enable_timeout_config = False
        wifi_dut.interfaces.wifi.set_wifi_config()
        logger().info(f"\n\n........Initiating passive scan functionality with dwell time: {dwell_time} ms........")
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")
        wifi_dut.interfaces.wifi.set_timeout_config(keep_alive_timeout_value=10, auth_assoc_timeout_value=100,
                                                    active_chan_scan_timeout_value=100,
                                                    passive_chan_scan_timeout_value=dwell_time)
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=dwell_time, scan_type=1, lp_mode=1)
        wlan_obj.scan(test_id='c551133')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['deinit'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("dwell_time", [300, 500, 700])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551134')
def test_wsdk_siwx3xx_passive_scan_for_diff_dwell_time_lp_chain_disabled_c551134(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                         request, sniffer_filter, siwx3xx_collections,
                                                                         dwell_time):
    """
    Verify Passive scan functionality by enabling dwell time to different values like 300ms,500ms,700ms and LP chain
    disabled.
    """
    try:
        # Align with current join API: net.init client before connect/-z/sl_net_up
        wifi_dut.interfaces.wifi.enable_timeout_config = False
        wifi_dut.interfaces.wifi.set_wifi_config()
        logger().info(f"\n\n........Initiating Passive scan functionality with dwell time: {dwell_time} ms........")
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")
        wifi_dut.interfaces.wifi.set_timeout_config(keep_alive_timeout_value=10, auth_assoc_timeout_value=100,
                                                    active_chan_scan_timeout_value=100,
                                                    passive_chan_scan_timeout_value=dwell_time)
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=dwell_time, scan_type=1, lp_mode=0)
        wlan_obj.scan(test_id='c551134')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
        wifi_dut.interfaces.wifi.oper_mode_opts.passive_chan_scan_timeout_value = dwell_time
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551137')
def test_wsdk_siwx3xx_passive_scan_and_active_scan_c551137(wifi_access_point, wifi_sniffer, wifi_dut, request, sniffer_filter,
                                                   siwx3xx_collections):
    """
    Verify Passive scan functionality connection initially with Passive scan disconnect and connect back using Active
    scan.
    """
    try:
        for scan_type in [1, 0]:
            logger().info(f"\n\n***************** Initiating test for scan type: {scan_type} *****************")
            wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                siwx3xx_collections, request, dwell_time=110, scan_type=scan_type, lp_mode=0)
            wlan_obj.scan(test_id='c551137')
            wlan_obj.join_to_ap()
            wlan_obj.sniffer_validation()
            wifi_dut.interfaces.wifi.leave()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "passive_chan_scan_timeout_value": 1000,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551132')
def test_wsdk_siwx3xx_passive_scan_max_dwell_time_1000ms_c551132(wifi_access_point, wifi_sniffer, wifi_dut, request,
                                                         sniffer_filter, siwx3xx_collections):
    """
    Verify Passive scan functionality by enabling dwell time to maximum value of 1000ms(1s)
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=1000, scan_type=1, lp_mode=0)
        wlan_obj.scan(test_id='c551132')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551135')
def test_wsdk_siwx3xx_passive_scan_func_probe_response_check_c551135(wifi_access_point, wifi_sniffer, wifi_dut, request,
                                                             sniffer_filter, siwx3xx_collections):
    """
    Negative Case : Verify Passive scan functionality if DUT did not receives any probe response whether DUT is
    switching to Active scan or not.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=0)
        wlan_obj.scan(test_id='c551135')
        logger().info("******** Checking for probe response packet in sniffer capture ********")
        packet_filter1 = f"wlan.fc.type_subtype == 5 && wlan.sa == {wlan_obj.ap_bssid} && wlan.da == {wlan_obj.dut_mac}"
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
            "Found probe response packet in sniffer capture, which is not expected"
        logger().info("****************** DUT did not switch to active scan ************************")
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["reset"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551136')
def test_wsdk_siwx3xx_passive_scan_with_dwell_time_1001ms_c551136(wifi_dut, siwx3xx_collections):
    """
    Negative Case : Verify Passive scan functionality by enabling Dwell time to 1001msec.
    """
    try:
        # Align with current join/net API: timeout config only after net.init
        wifi_dut.interfaces.wifi.enable_timeout_config = False
        wifi_dut.interfaces.wifi.set_wifi_config()
        logger().info(f"\nSetting dwell time: 1001ms in DUT")
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")
        # SiWx3xx validates dwell time on set_timeout_config (after net.init)
        wifi_dut.interfaces.wifi.set_timeout_config(
            keep_alive_timeout_value=10,
            auth_assoc_timeout_value=100,
            active_chan_scan_timeout_value=100,
            passive_chan_scan_timeout_value=1001,
            expected_status=SLStatus.SL_STATUS_SI91X_WRONG_PARAMETERS,
        )
        logger().info(f"Observed error code:'{hex(SLStatus.SL_STATUS_SI91X_WRONG_PARAMETERS)}' from DUT,"
                      f" when dwell time is set to more than maximum value")
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "passive_chan_scan_timeout_value": 1000,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551139')
def test_wsdk_siwx3xx_passive_scan_with_dwell_time_1000ms_lp_chain_disabled_c551139(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                            request, sniffer_filter, siwx3xx_collections):
    """
    Verify Passive scan functionality with maximum dwell time 1000ms and LP chain disabled, scan should happen only in
    single channel.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=1000, scan_type=1, lp_mode=0)
        wlan_obj.scan(all_ch_scan=False, test_id='c551139')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": Siwx3xxRegion.FromUser,
        "region_code": Siwx3xxRegionCode.Japan,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.wifi_access_point("raspi_wifi")
@pytest.mark.config('wifi_access_point', wifi={'interface': 'wlan0', 'region': 'Japan', 'channel': 13})
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551142')
def test_wsdk_siwx3xx_passive_scan_in_japan_region_lp_chain_enabled_c551142(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                    request, sniffer_filter, siwx3xx_collections):
    """
    Verify Passive scan functionality with different regions in Japan by setting scan in specific channel and LP
    enabled.
    """
    try:
        ap_bssid = wifi_access_point.interfaces.wifi.get_mac_address()
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"beacon_check_japan_region_c551145")
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_filter = f"(wlan.sa == {ap_bssid} && wlan.fc.type_subtype == 8 && wlan.ds.current_channel == {channel})"
        logger().info("******** Checking for japan region beacon in sniffer capture ********")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, beacon_filter)['packet_count'], \
            "Unable to find japan region beacons in sniffer"
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1, ap_bssid=ap_bssid)
        wlan_obj.scan(all_ch_scan=False, test_id='c551142')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": Siwx3xxRegion.FromUser,
        "region_code": Siwx3xxRegionCode.Europe,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config('wifi_access_point', wifi={'region': 'Europe', 'channel': 12})
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551143')
def test_wsdk_siwx3xx_passive_scan_in_europe_region_lp_chain_enabled_c551143(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                     request, sniffer_filter, siwx3xx_collections):
    """
    Verify Passive scan functionality with different regions in Europe by setting scan in specific channel and LP
    enabled.
    """
    try:
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"beacon_check_eu_region_c551143")
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_filter = f"(wlan.sa == {ap_bssid} && wlan.fc.type_subtype == 8 && wlan.ds.current_channel == {channel})"
        logger().info("******** Checking for europe region beacon in sniffer capture ********")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, beacon_filter)['packet_count'], \
            "Unable to find europe region beacons in sniffer"
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1)
        wlan_obj.scan(all_ch_scan=False, test_id='c551143')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": Siwx3xxRegion.FromUser,
        "region_code": Siwx3xxRegionCode.US,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config('wifi_access_point', wifi={'region': 'US'})
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551144')
def test_wsdk_siwx3xx_passive_scan_in_us_region_lp_chain_enabled_c551144(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                 request, sniffer_filter, siwx3xx_collections):
    """
    Verify Passive scan functionality with different regions in US by setting scan in specific channel and LP enabled.
    """
    try:
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"beacon_check_us_region_c551144")
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_filter = f"(wlan.sa == {ap_bssid} && wlan.fc.type_subtype == 8 && wlan.ds.current_channel == {channel})"
        logger().info("******** Checking for us region beacon in sniffer capture ********")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, beacon_filter)['packet_count'], \
            "Unable to find us region beacons in sniffer"
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1)
        wlan_obj.scan(all_ch_scan=False, test_id='c551144')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": Siwx3xxRegion.FromUser,
        "region_code": Siwx3xxRegionCode.Korea,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.wifi_access_point("raspi_wifi")
@pytest.mark.config('wifi_access_point', wifi={'interface': 'wlan0', 'region': 'Korea', 'channel': 13})
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551145')
def test_wsdk_siwx3xx_passive_scan_in_korea_region_lp_chain_enabled_c551145(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                    request, sniffer_filter, siwx3xx_collections):
    """
    Verify Passive scan functionality with different regions in KR by setting scan in specific channel and LP enabled.
    """
    try:
        ap_bssid = wifi_access_point.interfaces.wifi.get_mac_address()
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"beacon_check_korea_region_c551145")
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_filter = f"(wlan.sa == {ap_bssid} && wlan.fc.type_subtype == 8 && wlan.ds.current_channel == {channel})"
        logger().info("******** Checking for korea region beacon in sniffer capture ********")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, beacon_filter)['packet_count'], \
            "Unable to find korea region beacons in sniffer"
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1, ap_bssid=ap_bssid)
        wlan_obj.scan(all_ch_scan=False, test_id='c551145')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": Siwx3xxRegion.FromUser,
        "region_code": Siwx3xxRegionCode.Worldwide,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config('wifi_access_point', wifi={'region': 'Asia'})
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551146')
def test_wsdk_siwx3xx_passive_scan_in_world_wide_domain_lp_chain_enabled_c551146(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                         request, sniffer_filter, siwx3xx_collections):
    """
    Verify Passive scan functionality with different regions in WORLD_DOMAIN by setting scan in specific channel and
    LP enabled
    """
    try:
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"beacon_check_asia_region_c551146")
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        beacon_filter = f"(wlan.sa == {ap_bssid} && wlan.fc.type_subtype == 8 && wlan.ds.current_channel == {channel})"
        logger().info("******** Checking for asia region beacon in sniffer capture ********")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, beacon_filter)['packet_count'], \
            "Unable to find asia region beacons in sniffer"
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1)
        wlan_obj.scan(all_ch_scan=False, test_id='c551146')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLAN | Siwx3xxCoexMode.BLE,
        "features": Siwx3xxFeatureBitMap.Default,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C551140')
def test_wsdk_siwx3xx_passive_scan_connect_disconnect_30min_lp_chain_disabled_c551140(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                              request, sniffer_filter, siwx3xx_collections):
    """
    Verify Passive scan functionality with LP chain disabled, Passive scan disconnect and connect back with passive
    scan only do it in loop for 30 minutes.
    """
    try:
        sw = Stopwatch()
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=0)
        while sw.elapsed_sec <= 1800:
            time_left = int((1800 - sw.elapsed_sec) / 60)
            logger().info(f"*************** Remaining time to complete test is: '{time_left}' minutes ***************")
            wlan_obj.scan(test_id='C551140')
            wlan_obj.join_to_ap(ps_enable=False)
            wlan_obj.sniffer_validation()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(60)
            logger().info("\n\n")
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C551141')
def test_wsdk_siwx3xx_passive_scan_connect_disconnect_30min_lp_chain_enabled_c551141(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                             request, sniffer_filter, siwx3xx_collections):
    """
    Verify Passive scan functionality with LP chain enabled, Passive scan disconnect and connect back with passive scan
    only do it in loop for 30 minutes.
    """
    try:
        sw = Stopwatch()
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, siwx3xx_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1)
        while sw.elapsed_sec <= 1800:
            time_left = int((1800 - sw.elapsed_sec) / 60)
            logger().info(f"*************** Remaining time to complete test is: '{time_left}' minutes ***************")
            wlan_obj.scan(test_id='c551141')
            wlan_obj.join_to_ap(ps_enable=False)
            wlan_obj.sniffer_validation()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(60)
            logger().info("\n\n")
    except Exception as error:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
