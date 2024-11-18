# Description: This script is used to test the passive scan functionality by enabling passive scan bit in scan request.
"""
    setup requirement:
        1. DUT(Si917_SDK)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode and enable passive scan feature in DUT.
        2. Verify passive scan duration taken by DUT is within the expected threshold value.
        2. Join the access point and enable the dhcp.
        3. Enable the wlan and bt power save mode in dut after the connection.
        4. Initiate ping from the dut.
        5. Check for unicast probe request, power management bit and association request with HE information

    Author: CG team
"""

import time
import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xRegion,
    Si91xCoexMode,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xFeatureBitMap,
    Si91xOperatingMode,
    Si91xPowerSaveModes,
    Si91xTCPIPFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xPowerSaveProcedureTypes
)
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import CountryCode
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


class PassiveScanFunctionality:
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections, request,
                 dwell_time, scan_type, lp_mode=0, measure_scan_time=1, ap_bssid=None):
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.sl_collections = sl_collections
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
        self.sl_collections.connect(self.wifi_dut, self.wifi_access_point, retry_count=3)
        ip_config = self.sl_collections.configure_ip(self.wifi_dut, retry_count=3, timeout=120)[-1]
        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        time.sleep(5)
        logger().info("Pinging to DUT")
        status = self.sl_collections.ping(device_ip=device_ip, ping_count=ping_count, retry_count=3)
        assert status, "Failed to ping to DUT"
        if ps_enable:
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                               psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

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
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 400,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_with_dwell_time_400ms_c551130(wifi_access_point, wifi_sniffer, wifi_dut, request,
                                                         sniffer_filter, sl_collections):
    """
    Verify Passive scan functionality by enabling passive scan bit.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=400, scan_type=1, lp_mode=0)
        wlan_obj.scan(test_id='c551130')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_with_dwell_time_110ms_c551131(wifi_access_point, wifi_sniffer, wifi_dut, request,
                                                         sniffer_filter, sl_collections):
    """
    Verify Passive scan functionality by enabling dwell time to minimum value of 110ms.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=0)
        wlan_obj.scan(test_id='c551131')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['deinit'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("dwell_time", [200, 400, 600, 800])
def test_wsdk_passive_scan_for_diff_dwell_time_lp_chain_enabled_c551133(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                        request, sniffer_filter, sl_collections,
                                                                        dwell_time):
    """
    Verify Passive scan functionality by enabling dwell time to different values like 200ms,400ms,600ms,800ms and
    LP chain enabled.
    """
    try:
        wifi_dut.interfaces.wifi.set_wifi_config()
        logger().info(f"\n\n........Initiating passive scan functionality with dwell time: {dwell_time} ms........")
        wifi_dut.interfaces.wifi.set_timeout_config(keep_alive_timeout_value=10, auth_assoc_timeout_value=100,
                                                    active_chan_scan_timeout_value=100,
                                                    passive_chan_scan_timeout_value=dwell_time)
        wifi_dut.interfaces.wifi.init(config_required=False)
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=dwell_time, scan_type=1, lp_mode=1)
        wlan_obj.scan(test_id='c551133')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['deinit'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("dwell_time", [300, 500, 700])
def test_wsdk_passive_scan_for_diff_dwell_time_lp_chain_disabled_c551134(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                         request, sniffer_filter, sl_collections,
                                                                         dwell_time):
    """
    Verify Passive scan functionality by enabling dwell time to different values like 300ms,500ms,700ms and LP chain
    disabled.
    """
    try:
        wifi_dut.interfaces.wifi.set_wifi_config()
        logger().info(f"\n\n........Initiating Passive scan functionality with dwell time: {dwell_time} ms........")
        wifi_dut.interfaces.wifi.set_timeout_config(keep_alive_timeout_value=10, auth_assoc_timeout_value=100,
                                                    active_chan_scan_timeout_value=100,
                                                    passive_chan_scan_timeout_value=dwell_time)
        wifi_dut.interfaces.wifi.init(config_required=False)
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=dwell_time, scan_type=1, lp_mode=0)
        wlan_obj.scan(test_id='c551134')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
        wifi_dut.interfaces.wifi.oper_mode_opts.passive_chan_scan_timeout_value = dwell_time
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_and_active_scan_c551137(wifi_access_point, wifi_sniffer, wifi_dut, request, sniffer_filter,
                                                   sl_collections):
    """
    Verify Passive scan functionality connection initially with Passive scan disconnect and connect back using Active
    scan.
    """
    try:
        for scan_type in [1, 0]:
            logger().info(f"\n\n***************** Initiating test for scan type: {scan_type} *****************")
            wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                sl_collections, request, dwell_time=110, scan_type=scan_type, lp_mode=0)
            wlan_obj.scan(test_id='c551137')
            wlan_obj.join_to_ap()
            wlan_obj.sniffer_validation()
            wifi_dut.interfaces.wifi.leave()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 1000,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_max_dwell_time_1000ms_c551132(wifi_access_point, wifi_sniffer, wifi_dut, request,
                                                         sniffer_filter, sl_collections):
    """
    Verify Passive scan functionality by enabling dwell time to maximum value of 1000ms(1s)
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=1000, scan_type=1, lp_mode=0)
        wlan_obj.scan(test_id='c551132')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_func_probe_response_check_c551135(wifi_access_point, wifi_sniffer, wifi_dut, request,
                                                             sniffer_filter, sl_collections):
    """
    Negative Case : Verify Passive scan functionality if DUT did not receives any probe response whether DUT is
    switching to Active scan or not.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['deinit'])
@pytest.mark.end_state("wifi_dut", wifi=["reset"])
def test_wsdk_passive_scan_with_dwell_time_1001ms_c551136(wifi_dut, sl_collections):
    """
    Negative Case : Verify Passive scan functionality by enabling Dwell time to 1001msec.
    """
    try:
        wifi_dut.interfaces.wifi.set_wifi_config()
        logger().info(f"\nSetting dwell time: 1001ms in DUT")
        wifi_dut.interfaces.wifi.set_timeout_config(keep_alive_timeout_value=10, auth_assoc_timeout_value=100,
                                                    active_chan_scan_timeout_value=100,
                                                    passive_chan_scan_timeout_value=1001)
        wifi_dut.interfaces.wifi.init(expected_status=SLStatus.SL_STATUS_SI91X_WRONG_PARAMETERS)
        logger().info(f"Observed error code:'{hex(SLStatus.SL_STATUS_SI91X_WRONG_PARAMETERS)}' from DUT,"
                      f" when dwell time is set to more than maximum value")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_with_dwell_time_110ms_lp_chain_enabled_c551138(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                          request, sniffer_filter, sl_collections):
    """
    Verify Passive scan functionality with minimum dwell time 110ms and LP chain enabled , scan should happen in all
    channels.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1)
        wlan_obj.scan(test_id='c551138')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 1000,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_with_dwell_time_1000ms_lp_chain_disabled_c551139(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                            request, sniffer_filter, sl_collections):
    """
    Verify Passive scan functionality with maximum dwell time 1000ms and LP chain disabled, scan should happen only in
    single channel.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=1000, scan_type=1, lp_mode=0)
        wlan_obj.scan(all_ch_scan=False, test_id='c551139')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "region": Si91xRegion.FromUser,
        "region_code": Si91xRegionCode.Japan,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.wifi_access_point("raspi_wifi")
@pytest.mark.config('wifi_access_point', wifi={'interface': 'wlan0', 'region': 'Japan', 'channel': 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_in_japan_region_lp_chain_enabled_c551142(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                    request, sniffer_filter, sl_collections):
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
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1, ap_bssid=ap_bssid)
        wlan_obj.scan(all_ch_scan=False, test_id='c551142')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "region": Si91xRegion.FromUser,
        "region_code": Si91xRegionCode.Europe,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config('wifi_access_point', wifi={'region': 'Europe', 'channel': 12})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_in_europe_region_lp_chain_enabled_c551143(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                     request, sniffer_filter, sl_collections):
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
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1)
        wlan_obj.scan(all_ch_scan=False, test_id='c551143')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "region": Si91xRegion.FromUser,
        "region_code": Si91xRegionCode.US,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config('wifi_access_point', wifi={'region': 'US'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_in_us_region_lp_chain_enabled_c551144(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                 request, sniffer_filter, sl_collections):
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
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1)
        wlan_obj.scan(all_ch_scan=False, test_id='c551144')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "region": Si91xRegion.FromUser,
        "region_code": Si91xRegionCode.Korea,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.wifi_access_point("raspi_wifi")
@pytest.mark.config('wifi_access_point', wifi={'interface': 'wlan0', 'region': 'Korea', 'channel': 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_in_korea_region_lp_chain_enabled_c551145(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                    request, sniffer_filter, sl_collections):
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
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1, ap_bssid=ap_bssid)
        wlan_obj.scan(all_ch_scan=False, test_id='c551145')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "region": Si91xRegion.FromUser,
        "region_code": Si91xRegionCode.Worldwide,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config('wifi_access_point', wifi={'region': 'Asia'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_in_world_wide_domain_lp_chain_enabled_c551146(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                         request, sniffer_filter, sl_collections):
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
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1)
        wlan_obj.scan(all_ch_scan=False, test_id='c551146')
        wlan_obj.join_to_ap()
        wlan_obj.sniffer_validation()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_connect_disconnect_30min_lp_chain_disabled_c551140(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                              request, sniffer_filter, sl_collections):
    """
    Verify Passive scan functionality with LP chain disabled, Passive scan disconnect and connect back with passive
    scan only do it in loop for 30 minutes.
    """
    try:
        sw = Stopwatch()
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=0)
        while sw.elapsed_sec <= 1800:
            time_left = int((1800 - sw.elapsed_sec) / 60)
            logger().info(f"*************** Remaining time to complete test is: '{time_left}' minutes ***************")
            wlan_obj.scan(test_id='c551140')
            wlan_obj.join_to_ap(ps_enable=False)
            wlan_obj.sniffer_validation()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(60)
            logger().info("\n\n")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_and_active_scan_30min_lp_chain_enabled_c551147(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                          request, sniffer_filter, sl_collections):
    """
    Verify Passive scan functionality with LP chain enabled, Passive scan and active scan in loop for 30 minutes.
    """
    try:
        sw = Stopwatch()
        while sw.elapsed_sec <= 1800:
            time_left = int((1800 - sw.elapsed_sec) / 60)
            logger().info(f"*************** Remaining time to complete test is: '{time_left}' minutes ***************")
            for scan_type in [0, 1]:
                logger().info(f"******** Initiating test for scan type ---> {scan_type} ********")
                wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                    sl_collections, request, dwell_time=110, scan_type=scan_type,
                                                    lp_mode=1)
                wlan_obj.scan(test_id='c551147')
                wlan_obj.join_to_ap(ps_enable=False)
                wlan_obj.sniffer_validation()
                wifi_dut.interfaces.wifi.leave()
                time.sleep(60)
                logger().info("\n\n")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_connect_disconnect_30min_lp_chain_enabled_c551141(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                             request, sniffer_filter, sl_collections):
    """
    Verify Passive scan functionality with LP chain enabled, Passive scan disconnect and connect back with passive scan
    only do it in loop for 30 minutes.
    """
    try:
        sw = Stopwatch()
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "passive_chan_scan_timeout_value": 110,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wsdk_passive_scan_with_bg_scan_and_lp_chain_enabled_c551148(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                     request, sniffer_filter, sl_collections):
    """
    Verify Passive scan functionality with default dwell time and LP chain enabled and move to BGscan API.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=1)
        wlan_obj.join_to_ap()
        wlan_obj.dut_mac = wifi_dut.interfaces.wifi.get_mac_address()
        wlan_obj.sniffer_validation()

        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"unicast_probe_check_c551148")
        time.sleep(5)
        scan_time_threshold = (11 * 110 + 100) / 1000
        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=50, adv_trigger_level_change=4,
                                                                 adv_trigger_level=63, adv_passive_channel_time=50)
        scan_time = wifi_dut.interfaces.wifi.scan(scan_type=1, lp_mode=1, bgscan=True, bg_scan_periodicity=2,
                                                  measure_scan_time=True)[-1]
        scan_time = float(scan_time.split(':')[-1])
        assert scan_time <= scan_time_threshold, (f"Observed passive scan time is more than expected value:"
                                                  f"{scan_time_threshold} Seconds")
        logger().info(f"\n\n******** Time taken for passive scan is --> '{scan_time}' seconds, which is within the "
                      f"expected threshold value '{scan_time_threshold}' seconds ********")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("******** Checking for unicast probe request packet in sniffer capture ********")
        packet_filter1 = f"(wlan.fc.type_subtype == 4) && (wlan.sa == {wlan_obj.dut_mac}) && (wlan.da == {wlan_obj.ap_bssid})"
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
            "Found unicast probe request packet in sniffer capture, which is not expected"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
