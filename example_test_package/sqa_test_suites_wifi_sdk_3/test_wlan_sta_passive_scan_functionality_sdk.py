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


def logger():
    return get_logger(__name__)


class PassiveScanFunctionality:
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections, request,
                 dwell_time, scan_type, lp_mode=0, measure_scan_time=1):
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
        self.ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        self.dut_mac = None

    def scan(self):
        self.dut_mac = self.wifi_dut.interfaces.wifi.get_mac_address()
        if self.scan_type == 1:
            scan_time_threshold = ((11 * self.dwell_time) + 100) / 1000
            logger().info(f"Configuring the sniffer with channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=f"unicast_probe_check_{self.test_name[-7:]}")
            time.sleep(5)
            logger().info(
                f"************ Starting passive scan by enabling passive scan bit in scan request ************")
            scan_time = self.wifi_dut.interfaces.wifi.scan(scan_type=self.scan_type, lp_mode=self.lp_mode,
                                                           measure_scan_time=self.measure_scan_time)[-1]
            scan_time = float(scan_time.split(':')[-1])
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
            self.wifi_dut.interfaces.wifi.scan(scan_type=self.scan_type, measure_scan_time=self.measure_scan_time)

    def join_to_ap(self, ping_count=120):
        logger().info(f"\n\nConfiguring the sniffer with channel {self.wifi_access_point.interfaces.wifi.channel}")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
        time.sleep(3)
        self.sl_collections.connect(self.wifi_dut, self.wifi_access_point, retry_count=3)
        ip_config = self.sl_collections.configure_ip(self.wifi_dut, retry_count=3)[-1]
        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        status = self.sl_collections.ping(device_ip=device_ip, ping_count=ping_count, retry_count=3)
        assert status, "Failed to ping to DUT after powersave enabled"

    def sniffer_validation(self):
        logger().info("Stop sniffer capture finally")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.dut_mac,
                                                                                             da_addr=self.ap_bssid,
                                                                                             filter_name='power_mgmt_bit')
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.dut_mac,
                                                                                             da_addr=self.ap_bssid,
                                                                                             filter_name='association_request_HE')
        logger().info("******** Checking for power management bit in sniffer capture ********")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter2)['packet_count'], \
            "Unable to find power management bit 1 in sniffer"
        logger().info("******** Validating Assoc Req with HE information ********")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter3)['packet_count'], \
            'Unable to find Assoc Req  with HE capability in sniffer'


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
        wlan_obj.scan()
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
        wlan_obj.scan()
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
        wlan_obj.scan()
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
        wlan_obj.scan()
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
            wlan_obj.scan()
            wlan_obj.join_to_ap()
            wlan_obj.sniffer_validation()
            if scan_type:
                wifi_dut.interfaces.wifi.leave()
                wifi_dut.interfaces.wifi.deinit()
                wifi_dut.interfaces.wifi.init(config_required=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
