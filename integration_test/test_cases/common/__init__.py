import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import (
    Standard,
    Channel,
    Cipher,
    WirelessBand,
    WiFiScanResult,
    SecurityMode,
)
from typing import List

__all__ = ["run_ap_configuration_test"]


def logger():
    return get_logger("integration_test::common")


def run_ap_configuration_test(
    wifi_client,
    wifi_access_point,
    security,
    standard,
    channel,
    cipher,
    ssid=None,
):
    ap_iface = wifi_access_point.interfaces.wifi
    client_iface = wifi_client.interfaces.wifi
    kwargs = {}
    if ssid is not None:
        kwargs["ssid"] = ssid

    logger().info(
        f"Setting up AP for security={security} standard={standard} channel={channel} cipher={cipher}"
    )
    ap_iface.start_ap(
        security=security,
        standard=standard,
        channel=channel,
        cipher=cipher,
        **kwargs,
    )
    logger().info(f"Scanning for AP with client")
    sw = Stopwatch()
    max_time = 30
    while True:
        try:
            networks = client_iface.scan()  # type: List[WiFiScanResult]
            found_networks = [n for n in networks if n.ssid == ap_iface.ssid]
            assert any(found_networks), "Unable to find network in scan results"
            network = found_networks[0]
            if not ap_iface.auto_channel:
                assert (
                    network.rf_channel == ap_iface.channel
                ), f"Received wrong channel -- expected {ap_iface.channel} but found {network.rf_channel}"
            else:
                assert WirelessBand.get_band_for_channel(
                    network.rf_channel
                ) == WirelessBand.get_band_for_channel(
                    ap_iface.channel
                ), f"Band was unexpected -- expected {WirelessBand.get_band_for_channel(network.rf_channel)} but found {WirelessBand.get_band_for_channel(ap_iface.channel)}"
            if ap_iface.security == SecurityMode.Open:
                assert (
                    network.security_mode.upper() == ap_iface.security.name.upper()
                ), f"Received wrong security mode -- expected {ap_iface.security.name.upper()} but found {network.security_mode.upper()}"
            elif ap_iface.security in [
                SecurityMode.WPA,
                SecurityMode.WPA2,
            ]:
                if ap_iface.cipher == Cipher.TKIP_AES or ap_iface.cipher == Cipher.TKIP:
                    assert (
                        network.security_mode.upper() == SecurityMode.WPA2.name.upper()
                        or network.security_mode.upper()
                        == SecurityMode.WPA.name.upper()
                    ), f"Received wrong security mode -- expected WPA2 or WPA but found {network.security_mode.upper()}"
                else:
                    assert (
                        network.security_mode.upper() == ap_iface.security.name.upper()
                    ), f"Received wrong security mode -- expected {ap_iface.security.name.upper()} but found {network.security_mode.upper()}"
            elif ap_iface.security == SecurityMode.WPAWPA2MixedMode:
                assert (
                    network.security_mode.upper() == SecurityMode.WPA2.name.upper()
                    or network.security_mode.upper() == SecurityMode.WPA.name.upper()
                ), f"Received wrong security mode -- expected WPA2 or WPA but found {network.security_mode.upper()}"
            break
        except AssertionError as e:
            if sw.elapsed_sec > max_time:
                raise
            else:
                logger().info(str(e) + " -- retrying scan")
    logger().info(f"Joining client to AP")
    client_iface.join_ap(wifi_access_point)
    logger().info(f"Join successful")
    client_iface.leave()