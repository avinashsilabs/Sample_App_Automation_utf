import pytest
from typing import Dict, List, Tuple
from pyshark.packet.layer import Layer
import time


@pytest.mark.parametrize(
    "capture_filter, capture_filename, inspect_during_capture", [
        (None, "no_filter", False),
        ("ether host 88:da:1a:e4:ba:44", "mac_filter", False),
        (None, "no_filter", True),
        ("ether host 88:da:1a:e4:ba:44", "mac_filter", True),
    ],
)
def test_sniffer_icmp_inspection(
    wifi_sniffer, wifi_access_point, wifi_dut, capture_filter, capture_filename, inspect_during_capture, logger
):
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )

    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
    )
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    wifi_dut.interfaces.wifi.ping(ip_config.gateway)
    wifi_dut.interfaces.wifi.leave()
    if not inspect_during_capture:
        wifi_sniffer.interfaces.capture.stop_capture()
    else:
        # to ensure captured packets are flushed to file
        time.sleep(2)

    # decrypt with proper decryption key & verify that we can see the ICMP/DHCP packets
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    packet_layer_stats, eapol_layers = iterate_packets(
        wifi_sniffer.interfaces.capture,
        decryption_key,
        ["eapol", "dhcp", "icmp"],
        logger,
    )

    logger.info(packet_layer_stats)
    # Note: if the sniffer was unable to capture either of the first two EAPOL
    # message packets, we will be unable to properly decrypt the PTK and thus the assertions
    # below will fail
    if (
        len(eapol_layers) < 2
        or eapol_layers[0].get("wlan_rsna.keydes.msgnr") != "1"
        or eapol_layers[1].get("wlan_rsna.keydes.msgnr") != "2"
    ):
        logger.warning(
            "Missed capture of first 2 EAPOL messages -- cannot decrypt packets"
        )
    else:
        assert "icmp" in packet_layer_stats and packet_layer_stats["icmp"] > 0
        assert "dhcp" in packet_layer_stats and packet_layer_stats["dhcp"] > 0

    # decrypt with wrong decryption key & verify that we don't see any ICMP packets
    decryption_key = f"wrong_password:wrong_ssid"
    packet_layer_stats, _ = iterate_packets(
        wifi_sniffer.interfaces.capture, decryption_key, [], logger
    )
    assert "icmp" not in packet_layer_stats
    assert "dhcp" not in packet_layer_stats
    assert packet_layer_stats["total"] > 0


def test_live_sniffer(
    wifi_sniffer, wifi_access_point, wifi_dut
):
    with wifi_sniffer.interfaces.live_capture as live_capture:
        live_capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        timeout = 30
        start = time.time()
        live_capture.start_live_capture(timeout=timeout, capture_file=f"live_sniffing", filter_layer_name='wlan',
                                        filter_field='fc.type.type_subtype', filter_val='12')
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        ip_config = wifi_dut.interfaces.wifi.start_ip()
        wifi_dut.interfaces.wifi.ping(ip_config.gateway)
        wifi_dut.interfaces.wifi.leave()
        is_packet_found = False
        while time.time() - start < timeout:
            packet = live_capture.get_packet()
            if packet is not None:
                is_packet_found = True
                live_capture.stop_capture()
                break
        assert is_packet_found


def iterate_packets(
    capture_interface, decryption_key: str, print_layers: list, logger
) -> Tuple[Dict[str, int], List[Layer]]:
    packet_layer_stats = {}
    eapol_layers = []
    total_packet_count = 0
    for packet in capture_interface.iter_packets(
        decrypt_packets=True,
        encryption_type="WPA-PWD",
        decryption_key=decryption_key,
    ):
        total_packet_count += 1
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "eapol":
                eapol_layers.append(layer)
            if layer_name in print_layers:
                logger.info(layer)
            if not layer_name in packet_layer_stats:
                packet_layer_stats[layer_name] = 0
            packet_layer_stats[layer_name] += 1
    packet_layer_stats["total"] = total_packet_count
    return packet_layer_stats, eapol_layers
