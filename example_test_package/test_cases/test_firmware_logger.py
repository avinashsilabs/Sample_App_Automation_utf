import pytest

from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116Band, RS9116AsyncEventType


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "fw_log_enable": 1,
        "fw_tsf_granularity_us": 10,
        "g_common_log_level": 4,
        "g_cm_pm_log_level": 4,
        "g_wlan_lmac_log_level": 4,
        "g_wlan_umac_log_level": 4,
        "g_wlan_netstack_log_level": 4,
        "g_bt_ble_ctrl_log_level": 4,
        "g_bt_ble_stack_log_level": 4,
        "security": "WPA",
        "ssid": "RS9116_AP",
        "passphrase": "12345678",
        "channel": 36,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA",
        "ssid": "RS9116_AP",
        "passphrase": "12345678",
        "channel": 36,
    },
)
def test_wifi_join_9116_ap_5g(wifi_dut, wifi_client, logger):
    wifi_dut.interfaces.wifi.start_ap()
    wifi_client.interfaces.wifi.join()
    assert (
            wifi_client.interfaces.wifi.ping(
                server_ip=wifi_client.interfaces.wifi.client_gateway_ip
            )
            < 1
    )

    events = wifi_dut.interfaces.wifi.get_async_events()
    for event in events:
        if event.event_type == RS9116AsyncEventType.FIRMWARE_LOG:
            logger.info(f"Firmware log : {event.event_data}")