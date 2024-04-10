import time
import pytest
from utf.utils.logger import get_logger

from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xAwsQos,
    Si91xCertificateType,
    Si91xModuleType,
    Si91xCertIdentifier,
    Si91xBTFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
            | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default
            | Si91xTCPIPFeatureBitMap.SSL
            | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
            | Si91xTCPIPFeatureBitMap.DNSClient
            | Si91xTCPIPFeatureBitMap.Ping,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
            | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
            | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
            | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
            | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
            | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(1),
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS
            | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC
            | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS
            | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV
            | Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID
            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX
            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS
            | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE
            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS
            | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
            | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
            | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
            | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
            | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
            "ca_cert": [
                "azure_baltimore_ca.pem",
                "SL_NET_SIGNING_CERTIFICATE",
                "SL_NET_TLS_SERVER_CREDENTIAL_START",
            ],
            "client_cert": [
                "azure_client_cert.pem",
                "SL_NET_CERTIFICATE",
                "SL_NET_TLS_CLIENT_CREDENTIAL_START",
            ],
            "client_key": [
                "azure_client_key.pem",
                "SL_NET_PRIVATE_KEY",
                "SL_NET_TLS_CLIENT_CREDENTIAL_START",
            ],
        },
    ),
    # pytest.mark.start_state("wifi_dut", wifi=['init']),
    # pytest.mark.start_state("wifi_access_point", wifi="ap_enabled"),
]


@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_azure_dut_to_cloud(
    wifi_access_point, wifi_dut, azure_iot_client, sl_collections, logger, timeout=120
):
    logger.info("connecting to access point.....")
    dut_addr = sl_collections.join_to_wifi_network(
        wifi_dut,
        wifi_access_point=wifi_access_point,
        ping_after_power_save=True,
        retry_count=3,
        associated=wifi_dut.interfaces.wifi.associated,
    )
    # host_ip= wifi_dut.interfaces.wifi.dns_get("silabssample.azure-devices.net")

    wifi_dut.interfaces.wifi.start_ip()
    wifi_dut.interfaces.wifi.socket("AF_INET", "SOCK_STREAM", "IPPROTO_TCP")
    wifi_dut.interfaces.wifi.bsdSetSocketOpt(0, "SOL_TCP", "TCP_ULP", "tls")
    wifi_dut.interfaces.wifi.bsdSetSocketOption(0)
    wifi_dut.interfaces.wifi.bsdSocketConnect(0, "40.78.196.98")
    wifi_dut.interfaces.wifi.azure_iot_init(
        "SilabsHYDAzure.azure-devices.net",
        "symmetric_device",
        4002,
        0,
        "Vn0P8z6gqR5ShVvv6ouQOT0eAcQFQB9GLfG0teX+ZpI=",
    )
    logger.info("init successful")
    time.sleep(2)
    with azure_iot_client.interfaces.hub.start_receiving_events():
        wifi_dut.interfaces.wifi.azure_iot_publish("hi")
    assert "hi" in azure_iot_client.interfaces.hub.received_messages


def test_azure_cloud_to_dut(
    wifi_access_point, wifi_dut, azure_iot_client, sl_collections, logger, timeout=120
):
    logger.info("connecting to access point.....")
    dut_addr = sl_collections.join_to_wifi_network(
        wifi_dut,
        wifi_access_point=wifi_access_point,
        ping_after_power_save=True,
        retry_count=3,
        associated=wifi_dut.interfaces.wifi.associated,
    )
    # host_ip= wifi_dut.interfaces.wifi.dns_get("silabssample.azure-devices.net")

    wifi_dut.interfaces.wifi.start_ip()
    wifi_dut.interfaces.wifi.socket("AF_INET", "SOCK_STREAM", "IPPROTO_TCP")
    wifi_dut.interfaces.wifi.bsdSetSocketOpt(0, "SOL_TCP", "TCP_ULP", "tls")
    wifi_dut.interfaces.wifi.bsdSetSocketOption(0)
    wifi_dut.interfaces.wifi.bsdSocketConnect(0, "40.78.196.98")
    wifi_dut.interfaces.wifi.azure_iot_init(
        "SilabsHYDAzure.azure-devices.net",
        "symmetric_device",
        4002,
        0,
        "Vn0P8z6gqR5ShVvv6ouQOT0eAcQFQB9GLfG0teX+ZpI=",
    )
    logger.info("init successful")
    time.sleep(2)
    wifi_dut.interfaces.wifi.azure_iot_subscribe(timeout=timeout)
    azure_iot_client.interfaces.hub.send_message_to_device(
        "sample_raspi", "Sending c2d message 1"
    )
    # TODO : how to assert the recieved message on wifi_dut against the sent message
    wifi_dut.interfaces.wifi.azure_iot_recv()
    wifi_dut.interfaces.azure_iot_unsubscribe()
