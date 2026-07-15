"""
Standby power measurement for MQTT over WebSockets scenarios.

Test cases:
  1. TWT enabled, iTWT interval 60s, MQTT keep-alive (MQTT over WebSockets)
  2. Announced TWT enabled, iTWT interval 60s, MQTT keep-alive (MQTT over WebSockets)
  3. AWS MQTT over WebSockets standby

Logic reused from:
  - test_twt_power_mcu_advanced_sdk.py (C129925 / C129926 / AWS TWT standby)
  - test_twt_power_mcu_adv_mqtt_5mins_sdk.py (TWT + MQTT KA standby)
  - test_wlan_power_mqtt_diff_pwd_sdk.py (power capture helpers)
  - test_mqtt_power_enablement_sdk.py (CSV / transform pattern)
"""

import random
import string
import time

import pytest
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus
from retry import retry

from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.power.test_wlan_power_mqtt_diff_pwd_sdk import (
    M4_Sleep_Thread,
    Power_Measurement_Thread,
    WlanThread,
    __print_throughput,
)
from utf import TransformFileProperties
from utf.utf_config import UtfConfig
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xAwsQos,
    Si91xBTFeatureBitMap,
    Si91xCoexMode,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xOperatingMode,
    Si91xTCPIPFeatureBitMap,
)

pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]

POWER_CAPTURE_TIME = 90
M4_SLEEP_TIME = 300000
MQTT_KEEP_ALIVE_SEC = 60

# iTWT ~60s: wake_int_mantissa * 2^wake_int_exp us ≈ 7500 * 8192 ≈ 61.44s
ITWT_60S_PARAMS = {
    "wake_duration": 0x60,
    "wake_duration_tol": 0x60,
    "wake_int_exp": 13,
    "wake_int_exp_tol": 13,
    "wake_int_mantissa": 0x1D4C,
    "wake_int_mantissa_tol": 0x1D4C,
    "implicit_twt": 1,
    "triggered_twt": 0,
    "negotiation_type": 0,
    "twt_channel": 0,
    "twt_protection": 0,
    "twt_flow_id": 1,
    "restrict_tx_outside_tsp": 1,
    "twt_retry_limit": 6,
    "twt_retry_interval": 10,
    "req_type": 1,
    "twt_enable": 1,
    "wake_duration_unit": 0,
}

POWER_TRANSFORM = pytest.mark.transform_test_results(
    TransformFileProperties(file_name="perf_power_consumption_medium.csv", data_type="power_performance")
)

MQTT_WS_WIFI_CONFIG = {
    "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    "oper_mode": Si91xOperatingMode.Default,
    "coex_mode": Si91xCoexMode.WLANOnly,
    "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation |
                Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
    "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                      Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
    "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
    "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                           Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode |
                           Si91xExtCustomFeatureBitMap.DisableDebugPrints,
    "bt_features": 0,
    "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                          Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
    "ble_features": 0,
    "ble_custom_ext_features": 0,
    "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
}

AWS_MQTT_WS_WIFI_CONFIG = {
    "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    "oper_mode": Si91xOperatingMode.WiFiClient,
    "coex_mode": Si91xCoexMode.WLANOnly,
    "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
    "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                      Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.DNSClient |
                      Si91xTCPIPFeatureBitMap.Ping,
    "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
    "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                           Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                           Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
    "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                          Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                          Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT |
                          Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
    "bt_features": Si91xBTFeatureBitMap.Default,
    "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                       Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                       Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    "set_send_feature_frame": True,
    "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
}


def logger():
    return get_logger(__name__)


def text_generator(size=10):
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def _generate_power_csv(power_meter, performance_data, custom_performance_fixture, request, memory_configuration):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = (
        obtained_test_name.split("[")[0]
        if obtained_test_name and "[" in obtained_test_name
        else obtained_test_name
    )
    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results
    )
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(
        test_name=test_name,
        opn=opn,
        build_number=build_number,
        memory_configuration=memory_configuration,
        parsed_result=parsed_result["Output"],
        file_path=performance_file_root_dir,
        file_name=perf_file_name,
    )


class MqttWsTwTPowerStandby(ThreadBase):
    """Associate, connect MQTT with KA, enable iTWT (~60s), measure standby current."""

    def __init__(
        self,
        wifi_dut=None,
        wifi_access_point=None,
        sl_collections=None,
        power_meter=None,
        mqtt_server=None,
        announced_twt=False,
        keep_alive_interval=MQTT_KEEP_ALIVE_SEC,
        capture_time=POWER_CAPTURE_TIME,
        m4_sleep_time=M4_SLEEP_TIME,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.power_meter = power_meter
        self.mqtt_server = mqtt_server
        self.announced_twt = announced_twt
        self.keep_alive_interval = keep_alive_interval
        self.capture_time = capture_time
        self.m4_sleep_time = m4_sleep_time

    def _configure_itwt_60s(self):
        twt_type = "Announced" if self.announced_twt else "Unannounced"
        logger().info(f"Enabling {twt_type} iTWT with ~60s wake interval")
        self.wifi_dut.interfaces.wifi.set_twt(
            **ITWT_60S_PARAMS,
            un_announced_twt=0 if self.announced_twt else 1,
        )
        time.sleep(2)

    def run(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")

        if dut != "si917_ncp_sl_wifi":
            logger().info("M4-TA secure handshake")
            self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
        time.sleep(2)

        wlan_obj = WlanThread(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            sl_collections=self.sl_collections,
            without_dtim=True,
        )
        m4_obj = None
        if dut != "si917_ncp_sl_wifi":
            m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time)
        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter, capture_time=self.capture_time)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        logger().info(f"Configuring MQTT client with keep_alive={self.keep_alive_interval}s")
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_ws_client_power",
            keep_alive_interval=self.keep_alive_interval,
            is_retained=False,
        )
        logger().info("DUT connecting to MQTT server (MQTT over WebSockets use-case)")
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(5)

        self._configure_itwt_60s()

        logger().info("Setting filter broadcast command")
        self.wifi_dut.interfaces.wifi.set_filter_broadcast()
        time.sleep(2)

        logger().info("Enabling TA power save")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
        time.sleep(2)

        if dut != "si917_ncp_sl_wifi":
            m4_obj.start()
        time.sleep(10)

        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()

        try:
            self.wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
        except Exception as err:
            logger().info(f"MQTT disconnect during cleanup: {err}")
        time.sleep(5)


class AwsMqttWsPowerStandby(ThreadBase):
    """Associate, connect AWS MQTT, then measure standby current."""

    def __init__(
        self,
        wifi_dut=None,
        wifi_access_point=None,
        sl_collections=None,
        power_meter=None,
        aws_iot_client=None,
        capture_time=POWER_CAPTURE_TIME,
        m4_sleep_time=M4_SLEEP_TIME,
        topic="mqtt_ws_aws_power_topic",
        client_id="mqtt_ws_aws_power_client",
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.power_meter = power_meter
        self.aws_iot_client = aws_iot_client
        self.capture_time = capture_time
        self.m4_sleep_time = m4_sleep_time
        self.topic = topic
        self.client_id = client_id

    @retry(Exception, delay=15, tries=5)
    def _subscribe_from_dut(self):
        logger().info(f"DUT subscribing on AWS topic '{self.topic}' qos={Si91xAwsQos.QOS0}")
        self.wifi_dut.interfaces.wifi.aws_iot_mqtt_subscribe(
            topic_name=self.topic, qos=Si91xAwsQos.QOS0, timeout=120
        )

    @retry(Exception, delay=10, tries=3)
    def _connect_aws_from_raspi(self):
        logger().info("Connecting to AWS server from aws_iot_client")
        self.aws_iot_client.interfaces.aws_iot.aws_iot_connect()
        time.sleep(5)
        status = self.aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, "Connecting to AWS server from aws_iot_client failed"

    @retry(Exception, delay=10, tries=3)
    def _subscribe_from_raspi(self):
        logger().info(f"aws_iot_client subscribing on topic '{self.topic}'")
        self.aws_iot_client.interfaces.aws_iot.received_messages.clear()
        self.aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(self.topic, qos=Si91xAwsQos.QOS0)
        status = self.aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, f"Subscribe on topic '{self.topic}' failed from aws_iot_client"

    @retry(Exception, delay=15, tries=1)
    def _publish_from_dut(self, message):
        logger().info(f"DUT publishing on AWS topic '{self.topic}'")
        self.wifi_dut.interfaces.wifi.aws_iot_mqtt_publish(
            topic_name=self.topic, qos=Si91xAwsQos.QOS0, payload=message, timeout=120
        )

    def run(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        messages = [text_generator(size=10) for _ in range(2)]

        if dut != "si917_ncp_sl_wifi":
            logger().info("M4-TA secure handshake")
            self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
        time.sleep(2)

        wlan_obj = WlanThread(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            sl_collections=self.sl_collections,
            without_dtim=True,
        )
        m4_obj = None
        if dut != "si917_ncp_sl_wifi":
            m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time)
        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter, capture_time=self.capture_time)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Initiating AWS MQTT connection from DUT")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        self.wifi_dut.interfaces.wifi.aws_iot_mqtt_init(client_id=self.client_id)
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.aws_iot_mqtt_connect(timeout=120)
        time.sleep(5)

        self._subscribe_from_dut()
        self._connect_aws_from_raspi()
        self._subscribe_from_raspi()

        for count, msg in enumerate(messages):
            logger().info(
                f"DUT publishing message{count + 1} on topic '{self.topic}' "
                f"len={len(msg)} msg='{msg}'"
            )
            self._publish_from_dut(msg)
            time.sleep(3)

        time.sleep(2)
        logger().info("Setting filter broadcast command")
        self.wifi_dut.interfaces.wifi.set_filter_broadcast()
        time.sleep(2)

        logger().info("Enabling TA power save after AWS MQTT setup")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
        time.sleep(2)

        if dut != "si917_ncp_sl_wifi":
            m4_obj.start()
        time.sleep(10)

        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()

        try:
            self.wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
        except Exception as err:
            logger().info(f"AWS MQTT disconnect during cleanup: {err}")
        time.sleep(5)


@POWER_TRANSFORM
@pytest.mark.config("wifi_dut", wifi=MQTT_WS_WIFI_CONFIG)
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_mqtt_ws_standby_twt_60s_mqtt_ka(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    mqtt_server,
    performance_data,
    custom_performance_fixture,
    request,
):
    """Measure standby with TWT enabled, iTWT interval 60s, MQTT KA (MQTT over WebSockets)."""
    try:
        stdby_obj = MqttWsTwTPowerStandby(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            power_meter=power_meter,
            mqtt_server=mqtt_server,
            announced_twt=False,
            keep_alive_interval=MQTT_KEEP_ALIVE_SEC,
        )
        stdby_obj.start()
        stdby_obj.wait_for_exit()
        _generate_power_csv(
            power_meter, performance_data, custom_performance_fixture, request, "test_352K_M4SS_320K"
        )
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@POWER_TRANSFORM
@pytest.mark.config("wifi_dut", wifi=MQTT_WS_WIFI_CONFIG)
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_mqtt_ws_standby_announced_twt_60s_mqtt_ka(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    mqtt_server,
    performance_data,
    custom_performance_fixture,
    request,
):
    """Measure standby with Announced TWT enabled, iTWT interval 60s, MQTT KA (MQTT over WebSockets)."""
    try:
        stdby_obj = MqttWsTwTPowerStandby(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            power_meter=power_meter,
            mqtt_server=mqtt_server,
            announced_twt=True,
            keep_alive_interval=MQTT_KEEP_ALIVE_SEC,
        )
        stdby_obj.start()
        stdby_obj.wait_for_exit()
        _generate_power_csv(
            power_meter, performance_data, custom_performance_fixture, request, "test_352K_M4SS_320K"
        )
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@POWER_TRANSFORM
@pytest.mark.config("wifi_dut", wifi=AWS_MQTT_WS_WIFI_CONFIG)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_mqtt_ws_standby_aws_mqtt(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    aws_iot_client,
    performance_data,
    custom_performance_fixture,
    request,
):
    """Measure standby with AWS MQTT over WebSockets."""
    try:
        stdby_obj = AwsMqttWsPowerStandby(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            power_meter=power_meter,
            aws_iot_client=aws_iot_client,
        )
        stdby_obj.start()
        stdby_obj.wait_for_exit()
        _generate_power_csv(
            power_meter, performance_data, custom_performance_fixture, request, "test_352K_M4SS_320K"
        )
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
