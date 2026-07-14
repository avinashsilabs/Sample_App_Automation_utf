import random
import string
import time

import pytest

from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.mqtt.test_mqtt_sdk import logger
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.power.test_wlan_power_advanced_extended_scan_sdk import (
    device_scan_result,
)
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.power.test_wlan_power_mqtt_diff_pwd_sdk import (
    M4_Sleep_Thread,
    Power_Measurement_Thread,
    WlanThread,
    __print_throughput,
)
from utf import TransformFileProperties
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utf_config import UtfConfig
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xBLECustomFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xCoexMode,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xJoinFeatureBitMap,
    Si91xMqttQos,
    Si91xOperatingMode,
    Si91xTCPIPFeatureBitMap,
)


pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]

PAYLOAD_1K = 1024
PAYLOAD_10K = 10240
MQTT_RX_TOPIC = "mqtt_power_rx_topic"
POWER_CAPTURE_TIME = 90
M4_SLEEP_TIME = 300000

MQTT_POWER_WIFI_CONFIG = {
    "oper_mode": Si91xOperatingMode.Default,
    "coex_mode": Si91xCoexMode.WLANOnly,
    "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation |
                Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
    "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                      Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
    "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
    "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                           # Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                           Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
    "bt_features": 0,
    "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                          Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
    "ble_features": 0,
    "ble_custom_ext_features": 0,
    "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                       Si91xConfigFeatureBitMap.EnahanceMaxPsp,
}

MQTT_POWER_TLS_WIFI_CONFIG = {
    **MQTT_POWER_WIFI_CONFIG,
    "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
    "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                      Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
    "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                           Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                          Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature |
                          Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    "set_send_feature_frame": True,
    "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
}

MQTT_POWER_BLE_WIFI_CONFIG = {
    "oper_mode": Si91xOperatingMode.WiFiClient,
    "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
    "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled |
                Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
    "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                      Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
    "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
    "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                           Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                           Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode |
                           Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                           Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                           Si91xExtCustomFeatureBitMap.FeatureLowPower,
    "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                          Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
    "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    "bt_features": Si91xBTFeatureBitMap.Default,
    "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
    "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                               Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                               Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                               Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    "enable_ble_power_index_params": 1,
    "power_index": 63,
    "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
}

POWER_TRANSFORM = pytest.mark.transform_test_results(
    TransformFileProperties(file_name="perf_power_consumption_medium.csv", data_type="power_performance")
)


class MqttRxPublisherThread(ThreadBase):
    """Publish MQTT messages from host client at a fixed interval during power capture."""

    def __init__(self, mqtt_client=None, topic=None, message=None, qos=None,
                 publish_interval_sec=10, duration_sec=POWER_CAPTURE_TIME):
        super().__init__()
        self.mqtt_client = mqtt_client
        self.topic = topic
        self.message = message
        self.qos = qos
        self.publish_interval_sec = publish_interval_sec
        self.duration_sec = duration_sec

    def run(self):
        sw = Stopwatch()
        while sw.elapsed_sec < self.duration_sec:
            logger().info(f"MQTT client publishes {len(self.message)} bytes to {self.topic}")
            self.mqtt_client.interfaces.mqtt.mqtt_client_publish(
                topic=self.topic, payload=self.message, qos=self.qos
            )
            time.sleep(self.publish_interval_sec)


class MqttRxPowerStandby(ThreadBase):
    """Associate, subscribe on DUT, receive MQTT traffic, and measure standby current."""

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, power_meter=None,
                 mqtt_server=None, mqtt_client=None, ble_client=None, payload_size=PAYLOAD_10K,
                 publish_interval_sec=10, qos=Si91xMqttQos.QOS0, ta_powersave=False, twt_rx_latency=None,
                 tls_enabled=False, ble_connected=False, listen_interval_power=None,
                 capture_time=POWER_CAPTURE_TIME, m4_sleep_time=M4_SLEEP_TIME):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.power_meter = power_meter
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.ble_client = ble_client
        self.payload_size = payload_size
        self.publish_interval_sec = publish_interval_sec
        self.qos = qos
        self.ta_powersave = ta_powersave
        self.twt_rx_latency = twt_rx_latency
        self.tls_enabled = tls_enabled
        self.ble_connected = ble_connected
        self.listen_interval_power = listen_interval_power
        self.capture_time = capture_time
        self.m4_sleep_time = m4_sleep_time
        self.message = "".join(random.choices(string.ascii_uppercase + string.digits, k=self.payload_size))

    def _setup_ble_connection(self):
        conn_params = {
            "min_conn_interval": 0xa0,
            "max_conn_interval": 0xa0,
            "conn_latency": 0,
            "supervision_timeout": 3200,
        }
        with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_mqtt_power_ble_{int(time.time())}.log",
        ) as bt_logs:
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            self.wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name="Silabsautomation")
            self.wifi_dut.interfaces.wifi.bt_get_local_name()
            self.wifi_dut.interfaces.wifi.ble_start_advertising(
                ble_adv_type=128, ble_adv_int_min=2048, ble_adv_int_max=2048, ble_adv_channel_map=7
            )
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"
            scan_result = device_scan_result()
            device_found = scan_result.check_for_devices_in_scanned_results(
                ble_client=self.ble_client,
                bt_dut_address=bt_dut_address,
                adv_data=self.wifi_dut.interfaces.wifi.ble_advertising_data,
            )
            assert device_found, "DUT not found in scan results"
            self.ble_client.interfaces.bluetooth.stop_scanning()
            time.sleep(5)
            self.ble_client.interfaces.bluetooth.connect(
                dev_addr=bt_dut_address,
                min_conn_interval=conn_params["min_conn_interval"],
                max_conn_interval=conn_params["max_conn_interval"],
                conn_latency=conn_params["conn_latency"],
                supervision_timeout=conn_params["supervision_timeout"],
            )
            time.sleep(10)
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            ble_conn_config = bt_logs.read_ble_connection_params(conn_params)
            assert ble_conn_config["Status"] == "Success"
            assert ble_conn_config["max_conn_interval"] == conn_params["max_conn_interval"]

    def _configure_twt(self):
        logger().info(f"Enabling TWT auto selection with rx_latency={self.twt_rx_latency}ms")
        self.wifi_dut.interfaces.wifi.twt_auto_config(
            twt_enable=1,
            average_tx_throughput="\"0\"",
            tx_latency="\"0\"",
            rx_latency=self.twt_rx_latency,
            device_average_throughput=20000,
            estimated_extra_wake_duration_percent="\"0\"",
            twt_tolerable_deviation=10,
            default_wake_interval_ms=1024,
            default_minimum_wake_duration_ms=8,
            beacon_wake_up_count_after_sp=2,
        )
        time.sleep(5)

    def run(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")

        if dut != "si917_ncp_sl_wifi":
            logger().info("M4-TA secure handshake")
            self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
        time.sleep(2)

        if self.ble_connected:
            self._setup_ble_connection()

        if self.ta_powersave:
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin
            )
            self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=1000)

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
        mqtt_config = {
            "client_id": "Si91x_mqtt_client_power",
            "qos": int(self.qos),
            "keep_alive_interval": 55,
            "is_retained": False,
        }
        if self.tls_enabled:
            mqtt_config.update(server_port=8883, is_connection_encrypted=True)
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(**mqtt_config)
        logger().info("DUT connecting to MQTT server")
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(5)
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info(f"DUT subscribes to topic {MQTT_RX_TOPIC} with qos={self.qos}")
        self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=MQTT_RX_TOPIC, qos=self.qos)
        time.sleep(3)

        if self.twt_rx_latency is not None:
            self._configure_twt()

        logger().info("Setting filter broadcast command")
        self.wifi_dut.interfaces.wifi.set_filter_broadcast()
        time.sleep(2)

        pub_obj = MqttRxPublisherThread(
            mqtt_client=self.mqtt_client,
            topic=MQTT_RX_TOPIC,
            message=self.message,
            qos=self.qos,
            publish_interval_sec=self.publish_interval_sec,
            duration_sec=self.capture_time + 5,
        )
        pub_obj.start()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.start()
            time.sleep(2)

        pm_obj.start()
        pm_obj.wait_for_exit()
        pub_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()

        msgs = self.wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
        assert len(msgs) >= 1, "DUT did not receive any MQTT messages during power capture"
        assert msgs[0].topic == MQTT_RX_TOPIC, "DUT received message on unexpected topic"
        time.sleep(5)


def _run_mqtt_rx_power_test(
    power_meter, wifi_access_point, wifi_dut, sl_collections, mqtt_server, mqtt_client,
    performance_data, custom_performance_fixture, request, **kwargs
):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split("[")[0] if obtained_test_name and "[" in obtained_test_name else obtained_test_name
    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})

    stdby_obj = MqttRxPowerStandby(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        sl_collections=sl_collections,
        power_meter=power_meter,
        mqtt_server=mqtt_server,
        mqtt_client=mqtt_client,
        **kwargs,
    )
    stdby_obj.start()
    stdby_obj.wait_for_exit()

    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results
    )
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(
        test_name=test_name,
        opn=opn,
        build_number=build_number,
        memory_configuration="test_352K_M4SS_320K",
        parsed_result=parsed_result["Output"],
        file_path=performance_file_root_dir,
        file_name=perf_file_name,
    )


class StandByAssociatedMQTTTopicDiffLength(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, power_meter=None,
                 mqtt_server=None, mqtt_client=None, capture_time=75, m4_sleep_time=300000):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.power_meter = power_meter
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.capture_time = capture_time
        self.m4_sleep_time = m4_sleep_time

    def run(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")

        if dut != "si917_ncp_sl_wifi":
            logger().info("M4-TA secure handshake")
            self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

        time.sleep(2)
        self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin
        )
        self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=1000)

        wlan_obj = WlanThread(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            sl_collections=self.sl_collections,
            without_dtim=True,
        )

        if dut != "si917_ncp_sl_wifi":
            m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time)
        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter, capture_time=self.capture_time)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client",
            qos=1,
        )
        logger().info("Both DUT and third-party mqtt client connect to MQTT server")
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt,
            send_credentials=True,
            username="mytesttopic",
            password="aaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppfdssdgj",
        )
        time.sleep(25)
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt,
            username="mytesttopic",
            password="aaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjcabaxvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppfdssdgj",
        )
        time.sleep(5)

        for length in [62, 100, 122, 201]:
            topic = "".join(random.choices(string.ascii_uppercase + string.digits, k=length))
            message = "".join(random.choices(string.ascii_uppercase + string.digits, k=1000))
            self.mqtt_client.interfaces.mqtt.received_messages.clear()
            logger().info(f"Topic Length : {length} bytes")
            logger().info("DUT and MQTT client subscribe to the topic")
            self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
            self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
            time.sleep(3)

            logger().info("DUT publishes message over the topic")
            self.wifi_dut.interfaces.mqtt.mqtt_client_publish(
                topic=topic,
                message=message,
                qos=Si91xMqttQos.QOS1,
                timeout=20,
            )
            time.sleep(3)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break

            assert len(msgs) == 1, "No message is received by mqtt-client"
            assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[0].payload.decode() == message, (
                "No message is received by mqtt-client on subscribed topic or message received is wrong"
            )
            assert msgs[0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"

            logger().info("DUT unsubscribes to the topic")
            self.wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
            time.sleep(2)

        logger().info("Setting filter broadcast command")
        self.wifi_dut.interfaces.wifi.set_filter_broadcast()
        time.sleep(2)

        logger().info("Enabling TA power save")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save", listen_interval=1)
        time.sleep(2)

        if dut != "si917_ncp_sl_wifi":
            m4_obj.start()
            time.sleep(2)

        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()

        time.sleep(10)


# ********************************************************************************************************************
# MQTT RX power measurement test cases
# ********************************************************************************************************************


@POWER_TRANSFORM
@pytest.mark.config("wifi_dut", wifi=MQTT_POWER_WIFI_CONFIG)
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_mqtt_power_rx_10k_qos0_interval_10s_C978092(
    power_meter, wifi_access_point, wifi_dut, sl_collections, request,
    performance_data, mqtt_server, custom_performance_fixture, mqtt_client
):
    """Measure current when receiving payload=10K bytes every 10 seconds with QoS=0."""
    try:
        _run_mqtt_rx_power_test(
            power_meter, wifi_access_point, wifi_dut, sl_collections, mqtt_server, mqtt_client,
            performance_data, custom_performance_fixture, request,
            payload_size=PAYLOAD_10K, publish_interval_sec=10, qos=Si91xMqttQos.QOS0,
        )
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@POWER_TRANSFORM
@pytest.mark.config("wifi_dut", wifi=MQTT_POWER_WIFI_CONFIG)
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_mqtt_power_rx_10k_qos1_interval_10s_C978095(
    firmware_loader, power_meter, wifi_access_point, wifi_dut, sl_collections, request,
    performance_data, mqtt_server, custom_performance_fixture, mqtt_client
):
    """Measure current consumption when receiving payload=10K bytes with QoS=1."""
    try:
        _run_mqtt_rx_power_test(
            power_meter, wifi_access_point, wifi_dut, sl_collections, mqtt_server, mqtt_client,
            performance_data, custom_performance_fixture, request,
            payload_size=PAYLOAD_10K, publish_interval_sec=10, qos=Si91xMqttQos.QOS1,
        )
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@POWER_TRANSFORM
@pytest.mark.config("wifi_dut", wifi=MQTT_POWER_WIFI_CONFIG)
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_mqtt_power_rx_10k_qos0_ta_powersave_C978097(
    firmware_loader, power_meter, wifi_access_point, wifi_dut, sl_collections, request,
    performance_data, mqtt_server, custom_performance_fixture, mqtt_client
):
    """Measure current when receiving payload=10K bytes with TA powersave enabled."""
    try:
        _run_mqtt_rx_power_test(
            power_meter, wifi_access_point, wifi_dut, sl_collections, mqtt_server, mqtt_client,
            performance_data, custom_performance_fixture, request,
            payload_size=PAYLOAD_10K, publish_interval_sec=10, qos=Si91xMqttQos.QOS0, ta_powersave=True,
        )
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)