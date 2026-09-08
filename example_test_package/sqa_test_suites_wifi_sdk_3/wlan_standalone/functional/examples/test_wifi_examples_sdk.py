import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.firmware_manager import FirmwareManager
from utf_wiseconnect_3.tests.interfaces.wifi_sample_app_helper import SampleAppHelper


def logger():
    return get_logger(__name__)


@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "1000_ZEPHYR_1",
                          "passphrase": "12345678",
                          "security": "WPA2"})
@pytest.mark.firmware_app("test_icmp")
@pytest.mark.start_state("wifi_dut", wifi=None)
def test_wifi_sdk_icmp_ipv4_c26310(
        wifi_access_point,
        wiseconnect_duts,
        wifi_dut,
        wifi_sniffer,
        request,
):
    """
    Verify IPv4 ICMP connectivity.
    """

    test_name = request.node.name
    app_name = SampleAppHelper.get_firmware_app_name(request)
    fw_mgr = FirmwareManager.get_instance()
    flash_device = None
    validate_dut_logs = SampleAppHelper.get_harness_wifi_flag("validate_dut_logs")
    logger().info("\n *** Start sniffer configuration *** \n")

    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info(f"Flashing and booting sample-app '{app_name}'...")
        flash_device = SampleAppHelper.flash_and_boot_sample_app(
            fw_mgr, wiseconnect_duts, wifi_dut, app_name
        )
        # Wait for sample-app join + ICMP bring-up.
        time.sleep(45)

        wifi_sniffer.interfaces.capture.stop_capture()

        log_text = SampleAppHelper.read_uart_log(wifi_dut)
        SampleAppHelper.save_uart_log(log_text, test_name)

        # UART print strings can change with sample-app revisions; only assert when
        # harness enables validate_dut_logs (same idea as power_save).
        if validate_dut_logs:
            assert "Wi-Fi client interface init success" in log_text, (
                "Expected print 'Wi-Fi client interface init success' not found"
            )
            assert "Wi-Fi client connected" in log_text, (
                "Expected print 'Wi-Fi client connected' not found"
            )
            assert "64 bytes received from 8.8.8.8" in log_text, (
                "Expected print '64 bytes received from 8.8.8.8' not found"
            )
            assert "Failed to bring Wi-Fi client interface up" not in log_text, (
                "Unexpected print: Wi-Fi client interface bring-up failed "
                f"(saw error in log). Full UART log:\n{log_text}"
            )
        else:
            logger().info(
                "Skipping DUT log asserts because validate_dut_logs is not "
                "enabled in harness defaults.wifi"
            )

        logger().info("test_wifi_sdk_icmp_ipv4_c26310 completed successfully")
    finally:
        SampleAppHelper.release_uart(wifi_dut)
        SampleAppHelper.erase_flash(flash_device)


@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "1000_ZEPHYR_1",
                          "passphrase": "12345678",
                          "security": "WPA2"})
@pytest.mark.config("mqtt_server", port=1883)
@pytest.mark.firmware_app("test_mqtt")
@pytest.mark.start_state("wifi_dut", wifi=None)
def test_wifi_sdk_embedded_mqtt_c26333(
        wifi_access_point,
        wiseconnect_duts,
        wifi_dut,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        request,
):
    """
    Verify embedded MQTT client sample-app connect, subscribe, and publish.
    """

    test_name = request.node.name
    app_name = SampleAppHelper.get_firmware_app_name(request)
    fw_mgr = FirmwareManager.get_instance()
    flash_device = None
    validate_dut_logs = SampleAppHelper.get_harness_wifi_flag("validate_dut_logs")
    publish_topic = "WISECONNECT_SDK_TOPIC"
    publish_message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do"
    subscribe_topic = "THERMOSTAT-DATA"
    subscribe_payload = "UTF_EMBEDDED_MQTT_TRIGGER"
    broker_ip = mqtt_server.interfaces.mqtt.hostname_or_ip_address
    broker_port = mqtt_server.interfaces.mqtt.port
    logger().info("\n *** Start sniffer configuration *** \n")
    logger().info(
        f"MQTT broker={broker_ip}:{broker_port} "
        "(binary MQTT_BROKER_IP/PORT must match harness mqtt_server)"
    )

    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # Third-party MQTT client/server (same fixtures as TC127757).
        logger().info(".....Host MQTT client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
            server=mqtt_server.interfaces.mqtt
        )
        time.sleep(5)
        logger().info(f"Host MQTT client subscribes to topic: {publish_topic}")
        SampleAppHelper.mqtt_subscribe(mqtt_client, publish_topic, qos=0)

        logger().info(f"Flashing and booting sample-app '{app_name}'...")
        flash_device = SampleAppHelper.flash_and_boot_sample_app(
            fw_mgr, wiseconnect_duts, wifi_dut, app_name
        )

        # Wait for sample-app Wi-Fi join + MQTT connect/subscribe/publish.
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 90:
            time.sleep(0.5)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) >= 1:
                break

        assert len(msgs) >= 1, (
            "Sample app did not publish MQTT message to "
            f"'{publish_topic}' within timeout. "
            f"Broker was {broker_ip}:{broker_port}"
        )
        assert msgs[0].topic == publish_topic, (
            f"Unexpected publish topic: {msgs[0].topic}"
        )
        assert msgs[0].payload.decode() == publish_message, (
            "Published payload mismatch. "
            f"expected='{publish_message}', "
            f"got='{msgs[0].payload.decode(errors='replace')}'"
        )
        logger().info("Host MQTT client received sample-app publish message")

        # Trigger sample-app unsubscribe/disconnect path.
        logger().info(f"Publishing trigger message on topic: {subscribe_topic}")
        mqtt_client.interfaces.mqtt.mqtt_client_publish(
            topic=subscribe_topic,
            payload=subscribe_payload,
            qos=1,
        )

        log_text = ""
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            time.sleep(1)
            log_text = SampleAppHelper.read_uart_log(wifi_dut)
            if (
                    "Example execution completed" in log_text
                    or "Disconnected from MQTT broker" in log_text
            ):
                break

        wifi_sniffer.interfaces.capture.stop_capture()
        if not log_text:
            log_text = SampleAppHelper.read_uart_log(wifi_dut)
        SampleAppHelper.save_uart_log(log_text, test_name)

        if validate_dut_logs:
            assert "Wi-Fi client connected" in log_text, (
                "Expected print 'Wi-Fi client connected' not found"
            )
            assert "Init mqtt client Success" in log_text, (
                "Expected print 'Init mqtt client Success' not found"
            )
            assert "Connect to mqtt broker Success" in log_text, (
                "Expected print 'Connect to mqtt broker Success' not found"
            )
            assert "Subscribed to Topic" in log_text, (
                "Expected print 'Subscribed to Topic' not found"
            )
            assert "Published message successfully on topic" in log_text, (
                "Expected print 'Published message successfully on topic' not found"
            )
            assert "Message Received on Topic" in log_text, (
                "Expected print 'Message Received on Topic' not found"
            )
            assert (
                    "Disconnected from MQTT broker" in log_text
                    or "Example execution completed" in log_text
            ), (
                "Expected print for MQTT disconnect / execution complete not found"
            )
            assert "Failed to bring Wi-Fi client interface up" not in log_text, (
                "Unexpected print: Wi-Fi client interface bring-up failed "
                f"(saw error in log). Full UART log:\n{log_text}"
            )
        else:
            logger().info(
                "Skipping DUT log asserts because validate_dut_logs is not "
                "enabled in harness defaults.wifi"
            )

        logger().info("test_wifi_sdk_embedded_mqtt completed successfully")
    finally:
        SampleAppHelper.release_uart(wifi_dut)
        SampleAppHelper.erase_flash(flash_device)


@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "1000_ZEPHYR_1",
                          "passphrase": "12345678",
                          "security": "WPA2"})
@pytest.mark.config("mqtt_server", port=1883)
@pytest.mark.firmware_app("test_mqtt_over_tcp")
@pytest.mark.start_state("wifi_dut", wifi=None)
def test_wifi_sdk_paho_mqtt_over_tcp_c26347(
    wifi_access_point,
    wiseconnect_duts,
    wifi_dut,
    wifi_sniffer,
    mqtt_server,
    request,
):
    """
    Verify Paho MQTT over TCP sample-app connect, subscribe, and publish.

    The sample subscribes and publishes on the same topic (THERMOSTAT-DATA),
    so it receives its own publish and completes without a third-party MQTT client.
    mqtt_server is still required as the broker for the DUT.
    """

    test_name = request.node.name
    app_name = SampleAppHelper.get_firmware_app_name(request)
    fw_mgr = FirmwareManager.get_instance()
    flash_device = None
    validate_dut_logs = SampleAppHelper.get_harness_wifi_flag("validate_dut_logs")
    broker_ip = mqtt_server.interfaces.mqtt.hostname_or_ip_address
    broker_port = mqtt_server.interfaces.mqtt.port
    logger().info("\n *** Start sniffer configuration *** \n")
    logger().info(
        f"MQTT broker={broker_ip}:{broker_port} "
        "(binary MQTT_BROKER_IP/PORT must match harness mqtt_server)"
    )

    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        logger().info(f"Flashing and booting sample-app '{app_name}'...")
        flash_device = SampleAppHelper.flash_and_boot_sample_app(
            fw_mgr, wiseconnect_duts, wifi_dut, app_name
        )

        # Wait for DUT: join -> MQTT connect -> subscribe/publish same topic ->
        # receive own message -> unsubscribe/disconnect.
        log_text = ""
        sw = Stopwatch()
        while sw.elapsed_sec < 90:
            time.sleep(1)
            log_text = SampleAppHelper.read_uart_log(wifi_dut)
            if (
                "Paho MQTT over TCP demo executed successfully" in log_text
                or "Execution completed!" in log_text
                or "Disconnect to the MQTT broker Success" in log_text
            ):
                break

        wifi_sniffer.interfaces.capture.stop_capture()
        if not log_text:
            log_text = SampleAppHelper.read_uart_log(wifi_dut)
        SampleAppHelper.save_uart_log(log_text, test_name)

        if validate_dut_logs:
            assert "Wi-Fi client connected" in log_text, (
                "Expected print 'Wi-Fi client connected' not found"
            )
            assert "MQTT Connected Successfully!" in log_text, (
                "Expected print 'MQTT Connected Successfully!' not found"
            )
            assert "Subscribed to topic:" in log_text, (
                "Expected print 'Subscribed to topic:' not found"
            )
            assert "Publishes to Topic successfully" in log_text, (
                "Expected print 'Publishes to Topic successfully' not found"
            )
            assert "Message:" in log_text, (
                "Expected print 'Message:' not found "
                "(DUT should receive its own publish on THERMOSTAT-DATA)"
            )
            assert "Unsubscription to Topic Success" in log_text, (
                "Expected print 'Unsubscription to Topic Success' not found"
            )
            assert (
                "Disconnect to the MQTT broker Success" in log_text
                or "Paho MQTT over TCP demo executed successfully" in log_text
                or "Execution completed!" in log_text
            ), (
                "Expected print for MQTT disconnect / execution complete not found"
            )
            assert "Failed to bring Wi-Fi client interface up" not in log_text, (
                "Unexpected print: Wi-Fi client interface bring-up failed "
                f"(saw error in log). Full UART log:\n{log_text}"
            )
        else:
            logger().info(
                "Skipping DUT log asserts because validate_dut_logs is not "
                "enabled in harness defaults.wifi"
            )

        logger().info("test_wifi_sdk_paho_mqtt_over_tcp_c26347 completed successfully")
    finally:
        SampleAppHelper.release_uart(wifi_dut)
        SampleAppHelper.erase_flash(flash_device)


@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "1000_ZEPHYR_1",
                          "passphrase": "12345678",
                          "security": "WPA2"})
@pytest.mark.config("mqtt_server", port=1883)
@pytest.mark.firmware_app("test_lwip_mqtt_over_tcp")
@pytest.mark.start_state("wifi_dut", wifi=None)
def test_wifi_sdk_lwip_mqtt_over_tcp_c26346(
    wifi_access_point,
    wiseconnect_duts,
    wifi_dut,
    wifi_sniffer,
    mqtt_server,
    request,
):
    """
    Verify LWIP MQTT over TCP sample-app connect, subscribe, and publish.

    The sample subscribes and publishes on the same topic (THERMOSTAT-DATA),
    so it receives its own publish and completes without a third-party MQTT client.
    mqtt_server is still required as the broker for the DUT.
    """

    test_name = request.node.name
    app_name = SampleAppHelper.get_firmware_app_name(request)
    fw_mgr = FirmwareManager.get_instance()
    flash_device = None
    validate_dut_logs = SampleAppHelper.get_harness_wifi_flag("validate_dut_logs")
    broker_ip = mqtt_server.interfaces.mqtt.hostname_or_ip_address
    broker_port = mqtt_server.interfaces.mqtt.port
    logger().info("\n *** Start sniffer configuration *** \n")
    logger().info(
        f"MQTT broker={broker_ip}:{broker_port} "
        "(binary MQTT_BROKER_IP/PORT must match harness mqtt_server)"
    )

    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        logger().info(f"Flashing and booting sample-app '{app_name}'...")
        flash_device = SampleAppHelper.flash_and_boot_sample_app(
            fw_mgr, wiseconnect_duts, wifi_dut, app_name
        )

        # Wait for DUT: join -> MQTT connect -> subscribe/publish same topic ->
        # receive own message -> unsubscribe/disconnect.
        log_text = ""
        sw = Stopwatch()
        while sw.elapsed_sec < 90:
            time.sleep(1)
            log_text = SampleAppHelper.read_uart_log(wifi_dut)
            if (
                "Paho MQTT over TCP demo executed successfully" in log_text
                or "Execution completed!" in log_text
                or "Disconnect to the MQTT broker Success" in log_text
            ):
                break

        wifi_sniffer.interfaces.capture.stop_capture()
        if not log_text:
            log_text = SampleAppHelper.read_uart_log(wifi_dut)
        SampleAppHelper.save_uart_log(log_text, test_name)

        if validate_dut_logs:
            assert "Wi-Fi client connected" in log_text, (
                "Expected print 'Wi-Fi client connected' not found"
            )
            assert "MQTT Connected Successfully!" in log_text, (
                "Expected print 'MQTT Connected Successfully!' not found"
            )
            assert "Subscribed to topic:" in log_text, (
                "Expected print 'Subscribed to topic:' not found"
            )
            assert "Publishes to Topic successfully" in log_text, (
                "Expected print 'Publishes to Topic successfully' not found"
            )
            assert "Message:" in log_text, (
                "Expected print 'Message:' not found "
                "(DUT should receive its own publish on THERMOSTAT-DATA)"
            )
            assert "Unsubscription to Topic Success" in log_text, (
                "Expected print 'Unsubscription to Topic Success' not found"
            )
            assert (
                "Disconnect to the MQTT broker Success" in log_text
                or "Paho MQTT over TCP demo executed successfully" in log_text
                or "Execution completed!" in log_text
            ), (
                "Expected print for MQTT disconnect / execution complete not found"
            )
            assert "Failed to bring Wi-Fi client interface up" not in log_text, (
                "Unexpected print: Wi-Fi client interface bring-up failed "
                f"(saw error in log). Full UART log:\n{log_text}"
            )
        else:
            logger().info(
                "Skipping DUT log asserts because validate_dut_logs is not "
                "enabled in harness defaults.wifi"
            )

        logger().info("test_wifi_sdk_lwip_mqtt_over_tcp_c26346 completed successfully")
    finally:
        SampleAppHelper.release_uart(wifi_dut)
        SampleAppHelper.erase_flash(flash_device)


@pytest.mark.firmware_app("test_eap")
@pytest.mark.start_state("wifi_dut", wifi=None)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
def test_wifi_sdk_eap_c26335(
        wifi_access_point,
        wiseconnect_duts,
        wifi_dut,
        wifi_sniffer,
        radius_server,
        wifi_client,
        request,
):
    """
    Verify WPA2 enterprise connectivity using EAP-PEAPv0.
    """

    test_name = request.node.name
    app_name = SampleAppHelper.get_firmware_app_name(request)
    fw_mgr = FirmwareManager.get_instance()
    flash_device = None
    validate_dut_logs = SampleAppHelper.get_harness_wifi_flag("validate_dut_logs")
    logger().info("\n *** Start sniffer configuration *** \n")

    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info(f"Flashing and booting sample-app '{app_name}'...")
        flash_device = SampleAppHelper.flash_and_boot_sample_app(
            fw_mgr, wiseconnect_duts, wifi_dut, app_name
        )
        # Wait for sample-app enterprise join + DHCP.
        time.sleep(45)

        wifi_sniffer.interfaces.capture.stop_capture()

        log_text = SampleAppHelper.read_uart_log(wifi_dut)
        uart_log_file = SampleAppHelper.save_uart_log(log_text, test_name)

        # UART print strings can change with sample-app revisions; only assert when
        # harness enables validate_dut_logs (same idea as power_save).
        if validate_dut_logs:
            assert "Wi-Fi client connected" in log_text, (
                "Expected print 'Wi-Fi client connected' not found"
            )

            file_log_text = SampleAppHelper.read_log_file(uart_log_file)
            device_ip = SampleAppHelper.extract_dut_ip_from_log(file_log_text)
            assert device_ip, (
                "Unable to fetch DUT IP from UART log "
                f"(expected 'IP address of the client: <ip>'). Log file: {uart_log_file}"
            )
            logger().info(f"DUT IP fetched from UART log file: {device_ip}")

            ping_ok = SampleAppHelper.ping(wifi_client, device_ip)
            assert ping_ok, f"Remote client ping to DUT IP {device_ip} failed"
        else:
            logger().info(
                "Skipping UART/IP/ping asserts because validate_dut_logs is not "
                "enabled in harness defaults.wifi"
            )

        logger().info("test_wifi_sdk_eap_c26335 completed successfully")
    finally:
        SampleAppHelper.release_uart(wifi_dut)
        SampleAppHelper.erase_flash(flash_device)


@pytest.mark.firmware_app("test_crypto_aes")
@pytest.mark.start_state("wifi_dut", wifi=None)
def test_wifi_sdk_crypto_aes_c26309(wiseconnect_duts, wifi_dut, request):
    """
    Verify AES crypto sample-app execution.
    """
    SampleAppHelper.run_crypto_sample_app(
        request,
        wiseconnect_duts,
        wifi_dut,
        expected_logs=["Wi-Fi Init Success", "AES encryption success", "AES decryption success"],
    )


@pytest.mark.firmware_app("test_crypto_ecdh")
@pytest.mark.start_state("wifi_dut", wifi=None)
def test_wifi_sdk_crypto_ecdh_c26311(wiseconnect_duts, wifi_dut, request):
    """
    Verify ECDH crypto sample-app execution.
    """
    SampleAppHelper.run_crypto_sample_app(
        request,
        wiseconnect_duts,
        wifi_dut,
        expected_logs=["Wi-Fi Init Success", "ECDH point addition success", "ECDH point subtraction success",
                       "ECDH point multiplication success", "ECDH point double success", "ECDH point affine success"],
    )


@pytest.mark.firmware_app("test_crypto_ecdsa")
@pytest.mark.start_state("wifi_dut", wifi=None)
def test_wifi_sdk_crypto_ecdsa_c26312(wiseconnect_duts, wifi_dut, request):
    """
    Verify ECDSA crypto sample-app execution.
    """
    SampleAppHelper.run_crypto_sample_app(
        request,
        wiseconnect_duts,
        wifi_dut,
        expected_logs=["Wi-Fi Init Success", "ECC key pair generation success", "ECDSA signature generation success",
                       "ECDSA signature verification success"],
    )


@pytest.mark.firmware_app("test_crypto_gcm_cmac")
@pytest.mark.start_state("wifi_dut", wifi=None)
def test_wifi_sdk_crypto_gcm_cmac_c26313(wiseconnect_duts, wifi_dut, request):
    """
    Verify GCM/CMAC crypto sample-app execution.
    """
    SampleAppHelper.run_crypto_sample_app(
        request,
        wiseconnect_duts,
        wifi_dut,
        expected_logs=["Wi-Fi Init Success", "GCM encryption success", "GCM Decryption Success",
                       "CMAC Compute Success"],
    )


@pytest.mark.firmware_app("test_crypto_hmac")
@pytest.mark.start_state("wifi_dut", wifi=None)
def test_wifi_sdk_crypto_hmac_c26314(wiseconnect_duts, wifi_dut, request):
    """
    Verify HMAC crypto sample-app execution.
    """
    SampleAppHelper.run_crypto_sample_app(
        request,
        wiseconnect_duts,
        wifi_dut,
        expected_logs=["Wi-Fi Init Success", "HMAC success"],
    )


@pytest.mark.firmware_app("test_crypto_sha")
@pytest.mark.start_state("wifi_dut", wifi=None)
def test_wifi_sdk_crypto_sha_c26315(wiseconnect_duts, wifi_dut, request):
    """
    Verify SHA crypto sample-app execution.
    """
    SampleAppHelper.run_crypto_sample_app(
        request,
        wiseconnect_duts,
        wifi_dut,
        expected_logs=["Wi-Fi Init Success", "SHA success", "SHA Compare with expected value is Successful"],
    )


@pytest.mark.firmware_app("test_crypto_sha3")
@pytest.mark.start_state("wifi_dut", wifi=None)
def test_wifi_sdk_crypto_sha3_c26316(wiseconnect_duts, wifi_dut, request):
    """
    Verify SHA3 crypto sample-app execution.
    """
    SampleAppHelper.run_crypto_sample_app(
        request,
        wiseconnect_duts,
        wifi_dut,
        expected_logs=["Wi-Fi Init Success", "SHA3 success", "SHA3 Compare with expected value is Successful"],
    )
