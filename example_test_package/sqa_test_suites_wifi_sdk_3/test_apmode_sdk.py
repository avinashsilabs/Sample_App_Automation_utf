import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116OperatingMode,
    RS9116Band,
    RS9116FeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116TCPIPFeatureBitMap, RS9116CoexMode, RS9116ConfigFeatureBitMap,
    RS9116StoreConfiguration, RS9116PowerSaveModes, RS9116DataRate)
from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)

# Configuring static IP to DUT
mode = 'static'
static_ip = '192.168.100.76'
static_subnet = '255.255.255.0'
static_gateway = '192.168.100.76'

def ping_from_client(wifi_client, dut_ip, ping_count=10):
    logger().info(f"Initiating wlan ping from client '{wifi_client.name}' to DUT")
    client_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Client IP **********: {client_ip}")
    for count in range(3):
        try:
            rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ping -c {ping_count} {dut_ip}")
            assert rc == 0
            logger().info(f"\n{stdout}\n")
            return rc == 0
        except:
            time.sleep(10)

# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": RS9116OperatingMode.AccessPoint,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
#         "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
#         "custom_features": RS9116CustomFeatureBitMap.Default,
#         "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
#         "band": RS9116Band.TwoPointFourGHz,
#         "security": "WPA2", "ssid": "SILABS_AP_C19454", "passphrase": "12345678", "region_config": 0, "beacon": 100,
#         "region_code_ap": "US",
#     }
# )
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "interface": "wlan0",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "interface": "wlan0",
            "channel": 11,
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "interface": "wlan0",
            "channel": 11,
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "interface": "wlan0",
            "channel": 11,
        },
    }
)
@pytest.mark.start_state('wifi_dut', wifi='deinit')
@pytest.mark.config(
    "wifi_dut", wifi={"security": 'WPA2', "region_code_ap": "US"})
@pytest.mark.parametrize("channel", [11])
def test_dut_sdk_ap_mode_tx_rules_USregion_C19454(wifi_dut, wifi_client, channel, wifi_sniffer, wifi_clients):
    try:
        validation = True
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        file_name = f'test__C19454'
        wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
        time.sleep(3)
        ping_count = 10
        wifi_dut.interfaces.wifi.init(mode="ap")
        wifi_dut.interfaces.wifi.start_ip(static_ip=static_ip, static_subnet=static_subnet, static_gateway=static_gateway)
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_C19454", channel=channel)
        time.sleep(10)
        for i in range(0, len(wifi_clients)):
            connected = False
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            wifi_clients[i].interfaces.wifi.join(ssid="SILABS_AP_C19454", channel=channel, passphrase="123456789")
            time.sleep(5)
            dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {dut_ip}")
            for count in range(3):
               try:
                 logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                 status = ping_from_client(wifi_clients[i], dut_ip)
                 assert status, f"RASPI-STA{i + 1} failed to ping DUT"
                 connected = True
                 break
               except:
                 logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                 time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info("Waiting 30 seconds to check connection stability")
        time.sleep(30)
        logger().info("Checking the connection stability after 30 seconds")
        for i in range(0, len(wifi_clients)):
            logger().info(f"Initiating wlan ping from RASPI_STA{i + 1} for ping_count:{ping_count}")
            status = ping_from_client(wifi_clients[i], dut_ip, ping_count)
            assert status, f"Failed to ping DUT...RASPI-STA{i + 1} is disconnected from DUT-AP"
            logger().info(f"RASPI_STA{i + 1} is still connected to DUT-AP")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        for i in range(0, len(wifi_clients)):
             logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
             wifi_clients[i].interfaces.wifi.leave()
        logger().info("*********Validating the Sniffer Packet **********")
        packet_filter1 = f'((wlan.fc.type_subtype == 8) &&(wlan.country_info.code == "US")) && (wlan.ds.current_channel == {channel})' \
                     f'&& wlan.addr == {dut_mac_address}'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
          "Unable to find beacon frame with Region US in Sniffer"
        logger().info("*********Identified the beacons from DUT AP with region set to US*********")

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()
        raise e

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": RS9116OperatingMode.AccessPoint,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
#         "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
#         "custom_features": RS9116CustomFeatureBitMap.Default,
#         "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
#         "band": RS9116Band.TwoPointFourGHz,
#         "security": "WPA2", "ssid": "SILABS_AP_C19454", "passphrase": "12345678", "region_config": 0, "beacon": 100,
#         "region_code_ap": "JP",
#     }
# )
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": 13,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": 13,
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": 13,
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": 13,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state('wifi_dut', wifi='deinit')
@pytest.mark.config(
    "wifi_dut", wifi={"security": 'WPA2', "region_config": 0, "region_code_ap": "JP"})
@pytest.mark.parametrize("channel", [13])
def test_dut_sdk_ap_mode_tx_rules_JPregion_C19456(wifi_dut, wifi_client, channel, wifi_sniffer, wifi_clients):
    try:
        validation = True
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        file_name = f'test__C19456'
        wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
        time.sleep(3)
        ping_count = 10
        wifi_dut.interfaces.wifi.init(mode="ap")
        wifi_dut.interfaces.wifi.start_ip(static_ip=static_ip, static_subnet=static_subnet,
                                                             static_gateway=static_gateway)
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_C19456", channel=channel)
        time.sleep(10)
        logger().info(f"********** Number of wifi_clients are:{len(wifi_clients)} **********")
        for i in range(0, len(wifi_clients)):
            connected = False
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            wifi_clients[i].interfaces.wifi.join(ssid="SILABS_AP_C19456", channel=channel, passphrase="123456789")
            time.sleep(5)
            dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {dut_ip}")
            for count in range(3):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                    status = ping_from_client(wifi_clients[i], dut_ip)
                    assert status, f"RASPI-STA{i + 1} failed to ping DUT"
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info("Waiting 30 seconds to check connection stability")
        time.sleep(30)
        logger().info("Checking the connection stability after 30 seconds")
        for i in range(0, len(wifi_clients)):
            logger().info(f"Initiating wlan ping from RASPI_STA{i + 1} for ping_count:{ping_count}")
            status = ping_from_client(wifi_clients[i], dut_ip, ping_count)
            assert status, f"Failed to ping DUT...RASPI-STA{i + 1} is disconnected from DUT-AP"
            logger().info(f"RASPI_STA{i + 1} is still connected to DUT-AP")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        for i in range(0, len(wifi_clients)):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info(f"*********Validating the Sniffer Packet **********")
        packet_filter1 = f'((wlan.fc.type_subtype == 8) &&(wlan.country_info.code == "JP")) && (wlan.ds.current_channel == {channel})' \
                         f'&& wlan.addr == {dut_mac_address}'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)[
            "packet_count"], "Unable to find beacon frame with Region JP in Sniffer"
        logger().info(f"*********Identified the beacons from DUT AP with region set to Japan*********")

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()
        raise e

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": RS9116OperatingMode.AccessPoint,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.PSKSecurity,
#         "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
#         "custom_features": RS9116CustomFeatureBitMap.Default,
#         "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
#         "band": RS9116Band.TwoPointFourGHz,
#         "security": "WPA2", "ssid": "SILABS_AP_C19455", "passphrase": "12345678", "region_config": 0, "beacon": 100,
#         "region_code_ap": "EU",
#     }
# )
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state('wifi_dut', wifi='deinit')
@pytest.mark.config(
    "wifi_dut", wifi={"security": 'WPA2', "region_code_ap": "EU"})
@pytest.mark.parametrize("channel", [13])
def test_dut_sdk_ap_mode_tx_rules_EUregion_C19455(wifi_dut, wifi_client, channel, wifi_sniffer, wifi_clients):
    try:
        validation = True
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        file_name = f'test__C19455'
        wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
        time.sleep(3)
        ping_count = 10
        wifi_dut.interfaces.wifi.init(mode="ap")
        wifi_dut.interfaces.wifi.start_ip(static_ip=static_ip, static_subnet=static_subnet,
                                                             static_gateway=static_gateway)
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_C19455", channel=channel)
        time.sleep(10)
        logger().info(f"********** Number of wifi_clients are:{len(wifi_clients)} **********")
        for i in range(0, len(wifi_clients)):
            connected = False
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            wifi_clients[i].interfaces.wifi.join(ssid="SILABS_AP_C19455", channel=channel, passphrase="123456789")
            time.sleep(5)
            dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {dut_ip}")
            for count in range(3):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                    status = ping_from_client(wifi_clients[i], dut_ip)
                    assert status, f"RASPI-STA{i + 1} failed to ping DUT"
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info("Waiting 30 seconds to check connection stability")
        time.sleep(30)
        logger().info("Checking the connection stability after 30 seconds")
        for i in range(0, len(wifi_clients)):
            logger().info(f"Initiating wlan ping from RASPI_STA{i + 1} for ping_count:{ping_count}")
            status = ping_from_client(wifi_clients[i], dut_ip, ping_count)
            assert status, f"Failed to ping DUT...RASPI-STA{i + 1} is disconnected from DUT-AP"
            logger().info(f"RASPI_STA{i + 1} is still connected to DUT-AP")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        for i in range(0, len(wifi_clients)):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("*********Validating the Sniffer Packet **********")
        packet_filter1 = f'((wlan.fc.type_subtype == 8) &&(wlan.country_info.code == "EU")) && (wlan.ds.current_channel == {channel})' \
                         f'&& wlan.addr == {dut_mac_address}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)[
            "packet_count"], "Unable to find beacon frame with Region EU in Sniffer"
        logger().info("*********Identified the beacons from DUT AP with region set to Europe*********")

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()
        raise e

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()

