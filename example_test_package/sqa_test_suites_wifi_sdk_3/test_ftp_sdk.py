import time
from base64 import b64decode
import pytest
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xPowerSaveModes, Si91xFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap,\
    RS9116AsyncEventType, Si91xPowerSaveProcedureTypes, Si91xCustomFeatureBitMap
import random
import string
from datetime import datetime
import uuid
from typing import Dict

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
            "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.FTPClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "bt_features": 0,
            "ble_features": 0,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "band": 0,
            }
        )
    ]

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ftp_TC19004(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, ftp_server, ftp_client, logger, sl_collections):
    capture_filename = "test_ftp_TC19004"
    current_time = time.time()
    result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                             retry_count=3, rejoin_parms=[0, 6, 40, 0])
    device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger.info(f"host ip address is {host_ip}")
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1024))
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(temp_buffer)
    wifi_dut.interfaces.wifi.connect_to_ftp_server(flags=4, server_ip=host_ip, username="ftpuser", password="ftpuser",
                                                   server_port=21)
    set_dir = "/ftp_test"
    dir1 = "ftp_test1"
    dir2 = "ftp_test2"
    file_name = "new_ftp_test_file1.txt"
    ftp_created_dir_list = []
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    wifi_dut.interfaces.wifi.create_directory(set_dir)
    dir_create = 1
    try:
        wifi_dut.interfaces.wifi.set_directory(set_dir)
        ftp_created_dir_list.append(set_dir + "/" + dir1)
        wifi_dut.interfaces.wifi.create_directory(dir1)
        ftp_created_dir_list.append(set_dir + "/" + dir2)
        wifi_dut.interfaces.wifi.create_directory(dir2)
        ftp_created_dir_list.append(set_dir + "/" + file_name)
        wifi_dut.interfaces.wifi.ftp_file_create(file_name="ftp_test_file1.txt")
        wifi_dut.interfaces.wifi.ftp_file_write(file_content=temp_buffer)
        wifi_dut.interfaces.wifi.ftp_file_rename(old_file_name="ftp_test_file1.txt", new_file_name=file_name)
        wifi_dut.interfaces.wifi.query_directory_list("/ftp_test")
        time.sleep(20)
        events = wifi_dut.interfaces.wifi.get_async_events()
        ftp_dir_events = 0
        dir_list_dut = []
        for event in events:
            if event.event_type == RS9116AsyncEventType.FTP_DIR_READ:
                ftp_dir_event = event.event_data.decode()
                logger.info(f"ftp directory event received is {ftp_dir_event}")
                ftp_dir_event = ftp_dir_event.split(",")
                status = int(ftp_dir_event[0].split(":")[1])
                assert status == 0, f"FTP directory read is failed with error code {status}"
                ftp_dir_event.pop(0)
                for count in ftp_dir_event:
                    if "data" in count:
                        arg1 = count.split(":")[1]
                        arg1 = b64decode(arg1).decode()
                        ftp_dir_event[0] = arg1
                    if "length" in count:
                        ftp_dir_event.remove(count)

                ftp_dir_event.pop(len(ftp_dir_event) - 1)
                for count in ftp_dir_event:
                    count = count.strip("\r\n")
                    dir_list_dut = dir_list_dut + count.split("\r\n")
                ftp_dir_events = ftp_dir_events + 1

        assert ftp_dir_events > 1, "Atleast two FTP directory read events are not received"
        ftp_created_dir_list.append('')
        logger.info(f"DUT ***************** directory list is {dir_list_dut}")
        logger.info(f"Directory list expected is {ftp_created_dir_list}")
        for count in ftp_created_dir_list:
            if count == " ":
                ftp_created_dir_list.pop(count)
        assert ftp_created_dir_list == dir_list_dut, "Directory list comparison is failed"

        wifi_dut.interfaces.wifi.ftp_file_read(file_name="new_ftp_test_file1.txt")
        time.sleep(10)
        ftp_receive_file_data = ""
        ftp_file_events = 0
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == RS9116AsyncEventType.FTP_FILE_READ:
                ftp_event_data = event.event_data.decode()
                event_data_params = ftp_event_data.split(",")
                for event_data in event_data_params:
                    if "status" in event_data:
                        status = int(event_data.split(":")[1])
                        assert status == 0, f"expected status is 0, but observed error {status}"
                    if "data" in event_data:
                        ftp_file_data = event_data.split(":")[1]
                        if ftp_file_data != "":
                            ftp_receive_file_data = ftp_receive_file_data + ftp_file_data
                    ftp_file_events = ftp_file_events + 1
        assert ftp_file_events > 1, "Atleast two FTP file read events are not received"
        file_time_stamp = str(
            datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        rx_file = "./reports/" + capture_filename + "_rx_file" + file_time_stamp + ".txt"
        with open(rx_file, "w") as recv:
            recv.write(ftp_receive_file_data)
        assert temp_buffer == ftp_receive_file_data, f"Data write to the file by DUT, and read from the file is not " \
                                                     f"matched "

        wifi_dut.interfaces.wifi.ftp_file_delete(file_name="new_ftp_test_file1.txt")
        wifi_dut.interfaces.wifi.ftp_directory_delete(dir1)
        wifi_dut.interfaces.wifi.ftp_directory_delete(dir2)
        wifi_dut.interfaces.wifi.set_directory("/")
        wifi_dut.interfaces.wifi.ftp_directory_delete(set_dir)
        dir_create = 0
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")

        result = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["ftp"], capture_filename,
                                             ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
        if not len(result):
            logger.info(f"FTP packets are not captured or one of the 4-way handshake pkts are not captured")
            assert 0,(f"FTP packets are not captured or one of the 4-way handshake pkts are not captured")

    finally:
        wifi_dut.interfaces.wifi.ftp_disconnect()
        if dir_create:
            ftp_client.interfaces.ftp_client.login()
            ftp_client.interfaces.ftp_client.set_dir("/")
            ftp_client.interfaces.ftp_client.remove_dir("ftp_test")