# Test author: Vinod.G
# Test suite: FTP test suite
import time
from base64 import b64decode

import pytest
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, DeviceConstants, \
    RS9116AsyncEventType, RS9116PowerSaveProcedureTypes, RS9116CustomFeatureBitMap
import random
import string
from datetime import datetime
import uuid
from typing import Dict

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Open FTP server in raspberry 
        5. Open FTP client in the DUT 
        6. Run ftp operations,  create folder in server, create file,  delete file,  delete folder e.t.c
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.FTPClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
            "bt_features": 0,
            "ble_features": 0,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "band": 0,
            }
        )
    ]


def get_ftp_list(wifi_sniffer, dut_mac_address, logger, decryption_key: str, print_layers: list, capture_filename,
                 mode=0) -> Dict[str, int]:
    ftp_capture_list = []
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {dut_mac_address})'
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=local_capture_file
            ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "wlan":
                mac_layer = str(layer)
                for count in mac_layer.split("\n"):
                    if "Transmitter address" in count:
                        ta_address = count.split(": ")[1].strip()
            if layer_name in print_layers:
                if ta_address == dut_mac_address:
                    ftp_layer = str(layer)
                    logger.info(f"As per sniffer capture FTP packets sent by DUT..{ta_address}  ->  {ftp_layer}")
                    ftp_capture_list.append(tuple([ftp_layer, packet.sniff_timestamp]))
    return ftp_capture_list


def join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger):
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    logger.info("Start the sniffer")
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
        )

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    for count in range(1, 3):
        try:
            join_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            join_fail = 0
            break
        except:
            logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
            time.sleep(1)
    if join_fail:
        logger.info(f"Joining to the AP has failed")
        assert join_fail == 0, "Joining to the AP is failed"
    for count in range(1, 3):
        ip_fail = 1
        try:
            # DUT gets ipaddress through DHCP process after start_ip API is executed
            logger.info("DUT gets ipaddress through DHCP ")
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip_fail = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    if ip_fail:
        logger.info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    return mac_address


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ftp_TC19004(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, ftp_server, ftp_client, logger):
    capture_filename = "test_ftp_TC19004"
    current_time = time.time()
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
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
        ftp_capture_list = get_ftp_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["ftp"],
                                        capture_filename)
        if not len(ftp_capture_list):
            logger.info(f"FTP packets are not captured or one of the 4-way handshake pkts are not captured in the "
                        f"sniffer file")

            assert 0, (f"FTP packets are not captured or one of the 4-way handshake pkts are not captured in the "
                       f"sniffer file")
    finally:
        wifi_dut.interfaces.wifi.ftp_disconnect()
        if dir_create:
            ftp_client.interfaces.ftp_client.login()
            ftp_client.interfaces.ftp_client.set_dir("/")
            ftp_client.interfaces.ftp_client.remove_dir("ftp_test")
