import time
import pytest
import subprocess
import os
import fcntl
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf.utils.logger import get_logger

"""
* setup requirenment :
        - DUT(RS9116)
        - EFR32
        - Raspberry PI4
        - NRF board

* Python packages :
        -pip install colorama, pip install scapy, pip install serial, pip install pyserial
    
* Auther:
        NandanBaban.Patil@silabs.com
"""
class BLEDeviceState():
    Advertising='1'
    Connected='8'
    Disconnected='0'
    
def logger():
    return get_logger(__name__)

def reset_USB_Device():
    USB_DEV_NAME="239a:8029"
	# Same as _IO('U', 20) constant in the linux kernel.
    CONST_USB_DEV_FS_RESET_CODE = ord('U') << (4*2) | 20
	#usb_dev_path = ""

	# Based on 'lsusb' command, get the usb device path in the following format - 
	# /dev/bus/usb/<busnum>/<devnum>
    proc = subprocess.Popen(['lsusb'], stdout=subprocess.PIPE)
    cmd_output = proc.communicate()[0]
    usb_device_list = cmd_output.decode('utf8').split('\n')
    for device in usb_device_list:
    	if USB_DEV_NAME in device:
            logger().info("device: ".format(device))
            usb_dev_details = device.split()
            usb_bus = usb_dev_details[1]
            usb_dev = usb_dev_details[3][:3]
            usb_dev_path = '/dev/bus/usb/%s/%s' % (usb_bus, usb_dev)
    try:
        if usb_dev_path != "":
            logger().info("Trying to reset USB Device: " + usb_dev_path)
            device_file = os.open(usb_dev_path, os.O_WRONLY)
            fcntl.ioctl(device_file, CONST_USB_DEV_FS_RESET_CODE, 0)
            logger().info("USB Device reset successful.")
        else:
            logger().info("Device not found.")
    except:
        assert False, '\n\n ***Setup Issue*** Unable to detect Sweyntooth (NRF) Board.. Please reconnect the Board..!!\n\n'
    finally:
        if device_file:
            os.close(device_file)
def ble_vulnerability(ble_dut, ble_vulnerability_sniffer, test_duration, script_name, only_ADV=False):
    sniffer_log = f"reports/"+script_name+".log_"+str(int(time.time()))
    state_change = False
    try:
        reset_USB_Device()
    except Exception as e:
        logger.info("Got Exception during usb reset {}".format(str(e)))
    try:
        ble_dut_address = ble_dut.interfaces.wifi.ble_start()
        assert ble_dut_address is not None
        time.sleep(2)
        ble_vulnerability_sniffer.interfaces.ble_vul_sniffer.start_capture(
                dut_address=ble_dut_address,
                log_file=sniffer_log
        )
        if ble_dut.interfaces.wifi.ble_get_device_state()==BLEDeviceState.Advertising: 
            logger().info(f"\n\n ***** DUT {ble_dut_address} is in Advertising State *****\n\n")
        else:
            ble_dut.interfaces.wifi.ble_start_advertising()
            logger().info(f"\n\n ***** Advertising started Successfully on DUT : {ble_dut_address} *****\n\n")
        sw = Stopwatch()
        prev_state ='1'
        while sw.elapsed_sec < test_duration:
            current_state = ble_dut.interfaces.wifi.ble_get_device_state()
            assert current_state, "Failed to get device state, DUT got crashed or went into bad state"
            if current_state ==BLEDeviceState.Disconnected:
                logger().info("\n\n ***** DUT is disconnected ***** current state : {} prev state : {}\n\n".format(current_state, prev_state))
                ble_dut.interfaces.wifi.ble_start_advertising()
                prev_state=BLEDeviceState.Advertising
            elif current_state==BLEDeviceState.Connected:
                state_change=True
                time.sleep(2)
                if prev_state==BLEDeviceState.Advertising:
                    logger().info("\n\n ***** DUT is Connected ***** current state : {} prev state : {}\n\n".format(current_state, prev_state))
                    prev_state=current_state
                    time.sleep(2)
                    count=0
                while(ble_dut.interfaces.wifi.ble_get_device_state()==BLEDeviceState.Connected and sw.elapsed_sec < test_duration):
                    if count==120:
                        count=0
                        logger().info("\n\n ***** Looks like 3rd party script stoped execution form last 120 sec, So Re-executing 3rd party script *****\n\n")
                        logger().info("\n\n ***** Before restart of 3rd party script state OF DUT is {}: 'Connected state' *****\n\n".format(current_state))
                        ble_vulnerability_sniffer.interfaces.ble_vul_sniffer.stop_capture()
                        ble_vulnerability_sniffer.interfaces.ble_vul_sniffer.start_capture(
                                dut_address=ble_dut_address,
                        log_file=f"reports/"+script_name+".log_"+str(int(time.time()))
                        )
                    time.sleep(1)
                    count+=1
            elif current_state==BLEDeviceState.Advertising:
                time.sleep(2)
                count=0
                if not only_ADV:
                    while(ble_dut.interfaces.wifi.ble_get_device_state()==BLEDeviceState.Advertising and sw.elapsed_sec < test_duration):
                        if count==30:
                            count=0
                            logger().info("\n\n ***** Looks like 3rd party script stoped execution form last 30 sec, So Re-executing 3rd party script *****\n\n")
                            logger().info("\n\n ***** Before restart of 3rd party script state OF DUT is {}: Advertising *****\n\n".format(current_state))
                            ble_vulnerability_sniffer.interfaces.ble_vul_sniffer.stop_capture()
                            ble_vulnerability_sniffer.interfaces.ble_vul_sniffer.start_capture(
                                   dut_address=ble_dut_address,
                            log_file=f"reports/"+script_name+".log_"+str(int(time.time()))
                            )
                        time.sleep(1)
                        count+=1
    except Exception as e:
        if "could not open port" in str(e):
            assert False, "\n\n ******Setup issue... NRF Dongle went into bad state...Please reconnect NRF Dongle OR check of ble_sweyntooth ip_address in harness file******\n\n"
        else:
            logger().info("found Exception as {}".format(str(e)))
    finally:
       #need to add line of code to check the log file is genrated or not 
        with open(sniffer_log, 'r') as file:
            sniffer_logs = file.read()
            logger().info("\n\n ************* Printing Sniffer capture logs *************** \n\n")
            logger().info(sniffer_logs)
            pattern_found =False
            if "BTLE_CONNECT_REQ" in str(sniffer_logs): pattern_found=True
            assert pattern_found or state_change, "Failed... Attack from 3rd party script is not found...!"
            if pattern_found: 
                logger().info("\n\n *****Found 'BTLE_CONNECT_REQ' string in sniffer capture and DUT is stable throughout the test case So making the test case PASS**\n\n")
            elif state_change: 
                logger().info("\n\n *****DUT state is changed to connected state from Advertising state and DUT is stable throughout the test case So making the test case PASS**\n\n")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.config(
    "ble_vulnerability_sniffer",
    ble_vul_sniffer={
        "script": "llid_dealock.py"
    },
)
def test_verify_dut_with_llid_dealock_script_C20003(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
    #Test case to verify DUT behaviour after executing llid_dealock_script.py script
    test_duration = utf_constants.get("test_duration")
    ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="llid_dealock")
    ble_client.interfaces.bluetooth.close()
    reset_USB_Device()

"""Test case is blocked with https://jira.silabs.com/browse/UTF-2154"""
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#     },
# )
# @pytest.mark.config(
#     "ble_vulnerability_sniffer",
#     ble_vul_sniffer={
#         "script": "DA14580_exploit_att_crash.py"
#     },
# )
# def test_verify_dut_with_DA14580_exploit_att_crash_script_C20004(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
#     #Test case to verify DUT behaviour after executing DA14580_exploit_att_crash.py script
#     test_duration = utf_constants.get("test_duration")
#     ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="llid_dealock")
#     ble_client.interfaces.bluetooth.close()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.config(
    "ble_vulnerability_sniffer",
    ble_vul_sniffer={
        "script": "CC2640R2_public_key_crash.py"
    },
)
def test_verify_dut_with_CC2640R2_public_key_crash_script_C20005(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
    #Test case to verify DUT behaviour after executing CC2640R2_public_key_crash.py script
    test_duration = utf_constants.get("test_duration")
    ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="CC2640R2_public_key_crash")
    ble_client.interfaces.bluetooth.close()
    reset_USB_Device()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.config(
    "ble_vulnerability_sniffer",
    ble_vul_sniffer={
        "script": "Telink_key_size_overflow.py"
    },
)
def test_verify_dut_with_Telink_key_size_overflow_script_C20006(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
    #Test case to verify DUT behaviour after executing Telink_key_size_overflow.py script
    test_duration = utf_constants.get("test_duration")
    ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="Telink_key_size_overflow")
    ble_client.interfaces.bluetooth.close()
    reset_USB_Device()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.config(
    "ble_vulnerability_sniffer",
    ble_vul_sniffer={
        "script": "Microchip_invalid_lcap_fragment.py"
    },
)
def test_verify_dut_with_Microchip_invalid_lcap_fragment_script_C20007(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
    #Test case to verify DUT behaviour after executing Microchip_invalid_lcap_fragment.py script
    test_duration = utf_constants.get("test_duration")
    ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="Microchip_invalid_lcap_fragment")
    ble_client.interfaces.bluetooth.close()
    reset_USB_Device()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.config(
    "ble_vulnerability_sniffer",
    ble_vul_sniffer={
        "script": "sequential_att_deadlock.py"
    },
)
def test_verify_dut_with_sequential_att_deadlock_script_C20008(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
    #Test case to verify DUT behaviour after executing sequential_att_deadlock.py script
    test_duration = utf_constants.get("test_duration")
    ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="sequential_att_deadlock")
    ble_client.interfaces.bluetooth.close()
    reset_USB_Device()

"""Tese case is blocked with https://jira.silabs.com/browse/UTF-2150"""
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#     },
# )
# @pytest.mark.config(
#     "ble_vulnerability_sniffer",
#     ble_vul_sniffer={
#         "script": "Telink_zero_ltk_installation.py"
#     },
# )
# def test_verify_dut_with_Telink_zero_ltk_installation_script_C20009(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
#     #Test case to verify DUT behaviour after executing Telink_zero_ltk_installation.py script
#     test_duration = utf_constants.get("test_duration")
#     ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="Telink_zero_ltk_installation")
#     ble_client.interfaces.bluetooth.close()
#     reset_USB_Device()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.config(
    "ble_vulnerability_sniffer",
    ble_vul_sniffer={
        "script": "link_layer_length_overflow.py"
    },
)
def test_verify_dut_with_link_layer_length_overflow_script_C20010(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
    #Test case to verify DUT behaviour after executing link_layer_length_overflow.py script
    test_duration = utf_constants.get("test_duration")
    ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="link_layer_length_overflow")
    ble_client.interfaces.bluetooth.close()
    reset_USB_Device()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.config(
    "ble_vulnerability_sniffer",
    ble_vul_sniffer={
        "script": "DA14680_exploit_silent_overflow.py"
    },
)
def test_verify_dut_with_DA14680_exploit_silent_overflow_script_C20011(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
    #Test case to verify DUT behaviour after executing DA14680_exploit_silent_overflow.py script
    test_duration = utf_constants.get("test_duration")
    ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="DA14680_exploit_silent_overflow")
    ble_client.interfaces.bluetooth.close()
    reset_USB_Device()

"""Test Case is blocked with https://jira.silabs.com/browse/UTF-2154"""
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#     },
# )
# @pytest.mark.config(
#     "ble_vulnerability_sniffer",
#     ble_vul_sniffer={
#         "script": "CC_connection_req_crash.py"
#     },
# )
# def test_verify_dut_with_CC_connection_req_crash_script_C20012(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
#     #Test case to verify DUT behaviour after executing CC_connection_req_crash.py script
#     test_duration = utf_constants.get("test_duration")
#     ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="CC_connection_req_crash.py",only_ADV=True)
#     ble_client.interfaces.bluetooth.close()
#     reset_USB_Device()

"""Test case is blocked with https://jira.silabs.com/browse/UTF-2004"""
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#     },
# )
# @pytest.mark.config(
#     "ble_vulnerability_sniffer",
#     ble_vul_sniffer={
#         "script": "extras/non_compliance_dhcheck_skip.py"
#     },
# )
# def test_verify_dut_with_non_compliance_dhcheck_skip_script_C20013(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
#     #Test case to verify DUT behaviour after executing non_compliance_dhcheck_skip.py script
#     test_duration = utf_constants.get("test_duration")
#     ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="non_compliance_dhcheck_skip.py")
#     ble_client.interfaces.bluetooth.close()
#     reset_USB_Device()

"""Test case is blocked with https://jira.silabs.com/browse/UTF-2151"""
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#     },
# )
# @pytest.mark.config(
#     "ble_vulnerability_sniffer",
#     ble_vul_sniffer={
#         "script": "esp32_hci_desync.py"
#     },
# )
# def test_verify_dut_with_esp32_hci_desync_script_C20014(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
#     #Test case to verify DUT behaviour after executing esp32_hci_desync.py script
#     test_duration = utf_constants.get("test_duration")
#     ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="esp32_hci_desync")
#     ble_client.interfaces.bluetooth.close()
#     reset_USB_Device()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.config(
    "ble_vulnerability_sniffer",
    ble_vul_sniffer={
        "script": "zephyr_invalid_sequence.py"
    },
)
def test_verify_dut_with_zephyr_invalid_sequence_script_C20015(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
    #Test case to verify DUT behaviour after executing zephyr_invalid_sequence.py script
    test_duration = utf_constants.get("test_duration")
    ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="zephyr_invalid_sequence")
    ble_client.interfaces.bluetooth.close()
    reset_USB_Device()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.config(
    "ble_vulnerability_sniffer",
    ble_vul_sniffer={
        "script": "invalid_channel_map.py"
    },
)
def test_verify_dut_with_Invalid_Channel_Map_script_C20016(ble_dut, ble_client, ble_vulnerability_sniffer, utf_constants):
    #Test case to verify DUT behaviour after executing Invalid_Channel_Map.py script
    test_duration = utf_constants.get("test_duration")
    ble_vulnerability(ble_dut=ble_dut,ble_vulnerability_sniffer=ble_vulnerability_sniffer, test_duration=test_duration, script_name="Invalid_Channel_Map", only_ADV=True)
    ble_client.interfaces.bluetooth.close()
    reset_USB_Device()