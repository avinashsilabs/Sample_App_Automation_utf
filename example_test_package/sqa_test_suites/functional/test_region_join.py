import pytest
import time
import re
from datetime import datetime, date
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut

    Author: Aravind 
"""

class FilterPacket:
    def find_time_stamp(self):
        packet_filter1 = "Arrival Time:"
        count = 0
        time_diff_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter1 in x:
                result = re.search('2022(.*)IST', x)
                time_stamp = result.group(1).strip()
                logger().info(f'time_stamp={time_stamp}')
                time_diff_list.append(time_stamp)

        filter_file.close()
        return time_diff_list


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 0,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    },
)
def test_join_ASIA_2_4(wifi_access_point, wifi_dut ):


    logger().info(" setting channel 13 in AP...")
    wifi_access_point.interfaces.wifi.config['channel'] = 13
    # Set the region value in AP side
    logger().info("configuring AP in Asia region...")
    wifi_access_point.interfaces.wifi.config['region'] = 'Asia'
    # Set the region value in DUT side
    logger().info("configuring AP.....")

    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(30)
    logger().info("DUT Joining to AP in Asia region...")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info("DUT obtaining ip through DHCP")
    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")
    logger().info("connectivity success in Asia region.. ")

@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 0,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    },
)
def test_join_EU_2_4(wifi_access_point, wifi_dut ):

    logger().info(" setting channel 12 in AP...")
    wifi_access_point.interfaces.wifi.config['channel'] = 12
    # Set the region value in AP side
    logger().info("configuring AP in EU region...")
    wifi_access_point.interfaces.wifi.config['region'] = 'Europe'
    # Set the region value in DUT side
    logger().info("configuring AP.....")

    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(30)


    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info("DUT Joining to AP in Europe region...")

    result = wifi_dut.interfaces.wifi.start_ip()
    logger().info("DUT obtaining ip through DHCP.....")
    dut_ip = result.ip.decode()

    logger().info(f"DUT ip address : {dut_ip}")
    logger().info("connectivity success in EU region.. ")


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,

        "band": 0,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    },
)
def test_join_US_2_4(wifi_access_point, wifi_dut ):

    logger().info("setting channel 11 in AP...")
    wifi_access_point.interfaces.wifi.config['channel'] = 11
    # Set the region value in AP side
    logger().info("configuring AP in US region.....")
    wifi_access_point.interfaces.wifi.config['region'] = 'US'
    # Set the region value in DUT side
    logger().info("configuring AP.....")
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(30)
    logger().info("DUT Joining to AP in US region...")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()

    logger().info(f"DUT ip address : {dut_ip}")
    logger().info("connectivity success in US region.. ")


## connectivity of DUT in US region in 5Ghz band###

@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,

        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    },
)
def test_join_US_5Ghz(wifi_access_point, wifi_dut ):

    logger().info("setting channel 36 in AP...")
    wifi_access_point.interfaces.wifi.config['channel'] = 36
    # Set the region value in AP side
    logger().info("configuring AP in US region.....")
    wifi_access_point.interfaces.wifi.config['region'] = 'US'
    # Set the region value in DUT side
    logger().info("configuring AP.....")
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(10)
    logger().info("DUT Joining to AP in US region...")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()

    logger().info(f"DUT ip address : {dut_ip}")
    logger().info("connectivity success in US region 5Ghz Band.. ")

##connectivity of DUT in EU region 5Ghz band####
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 1,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    },
)
def test_join_EU_5Ghz(wifi_access_point, wifi_dut ):

    logger().info(" setting channel 48 in AP...")
    wifi_access_point.interfaces.wifi.config['channel'] = 48
    # Set the region value in AP side
    logger().info("configuring AP in EU region...")
    wifi_access_point.interfaces.wifi.config['region'] = 'Europe'
    # Set the region value in DUT side
    logger().info("configuring AP.....")

    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(10)
    logger().info("DUT Joining to AP in Europe region...")

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info("DUT obtaining ip through DHCP.....")
    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")
    logger().info("connectivity success in EU region  with 48 channel.. ")


##Connectivity  of DUT in Asia region 5Ghz Band##
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 1,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    },
)
def test_join_ASIA_5Ghz(wifi_access_point, wifi_dut ):


    logger().info(" setting channel 44 in AP...")
    wifi_access_point.interfaces.wifi.config['channel'] = 44
    # Set the region value in AP side
    logger().info("configuring AP in Asia region...")
    wifi_access_point.interfaces.wifi.config['region'] = 'Asia'
    # Set the region value in DUT side
    logger().info("configuring AP.....")

    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(10)
    logger().info("DUT Joining to AP in Asia region...")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info("DUT obtaining ip through DHCP")
    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")
    logger().info("connectivity success in Asia region.. ")



