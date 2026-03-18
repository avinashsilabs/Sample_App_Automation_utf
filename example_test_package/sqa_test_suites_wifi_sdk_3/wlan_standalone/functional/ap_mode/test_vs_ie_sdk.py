import re
import time
import pytest
import uuid
import random
from random import randint
from datetime import datetime
import string
from utf.utf_config import UtfConfig
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xOperatingMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xIEMgmtBitMap,
    Si91xIEUniqueIdentifiers,
)
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.sl_status import SLStatus

"""
Author: Achal Raghav

Description:
This file contains test cases for validating Vendor Specific Information Element (VS IE) 
injection capabilities of the Wi-Fi SDK. The tests ensure the Device Under Test (DUT) 
can correctly inject, manage, and validate Vendor Specific IEs in various management 
frames across different operating modes including Soft AP, STA, and Concurrent modes. 
The tests verify VS IE functionality in beacons, probe requests/responses, and 
association requests/responses frames.

Test Cases Overview:
- C893061: VS IE injection in Soft AP management frames (Beacon, Probe Response, Association Response)
- C893062: VS IE injection in STA management frames (Probe Request, Association Request)
- C893063: VS IE injection in Concurrent mode management frames (all frame types)
- C893064: VS IE remove all API in Soft AP management frames (validate removal of all vendor IEs)
- C893065: VS IE three IE addition failure (test maximum limit of vendor IEs)
- C893066: VS IE injection with maximum 255 bytes vendor data (test maximum payload size)
- C893068: VS IE not retained after DUT reinitialization (validate IE persistence after deinit/init)
- C893069: VS IE add/remove in concurrent mode long run (with continuous TCP traffic)
- C893070: VS IE injection in probe requests during background scan in STA mode
- C893072: VS IE injection error with invalid/non-reserved management frame bitmap
- C893073: VS IE overriding with existing unique ID in concurrent mode
- C893074: VS IE presence after rejoin (AP power cycle scenario with rejoin functionality)
- C893076: VS IE injection presence doesn't lead to failure upon repeated Addition and Removal

Requirements:
- Python 3.x
- Pytest framework
- Wi-Fi DUT with VS IE injection capabilities
- Access point, sniffer, and client setup
- UTF test framework and dependencies
"""


def logger():
    return get_logger(__name__)


class ContinuousTCPTraffic(ThreadBase):
    """Thread class for continuous TCP TX traffic from DUT"""

    def __init__(
        self,
        wifi_dut=None,
        remote_socket=None,
        dut_ip=None,
        data_len=100,
        duration_seconds=None,
        server_ip=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_socket = remote_socket
        self.dut_ip = dut_ip
        self.data_len = data_len
        self.duration_seconds = duration_seconds
        self.server_ip = server_ip
        self.tcp_socket_id = None
        self.server_port = None
        self.running = False

    def run(self):
        try:

            server_port = self.remote_socket.interfaces.socket.server_port
            socket_id = self.wifi_dut.interfaces.wifi.socket()
            logger().info(f"Socket open successfully : {socket_id}")
            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=socket_id,
                device_ip=self.dut_ip,
                server_port=server_port,
                timeout=5,
                asynch=0,
            )
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
                socket_fd=socket_id, option_name="SO_KEEPALIVE", option_val=60
            )
            logger().info("DUT is connecting to server socket")
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                socket_fd=socket_id, server_ip=self.server_ip, server_port=server_port
            )
            logger().info("*********** Socket connection is successful ************")
            self.running = True
            sw = Stopwatch()
            logger().info(
                f"Starting continuous TCP TX traffic for {self.duration_seconds} seconds"
            )

            while self.running and (
                self.duration_seconds is None or sw.elapsed_sec < self.duration_seconds
            ):
                try:
                    sent_data = "".join(
                        random.choices(string.ascii_uppercase + string.digits, k=100)
                    )
                    self.wifi_dut.interfaces.wifi.bsdSocketSend(
                        socket_fd=socket_id, data=sent_data, higher_data_len=0
                    )
                    time.sleep(0.1)  # Small delay between sends
                except Exception as e:
                    logger().warning(f"Error sending TCP data: {e}")
                    time.sleep(1)
            logger().info("Continuous TCP TX traffic completed")
        except Exception as e:
            logger().error(f"Error in continuous TCP traffic: {e}")
            raise
        finally:
            self.running = False

    def stop(self):
        self.running = False
        if self.tcp_socket_id is not None:
            try:
                self.wifi_dut.interfaces.wifi.close_socket(self.tcp_socket_id)
            except:
                pass


class VSIEInjection(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_sniffer=None,
        sl_collections=None,
        wifi_client=None,
        test_case_id=None,
        ie_buffer=None,
        ie_buffer_length=None,
        unique_id=None,
        mgmt_frame_bitmap=None,
        dut_mac_address=None,
        rasp_mac_address=None,
        ap_mac_address=None,
        sniffer_filter=None,
        aput_mac_address=None,
        staut_mac_address=None,
        remote_socket=None,
        switch=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.wifi_client = wifi_client
        self.test_case_id = test_case_id
        self.ie_buffer = ie_buffer
        self.ie_buffer_length = ie_buffer_length
        self.unique_id = unique_id
        self.mgmt_frame_bitmap = mgmt_frame_bitmap
        self.dut_mac_address = dut_mac_address
        self.rasp_mac_address = rasp_mac_address
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.aput_mac_address = aput_mac_address
        self.staut_mac_address = staut_mac_address
        self.remote_socket = remote_socket
        self.switch = switch

    def add_vendor_specific_ie(self):
        unique_id = self.wifi_dut.interfaces.wifi.add_vendor_ie(
            ie_buffer=self.ie_buffer,
            ie_buffer_length=self.ie_buffer_length,
            unique_id=self.unique_id,
            mgmt_frame_bitmap=self.mgmt_frame_bitmap,
        )
        return unique_id

    def initialize_soft_ap_interface(self):
        self.sl_collections.configure_dut_in_static_ip(
            self.wifi_dut,
            static_ip="192.168.100.76",
            static_subnet="255.255.255.0",
            static_gateway="192.168.100.76",
        )
        self.wifi_dut.interfaces.wifi.start_ap(
            ssid=self.ssid,
            security=self.security,
            psk=self.passphrase,
            channel=self.channel,
            dtim_beacon_count=4,
            beacon_interval=100,
            ht_caps=0,
        )
        self.wifi_client.interfaces.wifi.join(
            ssid=self.ssid, security=self.security, passphrase=self.passphrase
        )
        dut_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
        client_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"DUT IP ADDRESS : {dut_ip} and RASPI IP ADDRESS : {client_ip}")

        self.rasp_mac_address = self.wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"RASPI MAC ADDRESS: {self.rasp_mac_address}")

        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count:10")
        rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}"
        )
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")

    def initialize_sta_interface(self):
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"\n ACCESS POINT BSSID: {self.ap_mac_address} \n")
        scan_result = self.wifi_dut.interfaces.wifi.scan()
        logger().info(f"\n The WiFi Scan Results Are: {scan_result}")
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.wifi_access_point.interfaces.wifi.ssid,
            security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
            passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
            channel=self.wifi_access_point.interfaces.wifi.channel,
        )
        logger().info(f"\n Connected to the Access Point \n")

    def validate_vendor_specific_ie(self, mode: str, ie_buffer: str):
        split_ie_buffer = ie_buffer.split()

        vendor_ie_filter = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                tag_length=int(split_ie_buffer[1], 16),
                oui=int("".join(split_ie_buffer[2:5]), 16),
                oui_type_subtype=split_ie_buffer[5],
                vendor_data="".join(split_ie_buffer[5:]),
                filter_name="vendor_information_element",
            )
        )

        if mode == "ap" or mode == "concurrent":
            # Validate Beacons
            beacon_frame_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address, filter_name="beacon"
                )
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=f"{vendor_ie_filter} and {beacon_frame_filter}",
            )["packet_count"], "\n Vendor Information Element Missing in Beacons \n"
            # Validate Probe Responses
            probe_response_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address,
                    da_addr=self.rasp_mac_address,
                    filter_name="probe_response",
                )
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=f"{vendor_ie_filter} and {probe_response_filter}",
            )[
                "packet_count"
            ], "\n Vendor Information Element Missing in Probe Responses \n"
            # Validate Association Responses
            association_response_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address,
                    da_addr=self.rasp_mac_address,
                    filter_name="association_response",
                )
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=f"{vendor_ie_filter} and {association_response_filter}",
            )[
                "packet_count"
            ], "Vendor Information Element Missing in Association Responses \n"

        if mode == "sta" or mode == "concurrent":
            # Validate Probe Requests
            probe_request_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.staut_mac_address,
                    da_addr=self.ap_mac_address,
                    filter_name="probe_request",
                )
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=f"{vendor_ie_filter} and {probe_request_filter}",
            )[
                "packet_count"
            ], "\n Vendor Information Element Missing in Probe Requests \n"

            # Validate Association Requests
            association_request_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.staut_mac_address,
                    da_addr=self.ap_mac_address,
                    filter_name="association_request",
                )
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=f"{vendor_ie_filter} and {association_request_filter}",
            )[
                "packet_count"
            ], "Vendor Information Element Missing in Association Requests \n"

    def run(self):
        config = getattr(self.wifi_dut, "config", {})
        self.wifi_config = config.get("interfaces", {}).get("wifi", {})

        self.ssid = self.wifi_config.get("ssid")
        self.passphrase = self.wifi_config.get("passphrase")
        self.channel = self.wifi_config.get("channel")
        self.security = self.wifi_config.get("security")

        if self.test_case_id == "C893061":
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"DUT MAC ADDRESS : {self.aput_mac_address}")
            self.add_vendor_specific_ie()
            self.initialize_soft_ap_interface()
            self.validate_vendor_specific_ie(mode="ap", ie_buffer=self.ie_buffer)
        elif self.test_case_id == "C893062":
            self.staut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"DUT MAC ADDRESS : {self.staut_mac_address}")
            self.add_vendor_specific_ie()
            self.initialize_sta_interface()
            self.validate_vendor_specific_ie(mode="sta", ie_buffer=self.ie_buffer)
        elif self.test_case_id == "C893063":
            self.add_vendor_specific_ie()
            self.initialize_soft_ap_interface()
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(
                interface=2
            )
            logger().info(f"AP INTERFACE MAC ADDRESS : {self.aput_mac_address}")
            self.initialize_sta_interface()
            self.staut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"DUT MAC ADDRESS : {self.staut_mac_address}")
            self.validate_vendor_specific_ie(
                mode="concurrent", ie_buffer=self.ie_buffer
            )
        elif self.test_case_id == "C893064":
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"AP INTERFACE MAC ADDRESS : {self.aput_mac_address}")
            self.add_vendor_specific_ie()
            secondary_ie_buffer = "dd 05 ab cd ef 01 ea"
            self.wifi_dut.interfaces.wifi.add_vendor_ie(
                ie_buffer=secondary_ie_buffer,
                ie_buffer_length=len(secondary_ie_buffer.split()),
                unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
                mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
                | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
                | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
            )
            self.initialize_soft_ap_interface()
            self.validate_vendor_specific_ie(mode="ap", ie_buffer=self.ie_buffer)
            self.validate_vendor_specific_ie(mode="ap", ie_buffer=secondary_ie_buffer)
            self.wifi_sniffer.interfaces.capture.stop_capture()
            self.wifi_dut.interfaces.wifi.remove_all_vendor_ie()
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=11)
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=f"Validate_VS_IE_POST_REMOVE_ALL_CAPTURE_C893064"
            )
            self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            self.initialize_soft_ap_interface()
            split_ie_buffer = self.ie_buffer.split()
            vendor_ie_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    tag_length=int(split_ie_buffer[1], 16),
                    oui=int("".join(split_ie_buffer[2:5]), 16),
                    oui_type_subtype=split_ie_buffer[5],
                    vendor_data="".join(split_ie_buffer[5:]),
                    filter_name="vendor_information_element",
                )
            )
            # Validate Beacons
            beacon_frame_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address, filter_name="beacon"
                )
            )
            assert (
                self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=f"{vendor_ie_filter} and {beacon_frame_filter}",
                )["packet_count"]
                == False
            ), "\n Vendor Information Element Missing in Beacons \n"
            # Validate Probe Responses
            probe_response_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address,
                    da_addr=self.rasp_mac_address,
                    filter_name="probe_response",
                )
            )
            assert (
                self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=f"{vendor_ie_filter} and {probe_response_filter}",
                )["packet_count"]
                == False
            ), "\n Vendor Information Element Missing in Probe Responses \n"
            # Validate Association Responses
            association_response_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address,
                    da_addr=self.rasp_mac_address,
                    filter_name="association_response",
                )
            )
            assert (
                self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=f"{vendor_ie_filter} and {association_response_filter}",
                )["packet_count"]
                == False
            ), "Vendor Information Element Missing in Association Responses \n"

        elif self.test_case_id == "C893065":
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"AP INTERFACE MAC ADDRESS : {self.aput_mac_address}")
            self.add_vendor_specific_ie()
            secondary_ie_buffer = "dd 05 ab cd ef 01 ea"
            self.wifi_dut.interfaces.wifi.add_vendor_ie(
                ie_buffer=secondary_ie_buffer,
                ie_buffer_length=len(secondary_ie_buffer.split()),
                unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
                mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
                | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
                | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
            )
            logger().info(
                f"\n Adding Terenary IE to validate maximum limit of 2 IE's \n"
            )
            terenary_ie_buffer = "dd 05 ae ce ef 01 eb"
            self.wifi_dut.interfaces.wifi.add_vendor_ie(
                ie_buffer=terenary_ie_buffer,
                ie_buffer_length=len(terenary_ie_buffer.split()),
                unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
                mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
                | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
                | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
                expected_status=SLStatus.SL_STATUS_SI91X_VENDOR_IE_NO_SLOTS_AVAILABLE,
            )
            self.initialize_soft_ap_interface()
            self.validate_vendor_specific_ie(mode="ap", ie_buffer=self.ie_buffer)
            self.validate_vendor_specific_ie(mode="ap", ie_buffer=secondary_ie_buffer)
            self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            self.wifi_sniffer.interfaces.capture.stop_capture()
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=11)
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=f"Validate_VS_IE_POST_THREE_IE_ADDITION_FAILURE_C893065"
            )
            self.initialize_soft_ap_interface()
            self.validate_vendor_specific_ie(mode="ap", ie_buffer=self.ie_buffer)
            self.validate_vendor_specific_ie(mode="ap", ie_buffer=secondary_ie_buffer)

        elif self.test_case_id == "C893066":
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"AP INTERFACE MAC ADDRESS : {self.aput_mac_address}")
            self.add_vendor_specific_ie()
            self.initialize_soft_ap_interface()

            # Validate Beacons
            beacon_frame_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address, filter_name="beacon"
                )
            )
            self.validate_information_element(
                packet_filter=f"{beacon_frame_filter}", ie_buffer=self.ie_buffer
            )
            # Validate Probe Responses
            probe_response_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address,
                    da_addr=self.rasp_mac_address,
                    filter_name="probe_response",
                )
            )
            self.validate_information_element(
                packet_filter=f"{probe_response_filter}", ie_buffer=self.ie_buffer
            )
            # Validate Association Responses
            association_response_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address,
                    da_addr=self.rasp_mac_address,
                    filter_name="association_response",
                )
            )
            self.validate_information_element(
                packet_filter=f"{association_response_filter}", ie_buffer=self.ie_buffer
            )

        elif self.test_case_id == "C893068":
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"AP INTERFACE MAC ADDRESS : {self.aput_mac_address}")
            self.add_vendor_specific_ie()
            self.initialize_soft_ap_interface()
            self.validate_vendor_specific_ie(mode="ap", ie_buffer=self.ie_buffer)
            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info(f"\n Deinitializing The DUT \n")
            self.wifi_dut.interfaces.wifi.deinit()
            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            self.wifi_dut.interfaces.wifi.init()
            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=11)
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=f"Validate_VS_IE_POST_POWER_CYCLE_C893068"
            )
            self.initialize_soft_ap_interface()
            split_ie_buffer = self.ie_buffer.split()
            vendor_ie_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    tag_length=int(split_ie_buffer[1], 16),
                    oui=int("".join(split_ie_buffer[2:5]), 16),
                    oui_type_subtype=split_ie_buffer[5],
                    vendor_data="".join(split_ie_buffer[5:]),
                    filter_name="vendor_information_element",
                )
            )
            # Validate Beacons shouldn't contain VS IE
            beacon_frame_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address, filter_name="beacon"
                )
            )
            assert (
                self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=f"{vendor_ie_filter} and {beacon_frame_filter}",
                )["packet_count"]
                == False
            ), "\n Vendor Information Element Missing in Beacons \n"
            # Validate Probe Responses shouldn't contain VS IE
            probe_response_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address,
                    da_addr=self.rasp_mac_address,
                    filter_name="probe_response",
                )
            )
            assert (
                self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=f"{vendor_ie_filter} and {probe_response_filter}",
                )["packet_count"]
                == False
            ), "\n Vendor Information Element Missing in Probe Responses \n"
            # Validate Association Responses shouldn't contain VS IE
            association_response_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.aput_mac_address,
                    da_addr=self.rasp_mac_address,
                    filter_name="association_response",
                )
            )
            assert (
                self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=f"{vendor_ie_filter} and {association_response_filter}",
                )["packet_count"]
                == False
            ), "Vendor Information Element Missing in Association Responses \n"
        elif self.test_case_id == "C893070":
            self.staut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"STA INTERFACE MAC ADDRESS : {self.staut_mac_address}")
            self.add_vendor_specific_ie()
            self.initialize_sta_interface()
            self.validate_vendor_specific_ie(mode="sta", ie_buffer=self.ie_buffer)
            self.wifi_sniffer.interfaces.capture.stop_capture()
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=11)
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=f"Validate_VS_IE_POST_BG_SCAN_C893070"
            )
            """ Enabling BG scan """
            self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(
                adv_active_channel_time=15,
                adv_passive_channel_time=20,
                adv_enable_instant_scan=1,
                adv_trigger_level=-100,
                adv_trigger_level_change=50,
            )
            logger().info("\n *** Enabled BgScan *** \n")
            self.wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
            split_ie_buffer = self.ie_buffer.split()
            vendor_ie_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    tag_length=int(split_ie_buffer[1], 16),
                    oui=int("".join(split_ie_buffer[2:5]), 16),
                    oui_type_subtype=split_ie_buffer[5],
                    vendor_data="".join(split_ie_buffer[5:]),
                    filter_name="vendor_information_element",
                )
            )
            # Validate Probe Requests
            probe_request_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.staut_mac_address,
                    da_addr=self.ap_mac_address,
                    filter_name="probe_request",
                )
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=f"{vendor_ie_filter} and {probe_request_filter}",
            )[
                "packet_count"
            ], "\n Vendor Information Element Missing in Probe Requests \n"
        elif self.test_case_id == "C893073":
            ie_unique_id = self.add_vendor_specific_ie()
            logger().info(f"\n *** IE Unique ID: {ie_unique_id} *** \n")
            self.initialize_soft_ap_interface()
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(
                interface=2
            )
            logger().info(f"AP INTERFACE MAC ADDRESS : {self.aput_mac_address}")
            self.initialize_sta_interface()
            self.staut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(
                interface=1
            )
            logger().info(f"STATION INTERFACE MAC ADDRESS : {self.staut_mac_address}")
            self.validate_vendor_specific_ie(
                mode="concurrent", ie_buffer=self.ie_buffer
            )
            logger().info(f"\n Disconnecting STA from AP and Clients from APUT \n")
            self.wifi_dut.interfaces.wifi.leave()
            self.wifi_client.interfaces.wifi.leave()
            self.wifi_sniffer.interfaces.capture.stop_capture()
            secondary_ie_buffer = "dd 05 ab cd ef 01 ea"
            self.wifi_dut.interfaces.wifi.add_vendor_ie(
                ie_buffer=secondary_ie_buffer,
                ie_buffer_length=len(secondary_ie_buffer.split()),
                unique_id=ie_unique_id,
                mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
                | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_REQ
                | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
                | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_REQ
                | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
            )
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=11)
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=f"Validate_VS_IE_AFTER_OVERRIDING_C893073"
            )
            self.wifi_client.interfaces.wifi.join(
                ssid=self.ssid, security=self.security, passphrase=self.passphrase
            )
            dut_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
            client_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(
                f"DUT IP ADDRESS : {dut_ip} and RASPI IP ADDRESS : {client_ip}"
            )

            self.rasp_mac_address = self.wifi_client.interfaces.wifi.get_mac_address()
            logger().info(f"RASPI MAC ADDRESS: {self.rasp_mac_address}")

            logger().info(f"Initiating wlan ping from RASPI_STA for ping_count:10")
            rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(
                f"sudo ping -c {10} {dut_ip}"
            )
            assert rc == 0, f"RASPI-STA failed to ping DUT"
            logger().info(
                f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n"
            )
            self.initialize_sta_interface()
            self.validate_vendor_specific_ie(
                mode="concurrent", ie_buffer=secondary_ie_buffer
            )

        elif self.test_case_id == "C893075":
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(
                interface=2
            )
            logger().info(f"AP INTERFACE MAC ADDRESS : {self.aput_mac_address}")
            self.add_vendor_specific_ie()
            self.initialize_soft_ap_interface()
            self.initialize_sta_interface()
            self.validate_vendor_specific_ie(
                mode="concurrent", ie_buffer=self.ie_buffer
            )
            self.wifi_sniffer.interfaces.capture.stop_capture()
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=11)
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=f"Validate_VS_IE_POST_BG_SCAN_CONCURRENT_MODE_C893075"
            )
            self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(
                adv_active_channel_time=15,
                adv_passive_channel_time=20,
                adv_enable_instant_scan=1,
                adv_trigger_level=-100,
                adv_trigger_level_change=50,
            )
            logger().info("\n *** Enabled BgScan *** \n")
            self.wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
            self.validate_vendor_specific_ie(mode="sta", ie_buffer=self.ie_buffer)
        elif self.test_case_id == "C893075":
            self.add_vendor_specific_ie()
            self.initialize_soft_ap_interface()
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(
                interface=2
            )
            logger().info(f"AP INTERFACE MAC ADDRESS : {self.aput_mac_address}")
            self.initialize_sta_interface()
            self.staut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"DUT MAC ADDRESS : {self.staut_mac_address}")
            self.validate_vendor_specific_ie(
                mode="concurrent", ie_buffer=self.ie_buffer
            )
        elif self.test_case_id == "C893072":
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"DUT MAC ADDRESS : {self.aput_mac_address}")
            self.wifi_dut.interfaces.wifi.add_vendor_ie(
                ie_buffer=self.ie_buffer,
                ie_buffer_length=self.ie_buffer_length,
                unique_id=self.unique_id,
                mgmt_frame_bitmap=self.mgmt_frame_bitmap,
                expected_status=SLStatus.SL_STATUS_SI91X_VENDOR_IE_INVALID_PACKET_BITMAP,
            )
            logger().info(
                f"\n Adding IE with invalid mgmt frame bitmap failed which is Expected behaviour \n"
            )
        elif self.test_case_id == "C893069":
            # self.add_vendor_specific_ie()
            self.initialize_soft_ap_interface()
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(
                interface=2
            )
            logger().info(f"AP INTERFACE MAC ADDRESS : {self.aput_mac_address}")
            self.initialize_sta_interface()
            ip_config = self.wifi_dut.interfaces.wifi.start_ip()
            device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"Device IP Address : {device_ip}")
            self.staut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"DUT MAC ADDRESS : {self.staut_mac_address}")
            logger().info(f"\n Starting the Remote Socket Server \n")
            self.remote_socket.interfaces.socket.start_server(port=randint(5001, 6000))
            server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
            # self.validate_vendor_specific_ie(
            #    mode="concurrent", ie_buffer=self.ie_buffer
            # )
            # Start continuous TCP TX traffic in background
            tcp_traffic_thread = None
            if self.remote_socket:
                logger().info("Starting continuous TCP TX traffic from DUT")
                tcp_traffic_thread = ContinuousTCPTraffic(
                    wifi_dut=self.wifi_dut,
                    remote_socket=self.remote_socket,
                    dut_ip=device_ip,
                    data_len=100,
                    duration_seconds=100,  # 12 hours,
                    server_ip=server_ip,
                )
                tcp_traffic_thread.start()
                time.sleep(50)  # Allow TCP connection to establish
        elif self.test_case_id == "C893074":
            """Enabling Rejoin"""
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
                max_retry_attempts=0,
                scan_interval=6,
                beacon_missed_count=40,
                first_time_retry_enable=0,
            )
            self.staut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"DUT MAC ADDRESS : {self.staut_mac_address}")
            self.add_vendor_specific_ie()
            self.initialize_sta_interface()
            self.validate_vendor_specific_ie(mode="sta", ie_buffer=self.ie_buffer)
            self.wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("\n *** Start sniffer configuration *** \n")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel
            )
            logger().info("Start sniffer capture")
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=f"POST_REJOIN"
            )

            logger().info("***** Turn off Access Point *****")
            self.switch.interfaces.pdu_switch.turn_off(delay=10)
            logger().info("\n\n Adding sleep for 10 sec \n")
            time.sleep(20)
            self.wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("***** Turn on Access Point *****")
            self.switch.interfaces.pdu_switch.turn_on(delay=60)
        elif self.test_case_id == "C893076":
            unique_id = self.add_vendor_specific_ie()
            self.initialize_soft_ap_interface()
            self.aput_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(
                interface=2
            )
            logger().info(f"AP INTERFACE MAC ADDRESS : {self.aput_mac_address}")
            self.initialize_sta_interface()
            self.staut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"DUT MAC ADDRESS : {self.staut_mac_address}")
            self.validate_vendor_specific_ie(
                mode="concurrent", ie_buffer=self.ie_buffer
            )
            self.wifi_sniffer.interfaces.capture.stop_capture()
            split_ie_buffer = self.ie_buffer.split()
            vendor_ie_filter = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    tag_length=int(split_ie_buffer[1], 16),
                    oui=int("".join(split_ie_buffer[2:5]), 16),
                    oui_type_subtype=split_ie_buffer[5],
                    vendor_data="".join(split_ie_buffer[5:]),
                    filter_name="vendor_information_element",
                )
            )
            for iteration in range(5):
                logger().info(f"\n *** Iteration : {iteration+1} *** \n")
                self.wifi_dut.interfaces.wifi.remove_vendor_ie(unique_id=unique_id)
                self.wifi_sniffer.interfaces.capture.configure_interface(channel=11)
                self.wifi_sniffer.interfaces.capture.start_capture(
                    capture_file=f"Validate_VS_IE_Removal_{iteration+1}_Iteration_C893078"
                )
                # Validate Beacons
                beacon_frame_filter = (
                    self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.aput_mac_address, filter_name="beacon"
                    )
                )
                assert (
                    self.wifi_sniffer.interfaces.capture.sniffer_validation(
                        packet_filter1=f"{vendor_ie_filter} and {beacon_frame_filter}",
                    )["packet_count"]
                    == False
                ), "\n Vendor Information Element Present in Beacons \n"
                self.wifi_sniffer.interfaces.capture.stop_capture()
                logger().info(f"\n Re-adding the VS IE \n")
                unique_id = self.add_vendor_specific_ie()
                self.wifi_sniffer.interfaces.capture.configure_interface(channel=11)
                self.wifi_sniffer.interfaces.capture.start_capture(
                    capture_file=f"Validate_VS_IE_Addition_{iteration + 1}_Iteration_C893078"
                )
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=f"{vendor_ie_filter} and {beacon_frame_filter}",
                )["packet_count"], "\n Vendor Information Element Missing in Beacons \n"
                self.wifi_sniffer.interfaces.capture.stop_capture()

        else:
            pass

    def validate_information_element(self, packet_filter: str, ie_buffer=None):
        split_ie_buffer = ie_buffer.split()
        vendor_data = "".join(split_ie_buffer[5:])
        vendor_ie_filter = f"(wlan.tag.number == 221 and wlan.tag.length == {int(split_ie_buffer[1], 16)} and wlan.tag.vendor.oui.type == {split_ie_buffer[5]})"
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=f"{vendor_ie_filter} and {packet_filter}",
        )["packet_count"], "\n OUI, Length attribute Mismatch \n"
        current_time = time.time()
        updated_capture_file = (
            "filter_wireshark_capture"
            + "_"
            + str(datetime.fromtimestamp(current_time).strftime("%H_%M_%S"))
        )
        file_name = f"./reports/{updated_capture_file}.pcap"
        local_capture_file = file_name
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
        self.wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {self.wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter}' -T fields -e "
            f"frame.number -w "
            f"{wlan_filter_file}"
        )
        with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
            sftp.get(wlan_filter_file, local_capture_file)
        for packet in self.wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=False,
            encryption_type="WPA-PWD",
            capture_file_filter=local_capture_file,
        ):
            if packet["wlan.mgt"]:
                logger().info(
                    f" Vendor Data : {packet['wlan.mgt'].wlan_tag_vendor_data.replace(':', '')} "
                )
                break
        assert (
            packet["wlan.mgt"].wlan_tag_vendor_data.replace(":", "") == vendor_data
        ), "\n Vendor Data Mismatch \n"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["stop_ap_beaconing"])
@pytest.mark.WLAN_Dev_sanity_917
def test_vs_ie_injection_in_soft_ap_mgmt_frames_C893061(
    wifi_dut, wifi_sniffer, wifi_client, request, sl_collections, sniffer_filter
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_client=wifi_client,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C893061",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_dut.interfaces.wifi.remove_all_vendor_ie()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_vs_ie_injection_in_sta_mgmt_frames_C893062(
    wifi_dut, wifi_sniffer, wifi_access_point, sl_collections, request, sniffer_filter
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            test_case_id="C893062",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_REQ
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_REQ,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_dut.interfaces.wifi.remove_all_vendor_ie()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2",
        "ssid": "TEST_VS_IE_AP_INTERFACE",
        "passphrase": "Automation@123",
        "channel": 11,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_ASUS_AP",
        "passphrase": "Asus@12345",
        "channel": 11,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_AP_INTERFACE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["stop_ap_beaconing", "unassociated"])
def test_vs_ie_injection_in_concurrent_mode_mgmt_frames_C893063(
    wifi_dut,
    wifi_sniffer,
    wifi_client,
    wifi_access_point,
    sl_collections,
    request,
    sniffer_filter,
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C893063",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_REQ
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_REQ
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_dut.interfaces.wifi.remove_all_vendor_ie()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
        "region": 1,
        "region_code": "us",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["stop_ap_beaconing"])
def test_vs_ie_remove_all_api_in_soft_ap_mgmt_frames_C893064(
    wifi_dut, wifi_sniffer, wifi_client, request, sl_collections, sniffer_filter
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_client=wifi_client,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C893064",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
        "region": 1,
        "region_code": "us",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.end_state("wifi_dut", wifi=["stop_ap_beaconing"])
def test_vs_ie_three_ie_addition_failure_C893065(
    wifi_dut, wifi_sniffer, wifi_client, request, sl_collections, sniffer_filter
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_client=wifi_client,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C893065",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_dut.interfaces.wifi.remove_all_vendor_ie()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
        "region": 1,
        "region_code": "us",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.end_state("wifi_dut", wifi=["stop_ap_beaconing"])
def test_vs_ie_injection_with_max_255_bytes_vendor_data_C893066(
    wifi_dut, wifi_sniffer, wifi_client, request, sl_collections, sniffer_filter
):
    try:
        ie_buffer = (
            "dd fe aa bb cc 01 ab cd ef 10 22 33 44 55 66 77 88 99 aa bb cc dd ee "
            "ff 02 13 24 35 46 57 68 79 8a 9b ac bd ce df e1 f2 03 14 25 36 47 58 "
            "69 7a 8b 9c ad be cf d0 e2 f3 04 15 26 37 48 59 6a 7b 8c 9d ae bf c1 "
            "d2 e3 f4 05 16 27 38 49 5a 6b 7c 8d 9e af b0 c2 d3 e4 f5 06 17 28 39 "
            "4a 5b 6c 7d 8e 9f a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d 7e 8f a0 b1 "
            "c4 d5 e6 f7 08 19 2a 3b 4c 5d 6e 7f 90 a2 b3 c5 d6 e7 f8 09 1a 2b 3c "
            "4d 5e 6f 80 91 a3 b4 c6 d7 e8 f9 0a 1b 2c 3d 4e 5f 70 81 92 a4 b5 c7 "
            "d8 e9 fa 0b 1c 2d 3e 4f 60 71 82 93 a5 b6 c8 d9 ea fb 0c 1d 2e 3f 50 "
            "61 72 83 94 a6 b7 c9 da eb fc 0d 1e 2f 40 51 62 73 84 95 a7 b8 ca db "
            "ec fd 0e 1f 30 41 52 63 74 85 96 a8 b9 cb dc ed fe 0f 20 31 42 53 64 "
            "75 86 97 a9 ba cc dd ee ff 11 21 32 43 54 65 76 87 98 aa bb cd de ef "
            "9a ab bc"
        )

        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_client=wifi_client,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C893066",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_dut.interfaces.wifi.remove_all_vendor_ie()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
        "region": 1,
        "region_code": "us",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["stop_ap_beaconing"])
def test_vs_ie_not_retained_after_dut_reinitialization_C893068(
    wifi_dut, wifi_sniffer, wifi_client, request, sl_collections, sniffer_filter
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_client=wifi_client,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C893068",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2",
        "ssid": "TEST_VS_IE_AP_INTERFACE",
        "passphrase": "Automation@123",
        "channel": 11,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "security": "OPEN",
        "ssid": "TEST_VS_IE_ASUS_AP",
        "passphrase": "Asus@12345",
        "channel": 11,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_AP_INTERFACE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.skip(reason="Marking this Manual")
@pytest.mark.end_state("wifi_dut", wifi=["stop_ap_beaconing", "unassociated"])
def test_vs_ie_add_remove_in_concurrent_mode_long_run_C893069(
    wifi_dut,
    wifi_sniffer,
    wifi_client,
    wifi_access_point,
    sl_collections,
    request,
    sniffer_filter,
    remote_socket,
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sniffer_filter=sniffer_filter,
            remote_socket=remote_socket,
            sl_collections=sl_collections,
            test_case_id="C893069",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_REQ
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_REQ
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_dut.interfaces.wifi.remove_all_vendor_ie()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_vs_ie_injection_in_probe_reqs_during_bg_scan_C893070(
    wifi_dut, wifi_sniffer, wifi_access_point, sl_collections, request, sniffer_filter
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            test_case_id="C893070",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_REQ
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_REQ,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_dut.interfaces.wifi.remove_all_vendor_ie()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["stop_ap_beaconing"])
def test_vs_ie_injection_error_with_non_reserved_bitmap_C893072(
    wifi_dut, wifi_sniffer, wifi_client, request, sl_collections, sniffer_filter
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_client=wifi_client,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C893072",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=0,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_dut.interfaces.wifi.remove_all_vendor_ie()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2",
        "ssid": "TEST_VS_IE_AP_INTERFACE",
        "passphrase": "Automation@123",
        "channel": 11,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_ASUS_AP",
        "passphrase": "Asus@12345",
        "channel": 11,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_AP_INTERFACE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["stop_ap_beaconing", "unassociated"])
def test_vs_ie_overriding_with_existing_unique_id_C893073(
    wifi_dut,
    wifi_sniffer,
    wifi_client,
    wifi_access_point,
    sl_collections,
    request,
    sniffer_filter,
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C893073",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_REQ
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_REQ
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_dut.interfaces.wifi.remove_all_vendor_ie()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_INJECTION",
        "passphrase": "Automation@123",
        "channel": 11,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_vs_ie_presence_after_rejoin_C893074(
    switch,
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    sl_collections,
    request,
    sniffer_filter,
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            switch=switch,
            test_case_id="C893074",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_REQ
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_REQ,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_dut.interfaces.wifi.remove_all_vendor_ie()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2",
        "ssid": "TEST_VS_IE_AP_INTERFACE",
        "passphrase": "Automation@123",
        "channel": 11,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_ASUS_AP",
        "passphrase": "Asus@12345",
        "channel": 11,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_VS_IE_AP_INTERFACE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["stop_ap_beaconing", "unassociated"])
def test_vs_ie_injection_using_continious_add_remove_C893076(
    wifi_dut,
    wifi_sniffer,
    wifi_client,
    wifi_access_point,
    sl_collections,
    request,
    sniffer_filter,
):
    try:
        ie_buffer = "dd 05 aa bb cc 01 ee"
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        validate_vs_ie = VSIEInjection(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_case_id="C893076",
            ie_buffer=ie_buffer,
            ie_buffer_length=len(ie_buffer.split()),
            unique_id=Si91xIEUniqueIdentifiers.SL_WIFI_VENDOR_IE_AUTO_ASSIGN,
            mgmt_frame_bitmap=Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_BEACON
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_REQ
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_PROBE_RESP
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_REQ
            | Si91xIEMgmtBitMap.SL_WIFI_VENDOR_IE_IN_ASSOC_RESP,
        )
        validate_vs_ie.start()
        validate_vs_ie.wait_for_exit()
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_dut.interfaces.wifi.remove_all_vendor_ie()
