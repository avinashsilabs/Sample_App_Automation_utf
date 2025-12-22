import re
import time
import pytest as pytest
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf_wifi_zephyr.utils.sl_status import SLStatus
from collections import Counter
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wifi_zephyr.devices.si91x import (
    ZephyrWifiMfpOptions
)
from threading import Thread


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : gnbax
        2. Association of Third party AP's
        3. Validate MBSSID support in Third party AP's
        4. Scan available ssid's in vicinity and compare with AP configured VAP's list
        5. Connect DUT with T & NT based ssid with different security modes. 
        6. Trigger TCP/UDP traffic suing socket/iperf API's.
        7. Enable rejoin and verify the same functionality with different security modes.
       

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Vinod.G
"""


class WLanThread(ThreadBase):
    def __init__(
            self,
            wifi_dut=None,
            wifi_access_point=None,
            wifi_sniffer=None,
            test_case_no=None,
            sniffer_filter=None,
            ping_count=None,
            test_name=None,
            zephyr_wifi_collections=None,
            net_perf_client=None,
            wifi_client=None,
            switch=None,
            wifi_clients=None,
            protocol=None,
            multicast_client=None,
    ):
        super().__init__()
        self.scan_list = None
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.test_name = test_name
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.wifi_clients = wifi_clients
        self.protocol = "TCP"
        self.data = "Thisisfromclient"
        self.time_period = 60
        self.switch = switch
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        self.ssid = "SILABS_AP_MODE"
        self.security = "WPA2"
        self.password = "Automation@123"
        self.channel = "3"
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.no_of_clients = 1
        self.protocol = protocol
        self.multicast_client = multicast_client
        self.security_dict = {
            "OPEN": 0,
            "WPA2": 2,
            "WPA3": 7,
            "WPA2ENTERPRISE": 5,
            "WPA2WPA3MIXEDMODE": 8,
        }

    def run(self):
        try:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel
            )
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=self.test_name
            )

            if self.test_case_no == 219285:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.validate_rssi_channel_security()

            elif self.test_case_no == 219286:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.validate_rssi_channel_security()
                for i in range(0, 5):
                    self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                        wifi_dut=self.wifi_dut,
                        wifi_access_point=self.wifi_access_point,
                        associated=self.wifi_dut.interfaces.wifi.associated,
                        ping_after_power_save=False,
                    )

                    host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                    logger().info(f"Remote device ip :{host_ip}")
                    time.sleep(5)
                    self.zephyr_wifi_collections.run_traffic(
                        wifi_dut=self.wifi_dut,
                        net_perf_client=self.net_perf_client,
                        protocol=self.protocol,
                        device_ip=self.dut_addr["device_ip"],
                        host_ip=host_ip,
                        timeout=60,
                        traffic_type="TX",
                    )
                    time.sleep(2)
                    self.wifi_dut.interfaces.wifi.leave()
                    time.sleep(5)

            elif self.test_case_no == 219287:
                for i in range(0, 5):
                    self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                    self.validate_rssi_channel_security()
                    self.wifi_dut.interfaces.wifi.scan()
                    time.sleep(2)

                    self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                        wifi_dut=self.wifi_dut,
                        wifi_access_point=self.wifi_access_point,
                        associated=self.wifi_dut.interfaces.wifi.associated,
                        ping_after_power_save=False,
                    )

                    host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                    logger().info(f"Remote device ip :{host_ip}")
                    time.sleep(5)
                    self.net_perf_client.interfaces.net_perf.init_client(
                        host_ip=host_ip,
                        device_ip=self.dut_addr["device_ip"],
                        time_out=70,
                        protocol=self.protocol,
                        tos_value="0x00"
                    )

                    def start_client():
                        time.sleep(3)
                        logger().info(f"***** Connect to server  ******")
                        self.net_perf_client.interfaces.net_perf.start()

                    client_thread1 = Thread(target=start_client, args=(), )
                    client_thread1.start()

                    logger().info(
                        f"Host IP: {host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}"
                    )

                    logger().info(f"***** start listening  ******")
                    self.wifi_dut.interfaces.wifi.iperf(
                        family=2,
                        transfer_type=1,
                        protocol=6,
                        local_port=self.net_perf_client.interfaces.net_perf.client_port,
                        remote_ip=host_ip,
                        remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                        size=1460,
                        ttl=70,
                        throughput_type=3,
                        qos=0,
                        async_socket=0,
                        timeout=95,
                    )
                    client_thread1.join()
                    logger().info("data received is successful")
                    self.wifi_dut.interfaces.wifi.leave()
                    time.sleep(5)

            elif self.test_case_no == 219288:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.validate_rssi_channel_security()
                time.sleep(2)
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                self.wifi_dut.interfaces.wifi.join(  # ssid=vap_list[0],
                    ssid=self.wifi_access_point.interfaces.wifi.guest_networks[0]["ssid"],
                    passphrase=self.wifi_access_point.interfaces.wifi.guest_networks[0][
                        "passphrase"],
                    security=self.wifi_access_point.interfaces.wifi.guest_networks[0][
                        "security"].name.lower(), )

                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                                  wifi_access_point=self.wifi_access_point,
                                                                                  associated=False,
                                                                                  ping_after_power_save=False,
                                                                                  skip_connect=True,
                                                                                  retry_count=3, )

                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                time.sleep(5)

                self.zephyr_wifi_collections.run_traffic(
                    wifi_dut=self.wifi_dut,
                    net_perf_client=self.net_perf_client,
                    protocol=self.protocol,
                    device_ip=self.dut_addr["device_ip"],
                    host_ip=host_ip,
                    timeout=60,
                    traffic_type="TX",
                )

            elif self.test_case_no == 219289:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.validate_rssi_channel_security()
                # The below method is not supported in zephyr
                # self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                #     join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                #                         | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
                # )
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                    wifi_dut=self.wifi_dut,
                    wifi_access_point=self.wifi_access_point,
                    associated=self.wifi_dut.interfaces.wifi.associated,
                    power_save=False,
                    ping_after_power_save=False,
                    mfp=ZephyrWifiMfpOptions.WIFI_MFP_REQUIRED
                )
                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")

                self.zephyr_wifi_collections.run_traffic(
                    wifi_dut=self.wifi_dut,
                    net_perf_client=self.net_perf_client,
                    protocol=self.protocol,
                    device_ip=self.dut_addr["device_ip"],
                    host_ip=host_ip,
                    timeout=60,
                    traffic_type="RX",
                )

            elif self.test_case_no == 219290:
                for i in range(0, 5):
                    vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                    # The below feature is not supported in zephyr
                    # self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    #     join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                    #                         | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
                    # )
                    self.wifi_dut.interfaces.wifi.scan()
                    time.sleep(2)
                    self.wifi_dut.interfaces.wifi.join(
                        # ssid=vap_list[0],
                        ssid=self.wifi_access_point.interfaces.wifi.guest_networks[0]["ssid"],
                        security=self.wifi_access_point.interfaces.wifi.guest_networks[
                            0
                        ]["security"].name.lower(),
                        passphrase=self.wifi_access_point.interfaces.wifi.guest_networks[
                            0
                        ][
                            "passphrase"
                        ],
                        mfp=ZephyrWifiMfpOptions.WIFI_MFP_REQUIRED
                    )
                    self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                        wifi_dut=self.wifi_dut,
                        wifi_access_point=self.wifi_access_point,
                        associated=False,
                        ping_after_power_save=False,
                        skip_connect=True,
                        mfp=ZephyrWifiMfpOptions.WIFI_MFP_REQUIRED
                    )

                    host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                    logger().info(f"Remote device ip :{host_ip}")

                    logger().info("Stop Sniffer finally")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    self.wifi_dut.interfaces.wifi.leave()
                    time.sleep(10)



            elif self.test_case_no == 219293:
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                """ Enabling Rejoin """
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.validate_rssi_channel_security()

                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                    wifi_dut=self.wifi_dut,
                    wifi_access_point=self.wifi_access_point,
                    associated=self.wifi_dut.interfaces.wifi.associated,
                    power_save=False,
                    ping_after_power_save=False,
                )
                self.zephyr_wifi_collections.run_traffic(
                    wifi_dut=self.wifi_dut,
                    net_perf_client=self.net_perf_client,
                    protocol=self.protocol,
                    device_ip=self.dut_addr["device_ip"],
                    host_ip=host_ip,
                    timeout=60,
                    traffic_type="TX",
                )

            elif self.test_case_no == 219295:
                """Enabling Rejoin"""
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.validate_rssi_channel_security()

                self.wifi_dut.interfaces.wifi.scan()
                self.wifi_dut.interfaces.wifi.join(
                    # ssid=vap_list[0],
                    ssid=self.wifi_access_point.interfaces.wifi.guest_networks[0]["ssid"],
                    passphrase=self.wifi_access_point.interfaces.wifi.guest_networks[0][
                        "passphrase"
                    ],
                    security=self.wifi_access_point.interfaces.wifi.guest_networks[0][
                        "security"
                    ].name.lower(),
                )
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                    wifi_dut=self.wifi_dut,
                    wifi_access_point=self.wifi_access_point,
                    associated=False,
                    ping_after_power_save=False,
                    skip_connect=True,
                )

                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")

                self.zephyr_wifi_collections.run_traffic(
                    wifi_dut=self.wifi_dut,
                    net_perf_client=self.net_perf_client,
                    protocol=self.protocol,
                    device_ip=self.dut_addr["device_ip"],
                    host_ip=host_ip,
                    timeout=60,
                    traffic_type="TX",
                )

            elif self.test_case_no == 219296:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.validate_rssi_channel_security()
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                    wifi_dut=self.wifi_dut,
                    wifi_access_point=self.wifi_access_point,
                    associated=self.wifi_dut.interfaces.wifi.associated,
                    power_save=False,
                    ping_after_power_save=False,
                    mfp=ZephyrWifiMfpOptions.WIFI_MFP_REQUIRED
                )
                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                self.zephyr_wifi_collections.ping(self.dut_addr["device_ip"], ping_count=60)

            elif self.test_case_no == 219297:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.validate_rssi_channel_security()
                self.wifi_dut.interfaces.wifi.scan()
                self.wifi_dut.interfaces.wifi.join(
                    # ssid=vap_list[0],
                    ssid=self.wifi_access_point.interfaces.wifi.guest_networks[0]["ssid"],
                    security=self.wifi_access_point.interfaces.wifi.guest_networks[0][
                        "security"
                    ].name.lower(),
                    passphrase=self.wifi_access_point.interfaces.wifi.guest_networks[0][
                        "passphrase"
                    ],
                    mfp=ZephyrWifiMfpOptions.WIFI_MFP_REQUIRED
                )
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                    wifi_dut=self.wifi_dut,
                    wifi_access_point=self.wifi_access_point,
                    associated=False,
                    ping_after_power_save=False,
                    skip_connect=True,
                )
                self.zephyr_wifi_collections.ping(self.dut_addr["device_ip"], ping_count=60)

            elif self.test_case_no == 219298:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.validate_rssi_channel_security()

                self.wifi_dut.interfaces.wifi.join(
                    # ssid=vap_list[0],
                    ssid=self.wifi_access_point.interfaces.wifi.guest_networks[0]["ssid"],
                    security="open",
                    passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                    expected_status=SLStatus.SL_STATUS_FAIL,
                )

            elif self.test_case_no == 219299:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.validate_rssi_channel_security()

                self.wifi_dut.interfaces.wifi.scan()
                status = self.wifi_dut.interfaces.wifi.join(
                    # ssid=vap_list[0],
                    ssid=self.wifi_access_point.interfaces.wifi.guest_networks[0]["ssid"],
                    security=self.wifi_access_point.interfaces.wifi.guest_networks[0][
                        "security"
                    ].name.lower(),
                    passphrase="1234567899",
                    expected_status=SLStatus.SL_STATUS_FAIL
                )

            elif self.test_case_no == 219301:
                for i in range(0, 10):
                    self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                    self.validate_rssi_channel_security()
                    time.sleep(2)
                    self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                        wifi_dut=self.wifi_dut,
                        wifi_access_point=self.wifi_access_point,
                        power_save=False,
                        ping_after_power_save=False,
                        retry_count=3,
                        associated=self.wifi_dut.interfaces.wifi.associated,
                    )
                    self.zephyr_wifi_collections.ping(self.dut_addr["device_ip"], ping_count=60)
                    self.wifi_dut.interfaces.wifi.leave()
                    time.sleep(1)

            elif self.test_case_no == 219302:
                # NT BSSID based connection and disconnection multiple times
                for i in range(0, 10):
                    vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                    self.validate_rssi_channel_security()
                    time.sleep(2)
                    self.wifi_dut.interfaces.wifi.join(
                        # ssid=vap_list[0],
                        ssid=self.wifi_access_point.interfaces.wifi.guest_networks[0]["ssid"],
                        security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                        passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                    )
                    self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                        wifi_dut=self.wifi_dut,
                        wifi_access_point=self.wifi_access_point,
                        associated=False,
                        ping_after_power_save=False,
                        skip_connect=True,
                    )
                    self.zephyr_wifi_collections.ping(self.dut_addr["device_ip"], ping_count=60)
                    self.wifi_dut.interfaces.wifi.leave()
                    time.sleep(5)

            elif self.test_case_no == 219319:
                # connection with TX based BSSID in WPA2 security mode, and NT based BSSID in WPA3 security mode
                for i in range(0, 5):
                    self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                    self.validate_rssi_channel_security()

            elif self.test_case_no == 219320:
                # scan TX based BSSID in WPA3 security mode, and NT based BSSID in WPA3 Transition security
                for i in range(0, 5):
                    self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                    self.validate_rssi_channel_security()
                    time.sleep(2)

            elif self.test_case_no == 219321:
                # connection with TX based BSSID in WPA2 security mode, and NT based BSSID in WPA3 security mode
                for i in range(0, 5):
                    self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                    self.validate_rssi_channel_security()

            elif self.test_case_no == 219315:
                self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid

                # Initiate scan to find all available SSID in DUT scan list T & NT based BSSID
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.validate_rssi_channel_security()
                time.sleep(10)

                for i in range(0, 5):
                    # Initiate the connection again for T based BSSID
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel
                    )
                    self.wifi_sniffer.interfaces.capture.start_capture(
                        capture_file=self.test_name
                    )

                    self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                        wifi_dut=self.wifi_dut,
                        wifi_access_point=self.wifi_access_point,
                        associated=self.wifi_dut.interfaces.wifi.associated,
                        ping_after_power_save=False,
                    )

                    self.zephyr_wifi_collections.ping(self.dut_addr["device_ip"], ping_count=60)
                    time.sleep(2)
                    self.wifi_dut.interfaces.wifi.leave()
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    time.sleep(2)

                    # Initiate the connection again for NT based BSSID
                    vap0_mbssid = self.find_vaps_mbssid()
                    logger().info(f"VAP0 MBSSID = {vap0_mbssid}")
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel
                    )
                    self.wifi_sniffer.interfaces.capture.start_capture(
                        capture_file=self.test_name
                    )

                    self.wifi_dut.interfaces.wifi.scan()
                    self.wifi_dut.interfaces.wifi.join(
                        ssid=vap_list[0],
                        security=self.wifi_access_point.interfaces.wifi.guest_networks[
                            0
                        ]["security"].name.lower(),
                        passphrase=self.wifi_access_point.interfaces.wifi.guest_networks[
                            0
                        ][
                            "passphrase"
                        ],
                    )

                    self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                        wifi_dut=self.wifi_dut,
                        wifi_access_point=self.wifi_access_point,
                        associated=False,
                        ping_after_power_save=False,
                        skip_connect=True,
                        retry_count=3,
                    )

                    self.zephyr_wifi_collections.ping(self.dut_addr["device_ip"], ping_count=60)
                    time.sleep(2)
                    self.wifi_dut.interfaces.wifi.leave()
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    time.sleep(2)


            elif self.test_case_no == 219300:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()

                self.wifi_dut.interfaces.wifi.join(
                    ssid='""',
                    security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                    passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                    expected_negative_status=SLStatus.SL_STATUS_INVALID_PARAMETER,
                )

            elif self.test_case_no == 535830:
                try:
                    ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
                    logger().info(f"Initiating wlan Scan from DUT = {self.wifi_access_point.interfaces.wifi.ssid}")
                    scan_results = self.wifi_dut.interfaces.wifi.scan(ssid=self.wifi_access_point.interfaces.wifi.ssid)
                    logger().info(scan_results)
                    assert len(scan_results) > 0, "scan_list not found"
                    time.sleep(2)

                    self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                        wifi_dut=self.wifi_dut,
                        wifi_access_point=self.wifi_access_point,
                        associated=self.wifi_dut.interfaces.wifi.associated,
                        ping_after_power_save=False,
                    )

                    time.sleep(5)
                    self.zephyr_wifi_collections.ping(self.dut_addr["device_ip"], ping_count=120)

                    packet_filter1 = (self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter
                                      (sa_addr=ap_bssid,
                                       hidden_ssid="\"\"",
                                       filter_name="hidden_ssid"))

                    logger().info("Stop Sniffer finally")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                        'packet_count'], \
                        'Unable to find Broadcast packet'

                    self.wifi_dut.interfaces.wifi.leave()
                    time.sleep(10)
                except Exception as e:
                    logger().info(
                        f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n"
                    )
                    raise e

            elif self.test_case_no == 535831:
                self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
                packet_filter2 = "                    SSID:"
                packet_filter1 = (
                    self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.ap_mac_address,
                        radio_ch=self.wifi_access_point.interfaces.wifi.channel,
                        filter_name="beacon_mbssid",
                    )
                )
                self.wifi_sniffer.interfaces.capture.stop_capture()
                logger().info("Stop Sniffer finally")
                time.sleep(2)
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=packet_filter1, packet_filter2=packet_filter2
                )[
                    "packet_count"
                ], "Unable to find MBSSID bit enable in extended capability field in sniffer capture"

                vap_list = self.find_mbssid_vaps()
                logger().info(f"VAP List = {vap_list}")

                for i in range(0, 5):
                    """ Initiate the connection again for T based BSSID """
                    logger().info(
                        f"\n\n ***** Connection initiation for T based BSSID iteration number = {i} \n\n *****")
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel
                    )
                    self.wifi_sniffer.interfaces.capture.start_capture(
                        capture_file=f"T_based_connection_iteration_{i}"
                    )
                    if i == 0:
                        scan_results = self.wifi_dut.interfaces.wifi.scan(
                            ssid=self.wifi_access_point.interfaces.wifi.ssid)
                        assert len(scan_results) > 0, "scan_list not found"

                    self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                        wifi_dut=self.wifi_dut,
                        wifi_access_point=self.wifi_access_point,
                        associated=self.wifi_dut.interfaces.wifi.associated,
                        ping_after_power_save=False,
                        retry_count=3,
                    )
                    packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr["dut_mac_address"],
                        da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit",
                    )

                    self.zephyr_wifi_collections.ping(self.dut_addr["device_ip"], ping_count=60)
                    time.sleep(2)
                    self.wifi_dut.interfaces.wifi.leave()
                    self.wifi_sniffer.interfaces.capture.stop_capture()

                    """ Initiate the connection again for NT based BSSID """
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel
                    )
                    self.wifi_sniffer.interfaces.capture.start_capture(
                        capture_file=f"NT_based_connection_iteration_{i}"
                    )
                    for _ in range(0, 1):
                        self.scan_list = self.wifi_dut.interfaces.wifi.scan(
                            self.wifi_access_point.interfaces.wifi.guest_networks[
                                0
                            ]["ssid"], retries=3, timeout=25)
                    self.wifi_dut.interfaces.wifi.join(
                        # ssid=vap_list[0],
                        ssid=self.wifi_access_point.interfaces.wifi.guest_networks[0]["ssid"],
                        security=self.wifi_access_point.interfaces.wifi.guest_networks[
                            0
                        ]["security"].name.lower(),
                        passphrase=self.wifi_access_point.interfaces.wifi.guest_networks[
                            0
                        ][
                            "passphrase"
                        ],
                    )

                    self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                        wifi_dut=self.wifi_dut,
                        wifi_access_point=self.wifi_access_point,
                        associated=False,
                        ping_after_power_save=False,
                        skip_connect=True,
                        retry_count=3,
                    )
                    time.sleep(20)
                    vap0_mbssid = self.find_vaps_mbssid().replace(")]", "")
                    logger().info(f"VAP0 MBSSID = {vap0_mbssid}")
                    packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr["dut_mac_address"],
                        da_addr=vap0_mbssid,
                        filter_name="power_mgmt_bit",
                    )

                    self.zephyr_wifi_collections.ping(self.dut_addr["device_ip"], ping_count=10)
                    time.sleep(2)
                    self.wifi_dut.interfaces.wifi.leave()
                    self.wifi_sniffer.interfaces.capture.stop_capture()


            else:
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                    wifi_dut=self.wifi_dut,
                    wifi_access_point=self.wifi_access_point,
                    associated=self.wifi_dut.interfaces.wifi.associated,
                    ping_after_power_save=False,
                )

        except Exception as e:
            logger().info(
                f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n"
            )
            raise e

    def find_vaps_mbssid(self):
        vap0_bssid = ""
        # Regular expression pattern to match ssid and bssid
        pattern = r"ssid: (\S+) bssid: (\S+)"

        # Find all matches of the pattern in the scan_list string
        logger().info(f"\n\n Scan List = {self.scan_list}\n\n")
        matches = re.findall(pattern, str(self.scan_list))

        # Convert the list of tuples to a list of dictionaries
        ssid_bssid_list = [{"ssid": ssid, "bssid": bssid} for ssid, bssid in matches]
        for i in range(len(ssid_bssid_list)):
            if (
                    ssid_bssid_list[i]["ssid"]
                    == self.wifi_access_point.interfaces.wifi.guest_networks[0]["ssid"]
            ):
                vap0_bssid = ssid_bssid_list[i]["bssid"].replace("),", "")
                break
        return vap0_bssid

    def find_mbssid_vaps(self):
        # Regular expression pattern to match ssid and bssid
        packet_filter = "                    SSID:"
        count = 0
        ssid_list = []
        final_ssid_list = []

        filter_file = open(f"./reports/filter2_file.txt", "r")
        line = filter_file.readlines()

        logger().info(
            f"\n\n *** Trying to collect all T & NT based SSID from beacon packet *** \n\n"
        )
        for x in line:
            if packet_filter in x:
                print(x)
                ssid_list.append(x)
                output = ssid_list[count].strip().split(":")[1].strip().replace('"', "")
                final_ssid_list.append(output)
                count = count + 1
        return final_ssid_list

    def find_ssid_list_from_dut_scan(self, scan_type=False):
        # collect all ssid from DUT scan list
        ssid_list = []
        if scan_type:
            self.scan_list = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0, scan_type=2,
                                                                bg_scan_periodicity=10)
            logger().info(
                f"\n\n *** Start to collect all available ssid in DUT scan list ***\n\n"
            )
        else:
            self.scan_list = self.wifi_dut.interfaces.wifi.scan()
            logger().info(
                f"\n\n *** Start to collect all available ssid in DUT scan list ***\n\n"
            )

        for i in range(0, len(self.scan_list)):
            ssid_list.append(self.scan_list[i].ssid)
        return ssid_list

    def compare_list(self, list1, list2):
        """Returns True if list1(sniffer based ssid list) contains all elements of list2(scan based ssid list),
        False otherwise."""
        counter1 = Counter(list1)
        counter2 = Counter(list2)
        logger().info(f"***** Counter1 = {counter1}")
        logger().info(f"***** Counter2 = {counter2}")

        # Check if counter2 is a subset of counter1
        return all(counter2[element] <= counter1[element] for element in counter1)

    def verfiy_T_and_NT_based_mbssid_in_dut_list(self, scan_type=False):
        # Validation for T and NT based MBSSID in DUT scan list & sniffer capture
        packet_filter2 = "                    SSID:"
        ssid_list = self.find_ssid_list_from_dut_scan(scan_type=scan_type)
        # Check the ssid list from DUT scan list
        assert len(ssid_list) > 0, "DUT scan list is empty"
        time.sleep(2)
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.ap_mac_address,
                radio_ch=self.wifi_access_point.interfaces.wifi.channel,
                filter_name="beacon_mbssid",
            )
        )
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1, packet_filter2=packet_filter2
        )[
            "packet_count"
        ], "Unable to find MBSSID bit enable in extended capability field in sniffer capture"

        vap_list = self.find_mbssid_vaps()
        """ Start verification for T & NT based scan list is available in DUT scan list """
        assert self.compare_list(
            vap_list, ssid_list
        ), "Unable to match DUT ssid list with configured VAP list"
        logger().info("\n\n ***** DUT is able to scan all VAP's info ***** \n\n")
        return vap_list

    def validate_rssi_channel_security(self):
        # Validate same RSSI values for all T & MT based ssid, and configured channel & security values matching with
        # DUT scan list
        channel_dict = {}
        security_dict = {}

        # Define a dictionary to store SSID and BSSID values
        ssid_dict = {
            "main_bssid": self.wifi_access_point.interfaces.wifi.ssid,
            "vap0_bssid": self.wifi_access_point.interfaces.wifi.guest_networks[0][
                "ssid"
            ],
            "vap1_bssid": self.wifi_access_point.interfaces.wifi.guest_networks[1][
                "ssid"
            ],
            "vap2_bssid": self.wifi_access_point.interfaces.wifi.guest_networks[2][
                "ssid"
            ],
        }
        logger().info(f"\n\n *** SSID Dictionary = {ssid_dict} ***\n\n")

        # Define a dictionary to store channel and security values
        channel_dict[
            ssid_dict["main_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.channel
        channel_dict[
            ssid_dict["vap0_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[0]["channel"]
        channel_dict[
            ssid_dict["vap1_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[1]["channel"]
        channel_dict[
            ssid_dict["vap2_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[2]["channel"]

        # Define a dictionary to store security values
        security_dict[
            ssid_dict["main_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.security.name.upper()
        security_dict[
            ssid_dict["vap0_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[0][
            "security"
        ].name.upper()
        security_dict[
            ssid_dict["vap1_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[1][
            "security"
        ].name.upper()
        security_dict[
            ssid_dict["vap2_bssid"]
        ] = self.wifi_access_point.interfaces.wifi.guest_networks[2][
            "security"
        ].name.upper()

        # Define a dictionary to store security numbers for each SSID
        main_vap_sec_num = self.get_security_numbers(
            security_dict[ssid_dict["main_bssid"]]
        )
        main_vap0_sec_num = self.get_security_numbers(
            security_dict[ssid_dict["vap0_bssid"]]
        )
        main_vap1_sec_num = self.get_security_numbers(
            security_dict[ssid_dict["vap1_bssid"]]
        )
        main_vap2_sec_num = self.get_security_numbers(
            security_dict[ssid_dict["vap2_bssid"]]
        )

        ssid_rssi_dict = {}
        for entry in self.scan_list:
            ssid_rssi_dict[entry.ssid] = entry.rssi

        # Validate that the RSSI values are same for all SSID
        assert self.validate_for_same_rssi_values_for_all_ssid(
            ssid_rssi_dict, ssid_dict
        ), "RSSI values are not same for all SSID"

        # Define a list of VAP configurations to iterate over
        vap_configs = [
            ("main_bssid", main_vap_sec_num, "Main BSSID"),
            ("vap0_bssid", main_vap0_sec_num, "VAP 0"),
            ("vap1_bssid", main_vap1_sec_num, "VAP 1"),
            ("vap2_bssid", main_vap2_sec_num, "VAP 2"),
        ]

        # Initialize flag to count matches
        flag = 0

        # Find matches
        matching_cells = []
        for key, ssid in ssid_dict.items():
            for cell in self.scan_list:
                if cell.ssid == ssid:
                    matching_cells.append(cell)
                    break  # Exit loop once a match is found

        # Print the matching cells
        logger().info("Matching Cells:")
        for match in matching_cells:
            logger().info(match)

        # # Iterate over each VAP configuration
        for vap_key, sec_num, vap_name in vap_configs:
            for scan_item in matching_cells:
                if scan_item.ssid == ssid_dict[vap_key]:
                    if (
                            scan_item.rf_channel == channel_dict[ssid_dict[vap_key]]
                            and scan_item.security_mode == sec_num
                    ):
                        logger().info(
                            f"\n\n\n {vap_name} channel={channel_dict[ssid_dict[vap_key]]} & "
                            f"Security={self.get_keys_from_value(self.security_dict, sec_num)} match\n\n"
                        )
                        flag += 1
                        break  # Exit inner loop once a match is found

        # Logging the flag value
        logger().info(f"\n\n\n Flag Value = {flag}\n\n\n")
        # Assertion to ensure all VAPs were matched
        assert flag == len(
            vap_configs
        ), "Unable to match all configured VAPs with DUT scan list"

    # Function to retrieve the security number based on the security type
    def get_security_numbers(self, security_type):
        # Define a dictionary to map security types to numbers
        for value in self.security_dict.keys():
            if value == security_type:
                return self.security_dict[value]
        return None  # Return None if the number does not match any key

    def validate_for_same_rssi_values_for_all_ssid(self, scan_results, ssid_dict):
        # Create a mapping of SSID to RSSI from Scan Results
        scan_results_ssid_rssi = scan_results
        ssid_dict_ssids = set(ssid_dict.values())

        # Find RSSI values for SSIDs in ssid_dict
        rssi_values = {}
        for ssid in ssid_dict_ssids:
            if ssid in scan_results_ssid_rssi:
                rssi_values[ssid] = scan_results_ssid_rssi[ssid]
            else:
                rssi_values[
                    ssid
                ] = None  # or some default value if the SSID isn't found in scan_results

        pass_test_case = len(set(rssi_values.values())) == 1

        # Print the results
        logger().info("RSSI values for SSIDs in ssid_dict:")
        for ssid, rssi in rssi_values.items():
            logger().info(f"{ssid}: {rssi}")

        if pass_test_case:
            log_message = "RSSI values are same for all SSID"
        else:
            log_message = "RSSI values are not same for all SSID"

        logger().info(log_message)
        return pass_test_case

    def get_keys_from_value(self, dictionary, val):
        keys = []
        for key, value in dictionary.items():
            if value == val:
                keys.append(key)
        return keys


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219284')
def test_wifi_zephyr_mbssid_send_probe_request_asso_req_c219284(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    packet_filter2 = "                .1.. .... = Multiple BSSID: Supported"

    """	Verify whether DUT is able to send probe req/Assoc req with MBSSID support when enabled MBSSID 
        feature( Multiple BSSID field of the Extended Capabilities element)"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        ping_count=ping_count,
        test_case_no=219284, test_name=test_name, zephyr_wifi_collections=zephyr_wifi_collections, )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info(f"\n\n\n DUT MAC Address = {wlan_obj.dut_addr['dut_mac_address']}\n\n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr["dut_mac_address"], radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="assoc_mbssid", )

        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)[
            "packet_count"], "Unable to find MBSSID bit enable in extended capability field in sniffer capture"
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219285')
def test_wifi_zephyr_mbssid_scan_all_vap_c219285(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    """Verify whether DUT is able to scan all VAP's info when enabled MBSSID feature in AP"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        sniffer_filter=sniffer_filter,
        ping_count=ping_count,
        test_name=test_name,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219285,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "Open",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "Open",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "Open",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "Open",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219286')
def test_wifi_zephyr_mbssid_T_open_sec_c219286(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        protocol,
):
    test_name = request.node.name

    """Verify whether DUT is able to connect to T profile BSSID with open security enabled in AP"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219286,
        test_name=test_name,
        sniffer_filter=sniffer_filter,
        protocol=protocol,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219287')
def test_wifi_zephyr_mbssid_T_wpa2_psk_c219287(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        protocol,
):
    test_name = request.node.name

    """Verify whether DUT is able to connect to T profile BSSID with WPA2 PSK security enabled in AP"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219287,
        test_name=test_name,
        sniffer_filter=sniffer_filter,
        protocol=protocol,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "channel": 3,
        "standard": "gnbax",
        "security": "WPA2",
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219288')
def test_wifi_zephyr_mbssid_NT_wpa2_psk_c219288(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        protocol,
):
    test_name = request.node.name
    """Verify whether DUT is able to connect to NT based profile BSSID with WPA2 PSK security enabled in AP"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219288,
        test_name=test_name,
        sniffer_filter=sniffer_filter,
        protocol=protocol,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA3",
        "ssid": "Mbssid_ap",
        "passphrase": "123456789",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219289')
def test_wifi_zephyr_mbssid_T_wpa3_c219289(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        protocol,
):
    test_name = request.node.name
    """Verify whether DUT is able to connect to T profile BSSID with WPA3 Personal security enabled in AP"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219289,
        protocol=protocol,
        test_name=test_name,
        sniffer_filter=sniffer_filter,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA3",
        "ssid": "Mbssid_ap",
        "passphrase": "123456789",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219290')
def test_wifi_zephyr_mbssid_NT_wpa3_c219290(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        multicast_client,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        protocol,
):
    test_name = request.node.name

    """Verify whether DUT is able to connect to NT profile BSSID with WPA3 Personal security enabled in AP"""
    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219290,
        protocol=protocol,
        test_name=test_name,
        sniffer_filter=sniffer_filter,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        multicast_client=multicast_client,
    )

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "Open",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "Open",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "Open",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "Open",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219293')
def test_wifi_zephyr_mbssid_rejoin_T_open_sec_c219293(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        switch,
        protocol,
):
    test_name = request.node.name

    """Verify whether DUT is able to rejoin to T profile BSSID with open security enabled in AP"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219293,
        test_name=test_name,
        sniffer_filter=sniffer_filter,
        protocol=protocol,
        switch=switch,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=5)
        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)

        zephyr_wifi_collections.ping(wlan_obj.dut_addr["device_ip"], ping_count=60)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info("******* Turn on Access point Finally **********")
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219294')
def test_wifi_zephyr_mbssid_rejoin_T_wpa2_c219294(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        switch,
        protocol,
):
    test_name = request.node.name

    """Verify whether DUT is able to rejoin to T profile BSSID with WPA2 PSK security enabled in AP"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        test_name=test_name,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219293,
        sniffer_filter=sniffer_filter,
        switch=switch,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=5)

        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)

        zephyr_wifi_collections.ping(wlan_obj.dut_addr["device_ip"], ping_count=60)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info("******* Turn on Access point Finally **********")
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "channel": 3,
        "standard": "gnbax",
        "security": "WPA2",
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219295')
def test_wifi_zephyr_mbssid_rejoin_NT_wpa2_c219295(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        protocol,
        switch,
):
    test_name = request.node.name

    """Verify whether DUT is able to rejoin to NT profile BSSID with WPA2 PSK security enabled in AP"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        test_name=test_name,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219295,
        protocol=protocol,
        sniffer_filter=sniffer_filter,
        switch=switch,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=5)

        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)

        zephyr_wifi_collections.ping(wlan_obj.dut_addr["device_ip"], ping_count=60)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info("******* Turn on Access point Finally **********")
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA3",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219296')
def test_wifi_zephyr_mbssid_rejoin_T_wpa3_c219296(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        switch,
        protocol,
):
    test_name = request.node.name

    """Verify whether DUT is able to rejoin to T profile BSSID with WPA3 Personal security enabled in AP"""
    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        test_name=test_name,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219296,
        sniffer_filter=sniffer_filter,
        switch=switch,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=5)

        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)

        zephyr_wifi_collections.ping(wlan_obj.dut_addr["device_ip"], ping_count=60)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info("******* Turn on Access point Finally **********")
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "channel": 3,
        "standard": "gnbax",
        "security": "WPA3",
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219297')
def test_wifi_zephyr_mbssid_rejoin_NT_wpa3_c219297(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        switch,
        protocol,
):
    test_name = request.node.name

    """Verify whether DUT is able to rejoin to NT profile BSSID with WPA3 Personal security enabled in AP"""
    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        test_name=test_name,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219297,
        sniffer_filter=sniffer_filter,
        switch=switch,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=5)

        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)
        zephyr_wifi_collections.ping(wlan_obj.dut_addr["device_ip"], ping_count=60)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info("******* Turn on Access point Finally **********")
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219298')
def test_wifi_zephyr_mbssid_connection_with_wrong_security_c219298(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    packet_filter2 = "                .1.. .... = Multiple BSSID: Supported"

    """	Connection with Wrong security """

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        ping_count=ping_count,
        test_name=test_name,
        test_case_no=219298,
        zephyr_wifi_collections=zephyr_wifi_collections,
        sniffer_filter=sniffer_filter,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219299')
def test_wifi_zephyr_mbssid_neg_connection_with_wrong_password_c219299(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    """	Connection with Wrong password """

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        ping_count=ping_count,
        test_name=test_name,
        test_case_no=219299,
        sniffer_filter=sniffer_filter,
        zephyr_wifi_collections=zephyr_wifi_collections,
    )

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "channel": 3,
        "standard": "gnbax",
        "security": "WPA2",
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219300')
def test_wifi_zephyr_mbssid_neg_connection_failure_when_ssid_not_provided_c219300(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sniffer_filter, zephyr_wifi_collections
):
    test_name = request.node.name

    """The test case should fail when connecting to AP when SSID is not provided in the join API"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219300,
        test_name=test_name,
        sniffer_filter=sniffer_filter,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219301')
def test_wifi_zephyr_mbssid_connect_disconnect_to_ap_txbssid_c219301(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    """	Connect & disconnect(10 times) when STA connected to TXBSSID """
    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        ping_count=ping_count,
        test_name=test_name,
        test_case_no=219301,
        sniffer_filter=sniffer_filter,
        zephyr_wifi_collections=zephyr_wifi_collections,
    )

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "ssid": "Mbssid_ap",
        "passphrase": "123456789",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219302')
def test_wifi_zephyr_mbssid_connect_disconnect_nt_bssid_c219302(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    """	Connect & disconnect(10 times) when STA connected to NT BSSID """
    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        ping_count=ping_count,
        test_name=test_name,
        test_case_no=219302,
        sniffer_filter=sniffer_filter,
        zephyr_wifi_collections=zephyr_wifi_collections,
    )

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "ssid": "Mbssid_ap",
        "passphrase": "123456789",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA3",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219319')
def test_wifi_zephyr_mbssid_verify_scan_list_when_vap_wpa2_sec_NT_vap_wpa3_c219319(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    """	Verify whether DUT is able to scan all VAP's info when enabled MBSSID feature in AP and each VAP different  
    security(TX based Vap - WPA2 Personal & NT based VAP - WPA3 security """
    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        ping_count=ping_count,
        test_name=test_name,
        test_case_no=219319,
        zephyr_wifi_collections=zephyr_wifi_collections,
        sniffer_filter=sniffer_filter,
    )

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA3",
        "ssid": "Mbssid_ap",
        "passphrase": "123456789",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2WPA3MixedMode",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2WPA3MixedMode",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2WPA3MixedMode",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.test_src_map_id('C219320')
def test_wifi_zephyr_mbssid_verify_scan_list_when_vap_wpa3_sec_NT_vap_wpa3_transition_c219320(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    """	Verify whether DUT is able to scan all VAP's info when enabled MBSSID feature in AP and each VAP different 
    security(TX based Vap - WPA3 Personal & NT based VAP - WPA3 Transition security """
    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        ping_count=ping_count,
        test_name=test_name,
        test_case_no=219320,
        zephyr_wifi_collections=zephyr_wifi_collections,
        sniffer_filter=sniffer_filter,
    )

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "Open",
        "ssid": "Mbssid_ap",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.test_src_map_id('C219321')
def test_wifi_zephyr_mbssid_verify_scan_list_when_vap_open_sec_NT_vap_wpa2_sec_c219321(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    """	Verify whether DUT is able to scan all VAP's info when enabled MBSSID feature in AP and each VAP different 
        security(TX based Vap - Open & NT based VAP - WPA2 Personal security """
    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        ping_count=ping_count,
        test_name=test_name,
        test_case_no=219321,
        zephyr_wifi_collections=zephyr_wifi_collections,
        sniffer_filter=sniffer_filter,
    )

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "channel": 3,
        "broadcast_ssid": False,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    }
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
def test_wifi_zephyr_mbssid_T_wpa2_psk_hidden_ssid_c535830(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        utf_constants,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        protocol,
):
    test_name = request.node.name

    """
Check the connection with hidden MBSSID AP with WPA2 security enabled in AP"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=535830,
        test_name=test_name,
        sniffer_filter=sniffer_filter,
        protocol=protocol,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
    )
    try:
        for i in range(0, 4):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            time.sleep(10)

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax", "security": "WPA2",
                                               "broadcast_ssid": False})
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "channel": 7,
        "standard": "gnbax",
        "security": "WPA2",
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 7,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 7,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 7,
            },
        ],
    },
)
def test_wifi_zephyr_mbssid_T_NT_connect_disconnect_hidden_mode_c535831(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
):
    test_name = request.node.name

    """continuous connect disconnect b/w T and NT profile based SSID's"""
    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=535831,
        test_name=test_name,
        sniffer_filter=sniffer_filter,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise e


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "standard": "gnbax",
        "security": "WPA2",
        "ssid": "Mbssid_ap",
        "passphrase": "123456789",
        "channel": 3,
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["unassociated"]
)
def test_wifi_zephyr_mbssid_T_NT_connect_disconnect_c219315(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        request,
        sniffer_filter,
        zephyr_wifi_collections,
        net_perf_client,
        wifi_client,
        protocol,
):
    test_name = request.node.name

    """continuous connect disconnect b/w T and NT profile based SSID's"""

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        zephyr_wifi_collections=zephyr_wifi_collections,
        test_case_no=219315,
        test_name=test_name,
        sniffer_filter=sniffer_filter,
        protocol=protocol,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise e
