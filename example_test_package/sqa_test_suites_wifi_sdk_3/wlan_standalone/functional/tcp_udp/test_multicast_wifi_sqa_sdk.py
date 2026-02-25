import time
import uuid
from datetime import datetime
from typing import Dict
import pytest
import re
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    MulticastParams
)
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf_wiseconnect_3.tests.sl_status import SLStatus

"""The testcases added in this file run below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : BGN
        2. Association to Third party AP
        3. Get the ip address through DHCP
        4. Add multicast address to the multicast group
        5. Run Traffic
        6. Leave Multicast & verify the data integrity checks

    setup requirement:
        1. DUT(Si91x)
        2. NUC
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author : Saurabh Sharma/Achal Raghav
"""


def logger():
    return get_logger(__name__)


def extract_achieved_throughput(data):
    total_achieved_throughput = 0
    pattern = r"Throughput achieved @ (\d+.\d+)"
    match = re.search(pattern, data)
    if match:
        total_achieved_throughput = float(match.group(1))
    return total_achieved_throughput


class WifiJoin(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_sniffer=None,
        net_perf_client=None,
        wifi_client=None,
        protocol=None,
        capture_filename=None,
        sl_collections=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.sl_collections = sl_collections
        self.dut_addr = None

    def run(self):
        try:
            logger().info(
                f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}"
            )
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel
            )
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=f"{self.capture_filename}.pcap"
            )
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
                max_retry_attempts=0,
                scan_interval=6,
                beacon_missed_count=40,
                first_time_retry_enable=0,
            )
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                self.wifi_dut,
                self.wifi_access_point,
                associated=self.wifi_dut.interfaces.wifi.associated,
                power_save=True,
            )
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")

    def get_igmp_list(
        self, dut_mac_address, decryption_key: str, print_layers: list, capture_filename
    ) -> Dict[str, int]:
        igmp_capture_list = []
        current_time = time.time()
        updated_capture_file = (
            "filter_"
            + capture_filename
            + "_"
            + str(datetime.fromtimestamp(current_time).strftime("%H_%M_%S"))
        )
        file_name = f"./reports/{updated_capture_file}.pcap"
        local_capture_file = file_name
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
        packet_filter1 = f"(wlan.addr == {dut_mac_address})"
        self.wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {self.wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
            f"frame.number -w "
            f"{wlan_filter_file}"
        )
        with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
            sftp.get(wlan_filter_file, local_capture_file)
        for packet in self.wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=local_capture_file,
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
                        igmp_layer = str(layer)
                        logger().info(
                            f"As per sniffer capture IGMP packets sent by DUT..{ta_address}  ->  {igmp_layer}"
                        )
                        igmp_capture_list.append(
                            tuple([igmp_layer, packet.sniff_timestamp])
                        )
        return igmp_capture_list


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
            | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
            | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
        },
    )
]


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unsassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": "OPEN"})
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_receive_data_over_udp_socket_using_multicast_address_TC19369(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    multicast_client,
    request,
    wifi_client,
    protocol,
    sl_collections,
    net_perf_client,
):
    """
    Test case TC19369: Verify the Wi-Fi SDK's ability to receive data over a UDP socket using a multicast address.

    Steps:
    1. Retrieve the IP address of the remote device.
    2. Initialize and start the Wi-Fi join process.
    3. Retrieve multicast parameters from the multicast client.
    4. Configure the multicast filter on the DUT.
    5. Join the multicast group on the DUT.
    6. Initialize and start the net performance client.
    7. Start listening for multicast data on the DUT.
    8. Verify the achieved throughput based on the multicast filter configuration.
    9. Leave the multicast group on the DUT.
    10. Stop the sniffer capture and validate the IGMP packets.

    Args:
        wifi_sniffer: The Wi-Fi sniffer object for capturing packets.
        wifi_access_point: The Wi-Fi access point object.
        wifi_dut: The device under test (DUT) object.
        multicast_client: The multicast client object.
        request: The pytest request object.
        wifi_client: The Wi-Fi client object.
        protocol: The protocol used for the test (e.g., UDP).
        sl_collections: The SL collections object for handling exceptions.
        net_perf_client: The net performance client object.

    Raises:
        AssertionError: If any of the assertions fail during the test execution.
    """
    try:
        capture_filename = request.node.name
        logger().info(f"\n***** Retrieve IP Address of Remote Device ******\n")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        timeout = 60
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=capture_filename,
            sl_collections=sl_collections,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        (
            ip_version,
            ttl,
            multicast_mac,
            multicast_ip,
            device_port,
            server_port,
            buffer_length,
            no_of_pkts,
        ) = multicast_client.interfaces.multicast.multicast_params()
        logger().info(
            f"The MultiCast Client Info is : {ip_version}, {ttl}, {multicast_mac}, {multicast_ip}, {device_port}, {server_port}, {buffer_length}, {no_of_pkts}"
        )

        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address(server=multicast_ip)

        net_perf_client.interfaces.net_perf.init_client(
            host_ip=host_ip,
            device_ip=multicast_ip,
            time_out=timeout,
            protocol=protocol,
            time_to_leave="32",
            bandwidth="60M",
            host_role="C",
            bind_address=host_ip,
        )
        logger().info(
            f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}"
        )
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** start listening  ******")
        status, data = wifi_dut.interfaces.wifi.iperf(
            family=2,
            transfer_type=2,
            protocol=17,
            local_port=net_perf_client.interfaces.net_perf.client_port,
            local_ip=multicast_ip,
            remote_ip=host_ip,
            remote_port=net_perf_client.interfaces.net_perf.client_port,
            size=1470,
            ttl=30,
            throughput_type=4,
            qos=0,
            async_socket=1,
        )

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        wifi_dut.interfaces.wifi.sl_net_leave_multicast_address(server=multicast_ip)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        igmp_capture_list = wifi_obj.get_igmp_list(
            wifi_obj.dut_addr["dut_mac_address"],
            decryption_key,
            ["igmp"],
            capture_filename,
        )
        time.sleep(5)
        assert (
            len(igmp_capture_list) > 0
        ), "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unsassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": "OPEN"})
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_receive_data_over_multicast_address_which_is_removed_from_multicast_group_TC19370(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    multicast_client,
    request,
    wifi_client,
    protocol,
    sl_collections,
    net_perf_client,
):
    """
    Test case TC19370: Verify the Wi-Fi SDK's ability to receive data over a multicast address which is removed from the multicast group.

    Steps:
    1. Retrieve the IP address of the remote device.
    2. Initialize and start the Wi-Fi join process.
    3. Retrieve multicast parameters from the multicast client.
    4. Configure the multicast filter on the DUT.
    5. Join the multicast group on the DUT.
    6. Initialize and start the net performance client.
    7. Start listening for multicast data on the DUT.
    8. Leave the multicast group on the DUT.
    9. Verify that no data is received after leaving the multicast group.
    10. Stop the sniffer capture and validate the IGMP packets.

    Args:
        wifi_sniffer: The Wi-Fi sniffer object for capturing packets.
        wifi_access_point: The Wi-Fi access point object.
        wifi_dut: The device under test (DUT) object.
        multicast_client: The multicast client object.
        request: The pytest request object.
        wifi_client: The Wi-Fi client object.
        protocol: The protocol used for the test (e.g., UDP).
        sl_collections: The SL collections object for handling exceptions.
        net_perf_client: The net performance client object.

    Raises:
        AssertionError: If any of the assertions fail during the test execution.
    """
    try:
        capture_filename = request.node.name
        logger().info(f"\n***** Retrieve IP Address of Remote Device ******\n")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        timeout = 60
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=capture_filename,
            sl_collections=sl_collections,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        (
            ip_version,
            ttl,
            multicast_mac,
            multicast_ip,
            device_port,
            server_port,
            buffer_length,
            no_of_pkts,
        ) = multicast_client.interfaces.multicast.multicast_params()
        logger().info(
            f"The MultiCast Client Info is : {ip_version}, {ttl}, {multicast_mac}, {multicast_ip}, {device_port}, {server_port}, {buffer_length}, {no_of_pkts}"
        )
        for count in range(0, 2):
            if count % 2 == 0:
                logger().info(f"DUT joining to the multicast group {multicast_ip}")
                wifi_dut.interfaces.wifi.sl_net_join_multicast_address(
                    server=multicast_ip
                )
            else:
                wifi_dut.interfaces.wifi.sl_net_leave_multicast_address(
                    server=multicast_ip
                )

            net_perf_client.interfaces.net_perf.init_client(
                host_ip=host_ip,
                device_ip=multicast_ip,
                time_out=timeout,
                protocol=protocol,
                time_to_leave="32",
                bandwidth="60M",
                host_role="C",
                bind_address=host_ip,
            )
            logger().info(
                f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}"
            )
            logger().info(f"***** starting iperf ******")
            net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** start listening  ******")
            status, data = wifi_dut.interfaces.wifi.iperf(
                family=2,
                transfer_type=2,
                protocol=17,
                local_port=net_perf_client.interfaces.net_perf.client_port,
                local_ip=multicast_ip,
                remote_ip=host_ip,
                remote_port=net_perf_client.interfaces.net_perf.client_port,
                size=1470,
                ttl=30,
                throughput_type=4,
                qos=0,
                async_socket=1,
            )

        logger().info(
            "DUT not received any data when DUT not joined to multicast group"
        )
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        igmp_list = wifi_obj.get_igmp_list(
            wifi_obj.dut_addr["dut_mac_address"],
            decryption_key,
            ["igmp"],
            capture_filename,
        )
        time.sleep(5)
        assert (
            len(igmp_list) > 0
        ), "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unsassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": "OPEN"})
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_receive_data_using_multicast_filter_MULTICAST_MAC_SET_ALL_BIT_TC19372(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    multicast_client,
    request,
    wifi_client,
    protocol,
    sl_collections,
    net_perf_client,
):
    """
    Test case TC19372: Verify the Wi-Fi SDK's ability to receive data using the multicast filter with MULTICAST_MAC_ADD_BIT.

    Steps:
    1. Retrieve the IP address of the remote device.
    2. Initialize and start the Wi-Fi join process.
    3. Retrieve multicast parameters from the multicast client.
    4. Configure the multicast filter on the DUT.
    5. Join the multicast group on the DUT.
    6. Initialize and start the net performance client.
    7. Start listening for multicast data on the DUT.
    8. Verify the achieved throughput based on the multicast filter configuration.
    9. Leave the multicast group on the DUT.
    10. Stop the sniffer capture and validate the IGMP packets.

    Args:
        wifi_sniffer: The Wi-Fi sniffer object for capturing packets.
        wifi_access_point: The Wi-Fi access point object.
        wifi_dut: The device under test (DUT) object.
        multicast_client: The multicast client object.
        request: The pytest request object.
        wifi_client: The Wi-Fi client object.
        protocol: The protocol used for the test (e.g., UDP).
        sl_collections: The SL collections object for handling exceptions.
        net_perf_client: The net performance client object.

    Raises:
        AssertionError: If any of the assertions fail during the test execution.
    """
    try:
        capture_filename = request.node.name
        logger().info(f"\n***** Retrieve IP Address of Remote Device ******\n")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        timeout = 60
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=capture_filename,
            sl_collections=sl_collections,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        (
            ip_version,
            ttl,
            multicast_mac,
            multicast_ip,
            device_port,
            server_port,
            buffer_length,
            no_of_pkts,
        ) = multicast_client.interfaces.multicast.multicast_params()
        logger().info(
            f"The MultiCast Client Info is : {ip_version}, {ttl}, {multicast_mac}, {multicast_ip}, {device_port}, {server_port}, {buffer_length}, {no_of_pkts}"
        )

        logger().info(
            f"\nSetting the multicast filter type as : {MulticastParams.MULTICAST_MAC_SET_ALL}\n"
        )
        wifi_dut.interfaces.wifi.sl_net_configure_multicast_filter(
            filter_type=MulticastParams.MULTICAST_MAC_SET_ALL,
            multicast_address=multicast_mac,
        )

        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address(server=multicast_ip)

        net_perf_client.interfaces.net_perf.init_client(
            host_ip=host_ip,
            device_ip=multicast_ip,
            time_out=timeout,
            protocol=protocol,
            time_to_leave="32",
            bandwidth="60M",
            host_role="C",
            bind_address=host_ip,
        )
        logger().info(
            f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}"
        )
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** start listening  ******")
        status, data = wifi_dut.interfaces.wifi.iperf(
            family=2,
            transfer_type=2,
            protocol=17,
            local_port=net_perf_client.interfaces.net_perf.client_port,
            local_ip=multicast_ip,
            remote_ip=host_ip,
            remote_port=net_perf_client.interfaces.net_perf.client_port,
            size=1470,
            ttl=30,
            throughput_type=4,
            qos=0,
            async_socket=1,
            timeout=300,
        )
        throughput = extract_achieved_throughput(data)
        assert (
            throughput > 0
        ), "DUT not achieved throughput when multicast filter is set to all"

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        wifi_dut.interfaces.wifi.sl_net_leave_multicast_address(server=multicast_ip)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        igmp_capture_list = wifi_obj.get_igmp_list(
            wifi_obj.dut_addr["dut_mac_address"],
            decryption_key,
            ["igmp"],
            capture_filename,
        )
        time.sleep(5)
        assert (
            len(igmp_capture_list) > 0
        ), "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unsassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": "OPEN"})
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_receive_data_using_multicast_filter_MULTICAST_MAC_CLEAR_ALL_BIT_TC19373(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    multicast_client,
    request,
    wifi_client,
    protocol,
    sl_collections,
    net_perf_client,
):
    """
    Test case TC19373: Verify the Wi-Fi SDK's ability to receive data using the multicast filter with MULTICAST_MAC_ADD_BIT.

    Steps:
    1. Retrieve the IP address of the remote device.
    2. Initialize and start the Wi-Fi join process.
    3. Retrieve multicast parameters from the multicast client.
    4. Configure the multicast filter on the DUT.
    5. Join the multicast group on the DUT.
    6. Initialize and start the net performance client.
    7. Start listening for multicast data on the DUT.
    8. Verify the achieved throughput based on the multicast filter configuration.
    9. Leave the multicast group on the DUT.
    10. Stop the sniffer capture and validate the IGMP packets.

    Args:
        wifi_sniffer: The Wi-Fi sniffer object for capturing packets.
        wifi_access_point: The Wi-Fi access point object.
        wifi_dut: The device under test (DUT) object.
        multicast_client: The multicast client object.
        request: The pytest request object.
        wifi_client: The Wi-Fi client object.
        protocol: The protocol used for the test (e.g., UDP).
        sl_collections: The SL collections object for handling exceptions.
        net_perf_client: The net performance client object.

    Raises:
        AssertionError: If any of the assertions fail during the test execution.
    """

    try:
        capture_filename = request.node.name
        logger().info(f"\n***** Retrieve IP Address of Remote Device ******\n")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        timeout = 60
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=capture_filename,
            sl_collections=sl_collections,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        (
            ip_version,
            ttl,
            multicast_mac,
            multicast_ip,
            device_port,
            server_port,
            buffer_length,
            no_of_pkts,
        ) = multicast_client.interfaces.multicast.multicast_params()
        logger().info(
            f"The MultiCast Client Info is : {ip_version}, {ttl}, {multicast_mac}, {multicast_ip}, {device_port}, {server_port}, {buffer_length}, {no_of_pkts}"
        )

        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address(server=multicast_ip)

        logger().info(
            f"\nSetting the multicast filter type : {MulticastParams.MULTICAST_MAC_CLEAR_ALL}\n"
        )
        wifi_dut.interfaces.wifi.sl_net_configure_multicast_filter(
            filter_type=MulticastParams.MULTICAST_MAC_CLEAR_ALL,
            multicast_address=multicast_mac,
        )

        net_perf_client.interfaces.net_perf.init_client(
            host_ip=host_ip,
            device_ip=multicast_ip,
            time_out=timeout,
            protocol=protocol,
            time_to_leave="32",
            bandwidth="60M",
            host_role="C",
            bind_address=host_ip,
        )
        logger().info(
            f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}"
        )
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** start listening  ******")
        status, data = wifi_dut.interfaces.wifi.iperf(
            family=2,
            transfer_type=2,
            protocol=17,
            local_port=net_perf_client.interfaces.net_perf.client_port,
            local_ip=multicast_ip,
            remote_ip=host_ip,
            remote_port=net_perf_client.interfaces.net_perf.client_port,
            size=1470,
            ttl=30,
            throughput_type=4,
            qos=0,
            async_socket=1,
            timeout=300,
        )
        throughput = extract_achieved_throughput(data)
        assert (
            throughput == 0
        ), "DUT achieved throughput when multicast filter is cleared"
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        wifi_dut.interfaces.wifi.sl_net_leave_multicast_address(server=multicast_ip)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        igmp_capture_list = wifi_obj.get_igmp_list(
            wifi_obj.dut_addr["dut_mac_address"],
            decryption_key,
            ["igmp"],
            capture_filename,
        )
        time.sleep(5)
        assert (
            len(igmp_capture_list) > 0
        ), "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unsassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": "OPEN"})
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_receive_data_using_multicast_filter_MULTICAST_MAC_CLEAR_BIT_TC19374(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    multicast_client,
    request,
    wifi_client,
    protocol,
    sl_collections,
    net_perf_client,
):
    """
    Test case TC19374: Verify the Wi-Fi SDK's ability to receive data using the multicast filter with MULTICAST_MAC_ADD_BIT.

    Steps:
    1. Retrieve the IP address of the remote device.
    2. Initialize and start the Wi-Fi join process.
    3. Retrieve multicast parameters from the multicast client.
    4. Configure the multicast filter on the DUT.
    5. Join the multicast group on the DUT.
    6. Initialize and start the net performance client.
    7. Start listening for multicast data on the DUT.
    8. Verify the achieved throughput based on the multicast filter configuration.
    9. Leave the multicast group on the DUT.
    10. Stop the sniffer capture and validate the IGMP packets.

    Args:
        wifi_sniffer: The Wi-Fi sniffer object for capturing packets.
        wifi_access_point: The Wi-Fi access point object.
        wifi_dut: The device under test (DUT) object.
        multicast_client: The multicast client object.
        request: The pytest request object.
        wifi_client: The Wi-Fi client object.
        protocol: The protocol used for the test (e.g., UDP).
        sl_collections: The SL collections object for handling exceptions.
        net_perf_client: The net performance client object.

    Raises:
        AssertionError: If any of the assertions fail during the test execution.
    """
    try:
        capture_filename = request.node.name
        logger().info(f"\n***** Retrieve IP Address of Remote Device ******\n")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        timeout = 60
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=capture_filename,
            sl_collections=sl_collections,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        (
            ip_version,
            ttl,
            multicast_mac,
            multicast_ip,
            device_port,
            server_port,
            buffer_length,
            no_of_pkts,
        ) = multicast_client.interfaces.multicast.multicast_params()
        logger().info(
            f"The MultiCast Client Info is : {ip_version}, {ttl}, {multicast_mac}, {multicast_ip}, {device_port}, {server_port}, {buffer_length}, {no_of_pkts}"
        )

        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address(server=multicast_ip)

        for count in range(0, 2):
            if count == 1:
                logger().info(
                    f"\nSetting the multicast filter type : {MulticastParams.MULTICAST_MAC_CLEAR_BIT}\n"
                )
                wifi_dut.interfaces.wifi.sl_net_configure_multicast_filter(
                    filter_type=MulticastParams.MULTICAST_MAC_CLEAR_BIT,
                    multicast_address=multicast_mac,
                )

            net_perf_client.interfaces.net_perf.init_client(
                host_ip=host_ip,
                device_ip=multicast_ip,
                time_out=timeout,
                protocol=protocol,
                time_to_leave="32",
                bandwidth="60M",
                host_role="C",
                bind_address=host_ip,
            )
            logger().info(
                f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}"
            )
            logger().info(f"***** starting iperf ******")
            net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** start listening  ******")
            status, data = wifi_dut.interfaces.wifi.iperf(
                family=2,
                transfer_type=2,
                protocol=17,
                local_port=net_perf_client.interfaces.net_perf.client_port,
                local_ip=multicast_ip,
                remote_ip=host_ip,
                remote_port=net_perf_client.interfaces.net_perf.client_port,
                size=1470,
                ttl=30,
                throughput_type=4,
                qos=0,
                async_socket=1,
                timeout=300,
            )
            throughput = extract_achieved_throughput(data)
            if count == 1:
                assert (
                    throughput == 0
                ), "DUT achieved throughput when multicast filter is cleared"
            logger().info(f"\nachieved throughput Info: {throughput}\n")

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        wifi_dut.interfaces.wifi.sl_net_leave_multicast_address(server=multicast_ip)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        igmp_capture_list = wifi_obj.get_igmp_list(
            wifi_obj.dut_addr["dut_mac_address"],
            decryption_key,
            ["igmp"],
            capture_filename,
        )
        assert (
            len(igmp_capture_list) > 0
        ), "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unsassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": "OPEN"})
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_receive_data_using_multicast_filter_MULTICAST_MAC_ADD_BIT_TC19375(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    multicast_client,
    request,
    wifi_client,
    protocol,
    sl_collections,
    net_perf_client,
):
    """
    Test case TC19375: Verify the Wi-Fi SDK's ability to receive data using the multicast filter with MULTICAST_MAC_ADD_BIT.

    Steps:
    1. Retrieve the IP address of the remote device.
    2. Initialize and start the Wi-Fi join process.
    3. Retrieve multicast parameters from the multicast client.
    4. Configure the multicast filter on the DUT.
    5. Join the multicast group on the DUT.
    6. Initialize and start the net performance client.
    7. Start listening for multicast data on the DUT.
    8. Verify the achieved throughput based on the multicast filter configuration.
    9. Leave the multicast group on the DUT.
    10. Stop the sniffer capture and validate the IGMP packets.

    Args:
        wifi_sniffer: The Wi-Fi sniffer object for capturing packets.
        wifi_access_point: The Wi-Fi access point object.
        wifi_dut: The device under test (DUT) object.
        multicast_client: The multicast client object.
        request: The pytest request object.
        wifi_client: The Wi-Fi client object.
        protocol: The protocol used for the test (e.g., UDP).
        sl_collections: The SL collections object for handling exceptions.
        net_perf_client: The net performance client object.

    Raises:
        AssertionError: If any of the assertions fail during the test execution.
    """
    try:
        capture_filename = request.node.name
        logger().info(f"\n***** Retrieve IP Address of Remote Device ******\n")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        timeout = 60
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=protocol,
            capture_filename=capture_filename,
            sl_collections=sl_collections,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        (
            ip_version,
            ttl,
            multicast_mac,
            multicast_ip,
            device_port,
            server_port,
            buffer_length,
            no_of_pkts,
        ) = multicast_client.interfaces.multicast.multicast_params()
        logger().info(
            f"The MultiCast Client Info is : {ip_version}, {ttl}, {multicast_mac}, {multicast_ip}, {device_port}, {server_port}, {buffer_length}, {no_of_pkts}"
        )

        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address(server=multicast_ip)

        for count in range(0, 2):
            if count == 0:
                logger().info(
                    f"\nSetting the multicast filter type : {MulticastParams.MULTICAST_MAC_CLEAR_ALL}\n"
                )
                wifi_dut.interfaces.wifi.sl_net_configure_multicast_filter(
                    filter_type=MulticastParams.MULTICAST_MAC_CLEAR_ALL,
                    multicast_address=multicast_mac,
                )
            else:
                logger().info(
                    f"\nSetting the multicast filter type : {MulticastParams.MULTICAST_MAC_ADD_BIT}\n"
                )
                wifi_dut.interfaces.wifi.sl_net_configure_multicast_filter(
                    filter_type=MulticastParams.MULTICAST_MAC_ADD_BIT,
                    multicast_address=multicast_mac,
                )

            net_perf_client.interfaces.net_perf.init_client(
                host_ip=host_ip,
                device_ip=multicast_ip,
                time_out=timeout,
                protocol=protocol,
                time_to_leave="32",
                bandwidth="60M",
                host_role="C",
                bind_address=host_ip,
            )
            logger().info(
                f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}"
            )
            logger().info(f"***** starting iperf ******")
            net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** start listening  ******")
            status, data = wifi_dut.interfaces.wifi.iperf(
                family=2,
                transfer_type=2,
                protocol=17,
                local_port=net_perf_client.interfaces.net_perf.client_port,
                local_ip=multicast_ip,
                remote_ip=host_ip,
                remote_port=net_perf_client.interfaces.net_perf.client_port,
                size=1470,
                ttl=30,
                throughput_type=4,
                qos=0,
                async_socket=1,
                timeout=300,
            )
            throughput = extract_achieved_throughput(data)
            if count == 0:
                assert (
                    throughput == 0
                ), "DUT achieved throughput when multicast filter is cleared"
            else:
                assert (
                    throughput > 0
                ), "DUT not achieved throughput when multicast filter is added"
            logger().info(f"The achieved throughput are {throughput}")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        wifi_dut.interfaces.wifi.sl_net_leave_multicast_address(server=multicast_ip)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        igmp_capture_list = wifi_obj.get_igmp_list(
            wifi_obj.dut_addr["dut_mac_address"],
            decryption_key,
            ["igmp"],
            capture_filename,
        )
        assert (
            len(igmp_capture_list) > 0
        ), "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
