from utf.utils.logger import get_logger
import pytest
import string
import time
import ipaddress
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xPowerSaveModes,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xOperatingMode,
    Si91xExtCustomFeatureBitMap
)
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utf_config import UtfConfig


def logger():
    return get_logger(__name__)


"""
     Setup Requirement:
     
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)  
        
     Test Steps:
        
        1. Configure the DUT in 2G.
        2. Association of Third party AP's
        3. Configure the IPv6 addresses.
        4. Ping to the specified IPv6 address.
        5. Validate the Sniffer Checks.
    
     Author:
      - Achal Raghav 
      - Swathi Chinthala
"""

import ipaddress
import random



def random_ipv6_addr(prefix: str) -> str:
    # Ensure the prefix is interpreted as a /64 network
    network = ipaddress.IPv6Network(f"{prefix}/64", strict=False)

    # Generate a random 64-bit interface identifier
    random_suffix = random.getrandbits(64)

    # Combine the prefix and the random suffix
    full_ip_int = int(network.network_address) | random_suffix
    full_ip = ipaddress.IPv6Address(full_ip_int)

    return str(full_ip)


wan_ipv6_addr = random_ipv6_addr("2001:db8:abcd:0012::")
wan_gateway = "2001:db8:abcd:0012::1"


class WLanThread(ThreadBase):
    client_info = {"mac_address": None, "ip_address": None}
    dut_info = {"mac_address": None, "ip_address": None}

    def __init__(self, wifi_dut=None, wifi_sniffer=None, wifi_access_point=None, sl_collections=None, test_name=None,
                 wifi_client=None, test_id=None, ping_before_power_save=True, ping_after_power_save=True,
                 ipv6_addr_type="global", static_ipv6=None, ip_config_disable=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_before_power_save = ping_before_power_save
        self.ping_after_power_save = ping_after_power_save
        self.ipv6_addr_type = ipv6_addr_type
        self.static_ipv6 = static_ipv6
        self.ip_config_disable = ip_config_disable
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def sniffer_capture(self, mode: str = None):
        if mode == 'start':
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
        else:
            self.wifi_sniffer.interfaces.capture.stop_capture()

    def ping_async(self, ip_addr):

        self.logger.info(f"PINGING TO {ip_addr}")
        time.sleep(20)
        self.wifi_dut.interfaces.wifi.ping(server_ip=ip_addr, ip_version='ipv6', ping_size=64, num_ping_attempts=10)

    def run(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.sniffer_capture(mode='start')

        info_attr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                             wifi_access_point=self.wifi_access_point,
                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                             ip_version='ipv6',
                                                             ping_before_power_save=self.ping_before_power_save,
                                                             ping_after_power_save=self.ping_after_power_save,
                                                             ipv6_type=self.ipv6_addr_type,
                                                             retry_count=3,
                                                             power_save=False,
                                                             ip_config_disable=self.ip_config_disable)

        if self.test_id == 536194:
            ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version="ipv6", vid=0,
                                                           static_ipv6_address=self.static_ipv6,
                                                           ipv6_gw_address=self.static_ipv6,
                                                           expected_status=SLStatus.SL_STATUS_SI91X_INVALID_COMMAND_OR_OPERATION)

            return
        if self.static_ipv6:

            logger().info("********** Setting static_ipv6 value to DUT ")
            ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version="ipv6", vid=0,
                                                               static_ipv6_address=self.static_ipv6,
                                                               ipv6_gw_address=self.static_ipv6)
            logger().info(f"ip_config:{ip_config}")
            if self.ipv6_addr_type == 'global':
                info_attr['device_ip'] = ip_config[1]
            else:
                info_attr['device_ip'] = ip_config[0]

        if self.power_save:
            self.wifi_dut.interfaces.wifi.set_performance_profile('power_save_low_latency')
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                               psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            time.sleep(10)
        else:
            logger().info("skip power save mode configuration as in harness power_save flag is set to False")

        self.dut_info['ap_mac_address'] = self.wifi_access_point.interfaces.wifi.bssid
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.ipv6_addr_type)
        logger().info(f"remote_ip: {remote_ip}")
        ip_addr = ipaddress.ip_address(remote_ip)
        if self.test_id == 119358:
            ip_addr = ip_addr.exploded
        if self.test_id == 119362:
            self.logger.info(f"The 128 bit IPv6 address is {ip_addr.exploded}")
            ip_addr = ip_addr.compressed
        self.client_info['ip_address'] = ip_addr

        if self.test_id in [119358, 119362, 119393, 119394, 119399, 119400, 119360]:
            self.ping_async(ip_addr=ip_addr)

        if self.test_id in [119359, 119402, 119403, 119361, 537337, 537338]:

            device_ip = info_attr['device_ip']
            logger().info(f"device_ip : {device_ip}")

            if self.ipv6_addr_type == "link":
                interface = self.wifi_client.interfaces.wifi.config["interface"]
                device_ip = f"{device_ip}%{interface}"

            for count in range(0, 2):
                logger().info(f"=======>>>>>Pinging the DUT from remote side....")
                status = ping(device_ip, 10)
                if status:
                    break
                else:
                    client_interface = self.wifi_client.interfaces.wifi.config["interface"]
                    logger().info(f"=======>>>>>DUT NOT RESPONDING FOR PING REQUEST......")
                    logger().info(f"=======>>>>>Disabling the ethernet adaptor at remote side....")
                    self.wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {client_interface} down")
                    time.sleep(10)
                    logger().info(f"=======>>>>>Enabling the ethernet adaptor at remote side....")
                    self.wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {client_interface} up")
                    self.wifi_client.interfaces.wifi.shell.execute(f"sudo ip6tables -F")
                    time.sleep(20)

            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"


        self.dut_info['mac_address'] = info_attr['dut_mac_address']
        self.dut_info['ip_address'] = info_attr['device_ip']


pytestmark = [
    pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
     }
    )
]

@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119345')
def test_wifi_sdk_ipv6_packet_from_dut_c119345(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections, request,
                                               sniffer_filter,
                                               wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections,
                              wifi_client=wifi_client, test_id=119345)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(type=129,
                                                                                        filter_name='icmpv6_msg_type')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: ICMPV6 message not received'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119348')
def test_wifi_sdk_verify_stateless_dhcpv6_configuration_c119348(firmware_loader, wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=119348,
                              wifi_client=wifi_client,
                              ping_after_power_save=False,
                              ping_before_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        logger().info("checking for router advertisement packet to check the stateless dhcpv6 configuration")
        packet_filter = f"icmpv6.nd.ra.flag.o == 1 && icmpv6.nd.ra.flag.m == 0 && wlan.addr== {wlan_obj.dut_info['ap_mac_address']}"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
            'Sniffer: AP is not configured with stateless dhcpv6'

        #Router solicitation message
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info['mac_address'],
            filter_name='router_solicitation')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: router_solicitation message not received'
        # Router advertisement message
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wlan_obj.dut_info['mac_address'],
            filter_name='router_advertisement')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Sniffer: advertisement message not received'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "Open", "ipv6_state": "1",
                               "wan_ipv6_address": wan_ipv6_addr, "wan_ipv6_gateway": wan_gateway}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119349')
def test_wifi_sdk_verify_stateful_dhcpv6_procedure_c119349(firmware_loader, wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                           sniffer_filter, request,
                                                           wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections,
                              wifi_client=wifi_client, test_id=119349,
                              ping_after_power_save=False,
                              ping_before_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')

        logger().info("checking for router advertisement packet to check the stateful dhcpv6 configuration")
        packet_filter1 = f"icmpv6.nd.ra.flag.m == 1 && wlan.addr== {wlan_obj.dut_info['ap_mac_address']}"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: AP is not configured with stateful dhcpv6'
        #Router solicitation message
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info['mac_address'],
            filter_name='router_solicitation')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: router_solicitation message not received'
        # Router advertisement message
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wlan_obj.dut_info['mac_address'],
            filter_name='router_advertisement')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Sniffer: advertisement message not received'
        # Stateful IPv6 address
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info['mac_address'],
            filter_name='stateful_ipv6_address')
        logger().info(f"The filter is {packet_filter3}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Sniffer: stateful ipv6 address not received'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr, "wan_ipv6_gateway": wan_gateway, "security": "Open"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119358')
def test_wifi_sdk_check_dut_ping_with_128_bit_ipv6_address_c119358(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                   sl_collections,
                                                                   wifi_client, request, sniffer_filter):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point,
                              sl_collections=sl_collections, test_name=test_name, test_id=119358,
                              wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info['ip_address'],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: ipv6 echo req & reply packets not found'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1",
                               "wan_ipv6_address": wan_ipv6_addr, "security": "Open"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119359')
def test_wifi_sdk_check_ping_with_128_bit_ipv6_address_c119359(wifi_dut, wifi_sniffer, wifi_access_point,
                                                               sl_collections,
                                                               wifi_client, request, sniffer_filter):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point,
                              sl_collections=sl_collections, test_name=test_name, test_id=119359,
                              wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')

        logger().info("checking for router advertisement packet to check the stateful dhcpv6 configuration")
        packet_filter1 = f"icmpv6.nd.ra.flag.m == 1 && wlan.addr== {wlan_obj.dut_info['ap_mac_address']}"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: AP is not configured with stateful dhcpv6'

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info['ip_address'],
            filter_name='echo_req_reply')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Sniffer: IPV6 echo reply and request packets not found'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,"wan_ipv6_gateway": wan_gateway, "security": "Open"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119362')
def test_wifi_sdk_check_dut_ping_with_possible_shortest_ipv6_address_c119362(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                             sl_collections, request, sniffer_filter,
                                                                             wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point,
                              sl_collections=sl_collections, test_name=test_name, test_id=119362,
                              wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: IPV6 echo reply and request packets not found'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr, "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119396')
def test_wifi_sdk_ping_to_dut_stateless_dhcpv6_configuration_c119396(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                     sl_collections, request, sniffer_filter,
                                                                     wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=119396,
                              wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: ipv6 echo req & reply packets not found'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1",
                               "wan_ipv6_address": wan_ipv6_addr,"wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119397')
def test_wifi_sdk_ping_to_dut_stateful_dhcpv6_configuration_c119397(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                    sl_collections, request, sniffer_filter,
                                                                    wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=119397,
                              wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')

        logger().info("checking for router advertisement packet to check the stateful dhcpv6 configuration")
        packet_filter1 = f"icmpv6.nd.ra.flag.m == 1 && wlan.addr== {wlan_obj.dut_info['ap_mac_address']}"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'AP is not configured with stateful dhcpv6'

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Sniffer: IPV6 echo reply and request packets not found'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0", "security": "Open",
                               "wan_ipv6_gateway": wan_gateway,
                               "wan_ipv6_address": wan_ipv6_addr}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119393')
def test_wifi_sdk_ping_to_AP_global_stateless_dhcpv6_configuration_C119393(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                           sl_collections, request, sniffer_filter,
                                                                           wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119393,
                              ipv6_addr_type="global",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')

        logger().info("checking for router advertisement packet to check the stateful dhcpv6 configuration")
        packet_filter4 = f"icmpv6.nd.ra.flag.m == 0 && wlan.addr== {wlan_obj.dut_info['ap_mac_address']}"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count'], 'AP is not configured with stateful dhcpv6'

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1", "security": "Open",
                               "wan_ipv6_address": wan_ipv6_addr, "wan_ipv6_gateway": wan_gateway,}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119394')
def test_wifi_sdk_ping_to_AP_global_stateful_dhcpv6_configuration_C119394(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                          sl_collections, request, sniffer_filter,
                                                                          wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119394,
                              ipv6_addr_type="global",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0", "security": "Open",
                               "wan_ipv6_address": wan_ipv6_addr, "wan_ipv6_gateway": wan_gateway,}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119399')
def test_wifi_sdk_ping_to_AP_linklocal_stateless_dhcpv6_configuration_C119399(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                              sl_collections, request, sniffer_filter,
                                                                              wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119399,
                              ipv6_addr_type="link",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1)["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1", "security": "Open",
                               "wan_ipv6_address": wan_ipv6_addr, "wan_ipv6_gateway": wan_gateway,}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119400')
def test_wifi_sdk_ping_to_AP_linklocal_stateful_dhcpv6_configuration_C119400(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                             sl_collections, request, sniffer_filter,
                                                                             wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119400,
                              ipv6_addr_type="link",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')

        logger().info("checking for router advertisement packet to check the stateful dhcpv6 configuration")
        packet_filter4 = f"icmpv6.nd.ra.flag.m == 1 && wlan.addr== {wlan_obj.dut_info['ap_mac_address']}"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count'], 'AP is not configured with stateful dhcpv6'

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0", "security": "Open",
                               "wan_ipv6_address": wan_ipv6_addr, "wan_ipv6_gateway": wan_gateway}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119402')
def test_wifi_sdk_ping_to_DUT_linklocal_stateless_dhcpv6_configuration_C119402(wifi_dut, wifi_access_point,
                                                                               wifi_sniffer,
                                                                               sl_collections, request, sniffer_filter,
                                                                               wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119402,
                              ipv6_addr_type="link",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1", "security": "Open",
                               "wan_ipv6_address": wan_ipv6_addr, "wan_ipv6_gateway": wan_gateway,}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119403')
def test_wifi_sdk_ping_to_DUT_linklocal_stateful_dhcpv6_configuration_C119403(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                              sl_collections, request, sniffer_filter,
                                                                              wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119403,
                              ipv6_addr_type="link",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={
                                "ipv6_state": "1",
                                "security": "Open",
                                "passphrase": "12345678",
                                "connection_type": "STATIC_IPV6",
                                "wan_ipv6_address": wan_ipv6_addr,
                                "wan_ipv6_gateway": wan_gateway,
                                "wan_prefix_length": "64",
                                "lan_ipv6_address": "2405:3520:cc11:1241:3213:a134:1334:1421",
                                "lan_prefix_length": "64",
                                "lan_ipv6_prefix": "2405:3520:cc11:1241::",
                                "lan_ip_pool_start": "1000",
                                "lan_ip_pool_end": "5000",
                                "lan_lease_time": "86400",
                               }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_of_dut_long_Hextet_stateful_dhcpv6_config_C119361(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                              sl_collections, request, sniffer_filter,
                                                                              wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119361,
                              ipv6_addr_type="global",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.config(
    "wifi_access_point", wifi={
                                "ipv6_state": "1",
                                "security": "Open",
                                "passphrase": "12345678",
                                "connection_type": "STATIC_IPV6",
                                "wan_ipv6_address": wan_ipv6_addr,
                                "wan_ipv6_gateway": wan_gateway,
                                "wan_prefix_length": "64",
                                "lan_ipv6_address": "2405:3520:cc11:1241:3213:a134:1334:1421",
                                "lan_prefix_length": "64",
                                "lan_ipv6_prefix": "2405:3520:cc11:1241::",
                                "lan_ip_pool_start": "1000",
                                "lan_ip_pool_end": "5000",
                                "lan_lease_time": "86400",
                               }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_of_dut_by_removing_the_lz_stateful_dhcpv6_C119360(wifi_dut, wifi_access_point,
                                                                                       wifi_sniffer,
                                                                                       sl_collections, request,
                                                                                       sniffer_filter,
                                                                                       wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=119360,
                              ipv6_addr_type="global",
                              ping_before_power_save=False, ping_after_power_save=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={
                                "ipv6_state": "1",
                                "security": "Open",
                                "passphrase": "12345678",
                                "connection_type": "STATIC_IPV6",
                                "wan_ipv6_address": wan_ipv6_addr,
                                "wan_ipv6_gateway": wan_gateway,
                                "wan_prefix_length": "64",
                                "lan_ipv6_address": "2405:3520:cc11:1241:3213:a134:1334:1421",
                                "lan_prefix_length": "64",
                                "lan_ipv6_prefix": "2405:3520:cc11:1241::",
                                "lan_ip_pool_start": "1000",
                                "lan_ip_pool_end": "5000",
                                "lan_lease_time": "86400",
                               }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_Dut_LLA_Static_IP_1s_stateful_C537337(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                              sl_collections, request, sniffer_filter,
                                                                              wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=537337,
                              ipv6_addr_type="link",
                              ping_before_power_save=False, ping_after_power_save=False,
                              static_ipv6="1111:1111:1111:1111:1111:1111:1111:1111",
                              ip_config_disable=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)




@pytest.mark.config(
    "wifi_access_point", wifi={
                                "ipv6_state": "1",
                                "security": "Open",
                                "passphrase": "12345678",
                                "connection_type": "STATIC_IPV6",
                                "wan_ipv6_address": wan_ipv6_addr,
                                "wan_ipv6_gateway": wan_gateway,
                                "wan_prefix_length": "64",
                                "lan_ipv6_address": "2405:3520:cc11:1241:3213:a134:1334:1421",
                                "lan_prefix_length": "64",
                                "lan_ipv6_prefix": "2405:3520:cc11:1241::",
                                "lan_ip_pool_start": "1000",
                                "lan_ip_pool_end": "5000",
                                "lan_lease_time": "86400",
                               }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ping_Dut_LLA_with_Static_IP_fs_statefl_DHCP_C537338(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                     sl_collections, request, sniffer_filter,
                                                                     wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=537338,
                              ipv6_addr_type="link",
                              ping_before_power_save=False, ping_after_power_save=False,
                              static_ipv6="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                              ip_config_disable=True
                              )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info["ip_address"],
            da_addr=wlan_obj.client_info["ip_address"],
            filter_name='echo_req_reply')
        logger().info(f"Validating icmpv6 packets with filter :{packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find icmpv6 packets in sniffer"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.config(
    "wifi_access_point", wifi={
                                "ipv6_state": "1",
                                "security": "WPA2",
                                "passphrase": "12345678",
                                "connection_type": "STATIC_IPV6",
                                "wan_ipv6_address": wan_ipv6_addr,
                                "wan_ipv6_gateway": wan_gateway,
                                "wan_prefix_length": "64",
                                "lan_ipv6_address": "2405:3520:cc11:1241:3213:a134:1334:1421",
                                "lan_prefix_length": "64",
                                "lan_ipv6_prefix": "2405:3520:cc11:1241::",
                                "lan_ip_pool_start": "1000",
                                "lan_ip_pool_end": "5000",
                                "lan_lease_time": "86400",
                               }
                    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_assigning_static_ipv6_all_0s_to_dut_C536194(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, wifi_client=wifi_client,
                              test_id=536194,
                              ipv6_addr_type="link",
                              ping_before_power_save=False, ping_after_power_save=False,
                              static_ipv6="0000:0000:0000:0000:0000:0000:0000:0000",
                              ip_config_disable=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.sniffer_capture(mode='stop')
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)