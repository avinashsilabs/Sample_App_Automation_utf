import time
import pytest
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
import random
import string
from utf_wifi_zephyr.devices.si91x import Si91xBSDSocketParams, ZephyrHttpMethods, ZephyrTlsCredentials, ZephyrTLSParams
import ipaddress
from utf.utf_config import UtfConfig
from utf.utils import get_tls_certificate_dir

"""The testcases added in this file run below test steps for DUT(Soc917)
        1. Configuration of DUT in 2G : gnbax
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Verify TLS test suite and HTTPS OTAF test suites
     
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. NUC device for Sniffer

    Author: Vinod.G
"""


def text_generator(size=1000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def logger():
    return get_logger(__name__)


def random_ipv6_addr(network):
    """
    Generate a random IPv6 address in the given network
    Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
    Returns an IPv6Address object.
    """
    net = ipaddress.IPv6Network(network)
    # Which of the network.num_addresses we want to select?
    addr_no = random.randint(0, net.num_addresses)
    # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
    network_int = int.from_bytes(net.network_address.packed, byteorder="big")
    addr_int = network_int + addr_no
    addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
    return addr


class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, sniffer_filter=None, wifi_sniffer=None,
                 zephyr_wifi_collections=None, test_name=None, ap_mac_address=None, power_save=None, ca_cert=None,
                 ssl_server=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.test_name = test_name
        self.dut_addr = None
        self.device_ip = None
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.enc = "ccmp"
        self.power_save = power_save
        self.ca_cert = ca_cert
        self.ssl_server = ssl_server

    def run(self):
        try:
            self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, retry_count=3,
                                                                              wifi_access_point=self.wifi_access_point,
                                                                              associated=self.wifi_dut.interfaces.wifi.associated,
                                                                              ping_after_power_save=True,
                                                                              enc=self.enc,
                                                                              power_save=self.power_save)
            logger().info(
                f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    def tls_server_socket(self, port=5001, server_ip=None, data_length=100, time_seconds=30, data_transfer_type="tx"):

        logger().info(f"\n Starting the Remote TLS Server \n")
        self.ssl_server.interfaces.ssl.start_server()
        socket_id = self.wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET,
                                                         stream_type=Si91xBSDSocketParams.SOCK_STREAM,
                                                         protocol=Si91xBSDSocketParams.NET_IPPROTO_TLS_1_2
                                                         )
        logger().info(f"Socket open successfully : {socket_id}")
        self.wifi_dut.interfaces.wifi.wifi_setsockopt(socket_id, ZephyrTLSParams.SOL_TLS,
                                                      ZephyrTLSParams.TLS_SEC_TAG_LIST, 1)
        self.wifi_dut.interfaces.wifi.wifi_setsockopt(socket_id, ZephyrTLSParams.SOL_TLS, ZephyrTLSParams.TLS_HOSTNAME,
                                                      0)

        # self.wifi_dut.interfaces.wifi.bind(
        #    socket_fd=socket_id, device_ip=self.dut_addr['device_ip'], port=port, timeout=5)

        logger().info("DUT is connecting to server socket")
        for count in range(3):
            connect_status = False
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_id, server_ip, port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                assert connect_status, "Socket connection failed in DUT"
        logger().info("*********** Socket connection is successful ************")

        if data_transfer_type == "tx":
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=data_length)
            )

            sw = Stopwatch()
            t_end = time_seconds
            while sw.elapsed_sec <= t_end:
                time_left = int((t_end - sw.elapsed_sec) / 60)
                logger().info(f"*************** Remaining time to send data: '{time_left}' minutes ***************")
                try:
                    status, data = self.wifi_dut.interfaces.wifi.send(
                        socket_fd=socket_id, data=sent_data
                    )
                    if status != 0:
                        return socket_id
                    time.sleep(1)
                    server_socket_no = 1
                    data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no,
                                                                                    buffer_size=data_length)
                    logger().info(f"Data received on remote socket opened is {data_receive}")
                    assert sent_data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                    logger().info("Data sent by DUT and received on server is matching\n\n")
                except Exception as e:
                    logger().info(
                        f"Socket Data Transfer Failed Within Duration"
                    )
        else:
            sw = Stopwatch()
            t_end = time_seconds
            while sw.elapsed_sec <= t_end:
                time_left = int((t_end - sw.elapsed_sec) / 60)
                tx_buffer = "".join(
                    random.choices(string.ascii_uppercase + string.digits, k=data_length)
                )
                buffer_length = len(tx_buffer)
                self.ssl_server.interfaces.ssl.send_data_socket(1, 1, message=tx_buffer)
                time.sleep(1)
                buffer_rx = self.wifi_dut.interfaces.wifi.recv(socket_id, buffer_length)
                logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{socket_id} opened in the DUT is not matched"
                logger().info("Data sent by remote peer and received on DUT is matching")

        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        logger().info(f"Stopping the Remote Socket Server")
        self.ssl_server.interfaces.ssl.stop_server()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.firmware_app("test_tls")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.parametrize("ca_cert", ['ca-chain.cert.pem'])
@pytest.mark.start_state("wifi_dut", wifi='init')
def test_wifi_zephyr_tls_open_send_close_socket_c792409(
        firmware_loader, sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections, wifi_sniffer, request,
        wifi_client, ssl_server, ca_cert):
    """This test case Verifies the tls client socket open, send data,close functionality"""
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        # server_ip = ssl_server.interfaces.ssl.server_ip
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        port = ssl_server.interfaces.ssl.config['device_port1']
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, power_save=power_save,
                                     ca_cert=ca_cert, ssl_server=ssl_server)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        if ca_cert:
            cert_file = str(get_tls_certificate_dir().joinpath(ca_cert))
            with open(cert_file) as f:
                cert_contents = f.read()
            size = len(cert_contents)
            buffer_size = (512 * (int(size / 512))) + 512  # buffer_size should be more than size
            address = wifi_dut.interfaces.wifi.allocate_memory(size=buffer_size)
            wifi_dut.interfaces.wifi.load_memory(address, size=size, write_content=cert_contents)
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            wifi_dut.interfaces.wifi.wifi_tls_credential_add(ZephyrTlsCredentials.CA_CERTIFICATE_TAG,
                                                             ZephyrTlsCredentials.TLS_CREDENTIAL_CA_CERTIFICATE,
                                                             address, size)
        sw = Stopwatch()
        t_end = 300  # time in seconds
        while sw.elapsed_sec <= t_end:
            time_left = int((t_end - sw.elapsed_sec) / 60)
            logger().info(f"*************** Remaining time to complete test is: '{time_left}' minutes ***************")
            wifi_thread.tls_server_socket(port=port, server_ip=server_ip, data_length=100, time_seconds=30)

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.memory_free(address)
        wifi_dut.interfaces.wifi.reset()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.parametrize("ca_cert", ['ca-chain.cert.pem'])
@pytest.mark.firmware_app("test_tls")
def test_wifi_zephyr_tls_rx_c792411(
        firmware_loader, sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections, wifi_sniffer, request,
        wifi_client, ssl_server, ca_cert):
    """This test case Verifies the tls client socket open, rx data,close functionality"""
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        # server_ip = ssl_server.interfaces.ssl.server_ip
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        port = ssl_server.interfaces.ssl.config['device_port1']
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, power_save=power_save,
                                     ca_cert=ca_cert, ssl_server=ssl_server)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        if ca_cert:
            cert_file = str(get_tls_certificate_dir().joinpath(ca_cert))
            with open(cert_file) as f:
                cert_contents = f.read()
            size = len(cert_contents)
            buffer_size = (512 * (int(size / 512))) + 512  # buffer_size should be more than size
            address = wifi_dut.interfaces.wifi.allocate_memory(size=buffer_size)
            wifi_dut.interfaces.wifi.load_memory(address, size=size, write_content=cert_contents)
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            wifi_dut.interfaces.wifi.wifi_tls_credential_add(ZephyrTlsCredentials.CA_CERTIFICATE_TAG,
                                                             ZephyrTlsCredentials.TLS_CREDENTIAL_CA_CERTIFICATE,
                                                             address, size)

        wifi_thread.tls_server_socket(port=port, server_ip=server_ip, data_length=100, time_seconds=60,
                                      data_transfer_type="rx")

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.memory_free(address)
        wifi_dut.interfaces.wifi.reset()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.parametrize("server_cert", ['mosquitto-utf.silabs.com.cert.pem'])
@pytest.mark.parametrize("server_key", ['mosquitto-utf.silabs.com.key.pem'])
@pytest.mark.firmware_app("test_tls")
def test_wifi_zephyr_tls_server_tx_rx_ipv4_c792412(
        firmware_loader, sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections, wifi_sniffer, request,
        wifi_client, ssl_client, server_cert, server_key):
    """This test case Verifies the tls server socket open, tx data, rx data, and close functionality"""
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        # server_ip = ssl_server.interfaces.ssl.server_ip
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, power_save=power_save)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        if server_cert:
            cert_file = str(get_tls_certificate_dir().joinpath(server_cert))
            with open(cert_file) as f:
                cert_contents = f.read()
            size = len(cert_contents)
            buffer_size = (512 * (int(size / 512))) + 512  # buffer_size should be more than size
            address_server = wifi_dut.interfaces.wifi.allocate_memory(size=buffer_size)
            wifi_dut.interfaces.wifi.load_memory(address_server, size=size, write_content=cert_contents)
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            wifi_dut.interfaces.wifi.wifi_tls_credential_add(ZephyrTlsCredentials.SERVER_CERTIFICATE_TAG,
                                                             ZephyrTlsCredentials.TLS_CREDENTIAL_SERVER_CERTIFICATE,
                                                             address_server, size)
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        if server_key:
            cert_file = str(get_tls_certificate_dir().joinpath(server_key))
            with open(cert_file) as f:
                cert_contents = f.read()
            size = len(cert_contents)
            buffer_size = (512 * (int(size / 512))) + 512  # buffer_size should be more than size
            address_key = wifi_dut.interfaces.wifi.allocate_memory(size=buffer_size)
            wifi_dut.interfaces.wifi.load_memory(address_key, size=size, write_content=cert_contents)
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            wifi_dut.interfaces.wifi.wifi_tls_credential_add(ZephyrTlsCredentials.SER_KEY_TAG,
                                                             ZephyrTlsCredentials.TLS_CREDENTIAL_PRIVATE_KEY,
                                                             address_key, size)

        socket_id = wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET,
                                                    stream_type=Si91xBSDSocketParams.SOCK_STREAM,
                                                    protocol=Si91xBSDSocketParams.NET_IPPROTO_TLS_1_2)
        logger().info(f"Socket open successfully : {socket_id}")
        logger().info(f"Successfully opened tcp socket and socket id received is {socket_id} which is expected")
        wifi_dut.interfaces.wifi.wifi_setsockopt(socket_id, ZephyrTLSParams.SOL_TLS,
                                                 ZephyrTLSParams.TLS_SEC_TAG_LIST, 1)
        wifi_dut.interfaces.wifi.wifi_setsockopt(socket_id, ZephyrTLSParams.SOL_TLS, ZephyrTLSParams.TLS_HOSTNAME,
                                                 0)
        local_port = 5001
        device_ip = wifi_thread.dut_addr['device_ip']

        wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id, device_ip=device_ip, port=local_port, timeout=5)

        wifi_dut.interfaces.wifi.listen(socket_id, backlog=0)

        ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=local_port)
        # DUT
        socket_id_client = wifi_dut.interfaces.wifi.accept(socket_id)

        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            logger().info(f"sending {tx_buffer} from DUT")
            status, data = wifi_dut.interfaces.wifi.send(
                socket_fd=socket_id_client, data=tx_buffer
            )
            data_receive = ssl_client.interfaces.ssl.data_recv(buffer_length)

            if tx_buffer == data_receive.decode():
                logger().info("Data sent and received is matching")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id + 1)
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.memory_free(address_server)
        wifi_dut.interfaces.wifi.memory_free(address_key)
        wifi_dut.interfaces.wifi.reset()
