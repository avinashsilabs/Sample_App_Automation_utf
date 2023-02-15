import threading
import time

import pytest

from utf.utils.iperf import iperf_utils
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116JoinFeatureBitMap,
    RS9116PowerSaveModes,
    RS9116PowerSaveProcedureTypes,
    DeviceConstants, SocketOptions,
)


def pdu_switch(switch, sleep_time, logger):
    logger.info("Turning off the AP")
    switch.interfaces.pdu_switch.turn_off()
    logger.info("Successfully powered off AP")
    time.sleep(sleep_time)
    logger.info("Again turning on the AP")
    switch.interfaces.pdu_switch.turn_on()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ca_cert": ["ca-chain.cert.pem"],
        "set_tx_wait_time": True,
        "tx_wait_time": 160000,
        "rejoin_max_retry": 40,
        "scan_interval": 6,
        "beacon_missed_count": 40,
    },
)
@pytest.mark.parametrize(
    "cert1",
    [
        [
            "ca-chain.cert.pem",
            "mosquitto-utf.silabs.com.cert.pem",
            "mosquitto-utf.silabs.com.key.pem",
        ],
    ],
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "close_sockets"]
)
def test_ssl_client_tx_rejoin(
    wifi_dut, wifi_access_point, ssl_server, cert1, switch, logger
):
    port1 = 5001
    buffer_length = 20
    pkt_count = 100

    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    wifi_dut.interfaces.wifi.rejoin(
        rejoin_max=40,
        scan_interval=6,
        beacon_missedcount=40,
        first_time_retry=0,
    )

    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(
        wifi_access_point,
        join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromPowerSave,
    )

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    wifi_dut.interfaces.wifi.power_save_listen_interval(
        RS9116PowerSaveModes.PowerSaveMode2,
        RS9116PowerSaveProcedureTypes.FastPowerSave,
        listen_interval=1600,
    )

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    iperf_utils.ping(device_ip, 10)

    # Use this code, if you are using Raspi over WiFi. Add wifi_client fixture above
    # wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    # host_ip = wifi_client.interfaces.wifi.get_ip_address()
    # assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 5

    ssl_server.interfaces.ssl.start_server(
        port=port1, server_cert=cert1[1], server_key=cert1[2]
    )
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(
        protocol=SocketOptions.SSL_ENABLE
    )

    wifi_dut.interfaces.wifi.set_socket_option(
        sock,
        SocketOptions.SOL_SOCKET,
        SocketOptions.SO_SSL_ENABLE,
        SocketOptions.SSL_ENABLE,
    )
    logger.info(
        f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds"
    )
    wifi_dut.interfaces.wifi.set_socket_option(
        sock,
        SocketOptions.SOL_SOCKET,
        SocketOptions.TCP_RETRY,
        SocketOptions.TCP_MAX_RETRY,
    )

    wifi_dut.interfaces.wifi.set_socket_option(
        sock,
        SocketOptions.SOL_SOCKET,
        SocketOptions.SO_CERT_INDEX,
        SocketOptions.CERT_INDEX0,
    )

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(
        sock, ssl_server.interfaces.ssl, server_port=port1
    )

    for i in range(2):
        logger.info(f"************************{buffer_length}")
        bytes_sent = pkt_count * buffer_length
        socket_no = [1]
        pkt_rcv_timeout = 90

        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(
                socket, pkt_count, buffer_length, pkt_rcv_timeout
            )
        sleep_time = 1
        thread = threading.Thread(
            target=pdu_switch,
            args=(switch, sleep_time, logger),
        )
        thread.start()
        wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(
            socket_list=1,
            data_len=buffer_length,
            time_interval=550,
            number_of_pkts=pkt_count,
            timeout=700,
        )
        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(1)
        assert bytes_sent == bytes_received, (
            f"Number of bytes sent by DUT and received on the remote peer "
            f"not matched on socket {1} "
        )

    wifi_dut.interfaces.wifi.close_socket(sock)
    wifi_dut.interfaces.wifi.leave()
