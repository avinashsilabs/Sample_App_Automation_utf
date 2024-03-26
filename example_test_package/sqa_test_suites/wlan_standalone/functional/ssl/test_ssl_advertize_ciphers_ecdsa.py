# Test author: Vinod.G
# Test suite: Advertise CCM based more cipher suites for TLS_1.2
import pytest
from utf import UtfDatabaseProperties
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions,
    SocketType,
    Cipher,
    DefaultCipher,
)
from test_ssl_advertize_ciphers_rsa import ssl_connection_tx_rx

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Load ssl certificates in the DUT
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Create a new TCP/IP socket over ssl 
        6. Bind the socket with DUT ip address
        7. Connect the client with server socket as specified port number.
        8. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
        9. Analyze the cipher list sent in the tls-client-hello ssl packet and compare with the cipher list selected in
        the dut
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC Wifi Sniffer
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "ca_cert": "ca_ecdsa.crt",
            "set_send_feature_frame": True,
        }
    )
]


@pytest.mark.parametrize("cert",
                         [["server_ecdsa.crt",
                           "server_ecdsa.key"],
                          ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_tx_TC19616(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger, cert
):
    capture_filename = "test_advertise_ciphers_ssl_tx_TC19616"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 0, server_cert=cert[0], server_key=cert[1])


@pytest.mark.parametrize("cert",
                         [["server_ecdsa.crt",
                           "server_ecdsa.key"],
                          ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_rx_TC19617(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger, cert
):
    capture_filename = "test_advertise_ciphers_ssl_rx_TC19617"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 1, server_cert=cert[0], server_key=cert[1])
