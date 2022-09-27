import datetime
import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116BTFeatureBitMap
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
import time
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.devices.rs911x import RS9116BTFeatureBitMap, RS9116PowerSaveProcedureTypes, \
    RS9116ConfigFeatureBitMap
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes


def logger():
    return get_logger(__name__)


"""
####################################################################
                    Setup Requirements:
                    1. DUT (RS9116)
                    2. Access point
                    3. Raspberry pi4
                    4. EFR32

                    Author: Himaja Gudluri
####################################################################
"""


class wifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point

    def run(self):
        status = self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        self.logger.info(status)
        time.sleep(15)
        # add the power save here the below enable WIFI power save in the DUT
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        # check the WLan connection here
        wifi_status = self.wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"here==================>>>>>>>>>the wifi_status is as follows:{wifi_status}")


class A2DP_DUT_stream(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode, codec, Test_case):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode
        self.codec = codec
        self.Test_case = Test_case

    def run(self):
        if self.mode == "initiator":
            logger().info(
                f"------------------>here in A2DP as initiator "
                f"thread<-------------------------------------------------------------")
            tss = str(datetime.datetime.now())
            temp = tss.replace('.', ':')
            tss = temp.replace(' ', '')
            temp = tss.replace(':', '_')
            capture_file_path = "./reports/" + str(self.Test_case) + str(temp) + ".wav"
            with TimeMeasurer() as t:
                bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_a2dp()
                assert bt_dut_address is not None
                bt_client_address = self.bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address,
                                                                                        pin_code=pin_code)
                assert bt_client_address is not None
                # A2DP connection
                found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(
                    bt_client_address=bt_client_address,
                    inquiry_type=2,
                    inquiry_duration_ms=20000,
                    timeout=22,
                    retry_counts=3,
                )
                if not found:
                    assert found, f"Unable to find device with BD address {bt_dut_address}"
                self.wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                time.sleep(10)

                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )
                # Start capturing audio
                self.bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
                if self.codec == "SBC":
                    # A2DP SBC Audio streaming to Raspi
                    self.wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
                    time.sleep(60)
                elif self.codec == "PCM":
                    # A2DP PCM audio streaming to RASPI
                    assert self.codec != "PCM", "PCM is not supported"

                ping_response = self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                logger().info(f"l2ping response {ping_response}")
                assert ping_response, "dut is in inactive state..."

                # assert the captured audio size
                logger().info("============Capturing the size of audio file=============")
                captured_audio_size = self.bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
                logger().info(f"captured_audio_size : {captured_audio_size}")
                assert captured_audio_size != 0, "Captured size is zero"
            logger().info(f"BT time duration is {t.duration} seconds")

        elif self.mode == "acceptor":
            logger().info(f"------------------>here in A2DP as acceptor "
                          f"thread<-------------------------------------------------------------")
            capture_file_path = "./reports/test_sta_bt_with_STA_A2DP_2DH3_DUT_as_acceptor_C34675." + str(
                datetime.datetime.now())
            logger().info(capture_file_path)


class A2DP_and_AVRCP_with_Datastream(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode, codec, Test_case):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode
        self.codec = codec
        self.Test_case = Test_case

    def run(self):
        if self.mode == "initiator":
            logger().info(
                f"------------------>here in A2DP as initiator "
                f"thread<-------------------------------------------------------------")
            tss = str(datetime.datetime.now())
            temp = tss.replace('.', ':')
            tss = temp.replace(' ', '')
            temp = tss.replace(':', '_')
            capture_file_path = "./reports/" + str(self.Test_case) + str(temp) + ".wav"

            with TimeMeasurer() as t:
                bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_a2dp(enable_avrcp=True)
                assert bt_dut_address is not None
                bt_client_address = self.bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address,
                                                                                        pin_code=pin_code)
                assert bt_client_address is not None
                # A2DP Connection
                found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(
                    bt_client_address=bt_client_address,
                    inquiry_type=2,
                    inquiry_duration_ms=20000,
                    timeout=22,
                    retry_counts=3,
                )
                if not found:
                    assert found, f"Unable to find device with BD address {bt_dut_address}"
                self.wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                time.sleep(10)
                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )
                # Start capturing audio
                self.bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
                # A2DP streaming
                if self.codec == "SBC":
                    self.wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
                    time.sleep(5)
                elif self.codec == "PCM":
                    # for the time being set it to SBC will change it to PCM when implemented
                    self.wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
                    time.sleep(5)
                # Playback and volume control from Raspi
                self.bt_client.interfaces.bluetooth.bt_media_player.play(bt_dut_address)
                time.sleep(1)
                self.bt_client.interfaces.bluetooth.bt_media_player.pause(bt_dut_address)
                time.sleep(1)
                self.bt_client.interfaces.bluetooth.bt_media_player.play(bt_dut_address)
                time.sleep(1)
                self.bt_client.interfaces.bluetooth.bt_media_player.set_volume(bt_dut_address, volume=7)
                self.bt_client.interfaces.bluetooth.bt_media_player.next(bt_dut_address)
                time.sleep(1)
                self.bt_client.interfaces.bluetooth.bt_media_player.set_volume(bt_dut_address, volume=60)
                self.bt_client.interfaces.bluetooth.bt_media_player.previous(bt_dut_address)
                time.sleep(1)
                self.bt_client.interfaces.bluetooth.bt_media_player.set_volume(bt_dut_address, volume=127)
                time.sleep(1)
                self.bt_client.interfaces.bluetooth.bt_media_player.pause(bt_dut_address)

                # check the BT connection here
                connection_status = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                if connection_status != 0:
                    # disconnect
                    self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)

                # assert the captured audio size
                captured_audio_size = self.bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
                logger().info(f"captured_audio_size : {captured_audio_size}")
                assert int(captured_audio_size / 100000) >= 1
            logger().info(f"the BT audio streaming and avrcp happend for:{t.duration}seconds")
        elif self.mode == "acceptor":
            # further implementation
            logger().info(
                f"------------------>here in A2DP as acceptor "
                f"thread<-------------------------------------------------------------")
            capture_file_path = "./reports/test_sta_bt_with_STA_A2DP_2DH3_DUT_as_acceptor_C34675." + str(
                datetime.datetime.now())
            logger().info(capture_file_path)


# class HTTP_100mb_download(ThreadBase):
#     def __init__(self,http_server,wifi_dut,wifi_access_point,logger,index_path):
#         self.http_server=http_server
#         self.wifi_dut=wifi_dut
#         self.wifi_access_point=wifi_access_point
#         self.logger=logger
#         self.index_path=index_path
#     def run(self):
#         # Initiates scan in dut
#         self.wifi_dut.interfaces.wifi.scan(ssid=None)
#         # Joins the access point with given ssid and the passphrase
#         self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
#         # starts the dhcp in dut
#         self.wifi_dut.interfaces.wifi.start_ip()
#         # Enables the wifi power save in dut
#         self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
#         # Enables the bt power save in dut
#         self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
#         self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
#
#         # API used to get the http data
#         self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "bt_features": RS9116BTFeatureBitMap.Default
                       | RS9116BTFeatureBitMap.A2DPProfileEnable
                       | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.skip(reason="done for now")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "bt_disconnect"])
def test_sta_bt_with_STA_A2DP_2DH3_DUT_as_cinitiator_c34674(wifi_dut, bt_client, wifi_access_point):
    mode = "initiator"
    codec = "PCM"
    Test_case = "test_sta_bt_with_STA_A2DP_2DH3_DUT_as_initiator_c34674"
    with wifiJoinThread(wifi_dut, wifi_access_point), A2DP_DUT_stream(wifi_dut, bt_client, mode, codec, Test_case):
        time.sleep(20)


# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "bt_features":RS9116BTFeatureBitMap.Default
#             | RS9116BTFeatureBitMap.A2DPProfileEnable
#             | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
#     }
# )
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.skip(reason="done for now")
# def test_sta_bt_with_STA_A2DP_2DH3_DUT_as_acceptor_C34675(wifi_dut,bt_client,wifi_access_point):
#     # mode = "acceptor"
#     # with wifiJoinThread(wifi_dut, wifi_access_point), A2DP_DUT_stream(wifi_dut, bt_client, mode):
#     #     time.sleep(20)
#     with TimeMeasurer() as t:
#         bt_local_name = "rs911x_bt_spp"
#         bt_pin_code = "4321"
#         # setting the DUT in slave role.
#         wifi_dut.interfaces.wifi.bt_start()
#         bt_dut_address = wifi_dut.interfaces.wifi.bt_get_local_address()
#         assert bt_dut_address is not None
#         assert (wifi_dut.interfaces.wifi.bt_set_loacl_name(bt_local_name))
#         assert (wifi_dut.interfaces.wifi.bt_set_eir_data(f"{bt_local_name}_eir"))
#         assert (wifi_dut.interfaces.wifi.bt_set_slave_role())
#         assert (wifi_dut.interfaces.wifi.bt_set_ssp_mode(0, 3))
#         assert (wifi_dut.interfaces.wifi.bt_a2dp_init())
#
#         logger().info(f"the dut address is:{bt_dut_address}")
#         # setting the Remote in the Master mode.
#         assert (bt_client.interfaces.wifi.bt_start())
#         assert (bt_client.interfaces.wifi.bt_set_master_role())
#         assert (bt_client.interfaces.wifi.bt_set_pin_code(bt_pin_code))
#         assert (bt_client.interfaces.wifi.bt_a2dp_init())


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "bt_features": RS9116BTFeatureBitMap.Default
                       | RS9116BTFeatureBitMap.A2DPProfileEnable
                       | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "bt_disconnect"])
def test_sta_bt_with_STA_A2DP_2DH3_DUT_as_initiator_SBC_codec_c34678(wifi_dut, bt_client, wifi_access_point):
    mode = "initiator"
    codec = "SBC"
    test_case = "test_sta_bt_with_STA_A2DP_2DH3_DUT_as_initiator_SBC_codec_c34678"
    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    # with wifiJoinThread(wifi_dut, wifi_access_point), A2DP_DUT_stream(wifi_dut, bt_client, mode, codec, test_case):

    t1 = wifiJoinThread(wifi_dut, wifi_access_point)
    t2 = A2DP_DUT_stream(wifi_dut, bt_client, mode, codec, test_case)
    t1.start()
    time.sleep(2)
    t2.start()

    t1.wait_for_exit(True)
    t2.wait_for_exit(True)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "bt_features": RS9116BTFeatureBitMap.Default
                       | RS9116BTFeatureBitMap.A2DPProfileEnable
                       | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "bt_disconnect"])
def test_AVRCP_DUT_when_WLAN_is_connected_and_data_transfer_is_happening_C34708(wifi_dut, bt_client, wifi_access_point):
    mode = "initiator"
    codec = "PCM"
    test_case = "test_AVRCP_DUT_when_WLAN_is_connected_and_data_transfer_is_happening_C34708"
    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    with wifiJoinThread(wifi_dut, wifi_access_point), A2DP_and_AVRCP_with_Datastream(wifi_dut, bt_client, mode, codec,
                                                                                     test_case):
        time.sleep(20)

# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "bt_features":RS9116BTFeatureBitMap.Default
#             | RS9116BTFeatureBitMap.A2DPProfileEnable
#             | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
#         "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#         "tcpip_features": RS9116TCPIPFeatureBitMap.Default
#                           | RS9116TCPIPFeatureBitMap.SSL,
#         "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
#         "ca_cert": "ca-chain.cert.pem"
#     }
# )

# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
# @pytest.mark.end_state("wifi_dut", wifi=["disassociated", "bt_disconnect"])
# @pytest.mark.skip(reason="not working seeing too many errors")
# def test_STA_BT_functionality_with_HTTP_download_and_A2DP_Streaming_C34682(wifi_dut,wifi_access_point,bt_client):
#     mode="initiator"
#     codec="PCM"
#     Test_case="test_STA_BT_functionality_with_HTTP_download_and_A2DP_Streaming_C34682"
#     http_server="raspi_lighttpd"
#     index_path="./reports/100MB.html"
#     with HTTP_100mb_download(http_server,wifi_dut,wifi_access_point,logger,index_path), A2DP_DUT_stream(wifi_dut, bt_client, mode, codec, Test_case):
#         time.sleep(20)
