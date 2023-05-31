from datetime import datetime
import datetime
import pytest as pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116BTFeatureBitMap
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116BTFeatureBitMap,RS9116PowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.time_measurer import TimeMeasurer
import time
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BTSocketRole
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect.devices.rs911x import RS9116TCPIPFeatureBitMap,RS9116ExtTCPIPFeatureBitMap,RS9116CertificateType,RS9116CoexMode,RS9116PowerSaveModes,RS9116FeatureBitMap,RS9116ConfigFeatureBitMap
# import test_sta_ble_connection
from utf_wiseconnect.devices.rs911x import RS9116AsyncEventType
from utf_wiseconnect.devices.rs911x import RS9116CustomFeatureBitMap, RS9116ExtCustomFeatureBitMap

def logger():
    return get_logger(__name__)

ping_count = 10
time_lapse = 5
rejoin_value = 4

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
        logger().info("enabling wifi power save")
        enable_wifi_ps = self. wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        enable_wifi_ps = self. wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, 'failed to enable'

        # check the WLan connection here
        wifi_status=self.wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"here==================>>>>>>>>>the wifi_status is as follows:{wifi_status}")


class Wifi_Rejoin(ThreadBase):
    def __init__(self,wifi_dut,wifi_access_point):
        super(Wifi_Rejoin, self).__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
    def run(self):
        self.wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_value, scan_interval=6, beacon_missedcount=40,
                                        first_time_retry=0)
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)



class  WifiJoin_WlanRadioOff_onDUT(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
    def run(self):
        status = self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        self.logger.info(status)
        time.sleep(15)
        # add the power save here the below enable WIFI power save in the DUT
        logger().info("enabling wifi power save")
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        enable_wifi_ps = self.wifi_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, 'failed to enable'
        time.sleep(10)
        # check the WLan connection here
        wifi_status = self.wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"here==================>>>>>>>>>the wifi_status is as follows:{wifi_status}")
        # turing off the radio of WLAN on DUT
        status = self.wifi_dut.interfaces.wifi.wlan_radio_deinit()
        assert status, 'failed to disable wifi Radio'
        time.sleep(10)
        # status = self.wifi_dut.interfaces.wifi.wlan_radio_init()
        # assert status, 'failed to enable wifi Radio'
        time.sleep(10)
        wifi_status = self.wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"here==================>>>>>>>>>the wifi_status is as follows:{wifi_status}")


class A2DP_DUT_stream(ThreadBase):
    def __init__(self, wifi_dut, bt_client,mode,codec,Test_case,time_lapse):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode
        self.codec = codec
        self.Test_case = Test_case
        self.time_lapse = time_lapse

    def run(self):
        if(self.mode == "initiator"):
            logger().info(f"------------------>here in A2DP as initiator thread<-------------------------------------------------------------")
            tss=str(datetime.datetime.now())
            temp=tss.replace('.',':')
            tss=temp.replace(' ','')
            temp=tss.replace(':','_')
            capture_file_path = "./reports/"+str(self.Test_case)+str(temp)+".wav"
            with TimeMeasurer() as t:
                bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_a2dp()
                assert bt_dut_address is not None
                bt_client_address = self.bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address, pin_code=pin_code)
                assert bt_client_address is not None,"The Client address is not found in the scan results"
                #A2DP connection
                found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(
                    bt_client_address=bt_client_address,
                    inquiry_type=2,
                    inquiry_duration_ms=20000,
                    timeout=22,
                    retry_counts=3,
                )
                if not found:
                    logger().info(
                        f"Dut unable to find the bt client device. The test case may fail."
                    )
                self.wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                time.sleep(10)
                logger().info("enabling bt power save")

                enable_bt_ps = self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
                enable_bt_ps = self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_ps, 'failed to enable'

                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                ) is not None,"The connection is already terminated"
                for i in range(time_lapse):
                    # Start capturing audio
                    self.bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
                    if(self.codec == "SBC"):
                        # A2DP SBC Audio streaming to Raspi
                        t_end = time.time()+60 * time_lapse
                        while time.time() < t_end:
                            self.wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
                            time.sleep(60)
                    elif(self.codec == "PCM"):
                        #A2DP PCM audio streaming to RASPI
                        #for the time being using the SBC here also
                        logger().info(f"PCM codec not supported")
                        time.sleep(60)

                time.sleep(10)
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)

                # assert the captured audio size
                captured_audio_size = self.bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
                logger().info(f"captured_audio_size : {captured_audio_size}")
                assert int(captured_audio_size / 100000) >= 1
            logger().info(f"BT time duration is {t.duration} seconds")

        elif(self.mode == "acceptor"):
            logger().info(
                f"------------------>here in A2DP as Acceptor thread<-------------------------------------------------------------")
            tss = str(datetime.datetime.now())
            temp = tss.replace('.', ':')
            tss = temp.replace(' ', '')
            temp = tss.replace(':', '_')
            capture_file_path = "./reports/" + str(self.Test_case) + str(temp) + ".wav"
            with TimeMeasurer() as t:
                logger().info(f"hello in acceptor mode")
                # doing the initial connection and disconnection before the acceptor mode connection
                bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_a2dp()
                assert bt_dut_address is not None
                bt_client_address = self.bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address,
                                                                                        pin_code=pin_code)
                assert bt_client_address is not None ,"The Client address is not found in the scan results"
                # A2DP connection
                found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(
                    bt_client_address=bt_client_address,
                    inquiry_type=2,
                    inquiry_duration_ms=20000,
                    timeout=22,
                    retry_counts=3,
                )
                if not found:
                    logger().info(
                        f"Dut unable to find the bt client device. The test case may fail."
                    )
                assert found is not False
                self.wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                time.sleep(10)

                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )
                # Start capturing audio
                self.bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
                if (self.codec == "SBC"):
                    # A2DP SBC Audio streaming to Raspi
                    self.wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
                    time.sleep(30)
                elif (self.codec == "PCM"):
                    # A2DP PCM audio streaming to RASPI
                    # for the time being using the SBC here also
                    logger().info(f"PCM codec not supported")
                    time.sleep(30)
                # check the BT connection here
                connection_status = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                if (connection_status != 0):
                    # disconnect
                    self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)

                logger().info(f"initializing DUT in SLave mode")
                self.wifi_dut.interfaces.wifi.bt_set_slave_role()
                logger().info(f"the bt_client_address is :+>{bt_client_address}")

                found = self.bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20,
                                                                                       retry_counts=3)
                logger().info(f"device found is :=>>{found}")
                assert found is not False
                # create connection to the BUT from the Raspberrypi
                with self.bt_client.interfaces.bluetooth.bt_socket(
                        mode=BTSocketRole.Server
                ) as bt_server_socket:
                    with self.wifi_dut.interfaces.wifi.run_bt_task():
                        bt_server_socket.create_server()
                        connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                        logger().info(f"the status of the connection is:{connected}")
                        assert connected
                        # checking the L2ping
                        assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                            dest_addr=bt_dut_address
                        )

                        # Start capturing audio
                self.bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
                time.sleep(30)
                if (self.codec == "SBC"):
                    # A2DP SBC Audio streaming to Raspi
                    self.wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
                    time.sleep(30)
                elif (self.codec == "PCM"):
                    # A2DP PCM audio streaming to RASPI
                    # for the time being using the SBC here also
                    logger().info(f"PCM codec not supported")
                    # self.wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
                    time.sleep(30)
                    # check the BT connection here
                logger().info(f"checking if the connection previously made is stable or not and disconnect if the status is true")
                connection_status = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                time.sleep(10)
                if (connection_status != 0):
                    # disconnect
                    self.wifi_dut.interfaces.wifi.bt_suspend_a2dp_streaming()
                    self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)

                    # assert the captured audio size
                captured_audio_size = self.bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
                logger().info(f"captured_audio_size : {captured_audio_size}")
                assert int(captured_audio_size / 100000) >= 1
            logger().info(f"BT time duration is {t.duration} seconds")

class A2DP_and_AVRCP_with_Datastream(ThreadBase):
    def __init__(self, wifi_dut, bt_client,mode,codec,Test_case):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode
        self.codec = codec
        self.Test_case = Test_case
    def run(self):
        if self.mode == "initiator":
            logger().info(f"------------------>here in A2DP as initiator thread<-------------------------------------------------------------")
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
                assert bt_client_address is not None ,"The Client address is not found in the scan results"
                # A2DP Connection
                found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(
                    bt_client_address=bt_client_address,
                    inquiry_type=2,
                    inquiry_duration_ms=20000,
                    timeout=22,
                    retry_counts=3,
                )
                if not found:
                    logger().info(
                        f"Dut unable to find the bt client device. The test case may fail."
                    )
                self.wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                time.sleep(10)
                #powersave
                enable_bt_ps = self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_ps, "failed to enable bt power save"
                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )
                #Start capturing audio
                self.bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
                #A2DP streaming
                if self.codec == "SBC":
                    self.wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
                    time.sleep(60)
                elif self.codec =="PCM":
                    #for the time being set it to SBC will change it to PCM when implemented
                    logger().info(f"PCM codec not supported")
                    # self.wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
                    time.sleep(60)
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
                time.sleep(10)

                # check the BT connection here
                connection_status = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                if (connection_status != 0):
                    time.sleep(10)
                    self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address,timeout=60)

                # assert the captured audio size
                captured_audio_size = self.bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
                logger().info(f"captured_audio_size : {captured_audio_size}")
                assert int(captured_audio_size / 100000) >= 1
            logger().info(f"the BT audio streaming and avrcp happend for:{t.duration}seconds")
        elif self.mode =="acceptor":
            #further implementation
            logger().info(
                f"------------------>here in A2DP as acceptor thread<-------------------------------------------------------------")
            capture_file_path = "./reports/test_sta_bt_with_STA_A2DP_2DH3_DUT_as_acceptor_C34675." + str(
                datetime.datetime.now())
            logger().info(capture_file_path)

class HTTP_download(ThreadBase):
    def __init__(self,http_server,wifi_dut,wifi_access_point,index_path):
        self.http_server=http_server
        self.wifi_dut=wifi_dut
        self.wifi_access_point=wifi_access_point
        self.index_path=index_path
    def run(self):
        logger().info(f"path{self.index_path}")
        logger().info("Initiates scan in dut")
        scan_result = self.wifi_dut.interfaces.wifi.scan(ssid=None)
        assert scan_result, "scan failure,no ap found"

        logger().info("Joining access point")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)

        logger().info("starts the dhcp in dut")
        result = self.wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, self.wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")
        #powersave
        logger().info("enabling wifi power save")
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        enable_wifi_ps = self.wifi_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, 'failed to enable'

        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi

        logger().info("fetching the http data using get method")
        result = self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)
        time.sleep(30)
        assert result, "fetched data is empty,failed to get data"
        # return result
class Https_download(ThreadBase):
    def __init__(self,http_server,wifi_dut,wifi_access_point,index_path):
        self.http_server=http_server
        self.wifi_dut=wifi_dut
        self.wifi_access_point=wifi_access_point
        self.index_path=index_path
    def run(self):
        logger().info("initiates scan in dut")
        scan_results = self.wifi_dut.interfaces.wifi.scan(ssid=None)
        assert scan_results, "scan failure"

        logger().info("Joining access point")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)

        logger().info("starting dhcp in dut")
        result = self.wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, self.wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")

        logger().info("Enabling wifi power save")
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        enable_wifi_ps = self.wifi_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "failed to enable wifi power save"

        logger().info("Enabling bt power save")
        enable_bt_ps = self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        enable_bt_ps = self.wifi_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "failed to enable bt power save"
        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi

        logger().info("fetching https data using get method")
        status, content = self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)
        status1, content1 = self.http_client.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)

        logger().info(status)
        logger().info(content)
        assert content == content1, "fetched data is not same as expected data"

class sta_connect_ping_disconnect_reconnect(ThreadBase):
    def __init__(self,wifi_dut,wifi_access_point):
        self.wifi_dut=wifi_dut
        self.wifi_access_point = wifi_access_point

    def run(self):
        status = self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        self.logger.info(status)
        time.sleep(15)
        # add the power save here the below enable WIFI power save in the DUT
        logger().info("enabling wifi power save")
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        enable_wifi_ps = self.wifi_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, 'failed to enable'
        logger().info("starts the dhcp in dut")
        result = self.wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, self.wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")
        logger().info("disconnecting to ap.....")
        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(5)

        # check the WLan connection here
        wifi_status = self.wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"here==================>>>>>>>>>the wifi_status is as follows:{wifi_status}")
        status = self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        assert status,"\n..........RECONNECTION TO THE AP FAILED.............\n"
        self.logger.info(status)
        time.sleep(15)

class WLAN_continious_scan(ThreadBase):
    def __init__(self,wifi_dut,wifi_access_point):
        self.wifi_dut=wifi_dut
        self.wifi_access_point = wifi_access_point
    def run(self):
        for i in range(3):
            logger().info(f"performing WLan Scan for the time : {i}")
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            logger().info(f"scan results : {scan_results}")
            assert (len(scan_results) > 0), "scan failed"
            time.sleep(2)

class BT_Inquiry(ThreadBase):
    def __init__(self,wifi_dut,bt_client):
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
    def run(self):
        for i in range(3):
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_a2dp()
            assert bt_dut_address is not None
            bt_client_address = self.bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address,
                                                                                    pin_code=pin_code)
            assert bt_client_address is not None ,"the client address is not found in the scan results"
            # A2DP connection
            found = self.wifi_dut.interfaces.wifi.bt_inquiry_for_device(
                bt_client_address=bt_client_address,
                inquiry_type=2,
                inquiry_duration_ms=20000,
                timeout=22,
                retry_counts=3,
            )
            assert found is not True, "the client is not found"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH3_PACKETS_ONLY
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_sta_bt_with_STA_A2DP_2DH3_DUT_as_initiator_c34674(wifi_dut,bt_client,wifi_access_point):
    mode = "initiator"
    codec="SBC"
    Test_case="c34674"
    time_lapse=1
    wifi_join_obj=wifiJoinThread(wifi_dut, wifi_access_point)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut, bt_client,mode,codec,Test_case,time_lapse)
    wifi_join_obj.start()
    A2DP_join_obj.start()
    wifi_join_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH3_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.skip(reason="support for acceptor mode not available right now")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_with_STA_A2DP_2DH3_DUT_as_acceptor_C34675(wifi_dut,bt_client,wifi_access_point):
    mode = "acceptor"
    codec = "SBC"
    Test_case = "C34675"
    time_lapse = 1
    wifi_join_obj=wifiJoinThread(wifi_dut, wifi_access_point)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    wifi_join_obj.start()
    A2DP_join_obj.start()
    wifi_join_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH5_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_with_STA_A2DP_2DH5_DUT_as_initiator_C34676(wifi_dut,bt_client,wifi_access_point):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34676"
    time_lapse = 1
    wifi_join_obj=wifiJoinThread(wifi_dut, wifi_access_point)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    wifi_join_obj.start()
    A2DP_join_obj.start()
    wifi_join_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH5_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.skip(reason="support for acceptor mode not available right now")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_with_STA_A2DP_2DH5_DUT_as_acceptor_C34677(wifi_dut,bt_client,wifi_access_point):
    mode = "acceptor"
    codec = "SBC"
    Test_case = "C34677"
    time_lapse = 1
    wifi_join_obj=wifiJoinThread(wifi_dut, wifi_access_point)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    wifi_join_obj.start()
    A2DP_join_obj.start()
    wifi_join_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH3_PACKETS_ONLY
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_with_STA_A2DP_2DH3_DUT_as_initiator_SBC_codec_c34678(wifi_dut,bt_client,wifi_access_point):
    mode = "initiator"
    codec="SBC"
    Test_case="c34678"
    time_lapse = 1
    wifi_join_obj=wifiJoinThread(wifi_dut, wifi_access_point)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut, bt_client,mode,codec,Test_case,time_lapse)
    wifi_join_obj.start()
    A2DP_join_obj.start()
    wifi_join_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH3_PACKETS_ONLY
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.skip(reason="support for acceptor mode not available right now")
def test_sta_bt_with_STA_A2DP_2DH3_DUT_as_acceptor_SBC_codec_c34679(wifi_dut,bt_client,wifi_access_point):
    mode = "acceptor"
    codec="SBC"
    Test_case="c34679"
    wifi_join_obj=wifiJoinThread(wifi_dut, wifi_access_point)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut, bt_client,mode,codec,Test_case,time_lapse)
    wifi_join_obj.start()
    A2DP_join_obj.start()
    wifi_join_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH5_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_sta_BT_where_STA_continious_HTTP_Download_BT_initiator_2DH5_C34680(http_server,wifi_dut,bt_client,wifi_access_point,index_path):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34680"
    http_download_obj=HTTP_download(http_server,wifi_dut,wifi_access_point,index_path)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    http_download_obj.start()
    A2DP_join_obj.start()
    http_download_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH5_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.skip(reason="support for acceptor mode not available right now")
def test_sta_BT_where_STA_continious_HTTP_Download_BT_initiator_2DH5_C34681(http_server,wifi_dut,bt_client,wifi_access_point,index_path):
    mode = "acceptor"
    codec = "SBC"
    Test_case = "C34681"
    wifi_join_obj=wifiJoinThread(wifi_dut, wifi_access_point)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    wifi_join_obj.start()
    A2DP_join_obj.start()
    wifi_join_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_3DH3_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_sta_BT_where_STA_continious_HTTP_Download_BT_initiator_3DH5_C34682(http_server,wifi_dut,bt_client,wifi_access_point,index_path):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34682"
    http_download_obj=HTTP_download(http_server,wifi_dut,wifi_access_point,index_path)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    http_download_obj.start()
    A2DP_join_obj.start()
    http_download_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_3DH3_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.skip(reason="support for acceptor mode not available right now")
def test_sta_BT_where_STA_continious_HTTP_Download_BT_initiator_3DH5_C34683(http_server,wifi_dut,bt_client,wifi_access_point,index_path):
    mode = "acceptor"
    codec = "SBC"
    Test_case = "C34683"
    time_lapse=1
    http_download_obj=HTTP_download(http_server,wifi_dut,wifi_access_point,index_path)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    http_download_obj.start()
    A2DP_join_obj.start()
    http_download_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_3DH5_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_sta_BT_where_STA_continious_HTTP_Download_BT_initiator_3DH5_C34684(http_server,wifi_dut,bt_client,wifi_access_point,index_path):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34684"
    time_lapse = 1
    http_download_obj= HTTP_download(http_server,wifi_dut,wifi_access_point,index_path)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    http_download_obj.start()
    A2DP_join_obj.start()
    http_download_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_3DH5_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.skip(reason="support for acceptor mode not available right now")
def test_sta_BT_where_STA_continious_HTTP_Download_BT_acceptor_3DH5_C34685(http_server,wifi_dut,bt_client,wifi_access_point,index_path):
    mode = "acceptor"
    codec = "SBC"
    Test_case = "C34685"
    time_lapse = 1
    http_download_obj=HTTP_download(http_server,wifi_dut,wifi_access_point,index_path)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    http_download_obj.start()
    A2DP_join_obj.start()
    http_download_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH3_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_StaRejoin_BT_Streaming_C34690(http_server,wifi_dut,bt_client,wifi_access_point,index_path):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34690"
    time_lapse=1
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    Wifi_rejoin_obj=Wifi_Rejoin(wifi_dut, wifi_access_point)
    Wifi_rejoin_obj.start()
    A2DP_join_obj.start()
    Wifi_rejoin_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_sta_BT_where_STA_continious_HTTP_Download_BT_initiator_C34696(http_server,wifi_dut,bt_client,wifi_access_point,index_path):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34696"
    time_lapse=1
    http_download_obj=HTTP_download(http_server,wifi_dut,wifi_access_point,index_path)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    http_download_obj.start()
    A2DP_join_obj.start()
    http_download_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_sta_BT_where_STA_continious_HTTP_Download_BT_initiator_C34697(http_server,wifi_dut,bt_client,wifi_access_point,index_path):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34697"
    time_lapse =1
    http_download_obj=HTTP_download(http_server,wifi_dut,wifi_access_point,index_path)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    http_download_obj.start()
    A2DP_join_obj.start()
    http_download_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_sta_connect_ping_disconnect_reconnect_C34687(http_server,wifi_dut,bt_client,wifi_access_point):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34687"
    time_lapse=1
    Sta_connect_ping_disconnect_obj=sta_connect_ping_disconnect_reconnect(wifi_dut,wifi_access_point)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    Sta_connect_ping_disconnect_obj.start()
    A2DP_join_obj.start()
    Sta_connect_ping_disconnect_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_WLAN_continious_scan_with_A2DP_C34688(http_server,wifi_dut,bt_client,wifi_access_point):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34688"
    time_lapse=1
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    Wlan_scan=WLAN_continious_scan(wifi_dut,wifi_access_point)
    Wlan_scan.start()
    A2DP_join_obj.start()
    Wlan_scan.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_continious_scan_with_BT_inquiry_BTandBLE_enabled_C34689(http_server,wifi_dut,bt_client,wifi_access_point):
    BT_Inquiry_obj=BT_Inquiry(wifi_dut,bt_client)
    Wlan_scan_obj=WLAN_continious_scan(wifi_dut,wifi_access_point)
    Wlan_scan_obj.start()
    BT_Inquiry_obj.start()
    Wlan_scan_obj.wait_for_exit()
    BT_Inquiry_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_continious_scan_with_BT_inquiry_onlyBTenabled_C34689(http_server,wifi_dut,bt_client,wifi_access_point):
    BT_Inquiry_obj=BT_Inquiry(wifi_dut,bt_client)
    Wlan_scan_obj=WLAN_continious_scan(wifi_dut,wifi_access_point)
    Wlan_scan_obj.start()
    BT_Inquiry_obj.start()
    Wlan_scan_obj.wait_for_exit()
    BT_Inquiry_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_WLAN_continious_scan_with_A2DP_C34692(http_server,wifi_dut,bt_client,wifi_access_point):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34692"
    time_lapse = 1
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    Wlan_scan_obj=WLAN_continious_scan(wifi_dut,wifi_access_point)
    Wlan_scan_obj.start()
    A2DP_join_obj.start()
    Wlan_scan_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH3_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"6kB.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def Test_HTTPS6KB_download_BTA2DP_2DH3_initiator_C34698(http_server, wifi_dut,bt_client,http_client, wifi_access_point, index_path):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34698"
    time_lapse = 1
    A2DP_join_obj = A2DP_DUT_stream(wifi_dut, bt_client, mode, codec, Test_case, time_lapse)
    https_download_obj=Https_download(http_server, wifi_dut,http_client, wifi_access_point, index_path)
    A2DP_join_obj.start()
    https_download_obj.start()
    A2DP_join_obj.wait_for_exit()
    https_download_obj.wait_for_exit()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH3_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"1MB.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def Test_HTTPS1MB_download_BTA2DP_2DH3_initiator_C34699(http_server, wifi_dut,bt_client,http_client, wifi_access_point, index_path):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34699"
    time_lapse = 1
    A2DP_join_obj = A2DP_DUT_stream(wifi_dut, bt_client, mode, codec, Test_case, time_lapse)
    https_download_obj=Https_download(http_server, wifi_dut,http_client, wifi_access_point, index_path)
    A2DP_join_obj.start()
    https_download_obj.start()
    A2DP_join_obj.wait_for_exit()
    https_download_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def  test_Wlan_connection_dualpairOn_DUT_C34700(wifi_dut,bt_client,wifi_access_point):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34700"
    time_lapse=1
    wifi_join_obj=wifiJoinThread( wifi_dut, wifi_access_point),
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    wifi_join_obj.start()
    A2DP_join_obj.start()
    wifi_join_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_A2DP_Sta_connection_BLE_connect_disconnect_C34701(wifi_dut,bt_client,wifi_access_point,ble_client):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34701"
    ble_mode = "ble_slave"
    time_lapse=1
    wifi_join_obj = wifiJoinThread(wifi_dut, wifi_access_point),
    A2DP_join_obj = A2DP_DUT_stream(wifi_dut, bt_client, mode, codec, Test_case, time_lapse)
    BLE_connect_disconnect_obj= test_sta_ble_connection.BleThread_connection(wifi_dut, ble_client, ble_mode)
    wifi_join_obj.start()
    A2DP_join_obj.start()
    BLE_connect_disconnect_obj.start()
    wifi_join_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()
    BLE_connect_disconnect_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_A2DP_Sta_connection_BLE_connect_disconnect_C34703(wifi_dut,bt_client,wifi_access_point,ble_client):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34703"
    ble_mode = "ble_slave"
    time_lapse=1
    BLE_connect_disconnect_obj = test_sta_ble_connection.BleThread_connection(wifi_dut, ble_client, ble_mode)
    wifi_join_obj = wifiJoinThread(wifi_dut, wifi_access_point),
    A2DP_join_obj = A2DP_DUT_stream(wifi_dut, bt_client, mode, codec, Test_case, time_lapse)
    BLE_connect_disconnect_obj.start()
    wifi_join_obj.start()
    A2DP_join_obj.start()

    wifi_join_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()
    BLE_connect_disconnect_obj.wait_for_exit()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_long_run_A2DP_wifi_join_C34704(wifi_dut,bt_client,wifi_access_point):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34704"
    time_lapse=10
    wifi_join_obj=wifiJoinThread( wifi_dut, wifi_access_point)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    wifi_join_obj.start()
    A2DP_join_obj.start()
    wifi_join_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def  test_BTInquiry_with_HTTP_download_C34706(wifi_dut,bt_client,wifi_access_point,http_server,index_path):
    BT_inquiry_obj=BT_Inquiry(wifi_dut, bt_client)
    HTTP_download_obj=HTTP_download(http_server,wifi_dut,wifi_access_point,index_path)
    BT_inquiry_obj.start()
    HTTP_download_obj.start()
    BT_inquiry_obj.wait_for_exit()
    HTTP_download_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.BT_EDR_2DH3_PACKETS_ONLY
            | RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def  test_AVRCP_DUT_when_WLAN_is_connected_and_A2DPdata_transfer_is_happening_C34708(wifi_dut,bt_client,wifi_access_point):
    mode="initiator"
    codec="SBC"
    Test_case="C34708"
    wifi_join_obj = wifiJoinThread(wifi_dut, wifi_access_point)
    A2DP_Avrcp_obj=A2DP_and_AVRCP_with_Datastream(wifi_dut, bt_client, mode, codec, Test_case)
    wifi_join_obj.start()
    A2DP_Avrcp_obj.start()
    wifi_join_obj.wait_for_exit()
    A2DP_Avrcp_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "bt_features":RS9116BTFeatureBitMap.Default
            | RS9116BTFeatureBitMap.A2DPProfileEnable
            | RS9116BTFeatureBitMap.A2DPSourceRoleEnable
            | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def  test_A2DP_WLan_radioONOFF_C34709(wifi_dut,bt_client,wifi_access_point):
    mode = "initiator"
    codec = "SBC"
    Test_case = "C34709"
    time_lapse=1
    wlan_radio_on_off_obj = WifiJoin_WlanRadioOff_onDUT( wifi_dut, wifi_access_point)
    A2DP_join_obj=A2DP_DUT_stream(wifi_dut,bt_client,mode,codec,Test_case,time_lapse)
    wlan_radio_on_off_obj.start()
    A2DP_join_obj.start()
    wlan_radio_on_off_obj.wait_for_exit()
    A2DP_join_obj.wait_for_exit()
