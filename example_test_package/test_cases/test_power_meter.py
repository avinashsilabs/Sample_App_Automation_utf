from utils.logger import get_logger
import paramiko
import os
#Import modules
import pyvisa
import time
import csv
import os

def logger():
    return get_logger(__name__)


def test_capture_power_meter_data_points_to_file(power_meter):
    #power_meter.interfaces.power_meter.sample_test()
    # power_meter.interfaces.power_meter.initialize_instrument()
    # power_meter.interfaces.power_meter.enable_voltage_measure(3, power_meter.interfaces.power_meter._inst)
    # power_meter.interfaces.power_meter.enable_current_measure(3, power_meter.interfaces.power_meter._inst)
    # power_meter.interfaces.power_meter.set_sample_period(3, power_meter.interfaces.power_meter._inst, 0.001)
    # power_meter.interfaces.power_meter.configure_trigger_source_and_trigger_elog(3, power_meter.interfaces.power_meter._inst)
    # power_meter.interfaces.power_meter.capture_data_log(3, power_meter.interfaces.power_meter._inst)
    # power_meter.interfaces.power_meter.stop_data_log(3, power_meter.interfaces.power_meter._inst)
    #Communicating with Instrument
   

    print('\n"External Data Logger for Voltage & Current Measurements to csv file"\n')

    #Waiting for VISA address input 
    print('Enter VISA address of instrument(e.g. TCPIP0::141.183.189.37::inst0::INSTR)')
    VisaAddress = 'TCPIP0::10.207.19.83::inst0::INSTR'

    #Communicating with Instrument
    rm=pyvisa.ResourceManager()
    inst = rm.open_resource(VisaAddress)

    #Initiating variables 
    DUT = 0
    a = 0
    period = 0
    t_period = 0

    #Instrument Identity
    inst.write("*IDN?")
    print('Instrument Identity:'+inst.read())

    #----------------------------------------------------
    #External Datalogger - Voltage & Current Measurements 
    #----------------------------------------------------
    #Form - Set to ascii 
    inst.write("FORM ASCII")
    #Enable Elog Voltage Measurement
    inst.write("SENS:ELOG:FUNC:VOLT ON,(@3)")
    #Enable Elog Voltage Min/Max Measurement
    inst.write("SENS:ELOG:FUNC:VOLT:MINM ON,(@3)")
    #Enable Elog Current Measurement
    inst.write("SENS:ELOG:FUNC:CURR ON,(@3)")
    #Enable Elog Current Min/Max Measurement
    inst.write("SENS:ELOG:FUNC:CURR:MINM ON,(@3)")
    #Set Elog Integration period to 1ms
    inst.write("SENS:ELOG:PER 0.001,(@3)")
    #Query integration period that data is fetched 
    inst.write("SENS:ELOG:PER? (@3)")
    period = inst.read()
    t_period = period
    #Select Trigger source - Bus 
    inst.write("TRIG:TRAN:SOUR BUS,(@3)")
    #Initiate Elog
    inst.write("INIT:ELOG (@3)")
    #Delay by 0.1s
    time.sleep(0.1)
    #Trigger Elog
    inst.write("TRIG:ELOG (@3)")
    #Check for Error
    #inst.write("SYST:ERR?")
    #print(inst.read())

    #-----------------------------------------------------
    #Retrieve External Datalogger Output to csv file 
    #-----------------------------------------------------
    #Periodically retrieve voltage and current measurements 
    with open('Elog_Voltage_Current_Measurement.csv', mode='w',newline='')as f:
        f_writer = csv.writer(f)
        #Create column headers on csv file 
        f_writer.writerow([' Time(s)','Current(A)',' Imin(A)',' Imax(A)','Voltage(V)',' Vmin(V)',' Vmax(V)']) 
        #Retrieve measurements of maximum 10000 records 
        print('External Data Logger is initiated and running.')

        #Log measurements for a duration of 10 seconds. 
        for i in range(0, 10):  
            #inst.write("FETC:ELOG? 10000, (@3)")
            DUT=inst.query("FETC:ELOG? 10000, (@3)", 10)   
            x = DUT.split(",")
            while (a<len(x)):
                #Write measurement results to csv file 
                f_writer.writerow([t_period,x[a],x[a+1],x[a+2],x[a+3],x[a+4],x[a+5]])
                a = a + 6;
                t_period = float(t_period) + float(period);
            a=0;
            time.sleep(0.8)
            print('Data is logging...')
            
        #Abort Elog 
        inst.write("ABOR:ELOG (@3)")
        print("External Datalogger Completed")
            
        #Open csv file in Excel
        #print("Opening csv file...")
        #os.startfile('Elog_Voltage_Current_Measurement.csv')
