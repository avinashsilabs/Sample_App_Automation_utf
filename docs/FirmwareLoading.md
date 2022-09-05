# Firmware Loading

# Manifest
Provide list of markers for test cases under firmware_applications section in manifest. For each marker provide list of
devices and their firmware images for this marker. For each marker there is device_type, device_subtype and filename
inputs

# Harness
For each device in harness, there is subtype input along with type

# Test case
To load custom firmware on devices, mark test case with specific marker from the list of markers in manifest under
firmware_applications section and pass firmware_loader fixture as input parameter to test case

# Below are sample use cases

# Use case 1

# Manifest

firmware_applications:
    # List of markers for test cases
    wifitest:
    # List of devices and their firmware images for this marker
    - device_type: 'rs911x'
      device_subtype: 'rs9116'
      filename: 'RS9116W.2.4.1.17.rps'

# Test case

@pytest.mark.firmware_app("wifitest")
def test_something(firmware_loader):
    #some code
    pass

# Use case 2

# Manifest

firmware_applications:
    # List of markers for test cases
    wifitest:
    # List of devices and their firmware images for this marker
    - device_type: 'efx32'
      device_subtype: 'efr32'
      filename: 'sqa_test_agent.hex'

# Test case

@pytest.mark.firmware_app("wifitest")
def test_something(firmware_loader):
    #some code
    pass

# Use case 3

# Manifest

firmware_applications:
    # List of markers for test cases
    wifitest:
    # List of devices and their firmware images for this marker
    - device_type: 'rs911x'
      device_subtype: 'rs9116'
      filename: 'RS9116W.2.4.1.17.rps'
    - device_type: 'efx32'
      device_subtype: 'efr32'
      filename: 'sqa_test_agent.hex'

# Test case

@pytest.mark.firmware_app("wifitest")
def test_something(firmware_loader):
    #some code
    pass

# Use case 4

# Manifest

firmware:
  rs911x: RS9116W.2.4.1.17.rps
  efx32: generic_test_agent.hex

# Test case

from utf.utils.firmware_manager import FirmwareManager
def test_something():
    fw_mgr = FirmwareManager.get_instance()
    fw_mgr.load_default_firmware()
    pass

# Use case 5

# Manifest

firmware_applications:
    # List of markers for test cases
    wifitest:
    # List of devices and their firmware images for this marker
    - device_type: 'rs911x'
      device_subtype: 'rs9116'
      filename: 'RS9116W.2.4.1.17.rps'

# Test case

from utf.utils.firmware_manager import FirmwareManager

def test_something():
    fw_mgr = FirmwareManager.get_instance()
    fw_mgr.roll_back_to_default_firmware(app_name='wifitest')
    pass

# Use case 6

# Manifest

firmware_applications:
    # List of markers for test cases
    wifitest:
    # List of devices and their firmware images for this marker
    - device_type: 'efx32'
      device_subtype: 'efr32'
      filename: 'sqa_test_agent.hex'

# Test Case

from utf.utils.firmware_manager import FirmwareManager

def test_something():
    fw_mgr = FirmwareManager.get_instance()
    fw_mgr.roll_back_to_default_firmware(app_name='wifitest')
    pass
