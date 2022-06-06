# Running Tests

To run tests from the local PC command prompt as the test executor<br>
CD to the `executor` directory off the root of the repo
`launch_utf_tests.bat --harness 'System Name' --executor_type local`<br><br>
<b>Notes:</b><br>
- if a Popup come up to `allow firewall permissions for local lan` allow it
- `System Name` can be found in the System Information screen in Windows 

To run on Raspberry Pi as the test executor from the PC command prompt <br>
CD to the `executor` directory off the root of the repo
`launch_utf_tests.bat --harness 'System Name' --executor_type docker --target ip_address_of_raspberry_pi`<br><br>

