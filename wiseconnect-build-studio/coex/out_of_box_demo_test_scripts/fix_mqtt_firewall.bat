@echo off
setlocal EnableExtensions
cd /d "%~dp0"

rem ---------------------------------------------------------------------------
rem  WCBS MQTT relay host prep (Windows)
rem
rem  Out-of-box coex tests forward DUT MQTT to test.mosquitto.org through a
rem  Python TCP relay on this host's lab IP:1883. Common host blockers:
rem    1) Local Mosquitto (or another broker) already bound to 0.0.0.0:1883
rem    2) Windows Firewall inbound Block rules for python.exe
rem    3) Missing inbound Allow for TCP 1883
rem
rem  Run this once (UAC) after cloning / on a new lab PC, then re-run the test.
rem  Override the listen port with:  fix_mqtt_firewall.bat 1884
rem ---------------------------------------------------------------------------

set "MQTT_PORT=%~1"
if "%MQTT_PORT%"=="" set "MQTT_PORT=1883"
set "RULE_NAME=WCBS MQTT Relay"

net session >nul 2>&1
if errorlevel 1 (
  echo Requesting Administrator rights to fix MQTT port %MQTT_PORT% ...
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath '%~f0' -ArgumentList '%MQTT_PORT%' -Verb RunAs"
  exit /b %ERRORLEVEL%
)

echo.
echo === WCBS MQTT firewall / port fix ===
echo Port : %MQTT_PORT%
echo Rule : %RULE_NAME%
echo.

echo [1/4] Freeing TCP %MQTT_PORT% if a local Mosquitto service owns it...
sc query mosquitto >nul 2>&1
if not errorlevel 1 (
  for /f "tokens=3 delims=: " %%S in ('sc query mosquitto ^| findstr /I "STATE"') do set "MOSQ_STATE=%%S"
  if /I "%MOSQ_STATE%"=="RUNNING" (
    net stop mosquitto
    if errorlevel 1 (
      echo WARNING: could not stop mosquitto service.
    ) else (
      echo Stopped mosquitto service.
    )
  ) else (
    echo Mosquitto service is not running.
  )
) else (
  echo Mosquitto service not installed; skipping.
)

echo.
echo [2/4] Showing what currently listens on TCP %MQTT_PORT%...
netstat -ano | findstr ":%MQTT_PORT% " | findstr /I "LISTENING"
if errorlevel 1 (
  echo No LISTENING socket on TCP %MQTT_PORT% — port is free for the relay.
) else (
  echo WARNING: something is still listening above. Stop that process or pick another port.
)

echo.
echo [3/4] Disabling inbound Block rules for python.exe ^(Domain/Public^)...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$rules = Get-NetFirewallRule -DisplayName 'python.exe' -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' };" ^
  "if (-not $rules) { Write-Host 'No python.exe inbound Block rules found.' }" ^
  "else { $rules | Disable-NetFirewallRule; $rules | Select-Object DisplayName, Enabled, Direction, Action, Profile | Format-Table -AutoSize }"
if errorlevel 1 (
  echo WARNING: could not update python.exe firewall rules.
)

echo.
echo [4/4] Ensuring inbound Allow rule for TCP %MQTT_PORT%...
netsh advfirewall firewall delete rule name="%RULE_NAME%" >nul 2>&1
netsh advfirewall firewall add rule name="%RULE_NAME%" dir=in action=allow protocol=TCP localport=%MQTT_PORT% profile=any enable=yes
if errorlevel 1 (
  echo ERROR: failed to add firewall rule "%RULE_NAME%".
  exit /b 1
)
echo Added/replaced rule "%RULE_NAME%" ^(TCP %MQTT_PORT%, all profiles^).

echo.
echo === Current rule state ===
netsh advfirewall firewall show rule name="%RULE_NAME%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-NetFirewallRule -DisplayName 'python.exe','%RULE_NAME%' -ErrorAction SilentlyContinue |" ^
  " Select-Object DisplayName, Enabled, Direction, Action, Profile |" ^
  " Format-Table -AutoSize"

echo.
echo Done. Keep mqtt.broker_host=test.mosquitto.org and mqtt.relay=auto in config.local.json.
echo Re-run the out_of_box_demo coexistence test from Build Studio.
echo.
pause
exit /b 0
