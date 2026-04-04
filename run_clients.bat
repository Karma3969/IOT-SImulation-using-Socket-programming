@echo off
echo Starting multiple IoT devices in the background...

:: The /B flag runs the application in the background without opening a new window for each
start /B device_client.exe light1
start /B device_client.exe fan1
start /B device_client.exe fridge1
start /B device_client.exe thermostat

echo Devices are now running in the background!
echo Close this terminal window to stop them.
pause
