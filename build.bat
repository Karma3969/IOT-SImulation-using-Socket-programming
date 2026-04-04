@echo off
echo Building WebSocket Server...
gcc -Wall -O2 -o websocket_server.exe websocket_server.c utils.c db.c -lsqlite3
if %errorlevel% neq 0 exit /b %errorlevel%

echo Building Device Client...
gcc -Wall -O2 -o device_client.exe device_client.c utils.c
if %errorlevel% neq 0 exit /b %errorlevel%

echo Build Successful!
