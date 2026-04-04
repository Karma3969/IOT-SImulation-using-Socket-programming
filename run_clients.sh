#!/bin/bash
echo "Starting multiple IoT devices in the background..."

# Run multiple instances of the device client
./device_client light1 &
./device_client fan1 &
./device_client fridge1 &
./device_client thermostat &

echo "Devices are now running. Press [CTRL+C] to stop them all."

# Wait for all background processes to finish (or until user presses Ctrl+C)
wait
