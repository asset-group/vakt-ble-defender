#!/bin/bash

# Function to connect to the Bluetooth device
connect_device() {
    bluetoothctl << EOF
    connect $1
EOF
    sleep 5 # Wait for 5 seconds
    bluetoothctl << EOF
    disconnect $1
EOF
}

# MAC address of the Bluetooth device
DEVICE_MAC="C8:C9:A3:D3:65:1E"

# Loop to attempt reconnection every 3 seconds
while true; do
    connect_device $DEVICE_MAC
    sleep 3
done
