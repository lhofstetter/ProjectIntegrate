#!/bin/bash
default_wireless="wlan0" 
antenna_interface=$(iw dev | grep Interface | awk '{print $2}' | grep -v "^$default_wireless$" | head -n 1)

if [ -z "$antenna_interface" ]; then
    echo "Antenna interface not found."
    exit 1
fi

ip link set $antenna_interface down
iw dev $antenna_interface set type monitor
ip link set $antenna_interface up

current_channel=$(iw dev $default_wireless info | grep channel | awk '{print $2}')

iw dev $antenna_interface set channel $current_channel

./NodeRoutine &

node_pid=$!

# Continuously check for channel change
while true; do
    sleep 60  
    new_channel=$(iw dev $default_wireless info | grep channel | awk '{print $2}')
    
    # If the channel has changed, update the antenna device and potentially restart NodeRoutine
    if [ "$new_channel" != "$current_channel" ]; then
        iw dev $antenna_interface set channel $new_channel
        current_channel=$new_channel
        
        # Optionally restart NodeRoutine if necessary
        # kill $node_pid
        # ./NodeRoutine &
        # node_pid=$!
    fi
done
