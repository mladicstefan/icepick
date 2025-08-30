#!/usr/env/bin/bash

# Quick cleanup script for leaked monitor mode interfaces
# Removes all monX interfaces created by failed pcap sessions

echo "Cleaning up monitor interfaces..."

# Get all monitor interfaces (mon0, mon1, mon2, etc.)
monitor_interfaces=$(iw dev | grep -E '^\s+Interface mon[0-9]+' | awk '{print $2}')

if [ -z "$monitor_interfaces" ]; then
    echo "No monitor interfaces found to clean up."
    exit 0
fi

echo "Found monitor interfaces to remove:"
echo "$monitor_interfaces"

# Remove each monitor interface
for interface in $monitor_interfaces; do
    echo "Removing $interface..."
    sudo iw dev "$interface" del
    if [ $? -eq 0 ]; then
        echo "✓ Removed $interface"
    else
        echo "✗ Failed to remove $interface"
    fi
done

echo "Cleanup complete. Remaining interfaces:"
iw dev | grep -E '^\s+Interface' | awk '{print $2}'
