#! /usr/bin/env bash

#script to format unique OUI's from OUI.txt

awk '/\(base 16\)/ {
    mac = $1;
    sub(/.*\(base 16\)[[:space:]]*/, "", $0);  # Remove everything up to and including "(base 16)"
    print mac "," $0
}' "$1" >> out.txt
