# scancode4vulns
scan an .exe file to find code vulns


#!/bin/bash

# Prompt for file to scan
read -p "Enter .exe file to scan: " exe_file

# Check if file exists
if [ ! -f "$exe_file" ]; then
  echo "File not found"
  exit 1
fi

# Check for executable stack with objdump
if objdump -x "$exe_file" | grep -q 'GNU_STACK'; then
  echo "Executable stack found in $exe_file"
fi 

# Check for no-execute bit with readelf
if ! readelf -l "$exe_file" | grep -q 'NX enabled'; then
  echo "No-execute bit not set in $exe_file"
fi

# Scan imports/calls with nm
nm "$exe_file" | grep -iE 'malloc|strcpy|memcpy|scanf|system'

# Scan strings for sensitive terms
strings "$exe_file" | grep -iE 'password|auth|hash|key|credential' 

# Consider scanning with VirusTotal or similar malware scanning service
# Upload $exe_file to VirusTotal and parse output
