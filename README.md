# SSH Login Security Analyzer

## Overview
A Python command-line tool that analyses Linux SSH authentication logs, counts failed password attempts by source IP address, identifies IPs that reach a configurable failure threshold, and exports a CSV report.

## Features
- Reads SSH authentication log files.
- Detects failed SSH password attempts.
- Extracts source IP addresses.
- Counts failed attempts for each IP.
- Flags suspicious login activity using a configurable threshold.
- Displays results in the terminal.
- Exports results to a CSV file.

## Technologies Used
- Python 3
- Ubuntu Linux
- Regular Expressions
- CSV module
- Argument Parsing

## Requirements
- Ubuntu or another Linux system
- Python 3
- No external Python packages required.

## How to Run

Default command:

python3 analyzer.py

Change the detection threshold:

python3 analyzer.py --threshold 2

Choose an input log and output file:

python3 analyzer.py --log sample_auth.log --threshold 5 --output security_report.csv

## Test Data
The sample_auth.log file contains fictional SSH authentication records for testing.

## Limitations
This tool detects failed password patterns. It does not automatically block IP addresses or confirm whether an activity is malicious.
