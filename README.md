# python-security-log-analyzer
Python project for analyzing authentication logs and detecting suspicious login patterns.

Overview

A Python-based security log analyzer that processes authentication logs to identify potentially suspicious login activity.This project demonstrates Python scripting, file handling, data analysis, and basic security detection techniques.

Features

Log parsing: Reads authentication records from a text file and converts them into structured data.
User analysis: Calculates successful and failed login attempts for each user.
Failure-rate detection: Flags accounts whose login failure rates exceed a configurable threshold.
IP analysis: Tracks login activity and the user accounts targeted by each IP address.
Brute-force detection: Identifies IP addresses with repeated failed login attempts.
Time-window detection: Detects bursts of failed logins within a configurable time window.
Alert generation: Reports potentially suspicious users and IP addresses.

Technologies

Python 3,
datetime module,
Dictionaries, lists, loops, and functions,
File handling and string parsing

How to Run

1. Install Python 3.
2. Place security_log_analyzer.py and sample_auth.log in the same directory.
3. Run the script
   python security_log_analyzer.py
4. Review the login statistics and alerts printed to the terminal.

Detection Logic

The analyzer uses configurable thresholds to identify unusual login behavior. The time-window detector examines failed login attempts from each IP address and flags activity that exceeds the configured failure threshold within the specified time interval.

Limitations

This project uses sample authentication logs and simple threshold-based detefction rules. Alerts indicate potetnially suspicous activity and require further investigation, they do not independently establish that an attack occurred.

Purpose

Built as a cybersecurity portfolio project to practice Python programming, authentication log analysis, and basic security monitoring concepts.
