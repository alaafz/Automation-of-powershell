# Features & Automated Tasks #

## This script automates the following essential IT support functions ##

1. Clear Temp Files on Startup → Ensures system cleanliness by removing unnecessary temp files every day.
2. Generate Daily Critical Application Event Logs Report → Collects and stores critical event logs for review.
3. Generate Daily Error Application Event Logs Report → Highlights application errors for troubleshooting.
4. Check Storage Space Status → Monitors disk usage and alerts if storage is running low.
5. Monitor Services Health → Verifies essential system services are running correctly.
6. Check Network Connectivity → Tests network connections to detect any connectivity issues.
7. Analyze WiFi Signal Strength → Evaluates wireless signal performance.
8. Identify Drivers for Removal → Flags outdated or unnecessary drivers for cleanup.
9. Scan Drives for Bad Sectors → Performs periodic drive scans to detect potential issues.

## Prerequisites ##

* PowerShell Version: 5.1 or later
* Administrative Privileges: Required for certain tasks
* Required Modules: Install dependencies using:

## Installation & Usage ##
Step 1: 
Clone the Repository
- powershell
('''git clone https://github.com/alaafz/Automation-of-powershell.git''')

Step 2: Run the Script
- Execute the script with administrative privileges:

Powershell
.\DailyTasksAutomation.ps1

Step 3: Customize Settings
Modify config.json to adjust automation preferences for your specific environment.

Ensure "Run with highest privileges" is enabled.

## Logging & Reports ##
All reports are stored in the /Logs directory with timestamps for tracking system health.

## Future Enhancements ##
Add email notifications for alerts
