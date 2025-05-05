# ---------------------------
# Function to display the menu
# ---------------------------
function Show-Menu {
    Clear-Host
    Write-Host "-----------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "                   Daily Tasks Management           " -ForegroundColor Cyan
    Write-Host "-----------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "1. Create Startup entry for clear temp file everyday"
    Write-Host "2. Create Report for Daily Critical Application Event Logs"
    Write-Host "3. Create Report for Daily Error Application Event Logs"
    Write-Host "4. Check Storage Space Status"
    Write-Host "5. Check Services health monitoring"
    Write-Host "6. Check Network Connectivity"
    Write-Host "7. Check WiFi Strenth"
    Write-Host "8. Check Drivers to Remove"
    Write-Host "9. Scan Drives For Bad sectors"
    Write-Host "0. Exit"
}

# ---------------------------
# Function to create the scheduled task for clearing temp files
# ---------------------------
function Create-ClearTempTask {
    try {
        # Calculate tomorrow’s date at 6:00 AM (adjust as needed)
        $startTime = (Get-Date).Date.AddDays(1).AddHours(6)

        # Define the action: run PowerShell to remove all files from the temp directory
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" `
                    -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Remove-Item -Path '$env:TEMP\*' -Force -Recurse`""

        # Define a daily trigger starting at $startTime
        $Trigger = New-ScheduledTaskTrigger -Daily -At $startTime

        # Define task settings to ensure it runs if missed
        $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

        # Define the principal using the SYSTEM account
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $Principal = New-ScheduledTaskPrincipal -UserId $CurrentUser -LogonType Interactive

        # Define the task name
        $taskName = "Clear Temp Files Daily"

        # Register the scheduled task
        Register-ScheduledTask -TaskName $taskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal `
            -Description "Clears temporary files daily starting from next day"

        Write-Host "Scheduled task '$taskName' created successfully." -ForegroundColor Green
        Write-Host "It will run daily starting tomorrow at $($startTime.ToShortTimeString())." -ForegroundColor Green    
    
    }
    catch {
        Write-Host "Error creating scheduled task:" -ForegroundColor Red
        Write-Host $_ -ForegroundColor Red
    }
}

function Critical-SystemEventTask {
    # Write a header to the log file
    # Set up a timestamp and a log file path for critical events
    $timeStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $logFile = "$env:USERPROFILE\Desktop\CriticalEventLog_$timeStamp.txt"

    "Critical Event Tracking Log - Started at $(Get-Date)" | Out-File -FilePath $logFile

    try {
        # Retrieve the last 50 system events that are critical (Level 1)
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 50
        
        # Append formatted event details to the log file
        if (-not $events) {
            "No error (Level=2) events found in the System log." | Out-File -FilePath $logFile -Append
        }
        else {
            $events | ForEach-Object {
                $eventTime = $_.TimeCreated
                $eventMessage = $_.Message
                "Event Time: $eventTime`nEvent Details: $eventMessage`n---" | Out-File -FilePath $logFile -Append
            }
            Write-Output "System events have been logged to $logFile"
        }
    }
    catch {
        Write-Error "An error occurred while retrieving event logs: $_"
    }
}

function Error-ApplicationEventTask {
    # Write a header to the log file
    # Set up a timestamp and a log file path for Error events
    $timeStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $logFile = "$env:USERPROFILE\Desktop\ErrorEventLog_$timeStamp.txt"

    "Error Event Tracking Log - Started at $(Get-Date)" | Out-File -FilePath $logFile

    try {
        # Retrieve the last 50 application events that are Error (Level 1)
        $events = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} -MaxEvents 50
        
        # Append formatted event details to the log file
        if (-not $events) {
            "No error (Level=2) events found in the Application log." | Out-File -FilePath $logFile -Append
        }
        else {
            $events | ForEach-Object {
                $eventTime = $_.TimeCreated
                $eventMessage = $_.Message
                "Event Time: $eventTime`nEvent Details: $eventMessage`n---" | Out-File -FilePath $logFile -Append
            }
            Write-Output "System events have been logged to $logFile"
        }
    }
    catch {
        Write-Error "An error occurred while retrieving event logs: $_"
    }
}

function TryDiskUsageOfDevice {

    try {
        Get-CimInstance Win32_LogicalDisk |
        Where-Object { $_.DriveType -eq 3 } |
        Select-Object @{Name="Drive Name"; Expression={$_.DeviceID}},
                    @{Name="Total Capacity (GB)"; Expression={[math]::Round($_.Size/1GB, 2)}},
                    @{Name="Free Space (GB)"; Expression={[math]::Round($_.FreeSpace/1GB, 2)}} |
        Format-Table -AutoSize
    }
    catch {
        <#Do this if a terminating exception happens#>
        Write-Error "An error occurred while retrieving storage report : $_"
    }    
}

function TryServiceHealthService {
    try {
        $criticalServices = @("Spooler", "WinDefend", "wscsvc", "wuauserv", "eventlog", "LSASS", "RpcSs")

        foreach ($svcName in $criticalServices) {
            try {
                $service = Get-Service -Name $svcName -ErrorAction Stop
                if ($service.Status -eq "Running") {
                    Write-Output "Service '$svcName' is running normally."
                }
                else {
                    Write-Output "Service '$svcName' is stopped. Current status: $($service.Status)."
                }
            }
            catch {
                Write-Output "Service '$svcName' was not found."
            }
        }
    }
    catch {
        <#Do this if a terminating exception happens#>
        Write-Error "An error occurred while retrieving service report : $_"
    }    
}

function TryNetworkService {
    try {
        Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration |
        Where-Object { $_.IPEnabled -eq $true } |
        Select-Object `
            @{Name="Description"; Expression = { $_.Description }},
            @{Name="MACAddress"; Expression = { $_.MACAddress }},
            @{Name="IPAddress"; Expression = { $_.IPAddress -join ', ' }},
            @{Name="DefaultIPGateway"; Expression = { if ($_.DefaultIPGateway) { $_.DefaultIPGateway -join ', ' } else { 'N/A' } }},
            @{Name="DNSServerSearchOrder"; Expression = { if ($_.DNSServerSearchOrder) { $_.DNSServerSearchOrder -join ', ' } else { 'N/A' } }} |
        Format-Table -Wrap -AutoSize |
        Out-String -Width 200
    }
    catch {
        <#Do this if a terminating exception happens#>
        Write-Error "An error occurred while retrieving Network report : $_"
    }
}

function TryWifiSignalStrength{
    try {
        # Run the netsh command to show network details including BSSID values
        $rawOutput = netsh wlan show networks mode=bssid | Out-String
        $lines = $rawOutput -split "`r?`n"
        $networkData = @()
        $currentSSID = ""
        $currentBSSID = ""
        
        foreach ($line in $lines) {
            $line = $line.Trim()
            
            # Capture SSID - the network name line (e.g., "SSID 1 : MyNetwork")
            if ($line -match "^SSID\s+\d+\s+:\s+(.*)$") {
                $currentSSID = $matches[1].Trim()
            }
            # Capture BSSID (the access point MAC address)
            elseif ($line -match "^BSSID\s+\d+\s+:\s+([0-9A-Fa-f:]{17})$") {
                $currentBSSID = $matches[1]
            }
            # Capture Signal strength in percentage
            elseif ($line -match "^Signal\s+:\s+(\d+)%$") {
                $signal = $matches[1]
                $networkData += [PSCustomObject]@{
                    SSID           = $currentSSID
                    BSSID          = $currentBSSID
                    SignalStrength = "$signal%"
                }
            }
        }
        
        # Display in a table with wrapping and auto-sized columns for neat formatting
        $networkData | Format-Table -AutoSize -Wrap
    }
    catch {
        <#Do this if a terminating exception happens#>
        Write-Error "An error occurred while retrieving Wireless Strength report : $_"
    }
}

function tryDriverManagement{
    try {
        # Query installed drivers (with digital signatures) and select details for display.
        $driverList = Get-WmiObject -Class Win32_PnPSignedDriver |
        Select-Object DeviceName, Manufacturer, DriverVersion, InfName |
        Sort-Object DeviceName

        # Display the list and let the user select driver(s) interactively using Out-GridView.
        $selectedDrivers = $driverList | Out-GridView -Title "Select driver(s) to uninstall" -PassThru

        # Check if any drivers were selected.
        if ($selectedDrivers) {
            foreach ($driver in $selectedDrivers) {
                $infFile = $driver.InfName
                if ($infFile) {
                    Write-Output "Attempting to uninstall driver for '$($driver.DeviceName)' using INF file: $infFile"
                    # Uninstall the driver package using pnputil.
                    # The /delete-driver switch removes the package, and /uninstall removes any associated devices (as applicable).
                    $uninstallResult = pnputil.exe /delete-driver $infFile /uninstall /force

                    # Output the result of the uninstallation.
                    Write-Output $uninstallResult
                }
                else {
                    Write-Warning "No INF file found for device '$($driver.DeviceName)'. Skipping uninstall."
                }
            }
        }
        else {
            Write-Output "No drivers were selected for uninstallation."
        }

    }
    catch {
        <#Do this if a terminating exception happens#>
        Write-Error "An error occurred while retrieving Drivers report : $_"
    }
}


# Function to scan a specific drive for bad sectors using CHKDSK.
function Get-BadSectorReport {
    [CmdletBinding()]
    param (
        # Provide a single drive letter (A-Z) without a colon.
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^[A-Za-z]$")]
        [string]$DriveLetter
    )

    $drive = "${DriveLetter}:"
    Write-Output "Scanning drive $drive for bad sectors..."

    try {
        # Run CHKDSK on the drive and capture stdout and stderr.
        $chkdskOutput = chkdsk $drive 2>&1
    }
    catch {
        Write-Warning "Error running CHKDSK on drive ${drive}: $_"
        return
    }

    # Define a regular expression to search for a line mentioning the number of bad sectors.
    $badSectorRegex = '(?<count>\d+)\s+bad sector'
    $match = $chkdskOutput | Select-String -Pattern $badSectorRegex

    if ($match) {
        $badSectorCount = $match.Matches[0].Groups["count"].Value
    }
    elseif ($chkdskOutput -match "found no problems" -or $chkdskOutput -match "No bad sectors") {
        # If the output notes that no problems were found, assume 0 bad sectors.
        $badSectorCount = 0
    }
    else {
        $badSectorCount = "N/A (Unable to parse output)"
    }

    # Return a PSCustomObject with a summary and the full CHKDSK report (if needed).
    [PSCustomObject]@{
        Drive      = $drive
        BadSectors = $badSectorCount
        FullReport = $chkdskOutput -join "`n"
    }
}

# Function to iterate over all fixed drives and run Get-BadSectorReport.
function TryAllBadSectorReports {
    # Get all fixed drives (DriveType=3) using CIM.
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3"
    
    $results = foreach ($drive in $drives) {
        # Remove the colon from DeviceID (e.g., "C:" becomes "C")
        $driveLetter = $drive.DeviceID.TrimEnd(":")
        Get-BadSectorReport -DriveLetter $driveLetter
    }
    
    return $results
}

# ---------------------------
# Main loop to interact with the user
# ---------------------------
do {
    Show-Menu
    $choice = Read-Host "Enter your selection (0-8)"

    switch ($choice) {
        '1' {
            Write-Host "Creating Startup entry for clear temp file everyday..." -ForegroundColor White
            Create-ClearTempTask
        }
        '2' {
            Write-Host "Creating Report for Daily Critical System Event Logs..." -ForegroundColor White
            # Place your logic for generating the Critical System Event Logs report here
            Critical-SystemEventTask
        }
        '3' {
            Write-Host "Creating Report for Daily Error Application Event Logs..." -ForegroundColor White
            # Place your logic for generating the Error Application Event Logs report here
            Error-ApplicationEventTask
        }
        '4' {
            Write-Host "Check Disk Storage Space..." -ForegroundColor White
            # Place your logic for generating the Error Application Event Logs report here
            TryDiskUsageOfDevice
        }
        '5' {
            Write-Host "Check Security Service health status..." -ForegroundColor White
            # Place your logic for generating the Error Application Event Logs report here
            TryServiceHealthService
        }
        '6' {
            Write-Host "Check Network Connectivity..." -ForegroundColor White
            # Place your logic for generating the Error Application Event Logs report here
            TryNetworkService
        }
        '7' {
            Write-Host "Check WiFi Connectivity..." -ForegroundColor White
            # Place your logic for generating the Error Application Event Logs report here
            TryWifiSignalStrength
        }
        '8' {
            Write-Host "Check Drivers for uninstallation..." -ForegroundColor White
            # Place your logic for generating the Error Application Event Logs report here
            tryDriverManagement
        }
        '9' {
            Write-Host "Checking drives for Bad Sectors..." -ForegroundColor White
            # Place your logic for generating the Error Application Event Logs report here
            TryAllBadSectorReports
        }
        '0' {
            Write-Host "Exiting application..." -ForegroundColor Yellow
        }
        Default {
            Write-Host "Invalid selection. Please choose option 0 through 8." -ForegroundColor Magenta
        }
    }
    if ($choice -ne '0') {
        Write-Host ""
        Write-Host "Press any key to continue..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
} while ($choice -ne '0')
