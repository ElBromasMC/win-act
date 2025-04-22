#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Requests a Windows activation key, attempts activation with retries, and reports the status back to the server.
.DESCRIPTION
This script contacts a central activation key server to get a unique key for this machine's serial number.
It then attempts to activate Windows 11 Home using slmgr.vbs, retrying up to a defined limit.
Finally, it reports whether the activation ultimately succeeded or failed back to the server.
.NOTES
- Requires PowerShell 5.1 or later.
- MUST be run as Administrator to execute slmgr.vbs.
- Ensure the server URL and API Key are correctly configured.
- Network connectivity to the server is required.
- Error handling for slmgr.vbs output parsing is crucial and might need adjustments based on specific OS language or error messages.
#>

# --- Configuration ---
$serverBaseUrl = "http://<your_server_ip>:5000" # CHANGE THIS
$apiKey = "YOUR_STRONG_SECRET_API_KEY"         # CHANGE THIS

$maxRetries = 3
$retryDelaySeconds = 15 # Wait between activation attempts

# --- Constants for Reporting ---
$statusActivated = "ACTIVATED"
$statusFailed = "FAILED"

# --- Helper Function for Reporting Status ---
Function Report-ActivationStatus {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [Parameter(Mandatory=$true)]
        [ValidateSet('ACTIVATED','FAILED')]
        [string]$Status,
        [Parameter(Mandatory=$true)]
        [string]$SerialNumber
    )

    $reportUrl = "$serverBaseUrl/report_status"
    $headers = @{
        "Authorization" = "Bearer $apiKey"
        "Content-Type"  = "application/json"
    }
    $body = @{
        key           = $Key
        status        = $Status
        serial_number = $SerialNumber
    } | ConvertTo-Json -Depth 3

    Write-Host "Reporting final status '$Status' for key '$Key' to server..."
    try {
        $response = Invoke-RestMethod -Uri $reportUrl -Method Post -Headers $headers -Body $body -TimeoutSec 30
        Write-Host "Server response: $($response | ConvertTo-Json -Depth 3)"
        # You might want to check the server response content here for confirmation
    } catch {
        Write-Warning "!!! FAILED to report status '$Status' for key '$Key' back to the server. Error: $($_.Exception.Message)"
        # Log the error, maybe store locally for later retry?
        if ($_.Exception.Response) {
            $stream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $errorBody = $reader.ReadToEnd()
            Write-Warning "Server Error Response Body: $errorBody"
        }
    }
}


# --- Main Script ---

Write-Host "Starting Windows Activation Process..."

# 1. Get Computer Serial Number
Write-Host "Retrieving computer serial number..."
try {
    $serialNumber = (Get-CimInstance Win32_BIOS).SerialNumber.Trim()
    if ([string]::IsNullOrWhiteSpace($serialNumber)) {
        Write-Error "Failed to retrieve a valid computer serial number. Cannot proceed."
        exit 1
    }
    Write-Host "Computer Serial Number: $serialNumber"
} catch {
    Write-Error "FATAL: Error getting serial number: $($_.Exception.Message)"
    exit 1
}

# 2. Request Activation Key from Server
$activateUrl = "$serverBaseUrl/activate"
$requestHeaders = @{
    "Authorization" = "Bearer $apiKey"
    "Content-Type"  = "application/json"
}
$requestBody = @{
    "serial_number" = $serialNumber
} | ConvertTo-Json

Write-Host "Requesting activation key from server: $activateUrl"
$activationKey = $null
try {
    $response = Invoke-RestMethod -Uri $activateUrl -Method Post -Headers $requestHeaders -Body $requestBody -TimeoutSec 30
    if ($response -and $response.activation_key) {
        $activationKey = $response.activation_key
        Write-Host "Successfully received activation key: $activationKey (Status: PENDING on server)"
    } else {
        Write-Error "Server did not return a valid activation key. Response: $($response | ConvertTo-Json -Depth 3)"
        exit 1 # Cannot proceed without a key
    }
} catch {
    Write-Error "FATAL: Error contacting activation server ($activateUrl): $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $errorBody = $reader.ReadToEnd()
        Write-Error "Server Response Body: $errorBody"
    }
    exit 1 # Cannot proceed
}

# 3. Attempt Activation with Retries
Write-Host "Attempting to install product key: $activationKey"
$activationSuccess = $false
$finalStatus = $statusFailed # Default to failed unless explicitly successful

# Use cscript for potentially better output capture/control
$slmgrPath = "$env:SystemRoot\System32\slmgr.vbs"
if (-not (Test-Path $slmgrPath)) {
     Write-Error "FATAL: slmgr.vbs not found at '$slmgrPath'. Cannot perform activation."
     # Try reporting failure immediately? Or just exit? Reporting failure seems reasonable.
     Report-ActivationStatus -Key $activationKey -Status $statusFailed -SerialNumber $serialNumber
     exit 1
}

try {
    # Install the key first
    # Using -Wait helps ensure the process completes before we check output/proceed
    $ipkArgs = "/ipk $activationKey"
    Write-Host "Running: cscript.exe //Nologo $slmgrPath $ipkArgs"
    $ipkResult = Start-Process cscript.exe -ArgumentList "//Nologo", $slmgrPath, $ipkArgs -Wait -NoNewWindow -PassThru
    # Check exit code, although slmgr often returns 0 even if the key is invalid
    if ($ipkResult.ExitCode -ne 0) {
         Write-Warning "slmgr.vbs /ipk command exited with non-zero code: $($ipkResult.ExitCode). Activation may fail."
         # Consider if this should immediately trigger failure report? Maybe not, /ato is the real test.
    } else {
         Write-Host "Product key installation command executed." # Add check for "installed successfully" message if needed
    }

    Start-Sleep -Seconds 5 # Give Windows a moment after key installation

    # Now attempt online activation (/ato) with retries
    Write-Host "Attempting online activation (up to $maxRetries times)..."
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        Write-Host "Activation attempt $attempt of $maxRetries..."
        $atoArgs = "/ato"
        # Capture output for analysis
        $outputFile = "$env:TEMP\slmgr_ato_output_$($PID)_$attempt.txt"
        Write-Host "Running: cscript.exe //Nologo $slmgrPath $atoArgs > `"$outputFile`""
        try {
            # Run /ato, but we won't primarily rely on its output for success detection
            $atoResult = Start-Process cscript.exe -ArgumentList "//Nologo", $slmgrPath, $atoArgs -RedirectStandardOutput $outputFile -Wait -NoNewWindow -PassThru
            Start-Sleep -Seconds 10

            # --- NEW: Check WMI for Activation Status ---
            Write-Host "Checking activation status via WMI..."
            # LicenseStatus = 1 means Licensed (Activated)
            $activationInfo = Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%' AND LicenseStatus = 1"

            if ($activationInfo) {
                Write-Host "SUCCESS: Windows activated successfully (verified via WMI) on attempt $attempt!" -ForegroundColor Green
                $activationSuccess = $true
                $finalStatus = $statusActivated
                if (Test-Path $outputFile) { Remove-Item $outputFile -ErrorAction SilentlyContinue } # Clean up log
                break # Exit the retry loop on success
            } else {
                Write-Warning "Activation not confirmed via WMI after attempt $attempt. Exit code from slmgr: $($atoResult.ExitCode)."
                # Log slmgr output for debugging failures
                if (Test-Path $outputFile) {
                    $outputContent = Get-Content $outputFile -Raw
                    Write-Host "--- slmgr.vbs /ato output (Attempt $attempt) ---"
                    Write-Host $outputContent
                    Write-Host "--- End slmgr.vbs output ---"
                    # You can still check for specific error codes here if needed
                    if ($outputContent -match "0xC004C003") { Write-Warning "Detected error 0xC004C003: Activation server determined the specified product key is blocked."}
                    if ($outputContent -match "0x8007007B") { Write-Warning "Detected error 0x8007007B: DNS name does not exist (check network/KMS settings if applicable)."}
                    # Don't remove the log file on failure until the end
                } else {
                    Write-Warning "Could not find slmgr output file '$outputFile' for attempt $attempt."
                }
            }
            # --- End of WMI Check ---

        } catch {
            Write-Warning "Error executing slmgr.vbs /ato on attempt $attempt: $($_.Exception.Message)"
            # Optionally log this error in more detail
        }

        if (-not $activationSuccess -and $attempt -lt $maxRetries) {
            Write-Host "Waiting $retryDelaySeconds seconds before next attempt..."
            Start-Sleep -Seconds $retryDelaySeconds
        }
    } # End of retry loop

     # Clean up the last output file if it exists
    if (Test-Path $outputFile) { Remove-Item $outputFile -ErrorAction SilentlyContinue }

} catch {
    # Catch errors related to running Start-Process or file operations
    Write-Error "FATAL: An unexpected error occurred during the slmgr.vbs execution process: $($_.Exception.Message)"
    # Report failure as the outcome is unknown/problematic
    $finalStatus = $statusFailed
}

# 4. Report Final Status Back to Server
if ($activationSuccess) {
    Write-Host "Activation process completed successfully."
} else {
    Write-Warning "Activation process failed after $maxRetries attempts."
}

# Always report the determined final status back
Report-ActivationStatus -Key $activationKey -Status $finalStatus -SerialNumber $serialNumber

Write-Host "Activation script finished."

# Optional: Exit with code 0 on success, 1 on failure?
if ($activationSuccess) { exit 0 } else { exit 1 }

