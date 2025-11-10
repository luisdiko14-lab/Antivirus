<#
Lorry AntiVirus Setup + GUI
-----------------------------------------
Creates service, folders, and License.txt
Then launches the main antivirus GUI.
Run as Administrator.
#>

# === Force Admin Privileges ===
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Restarting with administrator privileges..."
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# === Paths ===
$AppName = "Lorry AntiVirus"
$Base = "$env:ProgramData\LorryAV"
$MainScript = Join-Path $Base "LorryAV.ps1"
$LicenseFile = Join-Path $Base "License.txt"

# === Setup Directories ===
Write-Host "Setting up Lorry AntiVirus..." -ForegroundColor Cyan
New-Item -Path $Base -ItemType Directory -Force | Out-Null

# === License ===
if (-not (Test-Path $LicenseFile)) {
@"
Lorry AntiVirus - License
--------------------------
This software is provided "as is" without any warranty.
Use at your own risk.
Created by Luis & ChatGPT.
(c) 2025 LorryAV Team. All Rights Reserved.

You are allowed to use, modify, and share this script
for educational and personal security purposes.
"@ | Out-File $LicenseFile -Encoding utf8
}

# === Write Main Antivirus GUI Script ===
@"
# --- Lorry AntiVirus GUI ---
# Simplified, local-only version
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

\$BaseFolder = "$Base"
\$Quarantine = Join-Path \$BaseFolder "Quarantine"
\$Logs = Join-Path \$BaseFolder "logs.txt"
New-Item -Path \$BaseFolder -ItemType Directory -Force | Out-Null
New-Item -Path \$Quarantine -ItemType Directory -Force | Out-Null

function Log(\$m) {
    "\$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  \$m" | Out-File \$Logs -Append -Encoding utf8
}

function HashFile(\$p) {
    try { (Get-FileHash -Path \$p -Algorithm SHA256).Hash } catch { return \$null }
}

function ScanFolder(\$path) {
    \$infected = 0
    \$files = Get-ChildItem -Path \$path -Recurse -File -ErrorAction SilentlyContinue
    foreach (\$f in \$files) {
        \$ext = [IO.Path]::GetExtension(\$f.FullName)
        if (\$ext -in '.exe','.bat','.ps1','.vbs','.scr','.js') {
            \$infected++
            Move-Item \$f.FullName -Destination (Join-Path \$Quarantine \$f.Name) -Force
            Log "Quarantined: \$f"
        }
    }
    [System.Windows.Forms.MessageBox]::Show("Scan complete. Quarantined \$infected suspicious files.","LorryAV")
}

# GUI
\$form = New-Object System.Windows.Forms.Form
\$form.Text = "$AppName"
\$form.Size = New-Object System.Drawing.Size(600,400)
\$form.StartPosition = 'CenterScreen'
\$form.Font = New-Object System.Drawing.Font('Segoe UI',10)

\$btnScan = New-Object System.Windows.Forms.Button
\$btnScan.Text = "Scan Folder"
\$btnScan.Size = New-Object System.Drawing.Size(200,40)
\$btnScan.Location = New-Object System.Drawing.Point(30,40)
\$btnScan.Add_Click({
    \$dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    if (\$dlg.ShowDialog() -eq 'OK') { ScanFolder \$dlg.SelectedPath }
})
\$form.Controls.Add(\$btnScan)

\$btnQuar = New-Object System.Windows.Forms.Button
\$btnQuar.Text = "Open Quarantine"
\$btnQuar.Size = New-Object System.Drawing.Size(200,40)
\$btnQuar.Location = New-Object System.Drawing.Point(30,100)
\$btnQuar.Add_Click({ ii \$Quarantine })
\$form.Controls.Add(\$btnQuar)

\$btnLog = New-Object System.Windows.Forms.Button
\$btnLog.Text = "View Logs"
\$btnLog.Size = New-Object System.Drawing.Size(200,40)
\$btnLog.Location = New-Object System.Drawing.Point(30,160)
\$btnLog.Add_Click({ notepad \$Logs })
\$form.Controls.Add(\$btnLog)

\$btnLicense = New-Object System.Windows.Forms.Button
\$btnLicense.Text = "View License"
\$btnLicense.Size = New-Object System.Drawing.Size(200,40)
\$btnLicense.Location = New-Object System.Drawing.Point(30,220)
\$btnLicense.Add_Click({ notepad "$LicenseFile" })
\$form.Controls.Add(\$btnLicense)

\$lbl = New-Object System.Windows.Forms.Label
\$lbl.Text = "Lorry AntiVirus is running locally.`nReady to scan or quarantine suspicious files."
\$lbl.Location = New-Object System.Drawing.Point(260,40)
\$lbl.Size = New-Object System.Drawing.Size(300,100)
\$form.Controls.Add(\$lbl)

[void]\$form.ShowDialog()
"@ | Out-File $MainScript -Encoding utf8 -Force

# === Add file associations (.ps1, .bat, etc) ===
Write-Host "Associating .ps1, .bat, .cmd for scan context..." -ForegroundColor Yellow
$assocScript = @"
@echo off
setlocal
echo Adding context menu entries for LorryAV...
reg add "HKCR\*\shell\LorryAVScan" /ve /d "Scan with Lorry AntiVirus" /f
reg add "HKCR\*\shell\LorryAVScan\command" /ve /d "powershell.exe -ExecutionPolicy Bypass -File `"$MainScript`"" /f
echo Done.
"@
$assocFile = Join-Path $Base "add_context.bat"
$assocScript | Out-File $assocFile -Encoding ascii -Force
Start-Process cmd.exe "/c $assocFile" -Verb RunAs -WindowStyle Hidden

# === Launch Main GUI ===
Write-Host "Setup complete! Launching Lorry AntiVirus GUI..." -ForegroundColor Green
Start-Process powershell "-ExecutionPolicy Bypass -File `"$MainScript`""
