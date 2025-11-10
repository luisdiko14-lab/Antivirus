<#
Lorry AntiVirus - Single-file PowerShell GUI prototype (updated)
Features added:
 - Auto-elevate to Administrator if not running elevated
 - First-Run Setup wizard to select watch folders and suspicious extensions (or "Any file")
 - Creates License.txt under ProgramData\LorryAV
 - All previous features retained (scan, watcher, quarantine, service install, logs, signature DB)
Save as: LorryAV.ps1
Run as Administrator (script will re-launch elevated automatically if needed).
#>

# ---------- Auto-elevate to admin if required ----------
function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    # Relaunch script as admin
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
    if (-not $psi.FileName) { $psi.FileName = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source }
    if (-not $psi.FileName) { $psi.FileName = "powershell.exe" }
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    $psi.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        exit
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Administrator privileges are required. Exiting.","LorryAV","OK","Error") | Out-Null
        exit 1
    }
}

# --- Configuration ---
$AppName = "Lorry AntiVirus"
$ServiceName = "LorryAntiVirus"
$BaseFolder = "$env:ProgramData\LorryAV"
$QuarantineFolder = Join-Path $BaseFolder "Quarantine"
$LogFile = Join-Path $BaseFolder "logs.txt"
$SigsFile = Join-Path $BaseFolder "signatures.txt"
$ServiceScript = Join-Path $BaseFolder "lorry_service.ps1"
$SetupFlag = Join-Path $BaseFolder "setup_done.flag"
$SetupConfigFile = Join-Path $BaseFolder "setup_config.json"

# Default suspicious extensions (modifiable during setup)
$DefaultExtensions = @(".ps1", ".bat", ".cmd", ".exe", ".vbs", ".js", ".scr")

# ---------- Helpers ----------
function Init-Folders {
    New-Item -Path $BaseFolder -ItemType Directory -Force | Out-Null
    New-Item -Path $QuarantineFolder -ItemType Directory -Force | Out-Null
    if (-not (Test-Path $SigsFile)) { "" | Out-File -FilePath $SigsFile -Encoding utf8 }
    if (-not (Test-Path $LogFile)) { "" | Out-File -FilePath $LogFile -Encoding utf8 }
}

function Log-Message { param($msg) $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); "$ts `t $msg" | Out-File -FilePath $LogFile -Append -Encoding utf8 }

function Load-Signatures { if (Test-Path $SigsFile) { Get-Content -Path $SigsFile -ErrorAction SilentlyContinue | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { $_.Trim().ToLower() } } else { @() } }
function Save-Signatures { param([string[]]$hashes) $hashes | Sort-Object -Unique | Out-File -FilePath $SigsFile -Encoding utf8; Log-Message "Signature DB updated. Count: $($hashes.Count)" }

function Quarantine-File { param($filePath) try { $name = [System.IO.Path]::GetFileName($filePath); $dest = Join-Path $QuarantineFolder ("{0}_{1}" -f (Get-Random -Maximum 99999), $name); Move-Item -Path $filePath -Destination $dest -Force; Log-Message "Quarantined: $filePath -> $dest"; return $dest } catch { Log-Message "Quarantine failed: $filePath - $_"; return $null } }

function Get-FileSHA256 { param($path) try { (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { Log-Message "Hash failed for $path - $_"; return $null } }

function Scan-File {
    param($filePath, $signatures, $suspiciousExts, $anyFile)
    $res = [pscustomobject]@{ Path = $filePath; Status = "Clean"; Reason = ""; Hash = "" }
    if (-not (Test-Path $filePath)) { $res.Status = "Missing"; $res.Reason = "File not found"; return $res }
    $hash = Get-FileSHA256 -path $filePath
    $res.Hash = $hash
    if ($hash -and $signatures -contains $hash) { $res.Status = "Infected"; $res.Reason = "Hash match"; return $res }
    if ($anyFile) {
        $res.Status = "Suspicious"
        $res.Reason = "Any-file mode enabled (manual review recommended)"
        return $res
    }
    $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
    if ($suspiciousExts -contains $ext) {
        $res.Status = "Suspicious"
        $res.Reason = "Suspicious extension ($ext)"
        return $res
    }
    return $res
}

function Scan-Path {
    param($path, $signatures, $suspiciousExts, $anyFile, [switch]$ShowProgress)
    $results = @()
    try {
        $items = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
        $count = $items.Count
        $i = 0
        foreach ($f in $items) {
            $i++
            if ($ShowProgress) {
                Write-Progress -Activity "Scanning" -Status "$i / $count : $($f.FullName)" -PercentComplete ([math]::Round($i / $count * 100))
            }
            $r = Scan-File -filePath $f.FullName -signatures $signatures -suspiciousExts $suspiciousExts -anyFile:$anyFile
            $results += $r
        }
        Write-Progress -Activity "Scanning" -Completed
    } catch { Log-Message "Scan-Path error: $_" }
    return $results
}

# Real-time watcher management (unchanged, uses configured extensions/anyFile)
$Global:FileWatchers = @()
function Start-WatchPaths {
    param([string[]]$paths, $signatures, $suspiciousExts, $autoQuarantine, $anyFile)
    Stop-WatchPaths
    foreach ($p in $paths) {
        if (-not (Test-Path $p)) { continue }
        $fsw = New-Object System.IO.FileSystemWatcher $p -Property @{
            IncludeSubdirectories = $true
            NotifyFilter = [System.IO.NotifyFilters]'FileName, LastWrite, CreationTime'
            Filter = '*.*'
        }
        $action = {
            param($s, $e)
            Start-Sleep -Milliseconds 300
            try {
                $file = $e.FullPath
                if (-not (Test-Path $file)) { return }
                $r = Scan-File -filePath $file -signatures $using:signatures -suspiciousExts $using:suspiciousExts -anyFile:$using:anyFile
                if ($r.Status -in @("Infected","Suspicious")) {
                    Log-Message "Realtime flagged: $($r.Path) -> $($r.Reason)"
                    if ($using:autoQuarantine) {
                        Quarantine-File -filePath $file | Out-Null
                    } else {
                        [System.Windows.Forms.MessageBox]::Show("$($r.Path)`nStatus: $($r.Status)`nReason: $($r.Reason)", "LorryAV - Realtime alert", 'OK', 'Warning') | Out-Null
                    }
                }
            } catch { Log-Message "Watcher error: $_" }
        }
        $created = Register-ObjectEvent -InputObject $fsw -EventName Created -SourceIdentifier "LorryAVCreated_$([guid]::NewGuid())" -Action $action
        $changed = Register-ObjectEvent -InputObject $fsw -EventName Changed -SourceIdentifier "LorryAVChanged_$([guid]::NewGuid())" -Action $action
        $fsw.EnableRaisingEvents = $true
        $Global:FileWatchers += @{watcher=$fsw; createdEvent=$created; changedEvent=$changed}
    }
    Log-Message "Real-time watcher started on paths: $($paths -join ', ')"
}

function Stop-WatchPaths {
    foreach ($item in $Global:FileWatchers) {
        try {
            $item.watcher.EnableRaisingEvents = $false
            Unregister-Event -SourceIdentifier $item.createdEvent.Name -Force -ErrorAction SilentlyContinue
            Unregister-Event -SourceIdentifier $item.changedEvent.Name -Force -ErrorAction SilentlyContinue
            $item.watcher.Dispose()
        } catch { }
    }
    $Global:FileWatchers = @()
    Log-Message "Real-time watcher stopped."
}

# Create service script and install/uninstall functions (unchanged logic but service will respect setup config)
function Create-ServiceScript {
    param($paths, $sigsFile, $quarantine, $suspiciousExts, $anyFile)
    $code = @"
# LorryAV background service runner
`$SigsFile = '$sigsFile'
`$QuarantineFolder = '$quarantine'
`$paths = @(
"@
    foreach ($p in $paths) { $code += "    `"$p`"`n" }
    $code += @"
)
function Get-FileSHA256 { param(`$p) try { (Get-FileHash -Path `$p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { return `$null } }
function Load-Sigs { if (Test-Path `$SigsFile) { Get-Content `$SigsFile | Where-Object {`$_ -and `$_.Trim() -ne "" } | ForEach-Object { `$_.Trim().ToLower() } } else { @() } }
function Quarantine-File { param(`$f) try { `$dest = Join-Path `$QuarantineFolder ("{0}_{1}" -f (Get-Random -Maximum 99999), (Get-Item `$f).Name); Move-Item -Path `$f -Destination `$dest -Force; } catch {} }
`$sigs = Load-Sigs
`$suspicious = @(
"@
    foreach ($ext in $suspiciousExts) { $code += "    `"$ext`"`n" }
    $code += @"
)
`$anyFile = $($anyFile.ToString().ToLower())
foreach (`$p in `$paths) {
    if (-not (Test-Path `$p)) { continue }
    `$fsw = New-Object System.IO.FileSystemWatcher `$p -Property @{ IncludeSubdirectories = $true; NotifyFilter = [System.IO.NotifyFilters]'FileName, LastWrite, CreationTime'; Filter='*.*' }
    Register-ObjectEvent -InputObject `$fsw -EventName Created -Action {
        Start-Sleep -Milliseconds 500
        param(`$s, `$e)
        if (-not (Test-Path `$e.FullPath)) { return }
        `$h = Get-FileSHA256 -p `$e.FullPath
        if (`$h -and `$sigs -contains `$h) { Quarantine-File -f `$e.FullPath; return }
        if (`$anyFile) { Quarantine-File -f `$e.FullPath; return }
        `$ext = [System.IO.Path]::GetExtension(`$e.FullPath).ToLower()
        if (`$suspicious -contains `$ext) { Quarantine-File -f `$e.FullPath; return }
    } | Out-Null
    `$fsw.EnableRaisingEvents = $true
}
while ($true) { Start-Sleep -Seconds 30 }
"@
    $code | Out-File -FilePath $ServiceScript -Encoding utf8 -Force
    Log-Message "Service script created at $ServiceScript"
}

function Install-Service {
    param([string[]]$pathsToWatch, $suspiciousExts, $anyFile)
    try {
        Create-ServiceScript -paths $pathsToWatch -sigsFile $SigsFile -quarantine $QuarantineFolder -suspiciousExts $suspiciousExts -anyFile $anyFile
        $pwsh = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
        if (-not $pwsh) { $pwsh = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" }
        $bin = "`"$pwsh`" -NoProfile -ExecutionPolicy Bypass -File `"$ServiceScript`""
        sc.exe create $ServiceName binPath= "$bin" start= auto DisplayName= "Lorry AntiVirus Service" | Out-Null
        Start-Sleep -Milliseconds 400
        sc.exe description $ServiceName "Background Lorry AntiVirus service (watcher)." | Out-Null
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Log-Message "Service installed and started: $ServiceName"
        return $true
    } catch { Log-Message "Install-Service failed: $_"; return $false }
}

function Uninstall-Service {
    try {
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        }
        sc.exe delete $ServiceName | Out-Null
        Remove-Item -Path $ServiceScript -Force -ErrorAction SilentlyContinue
        Log-Message "Service uninstalled: $ServiceName"
        return $true
    } catch { Log-Message "Uninstall-Service failed: $_"; return $false }
}

# ---------- First-Run Setup ----------
function Create-LicenseFile {
    $license = @"
Lorry AntiVirus - License
-------------------------
This software is provided "as-is" for personal/authorized use and educational purposes.
The author is not responsible for damages, data loss or other consequences from use.
You must run this on machines you own or are authorized to administer.

Permissions:
 - Use, modify and redistribute this script with attribution.
 - Do not use for unauthorized access or malicious activity.

"@
    $license | Out-File -FilePath (Join-Path $BaseFolder "License.txt") -Encoding utf8 -Force
    Log-Message "License.txt created."
}

function Run-FirstRunSetup {
    Init-Folders
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $f = New-Object System.Windows.Forms.Form
    $f.Text = "LorryAV - First Run Setup"
    $f.StartPosition = "CenterScreen"
    $f.Width = 640; $f.Height = 520; $f.Font = New-Object System.Drawing.Font("Segoe UI",10)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "Welcome to Lorry AntiVirus setup. Choose folders to watch and which file types to treat as suspicious."
    $lbl.SetBounds(10,10,600,40)
    $f.Controls.Add($lbl)

    $lbl2 = New-Object System.Windows.Forms.Label; $lbl2.Text = "Folders to watch (you can add multiple):"; $lbl2.SetBounds(10,60,400,20); $f.Controls.Add($lbl2)
    $lbFolders = New-Object System.Windows.Forms.ListBox; $lbFolders.SetBounds(10,85,470,120); $f.Controls.Add($lbFolders)
    $btnAddFolder = New-Object System.Windows.Forms.Button; $btnAddFolder.Text = "Add Folder"; $btnAddFolder.SetBounds(490,85,120,30)
    $btnAddFolder.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($dlg.ShowDialog() -eq "OK") { $lbFolders.Items.Add($dlg.SelectedPath) | Out-Null }
    })
    $f.Controls.Add($btnAddFolder)
    $btnRemoveFolder = New-Object System.Windows.Forms.Button; $btnRemoveFolder.Text = "Remove Selected"; $btnRemoveFolder.SetBounds(490,125,120,30)
    $btnRemoveFolder.Add_Click({ if ($lbFolders.SelectedIndex -ge 0) { $lbFolders.Items.RemoveAt($lbFolders.SelectedIndex) } })
    $f.Controls.Add($btnRemoveFolder)

    # Prepopulate with Desktop, Documents, Downloads
    $lbFolders.Items.Add([Environment]::GetFolderPath("Desktop")) | Out-Null
    $lbFolders.Items.Add([Environment]::GetFolderPath("MyDocuments")) | Out-Null
    $lbFolders.Items.Add(Join-Path $env:USERPROFILE "Downloads") | Out-Null

    $lbl3 = New-Object System.Windows.Forms.Label; $lbl3.Text = "Suspicious file extensions (one per line). Use format: .ext. Use ANY to treat every file as suspicious."; $lbl3.SetBounds(10,220,600,30); $f.Controls.Add($lbl3)
    $tbExt = New-Object System.Windows.Forms.TextBox; $tbExt.Multiline = $true; $tbExt.ScrollBars = "Both"; $tbExt.SetBounds(10,255,470,150); $f.Controls.Add($tbExt)
    $tbExt.Text = ($DefaultExtensions -join "`r`n")

    $cbAny = New-Object System.Windows.Forms.CheckBox; $cbAny.Text = "Treat ANY file as suspicious (override extensions)"; $cbAny.SetBounds(10,415,450,24); $f.Controls.Add($cbAny)

    $btnFinish = New-Object System.Windows.Forms.Button; $btnFinish.Text = "Finish Setup"; $btnFinish.SetBounds(480,430,130,36)
    $btnFinish.Add_Click({
        if ($lbFolders.Items.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("Please add at least one folder to watch.","LorryAV") | Out-Null; return }
        $folders = @()
        foreach ($i in $lbFolders.Items) { $folders += $i }
        $any = $cbAny.Checked
        $exts = @()
        if (-not $any) {
            $lines = $tbExt.Lines | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne "" }
            foreach ($l in $lines) {
                if ($l -eq "any") { $any = $true; break }
                if ($l -notmatch '^\.\w+') { continue }
                $exts += $l
            }
            if ($exts.Count -eq 0 -and -not $any) {
                [System.Windows.Forms.MessageBox]::Show("No valid extensions detected. Use format: .exe or enable ANY mode.","LorryAV") | Out-Null
                return
            }
        }
        # Save setup config
        $cfg = @{ folders = $folders; suspiciousExts = $exts; anyFile = $any }
        $cfg | ConvertTo-Json -Depth 5 | Out-File -FilePath $SetupConfigFile -Encoding utf8 -Force
        New-Item -Path $SetupFlag -ItemType File -Force | Out-Null
        Create-LicenseFile
        [System.Windows.Forms.MessageBox]::Show("Setup complete. You can start the app now.","LorryAV") | Out-Null
        $f.Close()
    })
    $f.Controls.Add($btnFinish)
    $f.ShowDialog()
}

# ---------- Initialization ----------
Init-Folders

# Run first-run setup if not done
if (-not (Test-Path $SetupFlag)) {
    Run-FirstRunSetup
}

# Load setup config (or defaults)
$suspiciousExts = $DefaultExtensions
$anyFile = $false
$watchPaths = @()
if (Test-Path $SetupConfigFile) {
    try {
        $cfg = Get-Content $SetupConfigFile -Raw | ConvertFrom-Json
        if ($cfg.suspiciousExts) { $suspiciousExts = $cfg.suspiciousExts }
        if ($cfg.anyFile) { $anyFile = $cfg.anyFile }
        if ($cfg.folders) { $watchPaths = $cfg.folders }
    } catch { Log-Message "Failed to load setup config: $_" }
} else {
    # defaults
    $watchPaths += [Environment]::GetFolderPath("Desktop")
    $watchPaths += [Environment]::GetFolderPath("MyDocuments")
    $watchPaths += Join-Path $env:USERPROFILE "Downloads"
}

# ---------- GUI (Windows Forms) ----------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Width = 860
$form.Height = 560
$form.Text = $AppName
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI",10)

# Left panel with buttons (most buttons updated to honor config)
$panelLeft = New-Object System.Windows.Forms.Panel
$panelLeft.SetBounds(8,8,280,520)
$panelLeft.AutoScroll = $true
$form.Controls.Add($panelLeft)

$y = 10
function add-button($text, $action) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $text; $btn.Width = 250; $btn.Height = 36
    $btn.Location = New-Object System.Drawing.Point(10,$GLOBALS:y)
    $btn.Add_Click($action)
    $panelLeft.Controls.Add($btn)
    $GLOBALS:y += 44
}

add-button "Scan Now (Choose folder)" {
    $folderDlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDlg.Description = "Select a folder to scan (recursively)."
    if ($folderDlg.ShowDialog() -eq "OK") {
        $sig = Load-Signatures
        $results = Scan-Path -path $folderDlg.SelectedPath -signatures $sig -suspiciousExts $suspiciousExts -anyFile:$anyFile -ShowProgress
        $infected = $results | Where-Object { $_.Status -in @("Infected","Suspicious") }
        if ($infected.Count -gt 0) {
            $msg = "Found $($infected.Count) flagged items. Quarantine them?"
            $res = [System.Windows.Forms.MessageBox]::Show($msg,"Scan results",[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Question)
            if ($res -eq "Yes") {
                foreach ($i in $infected) { try { Quarantine-File -filePath $i.Path | Out-Null } catch {} }
                [System.Windows.Forms.MessageBox]::Show("Quarantine complete.","LorryAV")
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Scan complete. No flagged items found.","LorryAV")
        }
    }
}

add-button "Start Real-time Watcher" {
    $sig = Load-Signatures
    Start-WatchPaths -paths $watchPaths -signatures $sig -suspiciousExts $suspiciousExts -autoQuarantine:$false -anyFile:$anyFile
    [System.Windows.Forms.MessageBox]::Show("Realtime watcher started on: `n$($watchPaths -join "`n")","LorryAV")
}

add-button "Stop Real-time Watcher" {
    Stop-WatchPaths
    [System.Windows.Forms.MessageBox]::Show("Realtime watcher stopped.","LorryAV")
}

add-button "Install Windows Service (LorryAntiVirus)" {
    $ok = Install-Service -pathsToWatch $watchPaths -suspiciousExts $suspiciousExts -anyFile $anyFile
    if ($ok) { [System.Windows.Forms.MessageBox]::Show("Service installed and started.","LorryAV") } else { [System.Windows.Forms.MessageBox]::Show("Service install failed. Check logs.","LorryAV") }
}

add-button "Uninstall Windows Service" {
    $ok = Uninstall-Service
    if ($ok) { [System.Windows.Forms.MessageBox]::Show("Service removed.","LorryAV") } else { [System.Windows.Forms.MessageBox]::Show("Service uninstall may have failed. Check logs.","LorryAV") }
}

add-button "View Logs" { if (Test-Path $LogFile) { notepad $LogFile } else { [System.Windows.Forms.MessageBox]::Show("No logs yet.","LorryAV") } }
add-button "Open Quarantine Folder" { ii $QuarantineFolder }
add-button "Open License.txt" { ii (Join-Path $BaseFolder "License.txt") }
add-button "Re-run Setup" {
    Run-FirstRunSetup
    # reload config
    if (Test-Path $SetupConfigFile) {
        $cfg = Get-Content $SetupConfigFile -Raw | ConvertFrom-Json
        $suspiciousExts = $cfg.suspiciousExts
        $anyFile = $cfg.anyFile
        $watchPaths = $cfg.folders
        [System.Windows.Forms.MessageBox]::Show("Setup reloaded.","LorryAV")
    }
}

add-button "Export Signature DB" {
    $save = New-Object System.Windows.Forms.SaveFileDialog
    $save.FileName = "lorry_signatures.txt"
    if ($save.ShowDialog() -eq "OK") {
        Copy-Item -Path $SigsFile -Destination $save.FileName -Force
        [System.Windows.Forms.MessageBox]::Show("Exported signatures.","LorryAV")
    }
}

add-button "Import Signatures (paste text)" {
    $form2 = New-Object System.Windows.Forms.Form; $form2.Text = "Paste SHA256 signatures (one per line)"; $form2.Width = 600; $form2.Height = 420; $form2.StartPosition = "CenterParent"
    $tb = New-Object System.Windows.Forms.TextBox; $tb.Multiline = $true; $tb.ScrollBars = "Both"; $tb.Dock = "Top"; $tb.Height = 320
    $btnOk = New-Object System.Windows.Forms.Button; $btnOk.Text = "Import"; $btnOk.Dock="Bottom"
    $btnOk.Add_Click({
        $lines = $tb.Lines | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -match '^[a-f0-9]{64}$' }
        if ($lines.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No valid SHA256 hashes detected. Each line should be a 64-char hex SHA256.","LorryAV") } else { Save-Signatures -hashes $lines; [System.Windows.Forms.MessageBox]::Show("Imported $($lines.Count) signatures.","LorryAV"); $form2.Close() }
    })
    $form2.Controls.Add($tb); $form2.Controls.Add($btnOk); $form2.ShowDialog()
}

add-button "Add Current File Hash to Signatures" {
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    if ($ofd.ShowDialog() -eq "OK") {
        $h = Get-FileSHA256 -path $ofd.FileName
        if ($h) {
            $sigs = Load-Signatures
            $sigs += $h
            Save-Signatures -hashes $sigs
            [System.Windows.Forms.MessageBox]::Show("Added signature: $h","LorryAV")
        } else { [System.Windows.Forms.MessageBox]::Show("Could not compute hash for file.","LorryAV") }
    }
}

add-button "Open Signature DB (edit)" { if (-not (Test-Path $SigsFile)) { "" | Out-File $SigsFile -Encoding utf8 }; notepad $SigsFile }
add-button "Export Logs (Save As)" {
    $save = New-Object System.Windows.Forms.SaveFileDialog; $save.FileName = "lorry_logs.txt"
    if ($save.ShowDialog() -eq "OK") { Copy-Item -Path $LogFile -Destination $save.FileName -Force; [System.Windows.Forms.MessageBox]::Show("Logs exported.","LorryAV") }
}

# Right area: status & info
$panelRight = New-Object System.Windows.Forms.Panel
$panelRight.SetBounds(300,8,540,520)
$form.Controls.Add($panelRight)

$lbl = New-Object System.Windows.Forms.Label
$lbl.Text = "Status & Quick Actions"
$lbl.Font = New-Object System.Drawing.Font("Segoe UI",12,[System.Drawing.FontStyle]::Bold)
$lbl.Location = New-Object System.Drawing.Point(8,8)
$lbl.AutoSize = $true
$panelRight.Controls.Add($lbl)

$infoBox = New-Object System.Windows.Forms.TextBox
$infoBox.Multiline = $true
$infoBox.SetBounds(8,40,520,420)
$infoBox.ReadOnly = $true
$infoBox.ScrollBars = "Vertical"
$panelRight.Controls.Add($infoBox)

function Refresh-Info {
    $sigCount = (Load-Signatures).Count
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $svcStatus = if ($service) { $service.Status } else { "Not Installed" }
    $watching = if ($Global:FileWatchers.Count -gt 0) { "Running" } else { "Stopped" }
    $quCount = (Get-ChildItem -Path $QuarantineFolder -File -ErrorAction SilentlyContinue).Count
    $lines = @()
    $lines += "App: $AppName"
    $lines += "Signatures: $sigCount"
    $lines += "Service ($ServiceName): $svcStatus"
    $lines += "Realtime watcher: $watching"
    $lines += "Quarantine items: $quCount"
    $lines += "Configured watch paths:"
    foreach ($p in $watchPaths) { $lines += " - $p" }
    $lines += "Suspicious extensions: " + (if ($anyFile) { "ANY (all files)" } else { ($suspiciousExts -join ", ") })
    $lines += ""
    $lines += "Log file: $LogFile"
    $lines += ""
    $lines += "Recent log (last 20 lines):"
    if (Test-Path $LogFile) { $lines += (Get-Content $LogFile -Tail 20 -ErrorAction SilentlyContinue) } else { $lines += "No logs yet." }
    $infoBox.Lines = $lines
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 3000
$timer.Add_Tick({ Refresh-Info })
$timer.Start()

Refresh-Info
$form.Add_Shown({ $form.Activate() })
[void] $form.ShowDialog()

# Cleanup
Stop-WatchPaths
# End of script
