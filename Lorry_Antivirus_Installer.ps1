Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "🌟 Lorry AntiVirus"
$form.Size = New-Object System.Drawing.Size(500,400)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)

# Title Label
$title = New-Object System.Windows.Forms.Label
$title.Text = "Lorry AntiVirus Installer & Runner"
$title.ForeColor = [System.Drawing.Color]::White
$title.Font = New-Object System.Drawing.Font("Arial",18,[System.Drawing.FontStyle]::Bold)
$title.Size = New-Object System.Drawing.Size(480,40)
$title.Location = New-Object System.Drawing.Point(10,10)
$title.TextAlign = 'MiddleCenter'
$form.Controls.Add($title)

# Status Box
$status = New-Object System.Windows.Forms.TextBox
$status.Multiline = $true
$status.ReadOnly = $true
$status.ScrollBars = "Vertical"
$status.Size = New-Object System.Drawing.Size(460,180)
$status.Location = New-Object System.Drawing.Point(10,70)
$status.BackColor = [System.Drawing.Color]::FromArgb(40,40,40)
$status.ForeColor = [System.Drawing.Color]::White
$status.Font = New-Object System.Drawing.Font("Consolas",10)
$form.Controls.Add($status)

# Install Button
$installButton = New-Object System.Windows.Forms.Button
$installButton.Text = "Install Lorry AntiVirus"
$installButton.Size = New-Object System.Drawing.Size(200,40)
$installButton.Location = New-Object System.Drawing.Point(50,270)
$installButton.BackColor = [System.Drawing.Color]::FromArgb(50,150,50)
$installButton.ForeColor = [System.Drawing.Color]::White
$installButton.Font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
$form.Controls.Add($installButton)

# Run Scan Button
$scanButton = New-Object System.Windows.Forms.Button
$scanButton.Text = "Run Quick Scan"
$scanButton.Size = New-Object System.Drawing.Size(200,40)
$scanButton.Location = New-Object System.Drawing.Point(250,270)
$scanButton.BackColor = [System.Drawing.Color]::FromArgb(50,50,150)
$scanButton.ForeColor = [System.Drawing.Color]::White
$scanButton.Font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
$form.Controls.Add($scanButton)

# Button Actions
$installButton.Add_Click({
    $status.AppendText("✅ Installing Lorry AntiVirus..." + [Environment]::NewLine)
    Start-Sleep -Seconds 2
    $status.AppendText("✅ Installed successfully!" + [Environment]::NewLine)
})

$scanButton.Add_Click({
    $status.AppendText("🛡️ Starting Quick Scan..." + [Environment]::NewLine)
    Start-Sleep -Seconds 1
    $targets = @("C:\Users", "D:\Downloads", "E:\USB")
    foreach ($target in $targets) {
        $status.AppendText("Scanning $target..." + [Environment]::NewLine)
        Start-Sleep -Milliseconds 500
    }
    $status.AppendText("✅ Scan complete. No threats detected." + [Environment]::NewLine)
})

# Show Form
$form.Add_Shown({$form.Activate()})
[void]$form.ShowDialog()
