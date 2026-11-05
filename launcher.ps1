# One-click launcher for scanner.py (started by run_scan.bat).
# Shows a dialog for AWS profile, region and sign-in method, sets up the
# profile / runs "aws sso login" if needed, then runs the scan and opens the report.
# Only non-secret settings are remembered (launcher-settings.json); access keys
# are written straight to the AWS credentials file (never passed on a command line).

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$Here         = $PSScriptRoot
$SettingsFile = Join-Path $Here 'launcher-settings.json'
$ReportFile   = Join-Path $Here 'aws_security_report.html'
$JsonFile     = Join-Path $Here 'aws_security_findings.json'
$Title        = 'AWS S3 & IAM Security Checker'

# Region code -> location shown in the dropdown. Only the code is passed to AWS;
# any other code can still be typed in by hand.
$Regions = [ordered]@{
    'ap-south-1' = 'Mumbai';            'ap-south-2' = 'Hyderabad'
    'us-east-1' = 'N. Virginia';        'us-east-2' = 'Ohio'
    'us-west-1' = 'N. California';      'us-west-2' = 'Oregon'
    'ca-central-1' = 'Canada Central';  'ca-west-1' = 'Calgary'
    'mx-central-1' = 'Mexico';          'sa-east-1' = 'Sao Paulo'
    'eu-west-1' = 'Ireland';            'eu-west-2' = 'London'
    'eu-west-3' = 'Paris';              'eu-central-1' = 'Frankfurt'
    'eu-central-2' = 'Zurich';          'eu-north-1' = 'Stockholm'
    'eu-south-1' = 'Milan';             'eu-south-2' = 'Spain'
    'ap-southeast-1' = 'Singapore';     'ap-southeast-2' = 'Sydney'
    'ap-southeast-3' = 'Jakarta';       'ap-southeast-4' = 'Melbourne'
    'ap-southeast-5' = 'Malaysia';      'ap-southeast-7' = 'Thailand'
    'ap-east-1' = 'Hong Kong';          'ap-northeast-1' = 'Tokyo'
    'ap-northeast-2' = 'Seoul';         'ap-northeast-3' = 'Osaka'
    'me-central-1' = 'UAE';             'me-south-1' = 'Bahrain'
    'il-central-1' = 'Tel Aviv';        'af-south-1' = 'Cape Town'
}

# "ap-south-1  (Mumbai)" -> "ap-south-1"
function Get-RegionCode([string]$Text) { ($Text.Trim() -split '\s+')[0] }

function Show-Message([string]$Text, [string]$Icon = 'Information') {
    [void][System.Windows.Forms.MessageBox]::Show($Text, $Title, 'OK', $Icon)
}

function Fail([string]$Text) {
    Write-Host "[ERROR] $Text" -ForegroundColor Red
    Show-Message $Text 'Error'
    exit 1
}

# Profile names already defined in ~/.aws/config and ~/.aws/credentials.
function Get-AwsProfiles {
    $names = @()
    foreach ($file in @("$env:USERPROFILE\.aws\config", "$env:USERPROFILE\.aws\credentials")) {
        if (Test-Path $file) {
            $names += Select-String -Path $file -Pattern '^\s*\[([^\]]+)\]' | ForEach-Object {
                $_.Matches[0].Groups[1].Value.Trim() -replace '^profile\s+', ''
            }
        }
    }
    $names | Where-Object { $_ -notmatch '^(sso-session|services)\s' } | Sort-Object -Unique
}

function Get-Settings {
    $defaults = @{ Profile = ''; Region = 'us-east-1'; Mode = 'existing'
                   SsoStartUrl = ''; SsoRegion = ''; SsoAccountId = ''; SsoRole = '' }
    if (Test-Path $SettingsFile) {
        try {
            $saved = Get-Content $SettingsFile -Raw | ConvertFrom-Json
            foreach ($k in @($defaults.Keys)) { if ($null -ne $saved.$k) { $defaults[$k] = [string]$saved.$k } }
        } catch { }
    }
    $defaults
}

function Show-LauncherDialog($Settings) {
    $font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Font = $font
    $form.ClientSize = New-Object System.Drawing.Size(470, 450)
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.StartPosition = 'CenterScreen'
    $form.TopMost = $true

    # Helpers to add a label + control on one row.
    $addLabel = {
        param($parent, [string]$text, [int]$y)
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $text; $l.Location = New-Object System.Drawing.Point(0, ($y + 3)); $l.AutoSize = $true
        $parent.Controls.Add($l)
    }
    $addText = {
        param($parent, [string]$name, [string]$value, [int]$y, [bool]$secret = $false)
        $t = New-Object System.Windows.Forms.TextBox
        $t.Name = $name; $t.Text = $value; $t.UseSystemPasswordChar = $secret
        $t.Location = New-Object System.Drawing.Point(135, $y); $t.Width = 305
        $parent.Controls.Add($t)
        $t
    }

    $top = New-Object System.Windows.Forms.Panel
    $top.Location = New-Object System.Drawing.Point(15, 15); $top.Size = New-Object System.Drawing.Size(440, 70)
    $form.Controls.Add($top)

    & $addLabel $top 'AWS profile' 0
    $profileBox = New-Object System.Windows.Forms.ComboBox
    $profileBox.Name = 'Profile'; $profileBox.DropDownStyle = 'DropDown'
    $profileBox.Location = New-Object System.Drawing.Point(135, 0); $profileBox.Width = 305
    foreach ($p in Get-AwsProfiles) { [void]$profileBox.Items.Add($p) }
    $profileBox.Text = $Settings.Profile
    $top.Controls.Add($profileBox)

    & $addLabel $top 'AWS region' 36
    $regionBox = New-Object System.Windows.Forms.ComboBox
    $regionBox.Name = 'Region'; $regionBox.DropDownStyle = 'DropDown'
    $regionBox.Location = New-Object System.Drawing.Point(135, 36); $regionBox.Width = 305
    $regionBox.MaxDropDownItems = 15
    foreach ($code in $Regions.Keys) { [void]$regionBox.Items.Add("$code  ($($Regions[$code]))") }
    $regionBox.Text = if ($Regions.Contains($Settings.Region)) { "$($Settings.Region)  ($($Regions[$Settings.Region]))" } else { $Settings.Region }
    $top.Controls.Add($regionBox)

    $group = New-Object System.Windows.Forms.GroupBox
    $group.Text = 'How do you sign in?'
    $group.Location = New-Object System.Drawing.Point(15, 92); $group.Size = New-Object System.Drawing.Size(440, 100)
    $form.Controls.Add($group)

    $modes = [ordered]@{
        existing  = 'Already signed in (use the profile as it is)'
        sso       = 'AWS SSO / IAM Identity Center (opens your browser)'
        accesskey = 'Access key ID and secret (saved to the profile)'
    }
    $radios = @{}
    $y = 22
    foreach ($m in $modes.Keys) {
        $rb = New-Object System.Windows.Forms.RadioButton
        $rb.Name = "Mode_$m"; $rb.Text = $modes[$m]; $rb.Tag = $m
        $rb.Location = New-Object System.Drawing.Point(12, $y); $rb.AutoSize = $true
        $group.Controls.Add($rb); $radios[$m] = $rb; $y += 24
    }

    # SSO details (only needed the first time for a profile).
    $ssoPanel = New-Object System.Windows.Forms.Panel
    $ssoPanel.Location = New-Object System.Drawing.Point(15, 205); $ssoPanel.Size = New-Object System.Drawing.Size(440, 175)
    $form.Controls.Add($ssoPanel)
    & $addLabel $ssoPanel 'SSO start URL' 0
    $ssoUrl = & $addText $ssoPanel 'SsoStartUrl' $Settings.SsoStartUrl 0
    & $addLabel $ssoPanel 'SSO region' 32
    $ssoRegion = & $addText $ssoPanel 'SsoRegion' $Settings.SsoRegion 32
    & $addLabel $ssoPanel 'AWS account ID' 64
    $ssoAccount = & $addText $ssoPanel 'SsoAccountId' $Settings.SsoAccountId 64
    & $addLabel $ssoPanel 'Role name' 96
    $ssoRole = & $addText $ssoPanel 'SsoRole' $Settings.SsoRole 96
    $ssoNote = New-Object System.Windows.Forms.Label
    $ssoNote.Text = "Leave these blank if the profile is already set up for SSO. Example start URL: https://my-org.awsapps.com/start  (role e.g. SecurityAudit)"
    $ssoNote.Location = New-Object System.Drawing.Point(0, 130); $ssoNote.Size = New-Object System.Drawing.Size(440, 40)
    $ssoNote.ForeColor = [System.Drawing.SystemColors]::GrayText
    $ssoPanel.Controls.Add($ssoNote)

    # Access key details.
    $keysPanel = New-Object System.Windows.Forms.Panel
    $keysPanel.Location = $ssoPanel.Location; $keysPanel.Size = $ssoPanel.Size
    $form.Controls.Add($keysPanel)
    & $addLabel $keysPanel 'Access key ID' 0
    $keyId = & $addText $keysPanel 'AccessKeyId' '' 0
    & $addLabel $keysPanel 'Secret access key' 32
    $keySecret = & $addText $keysPanel 'SecretAccessKey' '' 32 $true
    $keysNote = New-Object System.Windows.Forms.Label
    $keysNote.Text = "Saved to your AWS credentials file under the profile above (same as 'aws configure'). Leave blank to keep the keys already stored for this profile."
    $keysNote.Location = New-Object System.Drawing.Point(0, 66); $keysNote.Size = New-Object System.Drawing.Size(440, 40)
    $keysNote.ForeColor = [System.Drawing.SystemColors]::GrayText
    $keysPanel.Controls.Add($keysNote)

    $existingNote = New-Object System.Windows.Forms.Label
    $existingNote.Text = "Uses credentials already available to this profile (or your default credentials if the profile is blank)."
    $existingNote.Location = $ssoPanel.Location; $existingNote.Size = New-Object System.Drawing.Size(440, 40)
    $existingNote.ForeColor = [System.Drawing.SystemColors]::GrayText
    $form.Controls.Add($existingNote)

    $updatePanels = {
        $ssoPanel.Visible     = $radios['sso'].Checked
        $keysPanel.Visible    = $radios['accesskey'].Checked
        $existingNote.Visible = $radios['existing'].Checked
    }
    foreach ($rb in $radios.Values) { $rb.Add_CheckedChanged($updatePanels) }
    $mode = if ($radios.Contains($Settings.Mode)) { $Settings.Mode } else { 'existing' }
    $radios[$mode].Checked = $true
    & $updatePanels

    $runBtn = New-Object System.Windows.Forms.Button
    $runBtn.Name = 'Run'; $runBtn.Text = 'Run scan'
    $runBtn.Location = New-Object System.Drawing.Point(265, 405); $runBtn.Size = New-Object System.Drawing.Size(95, 30)
    $form.Controls.Add($runBtn)
    $cancelBtn = New-Object System.Windows.Forms.Button
    $cancelBtn.Text = 'Cancel'; $cancelBtn.DialogResult = 'Cancel'
    $cancelBtn.Location = New-Object System.Drawing.Point(365, 405); $cancelBtn.Size = New-Object System.Drawing.Size(90, 30)
    $form.Controls.Add($cancelBtn)
    $form.AcceptButton = $runBtn      # Enter = Run
    $form.CancelButton = $cancelBtn   # Esc = Cancel

    $state = @{ Result = $null }
    $runBtn.Add_Click({
        $sel = ($radios.Values | Where-Object Checked | Select-Object -First 1).Tag
        $r = @{
            Profile = $profileBox.Text.Trim(); Region = (Get-RegionCode $regionBox.Text); Mode = $sel
            SsoStartUrl = $ssoUrl.Text.Trim(); SsoRegion = $ssoRegion.Text.Trim()
            SsoAccountId = $ssoAccount.Text.Trim(); SsoRole = $ssoRole.Text.Trim()
            AccessKeyId = $keyId.Text.Trim(); SecretAccessKey = $keySecret.Text.Trim()
        }
        if ($r.Region -and $r.Region -notmatch '^[a-z]{2}(-[a-z]+)+-\d$') {
            Show-Message "'$($r.Region)' doesn't look like an AWS region (e.g. eu-west-1)." 'Warning'; return
        }
        if ($sel -eq 'sso') {
            $filled = @($r.SsoStartUrl, $r.SsoRegion, $r.SsoAccountId, $r.SsoRole | Where-Object { $_ })
            if ($filled.Count -gt 0 -and $filled.Count -lt 4) {
                Show-Message 'Fill in all four SSO fields, or leave them all blank to use the existing SSO profile.' 'Warning'; return
            }
            if ($r.SsoAccountId -and $r.SsoAccountId -notmatch '^\d{12}$') {
                Show-Message 'The AWS account ID must be 12 digits.' 'Warning'; return
            }
        }
        if ($sel -eq 'accesskey' -and ([bool]$r.AccessKeyId -ne [bool]$r.SecretAccessKey)) {
            Show-Message 'Enter both the access key ID and the secret access key (or leave both blank).' 'Warning'; return
        }
        $state.Result = $r
        $form.DialogResult = 'OK'
        $form.Close()
    })

    [void]$form.ShowDialog()
    $form.Dispose()
    $state.Result
}

function Assert-AwsCli {
    if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
        Fail "The AWS CLI is needed for this sign-in method but wasn't found.`n`nInstall AWS CLI v2 from https://aws.amazon.com/cli/ and run this again."
    }
}

# "aws configure set" for non-secret settings; stops the launcher if the write fails.
function Set-AwsConfig([string]$Key, [string]$Value, [string]$ProfileName) {
    & aws configure set $Key $Value --profile $ProfileName
    if ($LASTEXITCODE -ne 0) { Fail "Could not save '$Key' for profile '$ProfileName' with ""aws configure set""." }
}

# Sets key = value lines inside [Section] of an AWS credentials file, keeping every
# other line as it is. Used for access keys so the secret never appears on a command
# line. Written as UTF-8 without BOM, which is what botocore and the AWS CLI expect.
function Set-IniValues([string]$Path, [string]$Section, [System.Collections.Specialized.OrderedDictionary]$Values) {
    $lines = if (Test-Path $Path) { [System.IO.File]::ReadAllLines($Path) } else { @() }
    $pending = [ordered]@{}
    foreach ($k in $Values.Keys) { $pending[$k] = $Values[$k] }
    $out = New-Object System.Collections.Generic.List[string]
    $inSection = $false
    $found = $false
    # Add keys still missing from the section, before any blank lines that end it.
    $flush = {
        $at = $out.Count
        while ($at -gt 0 -and -not $out[$at - 1].Trim()) { $at-- }
        foreach ($k in @($pending.Keys)) { $out.Insert($at, "$k = $($pending[$k])"); $at++ }
        $pending.Clear()
    }

    foreach ($line in $lines) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            if ($inSection) { & $flush }
            $inSection = $Matches[1].Trim() -eq $Section
            if ($inSection) { $found = $true }
        } elseif ($inSection -and $line -match '^\s*([^=\s]+)\s*=' -and $pending.Contains($Matches[1])) {
            $k = $Matches[1]
            $out.Add("$k = $($pending[$k])")
            $pending.Remove($k)
            continue
        }
        $out.Add($line)
    }
    if ($inSection) { & $flush }
    if (-not $found) {
        if ($out.Count -gt 0 -and $out[$out.Count - 1].Trim()) { $out.Add('') }
        $out.Add("[$Section]")
        & $flush
    }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllLines($Path, $out, (New-Object System.Text.UTF8Encoding $false))
}

function Invoke-Main {
    $choice = Show-LauncherDialog (Get-Settings)
    if (-not $choice) { Write-Host 'Cancelled.'; exit 0 }

    # Remember the non-secret choices for next time.
    $remember = [ordered]@{}
    foreach ($k in 'Profile', 'Region', 'Mode', 'SsoStartUrl', 'SsoRegion', 'SsoAccountId', 'SsoRole') { $remember[$k] = $choice[$k] }
    $remember | ConvertTo-Json | Set-Content -Path $SettingsFile -Encoding UTF8

    $profileName = $choice.Profile
    if (-not $profileName -and $choice.Mode -ne 'existing') { $profileName = 'default' }

    # ---- Sign-in ------------------------------------------------------------
    if ($choice.Mode -eq 'accesskey') {
        Assert-AwsCli
        if ($choice.AccessKeyId) {
            $credFile = if ($env:AWS_SHARED_CREDENTIALS_FILE) { $env:AWS_SHARED_CREDENTIALS_FILE } else { "$env:USERPROFILE\.aws\credentials" }
            Write-Host "Saving access key to profile '$profileName' in $credFile..."
            try {
                Set-IniValues $credFile $profileName ([ordered]@{
                    aws_access_key_id = $choice.AccessKeyId; aws_secret_access_key = $choice.SecretAccessKey })
            } catch {
                Fail "Could not save the access key to $credFile.`n`n$($_.Exception.Message)"
            }
        }
        $choice.SecretAccessKey = $null
        if ($choice.Region) { Set-AwsConfig region $choice.Region $profileName }
    }
    elseif ($choice.Mode -eq 'sso') {
        Assert-AwsCli
        if ($choice.SsoStartUrl) {
            Write-Host "Configuring SSO for profile '$profileName'..."
            Set-AwsConfig sso_start_url  $choice.SsoStartUrl  $profileName
            Set-AwsConfig sso_region     $choice.SsoRegion    $profileName
            Set-AwsConfig sso_account_id $choice.SsoAccountId $profileName
            Set-AwsConfig sso_role_name  $choice.SsoRole      $profileName
            if ($choice.Region) { Set-AwsConfig region $choice.Region $profileName }
        } else {
            $hasSso = (& aws configure get sso_start_url --profile $profileName) -or
                      (& aws configure get sso_session --profile $profileName)
            if (-not $hasSso) {
                Fail "Profile '$profileName' isn't set up for SSO yet.`n`nRun again and fill in the SSO start URL, SSO region, account ID and role name."
            }
        }
        Write-Host 'Opening your browser for AWS SSO sign-in. Approve the request there...' -ForegroundColor Cyan
        & aws sso login --profile $profileName
        if ($LASTEXITCODE -ne 0) { Fail 'AWS SSO sign-in failed or was cancelled.' }
    }

    # ---- Python environment ---------------------------------------------------
    Set-Location $Here
    $venvPy = Join-Path $Here '.venv\Scripts\python.exe'
    if (-not (Test-Path $venvPy)) {
        Write-Host 'First run: creating Python environment and installing boto3...'
        if (Get-Command py -ErrorAction SilentlyContinue) { & py -3 -m venv .venv }
        elseif (Get-Command python -ErrorAction SilentlyContinue) { & python -m venv .venv }
        else { Fail "Python 3.9+ was not found.`n`nInstall it from https://www.python.org/downloads/ and run this again." }
        if (-not (Test-Path $venvPy)) { Fail 'Could not create the Python virtual environment (.venv).' }
        & $venvPy -m pip install --quiet --disable-pip-version-check -r requirements.txt
        if ($LASTEXITCODE -ne 0) { Remove-Item -Recurse -Force .venv; Fail 'Installing requirements with pip failed.' }
    }

    # ---- Scan -----------------------------------------------------------------
    # Remove the previous run's output so a failed scan can never show an old report.
    Remove-Item $ReportFile, $JsonFile -Force -ErrorAction SilentlyContinue
    $scanArgs = @('scanner.py', '--output', $ReportFile, '--json', $JsonFile)
    if ($profileName)   { $scanArgs += @('--profile', $profileName) }
    if ($choice.Region) { $scanArgs += @('--region', $choice.Region) }
    Write-Host "Running scan$(if ($profileName) { " with profile '$profileName'" })..." -ForegroundColor Cyan
    & $venvPy @scanArgs
    $rc = $LASTEXITCODE

    if ($rc -eq 2) {
        $hint = if ($choice.Mode -eq 'existing') { "`n`nIf your session has expired, run again and choose 'AWS SSO' or 'Access key'." } else { '' }
        Fail "The scan could not start: AWS rejected the credentials or the profile doesn't exist. See the console window for details.$hint"
    }
    if ($rc -ne 0 -or -not (Test-Path $ReportFile)) {
        Fail "The scanner stopped with an unexpected error (exit code $rc). See the console window for details."
    }

    Start-Process $ReportFile
    try {
        $findings = @((Get-Content $JsonFile -Raw | ConvertFrom-Json).findings)
        $failed = @($findings | Where-Object { $_.status -eq 'FAIL' })
        $errors = @($findings | Where-Object { $_.status -eq 'ERROR' }).Count
        $byRisk = ('Critical', 'High', 'Medium', 'Low' | ForEach-Object {
            $risk = $_; "${risk}: $(@($failed | Where-Object { $_.risk -eq $risk }).Count)" }) -join "`n"
        Show-Message "Scan complete. The report is open in your browser.`n`nFindings: $($failed.Count)`n$byRisk`n`nNot evaluated (permissions/errors): $errors"
    } catch {
        Show-Message 'Scan complete. The report is open in your browser.'
    }
    exit 0
}

# Run only when executed, not when dot-sourced (lets the dialog be tested on its own).
if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
