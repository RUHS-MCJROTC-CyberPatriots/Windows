#Requires -RunAsAdministrator
# CyberPatriot Quick Tool - practice / study use. Read the README before running anything.

# ---------- helpers ----------
function Ok($m)   { Write-Host "[SUCCESS] $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "[ERROR] $m" -ForegroundColor Red }
function Info($m) { Write-Host "[INFO] $m" -ForegroundColor Yellow }
function Ask($p)  { return ((Read-Host "$p (y/n)").Trim().ToLower() -eq 'y') }
function Set-Reg($path, $name, $value, $type = 'DWord') {
    try {
        if (-not (Test-Path $path)) { New-Item $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name $name -Value $value -Type $type -ErrorAction Stop
        Ok "$name = $value"
    } catch { Bad "Failed to set $name : $_" }
}

# ---------- 1. users ----------
function auditUsers {
    $allUsers = Get-LocalUser
    $adminGroupMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

    foreach ($user in $allUsers) {
        $userName = $user.Name
        $isAdmin = $adminGroupMembers | Where-Object { $_.Name -like "*\$userName" -or $_.Name -eq $userName }
        $currentRole = if ($isAdmin) { "Administrator" } else { "Standard User" }

        Write-Host "`n--------------------------------------------------"
        Write-Host "User: $userName   (Enabled: $($user.Enabled))" -ForegroundColor Cyan
        Write-Host "Current Role: $currentRole" -ForegroundColor Yellow
        $action = (Read-Host "Action for '$userName'? (y = keep, t = toggle role, p = new password, x = disable, d = delete, s = skip)").Trim().ToLower()

        if ($action -eq 't') {
            if ($isAdmin) {
                try {
                    Remove-LocalGroupMember -Group "Administrators" -Member $userName -ErrorAction Stop
                    Add-LocalGroupMember -Group "Users" -Member $userName -ErrorAction SilentlyContinue
                    Ok "Demoted $userName to Standard User."
                } catch { Bad "Failed to change role for $userName : $_" }
            } else {
                try {
                    Add-LocalGroupMember -Group "Administrators" -Member $userName -ErrorAction Stop
                    Ok "Promoted $userName to Administrator."
                } catch { Bad "Failed to change role for $userName : $_" }
            }
        }
        elseif ($action -eq 'p') {
            try {
                $pw = Read-Host "New password for $userName" -AsSecureString
                Set-LocalUser -Name $userName -Password $pw -PasswordNeverExpires $false -ErrorAction Stop
                Ok "Password changed for $userName."
            } catch { Bad "Failed to change password for $userName : $_" }
        }
        elseif ($action -eq 'x') {
            try { Disable-LocalUser -Name $userName -ErrorAction Stop; Ok "Disabled $userName." }
            catch { Bad "Failed to disable $userName : $_" }
        }
        elseif ($action -eq 'd') {
            if ($userName -eq $env:USERNAME) { Bad "Refusing to delete the account you are logged in as." }
            elseif (Ask "Really delete '$userName'") {
                try { Remove-LocalUser -Name $userName -ErrorAction Stop; Ok "Deleted $userName." }
                catch { Bad "Failed to delete $userName : $_" }
            }
        }
        elseif ($action -eq 'y') { Write-Host "Keeping current role for $userName." -ForegroundColor Gray }
        else { Write-Host "Skipped $userName." -ForegroundColor DarkGray }
    }

    Write-Host "`nOther privileged groups (review by hand):" -ForegroundColor Cyan
    foreach ($g in 'Remote Desktop Users','Backup Operators','Power Users') {
        $m = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
        if ($m) { Write-Host "$g : $($m.Name -join ', ')" -ForegroundColor Yellow }
    }
    Write-Host "`nUser role audit complete!" -ForegroundColor Green
}

# ---------- 2. password + lockout policy ----------
function SecPol {
    net accounts /uniquepw:7 /maxpwage:99 /minpwage:15 /minpwlen:10 | Out-Null
    net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null

    # Complexity and reversible encryption need secedit (file must stay Unicode)
    $cfg = "$env:TEMP\sec.cfg"
    secedit /export /cfg $cfg /quiet
    (Get-Content $cfg) `
        -replace 'PasswordComplexity\s*=\s*0','PasswordComplexity = 1' `
        -replace 'ClearTextPassword\s*=\s*1','ClearTextPassword = 0' |
        Set-Content $cfg -Encoding Unicode
    secedit /configure /db "$env:windir\security\local.sdb" /cfg $cfg /areas SECURITYPOLICY /quiet
    Remove-Item $cfg -Force -ErrorAction SilentlyContinue

    # Verify from the actual system, not hard-coded text
    $chk = "$env:TEMP\check.cfg"
    secedit /export /cfg $chk /quiet
    Write-Host "`nCurrent policy values:" -ForegroundColor Green
    $keys = 'PasswordHistorySize','MaximumPasswordAge','MinimumPasswordAge','MinimumPasswordLength',
            'PasswordComplexity','ClearTextPassword','LockoutBadCount','LockoutDuration','ResetLockoutCount'
    foreach ($k in $keys) {
        Get-Content $chk | Select-String "^$k\s*=" | ForEach-Object { Write-Host $_.Line -ForegroundColor Yellow }
    }
    Remove-Item $chk -Force -ErrorAction SilentlyContinue
    Write-Host "Targets: history 7, max 99, min 15, length 10, complexity 1, cleartext 0, lockout 5/30/30" -ForegroundColor Gray
    Write-Host "Password policy complete!" -ForegroundColor Green
}

# ---------- 3. security options ----------
function security {
    $sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    Info "Ctrl+Alt+Del required / hide last user"
    Set-Reg $sys DisableCAD 0
    Set-Reg $sys DontDisplayLastUserName 1

    Info "UAC"
    Set-Reg $sys EnableLUA 1
    Set-Reg $sys ConsentPromptBehaviorAdmin 2
    Set-Reg $sys ConsentPromptBehaviorUser 0
    Set-Reg $sys PromptOnSecureDesktop 1

    Info "LSA / network security options"
    Set-Reg $lsa LimitBlankPasswordUse 1
    Set-Reg $lsa RestrictAnonymous 1
    Set-Reg $lsa RestrictAnonymousSAM 1
    Set-Reg $lsa NoLMHash 1
    Set-Reg $lsa LmCompatibilityLevel 5
    Set-Reg $lsa EveryoneIncludesAnonymous 0
    Set-Reg $lsa SCENoApplyLegacyAuditPolicy 1

    try { Disable-LocalUser -Name "Guest" -ErrorAction Stop; Ok "Guest disabled." }
    catch { Bad "Guest: $_" }

    if (Ask "Rename built-in Administrator (only if another enabled admin exists)") {
        $new = Read-Host "New name"
        try { Rename-LocalUser -Name "Administrator" -NewName $new -ErrorAction Stop; Ok "Renamed to $new." }
        catch { Bad "Rename failed: $_" }
    }

    Write-Host "`nUser rights currently assigned (review by hand):" -ForegroundColor Cyan
    $ur = "$env:TEMP\ur.cfg"
    secedit /export /cfg $ur /quiet
    Select-String $ur -Pattern '^Se' | ForEach-Object { Write-Host $_.Line -ForegroundColor Gray }
    Remove-Item $ur -Force -ErrorAction SilentlyContinue
    Write-Host "Security options configuration complete! (logoff/reboot may be needed)" -ForegroundColor Green
}

# ---------- 4. firewall ----------
function firewall {
    if (Ask "Reset firewall to defaults first (removes custom rules, may remove rules required apps need)") {
        netsh advfirewall reset | Out-Null
        Ok "Firewall reset."
    }

    # Settings come AFTER the reset so the reset can't undo them
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Allow `
        -NotifyOnDisable True -LogAllowed True -LogBlocked True
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table | Out-Host

    Write-Host "Inbound allow rules (review by hand):" -ForegroundColor Cyan
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
        Select-Object DisplayName, Profile, Group | Format-Table -AutoSize | Out-Host

    $bad = Get-NetFirewallRule -DisplayName "*Telnet*","*FTP*" -ErrorAction SilentlyContinue
    if ($bad) { $bad | Disable-NetFirewallRule; Ok "Disabled Telnet/FTP rules." }

    Write-Host "Listening ports:" -ForegroundColor Cyan
    Get-NetTCPConnection -State Listen |
        Select-Object LocalAddress, LocalPort, @{n='Proc';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
        Sort-Object LocalPort | Format-Table -AutoSize | Out-Host
    Write-Host "Firewall configuration complete!" -ForegroundColor Green
}

# ---------- 5. audit policy ----------
function auditPolicy {
    auditpol /set /category:* /success:enable /failure:enable | Out-Null
    Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" SCENoApplyLegacyAuditPolicy 1
    auditpol /get /category:* | Out-Host
    Write-Host "Audit policy complete! (if a legacy audit item doesn't score, also set it in secpol.msc)" -ForegroundColor Green
}

# ---------- 6. remote desktop ----------
function rdp {
    $ts  = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $tcp = "$ts\WinStations\RDP-Tcp"
    if (Ask "Does the README REQUIRE Remote Desktop") {
        Set-Reg $ts fDenyTSConnections 0
        Set-Reg $tcp UserAuthentication 1
        Set-Reg $tcp SecurityLayer 2
        Set-Reg $tcp MinEncryptionLevel 3
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        $m = Get-LocalGroupMember "Remote Desktop Users" -ErrorAction SilentlyContinue
        Info "Remote Desktop Users: $($m.Name -join ', ')  <- confirm these are authorized"
    } else {
        Set-Reg $ts fDenyTSConnections 1
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" fAllowToGetHelp 0
        Ok "RDP and Remote Assistance disabled."
    }
}

# ---------- 7. shares ----------
function shares {
    $s = Get-SmbShare | Where-Object { -not $_.Special }
    if (-not $s) { Info "No non-default shares found."; return }
    foreach ($share in $s) {
        Write-Host "`nShare: $($share.Name)  Path: $($share.Path)" -ForegroundColor Cyan
        if (Ask "Remove '$($share.Name)'") {
            try { Remove-SmbShare -Name $share.Name -Force -ErrorAction Stop; Ok "Removed $($share.Name)." }
            catch { Bad "Failed: $_" }
        }
    }
}

# ---------- 8. services + insecure protocols ----------
function services {
    try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop; Ok "SMBv1 server disabled." }
    catch { Bad "SMBv1: $_" }
    foreach ($f in 'SMB1Protocol','TelnetClient','TelnetServer','IIS-FTPServer') {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue
        if ($feat -and $feat.State -eq 'Enabled') {
            try { Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop | Out-Null; Ok "Disabled feature $f." }
            catch { Bad "$f : $_" }
        }
    }

    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" EnableMulticast 0   # LLMNR off

    $risky = 'RemoteRegistry','TlntSvr','SNMP','SSDPSRV','upnphost','FTPSVC','W3SVC','RpcLocator','Browser'
    foreach ($name in $risky) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "`nService: $($svc.DisplayName) [$($svc.Name)]  Status: $($svc.Status)  Start: $($svc.StartType)" -ForegroundColor Cyan
            if ($svc.StartType -ne 'Disabled' -and (Ask "Disable it (not required by README)")) {
                try {
                    Stop-Service $name -Force -ErrorAction SilentlyContinue
                    Set-Service $name -StartupType Disabled -ErrorAction Stop
                    Ok "Disabled $name."
                } catch { Bad "$name : $_" }
            }
        }
    }
    Write-Host "`nRunning services (scan for anything unauthorized):" -ForegroundColor Cyan
    Get-Service | Where-Object Status -eq Running | Sort-Object DisplayName |
        Select-Object Name, DisplayName | Format-Table -AutoSize | Out-Host
}

# ---------- 9. updates + integrity ----------
function updates {
    Set-Service wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service wuauserv -ErrorAction SilentlyContinue
    $au = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    Set-Reg $au NoAutoUpdate 0
    Set-Reg $au AUOptions 4
    usoclient StartScan
    usoclient StartDownload
    usoclient StartInstall
    Info "Update scan triggered. Also check Settings > Update & Security."
    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 | Format-Table | Out-Host

    if (Ask "Run DISM RestoreHealth + sfc /scannow now (10+ minutes)") {
        DISM.exe /Online /Cleanup-Image /RestoreHealth
        sfc /scannow
    }
    Write-Host "Updates step complete! Remember to update Firefox and other third-party apps." -ForegroundColor Green
}

# ---------- 10. defender ----------
function defender {
    $settings = [ordered]@{
        DisableRealtimeMonitoring = $false
        DisableBehaviorMonitoring = $false
        DisableIOAVProtection     = $false
        DisableScriptScanning     = $false
        DisableBlockAtFirstSeen   = $false
        MAPSReporting             = 'Advanced'
        SubmitSamplesConsent      = 'SendSafeSamples'
        PUAProtection             = 'Enabled'
        CloudBlockLevel           = 'High'
        EnableNetworkProtection   = 'Enabled'
    }
    foreach ($k in $settings.Keys) {
        try { $p = @{ $k = $settings[$k] }; Set-MpPreference @p -ErrorAction Stop; Ok "$k = $($settings[$k])" }
        catch { Bad "$k : $_" }
    }
    Set-Service WinDefend -StartupType Automatic -ErrorAction SilentlyContinue

    $pref = Get-MpPreference
    if ($pref.ExclusionPath) {
        Write-Host "Exclusion paths:" -ForegroundColor Cyan
        foreach ($e in $pref.ExclusionPath) {
            Write-Host $e -ForegroundColor Yellow
            if (Ask "Remove this exclusion") { Remove-MpPreference -ExclusionPath $e }
        }
    }
    try { Update-MpSignature -ErrorAction Stop; Ok "Signatures updated." } catch { Bad "Signature update: $_" }
    Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureLastUpdated | Format-List | Out-Host
    if (Ask "Start a full scan in the background") { Start-MpScan -ScanType FullScan -AsJob | Out-Null; Info "Scan running as a job." }
    Info "Tamper Protection must be turned on in the Windows Security GUI."
}

# ---------- 11. persistence audit ----------
function persistence {
    Write-Host "Run keys:" -ForegroundColor Cyan
    $keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    foreach ($k in $keys) {
        Write-Host "== $k" -ForegroundColor Yellow
        $props = (Get-ItemProperty $k -ErrorAction SilentlyContinue).PSObject.Properties |
                 Where-Object { $_.Name -notlike 'PS*' }
        foreach ($p in $props) {
            Write-Host "  $($p.Name) = $($p.Value)"
            if (Ask "  Remove '$($p.Name)'") {
                Remove-ItemProperty -Path $k -Name $p.Name -ErrorAction SilentlyContinue; Ok "Removed $($p.Name)."
            }
        }
    }
    Write-Host "`nStartup folders:" -ForegroundColor Cyan
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force -ErrorAction SilentlyContinue |
        Select-Object FullName | Format-Table -AutoSize | Out-Host

    Write-Host "Non-Microsoft scheduled tasks:" -ForegroundColor Cyan
    $tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' }
    foreach ($t in $tasks) {
        Write-Host "`n$($t.TaskPath)$($t.TaskName)  -> $(($t.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; ')" -ForegroundColor Yellow
        if (Ask "Remove this task") {
            try { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop; Ok "Removed." }
            catch { Bad "$_" }
        }
    }

    Write-Host "`nProcesses with unsigned/invalid executables:" -ForegroundColor Cyan
    Get-Process | Where-Object Path | ForEach-Object {
        $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -ne 'Valid') { "{0} (PID {1}) {2} [{3}]" -f $_.Name, $_.Id, $_.Path, $sig.Status }
    } | Out-Host
}

# ---------- 12. prohibited software ----------
function software {
    $targets = 'steam','teamviewer','anydesk','putty','itunes','ccleaner','wireshark','nmap','utorrent','bittorrent',
               'cain','john','metasploit','netcat','angry ip','vuze','limewire','frostwire'
    $apps = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                             'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                             'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
            Where-Object DisplayName

    Write-Host "All installed programs:" -ForegroundColor Cyan
    $apps | Sort-Object DisplayName | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize | Out-Host

    foreach ($app in $apps) {
        $hit = $targets | Where-Object { $app.DisplayName -like "*$_*" }
        if ($hit) {
            Write-Host "`nFlagged: $($app.DisplayName)" -ForegroundColor Red
            if (Ask "Uninstall it (not required by README)") {
                $cmd = if ($app.QuietUninstallString) { $app.QuietUninstallString } else { $app.UninstallString }
                if ($cmd) { Start-Process cmd.exe -ArgumentList "/c $cmd" -Wait; Ok "Uninstall launched for $($app.DisplayName)." }
                else { Bad "No uninstall string; remove manually." }
            }
        }
    }
    Info "Also check Program Files, user profiles, and portable copies by hand."
}

# ---------- 13. hidden files + media ----------
function media {
    $adv = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-Reg $adv Hidden 1
    Set-Reg $adv ShowSuperHidden 1
    Set-Reg $adv HideFileExt 0
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue

    $av  = '*.mp3','*.wav','*.flac','*.aac','*.ogg','*.wma','*.m4a','*.mp4','*.avi','*.mov','*.mkv','*.wmv'
    $img = '*.gif','*.jpg','*.jpeg','*.png','*.bmp'

    $audioVideo = Get-ChildItem C:\Users -Recurse -File -Force -Include $av -ErrorAction SilentlyContinue
    $images = Get-ChildItem C:\Users -Recurse -File -Force -Include $img -ErrorAction SilentlyContinue |
              Where-Object { $_.FullName -notmatch '\\AppData\\' }

    Write-Host "`nAudio/video files:" -ForegroundColor Cyan
    $audioVideo | Select-Object FullName | Format-Table -AutoSize | Out-Host
    Write-Host "Images (outside AppData):" -ForegroundColor Cyan
    $images | Select-Object FullName | Format-Table -AutoSize | Out-Host

    $csv = "$env:USERPROFILE\Desktop\media_review.csv"
    $audioVideo + $images | Select-Object FullName, Length, LastWriteTime | Export-Csv $csv -NoTypeInformation
    Info "Saved list to $csv"

    if ($audioVideo -and (Ask "Delete ALL audio/video files listed above (forensics answered first?)")) {
        $audioVideo | Remove-Item -Force -ErrorAction SilentlyContinue; Ok "Audio/video deleted."
    }
    foreach ($f in $images) {
        Write-Host $f.FullName -ForegroundColor Yellow
        if (Ask "  Delete this image") { Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue }
    }
}

# ---------- 14. forensics hash finder ----------
function findHash {
    $target = (Read-Host "Hash to find").Trim()
    $alg = (Read-Host "Algorithm (MD5 / SHA1 / SHA256)").Trim().ToUpper()
    $root = Read-Host "Search root (blank = C:\Users)"
    if (-not $root) { $root = "C:\Users" }
    Info "Searching... this can take a while."
    Get-ChildItem $root -Recurse -File -Force -ErrorAction SilentlyContinue |
        Get-FileHash -Algorithm $alg -ErrorAction SilentlyContinue |
        Where-Object { $_.Hash -eq $target } | Select-Object Path, Hash | Format-List | Out-Host
    Info "Search finished."
}

# ---------- 15. firefox ----------
function firefox {
    $dir = "C:\Program Files\Mozilla Firefox\distribution"
    if (-not (Test-Path "C:\Program Files\Mozilla Firefox")) { Bad "Firefox not found in Program Files."; return }
    New-Item $dir -ItemType Directory -Force | Out-Null
    $json = @'
{
  "policies": {
    "DisableAppUpdate": false,
    "PasswordManagerEnabled": false,
    "OfferToSaveLogins": false,
    "AutofillAddressEnabled": false,
    "AutofillCreditCardEnabled": false,
    "PopupBlocking": { "Default": true, "Locked": true },
    "EnableTrackingProtection": { "Value": true, "Locked": true, "Cryptomining": true, "Fingerprinting": true },
    "Preferences": {
      "privacy.donottrackheader.enabled": { "Value": true, "Status": "locked" },
      "dom.disable_open_during_load": { "Value": true, "Status": "locked" },
      "app.update.auto": { "Value": true, "Status": "locked" }
    }
  }
}
'@
    Set-Content -Path "$dir\policies.json" -Value $json -Encoding UTF8
    Ok "policies.json written. Restart Firefox and verify at about:policies."
}

# ---------- menu ----------
while ($true) {
    Write-Host "`n=== CyberPatriot Quick Tool ===" -ForegroundColor Green
    Write-Host "1.  Audit Users"
    Write-Host "2.  Audit Password Policies"
    Write-Host "3.  Security Settings"
    Write-Host "4.  Firewall Settings"
    Write-Host "5.  Audit Policy"
    Write-Host "6.  Remote Desktop"
    Write-Host "7.  Shares"
    Write-Host "8.  Services & Protocols"
    Write-Host "9.  Updates & System Integrity"
    Write-Host "10. Windows Defender"
    Write-Host "11. Startup / Tasks / Processes"
    Write-Host "12. Prohibited Software"
    Write-Host "13. Hidden Files & Media"
    Write-Host "14. Find File By Hash"
    Write-Host "15. Firefox Hardening"
    Write-Host "0.  Exit"
    $choice = (Read-Host "Select an option (0-15)").Trim()

    switch ($choice) {
        '1'  { auditUsers }
        '2'  { SecPol }
        '3'  { security }
        '4'  { firewall }
        '5'  { auditPolicy }
        '6'  { rdp }
        '7'  { shares }
        '8'  { services }
        '9'  { updates }
        '10' { defender }
        '11' { persistence }
        '12' { software }
        '13' { media }
        '14' { findHash }
        '15' { firefox }
        '0'  { Write-Host "Exiting the tool. Goodbye!" -ForegroundColor Green; exit }
        default { Write-Host "Invalid option. Choose 0-15." -ForegroundColor Red }
    }
}
