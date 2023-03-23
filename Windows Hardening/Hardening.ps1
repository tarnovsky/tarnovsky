#Function to enable RDP through WMI
param ($ad, $changeAdmin)

function Enable-RDP
{
    param (
        $machine,
        $cred
    )
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $machine
    $s = New-PSSession -ComputerName $machine -Credential $cred
    Invoke-Command -Session $s -Scriptblock {Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name "fDenyTSConnections" -value 0; Enable-NetFirewallRule -DisplayGroup "Remote Desktop"}
    Remove-PSSession $s
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value ""
}

#Enable firewall for all profiles
function Enable-Firewall
{
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

#Disable the guest account
function Disable-Guest
{
    Disable-LocalUser -Name "Guest"
    Disable-ADAccount -Identify "Guest"
}

#Enable strong password policy
function Enable-PasswordPolicy
{
    net accounts /maxpwage:42
    net accounts /minpwlen:15
     net accounts /uniquepw:10
}


#Disable NetBIOS and LMHosts
function Disable-NetBIOSLMHosts
{
    $NICS = Get-WmiObject win32_NetworkAdapterConfiguration
    foreach ($NIC in $NICS)
    {
        $NIC.settcpipnetbios(2)
        $NIC.enablewins($false,$false)
    }
}

function Import-AuditGPO
{
    $domain = Get-ADDomain
    $loc = Get-ChildItem | where {$_.Name -Contains "backups"}
    New-GPO -Name "Audit"
    Import-GPO -BackupID "83B737F7-FFB9-434E-B067-881245F539E6" -TargetName "Audit" -Path $loc.FullName
    New-GPLink -Target $domain.DistinguishedName -Name "Audit" -LinkEnabled yes -Enforced yes
}

function Import-NameChangeGPO
{
    $domain = Get-ADDomain
    $loc = Get-ChildItem | where {$_.Name -Contains "backups"}
    New-GPO -Name "NameChange"
    Import-GPO -BackupID "47E734EC-A7D0-46D8-AA4D-6E6EF2383C5E" -TargetName "NameChange" -Path $loc.FullName
    New-GPLink -Target $domain.DistinguishedName -Name "NameChange" -LinkEnabled yes -Enforced yes
}

function Import-UserRightsGPO
{
    $domain = Get-ADDomain
    $loc = Get-ChildItem | where {$_.Name -Contains "backups"}
    New-GPO -Name "UserRights"
    Import-GPO -BackupID "60D1DF7A-9AB1-44B2-93C6-1867C6D50BF1" -TargetName "UserRights" -Path $loc.FullName
    New-GPLink -Target $domain.DistinguishedName -Name "UserRights" -LinkEnabled yes -Enforced yes
}

function Import-SecurityGPO
{
    $domain = Get-ADDomain
    $loc = Get-ChildItem | where {$_.Name -Contains "backups"}
    New-GPO -Name "LS"
    Import-GPO -BackupID "B5823E6E-77EF-4009-B1C1-29FE920184CE" -TargetName "LS" -Path $loc.FullName
    New-GPLink -Target $domain.DistinguishedName -Name "LS" -LinkEnabled yes -Enforced yes
}

function Import-SMBGPO
{
    $domain = Get-ADDomain
    $loc = Get-ChildItem | where {$_.Name -Contains "backups"}
    New-GPO -Name "SMB"
    Import-GPO -BackupID "0B936572-8291-4926-BB41-9740BAE37DCE" -TargetName "SMB" -Path $loc.FullName
    New-GPLink -Target $domain.DistinguishedName -Name "SMB" -LinkEnabled yes -Enforced yes
}

#Calls all functions for AD
function HardenAD
{
    Expand-Archive -Path backups.zip
    Disable-NetBIOSLMHosts

    if($changeAdmin.ToLower() -eq "yes")
    {
        Write-Host "Changing default admin name"
        Import-NameChangeGPO
    }

    Import-SecurityGPO
    Import-AuditGPO
    Import-UserRightsGPO
    Import-SMBGPO
}

#Calls all functions for a Windows machine
function HardenMachine
{
    Disable-NetBIOSLMHosts
    
    & $PSScriptRoot\securityGPO.ps1
    & $PSScriptRoot\auditGPO.ps1
    & $PSScriptRoot\userRightsGPO.ps1

    Remove-Item "DSCFromGPO" -Recurse
}

if(!$changeAdmin -or !$ad)
{
    Write-Host "Usage: .\hardening -ad (yes/no) -changeAdmin (yes/no)"
    exit
}
 
if(($ad.ToLower() -ne "yes" -and $ad.ToLower() -ne "no") -or ($changeAdmin.ToLower() -ne "yes" -and $changeAdmin.ToLower() -ne "no"))
{
    Write-Host "Usage: .\hardening -ad (yes/no) -changeAdmin (yes/no)"
    exit
}

if ($ad.ToLower() -eq "yes")
{
    Write-Host "Running HardenAD"
    HardenAD
    Write-Host "Review errors (if any exist) and delete backups.zip, the created backups folder, and this script"
}
elseif ($ad.ToLower() -eq "no")
{
    Write-Host "Running HardenMachine"
    Install-Module BaselineManagement -Force
    Install-Module -Name SecurityPolicyDsc -Force
    Install-Module -Name AuditPolicyDsc -Force
    HardenMachine
    New-NetFirewallRule -DisplayName "Enable SMB" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow

    Write-Host "Review errors (if any exist) and delete this script"
}

