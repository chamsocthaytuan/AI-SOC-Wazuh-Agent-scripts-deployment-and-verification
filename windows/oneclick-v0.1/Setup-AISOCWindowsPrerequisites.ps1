#Requires -Version 5.1
[CmdletBinding()]
param(
 [switch]$Apply,
 [string]$ManagerIP='10.0.70.12',
 [string]$AgentName,
 [string]$WazuhMsiPath,
 [string]$SuricataMsiPath,
 [string]$NpcapInstallerPath,
 [string]$CaptureIPv4,
 [switch]$RepointExisting
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
function Fail([string]$text) { throw "SETUP_FAILED: $text" }
function Test-PendingRestart {
 $paths=@(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
 )
 foreach($path in $paths) {
  if(Test-Path -LiteralPath $path) { return $true }
 }
 $session=Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
 if($session -and $session.PendingFileRenameOperations) { return $true }
 return $false
}
function AgentRoot {
 $candidates=@(
  (Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'ossec-agent'),
  (Join-Path $env:ProgramFiles 'ossec-agent'))
 foreach($path in $candidates) { if(Test-Path (Join-Path $path 'ossec.conf')) { return $path } }
 return $null
}
function StorePassword([string]$root) {
 $file=Join-Path $root 'authd.pass'
 if(Test-Path $file) { Fail 'Existing authd.pass is preserved; refusing overwrite' }
 $secure=Read-Host 'Enrollment Password (hidden)' -AsSecureString
 $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
 try {
  $clear=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  if($clear.Length -lt 16) { Fail 'Enrollment password must be at least 16 characters' }
  [IO.File]::WriteAllText($file, ($clear + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
  $clear=$null
 } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
 & icacls.exe $file '/inheritance:r' '/grant:r' 'SYSTEM:(F)' 'Administrators:(F)' | Out-Null
 if($LASTEXITCODE -ne 0) { Fail 'Enrollment password ACL setup failed' }
 Write-Host 'PASSWORD_FILE_OK (secret hidden)'
}
function ManagerFromConfig([string]$path) {
 $source=[IO.File]::ReadAllText($path)
 $source=[regex]::Replace($source,'^\s*<\?xml[^>]*\?>','')
 [xml]$doc='<bundle>'+$source+'</bundle>'
 $nodes=@($doc.SelectNodes('/bundle/ossec_config/client/server/address'))
 if($nodes.Count -ne 1) { Fail 'Expected exactly one Wazuh Manager address' }
 return $nodes[0].InnerText.Trim()
}
function EnsureAgent {
 $root=AgentRoot
 if($root) {
  if($AgentName) { Fail 'Existing Agent identity must not be changed' }
  $cfg=Join-Path $root 'ossec.conf'
  $current=ManagerFromConfig $cfg
  if($current -ne $ManagerIP) {
   if(-not $RepointExisting) { Fail "Agent uses $current; to change it explicitly supply -RepointExisting" }
   $old=[IO.File]::ReadAllText($cfg)
   $pattern='(<client>\s*<server>\s*<address>)([^<]*)(</address>)'
   if([regex]::Matches($old,$pattern).Count -ne 1) { Fail 'Cannot safely modify nonstandard ossec.conf' }
   Copy-Item $cfg "$cfg.bak.aisoc.$(Get-Date -Format yyyyMMddHHmmss)"
   $new=[regex]::Replace($old,$pattern, ('$1'+$ManagerIP+'$3'))
   [IO.File]::WriteAllText($cfg,$new,(New-Object Text.UTF8Encoding($false)))
   Restart-Service WazuhSvc
  }
  $keys=Join-Path $root 'client.keys'
  if(-not(Test-Path $keys) -or (Get-Item $keys).Length -eq 0) {
   if(-not(Test-NetConnection $ManagerIP -Port 1515 -InformationLevel Quiet)) { Fail 'TCP 1515 enrollment unavailable' }
   if(Test-Path -LiteralPath (Join-Path $root 'authd.pass')) {
    Write-Host 'ENROLLMENT_PASSWORD_EXISTS: preserving saved credential for retry'
   } else { StorePassword $root }
   Restart-Service WazuhSvc
   Write-Host 'ENROLLMENT_STARTED'
  } else { Write-Host 'AGENT_EXISTS: retained client.keys and Agent Name' }
  return $root
 }
 if(-not $AgentName) { $script:AgentName=(Read-Host 'New Agent Name').Trim() }
 if($AgentName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') { Fail 'Invalid Agent Name' }
 if(-not(Test-NetConnection $ManagerIP -Port 1514 -InformationLevel Quiet) -or
    -not(Test-NetConnection $ManagerIP -Port 1515 -InformationLevel Quiet)) { Fail 'Manager TCP 1514/1515 unreachable' }
 if(Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue) {
  Fail 'WazuhSvc is already registered but ossec.conf was not found. Inspect the existing/partial installation; refusing a blind MSI reinstall.'
 }
 if(-not $WazuhMsiPath) {
  $WazuhMsiPath=Join-Path $env:TEMP 'wazuh-agent-4.8.2-1.msi'
  if(-not(Test-Path $WazuhMsiPath)) {
   Invoke-WebRequest 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.2-1.msi' -OutFile $WazuhMsiPath -UseBasicParsing
  }
 }
 if(-not(Test-Path $WazuhMsiPath)) { Fail 'Wazuh Agent 4.8.2 MSI unavailable' }
 $logDir=Join-Path $env:ProgramData 'AI-SOC\InstallerLogs'
 New-Item -ItemType Directory -Path $logDir -Force | Out-Null
 $msiLog=Join-Path $logDir ('wazuh-agent-4.8.2-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
 if(Test-PendingRestart) {
  Write-Warning 'Windows reports a pending restart; some Wazuh MSI builds may reject installation. Do not clear pending-reboot registry keys manually.'
 }
 # The /L*v MSI log is required to diagnose generic 1603 errors.
 # No enrollment password is passed on the MSI command line.
 $p=Start-Process msiexec.exe -ArgumentList @('/i',('"{0}"' -f $WazuhMsiPath),'/qn','/norestart',
  ('WAZUH_MANAGER="{0}"' -f $ManagerIP),('WAZUH_REGISTRATION_SERVER="{0}"' -f $ManagerIP),
  ('WAZUH_AGENT_NAME="{0}"' -f $AgentName),'/L*v',('"{0}"' -f $msiLog)) -Wait -PassThru
 Write-Host "WAZUH_MSI_EXIT: $($p.ExitCode)"
 Write-Host "WAZUH_MSI_LOG: $msiLog"
 switch ([int]$p.ExitCode) {
  0 { }
  3010 { throw "SETUP_PAUSED: Wazuh MSI succeeded but Windows requires a reboot (3010). Restart Windows, then run the OneClick installer again. MSI log: $msiLog" }
  1603 { Fail "Wazuh MSI failed with 1603 (fatal installation error, NOT a reboot code). Inspect MSI log for 'Return value 3' and 'LaunchConditions'; do not uninstall or delete Agent keys blindly. Log: $msiLog" }
  1618 { Fail "Another Windows Installer operation is running (1618). Finish that operation before retrying. Log: $msiLog" }
  default { Fail "Wazuh MSI failed with exit code $($p.ExitCode). Inspect log: $msiLog" }
 }
 $root=AgentRoot
 if(-not $root) { Fail 'Wazuh MSI returned success but Agent not detected' }
 Stop-Service WazuhSvc -ErrorAction SilentlyContinue
 StorePassword $root
 Start-Service WazuhSvc
 Write-Host 'ENROLLMENT_STARTED: new Agent'
 return $root
}
function EnsureSuricata {
 if(-not(Test-Path "$env:windir\System32\Npcap\wpcap.dll")) {
  if(-not $NpcapInstallerPath -or -not(Test-Path $NpcapInstallerPath)) {
   Fail 'Npcap mandatory: obtain licensed installer at https://npcap.com and pass -NpcapInstallerPath'
  }
  $p=Start-Process $NpcapInstallerPath -Wait -PassThru
  if($p.ExitCode -ne 0) { Fail "Npcap installer failed/reboot required: $($p.ExitCode)" }
 }
 $home=Join-Path $env:ProgramFiles 'Suricata'
 $exe=Join-Path $home 'suricata.exe'
 if(-not(Test-Path $exe)) {
  if($SuricataMsiPath) {
   if(-not(Test-Path $SuricataMsiPath)) { Fail 'Suricata MSI not found' }
   $p=Start-Process msiexec.exe -ArgumentList @('/i',('"{0}"' -f $SuricataMsiPath),'/qn','/norestart') -Wait -PassThru
   if($p.ExitCode -ne 0) { Fail "Suricata MSI failed/reboot required: $($p.ExitCode)" }
  } elseif(Get-Command winget -ErrorAction SilentlyContinue) {
   & winget install --id OISF.Suricata --exact --silent --accept-package-agreements --accept-source-agreements
   if($LASTEXITCODE -ne 0) { Fail 'winget could not install Suricata' }
  } else { Fail 'Suricata mandatory: pass official -SuricataMsiPath' }
 }
 if(-not(Test-Path $exe)) { Fail 'Suricata executable missing' }
 $yaml=Join-Path $home 'suricata.yaml'
 if(-not(Test-Path $yaml)) { Fail 'Suricata YAML missing' }
 & $exe -T -c $yaml
 if($LASTEXITCODE -ne 0) { Fail 'Suricata config/rules validation failed' }
 if(-not(Get-Service Suricata -ErrorAction SilentlyContinue)) {
  $ip=$CaptureIPv4
  if(-not $ip) {
   $choices=@(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address })
   if($choices.Count -ne 1) { Fail 'More than one capture interface. Use -CaptureIPv4.' }
   $ip=$choices[0].IPv4Address.IPAddress
  }
  & $exe -c $yaml -i $ip -l (Join-Path $home 'log') --service-install
  if($LASTEXITCODE -ne 0) { Fail 'Suricata Windows service install failed' }
 }
 Start-Service Suricata -ErrorAction SilentlyContinue
 if((Get-Service Suricata).Status -ne 'Running') { Fail 'Suricata service stopped' }
 foreach($eve in @((Join-Path $home 'log\eve.json'),'C:\Suricata\log\eve.json')) {
  if(Test-Path $eve) { Write-Host "SURICATA_OK: $eve"; return $eve }
 }
 Fail 'eve.json missing: check YAML default-log-dir and interface'
}
function AddSuricataLocalfile([string]$root,[string]$eve) {
 $cfg=Join-Path $root 'ossec.conf'
 $old=[IO.File]::ReadAllText($cfg)
 $text=[regex]::Replace($old,'^\s*<\?xml[^>]*\?>','')
 [xml]$doc='<bundle>'+$text+'</bundle>'
 foreach($item in @($doc.SelectNodes('/bundle/ossec_config/localfile'))) {
  if($item.location -eq $eve) {
   if($item.log_format -ne 'json') { Fail 'Suricata localfile log_format is not JSON' }
   Write-Host 'OSSEC_SURICATA_LOCALFILE_OK (unchanged)'
   return
  }
 }
 $index=$old.IndexOf('</ossec_config>')
 if($index -lt 0) { Fail 'Wazuh ossec.conf tag not found' }
 $nl=[Environment]::NewLine
 $block='  <localfile>'+$nl+'    <log_format>json</log_format>'+$nl+'    <location>'+$eve+'</location>'+$nl+'  </localfile>'+$nl
 Copy-Item $cfg "$cfg.bak.aisoc.$(Get-Date -Format yyyyMMddHHmmss)"
 [IO.File]::WriteAllText($cfg,$old.Insert($index,$block),(New-Object Text.UTF8Encoding($false)))
 Restart-Service WazuhSvc
 Write-Host 'OSSEC_SURICATA_LOCALFILE_OK'
}
try {
 $ip=[Net.IPAddress]::Parse($ManagerIP)
 if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { Fail 'IPv4 required' }
} catch { Fail 'Invalid Manager IPv4' }
if(-not $Apply) {
 Write-Host "PREVIEW_WINDOWS: Lab Server=$ManagerIP; Wazuh 4.8.2, Npcap, Suricata and EVE required."
 Write-Host 'No changes made; Agent Name/password only requested for unregistered Agent.'
 return
}
$identity=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'Administrator required' }
$root=EnsureAgent
$eve=EnsureSuricata
AddSuricataLocalfile $root $eve
Write-Host 'WINDOWS_PREREQUISITES_OK (not Verification V2 E2E)'
