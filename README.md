# OpenVPN Windows MSI textual-prefix ACL PoC

<img width="1466" height="1022" alt="image" src="https://github.com/user-attachments/assets/85b71501-6ef3-4899-82f7-d845552964e4" />


This proof of concept demonstrates a Windows installation-path ACL issue in the
official OpenVPN `2.7.8-I002` amd64 MSI.

The installer classifies a custom path as being under Program Files by using a
textual prefix comparison without a path-component boundary. Consequently,
this sibling path is classified as if it were a Program Files descendant:

```text
C:\Program Files-PrefixCollision\OpenVPN
```

A standard user can create that installation root before installation. When an
administrator later installs OpenVPN into it, the intended ACL correction for
a non-default installation path is skipped and the user retains write access
to the installed service image. Replacing that stopped image and subsequently
starting `OpenVPNServiceInteractive` executes the replacement as LocalSystem.

## Files

- `Invoke-OpenVpnPrefixAclLocalSystemPoC.ps1` - four-phase reproduction and
  validation
- `OpenVpnLocalSystemServiceMarker.c` - fixed, bounded Windows service marker

The marker records only its process ID, account name, SID, and fixed service
name. It performs no network communication, starts no child process or shell,
consumes no caller-supplied payload data, and stops after at most 60 seconds.

## Tested input

The PoC accepts only the official OpenVPN `2.7.8-I002` amd64 MSI with a valid
OpenVPN Inc. Authenticode signature and this SHA-256 digest:

```text
33104DD02C48CBA172612882B1AF6276422B1B4340D4C9C84DD2AFB4B356FE9F
```

## Requirements

- a clean, disposable, network-disconnected 64-bit Windows VM;
- 64-bit Windows PowerShell 5.1;
- one local administrator and one local standard-user account; and
- an x64 MinGW-w64 compiler for building the marker.

Run `Prepare` and `Replace` as the same standard user. Run `Install` and
`Observe` from an elevated administrator session. All four phases must run in
the same disposable VM.

## Build

From this directory, compile the fixed marker:

```powershell
& 'C:\mingw64\bin\gcc.exe' -std=c11 -O2 -Wall -Wextra -Werror `
    -static-libgcc -fno-ident -s `
    '-Wl,--no-insert-timestamp,--dynamicbase,--nxcompat,--high-entropy-va' `
    -o '.\OpenVpnLocalSystemServiceMarker.exe' `
    '.\OpenVpnLocalSystemServiceMarker.c' -ladvapi32
```

## Reproduce

```powershell
# 1. Standard user: create the textual-sibling installation root.
& '.\Invoke-OpenVpnPrefixAclLocalSystemPoC.ps1' -Phase Prepare

# 2. Elevated administrator: verify and install the pinned MSI.
& '.\Invoke-OpenVpnPrefixAclLocalSystemPoC.ps1' -Phase Install `
    -MsiPath 'C:\Lab\OpenVPN-2.7.8-I002-amd64.msi'

# 3. The same standard user: prove marker denial and replace the stopped image.
& '.\Invoke-OpenVpnPrefixAclLocalSystemPoC.ps1' -Phase Replace `
    -PayloadPath '.\OpenVpnLocalSystemServiceMarker.exe'

# 4. Elevated administrator: perform one legitimate service start and observe.
& '.\Invoke-OpenVpnPrefixAclLocalSystemPoC.ps1' -Phase Observe
```

## Successful result

The final phase returns:

```text
outcome : LOCALSYSTEM_SERVICE_IMAGE_CODE_EXECUTION_OBSERVED
```

That result binds the following observations:

1. the standard user cannot open the protected marker for writing;
2. the same user replaces the exact stopped service image in place while its
   file identity and security descriptor remain unchanged;
3. the replacement process ID matches the Service Control Manager's process ID
   for `OpenVPNServiceInteractive`;
4. the marker and an independent process-owner query both report LocalSystem
   SID `S-1-5-18`; and
5. the original signed OpenVPN image is restored with its original SHA-256,
   file identity, and security descriptor.

The normalized final record is written to:

```text
C:\ProgramData\OpenVPNPrefixAclLocalSystemPoC\result.json
```

`Observe` stops and disables both OpenVPN services and restores the vendor
service image. It does not uninstall OpenVPN or remove the PoC directories;
discard the disposable VM after collecting the result.

> [!CAUTION]
> **LEGAL AND TECHNICAL DISCLAIMER**
>
> This code is for controlled research and analysis. The author assumes no liability for damages, system instability, or legal consequences arising from use or misuse of this software.
