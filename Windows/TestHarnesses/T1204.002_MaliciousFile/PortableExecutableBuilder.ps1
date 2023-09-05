function New-ATHPortableExecutableRunner {
<#
.SYNOPSIS

Builds an EXE or DLL that executes supplied PowerShell code dynamically.

Technique ID: T1204.002 (User Execution: Malicious File)

.DESCRIPTION

New-ATHPortableExecutableRunner

.PARAMETER FilePath

Specifies the path to the EXE or DLL to be generated. By default, New-ATHPortableExecutableRunner will generate an EXE unless an -ExportFunctionName argument is supplied. New-ATHPortableExecutableRunner can also be used to specify version info resource and signature information.

Relevant MITRE ATT&CK IDs:
1. T1204.002 - User Execution: Malicious File
2. T1129 - Shared Modules
3. T1036.001 - Masquerading: Invalid Code Signature

Note: When New-ATHPortableExecutableRunner signs the generated file, the certificate chain will not validate because the self-signed root certificate will not be trusted. New-ATHPortableExecutableRunner is not designed to subvert code signing validation.

.PARAMETER Dll

Specifies that a DLL should be built. When this switch is not specified, an EXE is built by default.

.PARAMETER ExportFunctionName

Specifies an export function name for the DLL to be generated. When this export function is called, it will execute the embedded PowerShell code.

.PARAMETER ExportOrdinal

Specifies an export ordinal for the DLL to be generated. If -ExportOrdinal is not specified, 1 will be used as the ordinal for the exported function.

.PARAMETER ScriptBlock

Specifies PowerShell code that will be embedded within the built executable. When the executable runs, this PowerShell code will execute. When -ScriptBlock is not supplied, a default scriptblock is used that will spawn a child powershell process with the TestGuid in the command-line. The TestGuid in the command-line is to validate that the executable was built and executes successfully.

.PARAMETER TemplateFilePath

Specifies a portable executable file from which its version info resource and optionally, signer information will be cloned (when -SignFile is supplied).

.PARAMETER OriginalFilename

Specifies the original name of the file, not including a path. This information enables an application to determine whether a file has been renamed by a user.

.PARAMETER InternalName

Specifies the internal name of the file.

.PARAMETER CompanyName

Specifies the company that produced the file.

.PARAMETER FileDescription

Specifies the file description to be presented to users.

.PARAMETER ProductVersion

Specifies the version of the product with which the file is distributed

.PARAMETER ProductName

Specifies the product name of the file.

.PARAMETER SignFile

Indicates that the generated file should be signed with a custom self-signed certificate.

.PARAMETER CertSigner

Specifies the common name for the signing certificate. "Atomic Endpoint Behavior" is used if -CertSigner is not supplied.

.PARAMETER CertIssuer

Specifies the common name for the issuing certificate. "Atomic Endpoint Behavior Root" is used if -CertIssuer is not supplied.

.PARAMETER CertSerialNumber

Specifies the certificate serial number of the signing certificate. This must be a hexidecimal string consisting of 1-20 bytes. "11223344556677889900AABBCCDDEEFF112233" is the default serial number if -CertSerialNumber is not supplied.

.PARAMETER CertCreationTime

Specifies the creation date/time of the signing certificate. The current date/time is used if -CertCreationTime is not supplied.

.PARAMETER CertExpirationTime

Specifies the expiration date/time of the signing certificate. Three years after the current date/time is used if -CertExpirationTime is not supplied.

.PARAMETER TestGuid
    
Optionally, specify a test GUID value to use to override the generated test GUID behavior. 

.EXAMPLE

New-ATHPortableExecutableRunner -FilePath runner.exe -ScriptBlock { [Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[Windows.Forms.MessageBox]::Show('Hello!','WARNING') }

.EXAMPLE

New-ATHPortableExecutableRunner -FilePath runner.dll -Dll -ExportFunctionName RunMe -ScriptBlock { [Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[Windows.Forms.MessageBox]::Show('Hello!','WARNING') }

.EXAMPLE

New-ATHPortableExecutableRunner -FilePath runner.exe -OriginalFilename foo.exe -InternalName bar.exe -CompanyName 'Contoso Inc.' -ProductVersion 1.2.3.4 -FileDescription 'Message box popup utility' -ScriptBlock { [Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[Windows.Forms.MessageBox]::Show('Hello!','WARNING') }

.EXAMPLE

New-ATHPortableExecutableRunner -FilePath runner.exe -OriginalFilename foo.exe -InternalName bar.exe -CompanyName 'Contoso Inc.' -ProductVersion 1.2.3.4 -FileDescription 'Message box popup utility' -SignFile -CertSigner 'Contoso Inc.' -CertIssuer 'Contoso Root Certification Agency (DO NOT TRUST)' -ScriptBlock { [Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[Windows.Forms.MessageBox]::Show('Hello!','WARNING') }

.EXAMPLE

Get-Item C:\Windows\System32\kernel32.dll | New-ATHPortableExecutableRunner -FilePath kernel32.dll -Dll -ExportFunctionName LoadLibraryExW -SignFile
rundll32 "$PWD\kernel32.dll", LoadLibraryExW

Clones kernel32.dll using its version info resource and signer information to emulate the "look and feel" of an existing PE file.

.EXAMPLE

Get-Item C:\Windows\System32\notepad.exe | New-ATHPortableExecutableRunner -FilePath notepad.exe

Clones the version info resource of notepad.exe.

.OUTPUTS

PSObject

Outputs an object consisting of relevant executable details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* TestGuid - Specifies the test GUID that was used for the test. This property is only populated when no scriptblock is supplied.
* PEFilePath - Specifies the full path to the generated executable.
* PEType - Specifies the type of executable generated: Exe or Dll.
* PEHashMD5 - Specifies the MD5 hash of the generated executable.
* PEHashSHA1 - Specifies the SHA1 hash of the generated executable.
* PEHashSHA256 - Specifies the SHA256 hash of the generated executable.
* EmbeddedScriptblock - Specifies the PowerShell scriptblock that was embedded in the generated executable.
* DllExportFunction - Specifies the implemented DLL export function. This field will only be populated when -Dll is specified.
* DllExportOrdinal - Specifies the implemented DLL export ordinal. This field will only be populated when -Dll is specified.
* VersionInfoResourcePresent - Indicates the the executable was built with a version info resource.
* OriginalFilename - Specifies the original filename present in the generated executable.
* InternalName - Specifies the internal name present in the generated executable.
* CompanyName - Specifies the company name present in the generated executable.
* FileDescription - Specifies the file description present in the generated executable.
* ProductVersion - Specifies the product version present in the generated executable.
* ProductName - Specifies the product name present in the generated executable.
* IsSigned - Indicates the the executable was signed.
* CertSigner - Specifies the common name of the signing certificate used to sign the generated executable.
* CertThumbprint - Specifies the SHA1 hash (thumbprint) of the signing certificate.
* CertSerialNumber - Specifies the serial number of the signing certificate.
* CertCreation - Specifies the creation date/time of the signing certificate.
* CertExpiration - Specifies the expiration date/time of the signing certificate.
* CertIssuer - Specifies the common name of the issuing certificate used to sign the signing certificate.
* CertIssuerThumbprint - Specifies the SHA1 hash (thumbprint) of the issuing certificate.
* TempResFilePath - Specifies the full path to the temporary .res file that was generated that was used to supply ilasm.exe with a version info resource.
* TempILFilePath - Specifies the full path to the temporary .NET assembly listing file that was used to supply ilasm.exe with the code that the generated executable will execute.
#>

    [CmdletBinding(DefaultParameterSetName = 'Exe')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Exe')]
        [Parameter(Mandatory, ParameterSetName = 'Dll')]
        [Parameter(Mandatory, ParameterSetName = 'SignExe')]
        [Parameter(Mandatory, ParameterSetName = 'SignDll')]
        [Parameter(Mandatory, ParameterSetName = 'ExeTemplate')]
        [Parameter(Mandatory, ParameterSetName = 'DllTemplate')]
        [String]
        $FilePath,

        [Parameter(Mandatory, ParameterSetName = 'Dll')]
        [Parameter(Mandatory, ParameterSetName = 'SignDll')]
        [Parameter(Mandatory, ParameterSetName = 'DllTemplate')]
        [Switch]
        $Dll,

        [Parameter(ParameterSetName = 'Dll')]
        [Parameter(ParameterSetName = 'SignDll')]
        [Parameter(ParameterSetName = 'DllTemplate')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ExportFunctionName = 'RunMe',

        [Parameter(ParameterSetName = 'Dll')]
        [Parameter(ParameterSetName = 'SignDll')]
        [Parameter(ParameterSetName = 'DllTemplate')]
        [UInt16]
        $ExportOrdinal = 1,

        [Parameter(ParameterSetName = 'Exe')]
        [Parameter(ParameterSetName = 'Dll')]
        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [Parameter(ParameterSetName = 'ExeTemplate')]
        [Parameter(ParameterSetName = 'DllTemplate')]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Mandatory, ParameterSetName = 'ExeTemplate', ValueFromPipelineByPropertyName)]
        [Parameter(Mandatory, ParameterSetName = 'DllTemplate', ValueFromPipelineByPropertyName)]
        [String]
        [ValidateNotNullOrEmpty()]
        [Alias('FullName')]
        $TemplateFilePath,

        [Parameter(ParameterSetName = 'Exe')]
        [Parameter(ParameterSetName = 'Dll')]
        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [String]
        [ValidateNotNullOrEmpty()]
        $OriginalFilename,

        [Parameter(ParameterSetName = 'Exe')]
        [Parameter(ParameterSetName = 'Dll')]
        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [String]
        [ValidateNotNullOrEmpty()]
        $InternalName,

        [Parameter(ParameterSetName = 'Exe')]
        [Parameter(ParameterSetName = 'Dll')]
        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [String]
        [ValidateNotNullOrEmpty()]
        $CompanyName,

        [Parameter(ParameterSetName = 'Exe')]
        [Parameter(ParameterSetName = 'Dll')]
        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [String]
        [ValidateNotNullOrEmpty()]
        $FileDescription,

        [Parameter(ParameterSetName = 'Exe')]
        [Parameter(ParameterSetName = 'Dll')]
        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ProductVersion,

        [Parameter(ParameterSetName = 'Exe')]
        [Parameter(ParameterSetName = 'Dll')]
        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ProductName,

        [Parameter(Mandatory, ParameterSetName = 'SignExe')]
        [Parameter(Mandatory, ParameterSetName = 'SignDll')]
        [Parameter(ParameterSetName = 'ExeTemplate')]
        [Parameter(ParameterSetName = 'DllTemplate')]
        [Switch]
        $SignFile,

        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [String]
        [ValidateNotNullOrEmpty()]
        $CertSigner = 'Atomic Endpoint Behavior',

        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [String]
        [ValidateNotNullOrEmpty()]
        $CertIssuer = 'Atomic Endpoint Behavior Root',

        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [String]
        [ValidatePattern('^([0-9A-F]{2}){1,20}$')]
        $CertSerialNumber = '11223344556677889900AABBCCDDEEFF112233',

        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [DateTime]
        $CertCreationTime = (Get-Date),

        [Parameter(ParameterSetName = 'SignExe')]
        [Parameter(ParameterSetName = 'SignDll')]
        [DateTime]
        $CertExpirationTime = ((Get-Date).AddYears(3)),

        [Guid]
        $TestGuid = (New-Guid)
    )

    $ParentDir = Split-Path -Path $FilePath -Parent
    $FileName = Split-Path -Path $FilePath -Leaf

    if (($ParentDir -eq '') -or ($ParentDir -eq '.')) {
        # Only a file name was supplied. Use the current directory to drop the executable.
        $ResolvedFilePath = Join-Path -Path $PWD -ChildPath $FilePath
        $ParentDir = $PWD
    } else {
        # A directory was supplied. Validate that it exists.
        if ((Test-Path -Path $ParentDir -PathType Container) -eq $False) {
            Write-Error "The directory supplied does not exist: $ParentDir"
            return
        }

        $ResolvedFilePath = Join-Path -Path $ParentDir -ChildPath $FileName
        $ParentDir = Resolve-Path -Path $ParentDir
    }

    $ExtIndex = $FileName.LastIndexOf('.')

    if ($ExtIndex -eq -1) {
        # An extension wasn't supplied for the filename. Use the filename as the assembly name.
        $AssemblyName = $FileName
    } else {
        $AssemblyName = $FileName.Substring(0, $ExtIndex)
    }

    # Filename of the temporary file that will be dropped consisting of the .NET assembly listing to be assembled.
    $ILFilePath = Join-Path -Path $ParentDir -ChildPath "$AssemblyName.il"

    # Filename of the resource file that will be generated and dropped that ilasm.exe will consume so that it can emit a version info resource in the resulting executable.
    $ResFilePath = Join-Path -Path $ParentDir -ChildPath "$AssemblyName.res"

    # Resolve the .NET runtime directory and validate that ilasm.exe is present. New-ATHPortableExecutableRunner requires ilasm.exe in order to generate an EXE or DLL in a dynamic fashion.
    $RuntimeDir = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    $ILAsmPath = Join-Path -Path $RuntimeDir -ChildPath 'ilasm.exe'

    if (-not (Test-Path -Path $ILAsmPath -PathType Leaf)) {
        Write-Error "ilasm.exe does not exist in the expected directory: $RuntimeDir"
        return
    }

    $BuildResFile = $False

    if ($OriginalFilename -or $InternalName -or $CompanyName -or $FileDescription -or $ProductVersion -or $TemplateFilePath) { $BuildResFile = $True }

    if (@('ExeTemplate', 'DllTemplate') -contains $PSCmdlet.ParameterSetName) {
        if (-not (Test-Path -Path $TemplateFilePath -PathType Leaf)) {
            Write-Error 'The supplied path to the PE file consisting of the version info resource properties to clone does not exist.'
            return
        }
    }

    $TestGuidToUse = $null

    if (-not $ScriptBlock) {
        $TestGuidToUse = $TestGuid
        $ScriptBlockToUse = [ScriptBlock]::Create("powershell.exe --% -nop -Command Write-Host $TestGuidToUse; Start-Sleep -Seconds 5; exit")
        
    } else {
        $ScriptBlockToUse = $ScriptBlock
    }

    # Assume the PE to be built is an EXE unless an export name or ordinal is supplied.
    $Directive = '.entrypoint'
    $PEType = 'Exe'

    $DllExportFunction = $null
    $DllExportOrdinal = $null

    if ($Dll) {
        $PEType = 'Dll'

        $DllExportFunction = $ExportFunctionName
        $DllExportOrdinal = $ExportOrdinal

        $Directive = ".export [$($ExportOrdinal)] as $ExportFunctionName"
    }

    # Unicode encode and base 64 encode the supplied PowerShell scriptblock for embedding into the assembly listing below.
    $ScriptBlockEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ScriptBlockToUse.ToString()))

    Write-Verbose "Encoded Scriptblock: $ScriptBlockEncoded"

    $DotNetDisassemblyListingTemplate = @"
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )
  .ver 4:0:0:0
}
.assembly extern System.Management.Automation
{
  .publickeytoken = (31 BF 38 56 AD 36 4E 35 )
  .ver 3:0:0:0
}

.assembly AtomicEndpointBehavior
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilationRelaxationsAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 )
  .custom instance void [mscorlib]System.Runtime.CompilerServices.RuntimeCompatibilityAttribute::.ctor() = ( 01 00 01 00 54 02 16 57 72 61 70 4E 6F 6E 45 78   // ....T..WrapNonEx
                                                                                                             63 65 70 74 69 6F 6E 54 68 72 6F 77 73 01 )       // ceptionThrows.
  .hash algorithm 0x00008004
  .ver 0:0:0:0
}

.module AtomicEndpointBehavior.$($PEType.ToLower())
.imagebase 0x10000000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00000001    //  ILONLY

.class private auto ansi beforefieldinit Test
       extends [mscorlib]System.Object
{
  .method public hidebysig static void  Main() cil managed
  {
    $Directive
    .maxstack  3
    .locals init (class [System.Management.Automation]System.Management.Automation.PowerShell V_0)
    IL_0000:  call       class [System.Management.Automation]System.Management.Automation.PowerShell [System.Management.Automation]System.Management.Automation.PowerShell::Create()
    IL_0005:  stloc.0
    IL_0006:  ldloc.0
    IL_0007:  call       class [mscorlib]System.Text.Encoding [mscorlib]System.Text.Encoding::get_Unicode()
    IL_000c:  ldstr      "$($ScriptBlockEncoded)"
    IL_0011:  call       uint8[] [mscorlib]System.Convert::FromBase64String(string)
    IL_0016:  callvirt   instance string [mscorlib]System.Text.Encoding::GetString(uint8[])
    IL_001b:  ldc.i4.1
    IL_001c:  callvirt   instance class [System.Management.Automation]System.Management.Automation.PowerShell [System.Management.Automation]System.Management.Automation.PowerShell::AddScript(string,
                                                                                                                                                                                               bool)
    IL_0021:  callvirt   instance class [mscorlib]System.Collections.ObjectModel.Collection``1<class [System.Management.Automation]System.Management.Automation.PSObject> [System.Management.Automation]System.Management.Automation.PowerShell::Invoke()
    IL_0026:  pop
    IL_0027:  ret
  }

  .method public hidebysig specialname rtspecialname
          instance void  .ctor() cil managed
  {
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  }
}
"@

    # Drop the dynamically generated .il file to be assembled
    Out-File -FilePath $ILFilePath -Encoding utf8 -InputObject $DotNetDisassemblyListingTemplate -ErrorAction Stop

    $ILAsmCommandLineArgs = New-Object -TypeName 'System.Collections.Generic.List[String]'

    $ILAsmCommandLineArgs.Add('/NOLOGO')
    $ILAsmCommandLineArgs.Add('/QUIET')

    switch ($PEType) {
        'Exe' { $ILAsmCommandLineArgs.Add('/EXE') }
        'Dll' { $ILAsmCommandLineArgs.Add('/DLL') }
    }

    if ($BuildResFile) {
        if ($TemplateFilePath) {
            $FileInfo = Get-Item -Path $TemplateFilePath -ErrorAction Stop

            # There is a chance for version info inconsistency if the executable has a localized resource MUI directory in the same path as the executable.
            # If the file has a hardlink, follow that as the target path is unlikely to have a localized MUI directory there.
            if ($FileInfo.Target) {
                [Diagnostics.FileVersionInfo] $VersionInfo = Get-Item -Path $FileInfo.Target[0] -ErrorAction Stop | Select-Object -ExpandProperty VersionInfo
            } else {
                [Diagnostics.FileVersionInfo] $VersionInfo = Get-Item -Path $TemplateFilePath -ErrorAction Stop | Select-Object -ExpandProperty VersionInfo
            }

            $ResFileArguments = @{
                FilePath = $ResFilePath
                FileType = $PEType
            }

            if ($VersionInfo.OriginalFilename) { $ResFileArguments['OriginalFilename'] = $VersionInfo.OriginalFilename }
            if ($VersionInfo.FileDescription)   { $ResFileArguments['FileDescription'] = $VersionInfo.FileDescription }
            if ($VersionInfo.ProductVersion)    { $ResFileArguments['ProductVersion'] = $VersionInfo.ProductVersion }
            if ($VersionInfo.InternalName)      { $ResFileArguments['InternalName'] = $VersionInfo.InternalName }
            if ($VersionInfo.ProductName)       { $ResFileArguments['ProductName'] = $VersionInfo.ProductName }
            if ($VersionInfo.Comments)          { $ResFileArguments['Comments'] = $VersionInfo.Comments }
            if ($VersionInfo.CompanyName)       { $ResFileArguments['CompanyName'] = $VersionInfo.CompanyName }
            if ($VersionInfo.LegalCopyright)    { $ResFileArguments['LegalCopyright'] = $VersionInfo.LegalCopyright }
            if ($VersionInfo.LegalTrademarks)   { $ResFileArguments['LegalTrademarks'] = $VersionInfo.LegalTrademarks }
            if ($VersionInfo.PrivateBuild)      { $ResFileArguments['PrivateBuild'] = $VersionInfo.PrivateBuild }
            if ($VersionInfo.SpecialBuild)      { $ResFileArguments['SpecialBuild'] = $VersionInfo.SpecialBuild }
            if ($VersionInfo.ProductVersionRaw) { $ResFileArguments['ProductVersionRaw'] = $VersionInfo.ProductVersionRaw }
            if ($VersionInfo.FileVersionRaw)    { $ResFileArguments['FileVersionRaw'] = $VersionInfo.FileVersionRaw }

            if ($VersionInfo.FileVersion) {
                $ResFileArguments['FileVersion'] = $VersionInfo.FileVersion
            } else {
                $ResFileArguments['FileVersion'] =  ' '
            }
        } else {
            $ResFileArguments = @{
                FilePath = $ResFilePath
                FileType = $PEType
                FileVersion = ' ' # Supplying FileVersion addresses a bug in System.Diagnostics.FileVersionInfo where it doesn't display version info if the file version is not populated.
            }

            if ($OriginalFilename) { $ResFileArguments['OriginalFilename'] = $OriginalFilename }
            if ($InternalName)     { $ResFileArguments['InternalName'] = $InternalName }
            if ($CompanyName)      { $ResFileArguments['CompanyName'] = $CompanyName }
            if ($FileDescription)  { $ResFileArguments['FileDescription'] = $FileDescription }
            if ($ProductVersion)   { $ResFileArguments['ProductVersion'] = $ProductVersion }
            if ($ProductName)      { $ResFileArguments['ProductName'] = $ProductName }
        }

        # Build the .red file that will be used to emit the version info resource
        $null = New-VersionInfoResourceFile @ResFileArguments -ErrorAction Stop

        $ILAsmCommandLineArgs.Add("/RESOURCE=`"$ResFilePath`"")
    }

    $ILAsmCommandLineArgs.Add("/OUTPUT=`"$ResolvedFilePath`"")
    $ILAsmCommandLineArgs.Add("`"$ILFilePath`"")

    $ILAsmCommandLine = "`"$ILAsmPath`" $($ILAsmCommandLineArgs -join ' ')"
    Write-Verbose "ILAsm.exe command-line: $ILAsmCommandLine"

    $ILAsmProcess = Start-Process -FilePath $ILAsmPath -ArgumentList $ILAsmCommandLineArgs -Wait -PassThru -NoNewWindow
    $ILAsmExitCode = $ILAsmProcess.ExitCode

    if ($ILAsmExitCode -ne 0) {
        Write-Error "ILAsm.exe returned a non-successful exit code: $ILAsmExitCode"
        return
    }

    $PEFileInfo = Get-Item -Path $ResolvedFilePath -ErrorAction Stop
    $HashMD5 = Get-FileHash -Path $PEFileInfo.FullName -Algorithm MD5 -ErrorAction Stop | Select-Object -ExpandProperty Hash
    $HashSha1 = Get-FileHash -Path $PEFileInfo.FullName -Algorithm SHA1 -ErrorAction Stop | Select-Object -ExpandProperty Hash
    $HashSha256 = Get-FileHash -Path $PEFileInfo.FullName -Algorithm SHA256 -ErrorAction Stop | Select-Object -ExpandProperty Hash

    $IsSigned = $False
    $CertSignerSubject = $null
    $CertSignerThumbprint = $null
    $CertSignerSN = $null
    $CertCreation = $null
    $CertExpiration = $null
    $CertIssuerSubject = $null
    $CertIssuerThumbprint = $null
    $SkipSignedFile = $False

    if ($SignFile) {
        if ($TemplateFilePath) {
            # First see if the file has an embedded Authenticode signature. Get-Authenticode signature prefers catalog sigs first. Embedded sigs should be considered first, in my opinion.
            $FullTemplatePath = Resolve-Path -Path $TemplateFilePath -ErrorAction Stop

            $LeafCert = $null
            
            try {
                $LeafCert = [X509Certificate]::CreateFromSignedFile($FullTemplatePath.Path)
            } catch {}

            if (-not $LeafCert) {
                # Try to obtain a catalog signature from Get-AuthenticodeSignature
                $LeafCert = Get-AuthenticodeSignature -FilePath $FullTemplatePath -ErrorAction Stop | Select-Object -ExpandProperty SignerCertificate
            }

            if ($LeafCert) {
                # Build the certificate chain
                $CertChain = New-Object -TypeName Security.Cryptography.X509Certificates.X509Chain
                $null = $CertChain.Build($LeafCert)
                if ($CertChain.ChainContext) { $BuildSuccessful = $True }

                if ($BuildSuccessful) {
                    if ($CertChain.ChainElements.Count -lt 2) {
                        Write-Warning "There must be at least two certificates present in the certificate chain. `"$FilePath`" will not be signed."
                        $SkipSignedFile = $True
                    } else {
                        $IssuingCert = New-SelfSignedCertificate -CloneCert $CertChain.ChainElements[1].Certificate -SerialNumber $CertChain.ChainElements[1].Certificate.SerialNumber -NotBefore $CertChain.ChainElements[1].Certificate.NotBefore -NotAfter $CertChain.ChainElements[1].Certificate.NotAfter -CertStoreLocation 'Cert:\CurrentUser\My'
                        $LeafCert = New-SelfSignedCertificate -CloneCert $CertChain.ChainElements[0].Certificate -SerialNumber $CertChain.ChainElements[0].Certificate.SerialNumber -NotBefore $CertChain.ChainElements[0].Certificate.NotBefore -NotAfter $CertChain.ChainElements[0].Certificate.NotAfter -CertStoreLocation 'Cert:\CurrentUser\My' -Signer $IssuingCert

                        $CertIssuerSubject = $IssuingCert.DnsNameList[0].Unicode
                        $CertIssuerThumbprint = $IssuingCert.Thumbprint
                    }
                } else {
                    Write-Warning "Unable to build a certificate chain from `"$FullTemplatePath`". `"$FilePath`" will not be signed."
                    $SkipSignedFile = $True
                }
            } else {
                Write-Warning "`"$FullTemplatePath`" is not signed. `"$FilePath`" will not be signed."
                $SkipSignedFile = $True
            }
        } else {
            # Create an issuing certificate that will be used to sign the leaf certificate
            $IssuerCertificateArguments = @{
                Subject = "CN=$CertIssuer"
                Type = 'CodeSigningCert'
                KeySpec = 'Signature'
                KeyUsage = 'DigitalSignature', 'CertSign'
                NotBefore = $CertCreationTime
                NotAfter = $CertExpirationTime
                CertStoreLocation = 'Cert:\CurrentUser\My'
            }

            $IssuingCert = New-SelfSignedCertificate @IssuerCertificateArguments

            $CertIssuerSubject = $IssuingCert.DnsNameList[0].Unicode
            $CertIssuerThumbprint = $IssuingCert.Thumbprint

            $LeafCertificateArguments = @{
                Subject = "CN=$CertSigner"
                SerialNumber = $CertSerialNumber
                Type = 'CodeSigningCert'
                KeySpec = 'Signature'
                KeyUsage = 'DigitalSignature'
                NotBefore = $CertCreationTime
                NotAfter = $CertExpirationTime
                CertStoreLocation = 'Cert:\CurrentUser\My'
            }

            $LeafCert = New-SelfSignedCertificate @LeafCertificateArguments -Signer $IssuingCert
        }

        if (-not $SkipSignedFile) {
            $Signature = Set-AuthenticodeSignature -FilePath $PEFileInfo.FullName -Certificate $LeafCert

            $CertSignerSubject = $Signature.SignerCertificate.DnsNameList[0].Unicode
            $CertSignerThumbprint = $Signature.SignerCertificate.Thumbprint
            $CertSignerSN = $Signature.SignerCertificate.SerialNumber
            $CertCreation = $Signature.SignerCertificate.NotBefore
            $CertExpiration = $Signature.SignerCertificate.NotAfter

            $IsSigned = $True

            # Delete the signing certificates from the registry
            Remove-Item -Path "Cert:\CurrentUser\My\$($LeafCert.Thumbprint)"
            Remove-Item -Path "Cert:\CurrentUser\My\$($IssuingCert.Thumbprint)"
        }
    }

    [PSCustomObject] @{
        TechniqueID = 'T1204.002'
        TestGuid = $TestGuidToUse
        PEFilePath = $PEFileInfo.FullName
        PEType = $PEType
        PEHashMD5 = $HashMD5
        PEHashSHA1 = $HashSha1
        PEHashSHA256 = $HashSha256
        EmbeddedScriptblock = $ScriptBlockToUse
        DllExportFunction = $DllExportFunction
        DllExportOrdinal = $DllExportOrdinal
        VersionInfoResourcePresent = $BuildResFile
        OriginalFilename = $PEFileInfo.VersionInfo.OriginalFilename
        InternalName = $PEFileInfo.VersionInfo.InternalName
        CompanyName = $PEFileInfo.VersionInfo.CompanyName
        FileDescription = $PEFileInfo.VersionInfo.FileDescription
        ProductVersion = $PEFileInfo.VersionInfo.ProductVersion
        ProductName = $PEFileInfo.VersionInfo.ProductName
        IsSigned = $IsSigned
        CertSigner = $CertSignerSubject
        CertThumbprint = $CertSignerThumbprint
        CertSerialNumber = $CertSignerSN
        CertCreation = $CertCreation
        CertExpiration = $CertExpiration
        CertIssuer = $CertIssuerSubject
        CertIssuerThumbprint = $CertIssuerThumbprint
        TempResFilePath = $ResFilePath
        TempILFilePath = $ILFilePath
    }
}

# Helper function. Do not export
function New-VersionInfoResourceFile
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]
        $FilePath,

        [Parameter(Mandatory)]
        [String]
        [ValidateSet('Exe', 'Dll')]
        $FileType,

        [String]
        [ValidateNotNullOrEmpty()]
        $OriginalFilename,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileDescription,

        [String]
        [ValidateNotNullOrEmpty()]
        $ProductVersion,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileVersion,

        [String]
        [ValidateNotNullOrEmpty()]
        $InternalName,

        [String]
        [ValidateNotNullOrEmpty()]
        $ProductName,

        [String]
        [ValidateNotNullOrEmpty()]
        $Comments,

        [String]
        [ValidateNotNullOrEmpty()]
        $CompanyName,

        [String]
        [ValidateNotNullOrEmpty()]
        $LegalCopyright,

        [String]
        [ValidateNotNullOrEmpty()]
        $LegalTrademarks,

        [String]
        [ValidateNotNullOrEmpty()]
        $PrivateBuild,

        [String]
        [ValidateNotNullOrEmpty()]
        $SpecialBuild,

        [Version]
        $ProductVersionRaw,

        [Version]
        $FileVersionRaw
    )

    $ParentDir = Split-Path -Path $FilePath -Parent
    $FileName = Split-Path -Path $FilePath -Leaf

    if (($ParentDir -eq '') -or ($ParentDir -eq '.')) {
        # Only a file name was supplied. Use the current directory to drop the executable.
        $FullFilePath = Join-Path -Path $PWD -ChildPath $FilePath
    } else {
        # A directory was supplied. Validate that it exists.
        if ((Test-Path -Path $ParentDir -PathType Container) -eq $False) {
            Write-Error "The directory supplied does not exist: $ParentDir"
            return
        }

        $FullFilePath = Join-Path -Path $ParentDir -ChildPath $FileName
    }

    function New-StringStructure {
        [OutputType([Byte[]])]
        param (
            [Parameter(Mandatory)]
            [String]
            $Key,

            [Parameter(Mandatory)]
            [String]
            $Value
        )

        [Byte[]] $KeyBytes = [Text.Encoding]::Unicode.GetBytes("$Key`0")

        [Byte[]] $ValueBytes = [Text.Encoding]::Unicode.GetBytes("$Value`0")

        [UInt16] $WordCount = $ValueBytes.Length / 2

        [UInt16] $StringStructLength = 6 + $KeyBytes.Length + $ValueBytes.Length

        $InsertPadding = $False
        $AppendPadding = $False

        if (($Key.Length % 2) -eq 1) {
            # Pad to a DWORD boundary by appending two null bytes
            $InsertPadding = $True
            $StringStructLength += 2
        }

        if (($Value.Length % 2) -eq 0) {
            # Pad to a DWORD boundary by appending two null bytes
            $AppendPadding = $True
            $StringStructLength += 2
        }

        $StringStructBytes = New-Object -TypeName Byte[]($StringStructLength)

        $MemoryStream = New-Object -TypeName IO.MemoryStream
        $BinaryWriter = New-Object -TypeName IO.BinaryWriter($MemoryStream)

        $BinaryWriter.Write($StringStructLength) # wLength
        $BinaryWriter.Write($WordCount) # wValueLength: "The size, in words, of the Value member"
        $BinaryWriter.Write(([UInt16] 1)) # wType: 1 - "This member is 1 if the version resource contains text data"
        $BinaryWriter.Write($KeyBytes) # szKey
        if ($InsertPadding) {
            $BinaryWriter.Write(([UInt16] 0))
        }
        $BinaryWriter.Write($ValueBytes) # Value
        if ($AppendPadding) {
            $BinaryWriter.Write(([UInt16] 0))
        }

        $null = $MemoryStream.Seek(0, 'Begin')
        $null = $MemoryStream.Read($StringStructBytes, 0, $StringStructBytes.Length)

        $BinaryWriter.Close()
        $MemoryStream.Close()

        return $StringStructBytes
    }

    # Write the template RESOURCEHEADER header for the .res file
    [Byte[]] $ResFileHeader = @(
        0x00,0x00,0x00,0x00, # DataSize
        0x20,0x00,0x00,0x00, # HeaderSize
        0xFF,0xFF,0x00,0x00, # TYPE
        0xFF,0xFF,0x00,0x00, # NAME
        0x00,0x00,0x00,0x00, # DataVersion
        0x00,0x00,           # MemoryFlags
        0x00,0x00,           # LanguageId
        0x00,0x00,0x00,0x00, # Version
        0x00,0x00,0x00,0x00  # Characteristics
    )

    $MemoryStream = New-Object -TypeName IO.MemoryStream
    $BinaryWriter = New-Object -TypeName IO.BinaryWriter($MemoryStream)

    $BinaryWriter.Write($ResFileHeader, 0, $ResFileHeader.Length)

    # Start writing the next RESOURCEHEADER structure containing the version info resource.
    $BinaryWriter.Write(([UInt32] 0))       # DataSize: This will be written at the end when the total size is calculated
    $BinaryWriter.Write(([UInt32] 0x20))    # HeaderSize
    $BinaryWriter.Write([UInt16]::MaxValue) # Type
    $BinaryWriter.Write(([UInt16] 0x10))    # Type: RT_VERSION
    $BinaryWriter.Write([UInt16]::MaxValue) # Name
    $BinaryWriter.Write(([UInt16] 1))       # Name: ID - 1
    $BinaryWriter.Write(([UInt32] 0))       # DataVersion
    $BinaryWriter.Write(([UInt16] 0))       # MemoryFlags
    $BinaryWriter.Write(([UInt16] 0))       # LanguageId
    $BinaryWriter.Write(([UInt32] 0))       # Version
    $BinaryWriter.Write(([UInt32] 0))       # Characteristics

    # Start writing the VS_VERSIONINFO structure
    $BinaryWriter.Write(([UInt16] 0))    # wLength: This will be written at the end when the total size is calculated
    $BinaryWriter.Write(([UInt16] 0x34)) # wValueLength: 0x34 - length of the VS_FIXEDFILEINFO structure in the Value field To-do: update this accordingly
    $BinaryWriter.Write(([UInt16] 0))    # wType: 0 - "the version resource contains binary data"
    $KeyBytes = [Byte[]] @(0x56,0x00,0x53,0x00,0x5F,0x00,0x56,0x00,0x45,0x00,0x52,0x00,0x53,0x00,0x49,0x00,0x4F,0x00,0x4E,0x00,0x5F,0x00,0x49,0x00,0x4E,0x00,0x46,0x00,0x4F,0x00,0x00,0x00,0x00,0x00) # "VS_VERSION_INFO"
    $BinaryWriter.Write($KeyBytes, 0, $KeyBytes.Length) # szKey

    $BinaryWriter.Write(0xFEEF04BD) # dwSignature
    $BinaryWriter.Write(0x00010000) # dwStrucVersion
    if ($FileVersionRaw) {
        $BinaryWriter.Write(([UInt16] $FileVersionRaw.Minor))    # dwFileVersionMS
        $BinaryWriter.Write(([UInt16] $FileVersionRaw.Major))
        $BinaryWriter.Write(([UInt16] $FileVersionRaw.Revision)) # dwFileVersionLS
        $BinaryWriter.Write(([UInt16] $FileVersionRaw.Build))
    } else {
        $BinaryWriter.Write(([UInt64] 0))
    }
    if ($ProductVersionRaw) {
        $BinaryWriter.Write(([UInt16] $ProductVersionRaw.Minor)) # dwProductVersionMS
        $BinaryWriter.Write(([UInt16] $ProductVersionRaw.Major))
        $BinaryWriter.Write(([UInt16] $ProductVersionRaw.Revision)) # dwProductVersionLS
        $BinaryWriter.Write(([UInt16] $ProductVersionRaw.Build))
    } else {
        $BinaryWriter.Write(([UInt64] 0))
    }
    $BinaryWriter.Write(([UInt32] 0x3F)) # dwFileFlagsMask
    $BinaryWriter.Write(([UInt32] 0))    # dwFileFlags
    $BinaryWriter.Write(([UInt32] 4))    # dwFileOS: 4 - "The file was designed for 32-bit Windows."
    switch ($FileType) {
        'Exe' { $BinaryWriter.Write(([UInt32] 1)) }
        'Dll' { $BinaryWriter.Write(([UInt32] 2)) }
    }
    $BinaryWriter.Write(([UInt32] 0))    # dwFileSubtype
    $BinaryWriter.Write(([UInt32] 0))    # dwFileDateMS
    $BinaryWriter.Write(([UInt32] 0))    # dwFileDateLS

    # Write the VarFileInfo block, indicating the langID and charsetID of the resource.
    $BinaryWriter.Write(([UInt16] 0x44)) # wLength
    $BinaryWriter.Write(([UInt16] 0)) # wValueLength: "This member is always equal to zero."
    $BinaryWriter.Write(([UInt16] 1)) # wType: 1 - "1 if the version resource contains text data"
    $VarFileInfoString = [Byte[]] @(0x56,0x00,0x61,0x00,0x72,0x00,0x46,0x00,0x69,0x00,0x6C,0x00,0x65,0x00,0x49,0x00,0x6E,0x00,0x66,0x00,0x6F,0x00,0x00,0x00,0x00,0x00) # "VarFileInfo"
    $BinaryWriter.Write($VarFileInfoString, 0, $VarFileInfoString.Length) # szKey
    # Write the value for the VarFileInfo key - "Translation"
    $BinaryWriter.Write(([UInt16] 0x24)) # wLength
    $BinaryWriter.Write(([UInt16] 4)) # wValueLength
    $BinaryWriter.Write(([UInt16] 0)) # wType: 0 - "0 if the version resource contains binary data"
    $TranslationString = [Byte[]] @(0x54,0x00,0x72,0x00,0x61,0x00,0x6E,0x00,0x73,0x00,0x6C,0x00,0x61,0x00,0x74,0x00,0x69,0x00,0x6F,0x00,0x6E,0x00,0x00,0x00,0x00,0x00) # "Translation"
    $BinaryWriter.Write($TranslationString, 0, $TranslationString.Length) # szKey
    # At this time, language-neutral unicode is all that will be supported
    $BinaryWriter.Write(([UInt16] 0x0409)) # langId: 0x0409 U.S. English
    $BinaryWriter.Write(([UInt16] 0x04E4)) # charsetID: 1252 - Multilingual

    if ($OriginalFilename -or $FileDescription -or $ProductVersion -or $FileVersion -or $InternalName -or $Comments -or $CompanyName -or $LegalCopyright -or $LegalTrademarks -or $PrivateBuild -or $ProductName -or $SpecialBuild) {
        # Start defining the version info string block
        $StringBlockMemoryStream = New-Object -TypeName IO.MemoryStream
        $StringBlockBinaryWriter = New-Object -TypeName IO.BinaryWriter($StringBlockMemoryStream)

        if ($OriginalFilename) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'OriginalFilename' -Value $OriginalFilename
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        if ($FileDescription) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'FileDescription' -Value $FileDescription
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        if ($ProductVersion) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'ProductVersion' -Value $ProductVersion
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        if ($FileVersion) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'FileVersion' -Value $FileVersion
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        if ($InternalName) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'InternalName' -Value $InternalName
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        if ($Comments) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'Comments' -Value $Comments
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        if ($CompanyName) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'CompanyName' -Value $CompanyName
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        if ($LegalCopyright) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'LegalCopyright' -Value $LegalCopyright
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        if ($LegalTrademarks) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'LegalTrademarks' -Value $LegalTrademarks
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        if ($PrivateBuild) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'PrivateBuild' -Value $PrivateBuild
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        if ($ProductName) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'ProductName' -Value $ProductName
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        if ($SpecialBuild) {
            [Byte[]] $StringStructBytes = New-StringStructure -Key 'SpecialBuild' -Value $SpecialBuild
            $StringBlockBinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)
        }

        [UInt16] $StringFileInfoHeaderLength = 0x3C + $StringBlockMemoryStream.Length

        $BinaryWriter.Write($StringFileInfoHeaderLength) # wLength
        $BinaryWriter.Write(([UInt16] 0)) # wValueLength: "This member is always equal to zero."
        $BinaryWriter.Write(([UInt16] 1)) # wType: 1 - "1 if the version resource contains text data"
        $StringFileInfoString = [Byte[]] @(0x53,0x00,0x74,0x00,0x72,0x00,0x69,0x00,0x6E,0x00,0x67,0x00,0x46,0x00,0x69,0x00,0x6C,0x00,0x65,0x00,0x49,0x00,0x6E,0x00,0x66,0x00,0x6F,0x00,0x00,0x00) # "StringFileInfo"
        $BinaryWriter.Write($StringFileInfoString, 0, $StringFileInfoString.Length) # szKey

        [UInt16] $StringFileInfoHeaderLength = $StringFileInfoHeaderLength - 0x24
        $BinaryWriter.Write($StringFileInfoHeaderLength) # wLength
        $BinaryWriter.Write(([UInt16] 0)) # wValueLength: "This member is always equal to zero."
        $BinaryWriter.Write(([UInt16] 1)) # wType: 1 - "1 if the version resource contains text data"
        $LangIDString = [Byte[]] @(0x30,0x00,0x34,0x00,0x30,0x00,0x39,0x00,0x30,0x00,0x34,0x00,0x45,0x00,0x34,0x00,0x00,0x00) # "040904E4"
        $BinaryWriter.Write($LangIDString, 0, $LangIDString.Length) # szKey

        $StringStructBytes = New-Object -TypeName Byte[]($StringBlockMemoryStream.Length)
        $null = $StringBlockMemoryStream.Seek(0, 'Begin')
        $null = $StringBlockMemoryStream.Read($StringStructBytes, 0, $StringStructBytes.Length)
        $BinaryWriter.Write($StringStructBytes, 0, $StringStructBytes.Length)

        $StringBlockBinaryWriter.Close()
        $StringBlockMemoryStream.Close()
    }

    $null = $MemoryStream.Seek(0x20, 'Begin')
    $BinaryWriter.Write(([UInt32] ($MemoryStream.Length - 0x40)))
    $null = $MemoryStream.Seek(0x40, 'Begin')
    $BinaryWriter.Write(([UInt16] ($MemoryStream.Length - 0x40)))

    $ResFileBytes = New-Object -TypeName Byte[]($MemoryStream.Length)
    $null = $MemoryStream.Seek(0, 'Begin')
    $null = $MemoryStream.Read($ResFileBytes, 0, $MemoryStream.Length)

    $BinaryWriter.Close()
    $MemoryStream.Close()

    [IO.File]::WriteAllBytes($FullFilePath, $ResFileBytes)

    Get-Item -Path $FullFilePath
}