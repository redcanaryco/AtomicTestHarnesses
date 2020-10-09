function Start-ATHProcessUnderSpecificParent {
<#
.SYNOPSIS

Creates a process as a child of a specified process ID.

Technique ID: T1134.004 (Access Token Manipulation: Parent PID Spoofing)

.DESCRIPTION

Start-ATHProcessUnderSpecificParent performs parent process ID spoofing and allows you to spawn an executable (with optional command-line arguments) from the parent process of one's choosing.

.PARAMETER FilePath

Specifies the filename or path to the executable to execute. If just a filename is specified, Start-ATHProcessUnderSpecificParent will look for the executable in the current working directory. If it is not present in the current working directory, Start-ATHProcessUnderSpecificParent will attempt to retrieve the full path via the OS load order. Relative or absolute paths will be resolved accordingly.

.PARAMETER CommandLine

Optionally, specify command-line arguments.

.PARAMETER ParentId

Specifies the process ID of the process under which a process will be spawned.

.PARAMETER TestGuid

Optionally, specify a test GUID value to use to override the generated test GUID behavior.

.INPUTS

System.Diagnostics.Process

Start-ATHProcessUnderSpecificParent accepts the output of Get-Process. Only one Process object should be supplied to Start-ATHProcessUnderSpecificParent.

Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process

Start-ATHProcessUnderSpecificParent accepts the output a Win32_Process WMI object via Get-CimInstance.

.OUTPUTS

PSObject

Outputs an object consisting of relevant execution details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* TestSuccess - Indicates that parent spoofing was successful.
* TestGuid - Specifies the test GUID that was used for the test. This property will not be populated when -FilePath is specified.
* ProcessId - Process ID of the process that spawned.
* ProcessPath - Executable path of the process that spawned.
* ProcessCommandLine - Command-line of the process that spawned.
* ParentProcessId - Process ID of the process that the child process spawned from.
* ParentProcessPath - Executable path of the process that the child process spawned from.
* ParentProcessCommandLine - Command-line of the process that the child process spawned from.
* SpoofingProcessId - Process ID of the process that performed the parent PID spoofing.
* SpoofingProcessPath - Executable path of the process that performed the parent PID spoofing.
* SpoofingProcessCommandLine - Command-line of the process that performed the parent PID spoofing.

.EXAMPLE

Start-ATHProcessUnderSpecificParent -ParentId $PID -FilePath notepad.exe

Spawns a notepad.exe process as a child of the current process.

.EXAMPLE

Get-Process -Name explorer | Select-Object -First 1 | Start-ATHProcessUnderSpecificParent -FilePath notepad.exe

Spawns a notepad.exe process as a child of the first explorer.exe process.

.EXAMPLE

Get-CimInstance -ClassName Win32_Process -Property Name, CommandLine, ProcessId -Filter "Name = 'svchost.exe' AND CommandLine LIKE '%'" | Select-Object -First 1 | Start-ATHProcessUnderSpecificParent -FilePath powershell.exe -CommandLine '-Command Write-Host foo'

Spawnd a process as a child of the first accessible svchost.exe process.

.EXAMPLE

Start-Process -FilePath $Env:windir\System32\notepad.exe -PassThru | Start-ATHProcessUnderSpecificParent -FilePath powershell.exe -CommandLine '-Command Write-Host foo'

Creates a notepad.exe process and then spawns a powershell.exe process as a child of it.

.EXAMPLE

Get-Process -Name lsass | Start-ATHProcessUnderSpecificParent -FilePath powershell.exe -CommandLine '-Command Write-Host foo'

Spawns a powershell.exe process as a child of lsass.exe. This example requires elevation.
#>

    [CmdletBinding(DefaultParameterSetName = 'UseTemplate')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'SupplyArgs')]
        [String]
        $FilePath,

        [Parameter(ParameterSetName = 'SupplyArgs')]
        [String]
        [ValidateNotNull()]
        $CommandLine,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'UseTemplate')]
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'SupplyArgs')]
        [Int]
        [Alias('Id')] # Supports pipelining with Get-Process
        [Alias('ProcessId')] # Supports pipelining with Get-CimInstance Win32_Process
        $ParentId,

        [Parameter(ParameterSetName = 'UseTemplate')]
        [Guid]
        $TestGuid = (New-Guid)
    )

    $TypeDef = @'
using System;
using System.Runtime.InteropServices;

namespace AtomicTestHarnesses_T1134_004 {
    public class ProcessNativeMethods {
        public struct STARTUPINFO {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public struct STARTUPINFOEX {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        public struct PROCESS_INFORMATION  {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            int processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool CloseHandle(
            IntPtr hHandle);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool DeleteProcThreadAttributeList(
            IntPtr lpAttributeList);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcess(
            IntPtr lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            int dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);
    }
}
'@

    Add-Type -TypeDefinition $TypeDef

    $FullFilePath = $null
    $CraftedCommandLineString = $null
    $TestGuidToUse = $null

    switch ($PSCmdlet.ParameterSetName) {
        'UseTemplate' {
            $FullFilePath = Get-Command -Name powershell.exe | Select-Object -ExpandProperty Path
            $TestGuidToUse = $TestGuid

            $CraftedCommandLineString = "`"$FullFilePath`" -nop -Command Write-Host $TestGuid"
        }

        'SupplyArgs' {
            # Attempt to retrieve file directory
            $FilePathParent = Split-Path -Path $FilePath -Parent

            if (-not $FilePathParent) { # Just a filename was supplied. No relative or absolute path.
                $MergedFilePath = Join-Path -Path $PWD -ChildPath $FilePath

                if (Test-Path -Path $MergedFilePath -PathType Leaf) {
                    $FullFilePath = Resolve-Path -Path $MergedFilePath -ErrorAction Stop | Select-Object -ExpandProperty Path
                } else {
                    $FullFilePath = Get-Command -Name $FilePath -ErrorAction Stop | Select-Object -ExpandProperty Path
                }
            } else { # A relative or absolute path was supplied.
                $FullFilePath = Resolve-Path -Path $FilePath -ErrorAction Stop | Select-Object -ExpandProperty Path
            }

            if ($CommandLine) {
                # Append the command-line arguments
                $CraftedCommandLineString = "`"$FullFilePath`" $CommandLine"
            } else {
                # Just supply the full path of the executable with no command-line arguments
                $CraftedCommandLineString = "`"$FullFilePath`""
            }
        }
    }

    Write-Verbose "Full path of specified executable: $FullFilePath"

    $EXTENDED_STARTUPINFO_PRESENT         = 0x00080000
    $CREATE_NO_WINDOW                     = 0x08000000
    $PROCESS_DUP_HANDLE                   = 0x00000040
    $PROCESS_CREATE_PROCESS               = 0x00000080
    $PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000

    $StartupInfo =   New-Object -TypeName AtomicTestHarnesses_T1134_004.ProcessNativeMethods+STARTUPINFO
    $StartupInfoEx = New-Object -TypeName AtomicTestHarnesses_T1134_004.ProcessNativeMethods+STARTUPINFOEX
    $ProcessInfo =   New-Object -TypeName AtomicTestHarnesses_T1134_004.ProcessNativeMethods+PROCESS_INFORMATION

    #region Initialize ProcThreadAttributeList
    $ProcThreadAttributeListSize = [IntPtr]::Zero

    Write-Verbose 'Determining size required for PROC_THREAD_ATTRIBUTE_LIST structure.'

    $Result = [AtomicTestHarnesses_T1134_004.ProcessNativeMethods]::InitializeProcThreadAttributeList(
        $StartupInfoEx.lpAttributeList,     # lpAttributeList
        1,                                  # dwAttributeCount
        0,                                  # dwFlags
        [ref] $ProcThreadAttributeListSize  # lpSize
    );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    # Throw an exception if the error code is anything other than "The data area passed to a system call is too small"
    if (($Result -eq $False) -and ($LastError.NativeErrorCode -ne 122)) {
        throw $LastError
    }

    # Allocate unmanaged memory of sufficient size for the PROC_THREAD_ATTRIBUTE_LIST structure
    $ProcThreadAttributeListPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ProcThreadAttributeListSize)

    $StartupInfoEx.lpAttributeList = $ProcThreadAttributeListPtr

    Write-Verbose 'Initializing memory for PROC_THREAD_ATTRIBUTE_LIST structure.'

    # Allocate ProcThreadAttributeList
    $Result = [AtomicTestHarnesses_T1134_004.ProcessNativeMethods]::InitializeProcThreadAttributeList(
        $StartupInfoEx.lpAttributeList,     # lpAttributeList
        1,                                  # dwAttributeCount
        0,                                  # dwFlags
        [ref] $ProcThreadAttributeListSize  # lpSize
    );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($Result -eq $False) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcThreadAttributeListPtr)

        throw $LastError
    }
    #endregion

    Write-Verbose "Attempting to obtain a PROCESS_CREATE_PROCESS|PROCESS_DUP_HANDLE handle to process ID: $ParentId."

    #region Obtain handle to the target process that we'll spawn our child proc from
    $ProcHandle = [AtomicTestHarnesses_T1134_004.ProcessNativeMethods]::OpenProcess(
        $PROCESS_CREATE_PROCESS -bor $PROCESS_DUP_HANDLE,   # processAccess - The minimum access rights required to spawn a child process.
        $False,                                             # bInheritHandle
        $ParentId                                           # processId - i.e. the process ID of the process we want to spawn a child process from
    );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($ProcHandle -eq [IntPtr]::Zero) {
        # Free unmanaged memory and close process handle
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcThreadAttributeListPtr)
        $null = [AtomicTestHarnesses_T1134_004.ProcessNativeMethods]::DeleteProcThreadAttributeList($StartupInfoEx.lpAttributeList)

        throw $LastError
    }
    #endregion

    #region Allocate a pointer to hold the value of the returned process handle
    $PointerToProcessHandle = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($PointerToProcessHandle, $ProcHandle)

    Write-Verbose "Specifying process ID $ParentId as target parent process ID."

    # Supply the process handle to the ProcThreadAttribute list
    $Result = [AtomicTestHarnesses_T1134_004.ProcessNativeMethods]::UpdateProcThreadAttribute(
        $StartupInfoEx.lpAttributeList,         # lpAttributeList
        0,                                      # dwFlags
        $PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,  # Attribute
        $PointerToProcessHandle,                # lpValue
        [IntPtr]::Size,                         # cbSize
        [IntPtr]::Zero,                         # lpPreviousValue
        [IntPtr]::Zero                          # lpReturnSize
    )

    if ($Result -eq $False) {
        # Free unmanaged memory and close process handle
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcThreadAttributeListPtr)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($PointerToProcessHandle)
        $null = [AtomicTestHarnesses_T1134_004.ProcessNativeMethods]::DeleteProcThreadAttributeList($StartupInfoEx.lpAttributeList)
        $null = [AtomicTestHarnesses_T1134_004.ProcessNativeMethods]::CloseHandle($ProcHandle)

        throw $LastError
    }
    #endregion

    #region Start process as child of target parent

    $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][AtomicTestHarnesses_T1134_004.ProcessNativeMethods+STARTUPINFOEX])
    $StartupInfoEx.StartupInfo = $StartupInfo

    Write-Verbose "Spawning process as a child of parent process ID $ParentId."

    $Result = [AtomicTestHarnesses_T1134_004.ProcessNativeMethods]::CreateProcess(
        [IntPtr]::Zero,                                         # lpApplicationName
        $CraftedCommandLineString,                              # lpCommandLine
        [IntPtr]::Zero,                                         # lpProcessAttributes
        [IntPtr]::Zero,                                         # lpThreadAttributes
        $False,                                                 # bInheritHandles
        $EXTENDED_STARTUPINFO_PRESENT -bor $CREATE_NO_WINDOW,   # dwCreationFlags
        [IntPtr]::Zero,                                         # lpEnvironment
        $PWD.Path,                                              # lpCurrentDirectory
        [ref] $StartupInfoEx,                                   # lpStartupInfo
        [ref] $ProcessInfo                                      # lpProcessInformation
    );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    # Free unmanaged memory and close process handle
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcThreadAttributeListPtr)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($PointerToProcessHandle)
    $null = [AtomicTestHarnesses_T1134_004.ProcessNativeMethods]::DeleteProcThreadAttributeList($StartupInfoEx.lpAttributeList)
    $null = [AtomicTestHarnesses_T1134_004.ProcessNativeMethods]::CloseHandle($ProcHandle)

    if ($Result -eq $False) {
        throw $LastError
    }
    #endregion

    # Get process information for the spawned process
    $WMIProcessInfo = Get-CimInstance -ClassName Win32_Process -Property ParentProcessId, ProcessId, CommandLine, ExecutablePath -Filter "ProcessId = $($ProcessInfo.dwProcessId)" -ErrorAction SilentlyContinue

    # Get process information for the targeted parent process
    $WMIParentProcessInfo = Get-CimInstance -ClassName Win32_Process -Property ProcessId, CommandLine, ExecutablePath -Filter "ProcessId = $($WMIProcessInfo.ParentProcessId)" -ErrorAction SilentlyContinue

    if (-not $WMIProcessInfo) {
        Write-Error "Failed to obtain spawned process info for process ID $($ProcessInfo.dwProcessId)." -ErrorAction Stop
    }

    if (-not $WMIParentProcessInfo) {
        Write-Error "Failed to obtain parent process info for process ID $ParentId." -ErrorAction Stop
    }

    $CurrentProcessInfo = Get-CimInstance -ClassName Win32_Process -Property CommandLine, ExecutablePath -Filter "ProcessId = $PID" -ErrorAction SilentlyContinue

    [PSCustomObject] @{
        TechniqueID = 'T1134.004'
        TestSuccess = $True
        TestGuid = $TestGuidToUse
        ProcessId = $ProcessInfo.dwProcessId
        ProcessPath = $WMIProcessInfo.ExecutablePath
        ProcessCommandLine = $WMIProcessInfo.CommandLine
        ParentProcessId = $WMIParentProcessInfo.ProcessId
        ParentProcessPath = $WMIParentProcessInfo.ExecutablePath
        ParentProcessCommandLine = $WMIParentProcessInfo.CommandLine
        SpoofingProcessId = $PID
        SpoofingProcessPath = $CurrentProcessInfo.ExecutablePath
        SpoofingProcessCommandLine = $CurrentProcessInfo.CommandLine
    }
}
