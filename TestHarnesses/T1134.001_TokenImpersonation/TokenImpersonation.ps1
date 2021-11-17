if (-not ('AtomicTestHarnesses_T1134_001.ProcessNativeMethods' -as [Type])) {
    $TypeDef = @'
using System;
using System.Runtime.InteropServices;
namespace AtomicTestHarnesses_T1134_001 {
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
    public enum LOGON_TYPE {
        LOGON32_LOGON_INTERACTIVE = 2,
        LOGON32_LOGON_NETWORK = 3,
        LOGON32_LOGON_BATCH = 4,
        LOGON32_LOGON_SERVICE = 5,
        LOGON32_LOGON_UNLOCK = 7,
        LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
        LOGON32_LOGON_NEW_CREDENTIALS = 9
    }

    [Flags]
    public enum LOGON_PROVIDER {
        LOGON32_PROVIDER_DEFAULT = 0,
        LOGON32_PROVIDER_WINNT35 = 1,
        LOGON32_PROVIDER_WINNT40 = 2,
        LOGON32_PROVIDER_WINNT50 = 3
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

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            LOGON_TYPE dwLogonType,
            LOGON_PROVIDER dwLogonProvider,
            ref IntPtr phToken 
            );

        [DllImport("advapi32.dll", SetLastError=true)]
            public static extern bool ImpersonateLoggedOnUser(
                IntPtr hToken);

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
function Invoke-ATHTokenImpersonation {
    <#
    .SYNOPSIS

    Test runner for token impersonation.
    
    Technique ID: T1134.001 (Token Impersonation/Theft)

    .DESCRIPTION

    Invoke-ATHTokenImpersonation was designed to simulate token impersonation on a local host. 

    .PARAMETER ProcessId

    Specifies the process id of the target process. This allows the user to choose a process that is running under any security context and attempt impersonation. 

    .PARAMETER AccessRights

    Specifies the access rights (QueryLimitedInformation, QueryInformation, AllAccess) the user wants to request when opening a handle to the target process.

    .PARAMETER Credential
    
    Specifies the credential the user wants to pass through to the LogonUser API. 
    
    .PARAMETER LogonType
    
    Specifies the LogonType (Network or NewCredential) the user wants to use to logon the target user. 
    
    .PARAMETER TestGuid
    
    Optionally, specify a test GUID value to use to override the generated test GUID behavior. 

    .INPUTS

    System.Diagnostics.Process

    Invoke-ATHTokenImpersonation accepts the output of Get-Process. Only one Process object should be supplied to Invoke-ATHTokenImpersonation.

    Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process

    Invoke-ATHTokenImpersonation accepts the output of a Win32_Process WMI object via Get-CimInstance.


    .OUTPUTS
    PSObject

    Outputs an object consisting of relevant execution details. The following object properties may be populated:
    
    * TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
    * TestSuccess - Will be set to True if it was determined that the technique executed successfully. Invoke-ATHTokenImpersonation can identify when impersonation was successful by checking the security context of the current thread and confirming it is different then the original security context.
    * TestGuid - Specifies the test GUID that was used for the test.
    * TestCommand - Specifies the command-line arguments used to perform the test.
    * SourceUser - Specifies the user that the current thread is running under before impersonation was performed.
    * SourceExecutableFilePath - Specifies the full path of the source executable. If the source executable is specified as a byte array, this property will be empty.
    * SourceExecutableFileHash - SHA256 hash of the source executable.
    * ImpersonatedUser - Specifies the user account that is being ran in the current thread after impersonation was performed.
    * SourceProcessId - Specifies the process ID of the process performing impersonation.
    * GrantedRights - The process rights used to request a handle to the target process. 
    * TargetExecutablePath - Specifies the full path of the target executable.
    * TargetExecutableFileHash - SHA256 hash of the target executable.

    .EXAMPLE

    Invoke-ATHTokenImpersonation

    .EXAMPLE

    Get-Process -name notepad | Invoke-ATHTokenImpersonation

    Perform impersonation where notepad.exe is the target process.

    .EXAMPLE

    Invoke-ATHTokenImpersonation -AccessRights AllAccess

    Performs impersonation and specifying the access rights as AllAccess.


    .EXAMPLE

    Get-Process -name notepad | Invoke-ATHTokenImpersonation -AccessRights AllAccess

    Performs impersonation and specifying the target process as notepad and the  access rights as AllAccess.

    .EXAMPLE

    $cred = Get-Credential
    Invoke-ATHTokenImpersonation -Credential $cred -LogonType Network

    Logs in a user with legitimate credentials under a Network Logon (Type 3), then impersonates the logged on user. 

    .EXAMPLE

    $cred = Get-Credential
    Invoke-ATHTokenImpersonation -Credential $cred -LogonType NewCredential

    Logs in a user with legitimate/illegitimate credentials under a NewCredential Logon (Type 9), then impersonates the logged on user. 
    #>

    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [Int32]
        [Alias('Id')]
        $ProcessId = (Get-Process -Name winlogon)[0].Id,

        [Parameter()]
        [string]
        [ValidateSet('AllAccess', 'QueryLimitedInformation', 'QueryInformation')]
        $AccessRights = 'QueryLimitedInformation',

        [Parameter()]
        [string]
        [ValidateSet('Network', 'NewCredential')]
        $LogonType = 'Network',

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [Guid]
        $TestGuid = (New-Guid)
    )
    $IsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($IsAdministrator -eq $False){
        Write-Error "Insufficent privileges to perform operation. Please run as Administrator." #The privileges you need to perform ImpersonateLoggedOnUser is SeImpersonatePrivilege. Easiest way to obtain this is to be apart of the Administrators group. 
        return
    }
    $SourceProcessPath = $null
    $SourceProcessPath =  (Get-CimInstance -ClassName Win32_Process -Property ExecutablePath  -Filter "ProcessId=$PID").Path

    if (-not ($PSBoundParameters.ContainsKey('Credential'))) {
        $SourceUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        $ProcessHandle = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::OpenProcess(
            $AccessRights, 
            $False,
            $ProcessId
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if($ProcessHandle -eq [IntPtr]::Zero){
            Write-Error $LastError
            return
        }

        $TokenHandle = [IntPtr]::Zero
        $TokenResult = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::OpenProcessToken(
            $ProcessHandle,
            'TokenDuplicate',
            [Ref] $TokenHandle
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if($TokenResult -eq 0){
            Write-Error $LastError
            $null = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::CloseHandle($ProcessHandle)
            return
        }

        $hToken = [IntPtr]::Zero

        $DuplicateToken = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::DuplicateTokenEx(
            $TokenHandle,
            'TokenQuery, TokenImpersonate',
            [IntPtr]::Zero,
            'SecurityImpersonation',
            2, #TokenImpersonation
            [ref]$hToken
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if($DuplicateToken -eq 0)
        {
            Write-Error $LastError
            $null = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::CloseHandle($ProcessHandle)
            $null = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::CloseHandle($TokenHandle)
            return
        }
    }
    else {

        $split = $Credential.UserName.Split("\")
        if ($split.Count -eq 2){
            $Domain = $split[0]
            $AccountName = $split[1]
        }
        else {
            $AccountName = $split[0]
        }
        $LogonTypeCount =  (Get-CimInstance Win32_LogonSession -Filter 'LogonType = 9' | Measure-Object).Count

        $SourceUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        
        $hToken = [IntPtr]::Zero

        if ($LogonType -eq 'NewCredential') { 
            $LogonTypeNumber = 9
            $LogonProvider = 3
        }
        else {
            $LogonTypeNumber = 3
            $LogonProvider = 1
        }

        $LogonCreds = [System.Net.NetworkCredential]::new("", $Credential.Password).Password

        $Logon = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::LogonUser(
            $AccountName,
            $Domain,
            $LogonCreds,
            $LogonTypeNumber,
            $LogonProvider,
            [ref]$hToken
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if($Logon -eq 0)
        {
            Write-Error $LastError
            return
        }
    }

    $Success = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::ImpersonateLoggedOnUser(
        $hToken
    );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Success -eq 0){
        Write-Error $LastError
        $null = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::CloseHandle($ProcessHandle)
        $null = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::CloseHandle($TokenHandle)
        $null = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::CloseHandle($DupToken)
        return
    }

    if ($LogonType -eq 'NewCredential'){
        $LogonTypeCountUpdate =  (Get-CimInstance Win32_LogonSession -Filter 'LogonType = 9' | Measure-Object).Count
        $Current = [System.Security.Principal.WindowsIdentity]::GetCurrent().ImpersonationLevel
        $TargetUser = $Credential.UserName
        $TestSuccess = $null
    
        if($LogonTypeCount -ne $LogonTypeCountUpdate){
            if ($Current -eq 'Impersonation'){
                $TestSuccess = $true
            } 
        }
    }
    else {
        $TargetUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        $TestSuccess = $null
    
        if($SourceUser -ne $TargetUser){
            if ($SourceUser -and $TargetUser)
            {
                $TestSuccess = $true
            }
        
        }
    }
    
    
    #Source Process Hash Logic: 
    $SHA256 = [Security.Cryptography.SHA256]::Create()
    $ResolvedSourceFilePath = Resolve-Path -Path $SourceProcessPath -ErrorAction Stop
    $SourceExeBytes = [IO.File]::ReadAllBytes($ResolvedSourceFilePath.Path)
    $SourceExeHash = ($SHA256.ComputeHash($SourceExeBytes) | ForEach-Object { $_.ToString('X2') }) -join ''

    #Running Command Information:
    $TestCommand = $MyInvocation

    if (-not ($PSBoundParameters.ContainsKey('Credential'))) {
        if ($PSBoundParameters.ContainsKey('LogonType')){
            Write-Error "LogonType is not supported without the Credential parameter"
            return
        }
        $AccessRightsOutput = $AccessRights
        #Target Process Hash Logic:
        $TargetExecutablePath = $null
        $TargetExecutablePath = (Get-CimInstance -ClassName Win32_Process -Property ExecutablePath  -Filter "ProcessId=$ProcessId").Path
        $ResolvedTargetFilePath = Resolve-Path -Path $TargetExecutablePath -ErrorAction Stop
        $TargetExeBytes = [IO.File]::ReadAllBytes($ResolvedTargetFilePath.Path)
        $TargetExeHash = ($SHA256.ComputeHash($TargetExeBytes) | ForEach-Object { $_.ToString('X2') }) -join ''

        $TargetProcessId = $ProcessId

        #Cleanup
        $null = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::CloseHandle($ProcessHandle)
        $null = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::CloseHandle($TokenHandle)

    }
    else {
        $AccessRightsOutput = $null
        $TargetExecutablePath = $null
        $TargetExeHash = $null
        $TargetProcessId = $null
    
    }    

         [PSCustomObject] @{
            TechniqueID              = 'T1134.001'
            TestSuccess              = $TestSuccess
            TestGuid                 = $TestGuid
            TestCommand              = $TestCommand.Line
            SourceUser               = $SourceUser
            SourceExecutableFilePath = $SourceProcessPath
            SourceExecutableFileHash = $SourceExeHash
            SourceProcessId          = $PID
            GrantedRights            = $AccessRightsOutput
            ImpersonatedUser         = $TargetUser
            TargetExecutableFilePath = $TargetExecutablePath
            TargetExecutableFileHash = $TargetExeHash
            TargetProcessId          = $TargetProcessId
        }

    #Cleanup   
    $null = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::CloseHandle($hToken)
    $Revert = [AtomicTestHarnesses_T1134_001.ProcessNativeMethods]::RevertToSelf();$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Revert -eq 0){
        Write-Error $LastError
        return
    }

}