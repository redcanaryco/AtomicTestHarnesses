if (-not ('AtomicTestHarnesses_T1078_003.ProcessNativeMethods' -as [Type])) {
    $TypeDef = @'
using System;
using System.Runtime.InteropServices;
namespace AtomicTestHarnesses_T1078_003 {
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

    [Flags]
     public enum TOKEN_INFORMATION_CLASS {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        MaxTokenInfoClass
     }

     [StructLayout(LayoutKind.Sequential)]
     public struct LUID
         {
             public UInt32 LowPart;
             public Int32 HighPart;
         }

     
    [Flags]
     public enum TokenAccess {
         STANDARD_RIGHTS_REQUIRED = 0x000F0000,
         STANDARD_RIGHTS_READ = 0x00020000,
         TOKEN_ASSIGN_PRIMARY = 0x0001,
         TOKEN_DUPLICATE = 0x0002,
         TOKEN_IMPERSONATE = 0x0004,
         TOKEN_QUERY = 0x0008,
         TOKEN_QUERY_SOURCE = 0x0010,
         TOKEN_ADJUST_PRIVILEGES = 0x0020,
         TOKEN_ADJUST_GROUPS = 0x0040,
         TOKEN_ADJUST_DEFAULT = 0x0080,
         TOKEN_ADJUST_SESSIONID = 0x0100,
         TOKEN_IMPERSONATEUSER = (TOKEN_DUPLICATE | TOKEN_QUERY),
         TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
         TOKEN_QUERY_ALL = (TOKEN_QUERY | TOKEN_QUERY_SOURCE),
         TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
             TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
             TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
             TOKEN_ADJUST_SESSIONID)
     }

 
     [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
         public struct TOKEN_STATISTICS {
             public LUID   TokenId;
             public LUID   AuthenticationId;
             public long   ExpirationTime;
             public uint   TokenType;
             public uint   ImpersonationLevel;
             public uint   DynamicCharged;
             public uint   DynamicAvailable;
             public uint   GroupCount;
             public uint   PrivilegeCount;
             public LUID   ModifiedId;
         }

    public class ProcessNativeMethods {
        [DllImport("advapi32.dll", SetLastError=true)]
            public static extern bool LogonUser(
                string lpszUsername,
                string lpszDomain,
                string lpszPassword,
                LOGON_TYPE dwLogonType,
                LOGON_PROVIDER dwLogonProvider,
                ref IntPtr phToken 
                );

        [DllImport("kernel32.dll", SetLastError=true)]
            public static extern bool CloseHandle(
                IntPtr hHandle);

        
         [DllImport("advapi32.dll", SetLastError=true)]
         public static extern bool GetTokenInformation(
             IntPtr TokenHandle,
             TOKEN_INFORMATION_CLASS TokenInformationClass,
             IntPtr TokenInformation,
             uint TokenInformationLength,
             ref uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError=true)]
         public static extern bool OpenProcessToken(
             IntPtr ProcessHandle,
             uint DesiredAccess, 
             ref IntPtr TokenHandle);
    }
    
}
'@
Add-Type -TypeDefinition $TypeDef
}
function Invoke-ATHLogonUser {
    <#
    .SYNOPSIS
    Test runner for logon events.
    
    Technique ID: T1078.003 (Valid Accounts: Local Accounts)

    .DESCRIPTION
    Invoke-ATHLogonUser was designed to simulate user logons on a local host. 
    
    .PARAMETER Credential
    
    Specifies the credential the user wants to pass through to the LogonUser API. 
    
    .PARAMETER LogonType
    
    Specifies the LogonType the user wants to use to logon the target user. 
    
    .PARAMETER TestGuid
    
    Optionally, specify a test GUID value to use to override the generated test GUID behavior. 

    .OUTPUTS
    PSObject
    Outputs an object consisting of relevant execution details. The following object properties may be populated:
    
    * TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
    * TestSuccess - Will be set to True if it was determined that the technique executed successfully. 
    * TestGuid - Specifies the test GUID that was used for the test.
    * TestCommand - Specifies the command-line arguments used to perform the test.
    * SourceUser - Specifies the user that initated the logon.
    * TargetUser - Specifies the user account that was logged on.
    * LogonType - Specifies the type of logon that was performed. 
    * LogonTypeId - Specifies the ID of the LogonType. 
    * LogonId - Integer value of the logon session ID. 

    .EXAMPLE
    $cred = Get-Credential
    Invoke-ATHLogonUser -Credential $cred

    .EXAMPLE
    $cred = Get-Credential
    Invoke-ATHTokenImpersonation -Credential $cred -LogonType LOGON32_LOGON_INTERACTIVE
    Logs in a user with legitimate credentials under an Interactive Logon (Type 2). 
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        [ValidateSet('LOGON32_LOGON_INTERACTIVE', 'LOGON32_LOGON_NETWORK', 'LOGON32_LOGON_BATCH', 'LOGON32_LOGON_SERVICE','LOGON32_LOGON_UNLOCK', 'LOGON32_LOGON_NETWORK_CLEARTEXT', 'LOGON32_LOGON_NEW_CREDENTIALS')]
        $LogonType = 'LOGON32_LOGON_INTERACTIVE',

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [Guid]
        $TestGuid = (New-Guid)
    )
    if  (-not ($PSBoundParameters.ContainsKey('Credential')))
    {
        Write-Error "Function not supported unless credentials are passed through"
        return
    }
    $split = $Credential.UserName.Split("\")
    if ($split.Count -eq 2){
        $Domain = $split[0]
        $AccountName = $split[1]
    }
    else {
        $AccountName = $split[0]
    }

    $SourceUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    
    $hToken = [IntPtr]::Zero

    if ($LogonType -eq 'LOGON32_LOGON_NEW_CREDENTIALS') { 
                    $LogonProvider = 'LOGON32_PROVIDER_WINNT50'
                }
    else{
        $LogonProvider = 'LOGON32_PROVIDER_DEFAULT'
    }
    $LogonCreds = [System.Net.NetworkCredential]::new("", $Credential.Password).Password

    $Logon = [AtomicTestHarnesses_T1078_003.ProcessNativeMethods]::LogonUser(
        $AccountName,
        $Domain,
        $LogonCreds,
        $LogonType,
        $LogonProvider,
        [ref]$hToken
    );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Logon -eq 0)
    {
        Write-Error $LastError
        $TestSuccess = $false
        return
    }
    $TestSuccess = $true

    $TokenLength = 0
    $TokenPtr = [IntPtr]::Zero
 
     $Result = [AtomicTestHarnesses_T1078_003.ProcessNativeMethods]::GetTokenInformation(
         $hToken,
         [AtomicTestHarnesses_T1078_003.TOKEN_INFORMATION_CLASS]::TokenStatistics,
         $TokenPtr,
         $TokenLength,
         [Ref] $TokenLength
     );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

     [IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenLength)
    
     $Result = [AtomicTestHarnesses_T1078_003.ProcessNativeMethods]::GetTokenInformation(
         $hToken,
         [AtomicTestHarnesses_T1078_003.TOKEN_INFORMATION_CLASS]::TokenStatistics,
         $TokenPtr,
         $TokenLength,
         [Ref] $TokenLength
     );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

     if($Result -eq 0){
         Write-Error $LastError
         return
     }

     $TokenStatistics = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPtr, [System.Type][AtomicTestHarnesses_T1078_003.TOKEN_STATISTICS])
     $Global:foo = $TokenStatistics
     $LogonId = $TokenStatistics.AuthenticationId.LowPart

    #CleanUp
    $null = [AtomicTestHarnesses_T1078_003.ProcessNativeMethods]::CloseHandle($hToken)

    switch ($LogonType)
    {
        LOGON32_LOGON_INTERACTIVE
        {
            $LogonTypeId = 2
        }
        LOGON32_LOGON_NETWORK
        {
            $LogonTypeId = 3
        }
        LOGON32_LOGON_BATCH
        {
            $LogonTypeId = 4
        }
        LOGON32_LOGON_SERVICE
        {
            $LogonTypeId = 5
        }
        LOGON32_LOGON_UNLOCK
        {
            $LogonTypeId = 7
        }
        LOGON32_LOGON_NETWORK_CLEARTEXT
        {
            $LogonTypeId = 8
        }
        LOGON32_LOGON_NEW_CREDENTIALS
        {
            $LogonTypeId = 9
        }

    }


    #Running Command Information:
    $TestCommand = $MyInvocation

        [PSCustomObject] @{
            TechniqueID              = 'T1078.003'
            TestSuccess              = $TestSuccess
            TestGuid                 = $TestGuid
            TestCommand              = $TestCommand.Line
            SourceUser               = $SourceUser
            TargetUser               = $AccountName
            LogonType                = $LogonType
            LogonTypeId              = $LogonTypeId
            LogonId                  = $LogonId

        } 


} 
