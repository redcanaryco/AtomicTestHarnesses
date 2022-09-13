Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Invoke-ATHTokenImpersonation' {
    BeforeAll {
        $Help = Get-Help -Name Invoke-ATHTokenImpersonation -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }

        $FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    }
    
    Context 'Validating error conditions' -Tag 'Unit', 'T1134.001' {
        It 'should fail to open process' {
            { Invoke-ATHTokenImpersonation -ProcessId 1234 -ErrorAction Stop } | Should -Throw
        }

        It 'should fail to open a handle with the specified access rights' {
            { Invoke-ATHTokenImpersonation -ProcessId $PID -AccessRights CreateThread -ErrorAction Stop } | Should -Throw
        }

    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1134.001' {
        It 'should impersonate user SYSTEM running under the winlogon process with QueryLimitedInformation as the requested rights' {
            $Result =  Invoke-ATHTokenImpersonation -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty
            
            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -Match 'QueryLimitedInformation'
            $Result.ImpersonatedUser            | Should -Match 'SYSTEM'
            $Result.TargetExecutableFilePath    | Should -Match 'winlogon.exe'
            $Result.TargetExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId             | Should -Not -BeNullOrEmpty
            $Result.PipeName                    | Should -BeNullOrEmpty
            $Result.ServiceName                 | Should -BeNullOrEmpty

            $Result
        }

        It 'should impersonate user SYSTEM running under the winlogon process with QueryInformation as the requested rights' {
            $Result = Get-Process -Name winlogon | Select-Object -First 1 | Invoke-ATHTokenImpersonation -AccessRights QueryInformation -TestGuid $FixedTestGuid 

            $Result | Should -Not -BeNullOrEmpty
            
            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -Match 'QueryInformation'
            $Result.ImpersonatedUser            | Should -Match 'SYSTEM'
            $Result.TargetExecutableFilePath    | Should -Match 'winlogon.exe'
            $Result.TargetExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId             | Should -Not -BeNullOrEmpty
            $Result.PipeName                    | Should -BeNullOrEmpty
            $Result.ServiceName                 | Should -BeNullOrEmpty

            $Result
        }

        It 'should impersonate user SYSTEM running under the winlogon process with AllAcccess as the requested rights' {
            $Result = Get-Process -Name winlogon | Select-Object -First 1 | Invoke-ATHTokenImpersonation -AccessRights AllAccess -TestGuid $FixedTestGuid 

            $Result | Should -Not -BeNullOrEmpty
            
            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -Match 'AllAccess'
            $Result.ImpersonatedUser            | Should -Match 'SYSTEM'
            $Result.TargetExecutableFilePath    | Should -Match 'winlogon.exe'
            $Result.TargetExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId             | Should -Not -BeNullOrEmpty
            $Result.PipeName                    | Should -BeNullOrEmpty
            $Result.ServiceName                 | Should -BeNullOrEmpty

            $Result
        }

        It 'should impersonate user SYSTEM running under the LSASS process with QueryLimitedInformation as the requested rights' {
            $Result = Get-Process -Name lsass | Invoke-ATHTokenImpersonation -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -Match 'QueryLimitedInformation'
            $Result.ImpersonatedUser            | Should -Match 'SYSTEM'
            $Result.TargetExecutableFilePath    | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId             | Should -Not -BeNullOrEmpty
            $Result.PipeName                    | Should -BeNullOrEmpty
            $Result.ServiceName                 | Should -BeNullOrEmpty

            $Result
        }

        It 'should impersonate user SYSTEM running under the LSASS process with QueryInformation as the requested rights' {
            $Result = Get-Process -Name lsass | Invoke-ATHTokenImpersonation -AccessRights QueryInformation -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -Match 'QueryInformation'
            $Result.ImpersonatedUser            | Should -Match 'SYSTEM'
            $Result.TargetExecutableFilePath    | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId             | Should -Not -BeNullOrEmpty
            $Result.PipeName                    | Should -BeNullOrEmpty
            $Result.ServiceName                 | Should -BeNullOrEmpty

            $Result
        }

        It 'should impersonate user SYSTEM running under the LSASS process with AllAccess as the requested rights' {
            $Result = Get-Process -Name lsass | Invoke-ATHTokenImpersonation -AccessRights AllAccess -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -Match 'AllAccess'
            $Result.ImpersonatedUser            | Should -Match 'SYSTEM'
            $Result.TargetExecutableFilePath    | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId             | Should -Not -BeNullOrEmpty
            $Result.PipeName                    | Should -BeNullOrEmpty
            $Result.ServiceName                 | Should -BeNullOrEmpty

            $Result
        }

        It 'should logon user John Doe with fake credentials and impersonate impersonate user John Doe' {
            $Result = Invoke-ATHTokenImpersonation -LogonToken -Credential $(New-Object System.Management.Automation.PSCredential ('JohnDoe', $(ConvertTo-SecureString 'fakecreds' -AsPlainText -Force))) -LogonType NewCredential -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -BeNullOrEmpty
            $Result.ImpersonatedUser            | Should -Match 'JohnDoe'
            $Result.TargetExecutableFilePath    | Should -BeNullOrEmpty
            $Result.TargetExecutableFileHash    | Should -BeNullOrEmpty
            $Result.TargetProcessId             | Should -BeNullOrEmpty
            $Result.PipeName                    | Should -BeNullOrEmpty
            $Result.ServiceName                 | Should -BeNullOrEmpty

            $Result
        }

        It ' should impersonate user SYSTEM by creating a service to call back on namedpipe - TestHarness' {
            $Result = Invoke-ATHTokenImpersonation -NamedPipe -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID 
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -BeNullOrEmpty
            $Result.ImpersonatedUser            | Should -Match 'SYSTEM'
            $Result.TargetExecutableFilePath    | Should -BeNullOrEmpty
            $Result.TargetExecutableFileHash    | Should -BeNullOrEmpty
            $Result.TargetProcessId             | Should -BeNullOrEmpty
            $Result.PipeName                    | Should -Match 'TestHarness'
            $Result.ServiceName                 | Should -Match 'TestHarness'

            $Result
        }

    }
}