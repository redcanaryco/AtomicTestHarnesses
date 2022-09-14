Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Invoke-ATHCreateProcessWithToken' {
    BeforeAll {
        $Help = Get-Help -Name Invoke-ATHCreateProcessWithToken -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }

        $FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    }
    
    Context 'Validating error conditions' -Tag 'Unit', 'T1134.002' {
        It 'should fail to open process' {
            { Invoke-ATHCreateProcessWithToken -TargetProcessId 1234 -ErrorAction Stop } | Should -Throw
        }

        It 'should fail to open a handle with the specified access rights' {
            { Invoke-ATHCreateProcessWithToken -TargetProcessId $PID -AccessRights CreateThread -ErrorAction Stop } | Should -Throw
        }

        It 'should fail to create process' {
            { Invoke-ATHCreateProcessWithToken -TargetProcessId $PID -NewProcessName calc -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1134.002' {
        It 'should obtain a handle to winlogon via QueryLimitedInformation rights, create a new primary token via duplication, then create a SYSTEM integrity powershell process. ' {
            $Result =  Invoke-ATHCreateProcessWithToken -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty
            
            $Result.TechniqueID                     | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                     | Should -BeTrue
            $Result.TestGuid                        | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                     | Should -Not -BeNullOrEmpty
            $Result.SourceUser                      | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath        | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId                 | Should -Not -BeNullOrEmpty
            $Result.GrantedRights                   | Should -Match 'QueryLimitedInformation'
            $Result.ImpersonatedUser                | Should -Match 'SYSTEM'
            $Result.LogonType                       | Should -BeNullOrEmpty
            $Result.TargetExecutableFilePath        | Should -Match 'winlogon.exe'
            $Result.TargetExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId                 | Should -Not -BeNullOrEmpty
            $Result.NewProcessExecutablePath        | Should -Match 'powershell.exe'
            $Result.NewProcessCommandline           | Should -Match 'powershell.exe -nop -Command Write-Host'
            $Result.NewProcessExecutableHash        | Should -Not -BeNullOrEmpty
            $Result.NewProcessId                    | Should -Not -BeNullOrEmpty

            $Result
        }

        It 'should obtain a handle to winlogon via QueryInformation rights, create a new primary token via duplication, then create a SYSTEM integrity powershell process.' {
            $Result = Get-Process -Name winlogon | Select-Object -First 1 | Invoke-ATHCreateProcessWithToken -AccessRights QueryInformation -TestGuid $FixedTestGuid 

            $Result | Should -Not -BeNullOrEmpty
            
            $Result.TechniqueID                     | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                     | Should -BeTrue
            $Result.TestGuid                        | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                     | Should -Not -BeNullOrEmpty
            $Result.SourceUser                      | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath        | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId                 | Should -Not -BeNullOrEmpty
            $Result.GrantedRights                   | Should -Match 'QueryInformation'
            $Result.ImpersonatedUser                | Should -Match 'SYSTEM'
            $Result.LogonType                       | Should -BeNullOrEmpty
            $Result.TargetExecutableFilePath        | Should -Match 'winlogon.exe'
            $Result.TargetExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId                 | Should -Not -BeNullOrEmpty
            $Result.NewProcessExecutablePath        | Should -Match 'powershell.exe'
            $Result.NewProcessCommandline           | Should -Match 'powershell.exe -nop -Command Write-Host'
            $Result.NewProcessExecutableHash        | Should -Not -BeNullOrEmpty
            $Result.NewProcessId                    | Should -Not -BeNullOrEmpty

            $Result
        }

        It 'should obtain a handle to winlogon via AllAccess rights, create a new primary token via duplication, then create a SYSTEM integrity powershell process.' {
            $Result = Get-Process -Name winlogon | Select-Object -First 1 | Invoke-ATHCreateProcessWithToken -AccessRights AllAccess -TestGuid $FixedTestGuid 

            $Result | Should -Not -BeNullOrEmpty
            
            $Result.TechniqueID                     | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                     | Should -BeTrue
            $Result.TestGuid                        | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                     | Should -Not -BeNullOrEmpty
            $Result.SourceUser                      | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath        | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId                 | Should -Not -BeNullOrEmpty
            $Result.GrantedRights                   | Should -Match 'AllAccess'
            $Result.ImpersonatedUser                | Should -Match 'SYSTEM'
            $Result.LogonType                       | Should -BeNullOrEmpty
            $Result.TargetExecutableFilePath        | Should -Match 'winlogon.exe'
            $Result.TargetExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId                 | Should -Not -BeNullOrEmpty
            $Result.NewProcessExecutablePath        | Should -Match 'powershell.exe'
            $Result.NewProcessCommandline           | Should -Match 'powershell.exe -nop -Command Write-Host'
            $Result.NewProcessExecutableHash        | Should -Not -BeNullOrEmpty
            $Result.NewProcessId                    | Should -Not -BeNullOrEmpty

            $Result
        }

        It 'should obtain a handle to lsass via QueryLimitedInformation rights, create a new primary token via duplication, then create a SYSTEM integrity powershell process.' {
            $Result = Get-Process -Name lsass | Invoke-ATHCreateProcessWithToken -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                     | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                     | Should -BeTrue
            $Result.TestGuid                        | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                     | Should -Not -BeNullOrEmpty
            $Result.SourceUser                      | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath        | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId                 | Should -Not -BeNullOrEmpty
            $Result.GrantedRights                   | Should -Match 'QueryLimitedInformation'
            $Result.ImpersonatedUser                | Should -Match 'SYSTEM'
            $Result.LogonType                       | Should -BeNullOrEmpty
            $Result.TargetExecutableFilePath        | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId                 | Should -Not -BeNullOrEmpty
            $Result.NewProcessExecutablePath        | Should -Match 'powershell.exe'
            $Result.NewProcessCommandline           | Should -Match 'powershell.exe -nop -Command Write-Host'
            $Result.NewProcessExecutableHash        | Should -Not -BeNullOrEmpty
            $Result.NewProcessId                    | Should -Not -BeNullOrEmpty

            $Result
        }

        It 'should obtain a handle to lsass via QueryInformation rights, create a new primary token via duplication, then create a SYSTEM integrity powershell process.' {
            $Result = Get-Process -Name lsass | Invoke-ATHCreateProcessWithToken -AccessRights QueryInformation -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                     | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                     | Should -BeTrue
            $Result.TestGuid                        | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                     | Should -Not -BeNullOrEmpty
            $Result.SourceUser                      | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath        | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId                 | Should -Not -BeNullOrEmpty
            $Result.GrantedRights                   | Should -Match 'QueryInformation'
            $Result.ImpersonatedUser                | Should -Match 'SYSTEM'
            $Result.LogonType                       | Should -BeNullOrEmpty
            $Result.TargetExecutableFilePath        | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId                 | Should -Not -BeNullOrEmpty
            $Result.NewProcessExecutablePath        | Should -Match 'powershell.exe'
            $Result.NewProcessCommandline           | Should -Match 'powershell.exe -nop -Command Write-Host'
            $Result.NewProcessExecutableHash        | Should -Not -BeNullOrEmpty
            $Result.NewProcessId                    | Should -Not -BeNullOrEmpty

            $Result
        }

        It 'should obtain a handle to lsass via AllAccess rights, create a new primary token via duplication, then create a SYSTEM integrity powershell process.' {
            $Result = Get-Process -Name lsass | Invoke-ATHCreateProcessWithToken -AccessRights AllAccess -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                     | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                     | Should -BeTrue
            $Result.TestGuid                        | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                     | Should -Not -BeNullOrEmpty
            $Result.SourceUser                      | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath        | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId                 | Should -Not -BeNullOrEmpty
            $Result.GrantedRights                   | Should -Match 'AllAccess'
            $Result.ImpersonatedUser                | Should -Match 'SYSTEM'
            $Result.LogonType                       | Should -BeNullOrEmpty
            $Result.TargetExecutableFilePath        | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId                 | Should -Not -BeNullOrEmpty
            $Result.NewProcessExecutablePath        | Should -Match 'powershell.exe'
            $Result.NewProcessCommandline           | Should -Match 'powershell.exe -nop -Command Write-Host'
            $Result.NewProcessExecutableHash        | Should -Not -BeNullOrEmpty
            $Result.NewProcessId                    | Should -Not -BeNullOrEmpty

            $Result
        }

        It 'should obtain a handle to lsass via QueryLimitedInformation rights, create a new primary token via duplication, then create a SYSTEM integrity cmd process.' {
            $Result = Get-Process -Name lsass | Invoke-ATHCreateProcessWithToken -ProcessCommandline 'C:\Windows\System32\cmd.exe' -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                     | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                     | Should -BeTrue
            $Result.TestGuid                        | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                     | Should -Not -BeNullOrEmpty
            $Result.SourceUser                      | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath        | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId                 | Should -Not -BeNullOrEmpty
            $Result.GrantedRights                   | Should -Match 'QueryLimitedInformation'
            $Result.ImpersonatedUser                | Should -Match 'SYSTEM'
            $Result.LogonType                       | Should -BeNullOrEmpty
            $Result.TargetExecutableFilePath        | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId                 | Should -Not -BeNullOrEmpty
            $Result.NewProcessExecutablePath        | Should -Match 'cmd.exe'
            $Result.NewProcessCommandline           | Should -Match 'cmd.exe'
            $Result.NewProcessExecutableHash        | Should -Not -BeNullOrEmpty
            $Result.NewProcessId                    | Should -Not -BeNullOrEmpty

            $Result
        }

        It 'should obtain a handle to lsass via QueryInformation rights, create a new primary token via duplication, then create a SYSTEM integrity cmd process.' {
            $Result = Get-Process -Name lsass | Invoke-ATHCreateProcessWithToken -ProcessCommandline 'C:\Windows\System32\cmd.exe' -AccessRights QueryInformation -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                     | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                     | Should -BeTrue
            $Result.TestGuid                        | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                     | Should -Not -BeNullOrEmpty
            $Result.SourceUser                      | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath        | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId                 | Should -Not -BeNullOrEmpty
            $Result.GrantedRights                   | Should -Match 'QueryInformation'
            $Result.ImpersonatedUser                | Should -Match 'SYSTEM'
            $Result.LogonType                       | Should -BeNullOrEmpty
            $Result.TargetExecutableFilePath        | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId                 | Should -Not -BeNullOrEmpty
            $Result.NewProcessExecutablePath        | Should -Match 'cmd.exe'
            $Result.NewProcessCommandline           | Should -Match 'cmd.exe'
            $Result.NewProcessExecutableHash        | Should -Not -BeNullOrEmpty
            $Result.NewProcessId                    | Should -Not -BeNullOrEmpty

            $Result
        }

        It 'should obtain a handle to lsass via AllAccess rights, create a new primary token via duplication, then create a SYSTEM integrity cmd process.' {
            $Result = Get-Process -Name lsass | Invoke-ATHCreateProcessWithToken -ProcessCommandline 'C:\Windows\System32\cmd.exe' -AccessRights AllAccess -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                     | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                     | Should -BeTrue
            $Result.TestGuid                        | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                     | Should -Not -BeNullOrEmpty
            $Result.SourceUser                      | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath        | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId                 | Should -Not -BeNullOrEmpty
            $Result.GrantedRights                   | Should -Match 'AllAccess'
            $Result.ImpersonatedUser                | Should -Match 'SYSTEM'
            $Result.LogonType                       | Should -BeNullOrEmpty
            $Result.TargetExecutableFilePath        | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId                 | Should -Not -BeNullOrEmpty
            $Result.NewProcessExecutablePath        | Should -Match 'cmd.exe'
            $Result.NewProcessCommandline           | Should -Match 'cmd.exe'
            $Result.NewProcessExecutableHash        | Should -Not -BeNullOrEmpty
            $Result.NewProcessId                    | Should -Not -BeNullOrEmpty

            $Result
        }

        It 'should logon user John Doe with fake credentials and impersonate impersonate user John Doe' {
            $Result = Invoke-ATHCreateProcessWithToken -CreateProcessVariant WithLogon -Credential $(New-Object System.Management.Automation.PSCredential ('JohnDoe', $(ConvertTo-SecureString 'fakecreds' -AsPlainText -Force))) -LogonFlag NewCredentials -ProcessCommandline 'C:\Windows\System32\cmd.exe' -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                     | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                     | Should -BeTrue
            $Result.TestGuid                        | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                     | Should -Not -BeNullOrEmpty
            $Result.SourceUser                      | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath        | Should -Match 'powershell.exe'
            $Result.SourceExecutableFileHash        | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId                 | Should -Not -BeNullOrEmpty
            $Result.GrantedRights                   | Should -BeNullOrEmpty
            $Result.ImpersonatedUser                | Should -Match 'JohnDoe'
            $Result.LogonType                       | Should -Match 'NewCredentials'
            $Result.TargetExecutableFilePath        | Should -BeNullOrEmpty
            $Result.TargetExecutableFileHash        | Should -BeNullOrEmpty
            $Result.TargetProcessId                 | Should -BeNullOrEmpty
            $Result.NewProcessExecutablePath        | Should -Match 'cmd.exe'
            $Result.NewProcessCommandline           | Should -Match 'cmd.exe'
            $Result.NewProcessExecutableHash        | Should -Not -BeNullOrEmpty
            $Result.NewProcessId                    | Should -Not -BeNullOrEmpty

            $Result
        }



    }
}