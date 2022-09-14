Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Invoke-ATHLogonUser' {
    BeforeAll {
        $Help = Get-Help -Name Invoke-ATHLogonUser -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }

        $FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    }
    
    Context 'Validating error conditions' -Tag 'Unit', 'T1078.003' {
        It 'should fail to open process' {
            { Invoke-ATHLogonUser -ErrorAction Stop } | Should -Throw
        }

    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1078.003' {

        It 'should login user John Doe with fake credentials with a LOGON32_LOGON_NEW_CREDENTIALS logon type' {
            $Result = Invoke-ATHLogonUser -LogonType LOGON32_LOGON_NEW_CREDENTIALS -Credential $(New-Object System.Management.Automation.PSCredential ('JohnDoe', $(ConvertTo-SecureString 'fakecreds' -AsPlainText -Force)))  -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.TargetUser                  | Should -Match 'JohnDoe'
            $Result.LogonType                   | Should -Match 'LOGON32_LOGON_NEW_CREDENTIALS'
            $Result.LogonTypeId                 | Should -Match '9'

            $Result
        }


    }
}