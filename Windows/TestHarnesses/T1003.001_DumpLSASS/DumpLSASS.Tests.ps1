Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Invoke-ATHDumpLSASS' {
    BeforeAll {
        $Help = Get-Help -Name Invoke-ATHDumpLSASS -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }

        $FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    }
    
    Context 'Validating error conditions' -Tag 'Unit', 'T1003.001' {
        It 'should fail to open process' {
            { Invoke-ATHDumpLSASS -ProcessId 0000 -ErrorAction Stop } | Should -Throw
        }

        It 'should fail to open a handle with the specified access rights' {
            { Invoke-ATHDumpLSASS -AccessRights CreateThread -ErrorAction Stop } | Should -Throw
        }

    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1003.001' {
        It 'should read LSASSs process memory via Dbghelp!MiniDumpWriteDump function' {
            $Result =  Invoke-ATHDumpLSASS -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty
            
            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.Variant                     | Should -match 'Dbghelp!MiniDumpWriteDump'
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -Match 'QueryInformation, VirtualMemoryRead'
            $Result.TargetExecutableFilePath    | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId             | Should -Not -BeNullOrEmpty
            $Result.DumpFile                    | Should -BeExactly 'C:\TestHarness.dmp'

            $Result
        }

        It 'should get LSASSs PID via Get-Process and pipe PID into Invoke-ATHDumpLSASS then read LSASSs process memory via Dbghelp!MiniDumpWriteDump function' {
            $Result =  Get-Process -name lsass | Invoke-ATHDumpLSASS -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty
            
            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.Variant                     | Should -match 'Dbghelp!MiniDumpWriteDump'
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -Match 'QueryInformation, VirtualMemoryRead'
            $Result.TargetExecutableFilePath    | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId             | Should -Not -BeNullOrEmpty
            $Result.DumpFile                    | Should -BeExactly 'C:\TestHarness.dmp'

            $Result
        }

        It 'should read LSASSs process memory via Kernel32!ReadProcessMemory function' {
            $Result =  Invoke-ATHDumpLSASS -Variant Kernel32!ReadProcessMemory -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty
            
            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.Variant                     | Should -match 'Kernel32!ReadProcessMemory'
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -Match 'QueryInformation, VirtualMemoryRead'
            $Result.TargetExecutableFilePath    | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId             | Should -Not -BeNullOrEmpty
            $Result.DumpFile                    | Should -BeNullOrEmpty

            $Result
        }

        It 'should read LSASSs process memory via Kernel32!ReadProcessMemory function with AllAccess' {
            $Result =  Invoke-ATHDumpLSASS -Variant Kernel32!ReadProcessMemory -AccessRights AllAccess -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty
            
            $Result.TechniqueID                 | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                 | Should -BeTrue
            $Result.TestGuid                    | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                 | Should -Not -BeNullOrEmpty
            $Result.Variant                     | Should -match 'Kernel32!ReadProcessMemory'
            $Result.SourceUser                  | Should -Not -BeNullOrEmpty
            $Result.SourceExecutableFilePath    | Should -match 'powershell.exe'
            $Result.SourceExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId             | Should -Not -BeNullOrEmpty
            $Result.GrantedRights               | Should -Match 'AllAccess'
            $Result.TargetExecutableFilePath    | Should -Match 'lsass.exe'
            $Result.TargetExecutableFileHash    | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId             | Should -Not -BeNullOrEmpty
            $Result.DumpFile                    | Should -BeNullOrEmpty

            $Result
        }

    }
}