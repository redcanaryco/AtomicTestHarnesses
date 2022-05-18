Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Invoke-ATHMSI' {
    BeforeAll {
        $Help = Get-Help -Name Invoke-ATHMSI -Full

        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }

        $FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1218.007' {
        It 'should fail to install MSI when an empty script content is supplied' {
            { Invoke-ATHMSI -ScriptContent $ScriptContent -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1218.007' {

        It 'should run the MSI file and launch VBScript code' {
            $Result = Invoke-ATHMSI -TestGuid $FixedTestGuid -DeleteMsi

            $Result | Should -Not -BeNullOrEmpty

            $Result

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                   | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                 | Should -BeExactly 'Msiexec'
            $Result.MsiAction                     | Should -BeExactly 'Install'
            $Result.MsiCustomAction               | Should -BeExactly 'Script'
            $Result.MsiScriptEngine               | Should -BeExactly 'VBScript'
            $Result.MsiScriptContent              | Should -Not -BeNullOrEmpty
            $Result.MsiFilePath                   | Should -Match 'Test\.msi$'
            $Result.MsiFileHash                   | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessId              | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessCommandLine     | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessName             | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessName        | Should -BeExactly 'powershell.exe'
            $Result.RunnerChildProcessCommandLine | Should -Not -BeNullOrEmpty
        }

        It 'should run the MSI file and launch VBScript code under the MSI action - Advertise' {
            $Result = Invoke-ATHMSI -ScriptEngine JScript -ExecutionType Msiexec -MSIAction Advertise -TestGuid $FixedTestGuid -DeleteMsi

            $Result | Should -Not -BeNullOrEmpty

            $Result

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                   | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                 | Should -BeExactly 'Msiexec'
            $Result.MsiAction                     | Should -BeExactly 'Advertise'
            $Result.MsiCustomAction               | Should -BeExactly 'Script'
            $Result.MsiScriptEngine               | Should -BeExactly 'JScript'
            $Result.MsiScriptContent              | Should -Not -BeNullOrEmpty
            $Result.MsiFilePath                   | Should -Match 'Test\.msi$'
            $Result.MsiFileHash                   | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessId              | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessCommandLine     | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessName             | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessName        | Should -BeExactly 'powershell.exe'
            $Result.RunnerChildProcessCommandLine | Should -Not -BeNullOrEmpty
        }

        It 'should run the MSI file with WMI under the MSI action - Install and launch executable code' {
            $Result = Invoke-ATHMSI -Exe -ExecutionType WMI -MSIAction Install -TestGuid $FixedTestGuid -DeleteMsi

            $Result | Should -Not -BeNullOrEmpty

            $Result

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                       | Should -BeTrue
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                       | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                     | Should -BeExactly 'WMI'
            $Result.MsiAction                         | Should -BeExactly 'Install'
            $Result.MsiCustomAction                   | Should -BeExactly 'Exe'
            $Result.MsiScriptEngine                   | Should -BeNull
            $Result.MsiScriptContent                  | Should -BeNull
            $Result.MsiFilePath                       | Should -Match 'Test\.msi$'
            $Result.MsiFileHash                       | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessId                  | Should -BeNull
            $Result.MsiExecProcessCommandLine         | Should -BeNull
            $Result.RunnerProcessId                   | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessName                 | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId              | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessName            | Should -Match 'MSI[A-Z0-9]{4}\.tmp'
            $Result.RunnerChildProcessCommandLine     | Should -Not -BeNullOrEmpty
        }

        It 'should run the MSI file with msiexec, and launch x86 DLL code' {
            $Result = Invoke-ATHMSI -Dll -MSIAction Admin -TestGuid $FixedTestGuid -DeleteMsi

            $Result | Should -Not -BeNullOrEmpty

            $Result

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                       | Should -BeTrue
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                       | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                     | Should -BeExactly 'Msiexec'
            $Result.MsiAction                         | Should -BeExactly 'Admin'
            $Result.MsiCustomAction                   | Should -BeExactly 'Dll'
            $Result.MsiScriptEngine                   | Should -BeNull
            $Result.MsiScriptContent                  | Should -BeNull
            $Result.MsiFilePath                       | Should -Match 'Test\.msi$'
            $Result.MsiFileHash                       | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessId                  | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessCommandLine         | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId                   | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId              | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessName            | Should -BeExactly 'powershell.exe'
            $Result.RunnerChildProcessCommandLine     | Should -Not -BeNullOrEmpty
        }

        It 'should run the MSI file with WMI under the Advertise MSI action, and launch DLL code' {
            $Result = Invoke-ATHMSI -Dll -ExecutionType WMI -MSIAction Advertise -TestGuid $FixedTestGuid -DeleteMsi

            $Result | Should -Not -BeNullOrEmpty

            $Result

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                       | Should -BeTrue
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                       | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                     | Should -BeExactly 'WMI'
            $Result.MsiAction                         | Should -BeExactly 'Advertise'
            $Result.MsiCustomAction                   | Should -BeExactly 'Dll'
            $Result.MsiScriptEngine                   | Should -BeNull
            $Result.MsiScriptContent                  | Should -BeNull
            $Result.MsiFilePath                       | Should -Match 'Test\.msi$'
            $Result.MsiFileHash                       | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessId                  | Should -BeNull
            $Result.MsiExecProcessCommandLine         | Should -BeNull
            $Result.RunnerProcessId                   | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId              | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessName            | Should -BeExactly 'powershell.exe'
            $Result.RunnerChildProcessCommandLine     | Should -Not -BeNullOrEmpty
        }

        It 'should run the MSI file with WMI under the MSI action - Admin and launch executable code' {
            $Result = Invoke-ATHMSI -Exe -ExecutionType WMI -MSIAction Admin -TestGuid $FixedTestGuid -DeleteMsi

            $Result | Should -Not -BeNullOrEmpty

            $Result

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                       | Should -BeTrue
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                       | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                     | Should -BeExactly 'WMI'
            $Result.MsiAction                         | Should -BeExactly 'Admin'
            $Result.MsiCustomAction                   | Should -BeExactly 'Exe'
            $Result.MsiScriptEngine                   | Should -BeNull
            $Result.MsiScriptContent                  | Should -BeNull
            $Result.MsiFilePath                       | Should -Match 'Test\.msi$'
            $Result.MsiFileHash                       | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessId                  | Should -BeNull
            $Result.MsiExecProcessCommandLine         | Should -BeNull
            $Result.RunnerProcessId                   | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId              | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessName            | Should -Match 'MSI[A-Z0-9]{4}\.tmp'
            $Result.RunnerChildProcessCommandLine     | Should -Not -BeNullOrEmpty
        }

        It 'should run the MSI file with COM, and launch x86 DLL code' {
            $Result = Invoke-ATHMSI -Dll -ExecutionType COM -DLLArchitecture x64 -TestGuid $FixedTestGuid -DeleteMsi

            $Result | Should -Not -BeNullOrEmpty

            $Result

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                       | Should -BeTrue
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                       | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                     | Should -BeExactly 'COM'
            $Result.MsiAction                         | Should -BeExactly 'Install'
            $Result.MsiCustomAction                   | Should -BeExactly 'Dll'
            $Result.MsiScriptEngine                   | Should -BeNull
            $Result.MsiScriptContent                  | Should -BeNull
            $Result.MsiFilePath                       | Should -Match 'Test\.msi$'
            $Result.MsiFileHash                       | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessId                  | Should -BeNull
            $Result.MsiExecProcessCommandLine         | Should -BeNull
            $Result.RunnerProcessId                   | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId              | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessName            | Should -BeExactly 'powershell.exe'
            $Result.RunnerChildProcessCommandLine     | Should -Not -BeNullOrEmpty
        }

        It 'should run the MSI file with COM, launch Executable code with MSI action - Admin' {
            $Result = Invoke-ATHMSI -Dll -ExecutionType COM -DLLArchitecture x64 -MsiAction Admin -TestGuid $FixedTestGuid -DeleteMsi

            $Result | Should -Not -BeNullOrEmpty

            $Result

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                       | Should -BeTrue
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                       | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                     | Should -BeExactly 'COM'
            $Result.MsiAction                         | Should -BeExactly 'Admin'
            $Result.MsiCustomAction                   | Should -BeExactly 'Dll'
            $Result.MsiScriptEngine                   | Should -BeNull
            $Result.MsiScriptContent                  | Should -BeNull
            $Result.MsiFilePath                       | Should -Match 'Test\.msi$'
            $Result.MsiFileHash                       | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessId                  | Should -BeNull
            $Result.MsiExecProcessCommandLine         | Should -BeNull
            $Result.RunnerProcessId                   | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId              | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessName            | Should -BeExactly 'powershell.exe'
            $Result.RunnerChildProcessCommandLine     | Should -Not -BeNullOrEmpty
        }

        It 'should run the MSI file with COM, with MSI action - Admin, and launch Executable code' {
            $Result = Invoke-ATHMSI -Exe -ExecutionType COM -MsiAction Admin -TestGuid $FixedTestGuid -DeleteMsi

            $Result | Should -Not -BeNullOrEmpty

            $Result

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                       | Should -BeTrue
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                       | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                     | Should -BeExactly 'COM'
            $Result.MsiAction                         | Should -BeExactly 'Admin'
            $Result.MsiCustomAction                   | Should -BeExactly 'Exe'
            $Result.MsiScriptEngine                   | Should -BeNull
            $Result.MsiScriptContent                  | Should -BeNull
            $Result.MsiFilePath                       | Should -Match 'Test\.msi$'
            $Result.MsiFileHash                       | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessId                  | Should -BeNull
            $Result.MsiExecProcessCommandLine         | Should -BeNull
            $Result.RunnerProcessId                   | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId              | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessName            | Should -Match 'MSI[A-Z0-9]{4}\.tmp'
            $Result.RunnerChildProcessCommandLine     | Should -Not -BeNullOrEmpty
        }

        It 'should run the MSI file with Win32API, with MSI action - Install, and launch script code' {
            $Result = Invoke-ATHMSI -ExecutionType Win32API -MsiAction Install -TestGuid $FixedTestGuid -DeleteMsi

            $Result | Should -Not -BeNullOrEmpty

            $Result

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                       | Should -BeTrue
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                       | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                     | Should -BeExactly 'Win32API'
            $Result.MsiAction                         | Should -BeExactly 'Install'
            $Result.MsiCustomAction                   | Should -BeExactly 'Script'
            $Result.MsiScriptEngine                   | Should -BeExactly 'VBScript'
            $Result.MsiScriptContent                  | Should -Not -BeNullOrEmpty
            $Result.MsiFilePath                       | Should -Match 'Test\.msi$'
            $Result.MsiFileHash                       | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessId                  | Should -BeNull
            $Result.MsiExecProcessCommandLine         | Should -BeNull
            $Result.RunnerProcessId                   | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId              | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessName            | Should -Match 'powershell.exe'
            $Result.RunnerChildProcessCommandLine     | Should -Not -BeNullOrEmpty
        }

        It 'should run the MSI file with Win32API, with MSI action - Advertise, and launch an embedded Exe' {
            $Result = Invoke-ATHMSI -Exe -ExecutionType Win32API -MsiAction Advertise -TestGuid $FixedTestGuid -DeleteMsi

            $Result | Should -Not -BeNullOrEmpty

            $Result

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                       | Should -BeTrue
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.TestCommand                       | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                     | Should -BeExactly 'Win32API'
            $Result.MsiAction                         | Should -BeExactly 'Advertise'
            $Result.MsiCustomAction                   | Should -BeExactly 'Exe'
            $Result.MsiScriptEngine                   | Should -BeNull
            $Result.MsiScriptContent                  | Should -BeNull
            $Result.MsiFilePath                       | Should -Match 'Test\.msi$'
            $Result.MsiFileHash                       | Should -Not -BeNullOrEmpty
            $Result.MsiExecProcessId                  | Should -BeNull
            $Result.MsiExecProcessCommandLine         | Should -BeNull
            $Result.RunnerProcessId                   | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId              | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessName            | Should -Match 'MSI[A-Z0-9]{4}\.tmp'
            $Result.RunnerChildProcessCommandLine     | Should -Not -BeNullOrEmpty
        }
    }
}
