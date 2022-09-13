Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

if (([IntPtr]::Size -eq 8)) {
    Describe 'Start-ATHProcessHerpaderp' {
        BeforeAll {
            $Help = Get-Help -Name Start-ATHProcessHerpaderp -Full
    
            $ExpectedTechniqueID = $null

            if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
                $ExpectedTechniqueID = $Matches['TechniqueID']
            }
        }

        Context 'Validating error conditions' -Tag 'Unit', 'T1055' {
            It 'should fail to process a non-existent source file' -Tag 'Unit', 'T1055' {
                { Start-ATHProcessHerpaderp -SourceFilePath "$env:SystemDrive\IDONOTEXIST.exe" -ErrorAction Stop } | Should -Throw
            }

            It 'should fail to process a non-existent replacement file' -Tag 'Unit', 'T1055' {
                { Start-ATHProcessHerpaderp -ReplacementFilePath "$env:SystemDrive\IDONOTEXIST.exe" -ErrorAction Stop } | Should -Throw
            }

            It 'should not process a source file that is not a portable executable (PE) file' -Tag 'Unit', 'T1055' {
                { Start-ATHProcessHerpaderp -SourceFilePath $MyInvocation.MyCommand.Path -ErrorAction Stop } | Should -Throw
            }

            It 'should not process a replacement file that is not a portable executable (PE) file' -Tag 'Unit', 'T1055' {
                { Start-ATHProcessHerpaderp -ReplacementFilePath $MyInvocation.MyCommand.Path -ErrorAction Stop } | Should -Throw
            }

            It 'should not process a source file that is larger than the replacement file' -Tag 'Unit', 'T1055' {
                { Start-ATHProcessHerpaderp -SourceFilePath "$Env:windir\System32\SnippingTool.exe" -ReplacementFilePath "$Env:windir\System32\cmd.exe" -ErrorAction Stop } | Should -Throw
            }

            It 'should not process a 32-bit source file' -Tag 'Unit', 'T1055' {
                { Start-ATHProcessHerpaderp -SourceFilePath "$Env:windir\SysWOW64\cmd.exe" -ErrorAction Stop } | Should -Throw
            }

            It 'should not process a 32-bit replacement file' -Tag 'Unit', 'T1055' {
                { Start-ATHProcessHerpaderp -ReplacementFilePath "$Env:windir\SysWOW64\cmd.exe" -ErrorAction Stop } | Should -Throw
            }
        }

        Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1055' {
            BeforeAll {
                $Script:FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            }

            It 'should execute without any arguments' -Tag 'Technique', 'T1055' {
                $Result = Start-ATHProcessHerpaderp -TestGuid $FixedTestGuid

                $Result | Should -Not -BeNullOrEmpty

                $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
                $Result.TestSuccess                   | Should -BeTrue
                $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
                $Result.ExecutionType                 | Should -BeExactly 'File'
                $Result.SourceExecutableFilePath      | Should -BeExactly "$PWD\test_executable.exe"
                $Result.SourceExecutableFileHash      | Should -Not -BeNullOrEmpty
                $Result.ReplacementExecutableFilePath | Should -BeExactly "$Env:windir\System32\SnippingTool.exe"
                $Result.ReplacementExecutableFileHash | Should -Not -BeNullOrEmpty
                $Result.TargetExecutablePath          | Should -BeExactly "$PWD\target.exe"
                $Result.ProcessId                     | Should -Not -BeNullOrEmpty
                $Result.ProcessPath                   | Should -BeExactly 'target.exe'
                $Result.ProcessCommandLine            | Should -BeExactly '"target.exe"'
                $Result.ProcessModule                 | Should -Not -BeNullOrEmpty
                $Result.ProcessMainThread             | Should -Not -BeNullOrEmpty
                $Result.ParentProcessId               | Should -Be $PID
                $Result.ParentProcessPath             | Should -Not -BeNullOrEmpty
                $Result.ParentProcessCommandLine      | Should -Not -BeNullOrEmpty
                $Result.ChildProcessId                | Should -Not -BeNullOrEmpty
                $Result.ChildProcessCommandLine       | Should -Match $FixedTestGuid
            }

            It 'should execute from the current PowerShell process specifying source and replacement executables on disk' -Tag 'Technique', 'T1055' {
                $Result = Start-ATHProcessHerpaderp -SourceFilePath "$Env:windir\System32\cmd.exe" -ReplacementFilePath "$Env:windir\System32\SnippingTool.exe" -TargetFilePath herp.exe -CommandLine 'User-supplied cmdline' -TestGuid $FixedTestGuid

                $Result | Should -Not -BeNullOrEmpty

                $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
                $Result.TestSuccess                   | Should -BeNullOrEmpty
                $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
                $Result.ExecutionType                 | Should -BeExactly 'File'
                $Result.SourceExecutableFilePath      | Should -BeExactly "$Env:windir\System32\cmd.exe"
                $Result.SourceExecutableFileHash      | Should -Not -BeNullOrEmpty
                $Result.ReplacementExecutableFilePath | Should -BeExactly "$Env:windir\System32\SnippingTool.exe"
                $Result.ReplacementExecutableFileHash | Should -Not -BeNullOrEmpty
                $Result.TargetExecutablePath          | Should -BeExactly "$PWD\herp.exe"
                $Result.ProcessId                     | Should -Not -BeNullOrEmpty
                $Result.ProcessPath                   | Should -BeExactly 'herp.exe'
                $Result.ProcessCommandLine            | Should -BeExactly 'User-supplied cmdline'
                $Result.ProcessModule                 | Should -Not -BeNullOrEmpty
                $Result.ProcessMainThread             | Should -Not -BeNullOrEmpty
                $Result.ParentProcessId               | Should -Be $PID
                $Result.ParentProcessPath             | Should -Not -BeNullOrEmpty
                $Result.ParentProcessCommandLine      | Should -Not -BeNullOrEmpty
                $Result.ChildProcessId                | Should -BeNullOrEmpty
                $Result.ChildProcessCommandLine       | Should -BeNullOrEmpty

                # Kill the spawned cmd.exe process
                Stop-Process -Id $Result.ProcessId -ErrorAction SilentlyContinue
            }

            It 'should execute as a child of the explorer.exe process specifying source and replacement executables on disk' -Tag 'Technique', 'T1055' {
                $ExplorerProcess = Get-Process -Name explorer | Select-Object -First 1
                $ExplorerProcess | Should -Not -BeNullOrEmpty

                $Result = $ExplorerProcess | Start-ATHProcessHerpaderp -SourceFilePath "$Env:windir\System32\cmd.exe" -ReplacementFilePath "$Env:windir\System32\SnippingTool.exe" -TargetFilePath herp.exe -CommandLine 'User-supplied cmdline' -TestGuid $FixedTestGuid

                $Result | Should -Not -BeNullOrEmpty

                $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
                $Result.TestSuccess                   | Should -BeNullOrEmpty
                $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
                $Result.ExecutionType                 | Should -BeExactly 'File'
                $Result.SourceExecutableFilePath      | Should -BeExactly "$Env:windir\System32\cmd.exe"
                $Result.SourceExecutableFileHash      | Should -Not -BeNullOrEmpty
                $Result.ReplacementExecutableFilePath | Should -BeExactly "$Env:windir\System32\SnippingTool.exe"
                $Result.ReplacementExecutableFileHash | Should -Not -BeNullOrEmpty
                $Result.TargetExecutablePath          | Should -BeExactly "$PWD\herp.exe"
                $Result.ProcessId                     | Should -Not -BeNullOrEmpty
                $Result.ProcessPath                   | Should -BeExactly 'herp.exe'
                $Result.ProcessCommandLine            | Should -BeExactly 'User-supplied cmdline'
                $Result.ProcessModule                 | Should -Not -BeNullOrEmpty
                $Result.ProcessMainThread             | Should -Not -BeNullOrEmpty
                $Result.ParentProcessId               | Should -Be $ExplorerProcess.Id
                $Result.ParentProcessPath             | Should -Not -BeNullOrEmpty
                $Result.ParentProcessCommandLine      | Should -Not -BeNullOrEmpty
                $Result.ChildProcessId                | Should -BeNullOrEmpty
                $Result.ChildProcessCommandLine       | Should -BeNullOrEmpty

                # Kill the spawned cmd.exe process
                Stop-Process -Id $Result.ProcessId -ErrorAction SilentlyContinue
            }

            It 'should execute from the current PowerShell process specifying source and replacement executables as byte arrays' -Tag 'Technique', 'T1055' {
                $SourceBytes = [IO.File]::ReadAllBytes("$Env:windir\System32\cmd.exe")
                $ReplacementBytes = [IO.File]::ReadAllBytes("$Env:windir\System32\SnippingTool.exe")

                $Result = Start-ATHProcessHerpaderp -SourceFileBytes $SourceBytes -ReplacementFileBytes $ReplacementBytes -TargetFilePath herp.exe -CommandLine 'User-supplied cmdline' -TestGuid $FixedTestGuid

                $Result | Should -Not -BeNullOrEmpty

                $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
                $Result.TestSuccess                   | Should -BeNullOrEmpty
                $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
                $Result.ExecutionType                 | Should -BeExactly 'Memory'
                $Result.SourceExecutableFilePath      | Should -BeNullOrEmpty
                $Result.SourceExecutableFileHash      | Should -Not -BeNullOrEmpty
                $Result.ReplacementExecutableFilePath | Should -BeNullOrEmpty
                $Result.ReplacementExecutableFileHash | Should -Not -BeNullOrEmpty
                $Result.TargetExecutablePath          | Should -BeExactly "$PWD\herp.exe"
                $Result.ProcessId                     | Should -Not -BeNullOrEmpty
                $Result.ProcessPath                   | Should -BeExactly 'herp.exe'
                $Result.ProcessCommandLine            | Should -BeExactly 'User-supplied cmdline'
                $Result.ProcessModule                 | Should -Not -BeNullOrEmpty
                $Result.ProcessMainThread             | Should -Not -BeNullOrEmpty
                $Result.ParentProcessId               | Should -Be $PID
                $Result.ParentProcessPath             | Should -Not -BeNullOrEmpty
                $Result.ParentProcessCommandLine      | Should -Not -BeNullOrEmpty
                $Result.ChildProcessId                | Should -BeNullOrEmpty
                $Result.ChildProcessCommandLine       | Should -BeNullOrEmpty

                # Kill the spawned cmd.exe process
                Stop-Process -Id $Result.ProcessId -Force -ErrorAction SilentlyContinue
            }

            It 'should execute as a child of the explorer.exe process specifying source and replacement executables as byte arrays' -Tag 'Technique', 'T1055' {
                $ExplorerProcess = Get-Process -Name explorer | Select-Object -First 1
                $ExplorerProcess | Should -Not -BeNullOrEmpty

                $SourceBytes = [IO.File]::ReadAllBytes("$Env:windir\System32\cmd.exe")
                $ReplacementBytes = [IO.File]::ReadAllBytes("$Env:windir\System32\SnippingTool.exe")

                $Result = $ExplorerProcess | Start-ATHProcessHerpaderp -SourceFileBytes $SourceBytes -ReplacementFileBytes $ReplacementBytes -TargetFilePath herp.exe -CommandLine 'User-supplied cmdline' -TestGuid $FixedTestGuid

                $Result | Should -Not -BeNullOrEmpty

                $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
                $Result.TestSuccess                   | Should -BeNullOrEmpty
                $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
                $Result.ExecutionType                 | Should -BeExactly 'Memory'
                $Result.SourceExecutableFilePath      | Should -BeNullOrEmpty
                $Result.SourceExecutableFileHash      | Should -Not -BeNullOrEmpty
                $Result.ReplacementExecutableFilePath | Should -BeNullOrEmpty
                $Result.ReplacementExecutableFileHash | Should -Not -BeNullOrEmpty
                $Result.TargetExecutablePath          | Should -BeExactly "$PWD\herp.exe"
                $Result.ProcessId                     | Should -Not -BeNullOrEmpty
                $Result.ProcessPath                   | Should -BeExactly 'herp.exe'
                $Result.ProcessCommandLine            | Should -BeExactly 'User-supplied cmdline'
                $Result.ProcessModule                 | Should -Not -BeNullOrEmpty
                $Result.ProcessMainThread             | Should -Not -BeNullOrEmpty
                $Result.ParentProcessId               | Should -Be $ExplorerProcess.Id
                $Result.ParentProcessPath             | Should -Not -BeNullOrEmpty
                $Result.ParentProcessCommandLine      | Should -Not -BeNullOrEmpty
                $Result.ChildProcessId                | Should -BeNullOrEmpty
                $Result.ChildProcessCommandLine       | Should -BeNullOrEmpty

                # Kill the spawned cmd.exe process
                Stop-Process -Id $Result.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
    }
} else {
    Write-Warning "Start-ATHProcessHerpaderp is not designed to operate in a 32-bit environment"

    Describe 'Start-ATHProcessHerpaderp' {
        Context 'Validating error conditions' -Tag 'Unit', 'T1055' {
            It 'should fail to execute in a 32-bit environment' -Tag 'Unit', 'T1055' {
                { Start-ATHProcessHerpaderp -ErrorAction Stop } | Should -Throw
            }
        }
    }
}