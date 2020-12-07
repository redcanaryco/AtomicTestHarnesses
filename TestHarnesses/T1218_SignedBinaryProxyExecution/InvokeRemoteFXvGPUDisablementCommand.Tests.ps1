Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Invoke-ATHRemoteFXvGPUDisablementCommand' {
    BeforeAll {
        $Help = Get-Help -Name Invoke-ATHRemoteFXvGPUDisablementCommand -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }

        $FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1218' {
        It 'should not execute an EXE that is not RemoteFXvGPUDisablement.exe' -Tag 'Unit', 'T1218' {
            { Invoke-ATHRemoteFXvGPUDisablementCommand -RemoteFXvGPUDisablementFilePath "$Env:windir\System32\notepad.exe" -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1218' {
        It 'should execute using default options' -Tag 'Technique', 'T1218' {
            $Result = Invoke-ATHRemoteFXvGPUDisablementCommand -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess       | Should -BeTrue
            $Result.TestGuid          | Should -BeExactly $FixedTestGuid
            $Result.ModulePath        | Should -Not -BeNullOrEmpty
            $Result.ModuleContents    | Should -Not -BeNullOrEmpty
            $Result.ModuleFileHash    | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath    | Should -Match '\\System32\\RemoteFXvGPUDisablement.exe$'
            $Result.RunnerProcessId   | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine | Should -Match '\\System32\\RemoteFXvGPUDisablement.exe" Disable$'
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -MatchExactly "$($FixedTestGuid)`$"
        }

        It 'should execute from a non-standard path' -Tag 'Technique', 'T1218' {
            $AlternatePath = "$env:windir\Temp\notepad.exe"

            Copy-Item -Path "$Env:windir\System32\RemoteFXvGPUDisablement.exe" -Destination $AlternatePath -ErrorAction Stop

            $Result = Invoke-ATHRemoteFXvGPUDisablementCommand -RemoteFXvGPUDisablementFilePath $AlternatePath -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess       | Should -BeTrue
            $Result.TestGuid          | Should -BeExactly $FixedTestGuid
            $Result.ModulePath        | Should -Not -BeNullOrEmpty
            $Result.ModuleContents    | Should -Not -BeNullOrEmpty
            $Result.ModuleFileHash    | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath    | Should -BeExactly "$AlternatePath"
            $Result.RunnerProcessId   | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine | Should -BeExactly "`"$AlternatePath`" Disable"
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -MatchExactly "$($FixedTestGuid)`$"

            Remove-Item -Path $AlternatePath -Force -ErrorAction SilentlyContinue
        }

        It 'should execute using a module path that is not specified in %PSModulePath%' -Tag 'Technique', 'T1218' {
            $Result = Invoke-ATHRemoteFXvGPUDisablementCommand -ModulePath $Env:TEMP -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess       | Should -BeTrue
            $Result.TestGuid          | Should -BeExactly $FixedTestGuid
            $Result.ModulePath.StartsWith("$Env:TEMP") | Should -BeTrue 
            $Result.ModuleContents    | Should -Not -BeNullOrEmpty
            $Result.ModuleFileHash    | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath    | Should -Match '\\System32\\RemoteFXvGPUDisablement.exe$'
            $Result.RunnerProcessId   | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine | Should -Match '\\System32\\RemoteFXvGPUDisablement.exe" Disable$'
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -MatchExactly "$($FixedTestGuid)`$"
        }
    }
}