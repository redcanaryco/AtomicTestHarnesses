Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Invoke-ATHMSBuild' {
    BeforeAll {
        $Help = Get-Help -Name Invoke-ATHMSBuild -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }

        $FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1127.001' {
        It 'should not execute an executable that is not MSBuild' -Tag 'Unit', 'T1127.001' {
            { Invoke-ATHMSBuild -MSBuildFilePath "$Env:windir\System32\notepad.exe" -ErrorAction Stop } | Should -Throw
        }

        It 'should not accept a project file in a non-existent directory' -Tag 'Unit', 'T1127.001' {
            $BogusPath = 'C:\dsdfsiuhsdrfsawgfds\sdlfksdjflksdj'

            Test-Path -Path $BogusPath -PathType Container | Should -BeFalse

            { Invoke-ATHMSBuild -ProjectFilePath $BogusPath -ErrorAction Stop } | Should -Throw
        }

        It 'should not accept a custom engine DLL in a non-existent directory' -Tag 'Unit', 'T1127.001' {
            $BogusPath = 'C:\dsdfsiuhsdrfsawgfds\sdlfksdjflksdj'

            Test-Path -Path $BogusPath -PathType Container | Should -BeFalse

            { Invoke-ATHMSBuild -UseCustomTaskFactory -CustomEngineDllPath $BogusPath -ErrorAction Stop } | Should -Throw
        }

        It 'should not execute when more then one *proj file is present when no command-line args are supplied' -Tag 'Unit', 'T1127.001' {
            $ProjFile1 = New-Item -Path test_project_1.proj -Force -ErrorAction SilentlyContinue
            $ProjFile2 = New-Item -Path test_project_2.proj -Force -ErrorAction SilentlyContinue
            
            { Invoke-ATHMSBuild -NoCLIProjectFile -ErrorAction Stop } | Should -Throw

            Remove-Item -Path test_project_1.proj -Force -ErrorAction SilentlyContinue
            Remove-Item -Path test_project_2.proj -Force -ErrorAction SilentlyContinue
        }

        It 'should not accept a non-*proj file extension when no command-line args are supplied' -Tag 'Unit', 'T1127.001' {
            { Invoke-ATHMSBuild -ProjectFilePath test.txt -NoCLIProjectFile -ErrorAction Stop } | Should -Throw
        }

        It 'should indicate that the MSBuild runner process failed to start' -Tag 'Unit', 'T1127.001' {
            Mock Invoke-CimMethod { return @{ ReturnValue = 1 } }

            { Invoke-ATHMSBuild -ErrorAction Stop } | Should -Throw
        }

        It 'should indicate that the MSBuild child process failed to launch' -Tag 'Unit', 'T1127.001' {
            Mock Wait-Event { return $null }

            { Invoke-ATHMSBuild -ErrorAction Stop } | Should -Throw
        }

        It 'should accept custom project XML' -Tag 'Unit', 'T1127.001' {
            $ProjectXml = @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="TestTarget">
    <TestTask />
  </Target>
  <UsingTask TaskName="TestTask" TaskFactory="CodeTaskFactory" AssemblyFile="$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Code Language="cs">
        <![CDATA[
        System.Console.WriteLine("Hello");
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
"@

            $Result = Invoke-ATHMSBuild -ProjectFileContent $ProjectXml
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeNullOrEmpty
            $Result.TestGuid                      | Should -BeNullOrEmpty
            $Result.ExecutionType                 | Should -BeExactly 'CustomProjectFileContent'
            $Result.ProjectFilePath               | Should -Not -BeNullOrEmpty
            $Result.ProjectFileHashSHA256         | Should -Not -BeNullOrEmpty
            $Result.ProjectContents               | Should -BeExactly $ProjectXml
            $Result.CustomEnginePath              | Should -BeNullOrEmpty
            $Result.CustomEngineHashSHA256        | Should -BeNullOrEmpty
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId          | Should -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -BeNullOrEmpty
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1127.001' {
        BeforeAll {
            $Script:DefaultMSBuildPath = "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())MSBuild.exe"
            $Script:AlternateMSBuildPath = "$env:windir\Temp\notepad.exe"

            Copy-Item -Path $Script:DefaultMSBuildPath -Destination $Script:AlternateMSBuildPath

            $Script:AlternateProjectFileName = 'test.txt'
        }

        It 'should compile and execute embedded .NET code (Language: <Language>, UseAlternateMSBuildPath: <UseAlternateMSBuildPath>, UseAlternateProjectFilename: <UseAlternateProjectFilename>, OmitProjectFromCLI: <OmitProjectFromCLI>)' -Tag 'Technique', 'T1127.001' {
            $Arguments = @{}

            if ($UseAlternateProjectFilename) {
                $ExpectedFileName = $AlternateProjectFileName

                $Arguments['ProjectFilePath'] = $ExpectedFileName
            } else {
                $ExpectedFileName = 'test.proj'
            }

            if ($UseAlternateMSBuildPath) {
                $ExpectedMSBuildFileName = $AlternateMSBuildPath.Split('\')[-1]
                $ExpectedMSBuildPath = $AlternateMSBuildPath

                $Arguments['MSBuildFilePath'] = $AlternateMSBuildPath
            } else {
                $ExpectedMSBuildFileName = 'MSBuild.exe'
                $ExpectedMSBuildPath = $DefaultMSBuildPath
            }

            if ($OmitProjectFromCLI) {
                $Arguments['NoCLIProjectFile'] = $True

                $IsCLIPresent = $False
            } else {
                $IsCLIPresent = $True
            }
            
            $Result = Invoke-ATHMSBuild -Language $Language -TestGuid $FixedTestGuid @Arguments
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'InlineSourceCode'
            $Result.ProjectFilePath.EndsWith($ExpectedFileName) | Should -Be $True
            $Result.ProjectFileHashSHA256         | Should -Not -BeNullOrEmpty
            $Result.ProjectContents               | Should -Match "<Code Language=`"$Language`">"
            $Result.CustomEnginePath              | Should -BeNullOrEmpty
            $Result.CustomEngineHashSHA256        | Should -BeNullOrEmpty
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath.ToLower()      | Should -BeExactly $ExpectedMSBuildPath.ToLower()
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine.EndsWith($ExpectedFileName) | Should -Be $IsCLIPresent
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result
        } -TestCases @(
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; Language = 'cs' },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; Language = 'cs' },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; Language = 'cs' },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; Language = 'cs' },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; Language = 'cs' },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; Language = 'cs' },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; Language = 'vb' },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; Language = 'vb' },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; Language = 'vb' },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; Language = 'vb' },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; Language = 'vb' },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; Language = 'vb' },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; Language = 'js' },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; Language = 'js' },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; Language = 'js' },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; Language = 'js' },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; Language = 'js' },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; Language = 'js' }
        )

        It 'should execute embedded property function code (UseAlternateMSBuildPath: <UseAlternateMSBuildPath>, UseAlternateProjectFilename: <UseAlternateProjectFilename>, OmitProjectFromCLI: <OmitProjectFromCLI>)' -Tag 'Technique', 'T1127.001' {
            $Arguments = @{}

            if ($UseAlternateProjectFilename) {
                $ExpectedFileName = $AlternateProjectFileName

                $Arguments['ProjectFilePath'] = $ExpectedFileName
            } else {
                $ExpectedFileName = 'test.proj'
            }

            if ($UseAlternateMSBuildPath) {
                $ExpectedMSBuildFileName = $AlternateMSBuildPath.Split('\')[-1]
                $ExpectedMSBuildPath = $AlternateMSBuildPath

                $Arguments['MSBuildFilePath'] = $AlternateMSBuildPath
            } else {
                $ExpectedMSBuildFileName = 'MSBuild.exe'
                $ExpectedMSBuildPath = $DefaultMSBuildPath
            }

            if ($OmitProjectFromCLI) {
                $Arguments['NoCLIProjectFile'] = $True

                $IsCLIPresent = $False
            } else {
                $IsCLIPresent = $True
            }
            
            $Result = Invoke-ATHMSBuild -UsePropertyFunctions -TestGuid $FixedTestGuid @Arguments
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'PropertyFunctions'
            $Result.ProjectFilePath.EndsWith($ExpectedFileName) | Should -Be $True
            $Result.ProjectFileHashSHA256         | Should -Not -BeNullOrEmpty
            $Result.ProjectContents               | Should -Match '\$\(\[System.Diagnostics.Process\]::Start\('
            $Result.CustomEnginePath              | Should -BeNullOrEmpty
            $Result.CustomEngineHashSHA256        | Should -BeNullOrEmpty
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath.ToLower()      | Should -BeExactly $ExpectedMSBuildPath.ToLower()
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine.EndsWith($ExpectedFileName) | Should -Be $IsCLIPresent
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result
        } -TestCases @(
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True  },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True  },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False }
        )

        It 'should execute a custom assembly unregistration method (UseAlternateMSBuildPath: <UseAlternateMSBuildPath>, UseAlternateProjectFilename: <UseAlternateProjectFilename>, OmitProjectFromCLI: <OmitProjectFromCLI>, UseCustomEngineDllPath: <UseCustomEngineDllPath>)' -Tag 'Technique', 'T1127.001' {
            $Arguments = @{}

            if ($UseAlternateProjectFilename) {
                $ExpectedFileName = $AlternateProjectFileName

                $Arguments['ProjectFilePath'] = $ExpectedFileName
            } else {
                $ExpectedFileName = 'test.proj'
            }

            if ($UseAlternateMSBuildPath) {
                $ExpectedMSBuildFileName = $AlternateMSBuildPath.Split('\')[-1]
                $ExpectedMSBuildPath = $AlternateMSBuildPath

                $Arguments['MSBuildFilePath'] = $AlternateMSBuildPath
            } else {
                $ExpectedMSBuildFileName = 'MSBuild.exe'
                $ExpectedMSBuildPath = $DefaultMSBuildPath
            }

            if ($OmitProjectFromCLI) {
                $Arguments['NoCLIProjectFile'] = $True

                $IsCLIPresent = $False
            } else {
                $IsCLIPresent = $True
            }

            if ($UseCustomEngineDllPath) {
                $ExpectedEngineName = 'CustomEngine.txt'

                $Arguments['CustomEngineDllPath'] = $ExpectedEngineName
            } else {
                $ExpectedEngineName = 'CustomEngine.dll'
            }
            
            $Result = Invoke-ATHMSBuild -UseUnregisterAssemblyTask -TestGuid $FixedTestGuid @Arguments
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'CustomUnregisterFunction'
            $Result.ProjectFilePath.EndsWith($ExpectedFileName) | Should -Be $True
            $Result.ProjectFileHashSHA256         | Should -Not -BeNullOrEmpty
            $Result.ProjectContents               | Should -Match 'UnregisterAssembly Assemblies'
            $Result.CustomEnginePath.EndsWith($ExpectedEngineName) | Should -Be $True
            $Result.CustomEngineHashSHA256        | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath.ToLower()      | Should -BeExactly $ExpectedMSBuildPath.ToLower()
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine.EndsWith($ExpectedFileName) | Should -Be $IsCLIPresent
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result
        } -TestCases @(
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True }
        )

        It 'should execute a custom logger assembly (UseAlternateMSBuildPath: <UseAlternateMSBuildPath>, UseAlternateProjectFilename: <UseAlternateProjectFilename>, OmitProjectFromCLI: <OmitProjectFromCLI>, UseCustomEngineDllPath: <UseCustomEngineDllPath>)' -Tag 'Technique', 'T1127.001' {
            $Arguments = @{}

            if ($UseAlternateProjectFilename) {
                $ExpectedFileName = $AlternateProjectFileName

                $Arguments['ProjectFilePath'] = $ExpectedFileName
            } else {
                $ExpectedFileName = 'test.proj'
            }

            if ($UseAlternateMSBuildPath) {
                $ExpectedMSBuildFileName = $AlternateMSBuildPath.Split('\')[-1]
                $ExpectedMSBuildPath = $AlternateMSBuildPath

                $Arguments['MSBuildFilePath'] = $AlternateMSBuildPath
            } else {
                $ExpectedMSBuildFileName = 'MSBuild.exe'
                $ExpectedMSBuildPath = $DefaultMSBuildPath
            }

            if ($OmitProjectFromCLI) {
                $Arguments['NoCLIProjectFile'] = $True

                $IsCLIPresent = $False
            } else {
                $IsCLIPresent = $True
            }

            if ($UseCustomEngineDllPath) {
                $ExpectedEngineName = 'CustomEngine.txt'

                $Arguments['CustomEngineDllPath'] = $ExpectedEngineName
            } else {
                $ExpectedEngineName = 'CustomEngine.dll'
            }
            
            $Result = Invoke-ATHMSBuild -UseCustomLogger -TestGuid $FixedTestGuid @Arguments
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'CustomLogger'
            $Result.ProjectFilePath.EndsWith($ExpectedFileName) | Should -Be $True
            $Result.ProjectFileHashSHA256         | Should -Not -BeNullOrEmpty
            $Result.ProjectContents               | Should -Match 'Message Text'
            $Result.CustomEnginePath.EndsWith($ExpectedEngineName) | Should -Be $True
            $Result.CustomEngineHashSHA256        | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath.ToLower()      | Should -BeExactly $ExpectedMSBuildPath.ToLower()
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine.EndsWith($ExpectedFileName) | Should -Be $IsCLIPresent
            $Result.RunnerCommandLine             | Should -Match 'logger'
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result
        } -TestCases @(
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True }
        )

        It 'should execute a custom assembly unregistration method (UseAlternateMSBuildPath: <UseAlternateMSBuildPath>, UseAlternateProjectFilename: <UseAlternateProjectFilename>, OmitProjectFromCLI: <OmitProjectFromCLI>, UseCustomEngineDllPath: <UseCustomEngineDllPath>)' -Tag 'Technique', 'T1127.001' {
            $Arguments = @{}

            if ($UseAlternateProjectFilename) {
                $ExpectedFileName = $AlternateProjectFileName

                $Arguments['ProjectFilePath'] = $ExpectedFileName
            } else {
                $ExpectedFileName = 'test.proj'
            }

            if ($UseAlternateMSBuildPath) {
                $ExpectedMSBuildFileName = $AlternateMSBuildPath.Split('\')[-1]
                $ExpectedMSBuildPath = $AlternateMSBuildPath

                $Arguments['MSBuildFilePath'] = $AlternateMSBuildPath
            } else {
                $ExpectedMSBuildFileName = 'MSBuild.exe'
                $ExpectedMSBuildPath = $DefaultMSBuildPath
            }

            if ($OmitProjectFromCLI) {
                $Arguments['NoCLIProjectFile'] = $True

                $IsCLIPresent = $False
            } else {
                $IsCLIPresent = $True
            }

            if ($UseCustomEngineDllPath) {
                $ExpectedEngineName = 'CustomEngine.txt'

                $Arguments['CustomEngineDllPath'] = $ExpectedEngineName
            } else {
                $ExpectedEngineName = 'CustomEngine.dll'
            }
            
            $Result = Invoke-ATHMSBuild -UseUnregisterAssemblyTask -TestGuid $FixedTestGuid @Arguments
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'CustomUnregisterFunction'
            $Result.ProjectFilePath.EndsWith($ExpectedFileName) | Should -Be $True
            $Result.ProjectFileHashSHA256         | Should -Not -BeNullOrEmpty
            $Result.ProjectContents               | Should -Match 'UnregisterAssembly Assemblies'
            $Result.CustomEnginePath.EndsWith($ExpectedEngineName) | Should -Be $True
            $Result.CustomEngineHashSHA256        | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath.ToLower()      | Should -BeExactly $ExpectedMSBuildPath.ToLower()
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine.EndsWith($ExpectedFileName) | Should -Be $IsCLIPresent
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result
        } -TestCases @(
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True }
        )

        It 'should execute a custom task factory assembly (UseAlternateMSBuildPath: <UseAlternateMSBuildPath>, UseAlternateProjectFilename: <UseAlternateProjectFilename>, OmitProjectFromCLI: <OmitProjectFromCLI>, UseCustomEngineDllPath: <UseCustomEngineDllPath>)' -Tag 'Technique', 'T1127.001' {
            $Arguments = @{}

            if ($UseAlternateProjectFilename) {
                $ExpectedFileName = $AlternateProjectFileName

                $Arguments['ProjectFilePath'] = $ExpectedFileName
            } else {
                $ExpectedFileName = 'test.proj'
            }

            if ($UseAlternateMSBuildPath) {
                $ExpectedMSBuildFileName = $AlternateMSBuildPath.Split('\')[-1]
                $ExpectedMSBuildPath = $AlternateMSBuildPath

                $Arguments['MSBuildFilePath'] = $AlternateMSBuildPath
            } else {
                $ExpectedMSBuildFileName = 'MSBuild.exe'
                $ExpectedMSBuildPath = $DefaultMSBuildPath
            }

            if ($OmitProjectFromCLI) {
                $Arguments['NoCLIProjectFile'] = $True

                $IsCLIPresent = $False
            } else {
                $IsCLIPresent = $True
            }

            if ($UseCustomEngineDllPath) {
                $ExpectedEngineName = 'CustomEngine.txt'

                $Arguments['CustomEngineDllPath'] = $ExpectedEngineName
            } else {
                $ExpectedEngineName = 'CustomEngine.dll'
            }
            
            $Result = Invoke-ATHMSBuild -UseCustomTaskFactory -TestGuid $FixedTestGuid @Arguments
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'CustomTaskFactory'
            $Result.ProjectFilePath.EndsWith($ExpectedFileName) | Should -Be $True
            $Result.ProjectFileHashSHA256         | Should -Not -BeNullOrEmpty
            $Result.ProjectContents               | Should -Match "<Task>$FixedTestGuid</Task>"
            $Result.CustomEnginePath.EndsWith($ExpectedEngineName) | Should -Be $True
            $Result.CustomEngineHashSHA256        | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath.ToLower()      | Should -BeExactly $ExpectedMSBuildPath.ToLower()
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine.EndsWith($ExpectedFileName) | Should -Be $IsCLIPresent
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result
        } -TestCases @(
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $False },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $False; UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $False; OmitProjectFromCLI = $True ; UseCustomEngineDllPath = $True },
            @{ UseAlternateMSBuildPath = $True;  UseAlternateProjectFilename = $True;  OmitProjectFromCLI = $False; UseCustomEngineDllPath = $True }
        )
    }
}