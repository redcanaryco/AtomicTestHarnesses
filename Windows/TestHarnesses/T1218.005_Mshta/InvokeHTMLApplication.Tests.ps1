Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Invoke-ATHHTMLApplication' {
    BeforeAll {
        $Help = Get-Help -Name Invoke-ATHHTMLApplication -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }

        $HTAFileName = 'test.hta'
        $FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1218.005' {
        It 'mshta.exe execution should not execute notepad.exe' -Tag 'Unit', 'T1218.005' {
            { Invoke-ATHHTMLApplication -HTAFilePath "$Env:windir\System32\notepad.exe" -ErrorAction Stop } | Should -Throw
        }

        It 'rundll32.exe execution should not execute notepad.exe' -Tag 'Unit', 'T1218.005' {
            { Invoke-ATHHTMLApplication -UseRundll32 -Rundll32FilePath "$Env:windir\System32\notepad.exe" -ErrorAction Stop } | Should -Throw
        }

        It 'should not run test when current working directory is the same as mshta.exe path' -Tag 'Unit', 'T1218.005' {
            Push-Location
            # Set current directory to the same directory as mshta.exe
            Set-Location -Path "$Env:windir\System32"

            { Invoke-ATHHTMLApplication -ErrorAction Stop } | Should -Throw

            Pop-Location
        }

        It 'should not run test when a non-existent HTA path is specified' -Tag 'Unit', 'T1218.005' {
            $BogusPath = 'C:\dsdfsiuhsdrfsawgfds'

            Test-Path -Path $BogusPath -PathType Container | Should -BeFalse

            { Invoke-ATHHTMLApplication -HTAFilePath $BogusPath -ErrorAction Stop } | Should -Throw
        }

        It 'should not run test when an HTA file is specified without an .hta extension when -SimulateUserDoubleClick is supplied' -Tag 'Unit', 'T1218.005' {
            { Invoke-ATHHTMLApplication -HTAFilePath Test.csv -SimulateUserDoubleClick -ErrorAction Stop } | Should -Throw
        }

        It 'should indicate that the HTA runner process failed to start' -Tag 'Unit', 'T1218.005' {
            Mock Invoke-CimMethod { return @{ ReturnValue = 1 } }

            { Invoke-ATHHTMLApplication -ErrorAction Stop } | Should -Throw

            $Result = Invoke-ATHHTMLApplication -ErrorAction SilentlyContinue

            Should -Invoke Invoke-CimMethod -Times 2

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeNullOrEmpty
            $Result.TestGuid                      | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                 | Should -Not -BeNullOrEmpty
            $Result.ScriptEngine                  | Should -Not -BeNullOrEmpty
            $Result.HTAFilePath                   | Should -Not -BeNullOrEmpty
            $Result.HTAFileHashSHA256             | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId               | Should -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -BeNullOrEmpty
            $Result.RunnerChildProcessId          | Should -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -BeNullOrEmpty
        }

        It 'should indicate that the HTA child process failed to launch' -Tag 'Unit', 'T1218.005' {
            Mock Wait-Event { return $null }

            { Invoke-ATHHTMLApplication -ErrorAction Stop } | Should -Throw

            $Result = Invoke-ATHHTMLApplication -ErrorAction SilentlyContinue

            Should -Invoke Wait-Event -Times 2

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeNullOrEmpty
            $Result.TestGuid                      | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                 | Should -Not -BeNullOrEmpty
            $Result.ScriptEngine                  | Should -Not -BeNullOrEmpty
            $Result.HTAFilePath                   | Should -Not -BeNullOrEmpty
            $Result.HTAFileHashSHA256             | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId               | Should -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -BeNullOrEmpty
            $Result.RunnerChildProcessId          | Should -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -BeNullOrEmpty
        }

        It 'should not accept VBScript.Encode as a script engine when the "about" protocol handler is used' -Tag 'Unit', 'T1218.005' {
            { Invoke-ATHHTMLApplication -InlineProtocolHandler About -ScriptEngine VBScript.Encode -ErrorAction Stop } | Should -Throw
        }

        It 'should not accept JScript.Encode as a script engine when the "about" protocol handler is used' -Tag 'Unit', 'T1218.005' {
            { Invoke-ATHHTMLApplication -InlineProtocolHandler About -ScriptEngine JScript.Encode -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1218.005' {
        It 'should accept and execute manually-suppled WSH wscript code' -Tag 'Technique', 'T1218.005' {

            $ScriptCode = @'
var objShell = new ActiveXObject('Wscript.Shell');
objShell.Run("powershell.exe -nop -Command Start-Sleep -Seconds 2; exit", 0, true);
window.close();
'@ # Hash (after being inserted into an HTA block): B6ABDFAED84EAFC826E1CF3637C3DBB0D33AB8611B9D4C32D6CEA602F091AED6

            $Result = Invoke-ATHHTMLApplication -ScriptContent $ScriptCode -ScriptEngine JScript -HTAFilePath $HTAFileName -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeNullOrEmpty
            $Result.TestGuid                      | Should -BeNullOrEmpty
            $Result.ExecutionType                 | Should -BeExactly 'File'
            $Result.ScriptEngine                  | Should -BeExactly 'JScript'
            $Result.HTAFilePath.EndsWith($HTAFileName) | Should -BeTrue
            $Result.HTAFileHashSHA256             | Should -BeExactly 'B6ABDFAED84EAFC826E1CF3637C3DBB0D33AB8611B9D4C32D6CEA602F091AED6'
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId          | Should -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -BeNullOrEmpty

            $Result

        }

        It 'should append HTA content to cmd.exe and execute it' -Tag 'Technique', 'T1218.005' {
            
            $Result = Invoke-ATHHTMLApplication -TemplatePE -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'File'
            $Result.ScriptEngine                  | Should -BeExactly 'JScript'
            $Result.HTAFilePath.EndsWith('Test.hta') | Should -BeTrue
            $Result.HTAFileHashSHA256             | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $FileInfo = Get-Item -Path $Result.HTAFilePath

            $FileInfo.VersionInfo.OriginalFilename | Should -BeExactly 'Cmd.Exe'

            $Result

        }
        
        It 'should simulate a user double-click (ScriptEngine: <ScriptEngine>)' -Tag 'Technique', 'T1218.005' {
            
            $Result = Invoke-ATHHTMLApplication -ScriptEngine $ScriptEngine -HTAFilePath $HTAFileName -SimulateUserDoubleClick -TestGuid $FixedTestGuid
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'File'
            $Result.ScriptEngine                  | Should -BeExactly $ScriptEngine
            $Result.HTAFilePath.EndsWith($HTAFileName) | Should -BeTrue
            $Result.HTAFileHashSHA256             | Should -BeExactly $HTAHash
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Match '{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}' # Related to execution via explorer.exe
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result

        } -TestCases @(
            @{ScriptEngine = 'JScript';         HTAHash = 'F72DE17D7D8C3D357C5885B2CC7B03A94F5638BDF58A4D0C1E991D0D8254D961'},
            @{ScriptEngine = 'JScript.Compact'; HTAHash = 'D400A93266771A377BCF9335F370CA29FF7D0A52FBFB90FBDA40415E7E8C7114'},
            @{ScriptEngine = 'JScript.Encode';  HTAHash = '6C5AC991FF41F4B1A030829A57C82C3B048DAEB96609C848D95FE5B8CF501167'},
            @{ScriptEngine = 'VBScript';        HTAHash = '6612A56932F2742852D70F151A0271C802CC56F7E2FC7B68018E3FAC264AF974'},
            @{ScriptEngine = 'VBScript.Encode'; HTAHash = '5C437FAEF659BE0B9BFE6AEDE079CA4F85A16C5CF3B02AE06C235603A93C5C88'}
        )

        It 'should permit executing from UNC paths (ScriptEngine: <ScriptEngine>)' -Tag 'Technique', 'T1218.005' {
            
            $Result = Invoke-ATHHTMLApplication -ScriptEngine $ScriptEngine -HTAFilePath $HTAFileName -AsLocalUNCPath -TestGuid $FixedTestGuid
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'File'
            $Result.ScriptEngine                  | Should -BeExactly $ScriptEngine
            $Result.HTAFilePath.EndsWith($HTAFileName) | Should -BeTrue
            $Result.HTAFileHashSHA256             | Should -BeExactly $HTAHash
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Match '"\\\\' # Path to HTA file starts with a UNC path
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result

        } -TestCases @(
            @{ScriptEngine = 'JScript';         HTAHash = 'F72DE17D7D8C3D357C5885B2CC7B03A94F5638BDF58A4D0C1E991D0D8254D961'},
            @{ScriptEngine = 'JScript.Compact'; HTAHash = 'D400A93266771A377BCF9335F370CA29FF7D0A52FBFB90FBDA40415E7E8C7114'},
            @{ScriptEngine = 'JScript.Encode';  HTAHash = '6C5AC991FF41F4B1A030829A57C82C3B048DAEB96609C848D95FE5B8CF501167'},
            @{ScriptEngine = 'VBScript';        HTAHash = '6612A56932F2742852D70F151A0271C802CC56F7E2FC7B68018E3FAC264AF974'},
            @{ScriptEngine = 'VBScript.Encode'; HTAHash = '5C437FAEF659BE0B9BFE6AEDE079CA4F85A16C5CF3B02AE06C235603A93C5C88'}
        )

        It 'should simulate lateral movement (ScriptEngine: <ScriptEngine>)' -Tag 'Technique', 'T1218.005' {
            
            $Result = Invoke-ATHHTMLApplication -ScriptEngine $ScriptEngine -HTAFilePath $HTAFileName -SimulateLateralMovement -TestGuid $FixedTestGuid
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'File'
            $Result.ScriptEngine                  | Should -BeExactly $ScriptEngine
            $Result.HTAFilePath.EndsWith($HTAFileName) | Should -BeTrue
            $Result.HTAFileHashSHA256             | Should -BeExactly $HTAHash
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine.EndsWith('-Embedding') | Should -BeTrue # Implies usage of the COM host process
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result

        } -TestCases @(
            @{ScriptEngine = 'JScript';         HTAHash = 'F72DE17D7D8C3D357C5885B2CC7B03A94F5638BDF58A4D0C1E991D0D8254D961'},
            @{ScriptEngine = 'JScript.Compact'; HTAHash = 'D400A93266771A377BCF9335F370CA29FF7D0A52FBFB90FBDA40415E7E8C7114'},
            @{ScriptEngine = 'JScript.Encode';  HTAHash = '6C5AC991FF41F4B1A030829A57C82C3B048DAEB96609C848D95FE5B8CF501167'},
            @{ScriptEngine = 'VBScript';        HTAHash = '6612A56932F2742852D70F151A0271C802CC56F7E2FC7B68018E3FAC264AF974'},
            @{ScriptEngine = 'VBScript.Encode'; HTAHash = '5C437FAEF659BE0B9BFE6AEDE079CA4F85A16C5CF3B02AE06C235603A93C5C88'}
        )

        It 'should simulate inline rundll32.exe execution (InlineProtocolHandler: <InlineProtocolHandler>, ScriptEngine: <ScriptEngine>)' -Tag 'Technique', 'T1218.005' {
            
            $ScriptEngineArg = @{}

            if ($ScriptEngine) {
                $ScriptEngineArg['ScriptEngine'] = $ScriptEngine
            } else {
                if ($InlineProtocolHandler -eq 'JavaScript') {
                    $ScriptEngine = 'JScript'
                } else {
                    $ScriptEngine = $InlineProtocolHandler
                }
            }

            $Result = Invoke-ATHHTMLApplication -UseRundll32 -InlineProtocolHandler $InlineProtocolHandler -TestGuid $FixedTestGuid @ScriptEngineArg

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'InlineRundll32'
            $Result.ScriptEngine                  | Should -BeExactly $ScriptEngine
            $Result.HTAFilePath                   | Should -BeNullOrEmpty
            $Result.HTAFileHashSHA256             | Should -BeNullOrEmpty
            $Result.RunnerFilePath.EndsWith('rundll32.exe') | Should -BeTrue
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Match $FixedTestGuid
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result

        } -TestCases @(
            @{ InlineProtocolHandler = 'JavaScript' },
            @{ InlineProtocolHandler = 'VBScript' },
            @{ InlineProtocolHandler = 'About'; ScriptEngine = 'JScript' },
            @{ InlineProtocolHandler = 'About'; ScriptEngine = 'JScript.Compact' },
            @{ InlineProtocolHandler = 'About'; ScriptEngine = 'VBScript' }
        )

        It 'should simulate inline mshta.exe execution (InlineProtocolHandler: <InlineProtocolHandler>, ScriptEngine: <ScriptEngine>)' -Tag 'Technique', 'T1218.005' {
            
            $ScriptEngineArg = @{}

            if ($ScriptEngine) {
                $ScriptEngineArg['ScriptEngine'] = $ScriptEngine
            } else {
                if ($InlineProtocolHandler -eq 'JavaScript') {
                    $ScriptEngine = 'JScript'
                } else {
                    $ScriptEngine = $InlineProtocolHandler
                }
            }

            $Result = Invoke-ATHHTMLApplication -InlineProtocolHandler $InlineProtocolHandler -TestGuid $FixedTestGuid @ScriptEngineArg

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'InlineMshta'
            $Result.ScriptEngine                  | Should -BeExactly $ScriptEngine
            $Result.HTAFilePath                   | Should -BeNullOrEmpty
            $Result.HTAFileHashSHA256             | Should -BeNullOrEmpty
            $Result.RunnerFilePath.EndsWith('mshta.exe') | Should -BeTrue
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Match $FixedTestGuid
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result

        } -TestCases @(
            @{ InlineProtocolHandler = 'JavaScript' },
            @{ InlineProtocolHandler = 'VBScript' },
            @{ InlineProtocolHandler = 'About'; ScriptEngine = 'JScript' },
            @{ InlineProtocolHandler = 'About'; ScriptEngine = 'JScript.Compact' },
            @{ InlineProtocolHandler = 'About'; ScriptEngine = 'VBScript' }
        )
    }
}