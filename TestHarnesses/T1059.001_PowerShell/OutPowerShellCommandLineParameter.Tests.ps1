Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Out-ATHPowerShellCommandLineParameter' {
    BeforeAll {
        $Help = Get-Help -Name Out-ATHPowerShellCommandLineParameter -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }

        $FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    }

    BeforeEach {
        if ($CommandLineSwitchType) {
            switch($CommandLineSwitchType) {
                'Hyphen'        { $SwitchChar = [Char] '-' }
                'EnDash'        { $SwitchChar = [Char] 0x2013 }
                'EmDash'        { $SwitchChar = [Char] 0x2014 }
                'HorizontalBar' { $SwitchChar = [Char] 0x2015 }
                'ForwardSlash'  { $SwitchChar = [Char] '/' }
            }
        }
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1059.001' {
        It 'should indicate that the PowerShell runner process failed to start' -Tag 'Unit', 'T1059.001' {
            Mock Invoke-CimMethod { return @{ ReturnValue = 1 } }

            { Out-ATHPowerShellCommandLineParameter -Execute -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1059.001' {
        It 'should execute -Command parameter variations (CommandLineSwitchType: <CommandLineSwitchType>, CommandParamVariation: <CommandParamVariation>)' -Tag 'Technique', 'T1059.001' {

            $Result = Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType $CommandLineSwitchType -CommandParamVariation $CommandParamVariation -Execute -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess | Should -BeTrue
            $Result.TestGuid    | Should -BeExactly $FixedTestGuid
            $Result.ProcessId   | Should -Not -BeNullOrEmpty
            $Result.CommandLine | Should -MatchExactly " $($SwitchChar)$($CommandParamVariation) .*$($FixedTestGuid)`$"

            $Result

        } -TestCases @(
            @{ CommandLineSwitchType = 'Hyphen';        CommandParamVariation = 'C' },
            @{ CommandLineSwitchType = 'Hyphen';        CommandParamVariation = 'Command' },
            @{ CommandLineSwitchType = 'EmDash';        CommandParamVariation = 'C' },
            @{ CommandLineSwitchType = 'EmDash';        CommandParamVariation = 'Command' },
            @{ CommandLineSwitchType = 'EnDash';        CommandParamVariation = 'C' },
            @{ CommandLineSwitchType = 'EnDash';        CommandParamVariation = 'Command' },
            @{ CommandLineSwitchType = 'HorizontalBar'; CommandParamVariation = 'C' },
            @{ CommandLineSwitchType = 'HorizontalBar'; CommandParamVariation = 'Command' },
            @{ CommandLineSwitchType = 'ForwardSlash';  CommandParamVariation = 'C' },
            @{ CommandLineSwitchType = 'ForwardSlash';  CommandParamVariation = 'Command' }
        )

        It 'should execute -Command and -EncodedArguments parameter variations (CommandLineSwitchType: <CommandLineSwitchType>, CommandParamVariation: <CommandParamVariation>, EncodedArgumentsParamVariation: <EncodedArgumentsParamVariation>)' -Tag 'Technique', 'T1059.001' {

            $Result = Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType $CommandLineSwitchType -CommandParamVariation $CommandParamVariation -UseEncodedArguments -EncodedArgumentsParamVariation $EncodedArgumentsParamVariation -Execute -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess | Should -BeTrue
            $Result.TestGuid    | Should -BeExactly $FixedTestGuid
            $Result.ProcessId   | Should -Not -BeNullOrEmpty
            $Result.CommandLine | Should -MatchExactly " $($SwitchChar)$($EncodedArgumentsParamVariation) .* $($SwitchChar)$($CommandParamVariation) "

            $Result

        } -TestCases @(
            @{ CommandLineSwitchType = 'Hyphen';        CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'Hyphen';        CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'Hyphen';        CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'Hyphen';        CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'Hyphen';        CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'Hyphen';        CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'EmDash';        CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'EmDash';        CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'EmDash';        CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'EmDash';        CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'EmDash';        CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'EmDash';        CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'EnDash';        CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'EnDash';        CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'EnDash';        CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'EnDash';        CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'EnDash';        CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'EnDash';        CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'HorizontalBar'; CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'HorizontalBar'; CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'HorizontalBar'; CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'HorizontalBar'; CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'HorizontalBar'; CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'HorizontalBar'; CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'ForwardSlash';  CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'ForwardSlash';  CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'ForwardSlash';  CommandParamVariation = 'C';       EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'ForwardSlash';  CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'ForwardSlash';  CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'ForwardSlash';  CommandParamVariation = 'Command'; EncodedArgumentsParamVariation = 'EncodedArguments' }
        )

        It 'should execute -EncodedCommand parameter variations (CommandLineSwitchType: <CommandLineSwitchType>, EncodedCommandParamVariation: <EncodedCommandParamVariation>)' -Tag 'Technique', 'T1059.001' {

            $Result = Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType $CommandLineSwitchType -EncodedCommandParamVariation $EncodedCommandParamVariation -Execute -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess | Should -BeTrue
            $Result.TestGuid    | Should -BeExactly $FixedTestGuid
            $Result.ProcessId   | Should -Not -BeNullOrEmpty
            $Result.CommandLine | Should -MatchExactly " $($SwitchChar)$($EncodedCommandParamVariation) "

            $Result

        } -TestCases @(
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'E' },
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'EC' },
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'EncodedCommand' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'E' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'EC' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'EncodedCommand' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'E' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'EC' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'EncodedCommand' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'E' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'EC' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'EncodedCommand' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'E' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'EC' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'EncodedCommand' }
        )

        It 'should execute -EncodedCommand and -EncodedArguments parameter variations' -Tag 'Technique', 'T1059.001' {

            $Result = Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType $CommandLineSwitchType -EncodedCommandParamVariation $EncodedCommandParamVariation -UseEncodedArguments -EncodedArgumentsParamVariation $EncodedArgumentsParamVariation -Execute -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess | Should -BeTrue
            $Result.TestGuid    | Should -BeExactly $FixedTestGuid
            $Result.ProcessId   | Should -Not -BeNullOrEmpty
            $Result.CommandLine | Should -MatchExactly " $($SwitchChar)$($EncodedArgumentsParamVariation) .* $($SwitchChar)$($EncodedCommandParamVariation) "

            $Result

        } -TestCases @(
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'Hyphen';        EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'EmDash';        EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'EnDash';        EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'HorizontalBar'; EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'E';              EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'EC';             EncodedArgumentsParamVariation = 'EncodedArguments' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EA' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EncodedA' },
            @{ CommandLineSwitchType = 'ForwardSlash';  EncodedCommandParamVariation = 'EncodedCommand'; EncodedArgumentsParamVariation = 'EncodedArguments' }
        )
    }
}