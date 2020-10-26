Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
$Module = Import-Module $ModuleManifest -Force -ErrorAction Stop -PassThru

$ExportedFunctionList = $Module.ExportedCommands.Keys

Describe 'Module-wide tests' -Tag 'Module' {
    foreach ($FunctionName in $ExportedFunctionList) {
        Context "Required exported command naming scheme for $FunctionName" {
            It 'should have an "ATH" noun prefix' -Tag 'Module' {
                $FunctionInfo = Get-Item -Path Function:$FunctionName

                $FunctionInfo.Noun.Substring(0, 3) | Should -BeExactly 'ATH'
            } -TestCases @(@{ FunctionName = $FunctionName })
        }

        Context "Pester test checks for $FunctionName" {
            It 'should have test code written for the exported function' -Tag 'Module' {
                $FunctionInfo = Get-Item -Path Function:$FunctionName

                $FunctionFilePath = $FunctionInfo.ScriptBlock.File

                $FunctionFileInfo = Get-Item -Path $FunctionFilePath

                $FunctionDirectory = $FunctionFileInfo.DirectoryName
                $FunctionFileBaseName = $FunctionFileInfo.BaseName # The filename without the extension

                $TestFilePath = Join-Path -Path $FunctionDirectory -ChildPath "$FunctionFileBaseName.Tests.ps1"

                Test-Path -Path $TestFilePath -PathType Leaf | Should -BeTrue

                $TestFileInfo = Get-Item -Path $TestFilePath

                $TestFileInfo | Should -Not -BeNullOrEmpty

                # For now, just validate that it isn't an empty file.
                # Until Pester can better discover tests without executing them, we'll hold off on incorporating more thorough logic.
                $TestFileInfo.Length | Should -BeGreaterThan 0
            } -TestCases @(@{ FunctionName = $FunctionName })
        }

        Context "Comment-based help for: $FunctionName" {
            $Script:Help = Get-Help -Name $FunctionName -Full
        
            # Parse the function using AST
            $Script:AST = [Management.Automation.Language.Parser]::ParseInput((Get-Content Function:$FunctionName), [ref]$null, [ref]$null)

            It 'should contain a .SYNOPSIS block' -Tag 'Module' {
                $Help = Get-Help -Name $FunctionName -Full

                $Help.Synopsis | Should -Not -BeNullOrEmpty
            } -TestCases @(@{ FunctionName = $FunctionName })

            It 'should have a .SYNOPSIS block that ends with a well-formatted attack technique ID' -Tag 'Module' {
                $Help = Get-Help -Name $FunctionName -Full

                $Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$' | Should -BeTrue
            } -TestCases @(@{ FunctionName = $FunctionName })

            It 'should contain a .DESCRIPTION block' -Tag 'Module' {
                $Help = Get-Help -Name $FunctionName -Full

                $Help.Description | Should -Not -BeNullOrEmpty
            } -TestCases @(@{ FunctionName = $FunctionName })
            
            # Examples
            It 'should contain at least one .EXAMPLE block' -Tag 'Module' {
                $Help = Get-Help -Name $FunctionName -Full

                @($Help.Examples.Example.Code).Count | Should -BeGreaterThan 0
            } -TestCases @(@{ FunctionName = $FunctionName })
            
            It 'should contain a matching number of .PARAMETER blocks for all defined parameters and be documented accordingly' -Tag 'Module' {
                $Help = Get-Help -Name $FunctionName -Full

                $HelpParameters = @($Help.Parameters.Parameter)

                $AST = [Management.Automation.Language.Parser]::ParseInput((Get-Content Function:$FunctionName), [ref]$null, [ref]$null)

                $ASTParameters = @($AST.ParamBlock.Parameters.Name.Variablepath.Userpath)

                $NamedArgs = try { $AST.ParamBlock.Attributes.NamedArguments } catch { $null }

                if ($NamedArgs -and $NamedArgs.ArgumentName -contains 'SupportsShouldProcess') {
                    $Count = $ASTParameters.Count + 2 # Accounting for -WhatIf and -Confirm
                } else {
                    $Count = $ASTParameters.Count
                }

                $HelpParameters.Count | Should -Be $Count

                # Each defined parameter in help should have a defined description
                $HelpParameters | ForEach-Object {
                    if ($ASTParameters -contains $_.Name) {
                        $_.Description | Should -Not -BeNullOrEmpty
                    }
                }
            } -TestCases @(@{ FunctionName = $FunctionName })
        }
    }
}