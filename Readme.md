# AtomicTestHarnesses PowerShell Module

The `AtomicTestHarnesses` PowerShell module contains a suite of tools for simulating attack techniques. It is designed to be used on its own or as a dependency for [`Atomic Red Team`](https://github.com/redcanaryco/atomic-red-team) tests. `AtomicTestHarnesses` is designed to run on PowerShell version 5 and above.

## What problem does AtomicTestHarnesses aim to address?

Have you ever been asked the question and been held accountable to answer the following? "Do we detect attack technique X?" If so, you may be familiar with the initial level of discomfort involved in not knowing how to confidently answer that question. In order to tackle such a potentially broadly-scoped question, at Red Canary, one of our first questions will be, "can we see the technique in the first place independent of benign, suspicious, or malicious behaviors?" In order to "see" techniques, one would ideally have a handle on as many variants of a technique as possible and to then build test code that can exercise all those variants in a _repeatable_ and _modular_ fashion. Implementation of all known technique variations in an abstracted and repeatable fashion is the niche that `AtomicTestHarnesses` aims to fill. If you can observe all known technique variations, then you've laid a foundation to detect behaviors that employ a technique in a fashion that is resilient to evasion.

## Installing the AtomicTestHarnesses Module

`AtomicTestHarnesses` is no different than any other PowerShell module. It can be installed from the [PowerShell Gallery](https://www.powershellgallery.com/), as an [auto-loaded module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_modules?view=powershell-7#module-auto-loading), or it can be manually imported.

### Installation Method #1: PowerShell Gallery

AtomicTestHarnesses is available in the [PowerShell Gallery](https://www.powershellgallery.com/packages/AtomicTestHarnesses). Installation from the PowerShell Gallery is the most straightforward installation method. Run the following:

```powershell
Install-Module -Name AtomicTestHarnesses -Scope CurrentUser
```

### Installation Method #2: Module Auto-loading

For manual installation from GitHub, you can follow these steps. Installation via `Install-Module` handles these steps that follow.

To support auto-loading of the `AtomicTestHarnesses` module, the `AtomicTestHarnesses` folder must reside in a module directory. There are multiple module directories by default, each with their own scope, each one present in the `%PSModulePath%` environment variable. You can view the existing module directories with the following PowerShell code:

```powershell
(Get-Item Env:\PSModulePath).Value.Split(';')
```

For example, if you wanted to install the module for all users, you would copy the `AtomicTestHarnesses` root directory to `%ProgramFiles%\WindowsPowerShell\Modules`

Upon copying the `AtomicTestHarnesses` root directory to the desired module path, you can begin using the exported functions right away without having to call [`Import-Module`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/import-module?view=powershell-7).

### Installation Method #3: Explicitly Importing

Rather than placing the `AtomicTestHarnesses` root directory in a module path, it can be directly imported regardless of where it resides by calling `Import-Module` on the module `PSD1` file. Example:

```powershell
Import-Module C:\Users\Test\Desktop\AtomicTestHarnesses\AtomicTestHarnesses.psd1
```

## Exploring Exposed Functionality

Upon the `AtomicTestHarnesses` module being loaded, to get a sense of what functionality is exposed, you can run the following command:

```powershell
Get-Command -Module AtomicTestHarnesses
```

You can then read the help documentation for each individual function with `Get-Help`:

```powershell
Get-Help -Name Invoke-ATHHTMLApplication -Full
```

## Misc Tips

If `AtomicTestHarnesses` is downloaded as a Zip file you may get warnings prior to importing the module indicating that it was downloaded from the internet and may not be trustworthy. To unmark the module as having been downloaded from the internet, run the following:

```powershell
Get-ChildItem -Path Path\To\AtomicTestHarnesses -Recurse | Unblock-File
```

## References
- [MS Docs - Installing Powershell Modules](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module?view=powershell-7)
- [MS Docs - Importing Powershell Modules](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/importing-a-powershell-module?view=powershell-7)

# Running Pester Tests

`AtomicTestHarnesses` includes a suite of [Pester](https://github.com/pester/Pester) tests that defenders can use to maximize their detection coverage by ensuring that they can, at a minimum, observe all established variants of a target attack technique.

## Setup

The included Pester tests require Pester v5+.

### Validate your current version of Pester

```powershell
Get-Module -ListAvailable -Name Pester
```

If you do not have Pester v5+, you will need to update it.

### Installing the latest version of Pester v5+

```powershell
Install-Module -Name Pester -MinimumVersion 5.0.0 -Scope CurrentUser
```

## Implemented Test Tags

Specific groups of tests can be run rather than running all available tests. The following tags are exposed:

1. `Module` - Module-wide tests designed to ensure consistency across all exported fcuntions.
2. `Unit` - Unit tests for exported functions
3. `Technique` - Tests that exercise specific attack technique functionality
4. `T1059.001` - [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
5. `T1134.004` - [Access Token Manipulation: Parent PID Spoofing](https://attack.mitre.org/techniques/T1134/004/)
6. `T1218.001` - [Signed Binary Proxy Execution: Compiled HTML File](https://attack.mitre.org/techniques/T1218/001/)
7. `T1218.005` - [Signed Binary Proxy Execution: Mshta](https://attack.mitre.org/techniques/T1218/005/)

## Running Tests

To run `AtomicTestHarnesses` Pester tests, first `cd` into the `AtomicTestHarnesses` directory.

Execute module-wide consistency tests:

```powershell
Invoke-Pester -Output Detailed -TagFilter Module
```

Running a suite of tests for one of the support MITRE ATT&CK Technique IDs:

```powershell
Invoke-Pester -Output Detailed -TagFilter T1134.004
```

Retrieving object output from passed tests:

```powershell
$TestResults = Invoke-Pester -Output Detailed -TagFilter T1134.004 -PassThru

# These results are what you would likely want to submit to the next stage in your test pipeline.
$TestResults.Passed.StandardOutput
```

Note: all `Technique`-tagged tests must output function object output so that returned objects can be programmatically retrieved.

# Contributing

Red Canary very much values community contributions! Currently, we are only able to consider pull requests for bug fixes. We are currently unable to accept pull requests for new test harness code until we feel a little more confident that we've educated the community on our design/implementation process. Thank you for your interest and time!