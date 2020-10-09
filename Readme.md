# AtomicTestHarnesses PowerShell Module

The `AtomicTestHarnesses` PowerShell module contains a suite of tools for simulating attack techniques. It is designed to be used on its own or as a dependency for `Atomic Red Team` tests.

## Installing the AtomicTestHarnesses Module

`AtomicTestHarnesses` is no different than any other PowerShell module. It can be installed either as an [auto-loaded module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_modules?view=powershell-7#module-auto-loading) or it can be explicitly imported.

### Installation Method #1: Module Auto-loading

To support auto-loading of the `AtomicTestHarnesses` module, the `AtomicTestHarnesses` folder must reside in a module directory. There are multiple module directories by default, each with their own scope, each one present in the `%PSModulePath%` environment variable. You can view the existing module directories with the following PowerShell code:

```powershell
(Get-Item Env:\PSModulePath).Value.Split(';')
```

For example, if you wanted to install the module for all users, you would copy the `AtomicTestHarnesses` root directory to `%ProgramFiles%\WindowsPowerShell\Modules`

Upon copying the `AtomicTestHarnesses` root directory to the desired module path, you can begin using the exported functions right away without having to call [`Import-Module`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/import-module?view=powershell-7).

### Installation Method #2: Explicitly Importing

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