Get-ChildItem "$PSScriptRoot\TestHarnesses" -Directory |
    Get-ChildItem -Include '*.ps1' -File |
    Where-Object { -not $_.Name.EndsWith('Tests.ps1') } |
    ForEach-Object { . $_.FullName }