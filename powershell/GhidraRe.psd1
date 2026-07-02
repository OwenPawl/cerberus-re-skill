@{
    RootModule = 'GhidraRe.psm1'
    ModuleVersion = '0.1.0'
    GUID = '6f1b682c-e6a7-4e46-a5dd-b1b57e5583f0'
    Author = 'OpenAI Codex'
    CompanyName = 'OpenAI'
    Copyright = '(c) OpenAI'
    Description = 'Native PowerShell commands for Cerberus RE.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Initialize-GhidraRe',
        'Invoke-GhidraReDoctor',
        'Add-GhidraReSource',
        'Get-GhidraReSources',
        'Resolve-GhidraReSource',
        'Import-GhidraReBinary',
        'Export-GhidraReAppleBundle',
        'Invoke-GhidraReBridgeCall',
        'Get-GhidraReBridgeSessions',
        'Select-GhidraReBridgeSession',
        'Open-GhidraReBridge',
        'Close-GhidraReBridge',
        'Close-GhidraReAllBridges',
        'Get-GhidraReCurrentContext',
        'Get-GhidraReBridgeSnapshot',
        'Search-GhidraReFunctions',
        'Invoke-GhidraReAnalyzeTarget',
        'Trace-GhidraReSelector',
        'Get-GhidraReNotesStatus',
        'Add-GhidraReNote',
        'Sync-GhidraReNotes',
        'Receive-GhidraReNotes',
        'Set-GhidraReNoteStatus',
        'Open-GhidraReSharedNotes'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('ghidra', 'lldb', 'frida', 'reverse-engineering', 'cerberus-re', 'ghidra-re')
        }
    }
}
