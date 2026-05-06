. "$PSScriptRoot/GhidraRe.Common.ps1"

function Initialize-GhidraRe {
    [CmdletBinding()]
    param(
        [switch]$SkipSmokeTest,
        [string]$SkillRoot
    )

    $args = @()
    if ($SkipSmokeTest) {
        $args += "--skip-smoke-test"
    }
    Invoke-GhidraReScript -ScriptName "bootstrap" -Arguments $args -SkillRoot $SkillRoot -RawOutput
}

function Invoke-GhidraReDoctor {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "doctor" -SkillRoot $SkillRoot -RawOutput
}

function Add-GhidraReSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [string]$Platform = "macos-image",
        [ValidateSet("cache", "direct")]
        [string]$Copy = "cache",
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_source_add" -Arguments @(
        $Name,
        "root=$Root",
        "platform=$Platform",
        "copy=$Copy"
    ) -SkillRoot $SkillRoot | Out-Null

    Get-GhidraReSources -SkillRoot $SkillRoot
}

function Get-GhidraReSources {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_source_list" -SkillRoot $SkillRoot
}

function Resolve-GhidraReSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$ImagePath,
        [ValidateSet("cache", "direct")]
        [string]$Copy = "cache",
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_source_resolve" -Arguments @(
        $Name,
        $ImagePath,
        "copy=$Copy"
    ) -SkillRoot $SkillRoot -RawOutput
}

function Import-GhidraReBinary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Binary,
        [string]$ProjectName,
        [string]$SkillRoot
    )

    $args = @($Binary)
    if ($ProjectName) {
        $args += $ProjectName
    }
    Invoke-GhidraReScript -ScriptName "ghidra_import_analyze" -Arguments $args -SkillRoot $SkillRoot -RawOutput
}

function Export-GhidraReAppleBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectName,
        [Parameter(Mandatory = $true)]
        [string]$ProgramName,
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_export_apple_bundle" -Arguments @(
        $ProjectName,
        $ProgramName
    ) -SkillRoot $SkillRoot -RawOutput
}

function Get-GhidraReBridgeSessions {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_sessions" -SkillRoot $SkillRoot
}

function Select-GhidraReBridgeSession {
    [CmdletBinding(DefaultParameterSetName = "Session")]
    param(
        [Parameter(ParameterSetName = "Session", Mandatory = $true)]
        [string]$Session,
        [Parameter(ParameterSetName = "Project", Mandatory = $true)]
        [string]$Project,
        [Parameter(ParameterSetName = "Program", Mandatory = $true)]
        [string]$Program,
        [string]$ProjectProgram,
        [string]$SkillRoot
    )

    $args = @()
    switch ($PSCmdlet.ParameterSetName) {
        "Session" { $args += "session=$Session" }
        "Project" {
            $args += "project=$Project"
            if ($ProjectProgram) {
                $args += "program=$ProjectProgram"
            }
        }
        "Program" { $args += "program=$Program" }
    }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_select" -Arguments $args -SkillRoot $SkillRoot
}

function Open-GhidraReBridge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectName,
        [string]$ProgramName,
        [string]$SkillRoot
    )

    $args = @($ProjectName)
    if ($ProgramName) {
        $args += $ProgramName
    }
    Invoke-GhidraReScript -ScriptName "ghidra_bridge_open" -Arguments $args -SkillRoot $SkillRoot -RawOutput | Out-Null
    if ($ProgramName) {
        return (Select-GhidraReBridgeSession -Project $ProjectName -ProjectProgram $ProgramName -SkillRoot $SkillRoot)
    }
    return (Select-GhidraReBridgeSession -Project $ProjectName -SkillRoot $SkillRoot)
}

function Close-GhidraReBridge {
    [CmdletBinding(DefaultParameterSetName = "Current")]
    param(
        [Parameter(ParameterSetName = "Session", Mandatory = $true)]
        [string]$Session,
        [Parameter(ParameterSetName = "Project", Mandatory = $true)]
        [string]$Project,
        [Parameter(ParameterSetName = "Program", Mandatory = $true)]
        [string]$Program,
        [string]$ProjectProgram,
        [string]$SkillRoot
    )

    $args = @()
    switch ($PSCmdlet.ParameterSetName) {
        "Session" { $args += "session=$Session" }
        "Project" {
            $args += "project=$Project"
            if ($ProjectProgram) {
                $args += "program=$ProjectProgram"
            }
        }
        "Program" { $args += "program=$Program" }
        default { }
    }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_close" -Arguments $args -SkillRoot $SkillRoot -RawOutput
}

function Close-GhidraReAllBridges {
    [CmdletBinding()]
    param(
        [string]$MissionName,
        [switch]$All,
        [string]$SkillRoot
    )

    $args = @()
    if ($MissionName) {
        $args += "mission=$MissionName"
    }
    if ($All) {
        $args += "all=true"
    }
    Invoke-GhidraReScript -ScriptName "ghidra_bridge_close_all" -Arguments $args -SkillRoot $SkillRoot
}

function Get-GhidraReCurrentContext {
    [CmdletBinding()]
    param(
        [string]$Session,
        [string]$Project,
        [string]$Program,
        [string]$SkillRoot
    )

    $args = @()
    if ($Session) { $args += "session=$Session" }
    if ($Project) { $args += "project=$Project" }
    if ($Program) { $args += "program=$Program" }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_current_context" -Arguments $args -SkillRoot $SkillRoot
}

function Get-GhidraReBridgeSnapshot {
    [CmdletBinding()]
    param(
        [string]$Session,
        [string]$Project,
        [string]$Program,
        [string]$SkillRoot
    )

    $args = @()
    if ($Session) { $args += "session=$Session" }
    if ($Project) { $args += "project=$Project" }
    if ($Program) { $args += "program=$Program" }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_snapshot" -Arguments $args -SkillRoot $SkillRoot
}

function Search-GhidraReFunctions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,
        [int]$Limit = 10,
        [string]$Session,
        [string]$Project,
        [string]$Program,
        [string]$SkillRoot
    )

    $args = @($Query, "limit=$Limit")
    if ($Session) { $args += "session=$Session" }
    if ($Project) { $args += "project=$Project" }
    if ($Program) { $args += "program=$Program" }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_functions_search" -Arguments $args -SkillRoot $SkillRoot
}

function Invoke-GhidraReAnalyzeTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,
        [int]$Limit = 5,
        [switch]$Navigate,
        [string]$Session,
        [string]$Project,
        [string]$Program,
        [string]$SkillRoot
    )

    $args = @($Query, "limit=$Limit", "navigate=$($Navigate.IsPresent.ToString().ToLowerInvariant())")
    if ($Session) { $args += "session=$Session" }
    if ($Project) { $args += "project=$Project" }
    if ($Program) { $args += "program=$Program" }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_analyze_target" -Arguments $args -SkillRoot $SkillRoot
}

function Trace-GhidraReSelector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Selector,
        [int]$Limit = 5,
        [string]$Session,
        [string]$Project,
        [string]$Program,
        [string]$SkillRoot
    )

    $args = @($Selector, "limit=$Limit")
    if ($Session) { $args += "session=$Session" }
    if ($Project) { $args += "project=$Project" }
    if ($Program) { $args += "program=$Program" }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_selector_trace" -Arguments $args -SkillRoot $SkillRoot
}

function Start-GhidraReMission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Goal,
        [Parameter(Mandatory = $true)]
        [string[]]$Target,
        [string[]]$Seed = @(),
        [string]$Mode = "trace",
        [string]$SkillRoot
    )

    $args = @($Name, "goal=$Goal", "mode=$Mode")
    foreach ($item in $Target) {
        $args += "target=$item"
    }
    foreach ($item in $Seed) {
        $args += "seed=$item"
    }

    Invoke-GhidraReScript -ScriptName "ghidra_mission_start" -Arguments $args -SkillRoot $SkillRoot -RawOutput | Out-Null
    Get-GhidraReMissionStatus -Name $Name -SkillRoot $SkillRoot
}

function Get-GhidraReMissionStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_mission_status" -Arguments @($Name) -SkillRoot $SkillRoot
}

function Trace-GhidraReMission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Seed,
        [string[]]$Target = @(),
        [int]$LimitTargets = 3,
        [int]$TraceLimit = 5,
        [string]$SkillRoot
    )

    $args = @($Name, "seed=$Seed", "limit_targets=$LimitTargets", "trace_limit=$TraceLimit")
    foreach ($item in $Target) {
        $args += "target=$item"
    }

    Invoke-GhidraReScript -ScriptName "ghidra_mission_trace" -Arguments $args -SkillRoot $SkillRoot -RawOutput | Out-Null
    Get-GhidraReMissionStatus -Name $Name -SkillRoot $SkillRoot
}

function Get-GhidraReMissionReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [ValidateSet("markdown", "json", "path")]
        [string]$Format = "markdown",
        [string]$SkillRoot
    )

    $result = Invoke-GhidraReScript -ScriptName "ghidra_mission_report" -Arguments @($Name, "format=$Format") -SkillRoot $SkillRoot -RawOutput
    if ($Format -eq "json") {
        return (ConvertFrom-GhidraReJsonIfPossible -Output $result)
    }
    return $result
}

function Complete-GhidraReMission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [switch]$CloseAll,
        [switch]$KeepSessionsOpen,
        [string]$Summary,
        [string]$SkillRoot
    )

    $args = @($Name)
    if ($CloseAll) { $args += "all=true" }
    if ($KeepSessionsOpen) { $args += "keep_sessions_open=true" }
    if ($Summary) { $args += "summary=$Summary" }

    Invoke-GhidraReScript -ScriptName "ghidra_mission_finish" -Arguments $args -SkillRoot $SkillRoot -RawOutput
}

function Start-GhidraReAutopilot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [int]$Rounds = 3,
        [int]$LimitTargets = 3,
        [int]$TraceLimit = 5,
        [string[]]$Seed = @(),
        [string[]]$Target = @(),
        [string]$SkillRoot
    )

    $args = @($Name, "rounds=$Rounds", "limit_targets=$LimitTargets", "trace_limit=$TraceLimit")
    foreach ($item in $Seed) {
        $args += "seed=$item"
    }
    foreach ($item in $Target) {
        $args += "target=$item"
    }

    Invoke-GhidraReScript -ScriptName "ghidra_mission_autopilot" -Arguments $args -SkillRoot $SkillRoot -RawOutput | Out-Null
    Get-GhidraReMissionStatus -Name $Name -SkillRoot $SkillRoot
}

function Get-GhidraReNotesStatus {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReCli -Arguments @("notes", "status") -SkillRoot $SkillRoot
}

function Add-GhidraReNote {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [Parameter(Mandatory = $true)]
        [string]$Body,
        [string]$Category = "workflow",
        [string]$Target,
        [string]$Mission,
        [string]$Project,
        [string]$Program,
        [string]$ProgramPath,
        [string]$Context,
        [string]$Platform,
        [ValidateSet("open", "remediated", "superseded")]
        [string]$Status = "open",
        [string]$SkillRoot
    )

    $args = @(
        "--title", $Title,
        "--body", $Body,
        "--category", $Category,
        "--status", $Status
    )
    if ($Target) { $args += @("--target", $Target) }
    if ($Mission) { $args += @("--mission", $Mission) }
    if ($Project) { $args += @("--project", $Project) }
    if ($Program) { $args += @("--program", $Program) }
    if ($ProgramPath) { $args += @("--program-path", $ProgramPath) }
    if ($Context) { $args += @("--context", $Context) }
    if ($Platform) { $args += @("--platform", $Platform) }

    $cliArgs = @("notes", "add") + $args
    Invoke-GhidraReCli -Arguments $cliArgs -SkillRoot $SkillRoot
}

function Sync-GhidraReNotes {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReCli -Arguments @("notes", "sync") -SkillRoot $SkillRoot
}

function Receive-GhidraReNotes {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReCli -Arguments @("notes", "pull") -SkillRoot $SkillRoot
}

function Set-GhidraReNoteStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Fingerprint,
        [string]$Summary,
        [string]$Title = "Shared note update",
        [string]$Body,
        [string]$Category = "workflow",
        [string]$Target,
        [ValidateSet("remediated", "superseded")]
        [string]$Status = "remediated",
        [string]$SupersededBy,
        [string]$SkillRoot
    )

    $commentParts = @()
    if ($Summary) { $commentParts += $Summary }
    if ($Body) { $commentParts += $Body }
    $comment = ($commentParts -join "`n")

    if ($Status -eq "superseded") {
        $cliArgs = @("notes", "supersede", $Fingerprint)
        if ($SupersededBy) {
            $cliArgs += @("--superseded-by", $SupersededBy)
        }
        if ($comment) {
            $cliArgs += @("--comment", $comment)
        }
        return Invoke-GhidraReCli -Arguments $cliArgs -SkillRoot $SkillRoot
    }

    $cliArgs = @("notes", "remediate", $Fingerprint)
    if ($Summary) {
        $cliArgs += @("--resolution", $Summary)
    }
    if ($comment) {
        $cliArgs += @("--comment", $comment)
    }

    Invoke-GhidraReCli -Arguments $cliArgs -SkillRoot $SkillRoot
}

function Open-GhidraReSharedNotes {
    [CmdletBinding()]
    param(
        [switch]$Browse,
        [string]$SkillRoot
    )

    $args = @("notes", "open-shared")
    if ($Browse) {
        $args += "--browse"
    } else {
        $args += "--no-browse"
    }

    Invoke-GhidraReCli -Arguments $args -SkillRoot $SkillRoot -RawOutput
}

Export-ModuleMember -Function @(
    "Initialize-GhidraRe",
    "Invoke-GhidraReDoctor",
    "Add-GhidraReSource",
    "Get-GhidraReSources",
    "Resolve-GhidraReSource",
    "Import-GhidraReBinary",
    "Export-GhidraReAppleBundle",
    "Get-GhidraReBridgeSessions",
    "Select-GhidraReBridgeSession",
    "Open-GhidraReBridge",
    "Close-GhidraReBridge",
    "Close-GhidraReAllBridges",
    "Get-GhidraReCurrentContext",
    "Get-GhidraReBridgeSnapshot",
    "Search-GhidraReFunctions",
    "Invoke-GhidraReAnalyzeTarget",
    "Trace-GhidraReSelector",
    "Start-GhidraReMission",
    "Get-GhidraReMissionStatus",
    "Trace-GhidraReMission",
    "Get-GhidraReMissionReport",
    "Complete-GhidraReMission",
    "Start-GhidraReAutopilot",
    "Get-GhidraReNotesStatus",
    "Add-GhidraReNote",
    "Sync-GhidraReNotes",
    "Receive-GhidraReNotes",
    "Set-GhidraReNoteStatus",
    "Open-GhidraReSharedNotes"
)
