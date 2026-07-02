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
    Invoke-GhidraReCli -Arguments (@("bootstrap") + $args) -SkillRoot $SkillRoot -RawOutput
}

function Invoke-GhidraReDoctor {
    [CmdletBinding()]
    param(
        [string]$FridaTarget,
        [string]$SkillRoot
    )

    $args = @("doctor")
    if ($FridaTarget) {
        $args += @("--frida-target", $FridaTarget)
    }
    Invoke-GhidraReCli -Arguments $args -SkillRoot $SkillRoot -RawOutput
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

    Invoke-GhidraReCli -Arguments @("bridge", "sessions") -SkillRoot $SkillRoot
}

function New-GhidraReBridgeBody {
    param(
        [string]$Session,
        [string]$Project,
        [string]$Program
    )

    $body = [ordered]@{}
    if ($Session) { $body["session"] = $Session }
    if ($Project) { $body["project"] = $Project }
    if ($Program) { $body["program"] = $Program }
    return $body
}

function ConvertTo-GhidraReBridgeJson {
    param(
        [object]$Body
    )

    if (-not $Body) {
        return "{}"
    }
    return ($Body | ConvertTo-Json -Compress -Depth 20)
}

function Invoke-GhidraReBridgeCall {
    [CmdletBinding(DefaultParameterSetName = "Body")]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        [Parameter(ParameterSetName = "Body")]
        [object]$Body = @{},
        [Parameter(ParameterSetName = "BodyJson")]
        [string]$BodyJson,
        [Parameter(ParameterSetName = "BodyPath")]
        [string]$BodyPath,
        [string]$SkillRoot
    )

    $payload = switch ($PSCmdlet.ParameterSetName) {
        "BodyJson" { $BodyJson }
        "BodyPath" { "@$BodyPath" }
        default { ConvertTo-GhidraReBridgeJson -Body $Body }
    }

    Invoke-GhidraReCli -Arguments @(
        "bridge",
        "call",
        $Endpoint,
        $payload
    ) -SkillRoot $SkillRoot
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

    $sessionArg = ""
    $projectArg = ""
    $programArg = ""
    switch ($PSCmdlet.ParameterSetName) {
        "Session" { $sessionArg = $Session }
        "Project" {
            $projectArg = $Project
            if ($ProjectProgram) {
                $programArg = $ProjectProgram
            }
        }
        "Program" { $programArg = $Program }
    }

    $body = New-GhidraReBridgeBody -Session $sessionArg -Project $projectArg -Program $programArg
    Invoke-GhidraReCli -Arguments @(
        "bridge",
        "status",
        (ConvertTo-GhidraReBridgeJson -Body $body)
    ) -SkillRoot $SkillRoot
}

function Open-GhidraReBridge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectName,
        [string]$ProgramName,
        [string]$SkillRoot
    )

    $args = @("bridge", "arm", $ProjectName)
    if ($ProgramName) {
        $args += $ProgramName
    }
    Invoke-GhidraReCli -Arguments $args -SkillRoot $SkillRoot
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
        [switch]$DisarmOnly,
        [string]$SkillRoot
    )

    $args = @("bridge", "close")
    if ($DisarmOnly) {
        $args = @("bridge", "disarm")
    }
    switch ($PSCmdlet.ParameterSetName) {
        "Session" { $args += @("--session", $Session) }
        "Project" {
            $args += @("--project", $Project)
            if ($ProjectProgram) {
                $args += @("--program", $ProjectProgram)
            }
        }
        "Program" { $args += @("--program", $Program) }
        default { }
    }

    Invoke-GhidraReCli -Arguments $args -SkillRoot $SkillRoot
}

function Close-GhidraReAllBridges {
    [CmdletBinding()]
    param(
        [string]$MissionName,
        [switch]$All,
        [string]$SkillRoot
    )

    if ($MissionName) {
        throw "Close-GhidraReAllBridges -MissionName is not available through the Python bridge CLI yet."
    }
    $sessions = Get-GhidraReBridgeSessions -SkillRoot $SkillRoot
    $closed = @()
    foreach ($sessionInfo in $sessions) {
        if ($sessionInfo.session_id) {
            $closed += (Close-GhidraReBridge -Session $sessionInfo.session_id -SkillRoot $SkillRoot)
        }
    }
    return $closed
}

function Get-GhidraReCurrentContext {
    [CmdletBinding()]
    param(
        [string]$Session,
        [string]$Project,
        [string]$Program,
        [string]$SkillRoot
    )

    $body = New-GhidraReBridgeBody -Session $Session -Project $Project -Program $Program
    Invoke-GhidraReBridgeCall -Endpoint "/context" -Body $body -SkillRoot $SkillRoot
}

function Get-GhidraReBridgeSnapshot {
    [CmdletBinding()]
    param(
        [string]$Session,
        [string]$Project,
        [string]$Program,
        [string]$SkillRoot
    )

    $body = New-GhidraReBridgeBody -Session $Session -Project $Project -Program $Program
    [pscustomobject]@{
        session    = Invoke-GhidraReBridgeCall -Endpoint "/session" -Body $body -SkillRoot $SkillRoot
        context    = Invoke-GhidraReBridgeCall -Endpoint "/context" -Body $body -SkillRoot $SkillRoot
        function   = Invoke-GhidraReBridgeCall -Endpoint "/function" -Body $body -SkillRoot $SkillRoot
        decompile  = Invoke-GhidraReBridgeCall -Endpoint "/decompile" -Body $body -SkillRoot $SkillRoot
        references = Invoke-GhidraReBridgeCall -Endpoint "/references" -Body $body -SkillRoot $SkillRoot
        variables  = Invoke-GhidraReBridgeCall -Endpoint "/variables" -Body $body -SkillRoot $SkillRoot
    }
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

    $body = New-GhidraReBridgeBody -Session $Session -Project $Project -Program $Program
    $body["query"] = $Query
    $body["limit"] = $Limit
    Invoke-GhidraReBridgeCall -Endpoint "/functions/search" -Body $body -SkillRoot $SkillRoot
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

    $body = New-GhidraReBridgeBody -Session $Session -Project $Project -Program $Program
    $body["query"] = $Query
    $body["limit"] = $Limit
    $body["navigate"] = $Navigate.IsPresent
    Invoke-GhidraReBridgeCall -Endpoint "/analyze/target" -Body $body -SkillRoot $SkillRoot
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

    $body = New-GhidraReBridgeBody -Session $Session -Project $Project -Program $Program
    $body["selector"] = $Selector
    $body["limit"] = $Limit
    Invoke-GhidraReBridgeCall -Endpoint "/objc/selector-trace" -Body $body -SkillRoot $SkillRoot
}

function Get-GhidraReNotesStatus {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_notes_status" -SkillRoot $SkillRoot
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
        "title=$Title",
        "body=$Body",
        "category=$Category",
        "status=$Status"
    )
    if ($Target) { $args += "target=$Target" }
    if ($Mission) { $args += "mission=$Mission" }
    if ($Project) { $args += "project=$Project" }
    if ($Program) { $args += "program=$Program" }
    if ($ProgramPath) { $args += "program_path=$ProgramPath" }
    if ($Context) { $args += "context=$Context" }
    if ($Platform) { $args += "platform=$Platform" }

    Invoke-GhidraReScript -ScriptName "ghidra_notes_add" -Arguments $args -SkillRoot $SkillRoot
}

function Sync-GhidraReNotes {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_notes_sync" -SkillRoot $SkillRoot
}

function Receive-GhidraReNotes {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_notes_pull" -SkillRoot $SkillRoot
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

    $args = @(
        "fingerprint=$Fingerprint",
        "title=$Title",
        "category=$Category",
        "status=$Status"
    )
    if ($Summary) { $args += "summary=$Summary" }
    if ($Body) { $args += "body=$Body" }
    if ($Target) { $args += "target=$Target" }
    if ($SupersededBy) { $args += "superseded_by=$SupersededBy" }

    Invoke-GhidraReScript -ScriptName "ghidra_notes_remediate" -Arguments $args -SkillRoot $SkillRoot
}

function Open-GhidraReSharedNotes {
    [CmdletBinding()]
    param(
        [switch]$Browse,
        [string]$SkillRoot
    )

    $args = @()
    if ($Browse) {
        $args += "browse=true"
    }

    Invoke-GhidraReScript -ScriptName "ghidra_notes_open_shared" -Arguments $args -SkillRoot $SkillRoot -RawOutput
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
    "Get-GhidraReNotesStatus",
    "Add-GhidraReNote",
    "Sync-GhidraReNotes",
    "Receive-GhidraReNotes",
    "Set-GhidraReNoteStatus",
    "Open-GhidraReSharedNotes"
)
