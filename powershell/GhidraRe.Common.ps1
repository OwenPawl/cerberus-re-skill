Set-StrictMode -Version Latest

function Resolve-GhidraReSkillRoot {
    param(
        [string]$SkillRoot
    )

    $candidates = @()

    if ($SkillRoot) {
        $candidates += $SkillRoot
    }

    if ($env:GHIDRA_RE_ROOT) {
        $candidates += $env:GHIDRA_RE_ROOT
    }

    if ($PSScriptRoot) {
        $candidates += (Join-Path $PSScriptRoot "..")
    }

    # Cerberus RE is installable under any "skill host" that follows the
    # ~/.<host>/skills/<skill>/SKILL.md convention. We currently probe both
    # OpenAI Codex and Anthropic Claude Code. Resolution order matters:
    # whichever host the caller already pointed at via env vars wins first,
    # then we fall back to on-disk probes.
    $skillHosts = @(
        @{
            Name    = "codex"
            EnvVar  = "CODEX_HOME"
            Default = ".codex"
        },
        @{
            Name    = "claude"
            EnvVar  = "CLAUDE_HOME"
            Default = ".claude"
        }
    )

    foreach ($hostInfo in $skillHosts) {
        $envValue = [System.Environment]::GetEnvironmentVariable($hostInfo.EnvVar)
        $hostHome = if ($envValue) {
            $envValue
        } else {
            Join-Path $HOME $hostInfo.Default
        }
        $candidates += (Join-Path $hostHome "skills\cerberus-re")
    }

    foreach ($candidate in $candidates) {
        if (-not $candidate) {
            continue
        }
        try {
            $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
        } catch {
            continue
        }
        if (Test-Path (Join-Path $resolved "scripts\common.sh")) {
            return $resolved
        }
    }

    throw "Unable to locate the Cerberus RE skill root. Pass -SkillRoot or set GHIDRA_RE_ROOT."
}

function Find-GhidraReBash {
    $candidates = @(
        "C:\Program Files\Git\bin\bash.exe",
        "C:\Program Files\Git\usr\bin\bash.exe",
        (Get-Command bash.exe -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source } | Where-Object {
            $_ -and
            $_ -notmatch '\\Windows\\System32\\bash\.exe$' -and
            $_ -notmatch '\\Microsoft\\WindowsApps\\bash\.exe$'
        })
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    return ($candidates | Select-Object -First 1)
}

function Find-GhidraReCygpath {
    param(
        [string]$BashPath
    )

    if (-not $BashPath) {
        return $null
    }

    $gitRoot = Split-Path (Split-Path $BashPath -Parent) -Parent
    $candidate = Join-Path $gitRoot "usr\bin\cygpath.exe"
    if (Test-Path $candidate) {
        return $candidate
    }
    return $null
}

function ConvertTo-GhidraReBashPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$CygpathPath
    )

    if ($CygpathPath -and (Test-Path $CygpathPath)) {
        return (& $CygpathPath -u $Path).Trim()
    }

    $normalized = $Path -replace '\\', '/'
    if ($normalized -match '^[A-Za-z]:/') {
        $drive = $normalized.Substring(0, 1).ToLowerInvariant()
        return "/$drive/$($normalized.Substring(3))"
    }
    return $normalized
}

function Test-GhidraReWindowsPath {
    param(
        [string]$Value
    )

    return ($Value -match '^[A-Za-z]:[\\/]') -or ($Value -match '^\\\\')
}

function ConvertTo-GhidraReArgument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Argument,
        [string]$CygpathPath
    )

    if ($Argument -match '^(?<key>[^=]+)=(?<value>.*)$') {
        $key = $Matches["key"]
        $value = $Matches["value"]
        if ($value -and -not ($value -like 'source:*') -and -not ($value -like 'json:*') -and (Test-GhidraReWindowsPath $value)) {
            return "$key=$(ConvertTo-GhidraReBashPath -Path $value -CygpathPath $CygpathPath)"
        }
        return $Argument
    }

    if (Test-GhidraReWindowsPath $Argument) {
        return (ConvertTo-GhidraReBashPath -Path $Argument -CygpathPath $CygpathPath)
    }

    return $Argument
}

function Get-GhidraReEnvironment {
    param(
        [string]$SkillRoot
    )

    $resolvedRoot = Resolve-GhidraReSkillRoot -SkillRoot $SkillRoot
    $bashPath = Find-GhidraReBash
    if (-not $bashPath) {
        throw "Git Bash was not found. Install Git for Windows or run the desktop installer bundle."
    }

    $cygpathPath = Find-GhidraReCygpath -BashPath $bashPath

    [pscustomobject]@{
        SkillRoot   = $resolvedRoot
        ScriptsRoot = Join-Path $resolvedRoot "scripts"
        BashPath    = $bashPath
        CygpathPath = $cygpathPath
    }
}

function Resolve-GhidraReScriptPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,
        [Parameter(Mandatory = $true)]
        [string]$SkillRoot
    )

    $resolved = if ([System.IO.Path]::IsPathRooted($ScriptName)) {
        $ScriptName
    } else {
        Join-Path (Join-Path $SkillRoot "scripts") $ScriptName
    }

    if (-not (Test-Path $resolved)) {
        throw "Cerberus RE script not found: $resolved"
    }

    return (Resolve-Path -LiteralPath $resolved).Path
}

function Join-GhidraReOutput {
    param(
        [object[]]$Lines
    )

    if (-not $Lines) {
        return ""
    }

    return (($Lines | ForEach-Object { "$_" }) -join "`n").Trim()
}

function ConvertFrom-GhidraReJsonIfPossible {
    param(
        [string]$Output
    )

    if (-not $Output) {
        return $null
    }

    $trimmed = $Output.Trim()
    if (($trimmed.StartsWith("{")) -or ($trimmed.StartsWith("["))) {
        return ($trimmed | ConvertFrom-Json)
    }

    return $trimmed
}

function Invoke-GhidraReScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,
        [string[]]$Arguments = @(),
        [string]$SkillRoot,
        [switch]$RawOutput
    )

    $envInfo = Get-GhidraReEnvironment -SkillRoot $SkillRoot
    $scriptPath = Resolve-GhidraReScriptPath -ScriptName $ScriptName -SkillRoot $envInfo.SkillRoot
    $bashScriptPath = ConvertTo-GhidraReBashPath -Path $scriptPath -CygpathPath $envInfo.CygpathPath
    $convertedArgs = @($Arguments | ForEach-Object { ConvertTo-GhidraReArgument -Argument "$_" -CygpathPath $envInfo.CygpathPath })

    $output = & $envInfo.BashPath $bashScriptPath @convertedArgs 2>&1
    $exitCode = $LASTEXITCODE
    $joined = Join-GhidraReOutput -Lines $output

    if ($exitCode -ne 0) {
        if ($joined) {
            throw $joined
        }
        throw "Cerberus RE script failed: $ScriptName"
    }

    if ($RawOutput) {
        return $joined
    }

    return (ConvertFrom-GhidraReJsonIfPossible -Output $joined)
}

function Find-GhidraRePython {
    $candidates = @()
    if ($env:PYTHON) {
        $candidates += $env:PYTHON
    }
    $candidates += @(
        (Get-Command python3 -ErrorAction SilentlyContinue | ForEach-Object { $_.Source }),
        (Get-Command python -ErrorAction SilentlyContinue | ForEach-Object { $_.Source }),
        (Get-Command py -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    )

    foreach ($candidate in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        if (Test-Path $candidate -PathType Leaf) {
            return $candidate
        }
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd) {
            return $cmd.Source
        }
    }

    throw "Python was not found. Install Python 3.11+ or pass it via the PYTHON environment variable."
}

function Invoke-GhidraReCli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [string]$SkillRoot,
        [switch]$RawOutput
    )

    $resolvedRoot = Resolve-GhidraReSkillRoot -SkillRoot $SkillRoot
    $python = Find-GhidraRePython

    Push-Location $resolvedRoot
    try {
        $output = & $python -m cerberus_re_skill @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }

    $joined = Join-GhidraReOutput -Lines $output
    if ($exitCode -ne 0) {
        if ($joined) {
            throw $joined
        }
        throw "Cerberus RE CLI failed: $($Arguments -join ' ')"
    }

    if ($RawOutput) {
        return $joined
    }

    return (ConvertFrom-GhidraReJsonIfPossible -Output $joined)
}
