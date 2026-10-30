<#
.SYNOPSIS
Azure DevOps job that runs the Initialize-ASTRuleGenerator rules on the PowerShell files of a branch.
.DESCRIPTION
Fails (exit code 1) on an Error finding, and when the analysis cannot run.
PSScriptAnalyzer and the rule module are loaded from the Security-PWSH-ADO-ci folder,
which is never analyzed itself.
Uses BUILD_SOURCESDIRECTORY and BUILD_SOURCEVERSION when available.
PR builds compare the tested merge commit to its first (target) parent.
Other builds compare the tested commit to its merge-base with the base branch,
so every commit of the branch is analyzed, not only the last one of a push.
The checkout must hold the full history and origin/BaseBranch (fetchDepth: 0);
no Git credentials are needed. The CI tooling folder is never analyzed.
.PARAMETER PSScriptAnalyzerVersion
Exact analyzer version, including for a bundled module. An installed version
is reused; PSGallery is contacted only when that version is missing.
.PARAMETER BaseBranch
Branch whose merge-base with the tested commit starts the compared range.
#>
[CmdletBinding()]
param(
    [version]$PSScriptAnalyzerVersion = '1.25.0',
    [string]$BaseBranch = 'main'
)

#_____________________________________________________________________________________________________
# Define functions
Function Get-ScriptDirectory {
	[cmdletbinding()]
	Param ()
	if ($psISE) {
        $ScriptPath = Split-Path -Parent $psISE.CurrentFile.FullPath
    } elseif($PSVersionTable.PSVersion.Major -gt 3) {
        $ScriptPath = $PSScriptRoot
    } else {
        $ScriptPath = split-path -parent $MyInvocation.MyCommand.Path
    }
	$ScriptPath
}
Function Write-SecurityJobLog {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [ValidateSet("info", "warning", "error")]
            [string]$info,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [string]$file = $script:fulllogpath,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
            [string]$message
    )
    if (!(test-path $file)) {
        New-Item -ItemType File -Path $file | out-null
        Add-Content -Path $file -value "INFO : File created on : $((get-date).ToString())"
    }
    Add-content -Path $file -value "$($info) : $($message)"
    write-verbose "$($info) : $($message)"
    if ($info -eq "warning") {
        write-warning -message $message
    }
    if ($info -eq "error") {
        Write-Error -Message $message -ErrorAction Continue
    }
}

function Invoke-RepositoryGit {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & git -C $script:RepositoryRoot @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed (exit $LASTEXITCODE): $($output -join [Environment]::NewLine)"
    }
    $output | ForEach-Object { $_.ToString() }
}
#_____________________________________________________________________________________________________
# Define log
$ScriptDirectory = Get-ScriptDirectory
$logpath = Join-Path $ScriptDirectory "Logs"
if (!(test-path $logpath)) {
    New-Item -ItemType Directory -Path $logpath | out-null
}
$timefile = (get-date).ticks.tostring()
$logfile = "sec_pwsh_malicious_$($env:BUILD_REPOSITORY_NAME)_$($env:BUILD_REQUESTEDFOR)_$($timefile).log"
$script:fulllogpath = join-path $logpath $logfile

#_____________________________________________________________________________________________________
$customexitcode = 0
try {
    $ErrorActionPreference = 'Stop'
    $script:RepositoryRoot = if ($env:BUILD_SOURCESDIRECTORY) {
        $env:BUILD_SOURCESDIRECTORY
    } else {
        $ScriptDirectory
    }
    $script:RepositoryRoot = Invoke-RepositoryGit -Arguments @('rev-parse', '--show-toplevel')
    $commitReference = if ($env:BUILD_SOURCEVERSION) { $env:BUILD_SOURCEVERSION } else { 'HEAD' }
    $commit = Invoke-RepositoryGit -Arguments @('rev-parse', '--verify', "$commitReference^{commit}")
    $checkedOutCommit = Invoke-RepositoryGit -Arguments @('rev-parse', '--verify', 'HEAD')
    if ($commit -ne $checkedOutCommit) {
        throw "BUILD_SOURCEVERSION ($commit) does not match the checked-out commit ($checkedOutCommit)."
    }

    Write-SecurityJobLog -info info -message "Commit user : $($env:BUILD_REQUESTEDFOR)" -Verbose
    Write-SecurityJobLog -info info -message "Project : $($env:BUILD_REPOSITORY_NAME)" -Verbose
    Write-SecurityJobLog -info info -message "Commit Branch : $($env:BUILD_SOURCEBRANCH)" -Verbose
    Write-SecurityJobLog -info info -message "Commit SHA : $commit" -Verbose
    Write-SecurityJobLog -info info -message "PowerShell : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))" -Verbose

    # Every commit of the branch is compared, not only the last one of a push: a harmful commit
    # followed by a harmless one must not pass. This needs the full history (fetchDepth: 0).
    if ((Invoke-RepositoryGit -Arguments @('rev-parse', '--is-shallow-repository')) -eq 'true') {
        throw "Shallow checkout: the comparison needs the full history (checkout fetchDepth: 0)."
    }
    $parents = (Invoke-RepositoryGit -Arguments @('rev-list', '--parents', '-n', '1', $commit)) -split ' '
    if ($env:BUILD_REASON -eq 'PullRequest') {
        # Azure DevOps PR builds test a merge commit; its first parent is the target.
        if ($parents.Count -lt 3) {
            throw "Expected an Azure DevOps pull request merge commit with two parents."
        }
        $baseCommit = $parents[1]
    } else {
        $baseReference = "refs/remotes/origin/$BaseBranch"
        if (-not (Invoke-RepositoryGit -Arguments @('for-each-ref', '--format=%(objectname)', $baseReference))) {
            throw "origin/$BaseBranch is not in the checkout: the comparison needs it (checkout fetchDepth: 0)."
        }
        $baseCommit = Invoke-RepositoryGit -Arguments @('merge-base', $baseReference, $commit)
        if ($baseCommit -eq $commit) {
            # The tested commit is already on the base branch: compare it to its parent.
            $baseCommit = if ($parents.Count -gt 1) { $parents[1] } else { $null }
        }
    }
    if ($baseCommit) {
        Write-SecurityJobLog -info info -message "Comparison: $baseCommit -> $commit" -Verbose
        $diffArguments = @('diff', '--name-only', '-z', '--diff-filter=ACMRT', $baseCommit, $commit, '--')
    } else {
        Write-SecurityJobLog -info info -message "Initial commit: analyzing all added scripts." -Verbose
        $diffArguments = @('diff-tree', '--root', '--no-commit-id', '-r', '--name-only', '-z', '--diff-filter=ACMRT', $commit, '--')
    }
    $outputgitdiff = ((Invoke-RepositoryGit -Arguments $diffArguments) -join "`n") -split "`0"
    # The CI tooling folder is never analyzed. 
    $scriptFiles = @($outputgitdiff | Where-Object { $_ -match '\.(ps1|psm1|psd1)$' -and -not $_.StartsWith('Security-PWSH-ADO-ci/') })
    $results = New-Object 'System.Collections.Generic.List[object]'

    if ($scriptFiles.Count -gt 0) {
        $toolRoot = Join-Path $ScriptDirectory 'Security-PWSH-ADO-ci'
        $PsscriptAnalyzermodule = Join-Path (Join-Path $toolRoot 'PSScriptAnalyzer') 'PSScriptAnalyzer.psd1'
        if (Test-Path -LiteralPath $PsscriptAnalyzermodule -PathType Leaf) {
            $manifest = Test-ModuleManifest -Path $PsscriptAnalyzermodule
            if ($manifest.Version -ne $PSScriptAnalyzerVersion) {
                throw "Bundled PSScriptAnalyzer version $($manifest.Version) differs from required version $PSScriptAnalyzerVersion."
            }
            Import-Module -Name $PsscriptAnalyzermodule -RequiredVersion $PSScriptAnalyzerVersion -Force
        } else {
            $installedModule = Get-Module -ListAvailable -Name PSScriptAnalyzer |
                Where-Object { $_.Version -eq $PSScriptAnalyzerVersion } |
                Select-Object -First 1
            if (-not $installedModule) {
                Write-SecurityJobLog -info info -message "Installing PSScriptAnalyzer $PSScriptAnalyzerVersion." -Verbose
                Install-Module -Name PSScriptAnalyzer -RequiredVersion $PSScriptAnalyzerVersion -Force -AcceptLicense -AllowClobber -Scope CurrentUser -Repository PSGallery
            }
            Import-Module -Name PSScriptAnalyzer -RequiredVersion $PSScriptAnalyzerVersion -Force
        }
        $custommodule = Join-Path (Join-Path $toolRoot 'Initialize-ASTRuleGenerator') 'Initialize-ASTRuleGenerator.psd1'
        if (-not (Test-Path -LiteralPath $custommodule -PathType Leaf)) {
            throw "Custom analyzer module not found: $custommodule"
        }

        foreach ($entry in $scriptFiles) {
            $changedFilePath = Join-Path $script:RepositoryRoot $entry
            if (-not (Test-Path -LiteralPath $changedFilePath -PathType Leaf)) {
                throw "Changed script not found in the checkout: $changedFilePath"
            }
            Write-SecurityJobLog -info info -message "Analyzing $changedFilePath" -Verbose
            foreach ($result in (Invoke-ScriptAnalyzer -Path $changedFilePath -CustomRulePath $custommodule -ErrorAction Stop)) {
                $results.Add($result)
            }
        }
    } else {
        Write-SecurityJobLog -info info -message "No changed PowerShell scripts to analyze." -Verbose
    }

    if ($results.Count -gt 0) {
        foreach ($result in $results) {
            Write-SecurityJobLog -info warning -message "$($result.ScriptName) - $($result.Severity) : $($result.RuleName) - $($result.Message) - $($result.Line)"
        }
        if ($results.Severity -contains 'Error') {
            $customexitcode = 1
            Write-SecurityJobLog -info error -message "Potential PWSH malicious code found in commit files - exit job with error" -Verbose
        }
    } else {
        Write-SecurityJobLog -info info -message "Analysis completed with no findings." -Verbose
    }
} catch {
    $customexitcode = 1
    $failure = $_
    $errorDetails = @(
        $failure.Exception.ToString()
        "Error ID: $($failure.FullyQualifiedErrorId)"
        $failure.InvocationInfo.PositionMessage
        $failure.ScriptStackTrace
    ) -join [Environment]::NewLine
    Write-SecurityJobLog -info error -message $errorDetails -Verbose
} finally {
    try {
        $reportPath = Join-Path $ScriptDirectory "pwsh-security-psanalyzer.log"
        Write-SecurityJobLog -info info -message "Copy current log to $reportPath" -Verbose
        Copy-Item -LiteralPath $script:fulllogpath -Destination $reportPath -Force -ErrorAction Stop
        Get-Content -LiteralPath $script:fulllogpath -ErrorAction Stop
    } catch {
        $customexitcode = 1
        Write-Error -Message "Unable to publish the analyzer log: $($_.Exception.Message)" -ErrorAction Continue
    }
}
exit $customexitcode