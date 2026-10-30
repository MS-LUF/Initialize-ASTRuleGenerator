#Requires -Version 5.1
<#
.SYNOPSIS
    GitLab CI job that runs the Initialize-ASTRuleGenerator rules on the PowerShell files of a commit.
.DESCRIPTION
    Finds the PowerShell files (.ps1, .psm1, .psd1) changed by CI_COMMIT_SHA, and runs
    PSScriptAnalyzer on each of them with the Initialize-ASTRuleGenerator module as a custom rule
    path. The commit is compared with:

    In a merge request pipeline, the base of the merge request diff
    (CI_MERGE_REQUEST_DIFF_BASE_SHA). In the pipeline of a branch other than the default branch,
    its merge-base with the default branch, so that every commit of the branch is analysed and a
    harmless push cannot hide an earlier harmful one. Elsewhere (default branch, tag), the
    previous commit of the push, CI_COMMIT_BEFORE_SHA.

    Every PowerShell file of the repository is analysed in a scheduled or manual pipeline, and
    when there is no previous commit to compare with. When the clone is shallow or lacks the
    default branch, the job fetches them from origin with the runner's own remote; if that
    fails, the job fails.

    The job fails (exit code 1) when a finding has the Error severity, and also on any unexpected
    error, such as the rule module failing to load: a security check that cannot run must not
    pass. Every run writes pwsh-security-psanalyzer.log next to this script, for the job
    artifact.

    PSScriptAnalyzer and the rule module are loaded from the Security-PWSH-gitlab-ci folder,
    which is never analysed itself. Git is taken from the runner when installed; otherwise the
    portable client in Security-PWSH-gitlab-ci/GitClient/GitSource.zip is unpacked into a
    folder under the system temp path, for this job only.

    This sample targets a Windows runner.
.EXAMPLE
    ./sec-pwsh-analysis-malicious.ps1

    Run by the GitLab job, with the CI_* variables GitLab sets.
.NOTES
    (c) 2021 lucas-cueff.com - Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:JobRoot = $PSScriptRoot
$script:ToolFolderName = 'Security-PWSH-gitlab-ci'
$script:ToolRoot = Join-Path $script:JobRoot $script:ToolFolderName
$script:LogPath = Join-Path $script:JobRoot 'pwsh-security-psanalyzer.log'
$script:AnalysedExtension = @('.ps1', '.psm1', '.psd1')

function Write-SecurityJobLog {
    # Writes one line to the log artifact and to the job output.
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('info', 'warning', 'error')]
        [string] $Level,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Message
    )
    $line = '{0} {1} : {2}' -f (Get-Date -Format 's'), $Level.ToUpperInvariant(), $Message
    Add-Content -LiteralPath $script:LogPath -Value $line
    if ($Level -eq 'info') {
        Write-Information -MessageData $line -InformationAction Continue
    } else {
        # Written as a warning, not an error: under ErrorActionPreference Stop an error would end
        # the script before the result is decided.
        Write-Warning -Message $line
    }
}

function Get-SecurityJobGit {
    # Returns the path of git.exe: the runner's own git when installed, otherwise the portable
    # client unpacked into a folder under the system temp path for this job.
    $installed = Get-Command -Name 'git.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($installed) {
        return $installed.Source
    }
    foreach ($programFiles in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($programFiles) {
            $candidate = Join-Path (Join-Path (Join-Path $programFiles 'Git') 'bin') 'git.exe'
            if (Test-Path -LiteralPath $candidate) {
                return $candidate
            }
        }
    }

    $jobId = $env:CI_JOB_ID
    if (-not $jobId) {
        $jobId = [guid]::NewGuid().ToString('N')
    }
    $destination = Join-Path ([System.IO.Path]::GetTempPath()) "sec-pwsh-git-$jobId"
    Write-SecurityJobLog -Level warning -Message "git is not installed on the runner; unpacking the portable client into $destination"
    Expand-Archive -LiteralPath (Join-Path (Join-Path $script:ToolRoot 'GitClient') 'GitSource.zip') -DestinationPath $destination -Force
    Join-Path (Join-Path $destination 'bin') 'git.exe'
}

function Invoke-SecurityJobGit {
    # Runs git in the repository and fails when git does: ErrorActionPreference Stop does not
    # cover the exit code of a native command under Windows PowerShell 5.1.
    param(
        [Parameter(Mandatory = $true)]
        [string] $Git,

        [Parameter(Mandatory = $true)]
        [string[]] $Argument
    )
    $output = & $Git -C $script:RepositoryRoot @Argument
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Argument -join ' ') failed with exit code $LASTEXITCODE"
    }
    $output
}

function Test-SecurityJobGitCommit {
    # Tells whether a commit (SHA or ref) is present in the clone, without failing the job.
    param(
        [Parameter(Mandatory = $true)]
        [string] $Git,

        [Parameter(Mandatory = $true)]
        [string] $Commit
    )
    $null = & $Git -C $script:RepositoryRoot rev-parse --verify --quiet "$Commit^{commit}"
    $LASTEXITCODE -eq 0
}

function Receive-SecurityJobHistory {
    # Fetches what the comparison needs and the runner's clone may lack: the full history of a
    # shallow clone and, when given, the default branch. The runner's remote is used as is, so
    # no credential is handled here.
    param(
        [Parameter(Mandatory = $true)]
        [string] $Git,

        [string] $Branch
    )
    $argument = @('fetch', '--quiet')
    if ((Invoke-SecurityJobGit -Git $Git -Argument @('rev-parse', '--is-shallow-repository')) -eq 'true') {
        $argument += '--unshallow'
    }
    $argument += 'origin'
    if ($Branch) {
        $argument += "+refs/heads/$($Branch):refs/remotes/origin/$($Branch)"
    }
    Write-SecurityJobLog -Level info -Message "Fetching from origin: git $($argument -join ' ')"
    Invoke-SecurityJobGit -Git $Git -Argument $argument | Out-Null
}

function Get-SecurityJobBase {
    # Returns the commit to compare CI_COMMIT_SHA with, or nothing when every PowerShell file of
    # the repository is to be analysed.
    #   - merge request pipeline: the base of the merge request diff;
    #   - scheduled or manual pipeline: none, every file;
    #   - pipeline of a branch other than the default branch: the merge-base with the default
    #     branch, so that every commit of the branch is analysed, not only the last push;
    #   - any other pipeline (default branch, tag): the previous commit of the push, or none.
    param(
        [Parameter(Mandatory = $true)]
        [string] $Git
    )
    $mergeRequestBase = $env:CI_MERGE_REQUEST_DIFF_BASE_SHA
    if ($mergeRequestBase) {
        if (-not (Test-SecurityJobGitCommit -Git $Git -Commit $mergeRequestBase)) {
            Receive-SecurityJobHistory -Git $Git
        }
        if (-not (Test-SecurityJobGitCommit -Git $Git -Commit $mergeRequestBase)) {
            throw "The base commit of the merge request ($mergeRequestBase) is not in the clone, even after fetching."
        }
        Write-SecurityJobLog -Level info -Message "Merge request pipeline: compared with the base of the merge request diff, $mergeRequestBase."
        return $mergeRequestBase
    }

    if (@('schedule', 'web') -contains $env:CI_PIPELINE_SOURCE) {
        Write-SecurityJobLog -Level info -Message "Pipeline started by '$($env:CI_PIPELINE_SOURCE)': every PowerShell file of the repository is analysed."
        return
    }

    $branch = $env:CI_COMMIT_BRANCH
    if ($branch -and $branch -ne $env:CI_DEFAULT_BRANCH) {
        $defaultBranch = $env:CI_DEFAULT_BRANCH
        if (-not $defaultBranch) {
            throw "CI_DEFAULT_BRANCH is not set: the branch '$branch' cannot be compared with the default branch."
        }
        $defaultRef = "refs/remotes/origin/$defaultBranch"
        $shallow = (Invoke-SecurityJobGit -Git $Git -Argument @('rev-parse', '--is-shallow-repository')) -eq 'true'
        if ($shallow -or -not (Test-SecurityJobGitCommit -Git $Git -Commit $defaultRef)) {
            Receive-SecurityJobHistory -Git $Git -Branch $defaultBranch
        }
        # Throws when the branch shares no history with the default branch: the job fails
        # rather than analyse less than the branch holds.
        $base = Invoke-SecurityJobGit -Git $Git -Argument @('merge-base', $defaultRef, $env:CI_COMMIT_SHA) | Select-Object -First 1
        Write-SecurityJobLog -Level info -Message "Branch pipeline: compared with the merge-base with $defaultBranch, $base."
        return $base
    }

    $before = $env:CI_COMMIT_BEFORE_SHA
    if ([string]::IsNullOrWhiteSpace($before) -or $before -match '^0+$') {
        Write-SecurityJobLog -Level info -Message 'No previous commit to compare with: every PowerShell file of the repository is analysed.'
        return
    }
    Write-SecurityJobLog -Level info -Message "Compared with the previous commit of the push, $before."
    $before
}

function Get-SecurityJobFile {
    # Returns the repository-relative paths of the PowerShell files to analyse.
    param(
        [Parameter(Mandatory = $true)]
        [string] $Git
    )
    $base = Get-SecurityJobBase -Git $Git
    if (-not $base) {
        $candidate = Invoke-SecurityJobGit -Git $Git -Argument @('ls-files')
    } else {
        # Deleted files are left out: there is nothing left to analyse.
        $candidate = Invoke-SecurityJobGit -Git $Git -Argument @('diff', '--name-only', '--diff-filter=d', $base, $env:CI_COMMIT_SHA)
    }

    foreach ($path in @($candidate)) {
        if (-not $path) { continue }
        Write-SecurityJobLog -Level info -Message "File in scope: $path"
        $normalised = $path -replace '\\', '/'
        if ($normalised -like "$($script:ToolFolderName)/*") { continue }
        if ($script:AnalysedExtension -notcontains [System.IO.Path]::GetExtension($normalised).ToLowerInvariant()) { continue }
        $normalised
    }
}

$exitCode = 1
try {
    if (Test-Path -LiteralPath $script:LogPath) {
        Remove-Item -LiteralPath $script:LogPath -Force
    }
    $script:RepositoryRoot = $env:CI_PROJECT_DIR
    if (-not $script:RepositoryRoot) {
        $script:RepositoryRoot = $script:JobRoot
    }

    Write-SecurityJobLog -Level info -Message "Scenario : $($env:SCENARIO)"
    Write-SecurityJobLog -Level info -Message "Project : $($env:CI_PROJECT_NAME)"
    Write-SecurityJobLog -Level info -Message "Commit user : $($env:GITLAB_USER_LOGIN)"
    Write-SecurityJobLog -Level info -Message "Pipeline source : $($env:CI_PIPELINE_SOURCE)"
    Write-SecurityJobLog -Level info -Message "Commit branch : $($env:CI_COMMIT_BRANCH)"
    Write-SecurityJobLog -Level info -Message "Default branch : $($env:CI_DEFAULT_BRANCH)"
    if ($env:CI_MERGE_REQUEST_DIFF_BASE_SHA) {
        Write-SecurityJobLog -Level info -Message "Merge request diff base SHA : $($env:CI_MERGE_REQUEST_DIFF_BASE_SHA)"
    }
    Write-SecurityJobLog -Level info -Message "Commit before SHA : $($env:CI_COMMIT_BEFORE_SHA)"
    Write-SecurityJobLog -Level info -Message "Commit SHA : $($env:CI_COMMIT_SHA)"
    if ($env:ASTRULEGENERATOR_CONFIG) {
        Write-SecurityJobLog -Level info -Message "Rules file : $($env:ASTRULEGENERATOR_CONFIG)"
    }

    Import-Module (Join-Path (Join-Path $script:ToolRoot 'PSScriptAnalyzer') 'PSScriptAnalyzer.psd1')
    $ruleModule = Join-Path (Join-Path $script:ToolRoot 'Initialize-ASTRuleGenerator') 'Initialize-ASTRuleGenerator.psd1'

    $git = Get-SecurityJobGit
    $files = @(Get-SecurityJobFile -Git $git)
    Write-SecurityJobLog -Level info -Message "PowerShell files to analyse: $($files.Count)"

    $results = @()
    foreach ($file in $files) {
        $fullPath = Join-Path $script:RepositoryRoot $file
        Write-SecurityJobLog -Level info -Message "Analysing $file"
        # When the rule module cannot load, this throws "Cannot find ScriptAnalyzer rules in the
        # specified path", which fails the job through the catch below.
        $results += @(Invoke-ScriptAnalyzer -Path $fullPath -CustomRulePath $ruleModule)
        # A file must not be able to hide its own findings with a suppression attribute.
        foreach ($result in @(Invoke-ScriptAnalyzer -Path $fullPath -CustomRulePath $ruleModule -SuppressedOnly)) {
            $results += [pscustomobject]@{
                ScriptName = $result.ScriptName
                Line       = $result.Line
                RuleName   = $result.RuleName
                Severity   = "$($result.Severity)"
                Message    = "Suppressed in the file, still counted: $($result.Message)"
            }
        }
    }

    foreach ($result in $results) {
        Write-SecurityJobLog -Level warning -Message "$($result.ScriptName) line $($result.Line) - $($result.Severity) : $($result.RuleName) - $($result.Message)"
    }
    if (@($results | Where-Object { "$($_.Severity)" -eq 'Error' }).Count -gt 0) {
        Write-SecurityJobLog -Level error -Message "Potential malicious PowerShell found: $($results.Count) finding(s), at least one with the Error severity. The job fails."
        $exitCode = 1
    } else {
        Write-SecurityJobLog -Level info -Message "Analysis finished: $($results.Count) finding(s), none with the Error severity."
        $exitCode = 0
    }
} catch {
    try {
        Write-SecurityJobLog -Level error -Message "The analysis could not run, so the job fails: $($_.Exception.Message)"
    } catch {
        Write-Warning -Message "The analysis could not run, so the job fails: $($_.Exception.Message)"
    }
    $exitCode = 1
}
exit $exitCode
