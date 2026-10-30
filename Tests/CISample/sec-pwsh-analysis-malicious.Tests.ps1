BeforeDiscovery {
    # The sample targets a Windows runner (it looks for git.exe), so its tests run on Windows only.
    # -Skip is evaluated during discovery, so the platform is found here rather than in BeforeAll.
    # $IsWindows does not exist under Windows PowerShell 5.1, which only runs on Windows.
    $script:OnWindows = ($null -eq (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)) -or $IsWindows
}

BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:SampleRoot = Join-Path $script:RepoRoot 'GitLab-CICD-Sample-Integration'
    # The child process runs the same PowerShell edition as the tests.
    $script:PowerShellPath = (Get-Process -Id $PID).Path
    $script:Git = (Get-Command -Name 'git' -CommandType Application | Select-Object -First 1).Source

    $script:SavedEnvironment = @{}
    foreach ($name in 'CI_PROJECT_DIR', 'CI_COMMIT_BEFORE_SHA', 'CI_COMMIT_SHA', 'CI_JOB_ID', 'CI_COMMIT_BRANCH', 'CI_DEFAULT_BRANCH', 'CI_MERGE_REQUEST_DIFF_BASE_SHA', 'CI_PIPELINE_SOURCE', 'ASTRULEGENERATOR_CONFIG') {
        $script:SavedEnvironment[$name] = [System.Environment]::GetEnvironmentVariable($name)
    }

    function Invoke-TestGit {
        param([string] $Repository, [string[]] $Argument)
        $output = & $script:Git -C $Repository -c user.name=Test -c user.email=test@example.com -c core.autocrlf=false @Argument
        if ($LASTEXITCODE -ne 0) { throw "git $($Argument -join ' ') failed" }
        $output
    }

    # Builds a repository laid out as the sample README describes: the job script at the root,
    # PSScriptAnalyzer and the rule module under Security-PWSH-gitlab-ci, with test rules: an
    # Error rule on "&" calls and a Warning rule on Get-Date.
    function New-TestRepository {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that only writes into the Pester TestDrive.')]
        param([string] $Name)
        $repository = Join-Path $TestDrive $Name
        $tools = Join-Path $repository 'Security-PWSH-gitlab-ci'
        $moduleFolder = Join-Path $tools 'Initialize-ASTRuleGenerator'
        New-Item -ItemType Directory -Path $moduleFolder -Force | Out-Null
        Copy-Item -Path (Join-Path $script:SampleRoot 'sec-pwsh-analysis-malicious.ps1') -Destination $repository

        $analyzer = Get-Module -Name PSScriptAnalyzer -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        Copy-Item -Path $analyzer.ModuleBase -Destination (Join-Path $tools 'PSScriptAnalyzer') -Recurse

        foreach ($item in 'Initialize-ASTRuleGenerator.psd1', 'Initialize-ASTRuleGenerator.psm1', 'Public', 'Private', 'en-US') {
            Copy-Item -Path (Join-Path $script:RepoRoot $item) -Destination $moduleFolder -Recurse
        }
        $rules = @(
            @{ Status = 'Enable'; Name = 'Ampersand calls'; ASTType = 'CommandAst'; ASTProperty = 'InvocationOperator'; Operator = 'eq'; SearchStringPattern = @('Ampersand'); Message = 'Ampersand call'; Severity = 'error' }
            @{ Status = 'Enable'; Name = 'Get-Date calls'; ASTType = 'StringConstantExpressionAst'; ASTProperty = 'Value'; Operator = 'eq'; SearchStringPattern = @('Get-Date'); Message = 'Get-Date call'; Severity = 'warning' }
        )
        Set-Content -Path (Join-Path $moduleFolder 'Initialize-ASTRuleGenerator.json') -Value (ConvertTo-Json -InputObject @{ rules = $rules } -Depth 5)

        Invoke-TestGit -Repository $TestDrive -Argument @('init', '--quiet', $repository) | Out-Null
        Set-Content -Path (Join-Path $repository 'clean.ps1') -Value 'Write-Output "hello"'
        Invoke-TestGit -Repository $repository -Argument @('add', '--all') | Out-Null
        Invoke-TestGit -Repository $repository -Argument @('commit', '--quiet', '-m', 'first') | Out-Null
        $repository
    }

    function Add-TestCommit {
        param([string] $Repository, [hashtable] $File)
        foreach ($name in $File.Keys) {
            Set-Content -Path (Join-Path $Repository $name) -Value $File[$name]
        }
        Invoke-TestGit -Repository $Repository -Argument @('add', '--all') | Out-Null
        Invoke-TestGit -Repository $Repository -Argument @('commit', '--quiet', '-m', 'change') | Out-Null
        Invoke-TestGit -Repository $Repository -Argument @('rev-parse', 'HEAD')
    }

    function Invoke-TestJob {
        param(
            [string] $Repository, [string] $Before, [string] $Commit, [string] $RulesFile,
            [string] $Branch, [string] $DefaultBranch, [string] $MergeRequestBase, [string] $PipelineSource
        )
        # An empty value removes the variable, so a value set by an earlier test never leaks.
        $env:CI_COMMIT_BRANCH = $Branch
        $env:CI_DEFAULT_BRANCH = $DefaultBranch
        $env:CI_MERGE_REQUEST_DIFF_BASE_SHA = $MergeRequestBase
        $env:CI_PIPELINE_SOURCE = $PipelineSource
        $env:CI_PROJECT_DIR = $Repository
        $env:CI_COMMIT_BEFORE_SHA = $Before
        $env:CI_COMMIT_SHA = $Commit
        $env:CI_JOB_ID = [guid]::NewGuid().ToString('N')
        $env:ASTRULEGENERATOR_CONFIG = $RulesFile
        $null = & $script:PowerShellPath -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Repository 'sec-pwsh-analysis-malicious.ps1') 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
        $logPath = Join-Path $Repository 'pwsh-security-psanalyzer.log'
        $log = ''
        if (Test-Path -LiteralPath $logPath) {
            $log = [System.IO.File]::ReadAllText($logPath)
        }
        [PSCustomObject]@{ ExitCode = $exitCode; Log = $log }
    }

    # Clones a branch the way a GitLab runner does by default: shallow, with that branch only, so
    # the default branch is not in the clone. A file:// URL makes git honour --depth locally.
    function New-TestRunnerClone {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that only writes into the Pester TestDrive.')]
        param([string] $Origin, [string] $Branch, [string] $Name, [switch] $Full)
        $clone = Join-Path $TestDrive $Name
        $url = 'file:///' + ($Origin -replace '\\', '/')
        $argument = @('clone', '--quiet', '--branch', $Branch)
        if (-not $Full) {
            $argument += @('--depth', '1')
        }
        Invoke-TestGit -Repository $TestDrive -Argument ($argument + @($url, $clone)) | Out-Null
        $clone
    }
}

AfterAll {
    foreach ($name in $script:SavedEnvironment.Keys) {
        [System.Environment]::SetEnvironmentVariable($name, $script:SavedEnvironment[$name])
    }
}

Describe 'GitLab CI sample script' -Tag Integration -Skip:(-not $script:OnWindows) {
    BeforeAll {
        $script:Repository = New-TestRepository -Name 'repo'
        $script:FirstCommit = Invoke-TestGit -Repository $script:Repository -Argument @('rev-parse', 'HEAD')
        $script:WarningCommit = Add-TestCommit -Repository $script:Repository -File @{ 'dated.ps1' = 'Get-Date'; 'notes.txt' = '& not PowerShell' }
        $script:ErrorCommit = Add-TestCommit -Repository $script:Repository -File @{ 'evil.ps1' = '& cmd.exe /c whoami' }
    }

    It 'passes and still writes the log when the changed PowerShell files have no Error finding' {
        $result = Invoke-TestJob -Repository $script:Repository -Before $script:FirstCommit -Commit $script:WarningCommit

        $result.ExitCode | Should -Be 0
        $result.Log | Should -Match 'PowerShell files to analyse: 1'
        $result.Log | Should -Match 'Get-Date calls'
        $result.Log | Should -Not -Match 'Analysing notes\.txt'
        $result.Log | Should -Match 'none with the Error severity'
    }

    It 'fails with exit code 1 when a changed file has an Error finding' {
        $result = Invoke-TestJob -Repository $script:Repository -Before $script:WarningCommit -Commit $script:ErrorCommit

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'evil\.ps1 line 1 - Error : Ampersand calls'
        $result.Log | Should -Match 'The job fails'
    }

    It 'analyses every PowerShell file except its own tools when there is no previous commit' {
        $result = Invoke-TestJob -Repository $script:Repository -Before ('0' * 40) -Commit $script:ErrorCommit

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'No previous commit to compare with'
        $result.Log | Should -Match 'PowerShell files to analyse: 4'
        $result.Log | Should -Match 'Analysing evil\.ps1'
        $result.Log | Should -Not -Match 'Analysing Security-PWSH-gitlab-ci/'
    }

    It 'fails when the rule module cannot load, instead of passing with no findings' {
        $result = Invoke-TestJob -Repository $script:Repository -Before $script:FirstCommit -Commit $script:WarningCommit -RulesFile (Join-Path $TestDrive 'no-such-rules.json')

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'The analysis could not run, so the job fails'
    }

    It 'fails when git cannot compare the commits' {
        $result = Invoke-TestJob -Repository $script:Repository -Before ('1' * 40) -Commit $script:ErrorCommit

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'git diff .* failed'
    }
}

Describe 'GitLab CI sample script, compared range by pipeline type' -Tag Integration -Skip:(-not $script:OnWindows) {
    BeforeAll {
        # The origin: main with the tools and a clean file, then a feature branch with a harmful
        # commit followed by a harmless one, then one more commit on main.
        $script:Origin = New-TestRepository -Name 'origin'
        Invoke-TestGit -Repository $script:Origin -Argument @('branch', '--move', '--force', 'main') | Out-Null
        $script:MainFirst = Invoke-TestGit -Repository $script:Origin -Argument @('rev-parse', 'HEAD')
        Invoke-TestGit -Repository $script:Origin -Argument @('checkout', '--quiet', '-b', 'feature') | Out-Null
        $script:HarmfulCommit = Add-TestCommit -Repository $script:Origin -File @{ 'evil.ps1' = '& cmd.exe /c whoami' }
        $script:HarmlessCommit = Add-TestCommit -Repository $script:Origin -File @{ 'later.ps1' = 'Write-Output "later"' }
        Invoke-TestGit -Repository $script:Origin -Argument @('checkout', '--quiet', 'main') | Out-Null
        $script:MainSecond = Add-TestCommit -Repository $script:Origin -File @{ 'dated.ps1' = 'Get-Date' }
    }

    It 'fails a branch pipeline whose last push is harmless when an earlier commit of the branch is harmful' {
        $clone = New-TestRunnerClone -Origin $script:Origin -Branch 'feature' -Name 'branch-pipeline'

        $result = Invoke-TestJob -Repository $clone -Before $script:HarmfulCommit -Commit $script:HarmlessCommit -Branch 'feature' -DefaultBranch 'main' -PipelineSource 'push'

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'Fetching from origin: git fetch --quiet --unshallow origin \+refs/heads/main:refs/remotes/origin/main'
        $result.Log | Should -Match "merge-base with main, $($script:MainFirst)"
        $result.Log | Should -Match 'PowerShell files to analyse: 2'
        $result.Log | Should -Match 'evil\.ps1 line 1 - Error : Ampersand calls'
        $result.Log | Should -Not -Match 'Analysing dated\.ps1'
    }

    It 'fails a branch pipeline when the default branch cannot be fetched' {
        $clone = New-TestRunnerClone -Origin $script:Origin -Branch 'feature' -Name 'no-origin'
        $missingOrigin = 'file:///' + ((Join-Path $TestDrive 'no-such-origin') -replace '\\', '/')
        Invoke-TestGit -Repository $clone -Argument @('remote', 'set-url', 'origin', $missingOrigin) | Out-Null

        $result = Invoke-TestJob -Repository $clone -Before $script:HarmfulCommit -Commit $script:HarmlessCommit -Branch 'feature' -DefaultBranch 'main' -PipelineSource 'push'

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'The analysis could not run, so the job fails: git fetch .* failed'
    }

    It 'fails a branch pipeline when the default branch is not known' {
        $clone = New-TestRunnerClone -Origin $script:Origin -Branch 'feature' -Name 'no-default'

        $result = Invoke-TestJob -Repository $clone -Before $script:HarmfulCommit -Commit $script:HarmlessCommit -Branch 'feature' -PipelineSource 'push'

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'CI_DEFAULT_BRANCH is not set'
    }

    It 'compares a merge request pipeline with the base of the merge request diff' {
        $clone = New-TestRunnerClone -Origin $script:Origin -Branch 'feature' -Name 'merge-request'

        $result = Invoke-TestJob -Repository $clone -Before ('0' * 40) -Commit $script:HarmlessCommit -DefaultBranch 'main' -MergeRequestBase $script:MainFirst -PipelineSource 'merge_request_event'

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'Fetching from origin: git fetch --quiet --unshallow origin\r?\n'
        $result.Log | Should -Match "base of the merge request diff, $($script:MainFirst)"
        $result.Log | Should -Match 'PowerShell files to analyse: 2'
        $result.Log | Should -Match 'Analysing evil\.ps1'
    }

    It 'compares a push to the default branch with the previous commit of the push' {
        $clone = New-TestRunnerClone -Origin $script:Origin -Branch 'main' -Name 'default-branch' -Full

        $result = Invoke-TestJob -Repository $clone -Before $script:MainFirst -Commit $script:MainSecond -Branch 'main' -DefaultBranch 'main' -PipelineSource 'push'

        $result.ExitCode | Should -Be 0
        $result.Log | Should -Match "previous commit of the push, $($script:MainFirst)"
        $result.Log | Should -Match 'PowerShell files to analyse: 1'
        $result.Log | Should -Not -Match 'Fetching from origin'
    }

    It 'analyses every PowerShell file in a scheduled pipeline' {
        $clone = New-TestRunnerClone -Origin $script:Origin -Branch 'feature' -Name 'scheduled'

        $result = Invoke-TestJob -Repository $clone -Before ('0' * 40) -Commit $script:HarmlessCommit -Branch 'feature' -DefaultBranch 'main' -PipelineSource 'schedule'

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match "Pipeline started by 'schedule': every PowerShell file"
        $result.Log | Should -Match 'Analysing clean\.ps1'
        $result.Log | Should -Match 'Analysing evil\.ps1'
        $result.Log | Should -Not -Match 'Fetching from origin'
    }
}
