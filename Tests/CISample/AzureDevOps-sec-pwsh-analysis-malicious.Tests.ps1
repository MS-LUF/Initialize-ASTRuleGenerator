BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:SampleRoot = Join-Path $script:RepoRoot 'AzureDevOPS-CICD-Sample-Integration'
    # The child process runs the same PowerShell edition as the tests.
    $script:PowerShellPath = (Get-Process -Id $PID).Path
    $script:Git = (Get-Command -Name 'git' -CommandType Application | Select-Object -First 1).Source

    # The job reads the Azure DevOps variables. The tests set them, and they may run inside a real
    # Azure DevOps job (a pull request build sets BUILD_REASON), so all of them are saved.
    $script:VariableName = 'BUILD_SOURCESDIRECTORY', 'BUILD_SOURCEVERSION', 'BUILD_REASON', 'BUILD_REPOSITORY_NAME', 'BUILD_REQUESTEDFOR', 'BUILD_SOURCEBRANCH', 'ASTRULEGENERATOR_CONFIG'
    $script:SavedEnvironment = @{}
    foreach ($name in $script:VariableName) {
        $script:SavedEnvironment[$name] = [System.Environment]::GetEnvironmentVariable($name)
    }

    function Invoke-TestGit {
        param([string] $Repository, [string[]] $Argument)
        $output = & $script:Git -C $Repository -c user.name=Test -c user.email=test@example.com -c core.autocrlf=false @Argument
        if ($LASTEXITCODE -ne 0) { throw "git $($Argument -join ' ') failed" }
        $output
    }

    # Builds a repository laid out as the sample README describes: the job script at the root,
    # PSScriptAnalyzer and the rule module under Security-PWSH-ADO-ci, with test rules: an Error
    # rule on "&" calls and a Warning rule on Get-Date. Its first commit stands for main.
    function New-TestRepository {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that only writes into the Pester TestDrive.')]
        param([string] $Name)
        $repository = Join-Path $TestDrive $Name
        $tools = Join-Path $repository 'Security-PWSH-ADO-ci'
        $moduleFolder = Join-Path $tools 'Initialize-ASTRuleGenerator'
        New-Item -ItemType Directory -Path $moduleFolder -Force | Out-Null
        Copy-Item -Path (Join-Path $script:SampleRoot 'sec-pwsh-analysis-malicious.ps1') -Destination $repository

        Copy-Item -Path $script:Analyzer.ModuleBase -Destination (Join-Path $tools 'PSScriptAnalyzer') -Recurse

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
        $first = Invoke-TestGit -Repository $repository -Argument @('rev-parse', 'HEAD')
        Invoke-TestGit -Repository $repository -Argument @('update-ref', 'refs/remotes/origin/main', $first) | Out-Null
        $repository
    }

    function Add-TestCommit {
        param([string] $Repository, [hashtable] $File)
        foreach ($name in $File.Keys) {
            $path = Join-Path $Repository $name
            New-Item -ItemType Directory -Path (Split-Path -Path $path -Parent) -Force | Out-Null
            Set-Content -Path $path -Value $File[$name]
        }
        Invoke-TestGit -Repository $Repository -Argument @('add', '--all') | Out-Null
        Invoke-TestGit -Repository $Repository -Argument @('commit', '--quiet', '-m', 'change') | Out-Null
        Invoke-TestGit -Repository $Repository -Argument @('rev-parse', 'HEAD')
    }

    # Runs the job on a commit, as a branch (not pull request) build of Azure DevOps would.
    function Invoke-TestJob {
        param([string] $Repository, [string] $Commit, [string] $RulesFile)
        Invoke-TestGit -Repository $Repository -Argument @('checkout', '--quiet', '--detach', $Commit) | Out-Null
        $env:BUILD_SOURCESDIRECTORY = $Repository
        $env:BUILD_SOURCEVERSION = $Commit
        $env:BUILD_REASON = 'IndividualCI'
        $env:BUILD_REPOSITORY_NAME = 'test'
        $env:BUILD_REQUESTEDFOR = 'test'
        $env:BUILD_SOURCEBRANCH = 'refs/heads/feature'
        $env:ASTRULEGENERATOR_CONFIG = $RulesFile
        $logPath = Join-Path $Repository 'pwsh-security-psanalyzer.log'
        if (Test-Path -LiteralPath $logPath) {
            Remove-Item -LiteralPath $logPath
        }
        $null = & $script:PowerShellPath -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Repository 'sec-pwsh-analysis-malicious.ps1') -PSScriptAnalyzerVersion $script:Analyzer.Version.ToString() 2>&1 3>&1 4>&1 6>&1
        $exitCode = $LASTEXITCODE
        $log = ''
        if (Test-Path -LiteralPath $logPath) {
            $log = [System.IO.File]::ReadAllText($logPath)
        }
        [PSCustomObject]@{ ExitCode = $exitCode; Log = $log }
    }

    # The analyser the tests copy into the sample layout; the job is told to require its version.
    $script:Analyzer = Get-Module -Name PSScriptAnalyzer -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
}

AfterAll {
    foreach ($name in $script:SavedEnvironment.Keys) {
        [System.Environment]::SetEnvironmentVariable($name, $script:SavedEnvironment[$name])
    }
}

Describe 'Azure DevOps CI sample script' -Tag Integration {
    BeforeAll {
        $script:Repository = New-TestRepository -Name 'repo'
        $script:WarningCommit = Add-TestCommit -Repository $script:Repository -File @{ 'dated.ps1' = 'Get-Date'; 'notes.txt' = '& not PowerShell' }
        $script:ErrorCommit = Add-TestCommit -Repository $script:Repository -File @{ 'evil.ps1' = '& cmd.exe /c whoami' }
        $script:HarmlessCommit = Add-TestCommit -Repository $script:Repository -File @{ 'later.ps1' = 'Write-Output "later"' }
        $script:ToolCommit = Add-TestCommit -Repository $script:Repository -File @{ 'Security-PWSH-ADO-ci/tool.ps1' = '& cmd.exe /c whoami' }
    }

    It 'passes and still writes the log when the changed PowerShell files have no Error finding' {
        $result = Invoke-TestJob -Repository $script:Repository -Commit $script:WarningCommit

        $result.ExitCode | Should -Be 0
        $result.Log | Should -Match 'Analyzing .*dated\.ps1'
        $result.Log | Should -Match 'dated\.ps1 - Warning : Get-Date calls'
        $result.Log | Should -Not -Match 'Analyzing .*notes\.txt'
    }

    It 'fails with exit code 1 when a changed file has an Error finding' {
        $result = Invoke-TestJob -Repository $script:Repository -Commit $script:ErrorCommit

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'evil\.ps1 - Error : Ampersand calls'
        $result.Log | Should -Match 'Potential PWSH malicious code found'
    }

    It 'still fails when a harmless commit follows the harmful one, since the whole branch is analysed' {
        $result = Invoke-TestJob -Repository $script:Repository -Commit $script:HarmlessCommit

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'evil\.ps1 - Error : Ampersand calls'
    }

    It 'never analyses its own tools folder' {
        $result = Invoke-TestJob -Repository $script:Repository -Commit $script:ToolCommit

        $result.Log | Should -Match 'Analyzing .*later\.ps1'
        $result.Log | Should -Not -Match 'Analyzing .*Security-PWSH-ADO-ci'
    }

    It 'fails when the rule module cannot load, instead of passing with no findings' {
        $result = Invoke-TestJob -Repository $script:Repository -Commit $script:WarningCommit -RulesFile (Join-Path $TestDrive 'no-such-rules.json')

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'error :'
        $result.Log | Should -Not -Match 'Analysis completed with no findings'
    }

    It 'fails when origin/main is not in the checkout, instead of analysing less' {
        $repository = New-TestRepository -Name 'nobase'
        $commit = Add-TestCommit -Repository $repository -File @{ 'dated.ps1' = 'Get-Date' }
        Invoke-TestGit -Repository $repository -Argument @('update-ref', '-d', 'refs/remotes/origin/main') | Out-Null

        $result = Invoke-TestJob -Repository $repository -Commit $commit

        $result.ExitCode | Should -Be 1
        $result.Log | Should -Match 'origin/main is not in the checkout'
    }
}
