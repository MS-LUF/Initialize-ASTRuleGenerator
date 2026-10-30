BeforeDiscovery {
    # At least one case per shipped rule: a script that must raise it, and a close benign script
    # that must not. A pattern added to a rule later gets its own case. Each pair was checked by hand; most benign scripts are the legitimate look-alike
    # the rule must not confuse with the threat.
    # The samples are kept in a data file, not in this script: as code they would be flagged by
    # the security analysis of every commit, and blocked by antivirus software that scans scripts.
    $caseFile = Join-Path $PSScriptRoot '../Samples/ShippedRuleCases.json'
    $script:RuleCase = @(foreach ($case in (ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($caseFile)))) {
            @{ Rule = $case.Rule; Positive = $case.Positive; Negative = $case.Negative }
        })

    # The corpus test reads every PowerShell file of the installed modules: slow, and its result
    # depends on the machine, so it only runs when asked for.
    $script:RunCorpus = $env:ASTRULEGENERATOR_CORPUS -eq '1'
}

BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:SavedOverride = $env:ASTRULEGENERATOR_CONFIG
    $env:ASTRULEGENERATOR_CONFIG = $null
    Import-Module PSScriptAnalyzer
    Import-Module (Join-Path $script:RepoRoot 'Initialize-ASTRuleGenerator.psd1') -Force
    $script:ShippedRule = @((Get-Content -Path (Join-Path $script:RepoRoot 'Initialize-ASTRuleGenerator.json') -Raw | ConvertFrom-Json).rules)

    function Get-ShippedFinding {
        param([string] $Script)
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($Script, [ref] $null, [ref] $null)
        @(Measure-CustomASTRule -ScriptBlockAst $ast 2>&1)
    }
}

AfterAll {
    $env:ASTRULEGENERATOR_CONFIG = $script:SavedOverride
}

Describe 'Shipped rules file' -Tag Unit {
    It 'loads every rule without error, all enabled, with unique names' {
        $output = Get-ShippedFinding -Script 'Get-Date'

        @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) | Should -BeNullOrEmpty
        @($script:ShippedRule | Where-Object { $_.Status -ne 'Enable' }) | Should -BeNullOrEmpty
        @($script:ShippedRule.Name | Sort-Object -Unique).Count | Should -Be $script:ShippedRule.Count
    }

    It 'names an ATT&CK technique in every rule message' {
        @($script:ShippedRule | Where-Object { $_.Message -notmatch '\(ATT&CK T\d{4}(\.\d{3})?(, T\d{4}(\.\d{3})?)*\)$' }).Name | Should -BeNullOrEmpty
    }

    It 'keeps the Error severity for the rules with no false positive measured' {
        $errorRule = @($script:ShippedRule | Where-Object { $_.Severity -eq 'error' } | ForEach-Object { $_.Name } | Sort-Object)
        $expected = @(
            'AMSI tampering', 'Characters picked from well-known variables', 'Credential dumping', 'Credential dumping command',
            'Defender tampering', 'Downloaded code run', 'Encoded command', 'Logs or history cleared', 'PowerShell 2 downgrade',
            'PowerShell logging tampering', 'Recovery inhibited', 'WMI event subscription'
        ) | Sort-Object

        $errorRule | Should -Be $expected
    }

    # The case table is built during discovery, so its rule names are handed over as test data.
    It 'has a test case for every shipped rule' -TestCases @(@{ Tested = @($script:RuleCase | ForEach-Object { $_.Rule }) }) {
        $tested = $Tested

        @($script:ShippedRule.Name | Where-Object { $tested -notcontains $_ }) | Should -BeNullOrEmpty
        @($tested | Where-Object { $script:ShippedRule.Name -notcontains $_ }) | Should -BeNullOrEmpty
    }
}

Describe 'Shipped rule <Rule>' -Tag Unit -ForEach $script:RuleCase {
    It 'is raised by the threat it describes' {
        $output = Get-ShippedFinding -Script $Positive

        @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) | Should -BeNullOrEmpty
        @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] -and $_.RuleName -eq $Rule }).Count | Should -BeGreaterThan 0
    }

    It 'is not raised by the benign look-alike' {
        $output = Get-ShippedFinding -Script $Negative

        @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] -and $_.RuleName -eq $Rule }) | Should -BeNullOrEmpty
    }
}

Describe 'Shipped rules on the installed modules' -Tag Corpus -Skip:(-not $script:RunCorpus) {
    It 'raise no Error finding on the PowerShell files of the modules installed on this machine' {
        $root = @($env:PSModulePath -split [System.IO.Path]::PathSeparator) + (Join-Path $PSHOME 'Modules') |
            Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Sort-Object -Unique
        $file = @(Get-ChildItem -Path $root -Recurse -File -Include '*.ps1', '*.psm1' -ErrorAction SilentlyContinue | Sort-Object FullName -Unique)
        $errorFinding = foreach ($item in $file) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($item.FullName, [ref] $null, [ref] $null)
            Measure-CustomASTRule -ScriptBlockAst $ast 2>$null | Where-Object { "$($_.Severity)" -eq 'Error' } |
                ForEach-Object { "$($item.FullName) line $($_.Extent.StartLineNumber): $($_.RuleName)" }
        }

        $file.Count | Should -BeGreaterThan 0
        $errorFinding | Should -BeNullOrEmpty -Because "legitimate modules must not fail a CI job: $($errorFinding -join '; ')"
    }
}
