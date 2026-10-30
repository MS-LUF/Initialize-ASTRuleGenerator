BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:ShippedManifest = Join-Path $script:RepoRoot 'Initialize-ASTRuleGenerator.psd1'

    # The module reads its rules from the file this variable names, when it is set. The tests set
    # it themselves; a value from the machine running them must not leak in.
    $script:SavedOverride = $env:ASTRULEGENERATOR_CONFIG
    $env:ASTRULEGENERATOR_CONFIG = $null

    # Builds a copy of the module in the TestDrive: with the shipped JSON, with every shipped rule
    # enabled or disabled, with given rules, or with no JSON at all.
    function New-TestModuleCopy {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that only writes into the Pester TestDrive.')]
        param([string] $Destination, [switch] $EnableAllRules, [switch] $DisableAllRules, [switch] $WithoutConfig, [object[]] $Rule, [object] $AllowList, [object] $EncodingCheck)
        $moduleFolder = Join-Path $Destination 'Initialize-ASTRuleGenerator'
        New-Item -ItemType Directory -Path $moduleFolder -Force | Out-Null
        Copy-Item -Path (Join-Path $script:RepoRoot 'Initialize-ASTRuleGenerator.psd1') -Destination $moduleFolder
        Copy-Item -Path (Join-Path $script:RepoRoot 'Initialize-ASTRuleGenerator.psm1') -Destination $moduleFolder
        Copy-Item -Path (Join-Path $script:RepoRoot 'Public') -Destination $moduleFolder -Recurse
        Copy-Item -Path (Join-Path $script:RepoRoot 'Private') -Destination $moduleFolder -Recurse
        if ($Rule) {
            # Given rules replace the shipped ones; ConvertTo-Json keeps any quote or backslash
            # in them valid JSON.
            $content = @{ rules = $Rule }
            if ($null -ne $AllowList) {
                $content.allowlist = $AllowList
            }
            if ($null -ne $EncodingCheck) {
                $content.encodingcheck = $EncodingCheck
            }
            Set-Content -Path (Join-Path $moduleFolder 'Initialize-ASTRuleGenerator.json') -Value (ConvertTo-Json -InputObject $content -Depth 5)
        } elseif (-not $WithoutConfig) {
            $json = Get-Content -Path (Join-Path $script:RepoRoot 'Initialize-ASTRuleGenerator.json') -Raw
            if ($EnableAllRules) {
                $json = $json -replace '"Status"\s*:\s*"Disable"', '"Status" : "Enable"'
            }
            if ($DisableAllRules) {
                $json = $json -replace '"Status"\s*:\s*"Enable"', '"Status" : "Disable"'
            }
            Set-Content -Path (Join-Path $moduleFolder 'Initialize-ASTRuleGenerator.json') -Value $json
        }
        Join-Path $moduleFolder 'Initialize-ASTRuleGenerator.psd1'
    }

    # One line per finding the sample script must raise with the shipped rules, as
    # "line|severity|rule name|message". Recorded on v0.9.0 under Windows PowerShell 5.1 and
    # PowerShell 7 with PSScriptAnalyzer 1.25.0, and checked line by line: it is the reference a
    # change to rule evaluation or to the shipped rules must still meet. (Before v0.9.0 the
    # reference was taken on the former sample rules, which v0.9.0 replaced; the
    # Invoke-Expression rule, added in the same version, contributes the second line-2 warning.)
    # The last line of the sample is benign and must raise nothing.
    # Both are kept in data files, not in this script: as code, the attack sample would be
    # flagged by the security analysis of every commit, and blocked by antivirus software.
    $sampleFolder = Join-Path $script:RepoRoot 'Tests/Samples'
    $script:SampleScript = [System.IO.File]::ReadAllText((Join-Path $sampleFolder 'BaselineSample.txt')).TrimEnd("`r", "`n")
    $script:ExpectedFinding = [System.IO.File]::ReadAllText((Join-Path $sampleFolder 'BaselineFinding.txt')).TrimEnd("`r", "`n") -split '\r?\n'

    function ConvertTo-FindingLine {
        param([object[]] $Record)
        $Record | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Extent.StartLineNumber, $_.Severity, $_.RuleName, $_.Message } | Sort-Object
    }

    Import-Module PSScriptAnalyzer
    $script:EnabledManifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'enabled') -EnableAllRules
    $script:SamplePath = Join-Path $TestDrive 'sample.ps1'
    Set-Content -Path $script:SamplePath -Value $script:SampleScript
    $script:JsonRuleName = @((Get-Content -Path (Join-Path $script:RepoRoot 'Initialize-ASTRuleGenerator.json') -Raw | ConvertFrom-Json).rules | ForEach-Object { $_.Name })
}

AfterAll {
    Remove-Module Initialize-ASTRuleGenerator -Force -ErrorAction SilentlyContinue
    $env:ASTRULEGENERATOR_CONFIG = $script:SavedOverride
}

Describe 'Measure-CustomASTRule baseline' -Tag Unit {
    It 'returns the reference findings when called directly with the sample script AST' {
        Import-Module $script:EnabledManifest -Force
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:SampleScript, [ref] $null, [ref] $null)

        $result = Measure-CustomASTRule -ScriptBlockAst $ast

        ConvertTo-FindingLine -Record $result | Should -Be ($script:ExpectedFinding | Sort-Object)
    }

    It 'returns nothing when every rule is disabled' {
        Import-Module (New-TestModuleCopy -Destination (Join-Path $TestDrive 'disabled') -DisableAllRules) -Force
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:SampleScript, [ref] $null, [ref] $null)

        Measure-CustomASTRule -ScriptBlockAst $ast | Should -BeNullOrEmpty
    }

    It 'returns the same findings with the module as shipped, whose rules are all enabled' {
        Import-Module $script:ShippedManifest -Force
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:SampleScript, [ref] $null, [ref] $null)

        ConvertTo-FindingLine -Record (Measure-CustomASTRule -ScriptBlockAst $ast) | Should -Be ($script:ExpectedFinding | Sort-Object)
    }

    It 'exports Measure-CustomASTRule only, since PSScriptAnalyzer treats every exported function as a rule' {
        $module = Import-Module $script:ShippedManifest -Force -PassThru

        @($module.ExportedCommands.Keys) | Should -Be @('Measure-CustomASTRule')
    }

    It 'fails to import with a clear message when the JSON is missing from the module folder' {
        $manifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'noconfig') -WithoutConfig

        { Import-Module $manifest -Force -ErrorAction Stop } | Should -Throw '*configuration file Initialize-ASTRuleGenerator.json missing in module folder*'
    }
}

Describe 'Measure-CustomASTRule through PSScriptAnalyzer' -Tag Integration {
    It 'raises the reference findings through Invoke-ScriptAnalyzer -CustomRulePath' {
        $result = Invoke-ScriptAnalyzer -Path $script:SamplePath -CustomRulePath $script:EnabledManifest |
            Where-Object { $script:JsonRuleName -contains $_.RuleName }

        ConvertTo-FindingLine -Record $result | Should -Be ($script:ExpectedFinding | Sort-Object)
    }

    It 'raises no finding on a benign script with the shipped rules' {
        $benignPath = Join-Path $TestDrive 'benign.ps1'
        Set-Content -Path $benignPath -Value 'Get-ChildItem -Path $env:TEMP | Where-Object { $_.Length -gt 1KB } | Select-Object -First 1'

        $result = Invoke-ScriptAnalyzer -Path $benignPath -CustomRulePath $script:ShippedManifest |
            Where-Object { $script:JsonRuleName -contains $_.RuleName }

        $result | Should -BeNullOrEmpty
    }

    It 'is listed by PSScriptAnalyzer as one rule named after the function, with its help description' {
        $rule = @(Get-ScriptAnalyzerRule -CustomRulePath $script:ShippedManifest | Where-Object { $_.SourceType -ne 'Builtin' })

        $rule.Count | Should -Be 1
        $rule[0].RuleName | Should -Be 'Measure-CustomASTRule'
        $rule[0].SourceName | Should -Be 'Initialize-ASTRuleGenerator'
        $rule[0].Description | Should -BeLike 'Runs the simple rules declared in a JSON rules file*'
    }
}

Describe 'Measure-CustomASTRule treats rule values as data' -Tag Unit {
    BeforeAll {
        function New-TestRule {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that only builds an in-memory rule.')]
            param([hashtable] $Override)
            $rule = @{
                Status              = 'Enable'
                Name                = 'Test rule'
                ASTType             = 'StringConstantExpressionAst'
                ASTProperty         = 'Value'
                Operator            = 'like'
                SearchStringPattern = @('*nothing-matches-this*')
                Message             = 'Test rule'
                Severity            = 'warning'
            }
            foreach ($key in $Override.Keys) {
                $rule[$key] = $Override[$key]
                if ($key -eq 'SearchOtherPattern') {
                    $rule.Remove('SearchStringPattern')
                }
            }
            $rule
        }

        # A valid rule run next to the rule under test, to show the other rules still run.
        $script:AmpersandRule = @{
            Status              = 'Enable'
            Name                = 'Ampersand calls'
            ASTType             = 'CommandAst'
            ASTProperty         = 'InvocationOperator'
            Operator            = 'eq'
            SearchStringPattern = @('Ampersand')
            Message             = 'Ampersand call'
            Severity            = 'warning'
        }

        function Invoke-TestRule {
            param([object[]] $Rule, [string] $Script, [string] $Name)
            $manifest = New-TestModuleCopy -Destination (Join-Path $TestDrive $Name) -Rule $Rule
            Import-Module $manifest -Force
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($Script, [ref] $null, [ref] $null)
            $output = @(Measure-CustomASTRule -ScriptBlockAst $ast 2>&1)
            [PSCustomObject]@{
                Record = @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
                Error  = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
            }
        }
    }

    It 'never runs a payload placed in <Field>, and <Outcome>' -ForEach @(
        @{ Field = 'SearchStringPattern'; Template = '$({0})'; Valid = $true; Outcome = 'compares it as text' }
        @{ Field = 'SearchStringPattern'; Template = '"; {0}; "'; Valid = $true; Outcome = 'compares it as text' }
        @{ Field = 'SearchOtherPattern'; Template = '$({0})'; Valid = $true; Outcome = 'compares it as a value' }
        @{ Field = 'ASTProperty'; Template = 'Value; {0}'; Valid = $false; Outcome = 'skips the rule' }
        @{ Field = 'Operator'; Template = 'eq "x") -or ($({0})'; Valid = $false; Outcome = 'skips the rule' }
        @{ Field = 'ASTType'; Template = 'StringConstantExpressionAst]) -or ($({0})) -or ([string'; Valid = $false; Outcome = 'skips the rule' }
    ) {
        $id = [guid]::NewGuid().ToString('N')
        $marker = Join-Path $TestDrive "injected-$id.txt"
        $payload = $Template -f "Set-Content -LiteralPath '$marker' -Value injected"
        $value = $payload
        if ($Field -like 'Search*') {
            $value = @($payload)
        }
        $evilRule = New-TestRule -Override @{ $Field = $value }

        $result = Invoke-TestRule -Rule @($evilRule, $script:AmpersandRule) -Script $script:SampleScript -Name "inject-$id"

        Test-Path -LiteralPath $marker | Should -BeFalse
        @($result.Record | Where-Object { $_.RuleName -eq 'Ampersand calls' }).Count | Should -Be 1
        if ($Valid) {
            $result.Error | Should -BeNullOrEmpty
        } else {
            $result.Error.Count | Should -Be 1
            $result.Error[0].FullyQualifiedErrorId | Should -BeLike 'InvalidRule*'
            $result.Error[0].Exception.Message | Should -BeLike "*rule 'Test rule' skipped*"
        }
    }

    It 'compares a code-like SearchOtherPattern value as the text it is' {
        # Before rule values were treated as data, this pattern became the code $true and matched
        # every non-empty string.
        $rule = New-TestRule -Override @{ Operator = 'eq'; SearchOtherPattern = @('$true') }
        $script = '$a = ''$true''' + [Environment]::NewLine + '$b = ''something else'''

        $result = Invoke-TestRule -Rule @($rule) -Script $script -Name 'code-like-pattern'

        $result.Error | Should -BeNullOrEmpty
        $result.Record.Count | Should -Be 1
        $result.Record[0].Extent.Text | Should -Be '''$true'''
    }

    It 'reports a rule that fails on some nodes once, counts those nodes as not matching, and keeps the other rules' {
        # An extent cannot be compared with a number, so the comparison fails on every command.
        $rule = New-TestRule -Override @{ ASTType = 'CommandAst'; ASTProperty = 'Extent'; Operator = 'gt'; SearchOtherPattern = @(5) }
        $script = '& cmd.exe /c echo 1' + [Environment]::NewLine + '& cmd.exe /c echo 2'

        $result = Invoke-TestRule -Rule @($rule, $script:AmpersandRule) -Script $script -Name 'evaluation-error'

        $result.Error.Count | Should -Be 1
        $result.Error[0].FullyQualifiedErrorId | Should -BeLike 'RuleEvaluationFailed*'
        @($result.Record | Where-Object { $_.RuleName -eq 'Test rule' }).Count | Should -Be 0
        @($result.Record | Where-Object { $_.RuleName -eq 'Ampersand calls' }).Count | Should -Be 2
    }

    It 'does not match a node whose property is missing when the rule compares text' {
        # Before rule values were treated as data, a missing property stopped the whole analysis.
        $rule = New-TestRule -Override @{ ASTProperty = 'NoSuchProperty'; Operator = 'notlike'; SearchStringPattern = @('*x*') }

        $result = Invoke-TestRule -Rule @($rule, $script:AmpersandRule) -Script $script:SampleScript -Name 'missing-property'

        $result.Error | Should -BeNullOrEmpty
        @($result.Record | Where-Object { $_.RuleName -eq 'Test rule' }).Count | Should -Be 0
        @($result.Record | Where-Object { $_.RuleName -eq 'Ampersand calls' }).Count | Should -Be 1
    }
}

Describe 'Measure-CustomASTRule reports invalid rules through PSScriptAnalyzer' -Tag Integration {
    It 'reports an invalid rule as a non-terminating error once per analysed file, and keeps the other findings' {
        $badRule = @{
            Status = 'Enable'; Name = 'Bad operator'; ASTType = 'CommandAst'; ASTProperty = 'InvocationOperator'
            Operator = 'bogus'; SearchStringPattern = @('Ampersand'); Message = 'x'; Severity = 'warning'
        }
        $goodRule = @{
            Status = 'Enable'; Name = 'Ampersand calls'; ASTType = 'CommandAst'; ASTProperty = 'InvocationOperator'
            Operator = 'eq'; SearchStringPattern = @('Ampersand'); Message = 'Ampersand call'; Severity = 'warning'
        }
        $manifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'invalid-through-pssa') -Rule @($badRule, $goodRule)
        $scriptFolder = Join-Path $TestDrive 'invalid-through-pssa-scripts'
        New-Item -ItemType Directory -Path $scriptFolder -Force | Out-Null
        Set-Content -Path (Join-Path $scriptFolder 'one.ps1') -Value '& cmd.exe /c echo 1'
        Set-Content -Path (Join-Path $scriptFolder 'two.ps1') -Value '& cmd.exe /c echo 2'

        $output = @(Invoke-ScriptAnalyzer -Path $scriptFolder -CustomRulePath $manifest 2>&1)

        # PSScriptAnalyzer does not keep the rule module's state between files, so the invalid
        # rule is reported for each of the two files.
        $errors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $errors.Count | Should -Be 2
        $errors | ForEach-Object { $_.Exception.Message | Should -BeLike "*rule 'Bad operator' skipped*" }
        @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] -and $_.RuleName -eq 'Ampersand calls' }).Count | Should -Be 2
    }
}

Describe 'Measure-CustomASTRule with rules from ASTRULEGENERATOR_CONFIG' -Tag Unit {
    BeforeAll {
        # A module copy with the shipped JSON, every rule disabled: a finding can only come from
        # the override file.
        $script:OverrideManifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'override-module')
        $script:OverridePath = Join-Path $TestDrive 'override-rules.json'
        $overrideRule = @{
            Status = 'Enable'; Name = 'Override ampersand'; ASTType = 'CommandAst'; ASTProperty = 'InvocationOperator'
            Operator = 'eq'; SearchStringPattern = @('Ampersand'); Message = 'From the override file'; Severity = 'error'
        }
        Set-Content -Path $script:OverridePath -Value (ConvertTo-Json -InputObject @{ rules = @($overrideRule) } -Depth 5)
    }

    AfterEach {
        $env:ASTRULEGENERATOR_CONFIG = $null
    }

    It 'uses the rules of the file the variable names, instead of the module folder' {
        $env:ASTRULEGENERATOR_CONFIG = $script:OverridePath
        Import-Module $script:OverrideManifest -Force
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:SampleScript, [ref] $null, [ref] $null)

        $result = @(Measure-CustomASTRule -ScriptBlockAst $ast)

        $result.Count | Should -Be 1
        $result[0].RuleName | Should -Be 'Override ampersand'
        # The sample's only "&" call is on line 6.
        $result[0].Extent.StartLineNumber | Should -Be 6
    }

    It 'fails to import when the variable names <Case>' -ForEach @(
        @{ Case = 'a missing file'; Value = 'missing'; Message = '*set by ASTRULEGENERATOR_CONFIG not found*' }
        @{ Case = 'a relative path'; Value = 'override-rules.json'; Message = '*ASTRULEGENERATOR_CONFIG must hold an absolute path*' }
    ) {
        if ($Value -eq 'missing') {
            $Value = Join-Path $TestDrive 'no-such-rules.json'
        }
        $env:ASTRULEGENERATOR_CONFIG = $Value

        { Import-Module $script:OverrideManifest -Force -ErrorAction Stop } | Should -Throw $Message
    }
}

Describe 'Measure-CustomASTRule with ASTRULEGENERATOR_CONFIG through PSScriptAnalyzer' -Tag Integration {
    BeforeAll {
        $script:PssaOverrideManifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'pssa-override-module')
        $script:PssaOverridePath = Join-Path $TestDrive 'pssa-override-rules.json'
        $overrideRule = @{
            Status = 'Enable'; Name = 'Override ampersand'; ASTType = 'CommandAst'; ASTProperty = 'InvocationOperator'
            Operator = 'eq'; SearchStringPattern = @('Ampersand'); Message = 'From the override file'; Severity = 'error'
        }
        Set-Content -Path $script:PssaOverridePath -Value (ConvertTo-Json -InputObject @{ rules = @($overrideRule) } -Depth 5)
    }

    AfterEach {
        $env:ASTRULEGENERATOR_CONFIG = $null
    }

    It 'reaches the module in the runspaces PSScriptAnalyzer creates' {
        $env:ASTRULEGENERATOR_CONFIG = $script:PssaOverridePath

        $result = @(Invoke-ScriptAnalyzer -Path $script:SamplePath -CustomRulePath $script:PssaOverrideManifest |
                Where-Object { $_.RuleName -eq 'Override ampersand' })

        $result.Count | Should -Be 1
        "$($result[0].Severity)" | Should -Be 'Error'
    }

    It 'stops the analysis when the file it names is missing, instead of using other rules' {
        # PSScriptAnalyzer does not show the module's own message; it stops. Version 1.25.0 reports
        # that it found no rules, 1.20.0 (bundled for the CI container) throws a bare exception.
        # Importing the module directly shows the reason.
        $env:ASTRULEGENERATOR_CONFIG = Join-Path $TestDrive 'no-such-rules.json'

        $failure = $null
        try {
            Invoke-ScriptAnalyzer -Path $script:SamplePath -CustomRulePath $script:PssaOverrideManifest -WarningAction SilentlyContinue -ErrorAction Stop
        } catch {
            $failure = $_
        }
        $failure | Should -Not -BeNullOrEmpty -Because 'the analysis must stop rather than run without the rules'
        $failure.Exception.Message | Should -Match "Cannot find ScriptAnalyzer rules|^Exception of type 'System\.Exception' was thrown\.$"
    }
}

Describe 'Measure-CustomASTRule reports each finding once' {
    BeforeAll {
        $script:OnceManifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'once-module')
        $script:OnceRule = @{
            Status = 'Enable'; Name = 'Once ampersand'; ASTType = 'CommandAst'; ASTProperty = 'InvocationOperator'
            Operator = 'eq'; SearchStringPattern = @('Ampersand'); Message = 'Ampersand call'; Severity = 'error'
        }
        $script:OnceRulesPath = Join-Path $TestDrive 'once-rules.json'
        Set-Content -Path $script:OnceRulesPath -Value (ConvertTo-Json -InputObject @{ rules = @($script:OnceRule) } -Depth 5)
    }

    AfterEach {
        $env:ASTRULEGENERATOR_CONFIG = $null
    }

    It 'gives one finding through PSScriptAnalyzer when the code is <Name>' -Tag Integration -ForEach @(
        @{ Name = 'at the top level'; Code = '& cmd.exe' }
        @{ Name = 'in a function'; Code = "function F {`n & cmd.exe`n}" }
        @{ Name = 'in a nested function'; Code = "function F {`n function G {`n & cmd.exe`n }`n}" }
        @{ Name = 'in a function and a script block'; Code = "function F {`n . {`n & cmd.exe`n }`n}" }
    ) {
        $env:ASTRULEGENERATOR_CONFIG = $script:OnceRulesPath
        $path = Join-Path $TestDrive 'once-sample.ps1'
        Set-Content -Path $path -Value $Code

        $result = @(Invoke-ScriptAnalyzer -Path $path -CustomRulePath $script:OnceManifest | Where-Object { $_.RuleName -eq 'Once ampersand' })

        $result.Count | Should -Be 1
    }

    It 'gives one allow-list finding through PSScriptAnalyzer for a file with nested script blocks' -Tag Integration {
        $rulesPath = Join-Path $TestDrive 'once-allowlist-rules.json'
        Set-Content -Path $rulesPath -Value (ConvertTo-Json -InputObject @{ rules = @($script:OnceRule); allowlist = @{ FileNamePattern = @('once-listed*.ps1') } } -Depth 5)
        $env:ASTRULEGENERATOR_CONFIG = $rulesPath
        $path = Join-Path $TestDrive 'once-listed.ps1'
        Set-Content -Path $path -Value "function F {`n . { 1 }`n}"

        $result = @(Invoke-ScriptAnalyzer -Path $path -CustomRulePath $script:OnceManifest | Where-Object { $_.RuleName -eq 'Allow-list' })

        $result.Count | Should -Be 1
    }

    It 'returns nothing for a nested script block given directly, since the outermost one covers it' -Tag Unit {
        $env:ASTRULEGENERATOR_CONFIG = $script:OnceRulesPath
        Import-Module $script:OnceManifest -Force
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput("function F {`n & cmd.exe`n}", [ref]$tokens, [ref]$errors)
        $nested = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.ScriptBlockAst] -and $null -ne $node.Parent }, $true)

        @(Measure-CustomASTRule -ScriptBlockAst $ast).Count | Should -Be 1
        @(Measure-CustomASTRule -ScriptBlockAst $nested).Count | Should -Be 0
        Remove-Module Initialize-ASTRuleGenerator -Force
    }

    It 'keeps a finding suppressed in the analysed file available through -SuppressedOnly' -Tag Integration {
        # The CI samples rely on this: a scanned file must not be able to hide its own findings.
        $env:ASTRULEGENERATOR_CONFIG = $script:OnceRulesPath
        $path = Join-Path $TestDrive 'once-suppressed.ps1'
        Set-Content -Path $path -Value "function F {`n [Diagnostics.CodeAnalysis.SuppressMessageAttribute('Once ampersand', '')]`n param()`n & cmd.exe`n}"

        $visible = @(Invoke-ScriptAnalyzer -Path $path -CustomRulePath $script:OnceManifest | Where-Object { $_.RuleName -eq 'Once ampersand' })
        $suppressed = @(Invoke-ScriptAnalyzer -Path $path -CustomRulePath $script:OnceManifest -SuppressedOnly | Where-Object { $_.RuleName -eq 'Once ampersand' })

        $visible.Count | Should -Be 0
        $suppressed.Count | Should -Be 1
        "$($suppressed[0].Severity)" | Should -Be 'Error'
    }
}

Describe 'Measure-CustomASTRule with MinimumCount' -Tag Unit {
    BeforeAll {
        # Three matches in all, from two patterns of the same rule.
        $script:CountRule = @{
            Status = 'Enable'; Name = 'Counted strings'; ASTType = 'StringConstantExpressionAst'; ASTProperty = 'Value'
            Operator = 'eq'; SearchStringPattern = @('alpha', 'beta'); Message = 'Counted string'; Severity = 'warning'
        }
        $script:CountScript = '$a = ''alpha''; $b = ''beta''; $c = ''alpha''; $d = ''gamma'''

        function Get-CountFinding {
            param([object] $MinimumCount)
            $rule = $script:CountRule.Clone()
            if ($null -ne $MinimumCount) {
                $rule.MinimumCount = $MinimumCount
            }
            $manifest = New-TestModuleCopy -Destination (Join-Path $TestDrive "count-$([guid]::NewGuid().ToString('N'))") -Rule @($rule)
            Import-Module $manifest -Force
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:CountScript, [ref] $null, [ref] $null)
            @(Measure-CustomASTRule -ScriptBlockAst $ast)
        }
    }

    It 'reports every match when MinimumCount is <MinimumCount>, counting all patterns of the rule' -ForEach @(
        @{ MinimumCount = $null }
        @{ MinimumCount = 1 }
        @{ MinimumCount = 3 }
    ) {
        $result = Get-CountFinding -MinimumCount $MinimumCount

        $result.Count | Should -Be 3
        @($result | Where-Object { $_.Message -eq 'Counted string : alpha' }).Count | Should -Be 2
    }

    It 'reports nothing when the script holds fewer matches than MinimumCount' {
        Get-CountFinding -MinimumCount 4 | Should -BeNullOrEmpty
    }
}

Describe 'Measure-CustomASTRule with an allow-list' {
    BeforeAll {
        $script:AllowRule = @{
            Status = 'Enable'; Name = 'Ampersand calls'; ASTType = 'CommandAst'; ASTProperty = 'InvocationOperator'
            Operator = 'eq'; SearchStringPattern = @('Ampersand'); Message = 'Ampersand call'; Severity = 'warning'
        }
        # Three files with the same flagged content: one listed by name, one by hash, one not
        # listed. The hashed file differs by a comment, so its hash is its own.
        $script:AllowFolder = Join-Path $TestDrive 'allow-scripts'
        New-Item -ItemType Directory -Path $script:AllowFolder -Force | Out-Null
        $script:NamedFile = Join-Path $script:AllowFolder 'Build-Tools.ps1'
        $script:HashedFile = Join-Path $script:AllowFolder 'hashed.ps1'
        $script:NormalFile = Join-Path $script:AllowFolder 'normal.ps1'
        Set-Content -Path $script:NamedFile -Value '& cmd.exe /c echo named'
        Set-Content -Path $script:HashedFile -Value ('& cmd.exe /c echo hashed' + [Environment]::NewLine + '# reviewed')
        Set-Content -Path $script:NormalFile -Value '& cmd.exe /c echo normal'
        $script:HashedFileHash = (Get-FileHash -LiteralPath $script:HashedFile -Algorithm SHA256).Hash

        $script:AllowManifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'allow-module') -Rule @($script:AllowRule) -AllowList @{
            FileNamePattern = @('build-*.PS1')
            Sha256          = @($script:HashedFileHash.ToLowerInvariant())
        }

        function Get-FileFinding {
            param([string] $Path)
            Import-Module $script:AllowManifest -Force
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $null, [ref] $null)
            @(Measure-CustomASTRule -ScriptBlockAst $ast)
        }
    }

    It 'skips a file whose name matches a pattern, leaving one Warning finding' -Tag Unit {
        $result = Get-FileFinding -Path $script:NamedFile

        $result.Count | Should -Be 1
        $result[0].RuleName | Should -Be 'Allow-list'
        "$($result[0].Severity)" | Should -Be 'Warning'
        $result[0].Message | Should -Be "File skipped by the allow-list (file name pattern 'build-*.PS1')"
    }

    It 'skips a file whose SHA-256 is listed, leaving one Warning finding' -Tag Unit {
        $result = Get-FileFinding -Path $script:HashedFile

        $result.Count | Should -Be 1
        $result[0].RuleName | Should -Be 'Allow-list'
        $result[0].Message | Should -Be "File skipped by the allow-list (SHA-256 $($script:HashedFileHash))"
    }

    It 'scans a file that is not listed' -Tag Unit {
        $result = Get-FileFinding -Path $script:NormalFile

        @($result | Where-Object { $_.RuleName -eq 'Allow-list' }) | Should -BeNullOrEmpty
        @($result | Where-Object { $_.RuleName -eq 'Ampersand calls' }).Count | Should -Be 1
    }

    It 'always scans a script given as a string, which has no file' -Tag Unit {
        Import-Module $script:AllowManifest -Force
        $ast = [System.Management.Automation.Language.Parser]::ParseInput((Get-Content -Path $script:NamedFile -Raw), [ref] $null, [ref] $null)

        $result = @(Measure-CustomASTRule -ScriptBlockAst $ast)

        @($result | Where-Object { $_.RuleName -eq 'Ampersand calls' }).Count | Should -Be 1
        @($result | Where-Object { $_.RuleName -eq 'Allow-list' }) | Should -BeNullOrEmpty
    }

    It 'refuses to load when the allow-list is invalid' -Tag Unit {
        $manifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'allow-invalid') -Rule @($script:AllowRule) -AllowList @{ FileNamePattern = @('Vendor\*.ps1') }

        { Import-Module $manifest -Force -ErrorAction Stop } |
            Should -Throw "*has an invalid allowlist: allowlist FileNamePattern 'Vendor\*.ps1' must be a file name pattern, without a path*"
    }

    It 'skips the listed files through Invoke-ScriptAnalyzer -Path, and scans the others' -Tag Integration {
        $result = @(Invoke-ScriptAnalyzer -Path $script:AllowFolder -CustomRulePath $script:AllowManifest)

        $byFile = @{}
        $result | Group-Object -Property ScriptName | ForEach-Object { $byFile[$_.Name] = @($_.Group | ForEach-Object { $_.RuleName }) }
        $byFile['Build-Tools.ps1'] | Should -Be @('Allow-list')
        $byFile['hashed.ps1'] | Should -Be @('Allow-list')
        $byFile['normal.ps1'] | Should -Be @('Ampersand calls')
    }
}

Describe 'Measure-CustomASTRule with the encoding check' {
    BeforeDiscovery {
        # Through Invoke-ScriptAnalyzer the module runs in its own runspace, where no mock reaches
        # it, so the real ANSI code page is used. The samples are built for code page 1252.
        $script:AnsiIs1252 = [System.Text.Encoding]::GetEncoding(0).CodePage -eq 1252
    }

    BeforeAll {
        $script:EncodingRule = @{
            Status = 'Enable'; Name = 'Expression calls'; ASTType = 'CommandAst'; ASTProperty = 'Extent.Text'
            Operator = 'match'; SearchStringPattern = @('^Invoke-Expression'); Message = 'Invoke-Expression call'; Severity = 'warning'
        }
        $script:EncodingMessage = 'File read as different code by Windows PowerShell 5.1 (code page 1252) and PowerShell 7 (UTF-8): save it as UTF-8 with a byte order mark (ATT&CK T1027)'

        # Without a byte order mark, Windows PowerShell 5.1 reads line 2 as part of a string: the
        # arrow's bytes, read as code page 1252, end with a curly quote. The arrow is built from its
        # code point so this test file stays ASCII.
        $arrow = [string][char]0x2192
        $hiding = "Write-Output 'a $arrow b'`r`nInvoke-Expression `$payload`r`nWrite-Output 'c $arrow d'`r`n"
        $script:EncodingFolder = Join-Path $TestDrive 'encoding-scripts'
        New-Item -ItemType Directory -Path $script:EncodingFolder -Force | Out-Null
        $script:AmbiguousFile = Join-Path $script:EncodingFolder 'ambiguous.ps1'
        $script:BomFile = Join-Path $script:EncodingFolder 'with-bom.ps1'
        [System.IO.File]::WriteAllText($script:AmbiguousFile, $hiding, [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText($script:BomFile, $hiding, [System.Text.UTF8Encoding]::new($true))

        $script:EncodingManifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'encoding-module') -Rule @($script:EncodingRule)
        $script:NoEncodingManifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'encoding-off') -Rule @($script:EncodingRule) -EncodingCheck 'Disable'

        # Imports the module alone (Mock needs a single copy loaded), fixes its ANSI code page to
        # 1252, then runs the rule on the file.
        function Get-EncodingFinding {
            param([string] $Manifest, [string] $Path)
            Remove-Module Initialize-ASTRuleGenerator -Force -ErrorAction SilentlyContinue
            Import-Module $Manifest -Force
            Mock -ModuleName 'Initialize-ASTRuleGenerator' Get-ASTRuleGeneratorAnsiEncoding { [System.Text.Encoding]::GetEncoding(1252) }
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $null, [ref] $null)
            @(Measure-CustomASTRule -ScriptBlockAst $ast)
        }
    }

    It 'raises one Error finding for a file read as different code, and still runs the rules' -Tag Unit {
        $result = Get-EncodingFinding -Manifest $script:EncodingManifest -Path $script:AmbiguousFile

        $encoding = @($result | Where-Object { $_.RuleName -eq 'Ambiguous file encoding' })
        $encoding.Count | Should -Be 1
        "$($encoding[0].Severity)" | Should -Be 'Error'
        $encoding[0].Message | Should -Be $script:EncodingMessage
        $encoding[0].Extent.StartLineNumber | Should -Be 1
        # Which edition parsed the file decides whether line 2 is code; under 7 it is.
        if ($PSVersionTable.PSEdition -eq 'Core') {
            @($result | Where-Object { $_.RuleName -eq 'Expression calls' }).Count | Should -Be 1
        }
    }

    It 'raises nothing for the same file with a byte order mark' -Tag Unit {
        $result = Get-EncodingFinding -Manifest $script:EncodingManifest -Path $script:BomFile

        @($result | Where-Object { $_.RuleName -eq 'Ambiguous file encoding' }) | Should -BeNullOrEmpty
        @($result | Where-Object { $_.RuleName -eq 'Expression calls' }).Count | Should -Be 1
    }

    It 'raises nothing when encodingcheck is Disable' -Tag Unit {
        $result = Get-EncodingFinding -Manifest $script:NoEncodingManifest -Path $script:AmbiguousFile

        @($result | Where-Object { $_.RuleName -eq 'Ambiguous file encoding' }) | Should -BeNullOrEmpty
    }

    It 'does not check a script given as a string, which has no file' -Tag Unit {
        Remove-Module Initialize-ASTRuleGenerator -Force -ErrorAction SilentlyContinue
        Import-Module $script:EncodingManifest -Force
        Mock -ModuleName 'Initialize-ASTRuleGenerator' Test-ASTRuleGeneratorEncoding { throw 'must not be called' }
        $ast = [System.Management.Automation.Language.Parser]::ParseInput([System.IO.File]::ReadAllText($script:AmbiguousFile), [ref] $null, [ref] $null)

        $result = @(Measure-CustomASTRule -ScriptBlockAst $ast)

        @($result | Where-Object { $_.RuleName -eq 'Ambiguous file encoding' }) | Should -BeNullOrEmpty
    }

    It 'leaves only the allow-list finding on an allow-listed file' -Tag Unit {
        $manifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'encoding-allowed') -Rule @($script:EncodingRule) -AllowList @{ FileNamePattern = @('ambiguous.ps1') }

        $result = Get-EncodingFinding -Manifest $manifest -Path $script:AmbiguousFile

        @($result | ForEach-Object { $_.RuleName }) | Should -Be @('Allow-list')
    }

    It 'refuses to load when encodingcheck is invalid' -Tag Unit {
        $manifest = New-TestModuleCopy -Destination (Join-Path $TestDrive 'encoding-invalid') -Rule @($script:EncodingRule) -EncodingCheck 'Off'

        { Import-Module $manifest -Force -ErrorAction Stop } |
            Should -Throw "*has an invalid encodingcheck: encodingcheck 'Off' must be Enable or Disable*"
    }

    It 'raises the Error through Invoke-ScriptAnalyzer -Path with the shipped rules file' -Tag Integration -Skip:(-not $script:AnsiIs1252) {
        $result = @(Invoke-ScriptAnalyzer -Path $script:EncodingFolder -CustomRulePath $script:ShippedManifest)

        $encoding = @($result | Where-Object { $_.RuleName -eq 'Ambiguous file encoding' })
        @($encoding | ForEach-Object { $_.ScriptName }) | Should -Be @('ambiguous.ps1')
        "$($encoding[0].Severity)" | Should -Be 'Error'
        $encoding[0].Message | Should -Be $script:EncodingMessage
    }
}
