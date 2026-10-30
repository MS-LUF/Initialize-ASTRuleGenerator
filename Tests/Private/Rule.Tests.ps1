BeforeAll {
    Import-Module PSScriptAnalyzer
    Import-Module (Join-Path $PSScriptRoot '../../Initialize-ASTRuleGenerator.psd1') -Force

    function New-TestRule {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that only builds an in-memory rule.')]
        param([hashtable] $Override)
        $rule = [ordered]@{
            Status              = 'Enable'
            Name                = 'Test rule'
            ASTType             = 'StringConstantExpressionAst'
            ASTProperty         = 'Value'
            Operator            = 'like'
            SearchStringPattern = @('*x*')
            Message             = 'Test message'
            Severity            = 'warning'
        }
        foreach ($key in $Override.Keys) {
            $rule[$key] = $Override[$key]
        }
        # Same shape as a rule read by ConvertFrom-Json.
        [PSCustomObject] $rule
    }
}

Describe 'ConvertTo-ASTRuleGeneratorRule' -Tag Unit {
    It 'returns a valid rule ready to evaluate' {
        $rule = New-TestRule -Override @{ ASTProperty = 'Right.tostring().length'; Operator = 'GT'; SearchStringPattern = $null; SearchOtherPattern = @(30) }

        $result = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Rule = $rule } {
            param($Rule)
            ConvertTo-ASTRuleGeneratorRule -Rule $Rule -Index 0
        }

        $result.Name | Should -Be 'Test rule'
        $result.AstType | Should -Be ([System.Management.Automation.Language.StringConstantExpressionAst])
        $result.PropertyPath | Should -Be @('Right', 'tostring()', 'length')
        $result.Operator | Should -Be 'gt'
        $result.Mode | Should -Be 'Other'
        $result.Pattern | Should -Be @(30)
    }

    It 'keeps SearchStringPattern when both pattern lists are set, as before' {
        $rule = New-TestRule -Override @{ SearchOtherPattern = @(1) }

        $result = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Rule = $rule } {
            param($Rule)
            ConvertTo-ASTRuleGeneratorRule -Rule $Rule -Index 0
        }

        $result.Mode | Should -Be 'String'
        $result.Pattern | Should -Be @('*x*')
    }

    It 'skips the rule and reports why when <Case>' -ForEach @(
        @{ Case = 'Name is missing'; Override = @{ Name = '' }; Reason = '*Name is missing*' }
        @{ Case = 'ASTType is not a name'; Override = @{ ASTType = 'Ast]) -or ($true' }; Reason = '*letters and digits only*' }
        @{ Case = 'ASTType does not exist'; Override = @{ ASTType = 'NoSuchAst' }; Reason = '*is not an AST class*' }
        @{ Case = 'ASTType is not an AST class'; Override = @{ ASTType = 'Parser' }; Reason = '*is not an AST class*' }
        @{ Case = 'ASTProperty calls a method'; Override = @{ ASTProperty = 'Extent.GetHashCode()' }; Reason = "*step 'GetHashCode()'*" }
        @{ Case = 'ASTProperty holds code'; Override = @{ ASTProperty = 'Value; Get-Date' }; Reason = '*is not a member name*' }
        @{ Case = 'Operator is not supported'; Override = @{ Operator = 'replace' }; Reason = "*Operator 'replace' is not supported*" }
        @{ Case = 'no pattern is given'; Override = @{ SearchStringPattern = @() }; Reason = '*SearchStringPattern or SearchOtherPattern is required*' }
        @{ Case = 'a regular expression is invalid'; Override = @{ Operator = 'match'; SearchStringPattern = @('(') }; Reason = "*pattern '(' is not valid for -match*" }
        @{ Case = 'a wildcard pattern is invalid'; Override = @{ SearchStringPattern = @('[a') }; Reason = "*pattern '``[a' is not valid for -like*" }
        @{ Case = 'a SearchOtherPattern value is an object'; Override = @{ SearchStringPattern = $null; SearchOtherPattern = @([PSCustomObject]@{ a = 1 }) }; Reason = '*not objects*' }
        @{ Case = 'Message is missing'; Override = @{ Message = $null }; Reason = '*Message is missing*' }
        @{ Case = 'Severity is not supported'; Override = @{ Severity = 'critical' }; Reason = "*Severity 'critical' is not supported*" }
        @{ Case = 'MinimumCount is zero'; Override = @{ MinimumCount = 0 }; Reason = "*MinimumCount '0' must be a whole number of at least 1*" }
        @{ Case = 'MinimumCount is text'; Override = @{ MinimumCount = '10' }; Reason = "*MinimumCount '10' must be a whole number*" }
        @{ Case = 'MinimumCount is a fraction'; Override = @{ MinimumCount = 2.5 }; Reason = "*MinimumCount '2.5' must be a whole number*" }
        @{ Case = 'MinimumCount is a Boolean'; Override = @{ MinimumCount = $true }; Reason = "*MinimumCount 'True' must be a whole number*" }
    ) {
        $rule = New-TestRule -Override $Override

        $output = @(InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Rule = $rule } {
                param($Rule)
                ConvertTo-ASTRuleGeneratorRule -Rule $Rule -Index 3 2>&1
            })

        $errors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) | Should -BeNullOrEmpty
        $errors.Count | Should -Be 1
        $errors[0].FullyQualifiedErrorId | Should -BeLike 'InvalidRule*'
        $errors[0].Exception.Message | Should -BeLike $Reason
    }

    It 'gives a MinimumCount of 1 when the rule has none, and keeps the one it has' {
        $without = New-TestRule -Override @{}
        $with = New-TestRule -Override @{ MinimumCount = 10 }

        $result = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Without = $without; With = $with } {
            param($Without, $With)
            [PSCustomObject]@{
                Without = (ConvertTo-ASTRuleGeneratorRule -Rule $Without -Index 0).MinimumCount
                With    = (ConvertTo-ASTRuleGeneratorRule -Rule $With -Index 1).MinimumCount
            }
        }

        $result.Without | Should -Be 1
        $result.With | Should -Be 10
    }

    It 'names a rule without a name by its position' {
        $rule = New-TestRule -Override @{ Name = $null }

        $output = @(InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Rule = $rule } {
                param($Rule)
                ConvertTo-ASTRuleGeneratorRule -Rule $Rule -Index 3 2>&1
            })

        $output[0].Exception.Message | Should -BeLike '*rule #3 skipped*'
    }
}

Describe 'Get-ASTRuleGeneratorPropertyValue' -Tag Unit {
    BeforeAll {
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseInput('$a = "abcdef"; & cmd.exe /c x', [ref] $null, [ref] $null)
    }

    It 'follows a property path, with tostring() and length, one value per node' {
        $nodes = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))

        $values = (InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Nodes = $nodes } {
            param($Nodes)
            [PSCustomObject]@{ Values = (Get-ASTRuleGeneratorPropertyValue -InputObject $Nodes -Path 'Right', 'tostring()', 'length' -RuleName 'Test rule') }
        }).Values

        @($values).Count | Should -Be 1
        $values[0] | Should -Be 8
    }

    It 'returns null for a node when a step meets a null value' {
        $nodes = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))

        $values = (InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Nodes = $nodes } {
            param($Nodes)
            [PSCustomObject]@{ Values = (Get-ASTRuleGeneratorPropertyValue -InputObject $Nodes -Path 'NoSuchProperty', 'Value' -RuleName 'Test rule') }
        }).Values

        @($values).Count | Should -Be 1
        $values[0] | Should -BeNullOrEmpty
    }

    It 'keeps a collection value whole, and converts it to text with AsString' {
        $nodes = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))

        $values = (InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Nodes = $nodes } {
            param($Nodes)
            [PSCustomObject]@{ Values = (Get-ASTRuleGeneratorPropertyValue -InputObject $Nodes -Path 'CommandElements' -RuleName 'Test rule') }
        }).Values
        $text = (InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Nodes = $nodes } {
            param($Nodes)
            [PSCustomObject]@{ Values = (Get-ASTRuleGeneratorPropertyValue -InputObject $Nodes -Path 'InvocationOperator' -AsString -RuleName 'Test rule') }
        }).Values

        @($values).Count | Should -Be 1
        @($values[0]).Count | Should -Be 3
        $text[0] | Should -BeOfType [string]
        $text[0] | Should -Be 'Ampersand'
    }

    It 'returns an empty list for no node' {
        $values = (InModuleScope 'Initialize-ASTRuleGenerator' {
            [PSCustomObject]@{ Values = (Get-ASTRuleGeneratorPropertyValue -InputObject @() -Path 'Value' -RuleName 'Test rule') }
        }).Values

        @($values).Count | Should -Be 0
    }
}

Describe 'Test-ASTRuleGeneratorCondition' -Tag Unit {
    BeforeEach {
        InModuleScope 'Initialize-ASTRuleGenerator' { $script:RuleEvaluationReported = @{} }
    }

    It 'applies -<Operator> as PowerShell does' -ForEach @(
        @{ Operator = 'eq'; Value = 'ABC'; Pattern = 'abc'; Expected = $true }
        @{ Operator = 'ceq'; Value = 'ABC'; Pattern = 'abc'; Expected = $false }
        @{ Operator = 'ne'; Value = 'ABC'; Pattern = 'abd'; Expected = $true }
        @{ Operator = 'cne'; Value = 'ABC'; Pattern = 'abc'; Expected = $true }
        @{ Operator = 'like'; Value = 'Win32_Process'; Pattern = '*win32_*'; Expected = $true }
        @{ Operator = 'clike'; Value = 'Win32_Process'; Pattern = '*win32_*'; Expected = $false }
        @{ Operator = 'notlike'; Value = 'abc'; Pattern = 'x*'; Expected = $true }
        @{ Operator = 'cnotlike'; Value = 'abc'; Pattern = 'A*'; Expected = $true }
        @{ Operator = 'match'; Value = 'FromBase64String'; Pattern = 'base64'; Expected = $true }
        @{ Operator = 'cmatch'; Value = 'FromBase64String'; Pattern = 'base64'; Expected = $false }
        @{ Operator = 'notmatch'; Value = 'abc'; Pattern = '^x'; Expected = $true }
        @{ Operator = 'cnotmatch'; Value = 'abc'; Pattern = '^A'; Expected = $true }
        @{ Operator = 'gt'; Value = 31; Pattern = 30; Expected = $true }
        @{ Operator = 'cgt'; Value = 'B'; Pattern = 'b'; Expected = $true }
        @{ Operator = 'ge'; Value = 30; Pattern = 30; Expected = $true }
        @{ Operator = 'cge'; Value = 'b'; Pattern = 'B'; Expected = $false }
        @{ Operator = 'lt'; Value = 29; Pattern = 30; Expected = $true }
        @{ Operator = 'clt'; Value = 'b'; Pattern = 'B'; Expected = $true }
        @{ Operator = 'le'; Value = 30; Pattern = 30; Expected = $true }
        @{ Operator = 'cle'; Value = 'B'; Pattern = 'b'; Expected = $false }
        @{ Operator = 'contains'; Value = @('A', 'b'); Pattern = 'a'; Expected = $true }
        @{ Operator = 'ccontains'; Value = @('A', 'b'); Pattern = 'a'; Expected = $false }
        @{ Operator = 'notcontains'; Value = @('a', 'b'); Pattern = 'c'; Expected = $true }
        @{ Operator = 'cnotcontains'; Value = @('A', 'b'); Pattern = 'a'; Expected = $true }
        @{ Operator = 'in'; Value = 'A'; Pattern = @('a', 'b'); Expected = $true }
        @{ Operator = 'cin'; Value = 'A'; Pattern = @('a', 'b'); Expected = $false }
        @{ Operator = 'notin'; Value = 'c'; Pattern = @('a', 'b'); Expected = $true }
        @{ Operator = 'cnotin'; Value = 'A'; Pattern = @('a', 'b'); Expected = $true }
    ) {
        $result = (InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Value = $Value; Operator = $Operator; Pattern = $Pattern } {
            param($Value, $Operator, $Pattern)
            [PSCustomObject]@{ Values = (Test-ASTRuleGeneratorCondition -Value @(, $Value) -Operator $Operator -Pattern $Pattern -RuleName 'Test rule') }
        }).Values

        @($result).Count | Should -Be 1
        $result[0] | Should -Be $Expected
    }

    It 'covers every supported operator' {
        $supported = InModuleScope 'Initialize-ASTRuleGenerator' { $script:SupportedOperator }
        $tested = 'eq', 'ceq', 'ne', 'cne', 'like', 'clike', 'notlike', 'cnotlike', 'match', 'cmatch', 'notmatch', 'cnotmatch',
        'gt', 'cgt', 'ge', 'cge', 'lt', 'clt', 'le', 'cle', 'contains', 'ccontains', 'notcontains', 'cnotcontains',
        'in', 'cin', 'notin', 'cnotin'

        @($supported | Sort-Object) | Should -Be @($tested | Sort-Object)
    }

    It 'returns one result per value, in order, and skips null values with SkipNull' {
        $result = (InModuleScope 'Initialize-ASTRuleGenerator' {
            [PSCustomObject]@{ Values = (Test-ASTRuleGeneratorCondition -Value @('abc', $null, 'xbc') -Operator 'notlike' -Pattern 'a*' -SkipNull -RuleName 'Test rule') }
        }).Values

        $result | Should -Be @($false, $false, $true)
    }

    It 'compares null values without SkipNull, as PowerShell does' {
        $result = (InModuleScope 'Initialize-ASTRuleGenerator' {
            [PSCustomObject]@{ Values = (Test-ASTRuleGeneratorCondition -Value @($null) -Operator 'ne' -Pattern 5 -RuleName 'Test rule') }
        }).Values

        $result | Should -Be @($true)
    }

    It 'counts a failing comparison as not matching and reports it once per rule' {
        $extent = [System.Management.Automation.Language.Parser]::ParseInput('Get-Date', [ref] $null, [ref] $null).Extent

        $output = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Extent = $extent } {
            param($Extent)
            $first = @(Test-ASTRuleGeneratorCondition -Value @($Extent, $Extent) -Operator 'gt' -Pattern 5 -RuleName 'Test rule' 2>&1)
            $second = @(Test-ASTRuleGeneratorCondition -Value @($Extent) -Operator 'gt' -Pattern 5 -RuleName 'Test rule' 2>&1)
            [PSCustomObject]@{ First = $first; Second = $second }
        }

        $errors = @(@($output.First) + @($output.Second) | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $errors.Count | Should -Be 1
        $errors[0].FullyQualifiedErrorId | Should -BeLike 'RuleEvaluationFailed*'
        $errors[0].Exception.Message | Should -BeLike "*rule 'Test rule' could not be evaluated*"
        @($output.First | ForEach-Object { $_ } | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) | Should -Be @($false, $false)
        @($output.Second | ForEach-Object { $_ } | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) | Should -Be @($false)
    }
}

Describe 'Write-ASTRuleGeneratorEvaluationError' -Tag Unit {
    BeforeEach {
        InModuleScope 'Initialize-ASTRuleGenerator' { $script:RuleEvaluationReported = @{} }
    }

    It 'reports each rule once while the module is loaded' {
        $output = @(InModuleScope 'Initialize-ASTRuleGenerator' {
                Write-ASTRuleGeneratorEvaluationError -RuleName 'One' -Message 'first' 2>&1
                Write-ASTRuleGeneratorEvaluationError -RuleName 'One' -Message 'second' 2>&1
                Write-ASTRuleGeneratorEvaluationError -RuleName 'Two' -Message 'third' 2>&1
            })

        $output.Count | Should -Be 2
        $output[0].Exception.Message | Should -BeLike "*rule 'One'*first"
        $output[1].Exception.Message | Should -BeLike "*rule 'Two'*third"
        $output[0].TargetObject | Should -Be 'One'
    }
}
