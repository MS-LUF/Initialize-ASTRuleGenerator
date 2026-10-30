BeforeDiscovery {
    # -Skip is evaluated during discovery, so the platform is found here rather than in BeforeAll.
    # $IsWindows does not exist under Windows PowerShell 5.1, which only runs on Windows.
    $script:OnWindows = ($null -eq (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)) -or $IsWindows
}

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Initialize-ASTRuleGenerator.psd1') -Force

    # The tests set the variable themselves; a value from the machine running them must not leak in.
    $script:SavedOverride = $env:ASTRULEGENERATOR_CONFIG
    $env:ASTRULEGENERATOR_CONFIG = $null
}

AfterAll {
    $env:ASTRULEGENERATOR_CONFIG = $script:SavedOverride
}

Describe 'Get-ASTRuleGeneratorConfigPath' -Tag Unit {
    AfterEach {
        $env:ASTRULEGENERATOR_CONFIG = $null
    }

    It 'returns the file in the module folder when the variable is <Case>' -ForEach @(
        @{ Case = 'unset'; Value = $null }
        @{ Case = 'empty'; Value = '' }
        @{ Case = 'blank'; Value = '   ' }
    ) {
        $env:ASTRULEGENERATOR_CONFIG = $Value
        $root = Join-Path $TestDrive 'module'

        $result = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Root = $root } {
            param($Root)
            Get-ASTRuleGeneratorConfigPath -ModuleRoot $Root
        }

        $result.Path | Should -Be (Join-Path $root 'Initialize-ASTRuleGenerator.json')
        $result.FromEnvironment | Should -BeFalse
    }

    It 'returns the absolute path <Value> set in the variable' -Skip:(-not $script:OnWindows) -ForEach @(
        @{ Value = 'C:\Rules\rules.json' }
        @{ Value = 'd:/rules/rules.json' }
        @{ Value = '\\server\share\rules.json' }
    ) {
        $env:ASTRULEGENERATOR_CONFIG = $Value

        $result = InModuleScope 'Initialize-ASTRuleGenerator' { Get-ASTRuleGeneratorConfigPath -ModuleRoot 'C:\Module' }

        $result.Path | Should -Be $Value
        $result.FromEnvironment | Should -BeTrue
    }

    It 'rejects the path <Value>, which is not absolute' -Skip:(-not $script:OnWindows) -ForEach @(
        @{ Value = 'rules.json' }
        @{ Value = 'rules\rules.json' }
        @{ Value = '.\rules.json' }
        @{ Value = '\rules.json' }
        @{ Value = 'C:rules.json' }
    ) {
        $env:ASTRULEGENERATOR_CONFIG = $Value

        { InModuleScope 'Initialize-ASTRuleGenerator' { Get-ASTRuleGeneratorConfigPath -ModuleRoot 'C:\Module' } } |
            Should -Throw "*ASTRULEGENERATOR_CONFIG must hold an absolute path, not '$Value'*"
    }

    It 'accepts a path starting with a slash and rejects a relative one outside Windows' -Skip:$script:OnWindows {
        $env:ASTRULEGENERATOR_CONFIG = '/etc/rules.json'
        $result = InModuleScope 'Initialize-ASTRuleGenerator' { Get-ASTRuleGeneratorConfigPath -ModuleRoot '/module' }
        $result.Path | Should -Be '/etc/rules.json'

        $env:ASTRULEGENERATOR_CONFIG = 'rules.json'
        { InModuleScope 'Initialize-ASTRuleGenerator' { Get-ASTRuleGeneratorConfigPath -ModuleRoot '/module' } } |
            Should -Throw '*must hold an absolute path*'
    }
}

Describe 'Read-ASTRuleGeneratorConfig' -Tag Unit {
    It 'returns the content of a valid rules file' {
        $path = Join-Path $TestDrive 'valid.json'
        Set-Content -Path $path -Value '{ "rules": [ { "Name": "One" }, { "Name": "Two" } ] }'

        $config = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Path = $path } {
            param($Path)
            Read-ASTRuleGeneratorConfig -Path $Path
        }

        @($config.rules).Count | Should -Be 2
        $config.rules[1].Name | Should -Be 'Two'
    }

    It 'keeps the message of earlier versions when the file in the module folder is missing' {
        $path = Join-Path $TestDrive 'absent.json'

        { InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Path = $path } { param($Path) Read-ASTRuleGeneratorConfig -Path $Path } } |
            Should -Throw 'configuration file Initialize-ASTRuleGenerator.json missing in module folder'
    }

    It 'names the variable when the file it points to is missing' {
        $path = Join-Path $TestDrive 'absent.json'

        { InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Path = $path } { param($Path) Read-ASTRuleGeneratorConfig -Path $Path -FromEnvironment } } |
            Should -Throw "*configuration file '$path' set by ASTRULEGENERATOR_CONFIG not found*"
    }

    It 'throws when the file is <Case>' -ForEach @(
        @{ Case = 'not JSON'; Content = 'rules = nothing'; Message = '*could not be read as JSON*' }
        @{ Case = 'empty'; Content = ''; Message = '*has no rules array*' }
        @{ Case = 'JSON without rules'; Content = '{ "rule": [] }'; Message = '*has no rules array*' }
    ) {
        $path = Join-Path $TestDrive "bad-$([guid]::NewGuid().ToString('N')).json"
        Set-Content -Path $path -Value $Content

        { InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Path = $path } { param($Path) Read-ASTRuleGeneratorConfig -Path $Path } } |
            Should -Throw $Message
    }
}
