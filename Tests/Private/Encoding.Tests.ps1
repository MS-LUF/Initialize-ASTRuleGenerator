BeforeDiscovery {
    # The variable is absent under Windows PowerShell 5.1, which only runs on Windows.
    $script:OnWindows = (-not (Test-Path -Path 'Variable:IsWindows')) -or $IsWindows
}

BeforeAll {
    $script:SavedOverride = $env:ASTRULEGENERATOR_CONFIG
    $env:ASTRULEGENERATOR_CONFIG = $null
    Import-Module (Join-Path $PSScriptRoot '../../Initialize-ASTRuleGenerator.psd1') -Force

    # The non-ASCII characters are built from their code points, so this file stays ASCII and is
    # read the same way by both editions.
    $script:Arrow = [string][char]0x2192
    $script:EmDash = [string][char]0x2014
    $script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    # Read as code page 1252, the arrow's UTF-8 bytes end with a curly single quote: the first
    # string closes early, and line 2 falls inside a string.
    $script:HiddenFrom51 = "Write-Output 'a $script:Arrow b'`r`nInvoke-Expression `$payload`r`nWrite-Output 'c $script:Arrow d'`r`n"
}

AfterAll {
    $env:ASTRULEGENERATOR_CONFIG = $script:SavedOverride
}

Describe 'ConvertTo-ASTRuleGeneratorEncodingCheck' -Tag Unit {
    It 'turns the check on for <Case>' -ForEach @(
        @{ Case = 'a rules file without the setting'; Value = $null }
        @{ Case = 'Enable'; Value = 'Enable' }
        @{ Case = 'enable in lower case'; Value = 'enable' }
    ) {
        $result = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Value = $Value } { param($Value) ConvertTo-ASTRuleGeneratorEncodingCheck -EncodingCheck $Value }

        $result | Should -BeTrue
    }

    It 'turns the check off for Disable' {
        $result = InModuleScope 'Initialize-ASTRuleGenerator' { ConvertTo-ASTRuleGeneratorEncodingCheck -EncodingCheck 'Disable' }

        $result | Should -BeFalse
    }

    It 'rejects <Case>' -ForEach @(
        @{ Case = 'another word'; Value = 'On' }
        @{ Case = 'an empty string'; Value = '' }
        @{ Case = 'a JSON boolean'; Value = $false }
        @{ Case = 'a number'; Value = 1 }
    ) {
        { InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Value = $Value } { param($Value) ConvertTo-ASTRuleGeneratorEncodingCheck -EncodingCheck $Value } } |
            Should -Throw '*must be Enable or Disable*'
    }
}

Describe 'Get-ASTRuleGeneratorFileByte' -Tag Unit {
    It 'returns the bytes of the file as a byte array' {
        $path = Join-Path $TestDrive 'bytes.bin'
        [System.IO.File]::WriteAllBytes($path, [byte[]](0xEF, 0xBB, 0xBF, 0x61))

        $result = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Path = $path } {
            param($Path)
            $bytes = Get-ASTRuleGeneratorFileByte -Path $Path
            [PSCustomObject]@{ IsByteArray = $bytes -is [byte[]]; Values = $bytes }
        }

        $result.IsByteArray | Should -BeTrue
        $result.Values | Should -Be @(0xEF, 0xBB, 0xBF, 0x61)
    }

    It 'throws when the file is missing' {
        $path = Join-Path $TestDrive 'missing.ps1'

        { InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Path = $path } { param($Path) Get-ASTRuleGeneratorFileByte -Path $Path } } | Should -Throw
    }
}

Describe 'Get-ASTRuleGeneratorAnsiEncoding' -Tag Unit {
    It 'returns the system ANSI code page on Windows' -Skip:(-not $script:OnWindows) {
        $result = InModuleScope 'Initialize-ASTRuleGenerator' { Get-ASTRuleGeneratorAnsiEncoding }

        $result | Should -BeOfType [System.Text.Encoding]
        $result.CodePage | Should -Be ([System.Text.Encoding]::GetEncoding(0).CodePage)
    }

    It 'returns code page 1252 outside Windows' -Skip:$script:OnWindows {
        $result = InModuleScope 'Initialize-ASTRuleGenerator' { Get-ASTRuleGeneratorAnsiEncoding }

        $result.CodePage | Should -Be 1252
    }
}

Describe 'Test-ASTRuleGeneratorEncoding' -Tag Unit {
    BeforeEach {
        Mock -ModuleName 'Initialize-ASTRuleGenerator' Get-ASTRuleGeneratorAnsiEncoding { [System.Text.Encoding]::GetEncoding(1252) }
        Mock -ModuleName 'Initialize-ASTRuleGenerator' Get-ASTRuleGeneratorFileByte { $script:FileByte }
    }

    It 'reports code page 1252 for <Case>' -ForEach @(
        @{ Case = 'an arrow that moves a line into a string under 5.1'; Kind = 'HiddenFrom51' }
        @{ Case = 'an arrow that moves a line into a string under 7'; Kind = 'HiddenFrom7' }
        @{ Case = 'an em dash that closes a double-quoted string under 5.1'; Kind = 'EmDash' }
        @{ Case = 'an ANSI file whose curly quote 7 does not read as a quote'; Kind = 'AnsiQuote' }
    ) {
        $script:FileByte = switch ($Kind) {
            'HiddenFrom51' { $script:Utf8NoBom.GetBytes($script:HiddenFrom51) }
            'HiddenFrom7' { $script:Utf8NoBom.GetBytes("Write-Output 'a $script:Arrow`r`nInvoke-Expression `$payload`r`nWrite-Output $script:Arrow b'`r`n") }
            'EmDash' { $script:Utf8NoBom.GetBytes("Write-Output `"a $script:EmDash b`"`r`nGet-Date`r`n") }
            'AnsiQuote' { [System.Text.Encoding]::GetEncoding(1252).GetBytes("Write-Output 'it$([char]0x2019)s'`r`nGet-Date`r`n") }
        }

        $result = InModuleScope 'Initialize-ASTRuleGenerator' { Test-ASTRuleGeneratorEncoding -FilePath 'C:\Repo\a.ps1' }

        $result | Should -Be 1252
    }

    It 'reports nothing for <Case>' -ForEach @(
        @{ Case = 'an ASCII file'; Kind = 'Ascii' }
        @{ Case = 'accented letters only'; Kind = 'Accents' }
        @{ Case = 'an arrow in a comment'; Kind = 'Comment' }
        @{ Case = 'the same hiding file with a UTF-8 byte order mark'; Kind = 'Utf8Bom' }
        @{ Case = 'the same hiding file in UTF-16 with a byte order mark'; Kind = 'Utf16Bom' }
        @{ Case = 'an empty file'; Kind = 'Empty' }
    ) {
        $script:FileByte = switch ($Kind) {
            'Ascii' { $script:Utf8NoBom.GetBytes("Write-Output 'plain'`r`n") }
            'Accents' { $script:Utf8NoBom.GetBytes("Write-Output 'caf$([char]0xE9) $([char]0xE0) $([char]0xFC)'`r`n") }
            'Comment' { $script:Utf8NoBom.GetBytes("# a $script:Arrow b`r`nGet-Date`r`n") }
            'Utf8Bom' { [System.Text.UTF8Encoding]::new($true).GetPreamble() + $script:Utf8NoBom.GetBytes($script:HiddenFrom51) }
            'Utf16Bom' { [System.Text.Encoding]::Unicode.GetPreamble() + [System.Text.Encoding]::Unicode.GetBytes($script:HiddenFrom51) }
            'Empty' { , [byte[]]@() }
        }

        $result = InModuleScope 'Initialize-ASTRuleGenerator' { Test-ASTRuleGeneratorEncoding -FilePath 'C:\Repo\a.ps1' }

        $result | Should -BeNullOrEmpty
    }

    It 'reports nothing when the ANSI code page is UTF-8' {
        Mock -ModuleName 'Initialize-ASTRuleGenerator' Get-ASTRuleGeneratorAnsiEncoding { [System.Text.Encoding]::UTF8 }
        $script:FileByte = $script:Utf8NoBom.GetBytes($script:HiddenFrom51)

        $result = InModuleScope 'Initialize-ASTRuleGenerator' { Test-ASTRuleGeneratorEncoding -FilePath 'C:\Repo\a.ps1' }

        $result | Should -BeNullOrEmpty
    }

    It 'skips the check with a non-terminating error when the file cannot be read' {
        Mock -ModuleName 'Initialize-ASTRuleGenerator' Get-ASTRuleGeneratorFileByte { throw 'file locked' }

        $output = @(InModuleScope 'Initialize-ASTRuleGenerator' { Test-ASTRuleGeneratorEncoding -FilePath 'C:\Repo\locked.ps1' 2>&1 })

        $errorRecord = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $errorRecord.Count | Should -Be 1
        $errorRecord[0].FullyQualifiedErrorId | Should -BeLike 'EncodingCheckReadFailed*'
        $errorRecord[0].Exception.Message | Should -BeLike "*'C:\Repo\locked.ps1' could not be read for the encoding check, so the check is skipped: file locked*"
        @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) | Should -BeNullOrEmpty
    }
}
