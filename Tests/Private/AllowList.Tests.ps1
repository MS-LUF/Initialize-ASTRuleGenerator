BeforeAll {
    $script:SavedOverride = $env:ASTRULEGENERATOR_CONFIG
    $env:ASTRULEGENERATOR_CONFIG = $null
    Import-Module (Join-Path $PSScriptRoot '../../Initialize-ASTRuleGenerator.psd1') -Force

    # SHA-256 of the three bytes "abc" (FIPS 180-2 test vector).
    $script:AbcHash = 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD'
}

AfterAll {
    $env:ASTRULEGENERATOR_CONFIG = $script:SavedOverride
}

Describe 'ConvertTo-ASTRuleGeneratorAllowList' -Tag Unit {
    It 'returns an empty allow-list when the rules file has none' {
        $result = InModuleScope 'Initialize-ASTRuleGenerator' { ConvertTo-ASTRuleGeneratorAllowList -AllowList $null }

        $result.HasEntry | Should -BeFalse
        @($result.FileNamePattern).Count | Should -Be 0
        @($result.Sha256).Count | Should -Be 0
    }

    It 'keeps the patterns and puts the hashes in upper case' {
        $allowList = [PSCustomObject]@{ FileNamePattern = @('Build-*.ps1', 'vendor?.psm1'); Sha256 = @($script:AbcHash.ToLowerInvariant()) }

        $result = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ AllowList = $allowList } {
            param($AllowList)
            ConvertTo-ASTRuleGeneratorAllowList -AllowList $AllowList
        }

        $result.HasEntry | Should -BeTrue
        $result.FileNamePattern | Should -Be @('Build-*.ps1', 'vendor?.psm1')
        $result.Sha256 | Should -Be @($script:AbcHash)
    }

    It 'accepts a section with only one of the two lists' {
        $allowList = [PSCustomObject]@{ Sha256 = @($script:AbcHash) }

        $result = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ AllowList = $allowList } {
            param($AllowList)
            ConvertTo-ASTRuleGeneratorAllowList -AllowList $AllowList
        }

        $result.HasEntry | Should -BeTrue
        @($result.FileNamePattern).Count | Should -Be 0
    }

    It 'rejects <Case>' -ForEach @(
        @{ Case = 'a section that is not an object'; AllowList = @('Build-*.ps1'); Message = '*must be an object*' }
        @{ Case = 'an unknown key'; AllowList = [PSCustomObject]@{ PathPattern = @('*') }; Message = "*unknown key 'PathPattern'*" }
        @{ Case = 'an empty pattern'; AllowList = [PSCustomObject]@{ FileNamePattern = @(' ') }; Message = '*must be a non-empty string*' }
        @{ Case = 'a pattern that is not a string'; AllowList = [PSCustomObject]@{ FileNamePattern = @(5) }; Message = '*must be a non-empty string*' }
        @{ Case = 'a pattern with a backslash'; AllowList = [PSCustomObject]@{ FileNamePattern = @('Vendor\*.ps1') }; Message = '*must be a file name pattern, without a path*' }
        @{ Case = 'a pattern with a slash'; AllowList = [PSCustomObject]@{ FileNamePattern = @('Vendor/*.ps1') }; Message = '*must be a file name pattern, without a path*' }
        @{ Case = 'an invalid wildcard pattern'; AllowList = [PSCustomObject]@{ FileNamePattern = @('[a.ps1') }; Message = '*is not a valid wildcard pattern*' }
        @{ Case = 'a hash that is too short'; AllowList = [PSCustomObject]@{ Sha256 = @('BA7816BF') }; Message = '*must be 64 hexadecimal characters*' }
        @{ Case = 'a hash that is not hexadecimal'; AllowList = [PSCustomObject]@{ Sha256 = @('Z' * 64) }; Message = '*must be 64 hexadecimal characters*' }
    ) {
        { InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ AllowList = $AllowList } { param($AllowList) ConvertTo-ASTRuleGeneratorAllowList -AllowList $AllowList } } |
            Should -Throw $Message
    }
}

Describe 'Get-ASTRuleGeneratorFileHash' -Tag Unit {
    It 'returns the SHA-256 of the file bytes in upper case' {
        $path = Join-Path $TestDrive 'abc.bin'
        [System.IO.File]::WriteAllBytes($path, [byte[]](0x61, 0x62, 0x63))

        $hash = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ Path = $path } { param($Path) Get-ASTRuleGeneratorFileHash -Path $Path }

        $hash | Should -BeExactly $script:AbcHash
    }
}

Describe 'Test-ASTRuleGeneratorAllowList' -Tag Unit {
    BeforeAll {
        function New-TestAllowList {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that only builds an in-memory allow-list.')]
            param([string[]] $Pattern = @(), [string[]] $Hash = @())
            [PSCustomObject]@{ FileNamePattern = $Pattern; Sha256 = $Hash; HasEntry = ($Pattern.Count + $Hash.Count) -gt 0 }
        }
    }

    It 'matches the file name, ignoring case' {
        Mock -ModuleName 'Initialize-ASTRuleGenerator' Get-ASTRuleGeneratorFileHash { throw 'must not be called' }
        $allowList = New-TestAllowList -Pattern 'build-*.PS1'
        # Built with the platform's separator: outside Windows a backslash is part of a file name.
        $path = Join-Path (Join-Path 'Repo' 'Scripts') 'Build-Tools.ps1'

        $reason = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ AllowList = $allowList; Path = $path } {
            param($AllowList, $Path)
            Test-ASTRuleGeneratorAllowList -FilePath $Path -AllowList $AllowList
        }

        $reason | Should -Be "file name pattern 'build-*.PS1'"
    }

    It 'compares the file name only, never the folders of its path' {
        $allowList = New-TestAllowList -Pattern 'Vendor*'
        $path = Join-Path (Join-Path 'Repo' 'Vendor') 'evil.ps1'

        $reason = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ AllowList = $allowList; Path = $path } {
            param($AllowList, $Path)
            Test-ASTRuleGeneratorAllowList -FilePath $Path -AllowList $AllowList
        }

        $reason | Should -BeNullOrEmpty
    }

    It 'matches a listed hash, and does not compute a hash when none is listed' {
        Mock -ModuleName 'Initialize-ASTRuleGenerator' Get-ASTRuleGeneratorFileHash { $script:AbcHash } -ParameterFilter { $Path -eq 'C:\Repo\listed.ps1' }
        $withHash = New-TestAllowList -Hash $script:AbcHash
        $withoutHash = New-TestAllowList -Pattern 'other.ps1'

        $result = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ WithHash = $withHash; WithoutHash = $withoutHash } {
            param($WithHash, $WithoutHash)
            [PSCustomObject]@{
                Listed    = Test-ASTRuleGeneratorAllowList -FilePath 'C:\Repo\listed.ps1' -AllowList $WithHash
                NoHashSet = Test-ASTRuleGeneratorAllowList -FilePath 'C:\Repo\listed.ps1' -AllowList $WithoutHash
            }
        }

        $result.Listed | Should -Be "SHA-256 $($script:AbcHash)"
        $result.NoHashSet | Should -BeNullOrEmpty
        Should -Invoke -ModuleName 'Initialize-ASTRuleGenerator' Get-ASTRuleGeneratorFileHash -Times 1 -Exactly
    }

    It 'does not match a file whose hash is not listed' {
        Mock -ModuleName 'Initialize-ASTRuleGenerator' Get-ASTRuleGeneratorFileHash { 'F' * 64 }
        $allowList = New-TestAllowList -Hash $script:AbcHash

        $reason = InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ AllowList = $allowList } {
            param($AllowList)
            Test-ASTRuleGeneratorAllowList -FilePath 'C:\Repo\other.ps1' -AllowList $AllowList
        }

        $reason | Should -BeNullOrEmpty
    }

    It 'scans a file whose hash cannot be computed, and reports it' {
        Mock -ModuleName 'Initialize-ASTRuleGenerator' Get-ASTRuleGeneratorFileHash { throw 'file locked' }
        $allowList = New-TestAllowList -Hash $script:AbcHash

        $output = @(InModuleScope 'Initialize-ASTRuleGenerator' -Parameters @{ AllowList = $allowList } {
                param($AllowList)
                Test-ASTRuleGeneratorAllowList -FilePath 'C:\Repo\locked.ps1' -AllowList $AllowList 2>&1
            })

        @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) | Should -BeNullOrEmpty
        $errors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $errors.Count | Should -Be 1
        $errors[0].FullyQualifiedErrorId | Should -BeLike 'AllowListHashFailed*'
        $errors[0].Exception.Message | Should -BeLike '*locked.ps1*so the file is scanned*file locked*'
    }
}
