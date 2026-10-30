BeforeDiscovery {
    # The rule's OutputType names a PSScriptAnalyzer type, which must be loaded for its help to
    # be read.
    Import-Module PSScriptAnalyzer
    Import-Module (Join-Path $PSScriptRoot '../Initialize-ASTRuleGenerator.psd1') -Force
}

BeforeAll {
    $script:SavedOverride = $env:ASTRULEGENERATOR_CONFIG
    $env:ASTRULEGENERATOR_CONFIG = $null
    Import-Module PSScriptAnalyzer
    Import-Module (Join-Path $PSScriptRoot '../Initialize-ASTRuleGenerator.psd1') -Force
}

AfterAll {
    $env:ASTRULEGENERATOR_CONFIG = $script:SavedOverride
}

Describe 'Comment-based help' -Tag Unit {
    InModuleScope 'Initialize-ASTRuleGenerator' {
        BeforeAll {
            # Every function, public and private: a private function's broken help is still a
            # regression, even if users do not see it.
            $script:AllFunctionName = Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public'), (Join-Path $script:ModuleRoot 'Private') -Filter '*.ps1' -Recurse -File |
                ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) } |
                Sort-Object -Unique
        }

        It 'finds at least the functions known today (guards against checking nothing)' {
            $script:AllFunctionName.Count | Should -BeGreaterOrEqual 7
        }

        It 'defines every function in a file of the same name' {
            $missing = $script:AllFunctionName | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) }
            $missing | Should -BeNullOrEmpty
        }

        It 'gives every function a help block that PowerShell recognises' {
            # A help line starting with a literal "." (prose wrapping before a dot-prefixed term)
            # is read as an unknown keyword and silently breaks the whole block.
            $broken = foreach ($name in $script:AllFunctionName) {
                $command = Get-Command -Name $name -ErrorAction SilentlyContinue
                if (-not $command) { continue }
                $help = $command.ScriptBlock.Ast.GetHelpContent()
                if (-not $help -or -not $help.Synopsis -or -not $help.Description) { $name }
            }
            $broken | Should -BeNullOrEmpty -Because "the help of these functions did not parse: $($broken -join ', ')"
        }

        It 'documents every parameter of every function' {
            $common = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
            $undocumented = foreach ($name in $script:AllFunctionName) {
                $command = Get-Command -Name $name -ErrorAction SilentlyContinue
                if (-not $command) { continue }
                $help = $command.ScriptBlock.Ast.GetHelpContent()
                foreach ($parameter in $command.Parameters.Keys) {
                    if ($common -notcontains $parameter -and -not $help.Parameters.ContainsKey($parameter.ToUpperInvariant())) {
                        "$name -$parameter"
                    }
                }
            }
            $undocumented | Should -BeNullOrEmpty -Because "these parameters have no .PARAMETER entry: $($undocumented -join ', ')"
        }
    }
}

Describe 'Internal design documents' -Tag Unit {
    It 'are not referenced from any file other than themselves' {
        # The two design documents are for people working on this repository. Code, help text,
        # the manifest and user documentation must stand on their own without pointing at them.
        # The names are assembled here so that this file does not match its own search.
        $internalName = @(('Archi' + 'tecture.md'), ('CLAU' + 'DE.md'))
        $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

        $offender = Get-ChildItem -Path $root -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1', '*.json', '*.md', '*.xml', '*.txt', '*.yml' |
            Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' -and $internalName -notcontains $_.Name } |
            Where-Object {
                $content = [System.IO.File]::ReadAllText($_.FullName)
                @($internalName | Where-Object { $content.IndexOf($_, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 }).Count -gt 0
            } |
            ForEach-Object { $_.FullName.Substring($root.Length).TrimStart('\', '/') }

        $offender | Should -BeNullOrEmpty -Because "these files mention an internal design document: $($offender -join ', ')"
    }
}

Describe 'Generated help files' -Tag Unit {
    BeforeAll {
        $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
        $script:PublicName = Get-ChildItem -Path (Join-Path $script:RepoRoot 'Public') -Filter '*.ps1' -File |
            ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }
        $script:Manifest = Test-ModuleManifest -Path (Join-Path $script:RepoRoot 'Initialize-ASTRuleGenerator.psd1')
        $script:ModuleVersion = $script:Manifest.Version.ToString()
    }

    It 'has a page for every public function, with no placeholder left in it' {
        foreach ($name in $script:PublicName) {
            $page = Join-Path $script:RepoRoot "Docs/$name.md"
            $page | Should -Exist
            [System.IO.File]::ReadAllText($page) | Should -Not -Match '\{\{'
        }
    }

    It 'documents every parameter of every public function in its page' {
        # Catches a parameter added without regenerating the help.
        $common = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
        foreach ($name in $script:PublicName) {
            $content = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot "Docs/$name.md"))
            $missing = (Get-Command -Name $name).Parameters.Keys |
                Where-Object { $common -notcontains $_ -and $content -notmatch "(?m)^### -$_\s*$" }
            $missing | Should -BeNullOrEmpty -Because "Docs/$name.md lacks these parameters: $($missing -join ', ')"
        }
    }

    It 'has the same synopsis in each page as in the function''s help' {
        # Catches help edited without regenerating the pages.
        foreach ($name in $script:PublicName) {
            $content = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot "Docs/$name.md"))
            $synopsis = (Get-Command -Name $name).ScriptBlock.Ast.GetHelpContent().Synopsis.Trim()
            $content | Should -Match "(?m)^## SYNOPSIS\r?\n$([regex]::Escape($synopsis))\s*$"
        }
    }

    It 'has an external help entry for every public function' {
        $xml = [xml][System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'en-US/Initialize-ASTRuleGenerator-help.xml'))
        $documented = @($xml.helpItems.command | ForEach-Object { $_.details.name })

        ($documented | Sort-Object) -join ',' | Should -Be (($script:PublicName | Sort-Object) -join ',')
    }

    It 'has a module page whose help version matches the manifest' {
        $page = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'Docs/Initialize-ASTRuleGenerator.md'))

        $page | Should -Match "(?m)^Help Version: $([regex]::Escape($script:ModuleVersion))\.0\s*$"
        $page | Should -Not -Match '\{\{'
    }

    It 'has a README change-log entry and release notes for the manifest version' {
        $readme = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'README.md'))
        $notes = $script:Manifest.ReleaseNotes

        $readme | Should -Match "(?m)^- \*\*$([regex]::Escape($script:ModuleVersion))\*\* - "
        $notes | Should -BeLike "v$($script:ModuleVersion) - *"
    }
}

Describe 'Module manifest' -Tag Unit {
    It 'exports exactly the functions defined under Public' {
        $root = Join-Path $PSScriptRoot '..'
        $publicName = Get-ChildItem -Path (Join-Path $root 'Public') -Filter '*.ps1' -File |
            ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) } | Sort-Object
        $exported = (Import-Module (Join-Path $root 'Initialize-ASTRuleGenerator.psd1') -Force -PassThru).ExportedFunctions.Keys | Sort-Object

        ($exported -join ',') | Should -Be ($publicName -join ',')
    }

    It 'lists every file of the module in FileList, and only existing files' {
        $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
        # Test-ModuleManifest returns FileList as full paths.
        $listed = @((Test-ModuleManifest -Path (Join-Path $root 'Initialize-ASTRuleGenerator.psd1')).FileList |
                ForEach-Object { $_.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/' } | Sort-Object)
        $actual = @(
            Get-ChildItem -Path $root -File | Where-Object { $_.Name -like 'Initialize-ASTRuleGenerator.*' }
            Get-ChildItem -Path (Join-Path $root 'Public'), (Join-Path $root 'Private'), (Join-Path $root 'en-US') -File -Recurse
        ) | ForEach-Object { $_.FullName.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/' } | Sort-Object

        ($listed -join ',') | Should -Be ($actual -join ',')
    }
}
