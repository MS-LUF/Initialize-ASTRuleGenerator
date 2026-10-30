# Initialize-ASTRuleGenerator - How-to

Task-by-task guide. Every command below was run as shown, from a folder holding the module (in
`.\Initialize-ASTRuleGenerator`), a rules file and a script to analyse. The output is from
PowerShell 7.6 with PSScriptAnalyzer 1.25.0; Windows PowerShell 5.1 gives the same findings. Long
paths in error messages are shortened with `...`.

## Write a rules file

A rules file is JSON with a `rules` array. This one, `my-rules.json`, flags download methods as
errors and code run from a string as warnings:

```json
{
    "rules": [
        {
            "Status": "Enable",
            "Name": "Download cradle",
            "ASTType": "InvokeMemberExpressionAst",
            "ASTProperty": "Member.Value",
            "Operator": "eq",
            "SearchStringPattern": ["DownloadString", "DownloadFile"],
            "Message": "Download method called",
            "Severity": "error"
        },
        {
            "Status": "Enable",
            "Name": "Dynamic code",
            "ASTType": "StringConstantExpressionAst",
            "ASTProperty": "Value",
            "Operator": "eq",
            "SearchStringPattern": ["Invoke-Expression", "iex"],
            "Message": "Code run from a string",
            "Severity": "warning"
        }
    ]
}
```

Each rule has these properties:

| Property | Meaning |
| --- | --- |
| `Status` | `Enable` or `Disable`. Only enabled rules run. |
| `Name` | Name of the rule, shown as the finding's rule name. |
| `ASTType` | Class of the [System.Management.Automation.Language](https://learn.microsoft.com/dotnet/api/system.management.automation.language) namespace to look for, such as `CommandAst`, `StringConstantExpressionAst` or `InvokeMemberExpressionAst`. |
| `ASTProperty` | Property of that class to compare, or a path of properties separated by dots (`Member.Value`, `Right.Extent.Text`). The step `tostring()` converts the value to text (`Right.tostring().length`). No other method call is allowed. |
| `Operator` | PowerShell comparison operator without its hyphen: `eq`, `ne`, `like`, `notlike`, `match`, `notmatch`, `gt`, `ge`, `lt`, `le`, `contains`, `notcontains`, `in`, `notin`, or its case-sensitive form starting with `c` (`cmatch`). |
| `SearchStringPattern` | Values compared with the property's text: wildcard patterns for `like`, regular expressions for `match`. |
| `SearchOtherPattern` | Values compared with the property as it is, such as numbers. Used only when `SearchStringPattern` is absent. |
| `Message` | Message of each finding; the pattern that matched is added after it. |
| `Severity` | `info`, `warning` or `error`. |
| `MinimumCount` | Optional whole number. The rule reports its findings only when the script holds at least that many, counting all its patterns: a weak signal becomes useful when repeated. |

Every value is used as data, never run as code.

## Use the shipped rules

The module ships `Initialize-ASTRuleGenerator.json` with 41 enabled rules for PowerShell
threats and obfuscation, each naming its MITRE ATT&CK technique. Without
`ASTRULEGENERATOR_CONFIG`, they analyse the script shown in the next section like this:

```powershell
PS> Invoke-ScriptAnalyzer -Path .\suspicious.ps1 -CustomRulePath .\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1

RuleName                            Severity     ScriptName Line  Message
--------                            --------     ---------- ----  -------
Download method                     Warning      suspicious 2     Download method called (ATT&CK T1105) :
                                                 .ps1             DownloadString
Invoke-Expression call              Warning      suspicious 3     Code run from a string (ATT&CK T1059.001) :
                                                 .ps1             (?i)^\s*(?:iex|invoke-expression)\b
```

The shipped rules look at one part of the script at a time. Here the download and the
`Invoke-Expression` that runs it are separate statements, so each raises its own warning. The
"Downloaded code run" error, which needs both in one pipeline, is not raised. Rules with the
Error severity are the ones that raised no finding on 453 files of legitimate modules. Disable
or change rules in the file, or use your own file as shown next.

## Run your rules

The script to analyse, `suspicious.ps1`:

```powershell
$url = 'https://example.com/payload.ps1'
$code = (New-Object Net.WebClient).DownloadString($url)
Invoke-Expression $code
```

Point `ASTRULEGENERATOR_CONFIG` at the rules file, by absolute path, and run PSScriptAnalyzer
with the module as a custom rule path:

```powershell
PS> $env:ASTRULEGENERATOR_CONFIG = Join-Path $PWD 'my-rules.json'
PS> Invoke-ScriptAnalyzer -Path .\suspicious.ps1 -CustomRulePath .\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1

RuleName                            Severity     ScriptName Line  Message
--------                            --------     ---------- ----  -------
Download cradle                     Error        suspicious 2     Download method called : DownloadString
                                                 .ps1
Dynamic code                        Warning      suspicious 3     Code run from a string : Invoke-Expression
                                                 .ps1
```

Without the variable, the module reads `Initialize-ASTRuleGenerator.json` in its own folder, as
in the previous section. The rules file is read again by every analysis, so an edit is used by
the next run.

## When a rule is invalid

A rule that breaks the requirements above is skipped and reported as an error; the other rules
still run. Here the second rule of `bad-rules.json` uses `equals`, which is not an operator:

```powershell
PS> $env:ASTRULEGENERATOR_CONFIG = Join-Path $PWD 'bad-rules.json'
PS> Invoke-ScriptAnalyzer -Path .\suspicious.ps1 -CustomRulePath .\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1
Invoke-ScriptAnalyzer: Initialize-ASTRuleGenerator: rule 'Dynamic code' skipped: Operator 'equals' is not supported (supported: eq, ne, like, notlike, match, notmatch, gt, ge, lt, le, contains, notcontains, in, notin, ceq, cne, clike, cnotlike, cmatch, cnotmatch, cgt, cge, clt, cle, ccontains, cnotcontains, cin, cnotin).

RuleName                            Severity     ScriptName Line  Message
--------                            --------     ---------- ----  -------
Download cradle                     Error        suspicious 2     Download method called : DownloadString
                                                 .ps1
```

When several files are analysed, the error is repeated for each file.

## When the rules file cannot be read

A rules file that is missing, is not JSON or has no `rules` array stops the module from loading,
and the analysis stops: the module never falls back to other rules. PSScriptAnalyzer does not
show the reason:

```powershell
PS> $env:ASTRULEGENERATOR_CONFIG = Join-Path $PWD 'no-such-file.json'
PS> Invoke-ScriptAnalyzer -Path .\suspicious.ps1 -CustomRulePath .\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1
WARNING: Cannot find rule extension '...\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1'.
Invoke-ScriptAnalyzer: Cannot find ScriptAnalyzer rules in the specified path
```

Importing the module shows it:

```powershell
PS> Import-Module .\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1
Exception: Initialize-ASTRuleGenerator: configuration file '...\no-such-file.json' set by ASTRULEGENERATOR_CONFIG not found
```

The variable must hold an absolute path; a relative one is refused, because PSScriptAnalyzer does
not resolve it against your current folder:

```powershell
PS> $env:ASTRULEGENERATOR_CONFIG = 'my-rules.json'
PS> Import-Module .\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1
Exception: Initialize-ASTRuleGenerator: ASTRULEGENERATOR_CONFIG must hold an absolute path, not 'my-rules.json'.
```

## Skip reviewed files with an allow-list

A rules file may hold an `allowlist` section next to `rules`, with two optional lists:

| Key | Meaning |
| --- | --- |
| `FileNamePattern` | Wildcard patterns (`*`, `?`) compared with the **file name only**, not its folders, ignoring case. A pattern holding `\` or `/` is refused. |
| `Sha256` | SHA-256 hashes of files, as `Get-FileHash` gives them (64 hexadecimal characters, any case). |

A file on the list is not scanned. Instead, it gets one Warning finding that says why it was
skipped. A script given as a string (`-ScriptDefinition`) has no file and is always scanned.

> **Warning**: a file name pattern lets any file with a matching name escape scanning, wherever
> it is in the repository. Prefer hashes, which only skip the exact content that was reviewed.
> Keep the rules file out of the repository it scans, unless changes to it are protected (code
> owners, protected branch); otherwise the commit that adds a script can also allow-list it.

Here, the folder `scripts` holds `suspicious.ps1` and two reviewed scripts:
- `Build-Deploy.ps1` runs `Invoke-Expression`;
- `approved.ps1` calls `DownloadString`.

First, take the hash of the reviewed file:

```powershell
PS> Get-FileHash .\scripts\approved.ps1 | Select-Object Hash

Hash
----
9423FE946E215C7249EDA01551825D15C9E1B7946C30D6CB3A56E2624813A984
```

Then list it, and the build scripts by name, in `reviewed-rules.json`. It holds the same two
rules as `my-rules.json`:

```json
{
    "allowlist": {
        "FileNamePattern": ["Build-*.ps1"],
        "Sha256": ["9423FE946E215C7249EDA01551825D15C9E1B7946C30D6CB3A56E2624813A984"]
    },
    "rules": [ ... ]
}
```

```powershell
PS> $env:ASTRULEGENERATOR_CONFIG = Join-Path $PWD 'reviewed-rules.json'
PS> Invoke-ScriptAnalyzer -Path .\scripts -CustomRulePath .\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1

RuleName                            Severity     ScriptName Line  Message
--------                            --------     ---------- ----  -------
Allow-list                          Warning      approved.p 1     File skipped by the allow-list (SHA-256 9423FE946E215
                                                 s1               C7249EDA01551825D15C9E1B7946C30D6CB3A56E2624813A984)
Allow-list                          Warning      Build-Depl 1     File skipped by the allow-list (file name pattern
                                                 oy.ps1           'Build-*.ps1')
Download cradle                     Error        suspicious 2     Download method called : DownloadString
                                                 .ps1
Dynamic code                        Warning      suspicious 3     Code run from a string : Invoke-Expression
                                                 .ps1
```

Editing `approved.ps1` changes its hash, so it is scanned again until the new content is
reviewed and its new hash listed.

An invalid allow-list stops the module from loading, so that a mistake never skips other files
than intended:

```powershell
PS> $env:ASTRULEGENERATOR_CONFIG = Join-Path $PWD 'bad-allowlist-rules.json'
PS> Import-Module .\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1
Exception: Initialize-ASTRuleGenerator: rules file '...\bad-allowlist-rules.json' has an invalid allowlist: allowlist FileNamePattern 'Vendor\*.ps1' must be a file name pattern, without a path
```

## Files that Windows PowerShell 5.1 and PowerShell 7 read differently

Windows PowerShell 5.1 reads a script file without a byte order mark in the system's ANSI code
page (1252 on Western European Windows), while PowerShell 7 reads it as UTF-8. Some characters
then turn into quotes for 5.1: the UTF-8 bytes of `→`, read as code page 1252, end with `’`,
which PowerShell treats as a single quote. A line can be code for one edition and part of a
string for the other, so a scan under either edition can miss code the other one runs.

`notes.ps1`, saved as UTF-8 without a byte order mark:

```powershell
Write-Output 'Step 1 → step 2'
Invoke-Expression $payload
Write-Output 'Step 3 → done'
```

Under PowerShell 7, with the shipped rules:

```powershell
PS> Invoke-ScriptAnalyzer -Path .\scripts\notes.ps1 -CustomRulePath .\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1

RuleName                            Severity     ScriptName Line  Message
--------                            --------     ---------- ----  -------
Ambiguous file encoding             Error        notes.ps1  1     File read as different code by
                                                                  Windows PowerShell 5.1 (code page
                                                                  1252) and PowerShell 7 (UTF-8):
                                                                  save it as UTF-8 with a byte
                                                                  order mark (ATT&CK T1027)
Invoke-Expression call              Warning      notes.ps1  2     Code run from a string (ATT&CK
                                                                  T1059.001) : (?i)^\s*(?:iex|invoke
                                                                  -expression)\b
```

Under Windows PowerShell 5.1, line 2 is inside a string, so only the Error remains:

```powershell
PS> Invoke-ScriptAnalyzer -Path .\scripts\notes.ps1 -CustomRulePath .\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1

RuleName                            Severity     ScriptName Line  Message
--------                            --------     ---------- ----  -------
Ambiguous file encoding             Error        notes.ps1  1     File read as different code by
                                                                  Windows PowerShell 5.1 (code page
                                                                  1252) and PowerShell 7 (UTF-8):
                                                                  save it as UTF-8 with a byte
                                                                  order mark (ATT&CK T1027)
```

Saved as UTF-8 with a byte order mark, the file is read the same way by both editions, and the
Error goes away (here under PowerShell 7):

```powershell
PS> Set-Content -Path .\scripts\notes.ps1 -Value (Get-Content .\scripts\notes.ps1 -Raw -Encoding utf8) -Encoding utf8BOM -NoNewline
PS> Invoke-ScriptAnalyzer -Path .\scripts\notes.ps1 -CustomRulePath .\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1

RuleName                            Severity     ScriptName Line  Message
--------                            --------     ---------- ----  -------
Invoke-Expression call              Warning      notes.ps1  2     Code run from a string (ATT&CK
                                                                  T1059.001) : (?i)^\s*(?:iex|invoke
                                                                  -expression)\b
```

The check compares the tokens of both readings, so accented letters alone, or an arrow in a
comment, raise nothing. A script given as a string (`-ScriptDefinition`) has no file and is not
checked. Outside Windows, code page 1252 is assumed. To turn the check off, add
`"encodingcheck": "Disable"` to the rules file; any value other than `Enable` or `Disable` stops
the module from loading.

## Check every commit in GitLab CI

The [GitLab CI-CD sample](GitLab-CICD-Sample-Integration/README.md) runs the rules on the
PowerShell files of each commit on a Windows runner, and fails the job on any finding with the
Error severity, or when the analysis cannot run.

## Check every branch in Azure Pipelines

The [Azure DevOps CI-CD sample](AzureDevOPS-CICD-Sample-Integration/README.md) runs the rules on
the PowerShell files changed since the branch left `main`, on the Microsoft-hosted
`ubuntu-latest` agent, and fails the job on any finding with the Error severity, or when the
analysis cannot run. To check pull requests before they reach `main`, add the pipeline as a build
validation in the branch policy of `main`.
