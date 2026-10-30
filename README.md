![image](https://www.lucas-cueff.com/files/gallery.png)

# Initialize-ASTRuleGenerator
A PSScriptAnalyzer custom rule module that turns simple rules, declared in a JSON file, into checks on the syntax tree (AST) of your PowerShell scripts. A rule is an AST class, a property, a PowerShell comparison operator and a list of patterns: enough to write many basic checks without a PowerShell rule module per check, for example to detect IoCs or malicious code in a CI pipeline.

(c) 2021-2026 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).

## Function
| Function | What it does |
| --- | --- |
| `Measure-CustomASTRule` | The rule PSScriptAnalyzer runs: applies the rules of the JSON rules file to each script analysed. See [Docs](Docs/Measure-CustomASTRule.md). |

## Install
- Windows PowerShell 5.1 or PowerShell 7, and PSScriptAnalyzer (tested with 1.25.0): `Install-Module PSScriptAnalyzer -Scope CurrentUser`.
- Copy the module folder (`Initialize-ASTRuleGenerator.psd1`, `.psm1`, `.json`, and the `Public`, `Private` and `en-US` folders) where you keep your modules or your analysis tools.

## Quick start
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
The rules file and the script of this example, the rule properties and the error cases are in [HowTo.md](HowTo.md).

## Good to know
- The rules are read from `Initialize-ASTRuleGenerator.json` in the module folder, unless `ASTRULEGENERATOR_CONFIG` holds the absolute path of another file.
- The shipped file holds 41 enabled rules: PowerShell threats (AMSI and Defender tampering, encoded or hidden PowerShell, PowerShell 2 downgrade, download and run, suspicious URLs, reflective loading, code injection, credential dumping, deleted backups, cleared logs, persistence) and obfuscation (backticks, characters picked from variables, reordered format strings, many `[char]` casts...). Each message names its MITRE ATT&CK technique. Only rules that raised no finding on 453 files of legitimate modules have the Error severity; disable or change rules in the file to suit you.
- A rule can have a `MinimumCount`: it then reports only when the script holds at least that many matches.
- An optional `allowlist` section in the rules file skips files by file name pattern or by SHA-256 hash; each skipped file leaves one Warning finding. **A file name pattern lets any file with a matching name escape scanning**: prefer hashes, and keep the rules file out of the repository it scans unless it is protected. See [HowTo.md](HowTo.md).
- Windows PowerShell 5.1 reads a script without a byte order mark in the ANSI code page, PowerShell 7 as UTF-8: with characters such as `→` or `—`, they can see different code. Such a file gets an Error finding, `Ambiguous file encoding`; save it as UTF-8 with a byte order mark. See [HowTo.md](HowTo.md).
- Rule values are used as data, never run as code. An invalid rule is skipped and reported as an error; the other rules still run.
- A rules file that cannot be read stops the analysis with "Cannot find ScriptAnalyzer rules in the specified path"; `Import-Module` on the manifest shows why.
- `Get-Help Measure-CustomASTRule` needs PSScriptAnalyzer to be loaded first.
- A [GitLab CI-CD sample](GitLab-CICD-Sample-Integration/README.md) checks the PowerShell files of every commit.
- An [Azure DevOps CI-CD sample](AzureDevOPS-CICD-Sample-Integration/README.md) checks the PowerShell files changed on every branch.

## Change log
- **1.1.0** - first stable release, no longer a beta; the version follows the release tags. Same behaviour as 0.12.0.
- **0.12.0** - new Error finding, `Ambiguous file encoding`, for a file without a byte order mark that Windows PowerShell 5.1 and PowerShell 7 read as different code, which can hide code from a scan; turn it off with `"encodingcheck": "Disable"` in the rules file.
- **0.11.0** - 9 new shipped rules: reflective assembly load, execution policy weakened, PowerShell 2 downgrade (Error), logging policy values, paste-host, GitHub raw and bare-IP URLs, hex decoding, hidden `Start-Process`; "Hidden or policy-bypassing PowerShell" also catches `-ep bypass`. Results change for anyone using the shipped file.
- **0.10.0** - optional `allowlist` section in the rules file: files whose name matches a wildcard pattern, or whose SHA-256 is listed, are skipped with a Warning finding; an invalid allow-list stops the module from loading.
- **0.9.0** - the shipped sample rules, too noisy to gate a pipeline, are replaced by 32 enabled rules detecting PowerShell threats and obfuscation, each naming its ATT&CK technique; new optional `MinimumCount` per rule. Results change for anyone using the shipped file.
- **0.8.1** - help rewritten, and published in `Docs` (markdown) and `en-US` (Get-Help). No change in behaviour.
- **0.8.0** - `ASTRULEGENERATOR_CONFIG` can name another rules file, by absolute path; a rules file that is missing, is not JSON or has no rules array stops the module from loading; the rules file is read again by every analysis.
- **0.7.0** - rule values are used as data, never run as code (ASTProperty: property names separated by dots plus `tostring()`; Operator: supported comparison operators only); an invalid rule is skipped and reported instead of stopping the analysis; same results for the sample rules, faster.
- **0.6.0** - requires PowerShell 5.1 or later; one file per function, explicit exports; rules and results unchanged.
- **0.5** - first public release (beta): PSScriptAnalyzer rules generated from the JSON file `Initialize-ASTRuleGenerator.json` in the module folder.
