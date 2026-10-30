---
external help file: Initialize-ASTRuleGenerator-help.xml
Module Name: Initialize-ASTRuleGenerator
online version:
schema: 2.0.0
---

# Measure-CustomASTRule

## SYNOPSIS
Applies the rules declared in a JSON rules file to a script, as a PSScriptAnalyzer custom rule.

## SYNTAX

```
Measure-CustomASTRule [-ScriptBlockAst] <ScriptBlockAst> [<CommonParameters>]
```

## DESCRIPTION
Runs the simple rules declared in a JSON rules file on each script PSScriptAnalyzer analyses with this module as a custom rule path.
It returns one finding for each part of the script that a rule matches.
A finding is named after the rule, and its message is the rule's message followed by the pattern that matched.

The rules file is Initialize-ASTRuleGenerator.json in the module folder.
To use another file, set the environment variable ASTRULEGENERATOR_CONFIG to its absolute path.
A rules file that is missing, is not JSON or has no rules array stops the module from loading: PSScriptAnalyzer then reports that it cannot find the rules, and Import-Module on the module manifest shows the reason.
The file is read again by every analysis, so an edit is used by the next run.

Each rule has a Status (Enable or Disable), a Name, an ASTType, an ASTProperty, an Operator, a Message, a Severity (info, warning or error), and either SearchStringPattern or SearchOtherPattern.
Only rules whose Status is Enable run.
A rule may also have a MinimumCount: it then reports its findings only when the script holds at least that many of them, which makes a weak signal useful when it is repeated.

ASTType is the name of a class of the System.Management.Automation.Language namespace, for example StringConstantExpressionAst or CommandAst.
ASTProperty is a property of that class, or a path of properties separated by dots, for example Right.Extent.Text.
The step tostring() converts the value to text, as in Right.tostring().length.
No other method call is allowed.

Operator is a PowerShell comparison operator without its hyphen: eq, ne, like, notlike, match, notmatch, gt, ge, lt, le, contains, notcontains, in or notin, or its case-sensitive form starting with c, for example cmatch.

SearchStringPattern lists values compared with the text of the property, such as wildcard patterns for like or regular expressions for match.
SearchOtherPattern lists values compared with the property as it is, such as numbers.
When a rule has both, SearchStringPattern is used.

The rules file may also hold an allowlist section with two lists: FileNamePattern, wildcard patterns compared with the file name only (not its folders), ignoring case, and Sha256, the hashes of files as Get-FileHash gives them.
A file on the list is not scanned; it gets one Warning finding that says why.
A script given as a string has no file and is always scanned.
An invalid allowlist stops the module from loading.
Warning: a file name pattern lets any file with a matching name escape scanning, wherever it is.
Prefer hashes, and keep the rules file out of the repository it scans unless that file is protected.

Windows PowerShell 5.1 reads a script file without a byte order mark in the system's ANSI code page, while PowerShell 7 reads it as UTF-8.
With some non-ASCII characters, such as an arrow or a dash, the two editions then see different code, and code can be hidden inside a string for one of them.
Such a file gets one Error finding named Ambiguous file encoding; saving it as UTF-8 with a byte order mark removes the ambiguity.
Outside Windows, code page 1252 is assumed.
Set encodingcheck to Disable in the rules file to turn this check off; any value other than Enable or Disable stops the module from loading.

Every value of a rule is used as data, never run as code.
A rule that breaks these requirements is skipped and reported as a non-terminating error, once for each file analysed, and the other rules still run.

## EXAMPLES

### EXAMPLE 1
```
Invoke-ScriptAnalyzer -Path .\MyScript.ps1 -CustomRulePath .\Initialize-ASTRuleGenerator.psd1
```

Runs the enabled rules of the rules file in the module folder on MyScript.ps1, together with the rules of PSScriptAnalyzer itself.

### EXAMPLE 2
```
$env:ASTRULEGENERATOR_CONFIG = 'C:\Rules\my-rules.json'; Invoke-ScriptAnalyzer -Path .\MyScript.ps1 -CustomRulePath .\Initialize-ASTRuleGenerator.psd1
```

Runs the enabled rules of C:\Rules\my-rules.json instead of the rules file in the module folder.

## PARAMETERS

### -ScriptBlockAst
The syntax tree of the script being analysed.
PSScriptAnalyzer passes it when it runs the rule.

```yaml
Type: ScriptBlockAst
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]
## NOTES
The rules file shipped with the module holds enabled rules that detect common PowerShell threats and obfuscation, each naming its MITRE ATT&CK technique.
Rules with the Error severity are the ones that showed no false positive on a corpus of legitimate modules.
Disable or change rules in that file, or write your own file.

## RELATED LINKS
