#Requires -Version 3.0

# Import configuration file
$script:configfile = 'Initialize-ASTRuleGenerator.json'
$script:configfilePath = Join-Path (Split-Path -Parent $PSCommandPath) $script:configfile
if (!(test-path $configfilePath)) {
    throw "configuration file $($script:configfile) missing in module folder"
} else {
    $moduleconfig = get-content $script:configfilePath | convertfrom-json
}

# Import Localized Data
# Explicit culture needed for culture that do not match when using PowerShell Core: https://github.com/PowerShell/PowerShell/issues/8219
if ([System.Threading.Thread]::CurrentThread.CurrentUICulture.Name -ne 'en-US')
{
    Import-LocalizedData -BindingVariable Messages -UICulture 'en-US'
}
else
{
    Import-LocalizedData -BindingVariable Messages
}
<#
.SYNOPSIS
    Function used to generate automatically PSScriptAnalyzer rules based on a JSON configuration file Initialize-ASTRuleGenerator.json
.DESCRIPTION
    Use this function to generate automatically PSScriptAnalyzer rules based on a JSON configuration file Initialize-ASTRuleGenerator.json
    This file must be hosted in the root folder of the module folder containing psm1/psd1 file.
    Each rule defined in the JSON file must have the following properties set :
    - Status : (string) value "Enable" or "Disable"
    - Name : (string) name of the rule
    - ASTType : (string) AST object to be used to build the predicate. Ex : "StringConstantExpressionAst" (more information here : https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.language.ast?view=powershellsdk-7.0.0)
    - ASTProperty : (string) property of the AST object to read and to be compared with your own value to match the rule. Ex : "value" (for StringConstantExpressionAst set as ASTType)
    - Operator : (string) powershell operator to be used to compare your search value to the ASTProperty. Ex : "eq" for equal / eq powershell operator.
    - SearchStringPattern : (array of string) your search pattern in string format. Ex : "*MyValue*" for a "like" operator set in "operator" property. You can set also a regex if you are using a "match" operator
    - SearchOtherPattern : (array of non string) your search pattern in non string format. Note : you must choose between SearchStringPattern and SearchOtherPattern property. When using "SearchOtherPattern" you can use sub method or property in "ASTProperty"
    - Message : (string) message shown in each rule result. Note : the SearchStringPattern value will also be shown automatically
    - Severity : (string) value "info" or "warning" or "error"

.EXAMPLE
    Measure-CustomASTRule -ScriptBlockAst $ScriptBlockAst
.INPUTS
    [System.Management.Automation.Language.ScriptBlockAst]
.OUTPUTS
    [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]]
.NOTES
    check the JSON sample file provided to learn about building your own rules
#>
function Measure-CustomASTRule {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )
    Process
    {
        $results = @()
        foreach ($rule in $moduleconfig.rules) {
            if ($rule.Status -eq "Enable") {
                try {
                    if ($rule.SearchStringPattern) {
                        foreach ($pattern in $rule.SearchStringPattern) {
                            $rulepredicatescriptblockasstring = "(`$args[0] -is [System.Management.Automation.Language.$($rule.ASTType)]) -and (`$args[0].$($rule.ASTProperty).tostring() -$($rule.Operator) `"$($pattern)`")"
                            $rulepredicatescriptblock = [Scriptblock]::Create($rulepredicatescriptblockasstring)
                            $rulepredicateresults = $ScriptBlockAst.findall($rulepredicatescriptblock, $true)
                            foreach ($item in $rulepredicateresults) {
                                $result = [Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]]@{
                                    "Message"  = "$($rule.Message) : $($pattern)"
                                    "Extent"   = $item.Extent
                                    "RuleName" = $rule.name
                                    "Severity" = $rule.Severity
                                }
                                $results += $result
                            }
                        }
                    } elseif ($rule.SearchOtherPattern) {
                        foreach ($pattern in $rule.SearchOtherPattern) {
                            $rulepredicatescriptblockasstring = "(`$args[0] -is [System.Management.Automation.Language.$($rule.ASTType)]) -and (`$args[0].$($rule.ASTProperty) -$($rule.Operator) $($pattern))"
                            $rulepredicatescriptblock = [Scriptblock]::Create($rulepredicatescriptblockasstring)
                            $rulepredicateresults = $ScriptBlockAst.findall($rulepredicatescriptblock, $true)
                            foreach ($item in $rulepredicateresults) {
                                $result = [Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]]@{
                                    "Message"  = "$($rule.Message) : $($pattern)"
                                    "Extent"   = $item.Extent
                                    "RuleName" = $rule.name
                                    "Severity" = $rule.Severity
                                }
                                $results += $result
                            }
                        }
                    }
                } catch {
                    $PSCmdlet.ThrowTerminatingError($PSItem)
                }
            }
        }
        if ($results) {
            return $results
        }
    }
}

Export-ModuleMember -Function Measure-CustomASTRule