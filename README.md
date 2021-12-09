![image](http://www.lucas-cueff.com/files/gallery.png)

# Initialize-ASTRuleGenerator
generate automatically simple PSScriptAnalyzer rules based on a JSON configuration file Initialize-ASTRuleGenerator.json

(c) 2021 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).

## Notes version :
### 0.5 - first public release - beta version
 - generate automatically **PSScriptAnalyzer** rules based on a JSON configuration file **Initialize-ASTRuleGenerator.json**. This file must be hosted in the root folder of the module folder containing psm1/psd1 file.

## Why this module ?
If you need to build a lot of PSScriptAnalyzer rules which are basics, whatever the purpose (syntax optimization, coding rule verification, security check...) ==> it could be useful. Indeed, instead of managing multiples PSM1 including your static rules you can use this rule engine with a JSON config file :-)
For instance you can easily backport security IoC into basic rules to detect malicious powershell content...

## How-to
### prerequisites
- update **PSScriptAnalyzer** module
```
	C:\PS> update-module PSScriptAnalyzer -scope allusers -force
```
- build your own **Initialize-ASTRuleGenerator.json** JSON configuration file
#### build your config file
- each rule defined in the JSON file must have the following properties set :
    - Status : (string) value "Enable" or "Disable"
    - Name : (string) name of the rule
    - ASTType : (string) AST object to be used to build the predicate. Ex : "StringConstantExpressionAst" (more information [here](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.language.ast?view=powershellsdk-7.0.0))
    - ASTProperty : (string) property of the AST object to read and to be compared with your own value to match the rule. Ex : "value" (for StringConstantExpressionAst set as ASTType)
    - Operator : (string) powershell operator to be used to compare your search value to the ASTProperty. Ex : "eq" for equal / eq powershell operator.
    - SearchStringPattern : (array of string) your search pattern in string format. Ex : "*MyValue*" for a "like" operator set in "operator" property. You can set also a regex if you are using a "match" operator
    - SearchOtherPattern : (array of non string) your search pattern in non string format. Note : you must choose between SearchStringPattern and SearchOtherPattern property. When using "SearchOtherPattern" you can use sub method or property in "ASTProperty"
    - Message : (string) message shown in each rule result. Note : the SearchStringPattern value will also be shown automatically
    - Severity : (string) value "info" or "warning" or "error"
- see sample JSON file embedded for more information
### use module from PowerShell with PSScriptAnalyzer
```
	C:\PS> Invoke-ScriptAnalyzer -Path C:\myscript.ps1 -CustomRulePath C:\Initialize-ASTRuleGenerator.psd1
```
 
## Function
 - Measure-CustomASTRule