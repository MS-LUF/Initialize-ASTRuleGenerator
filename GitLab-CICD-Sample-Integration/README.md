![image](http://www.lucas-cueff.com/files/gallery.png)

# Initialize-ASTRuleGenerator - GitLab CI-CD sample integration
A simple integration sample of Initialize-ASTRuleGenerator as a dedicated job of a Gitlab repository / Gitlab CI-CD  
  
(c) 2021 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).

## Notes
### 0.5 - first public release - sample - beta version
- work on all runner type (Shell or Docker)
- All external prerequisites are embedded :
    - Initialize-ASTRuleGenerator module
    - Git windows client (used to get file name linked to the commit)
    - PSScriptAnalyzer PowerShell module

## Sample installation
### Prerequisites
- Gitlab repository available
- Windows runner available (shared or dedicated)
- CI-CD pipeline defined

### Installation
- Copy folder **Security-PWSH-gitlab-ci** at the root of your GitLab repository
  - Download each source required in each subfolders (see **source.txt** file for more information in each subfolder)
- Copy file **sec-pwsh-analysis-malicious.ps1** at the root of your GitLab repository
- Edit your **.gitlab-ci.yml** file and add the sample content available in my **.gitlab-ci.yml**
    - add the new stage
    - copy the **repository_based_script_on_windows** section
    - edit the **repository_based_script_on_windows** pasted section and update **tags** to set your own runner tag
