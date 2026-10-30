![image](http://www.lucas-cueff.com/files/gallery.png)

# Initialize-ASTRuleGenerator - Azure DevOps CI-CD sample integration
A simple integration sample of Initialize-ASTRuleGenerator as a dedicated job of an Azure DevOps (Azure Repos) repository / Azure Pipelines

(c) 2021-2026 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).

## What the job does
- finds the PowerShell files (.ps1, .psm1, .psd1) added or changed on the branch: between the tested commit and the point where the branch left `main`, so every commit of the branch is analysed, not only the last one of a push. A pull request build compares the merge commit with the target branch.
- runs PSScriptAnalyzer on each of them with the Initialize-ASTRuleGenerator rules. The `Security-PWSH-ADO-ci` folder itself is never analysed.
- fails (exit code 1) when a finding has the Error severity, and also when the analysis cannot run (rule module that does not load, shallow checkout, `main` missing from the checkout...): a security check that cannot run does not pass.
- writes `pwsh-security-psanalyzer.log` on every run; when the job fails, the log is published as the `sec-pwsh-analysis-failure-log` build artifact.

## Notes
- runs on the Microsoft-hosted `ubuntu-latest` agent, with its PowerShell 7 and git. The script also runs under Windows PowerShell 5.1 and PowerShell 7 on a Windows agent with git.
- all external prerequisites are embedded :
    - Initialize-ASTRuleGenerator module
    - PSScriptAnalyzer PowerShell module (1.25.0, the version the script requires: change `-PSScriptAnalyzerVersion` if you bundle another one)
- the checkout needs the full history (`fetchDepth: 0` in `azure-pipelines.yml`), so that `origin/main` and the branch history are there. No credentials are kept in the checkout.
- the stage is skipped on `main` itself. If your base branch has another name, change the stage condition and `-BaseBranch` in `azure-pipelines.yml`.
- to use a rules file kept in your repository rather than the one in the module folder, set `ASTRULEGENERATOR_CONFIG` to its absolute path in `azure-pipelines.yml` (see the commented example there).
- to analyse pull requests before they reach `main`, add this pipeline as a build validation in the branch policy of `main`.
- the job script, the rules and the tools are in the repository it analyses, so a branch can change them. To prevent that, keep them in a separate, protected repository and run them from an extends template, with a Required template check.

## Sample installation
### Prerequisites
- Azure DevOps repository available (Azure Repos Git)
- Azure Pipelines available, with the Microsoft-hosted agents (or a self-hosted agent with PowerShell 7 and git)

### Installation
- Copy folder **Security-PWSH-ADO-ci** at the root of your repository
  - Download each source required in each subfolder (see **source.txt** file for more information in each subfolder)
- Copy file **sec-pwsh-analysis-malicious.ps1** at the root of your repository
- Copy file **azure-pipelines.yml** at the root of your repository (or add its stage to your own pipeline)
    - check the base branch name (`main`) in the stage condition and in `-BaseBranch`
- In Azure Pipelines, create a pipeline from the existing **azure-pipelines.yml** file of your repository
