![image](http://www.lucas-cueff.com/files/gallery.png)

# Initialize-ASTRuleGenerator - GitLab CI-CD sample integration
A simple integration sample of Initialize-ASTRuleGenerator as a dedicated job of a Gitlab repository / Gitlab CI-CD  
  
(c) 2021-2026 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).

## What the job does
- finds the PowerShell files (.ps1, .psm1, .psd1) changed by `CI_COMMIT_SHA`, compared with:
    - in a merge request pipeline, the base of the merge request diff (`CI_MERGE_REQUEST_DIFF_BASE_SHA`);
    - on a branch other than the default branch, its merge-base with the default branch: every commit of the branch is analysed, so a harmless push cannot hide an earlier harmful one;
    - on the default branch or a tag, the previous commit of the push (`CI_COMMIT_BEFORE_SHA`).
- analyses every PowerShell file of the repository in a scheduled or manual pipeline, and when there is no previous commit to compare with.
- runs PSScriptAnalyzer on each of them with the Initialize-ASTRuleGenerator rules. The `Security-PWSH-gitlab-ci` folder itself is never analysed.
- fails (exit code 1) when a finding has the Error severity, and also when the analysis cannot run (rule module that does not load, git that cannot compare the commits...): a security check that cannot run does not pass.
- counts findings a file suppresses for itself with a `SuppressMessageAttribute`: a scanned file cannot hide its own findings. They are logged as `Suppressed in the file, still counted`.
- writes `pwsh-security-psanalyzer.log` on every run, kept as the job artifact.

## Notes
- targets a Windows runner, with Windows PowerShell 5.1 or PowerShell 7.
- all external prerequisites are embedded :
    - Initialize-ASTRuleGenerator module
    - PSScriptAnalyzer PowerShell module (1.25.0)
    - Git windows client, used only when git is not installed on the runner. It is then unpacked into a folder under the system temp path, for the job only.
- GitLab clones shallow by default, with the pipeline's branch only. When the job needs more (the default branch, older commits), it runs `git fetch` from `origin` with the runner's own remote; if that fails, the job fails. `GIT_DEPTH: "0"` in `.gitlab-ci.yml` gives a full clone and saves part of that fetch.
- to use a rules file kept in your repository rather than the one in the module folder, set `ASTRULEGENERATOR_CONFIG` to its absolute path in `.gitlab-ci.yml` (see the commented example there).

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
