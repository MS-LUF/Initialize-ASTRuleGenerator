
#
## Created by: lucas.cueff[at]lucas-cueff.com
#
## released on 12/2021
#
# v0.5 - first public release - beta version - sample script that can be used on a Gitlab CI-CD context (dedicated gitlab job) to analyse all commit concerning pwsh.
# 
#'(c) 2021 lucas-cueff.com - Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).'

#_____________________________________________________________________________________________________
# Define functions
Function Get-ScriptDirectory {
	[cmdletbinding()]
	Param ()
	if ($psISE) {
        $ScriptPath = Split-Path -Parent $psISE.CurrentFile.FullPath
    } elseif($PSVersionTable.PSVersion.Major -gt 3) {
        $ScriptPath = $PSScriptRoot
    } else {
        $ScriptPath = split-path -parent $MyInvocation.MyCommand.Path
    }
	$ScriptPath
}
Function Write-Log {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [ValidateSet("info", "warning", "error")]
            [string]$info,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [string]$file = $global:fulllogpath,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
            [string]$message
    )
    if (!(test-path $file)) {
        New-Item -ItemType File -Path $file | out-null
        Add-Content -Path $file -value "INFO : File created on : $((get-date).ToString())"
    }
    Add-content -Path $file -value "$($info) : $($message)"
    write-verbose "$($info) : $($message)"
    if ($info -eq "warning") {
        write-warning -message $message
    }
    if ($info -eq "error") {
        write-error -message $message
    }
}
#_____________________________________________________________________________________________________
# Define log
$logpath = join-path ($env:temp) $CI_PROJECT_NAME
if (!(test-path $logpath)) {
    New-Item -ItemType Directory -Path $logpath | out-null
}
$timefile = (get-date).ticks.tostring()
$logfile = "sec_pwsh_malicious_$($CI_PROJECT_NAME)_$($GITLAB_USER_LOGIN)_$($timefile).log"
$global:fulllogpath = join-path $logpath $logfile

#_____________________________________________________________________________________________________
# import PSScriptAnalyzer module and define custom script analyzer module
try {
    import-module (join-path (Get-ScriptDirectory) "Security-PWSH-gitlab-ci\PSScriptAnalyzer\PSScriptAnalyzer.psd1")
} catch {
    throw "not able to load $(Get-ScriptDirectory)\Security-PWSH-gitlab-ci\PSScriptAnalyzer\PSScriptAnalyzer.psd1"
}
$custommodule = join-path (Get-ScriptDirectory) "Security-PWSH-gitlab-ci\Initialize-ASTRuleGenerator\Initialize-ASTRuleGenerator.psd1"
#_____________________________________________________________________________________________________

Write-Log -info info -message "Scenario running : $($SCENARIO)" -Verbose
Write-Log -info info -message "Commit user : $($GITLAB_USER_LOGIN)" -Verbose
Write-Log -info info -message "Project : $($CI_PROJECT_NAME)" -Verbose
Write-Log -info info -message "Commit Message : $($CI_COMMIT_MESSAGE)" -Verbose
Write-Log -info info -message "Commit Branch : $($CI_COMMIT_BRANCH)" -Verbose
Write-Log -info info -message "Commit Before SHA : $($CI_COMMIT_BEFORE_SHA)" -Verbose
Write-Log -info info -message "Commit SHA : $($CI_COMMIT_SHA)" -Verbose

if (test-path "$($env:ProgramFiles)\Git\bin\git.exe") {
    $outputgitdiff =  & "$($env:ProgramFiles)\Git\bin\git.exe" diff --name-only $CI_COMMIT_BEFORE_SHA $CI_COMMIT_SHA
} elseif (test-path "$(${env:ProgramFiles(x86)})\Git\bin\git.exe") {
    $outputgitdiff =  & "$(${env:ProgramFiles(x86)})\Git\bin\git.exe" diff --name-only $CI_COMMIT_BEFORE_SHA $CI_COMMIT_SHA
} else {
    Write-Log -info warning -message "not able to find git.exe on runnner, copying git Windows client locally" -Verbose
    if (!(test-path "c:\Tools")) {
        new-item -ItemType Directory -Path "c:\tools" -force
    }
    Expand-Archive -Path (join-path (Get-ScriptDirectory) "Security-PWSH-gitlab-ci\GitClient\GitSource.zip") -DestinationPath "c:\tools" -force
    $outputgitdiff =  & "c:\Tools\bin\git.exe" diff --name-only $CI_COMMIT_BEFORE_SHA $CI_COMMIT_SHA
}
$results = @()
if ($outputgitdiff) {
    foreach ($entry in $outputgitdiff) {
        Write-Log -info info -message "Commit File found : $($entry)" -Verbose
        if ($entry -like "*.ps*") {
            if (test-path (join-path (Get-ScriptDirectory) $entry)) {
                Write-Log -info info -message "Looking for PWSH malicious code in $(join-path (Get-ScriptDirectory) $entry)" -Verbose
                $results +=  Invoke-ScriptAnalyzer -Path (join-path (Get-ScriptDirectory) $entry) -CustomRulePath $custommodule
            }
        }
    }
}
if ($results) {
    Write-Log -info info -message "PsScriptAnalyzer reports generation."
    foreach ($result in $results) {
        Write-Log -info warning -message "$($result.ScriptName) - $($result.Severity) : $($result.RuleName) - $($result.message) - $($result.line)"
    }
    if ($results.Severity -contains "error") {
        Write-Log -info error -message "Potential PWSH malicious code found in commit files - exit job with error" -Verbose
        $customexitcode = -1
    } else {
        $customexitcode = 0
    }
    write-log -info info -message "Copy current log $($global:fulllogpath) to pwsh-security-psanalyzer.log" -Verbose
    if (test-path (join-path (Get-ScriptDirectory) "pwsh-security-psanalyzer.log")) {
        remove-item -Force -Path (join-path (Get-ScriptDirectory) "pwsh-security-psanalyzer.log")
    }
    copy-item -Path $global:fulllogpath -Destination (join-path (Get-ScriptDirectory) "pwsh-security-psanalyzer.log") -Force
    exit $customexitcode
}