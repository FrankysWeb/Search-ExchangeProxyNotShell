write-host "
------------------------------------------------------
Checking for suspicious files...
------------------------------------------------------
"

$SuspiciousFiles = @(
"C:\root\DrSDKCaller.exe",
"C:\Users\Public\all.exe",
"C:\Users\Public\dump.dll",
"C:\Users\Public\ad.exe",
"C:\PerfLogs\gpg-error.exe",
"C:\PerfLogs\cm.exe",
"C:\Program Files\Common Files\system\ado\msado32.tlb"
)

foreach ($SuspiciousFile in $SuspiciousFiles) {
	if (test-path $SuspiciousFile) {
		write-host "Suspicious File $SuspiciousFile found!" -foregroundcolor red
	}
	else {
		write-host "Suspicious File $SuspiciousFile not found!" -foregroundcolor green
	}
}

write-host "
------------------------------------------------------
Checking IIS Logs for IOCs... (this can take some time)
------------------------------------------------------
"
Import-Module WebAdministration
$IISLogdir = (get-item "IIS:\Sites\Default Web Site").logfile.directory
if ($IISLogdir -match "%SystemDrive%") {
	$IISLogdir = $IISLogdir.replace("%SystemDrive%","c:")
}
$IOCs = Get-ChildItem -Recurse -Path $IISLogdir -Filter "*.log" | Select-String -Pattern 'powershell.*autodiscover\.json.*\@.*200'
if ($IOCs) {
	write-host "IOC powershell.*autodiscover\.json.*\@.*200 found in IIS Logs" -foregroundcolor red
}
else {
	write-host "IOC powershell.*autodiscover\.json.*\@.*200 not found in IIS Logs" -foregroundcolor green
}
write-host "
------------------------------------------------------
Checking for WebShells...
------------------------------------------------------
"
$Webshell1 = [PSCustomObject]@{
	ID = 1
    Name = "FrontEnd\HttpProxy\owa\auth\pxh4HG1v.ashx"
    Hash = "c838e77afe750d713e67ffeb4ec1b82ee9066cbe21f11181fd34429f70831ec1"
}
$Webshell2 = [PSCustomObject]@{
	ID = 2
    Name = "FrontEnd\HttpProxy\owa\auth\RedirSuiteServiceProxy.aspx"
    Hash = "65a002fe655dc1751add167cf00adf284c080ab2e97cd386881518d3a31d27f5"
}
$Webshell3 = [PSCustomObject]@{
	ID = 3
    Name = "FrontEnd\HttpProxy\owa\auth\RedirSuiteServiceProxy.aspx"
    Hash = "b5038f1912e7253c7747d2f0fa5310ee8319288f818392298fd92009926268ca"
}
$Webshell4 = [PSCustomObject]@{
	ID = 4
    Name = "FrontEnd\HttpProxy\owa\auth\errorEE.aspx"
    Hash = "be07bd9310d7a487ca2f49bcdaafb9513c0c8f99921fdf79a05eaba25b52d257"
}
[System.Collections.ArrayList]$WebShellArray = @()
$WebShellArray.Add($Webshell1) | out-null
$WebShellArray.Add($Webshell2) | out-null
$WebShellArray.Add($Webshell3) | out-null
$WebShellArray.Add($Webshell4) | out-null

foreach ($WebShell in $WebShellArray) {
	$WebshellPath = "$exinstall" + $WebShell.Name
	if (test-path $WebshellPath) {
		$FileHash = (Get-FileHash $WebshellPath).Hash.ToLower()
		if ($Webshell.Hash -eq $FileHash) {
			write-host "WebShell File $WebshellPath found!" -foregroundcolor red
		}
		else {
			write-host "WebShell File $WebshellPath not found!" -foregroundcolor green
		}
	}
	else {
		write-host "WebShell File $WebshellPath not found!" -foregroundcolor green
	}
}