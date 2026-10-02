# IDM_Trial_Reset_IAS
Run PowerShell as Administrator and use the command below:
$tmp = "$env:TEMP\ias.cmd"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AliDbg/IDM_Trial_Reset_IAS/refs/heads/main/IDM_TrialReset_IAS.cmd" -OutFile $tmp; Start-Process cmd.exe -ArgumentList "/c $tmp" -Wait; Remove-Item $tmp
