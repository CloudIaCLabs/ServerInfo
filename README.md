ServerInfo PowerShell Module goal is to consolidate all commands used on daily basis in a re-usable format in one place so that they can be re-used and enhanced avoiding repeat re-writing of same scripts to accomplish daily tasks. <br/>
- Keep function format same where possible to promote functionality, security, learning, simplicity, readability  <br/>
- This module & functions were last tested in Microsoft Windows 2016 Server environment  <br/>

List of Functions in this Module: <br/>
Get-Uptime <br/>
Get-OSInfo  <br/>

Get-InstalledSoftware   <br/>
Get-Reboothistory <br/>
Get-Patchistory   <br/>



Example usage: <br/>
1) Get-Uptime <br/>
2) Get-Content servers.txt | Get-Uptime <br/>
3) Get-Content servers.txt | Get-Uptime | Export-Csv C:\Temp\test.csv <br/>


1) Get-OSInfo <br/>
2) Get-Content servers.txt | Get-OSInfo <br/>
3) Get-Content servers.txt | Get-OSInfo | Export-Csv C:\Temp\test.csv <br/>



Note: 
To find help for a function and its usage, please check

PS > Get-Help Get-InstalledSoftware

