ServerInfo PowerShell Module goal is to consolidate all commands used on daily basis in a re-usable format in one place so that they can be re-used and enhanced avoiding repeat re-writing of same scripts to accomplish same task. <br/>
- Keep function format same where possible to promote functionality, security, learning, simplicity, readability  <br/>
- This module & functions were tested in Microsoft Windows 2016 Server environment  <br/>

List of Functions in this Module: <br/>
Get-Uptime <br/>
Get-OSInfo  <br/>

Get-Reboothistory [Under Development ..] <br/>
Get-Patchistory   [Under Development ..]   <br/>



Example usage: <br/>
1) Get-Uptime <br/>
2) Get-Content servers.txt | Get-Uptime <br/>
3) Get-Content servers.txt | Get-Uptime | Export-Csv C:\Temp\test.csv <br/>


1) Get-OSInfo <br/>
2) Get-Content servers.txt | Get-OSInfo <br/>
3) Get-Content servers.txt | Get-OSInfo | Export-Csv C:\Temp\test.csv <br/>

