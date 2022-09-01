﻿$Date = Get-Date -Format "yyyyMMddhhmmss"
$SummaryLog = ("C:\Temp\ServerInfo_errors_" + $Date +".txt")

function Get-OSInfo {
[CmdletBinding()]
    param(
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage="This. Computer. Name.")]
        [Alias('HostName','cn')]
        [String[]]$ComputerName = $Env:ComputerName,
        
        [Parameter()]
        [String]$ErrorLogFilePath=$SummaryLog
    )

    BEGIN{
        Remove-Item -Path $ErrorLogFilePath -Force -ErrorAction SilentlyContinue
        $ErrorsHappened = $False
    }

    PROCESS{
        Write-Verbose "HERE WE GO!!!"
        foreach ($computer in $ComputerName) {
            try{
            Write-Verbose "-------------------------------"
            Write-Verbose "Retrieving data from $Computer"
            
            $session = New-CimSession -ComputerName $Computer –SessionOption (New-CimSessionOption –Protocol DCOM) -ErrorAction Stop
            $os = Get-CimInstance -ClassName win32_OperatingSystem -CimSession $session
            $cs = Get-CimInstance -ClassName win32_ComputerSystem -CimSession $session 
            
            $properties = @{ComputerName = $Computer
                            Status = 'Connected'
                            OSVersion = $os.caption
                            Model = $cs.model
                            mfgr = $cs.Manufacturer }
                
            
               }  catch {
                    
                    Write-Verbose "Couldn't Connect to $Computer"
                    $Computer | out-File $ErrorLogFilePath -Append
                    $ErrorsHappened = $True
                    $properties = @{ComputerName = $Computer
                            Status = 'Disconnected'
                            OSVersion = $null
                            Model =$null
                            mfgr =$null}

                     } finally {
                    
                        $obj = New-Object -TypeName PSObject -Property $properties
                        $obj.psobject.typenames.insert(0,'ServerInfo.Custom.Objectfmt0')
                        Write-Output $obj
                                     
                        } #End finally
            

         }# End foreach

     } #End PROCESS    
         
         END{
            if($ErrorsHappened){
             Write-Warning "Errors Logged to $ErrorLogFilePath"
            }
         
         }

          
  } # End function


function Get-Uptime {
[CmdletBinding()]
    param(
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage="This. Computer. Name.")]
        [Alias('HostName','cn')]
        [String[]]$ComputerName = $Env:ComputerName,
        
        [Parameter()]
        [String]$ErrorLogFilePath=$SummaryLog
    )

    BEGIN{
        Remove-Item -Path $ErrorLogFilePath -Force -ErrorAction SilentlyContinue
        $ErrorsHappened = $False
        $CurrentDate = Get-Date
    }

    PROCESS{
        Write-Verbose "HERE WE GO!!!"
        foreach ($computer in $ComputerName) {
            try{
            Write-Verbose "-------------------------------"
            Write-Verbose "Retrieving data from $Computer"
            
            New-CimSession -ComputerName $Computer –SessionOption (New-CimSessionOption –Protocol DCOM) -ErrorAction Stop
            $bootuptime = (Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer).LastBootUpTime
       
            $time = $CurrentDate - $bootuptime

            $Properties = [Ordered] @{ ComputerName = $Computer
                                   Status = "Connected"
                                   Days = $time.Days
                                   Hours = $time.Hours
                                   Minutes = $time.Minutes
                                   Seconds = $time.Seconds
                                   }
                
            
               }  catch {
                    
                    Write-Verbose "Couldn't Connect to $Computer"
                    $Computer | out-File $ErrorLogFilePath -Append
                    $ErrorsHappened = $True
                    $Properties = [Ordered] @{ ComputerName = $Computer
                                   Status = "Psh_WinRM_Connection_Failed"
                                   Days = $null
                                   Hours = $null
                                   Minutes = $null
                                   Seconds = $null
                                   }

                     } finally {
                    
                        $obj = New-Object -TypeName PSObject -Property $properties
                        $obj.psobject.typenames.insert(0,'ServerInfo.Custom.Objectfmt1')
                        Write-Output $obj
                                     
                        } #End finally
            

         }# End foreach

     } #End PROCESS    
         
         END{
            if($ErrorsHappened){
             Write-Warning "Errors Logged to $ErrorLogFilePath"
            }
         
         }

          
  } # End function
  
  
<#
.Synopsis
    This is a function to fetch reboot history

.DESCRIPTION
    This is a function to fetch reboot history of a server or list of servers

.EXAMPLE

    PS> Get-RebootHistory
    Fetches reboot history of localhost

.EXAMPLE

    PS>  Get-RebootHistory -ComputerName (get-content servers.txt) -DaysFromToday 7 -MaxEvents 3 |ft

.LINK


#>

function Get-RebootHistory {

[CmdletBinding()]
    param(
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage="This. Computer. Name.")]
        [Alias('HostName','cn')]
        [String[]]$ComputerName = $Env:ComputerName,
        
        [Parameter()]
        [String]$ErrorLogFilePath=$SummaryLog,
        [int]     $DaysFromToday = 7,
        [int]     $MaxEvents = 999
    )

    BEGIN{
            #Remove-Item -Path C:\Temp\ServerInfo*.log -Force -Recurse -ErrorAction SilentlyContinue
            $ErrorsHappened = $False
            $Result=@()
         }

    PROCESS{
        Write-Verbose "HERE WE GO!!!"
        foreach ($computer in $ComputerName) {
            $Computer = $Computer.trim()
            try{
            Write-Verbose "-------------------------------"
            Write-Verbose "Retrieving data from $Computer"
            New-CimSession -ComputerName $Computer –SessionOption (New-CimSessionOption –Protocol DCOM) -ErrorAction Stop | out-null
            $EventList = Get-WinEvent -ComputerName $Computer -FilterHashtable @{
                    Logname = 'system'
                    Id = '1074', '6008'
                    StartTime = (Get-Date).AddDays(-$DaysFromToday)
                    } -MaxEvents $MaxEvents -ErrorAction Stop
             if ($null -ne $EventList ){
             @(foreach ($Event in $EventList){
                    if ($Event.ID -eq 1074){
             $Properties = [Ordered]@{
                       ComputerName = $Computer
                       EventID = $Event.ID
                       TimeStamp = $Event.TimeCreated
                       UserName = $Event.Properties.Value[6]
                       ShutdownType = $Event.Properties.Value[4]
                    }
                $Objoutput = New-Object -TypeName PSObject -Property $Properties
                $Result += $Objoutput
  
                   }elseif($Event.ID -eq 6008){
              $Properties = [Ordered]@{
                       ComputerName = $Computer
                       EventID = $Event.ID
                       TimeStamp = $Event.TimeCreated
                       UserName = $null
                       ShutdownType = 'unexpected shutdown'
                    }
                $Objoutput = New-Object -TypeName PSObject -Property $Properties
                $Result += $Objoutput
                   }
               
                })
              }else{
                    Write-Verbose "Entered Connected Hosts Section"
                   $Properties = [Ordered]@{
                       ComputerName = $Computer
                       EventID = 'NoRecentEventsFound'
                       TimeStamp = $null
                       UserName = $null
                       ShutdownType = $null
                    }
                
                $Objoutput = New-Object -TypeName PSObject -Property $Properties
                $Result += $Objoutput
              
              }
           
               }  catch {
                    
                    Write-Verbose "Couldn't Connect to $Computer"
                    $ErrorsHappened = $True
                    Write-Verbose "Entered Disconnected Hosts Section"
                    $timestmp = Get-Date -Format "yyyy-MM-dd-hhmmss"
                    "$timestmp Get-RebootHistory@ServerInfo RemoteConnectionFailed $Computer" | out-File $ErrorLogFilePath -Append
                   $Properties = [Ordered]@{
                       ComputerName = $Computer
                       EventID = $null
                       TimeStamp = $null
                       UserName = $null
                       ShutdownType = $null
                       }

                $Objoutput = New-Object -TypeName PSObject -Property $Properties
                $Result += $Objoutput

                     } finally {
                    
                                 Write-output $Result
                                 $Result=@()
                                     
                               } #End finally

         }# End foreach

     } #End PROCESS    
         
         END{
            if($ErrorsHappened){
            # Write-Warning "Errors Logged to $ErrorLogFilePath"
             Write-Warning "Errors Logged to $ErrorLogFilePath"
            }
         
         }

          
  } # End function


<#
.Synopsis
    This is a function to fetch recent patch summary

.DESCRIPTION
    This is a function to fetch recent patch summary of a server or list of servers

.EXAMPLE

    PS> Get-PatchSummary
    Fetches patch summary of localhost

.EXAMPLE

    PS>  Get-PatchSummary -ComputerName (get-content servers.txt) -DaysFromToday 40  |ft

.LINK


#>
function Get-PatchSummary {
[CmdletBinding()]
    param(
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage="This. Computer. Name.")]
        [Alias('HostName','cn')]
        [String[]]$ComputerName = $Env:ComputerName,
        
        [Parameter()]
        [String]$ErrorLogFilePath=$SummaryLog,
        [int]     $DaysFromToday = 30
    )

    BEGIN{
            #Remove-Item -Path C:\Temp\ServerInfo*.log -Force -Recurse -ErrorAction SilentlyContinue
            $ErrorsHappened = $False
            $Result=@()
         }

    PROCESS{
        Write-Verbose "HERE WE GO!!!"
        foreach ($computer in $ComputerName) {
            try{
            Write-Verbose "-------------------------------"
            Write-Verbose "Retrieving data from $Computer"
           New-CimSession -ComputerName $Computer –SessionOption (New-CimSessionOption –Protocol DCOM) -ErrorAction Stop | out-null

           $Items = Invoke-Command -ComputerName $Computer -ScriptBlock {param($Localvar) Get-Hotfix  | ?{$_.InstalledOn -gt ((Get-Date).AddDays(-$Localvar))}} -ArgumentList $DaysFromToday
             
             if ($null -ne $Items ){
             @(foreach ($Item in $Items){   
                $Properties = [Ordered] @{ ComputerName = $Computer
                                   Status = "Connected"
                                   Description = $Item.Description
                                   HotFixID = $Item.HotFixID
                                   InstalledBy = $Item.InstalledBy
                                   InstalledOn = $Item.InstalledOn
                                   }

                $Objoutput = New-Object -TypeName PSObject -Property $Properties
                $Result += $Objoutput
        
               })
               }else{
                   Write-Verbose "Entered Connected Hosts Section"
                    $Properties = [Ordered] @{ ComputerName = $Computer
                                   Status = "Connected"
                                   Description = "NoRecentPatchesFound"
                                   HotFixID = $null
                                   InstalledBy = $null
                                   InstalledOn = $null
                                   }
                 $Objoutput = New-Object -TypeName PSObject -Property $Properties
                 $Result += $Objoutput
       
               }
        
                
            
               }  catch {
                    
                    Write-Verbose "Couldn't Connect to $Computer"
                    $ErrorsHappened = $True
                    Write-Verbose "Entered Disconnected Hosts Section"
                    $timestmp = Get-Date -Format "yyyy-MM-dd-hhmmss"
                    "$timestmp Get-PatchSummary@ServerInfo RemoteConnectionFailed $Computer" | out-File $ErrorLogFilePath -Append
                    $Properties = [Ordered] @{ ComputerName = $Computer
                                   Status = "Unable_to_Connect"
                                   Description = $null
                                   HotFixID = $null
                                   InstalledBy = $null
                                   InstalledOn = $null
                                   }
                 $Objoutput = New-Object -TypeName PSObject -Property $Properties
                 $Result += $Objoutput

                     } finally {
                    
                            Write-output $Result
                            $Result=@()
                                     
                        } #End finally
            

         }# End foreach

     } #End PROCESS    
         
         END{
            if($ErrorsHappened){
            # Write-Warning "Errors Logged to $ErrorLogFilePath"
             Write-Warning "Errors Logged to $ErrorLogFilePath"
            }
         
         }

          
  } # End function




  <#
.Synopsis
    This is a function to fetch list Installed Software

.DESCRIPTION
    This is a function to list, Installed Software  on a server or list of servers

.EXAMPLE

    PS> Get-InstalledSoftware
    Installed Software list on localhost

.EXAMPLE

    PS>  Get-InstalledSoftware (get-content servers.txt) |ft

    
.EXAMPLE

    PS>  Get-InstalledSoftware (get-content servers.txt) -Search VMware Tools  |ft

.LINK


#>
function Get-InstalledSoftware {
[CmdletBinding()]
    param(
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage="This. Computer. Name.")]
        [Alias('HostName','cn')]
        [String[]]$ComputerName = $Env:ComputerName,
        
        [Parameter()]
        [String]$ErrorLogFilePath=$SummaryLog,
        [string] $Search

    )

    BEGIN{
            #Remove-Item -Path C:\Temp\ServerInfo*.log -Force -Recurse -ErrorAction SilentlyContinue
            $ErrorsHappened = $False
            $Result=@()
         }

    PROCESS{
        Write-Verbose "HERE WE GO!!!"
        foreach ($computer in $ComputerName) {
            try{
            Write-Verbose "-------------------------------"
            Write-Verbose "Retrieving data from $Computer"
           New-CimSession -ComputerName $Computer –SessionOption (New-CimSessionOption –Protocol DCOM) -ErrorAction Stop | out-null

      $sb={
                $result =@()     
                $keypath32 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                $keypath64 ="HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                Get-ChildItem $keypath32 -Recurse | ForEach-Object {
                    $regkey = (Get-ItemProperty $_.PSPath)
                        $Properties = [Ordered] @{ ComputerName = $Computer
                                   Status = "Connected"
                                   DisplayName = $regkey.DisplayName
                                   DisplayVersion = $regkey.DisplayVersion 
                                   Publisher = $regkey.Publisher
                                   InstallDate = $regkey.InstallDate
                                   }

                        $Objoutput = New-Object -TypeName PSObject -Property $Properties
                        if($regkey.DisplayName -ne $null){ 
                        $Result += $Objoutput }
                }
                    Get-ChildItem $keypath64 -Recurse | ForEach-Object {
                        $regkey = (Get-ItemProperty $_.PSPath)
                        $Properties = [Ordered] @{ ComputerName = $Computer
                                   Status = "Connected"
                                   DisplayName = $regkey.DisplayName
                                   DisplayVersion = $regkey.DisplayVersion 
                                   Publisher = $regkey.Publisher
                                   InstallDate = $regkey.InstallDate
                                   }

                        $Objoutput = New-Object -TypeName PSObject -Property $Properties
                        if($regkey.DisplayName -ne $null){ 
                        $Result += $Objoutput }
                }
                $result    
            }

               if (!($search)) {
                   $Items = Invoke-Command -ComputerName $Computer -ScriptBlock $sb
                 }else{
                        $Items = Invoke-Command -ComputerName $Computer -ScriptBlock $sb
                        $Items = $Items | where {$_.displayname -like "*$($search)*" } 
                      }
 
              
             if ($null -ne $Items ){
             @(foreach ($Item in $Items){   
                $Properties = [Ordered] @{ ComputerName = $Computer
                                   Status = "Connected"
                                   DisplayName = $Item.DisplayName
                                   DisplayVersion = $Item.DisplayVersion 
                                   Publisher = $Item.Publisher
                                   InstallDate = $Item.InstallDate
                                   }

                $Objoutput = New-Object -TypeName PSObject -Property $Properties
                $Result += $Objoutput
        
               })
               }else{
                   Write-Verbose "Entered Connected Hosts Section"
                    $Properties = [Ordered] @{ ComputerName = $Computer
                                   Status = "Connected"
                                   DisplayName = $null
                                   DisplayVersion = $null
                                   Publisher = $null
                                   InstallDate = $null
                                   }
                 $Objoutput = New-Object -TypeName PSObject -Property $Properties
                 $Result += $Objoutput
       
               }
        
                
            
               }  catch {
                    
                    Write-Verbose "Couldn't Connect to $Computer"
                    $ErrorsHappened = $True
                    Write-Verbose "Entered Disconnected Hosts Section"
                    $timestmp = Get-Date -Format "yyyy-MM-dd-hhmmss"
                    "$timestmp Get-InstalledSoftware@ServerInfo RemoteConnectionFailed $Computer" | out-File $ErrorLogFilePath -Append
                    $Properties = [Ordered] @{ ComputerName = $Computer
                                   Status = "Unable_to_Connect"
                                   DisplayName = $null
                                   DisplayVersion = $null
                                   Publisher = $null
                                   InstallDate = $null
                                   }
                 $Objoutput = New-Object -TypeName PSObject -Property $Properties
                 $Result += $Objoutput

                     } finally {
                    
                            Write-output $Result
                            $Result=@()
                                     
                        } #End finally
            

         }# End foreach

     } #End PROCESS    
         
         END{
            if($ErrorsHappened){
            # Write-Warning "Errors Logged to $ErrorLogFilePath"
             Write-Warning "Errors Logged to $ErrorLogFilePath"
            }
         
         }

          
  } # End function







