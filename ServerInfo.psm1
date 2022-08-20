$Date = Get-Date -Format "yyyyMMddhhmmss"
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



