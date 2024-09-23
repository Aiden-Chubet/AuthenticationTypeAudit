# Get event log results for authentication method excluding Kerberos
    Function Get-AuditEvents {
        $ServerList = 'APP01','FP01','PS01','101ES-DC1','DC2','DC1'
        Foreach ($Server in $ServerList) {
            $filterHash = @{
                LogName = "Security"
                Id = 4624
                StartTime = (Get-Date).AddDays(-1)
            }
            $lockoutEvents = Get-WinEvent -ComputerName $Server -FilterHashTable $filterHash -MaxEvents 100 -ErrorAction 0 |
                Where-Object { $_.Properties[10].Value -notlike "Kerberos" } |
                Sort-Object -Property TimeCreated -Descending
            $lockoutEvents | Select-Object @{
                Name = "Supplicant"
                Expression = { $_.Properties[5].Value }
            }, @{
                Name = "TimeStamp"
                Expression = { $_.TimeCreated }
            }, @{
                Name = "AuthServer"
                Expression = { $_.MachineName }
            }, @{
                Name = "LogonType"
                Expression = { $_.Properties[8].Value }
            }, @{
                Name = "LogonProcess"
                Expression = { $_.Properties[9].Value }
            }, @{
                Name = "Authentication"
                Expression = { $_.Properties[10].Value }
            }, @{
                Name = "LMPackage"
                Expression = { $_.Properties[14].Value }
            }, @{
                Name = "User"
                Expression = { $_.Properties[1].Value }
            }, @{
                Name = "Workstation"
                Expression = { $_.Properties[11].Value }
            }, @{
                Name = "IPAddress"
                Expression = { $_.Properties[18].Value }
            }
        }
    }
    
    ## Test function
    Get-AuditEvents


    # Get event log results for NTLM authentication method only
    Function Get-NTLMEvents {
        $ServerList = 'APP01','FP01','PS01'
        Foreach ($Server in $ServerList) {
            $filterHash = @{
                LogName = "Security"
                Id = 4624
                StartTime = (Get-Date).AddDays(-1)
            }
            $lockoutEvents = Get-WinEvent -ComputerName $Server -FilterHashTable $filterHash -MaxEvents 100 -ErrorAction 0 |
                Where-Object { $_.Properties[10].Value -eq "NTLM" } |
                Sort-Object -Property TimeCreated -Descending
            $lockoutEvents | Select-Object @{
                Name = "Supplicant"
                Expression = { $_.Properties[5].Value }
            }, @{
                Name = "TimeStamp"
                Expression = { $_.TimeCreated }
            }, @{
                Name = "AuthServer"
                Expression = { $_.MachineName }
            }, @{
                Name = "LogonType"
                Expression = { $_.Properties[8].Value }
            }, @{
                Name = "LogonProcess"
                Expression = { $_.Properties[9].Value }
            }, @{
                Name = "Authentication"
                Expression = { $_.Properties[10].Value }
            }, @{
                Name = "LMPackage"
                Expression = { $_.Properties[14].Value }
            }, @{
                Name = "User"
                Expression = { $_.Properties[1].Value }
            }, @{
                Name = "Workstation"
                Expression = { $_.Properties[11].Value }
            }, @{
                Name = "IPAddress"
                Expression = { $_.Properties[18].Value }
            }
        }
    }
    
    ## Test function
    Get-NTLMEvents | Export-CSV -Path C:\Exports\NTLMAudit.csv
    
