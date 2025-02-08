<#
-------------------------------------------
Description :
The purpose of the script is to set the group Domain Admins as owners for the following Active Directory objects:
AD object types: group
-------------------------------------------
Dependancies and compatibility:
Script has been created to run on Windows Server 2019
Script uses activedirectory module 
this script now has a whatif mode as well which will not write any data , if the Whatif mode is $true 
#>

#What if declartion

$Whatifmode = $true 

#Get domain short name
$Domaindata = Get-ADDomain | Select-Object DistinguishedName,NetBIOSName,PDCEmulator
$Domain = $Domaindata.NetBIOSName
$DomainServer =  $Domaindata.PDCEmulator
# Set log file path
$logPath = "C:\temp\ADFiles"
$logtimestamp = (Get-Date).toString("yyyyMMdd")
$logFileName = "$env:computername-$logtimestamp-SetDomainAdminsASOwner-GroupObjects.log"
$LogFile = Join-Path -Path $logPath -ChildPath $logFileName

#log files to keep
$NumberOfLogsToKeep=31

#creating a,d cleaning log files
If(Test-Path -Path $LogPath){
    #Make some cleanup and keep only the most recent ones
    Get-ChildItem -Path $LogPath |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -Skip $NumberOfLogsToKeep |
        Remove-Item -Verbose
}
Else{
    #No logs to clean but create the Logs folder
    New-Item -Path $LogPath -ItemType Directory -Verbose
}

#log file function
Function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string] $message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO","WARN","ERROR")]
        [string] $level = "INFO"
    )
    # Create timestamp
    $timestamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    # Append content to log file
    Add-Content -Path $LogFile -Value "$timestamp [$level] - $message"
}


#Start script process
If(-not $Whatifmode){
    Write-Log -message "Script started" -level INFO
}
Else{
    Write-Log -message "Script started in WHAT IF MODE" -level INFO
}

#get all desired objects
$toplevelOU = Get-ADOrganizationalUnit -Filter * -Server $DomainServer -SearchBase $($Domaindata.DistinguishedName) -SearchScope subtree |
        Select-Object -ExpandProperty DistinguishedName

 [array]$AllObjects  = $null                     
    Foreach ($OU in $toplevelOU){
        Try {
                [array]$GroupObjects = $null
                Write-host "Working on $OU"
                $GroupObjects = Get-ADGroup -Filter * -SearchBase $OU -SearchScope OneLevel -Server $DomainServer -Properties Name, ObjectClass,nTSecurityDescriptor | 
                    Select-Object Name,ObjectClass,DistinguishedName ,nTSecurityDescriptor, @{Name="Owner"; Expression={$($_.nTSecurityDescriptor).Owner}} 
                    Write-Host "Group count is $(($GroupObjects| Measure-Object).count)"
                If($(($GroupObjects| Measure-Object).count) -gt '0'){
                    $GroupObjects | Export-csv $PSScriptRoot\GroupObjects.csv -NoTypeInformation -Append
                }
            }catch {
                    Write-Host "$($error[0].Exception.Message)"
                    Write-Log -message "Not able to get desired objects for $OU" -level ERROR
            }
        } # end of For loop for each domain
        
        $AllObjects = Import-csv  $PSScriptRoot\GroupObjects.csv

    $CountAllObjects = $AllObjects.count
    Write-host $CountAllObjects -ForegroundColor Yellow
    Write-Log -message "$CountAllObjects objects found" -level INFO


<##>

#Checking current owner for each object
Write-Log -message "Checking current owner for each object" -level INFO
# Create Array for output
[array]$Array = @()

$updateObjects = $AllObjects | Where-Object {$_.Owner -notmatch "$Domain\\Domain Admins" -and $_.owner -notmatch "$Domain\\Enterprise Admins" -and $_.owner -notmatch "BUILTIN\\Administrators"}  

#looking into variable to find nTSecurityDescriptor not equal to Domain Admins
$updateObjects  | ForEach-Object {
    $dn=$_.DistinguishedName
    $owner=$_.owner
    #store info if owner is NOT Domain Admins
    #if (($owner -ne "$Domain\Domain Admins") -and ($owner -ne "$Domain\Enterprise Admins") -and ($owner -ne "BUILTIN\Administrators")) {
        $Array += New-Object psobject -Property @{
            DistinguishedName = $dn
            Owner = $owner
        }
    #}
}
$CountArray=$Array.count
Write-Log -message "$CountArray non-compliant objects (Owner not equal to Domain Admins)" -level INFO

If(-not $Whatifmode){
    #Correct Non-Compliant objects
    Write-Log -message "Set Domain Admins as owner of non-compliant objects ($CountArray)" -level INFO  
    $Array  | ForEach-Object {
        if ($dn) {Clear-Variable dn}
        $dn=$_.DistinguishedName
        $CurrentOwner=$_.owner
        Write-Log -message "$dn has as owner $CurrentOwner" -level INFO 
    
        Try {
            #Define target
            $adsitarget = [adsi]"LDAP://$($dn)" 

            #Set Domain Admin as Owner
            $NewOwner = New-Object System.Security.Principal.NTAccount("$domain", "Domain Admins")
            $adsitarget.PSBase.ObjectSecurity.SetOwner($newowner)
            $adsitarget.PSBase.CommitChanges()
            Write-Log -message "Owner has been changed for $dn" -level INFO 
        }
        Catch {
            Write-Log -message "Cannot set owner for $dn" -level ERROR 
        }
    }  # end of action for Setting owner
} # end of What if mode is False
Else{  #Start of What if is true
    Write-Log -message "No action being taken as Executed in Whatif mode" -level INFO 
}

Write-Log -message "Script finished" -level INFO
<##>