#Requires -RunAsAdministrator

function Az-ArcOnboarding {

# Arc Onboarding Script

# This script will create a new Azure AD Application and Service Principal, and then assign the Service Principal to the specified Azure Subscription with the specified role.

# Prerequisites:
# - Azure Subscription
# - Azure Resource Group
# - Azure Location for the Arc Enabled Servers
# - Azure AD Application and Service Principal
# - Azure AD Application and Service Principal assigned to Azure Subscription or Azure Resource Group with Azure Connected Machine Onboarding role

# Example: Az-ArcOnboarding -ExistingClientId "a1969b86-89e4-42c4-82ed-6327b8e42fdd" -ExistingClientSecret "1CE8Q~xgn4xMmv6ck3ggT_-7hkWutbkJ0lQxNdwZ" -DownloadAzureArcAgent $true -TenantId "54e09220-a248-2bcb-afa0-453bab450767" -AzureArcResourceGroupName "ArcLandingZone" -SubscriptionId "534e8123-f591-5bb6-a2ab-9g55d69b5907" -AzureArcLocation "westeurope" -ServersToOnboard CONTOSOSRV0,CONTOSOSRV1,CONTOSOSRV2,CONTOSOSRV3 -AzureVMLab $true

# This script can onboard Azure VMs to be able to try the Azure Arc experience. Add the -AzureVMLab $true parameter to onboard Azure VMs.

[CmdletBinding()]
param (
    [string]$Proxy,
    [string]$ExistingClientId,
    [string]$ExistingClientSecret,
    [bool]$DownloadAzureArcAgent,
    [string]$TenantId,
    [string]$AzureArcResourceGroupName,
    [string]$SubscriptionId,
    [string]$AzureArcLocation,
    $CreateNewServicePrincipal,
    [ValidatePattern("(\S+)\.csv$")]
    [string]$ServersToOnboardFile,
    [string[]]$ServersToOnboard,
    [bool]$AzureVMLab
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$refVersion = [version] '4.5'
$provider = 'Microsoft.HybridCompute'

$ArcServicePrincipalName = "ArcOnboardingServicePrincipal"

function Check-AzureArcPublicEndpoint {
    param(
        [string]$AzureArcLocation
    )
    Write-Output "$env:COMPUTERNAME : Testing on machine"
    $LogPath = "C:\temp\Check-AzureArcPublicEndpoint_log.txt"
    $LogMessage = "$(Get-Date) : $env:COMPUTERNAME : INFO : Testing on machine"
    $LogMessage | Out-File -FilePath $LogPath -Append
    ##Write-Host "Downloading the latest Azure IP Ranges and Service Tags – Public Cloud" -ForegroundColor Yellow
    $rawhtml = Invoke-RestMethod -Uri 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519' -UseBasicParsing
    $source = [Regex]::Match($rawhtml, 'https://download.microsoft.com[^"]*').Value
    $destination = Invoke-RestMethod -Uri $source

    $lookups = 'AzureArcInfrastructure','AzureAD','AzureTrafficManager','AzureResourceManager','AzureStorage','WindowsAdminCenter'

    ##Write-Host "Azure Arc region to verify public connection to: $AzureArcLocation" -ForegroundColor Yellow
    $region = $AzureArcLocation
    #$region = ($destination.values | Select-Object -expand properties | Select-Object @{Label="Region";Expression={($_.region)}} -Unique | Sort-Object -Property Region | Out-GridView -OutputMode Single -Title 'Select an Azure Region').Region

    ##Write-Host "Constructing list of URLs to test" -ForegroundColor Yellow
    $urls = @('aka.ms','download.microsoft.com','packages.microsoft.com','management.azure.com','login.windows.net','login.microsoftonline.com','pas.windows.net','guestnotificationservice.azure.com','dc.services.visualstudio.com','www.office.com','agentserviceapi.guestconfiguration.azure.com')
    $urls += (Invoke-RestMethod -Uri ("https://gbl.his.arc.azure.com/discovery?location=$region&api-version=1.1-preview")).substring(8)
    $urls += (Invoke-RestMethod "https://guestnotificationservice.azure.com/urls/allowlist?api-version=2020-01-01&location=$region")

    #Write-Host "Testing URLs" -ForegroundColor Yellow
    foreach ($url in $urls) {
        if (((Test-NetConnection $url -Port 443 -WarningAction:SilentlyContinue).TCPTESTSucceeded) -ne $true) {
            Write-Host "$env:COMPUTERNAME : $url is not reachable" -ForegroundColor Red
            $LogMessage = "$(Get-Date) : $env:COMPUTERNAME : ERROR : $url is not reachable"
            $LogMessage | Out-File -FilePath $LogPath -Append
        
        } else {
            ##Write-Host "$url is reachable" -ForegroundColor Green
        }
    }
    Write-Host "$env:COMPUTERNAME : Testing done" -ForegroundColor Green
    $LogMessage = "$(Get-Date) : $env:COMPUTERNAME : INFO : Testing done"
    $LogMessage | Out-File -FilePath $LogPath -Append
}

function Check-ExistingOrCreateAzureResourceGroup {
    $AzArcResourceGroup = Get-AzResourceGroup -Name $AzArcResourceGroupName -Location $AzureArcLocation -ErrorAction SilentlyContinue
    if ($AzArcResourceGroup -eq $null) {
        Write-Host "Azure Resource Group $($AzArcResourceGroupName) not found, creating now"
        $AzArcResourceGroup = New-AzResourceGroup -Name $AzArcResourceGroupName -Location $AzureArcLocation
    } else {
        Write-Host "Azure Resource Group $($AzArcResourceGroupName) found, using existing"
    }
}

function Use-ExistingAzureArcServicePrincipal {
    $AzArcservicePrincipalClientId = $ExistingClientId
    $ArcClientSecret = $ExistingClientSecret
    Write-Host "Service Principal Client ID: $AzArcservicePrincipalClientId"
}

function Add-AzureArcServicePrincipal {
    $sp = New-AzADServicePrincipal -DisplayName $ArcServicePrincipalName -Role "Azure Connected Machine Onboarding" -EndDate (Get-Date).AddHours(1)
    $AzArcservicePrincipalClientId = $sp.AppId
    Write-Host "Service Principal Client ID: $AzArcservicePrincipalClientId"
    Write-Host "Getting Client Secret"
    $ArcClientSecret = ConvertTo-SecureString -String $($sp.PasswordCredentials.SecretText) -AsPlainText -Force
    Write-Host "Azure AD Application and Service Principal created"
    Write-Host "Client Secret will expire in 1 hour" -ForegroundColor Yellow
}

function Download-AzArcAgent {
    try {
        Write-Host "Testing if Microsoft Uri is reachable"
        $downloadUri = "https://aka.ms/AzureConnectedMachineAgent"
        $MSUri = Invoke-WebRequest -UsebasicParsing -Uri $downloadUri -DisableKeepAlive -Method Head
        if($MSUri.StatusCode -eq "200"){
            Write-Host "Microsoft Uri is reachable"
            Write-Host "Downloading Azure Connected Machine Agent"
            if ($Proxy) {
                Invoke-WebRequest -UseBasicParsing -Proxy $Proxy -Uri $downloadUri -OutFile "$env:TEMP\AzureConnectedMachineAgent.msi"
            } else {
                Invoke-WebRequest -UseBasicParsing -Uri $downloadUri -OutFile "$env:TEMP\AzureConnectedMachineAgent.msi"
            }
            Write-Host "Azure Connected Machine Agent downloaded"
        } else {
            Write-Host "Unable to reach Microsoft download Uri. Please check your internet connection and try again." -ForegroundColor Red;
            return;
        }
    }
    catch {
        Write-Host "Unable to reach Microsoft download Uri. Please check your internet connection and try again." -ForegroundColor Red;
        return;
    }
}
    
function Test-AzureStackHCI() {
    [CmdletBinding()]
    param (
    )

    try {
        $product=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName | select -ExpandProperty ProductName
    }
    catch {
        Write-Verbose -Message "Error $_ Unable to determine product SKU from registry" -Verbose
        # Will attempt to install anyway
        return $false
    }
    if ($product -eq 'Azure Stack HCI') {
        return $true
    }
    return $false
}

function Test-PowerShellVersion() {
    [CmdletBinding()]
    param (
    )
    if ($PSVersionTable.PSVersion -ge [Version]"4.0") {
        Write-Verbose -Message "$env:COMPUTERNAME : PowerShell version: $($PSVersionTable.PSVersion)" -Verbose
        $LogPath = "C:\temp\Test-PowerShellVersion_log.txt"
        $LogMessage = "$(Get-Date) : $env:COMPUTERNAME : INFO : Machine has PowerShell version $($PSVersionTable.PSVersion)"
        $LogMessage | Out-File -FilePath $LogPath -Append
        return $true
    } else {
        Write-Verbose -Message "$env:COMPUTERNAME : PowerShell version: $($PSVersionTable.PSVersion)" -Verbose
        $LogPath = "C:\temp\Test-PowerShellVersion_log.txt"
        $LogMessage = "$(Get-Date) : $env:COMPUTERNAME : ERROR : Machine has PowerShell version $($PSVersionTable.PSVersion)"
        $LogMessage | Out-File -FilePath $LogPath -Append
        return $false
    }
}

function Test-DotNetFramework() {
    [CmdletBinding()]
    param (
    )
    $refVersion = [version] '4.5'
    try {
        $installedVersion = [version] (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Version | select -ExpandProperty Version)
    }
    catch {
        Write-Verbose -Message "$env:COMPUTERNAME : Error $_ Unable to determine .NET Framework version" -Verbose
        $LogPath = "C:\temp\Test-DotNetFramework_log.txt"
        $LogMessage = "$(Get-Date) : $env:COMPUTERNAME : ERROR : Unable to determine .NET Framework version $_"
        $LogMessage | Out-File -FilePath $LogPath -Append
        # Will attempt to install anyway
        return $true
    }
    Write-Verbose -Message "$env:COMPUTERNAME : .NET Framework version: $installedVersion" -Verbose
    $LogPath = "C:\temp\Test-DotNetFramework_log.txt"
        $LogMessage = "$(Get-Date) : $env:COMPUTERNAME : INFO : Machine has DotNetFramework version $installedVersion"
        $LogMessage | Out-File -FilePath $LogPath -Append
    if ($installedVersion -ge $refVersion) {
        return $true
    }
    return $false
}

function Test-IsAzure() {
    [CmdletBinding()]
    param (
    )

    Write-Verbose "$env:COMPUTERNAME : Checking if this is an Azure virtual machine" -Verbose
    try {
        if ($PSVersionTable.PSVersion -ge [Version]"6.0") {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://169.254.169.254/metadata/instance/compute?api-version=2019-06-01" -Headers @{Metadata = "true"} -NoProxy -TimeoutSec 1 -ErrorAction SilentlyContinue
        } else {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://169.254.169.254/metadata/instance/compute?api-version=2019-06-01" -Headers @{Metadata = "true"} -TimeoutSec 1 -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Verbose "$env:COMPUTERNAME : Error $_ checking if we are in Azure" -Verbose
        return $false
    }
    if ($null -ne $response -and $response.StatusCode -eq 200) {
        $content = ConvertFrom-Json $($response.Content.ToString())
        if ($null -ne $content.resourceId) {
            Write-Verbose "$env:COMPUTERNAME : Azure check indicates that we are in Azure" -Verbose
            $LogPath = "C:\temp\Test-IsAzure_log.txt"
            $LogMessage = "$(Get-Date) : $env:COMPUTERNAME : ERROR : Machine is in Azure, cannot install Azure Arc"
            $LogMessage | Out-File -FilePath $LogPath -Append
            Write-Verbose "$env:COMPUTERNAME : Run the script again with parameter -AzureVMLab $true to install Azure Connected Machine Agent on Azure VMs" -Verbose
            $LogMessage = "$(Get-Date) : $env:COMPUTERNAME : INFO : Run the script again with parameter -AzureVMLab $true to install Azure Connected Machine Agent on Azure VMs"
            $LogMessage | Out-File -FilePath $LogPath -Append
            return $true
        }
    }
    return $false
}

function Get-MsiLogSummary() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$LogPath = "C:\temp\installationlog.txt"
    )

    try
    {
        $LogPath = Resolve-Path $LogPath
        Write-Verbose "$env:COMPUTERNAME : Reading Logs from $LogPath" -Verbose

        $patterns = @(
            "Installation success or error status",
            "Product: Azure Connected Machine Agent"
        );

        $regex = "(" + ($patterns -join ")|(" ) + ")"

        Write-Verbose "$env:COMPUTERNAME : Looking for Patterns: $regex" -Verbose

        $inCustomAction = $false
        $logCustomAction = $false
        $caOutput = new-object -TypeName System.Collections.ArrayList
        Get-Content $LogPath | % {
            # log interesting lines
            if ( ($_ -match $regex)) {
                "$env:COMPUTERNAME : $_" # output to pipeline
            }

            # Wix custom actions start with "Calling custom Action". Gather the log from the CA till we see if it passed
            # At the end, log that output only if it failed with "returned actual error"
            if ($_ -match "Calling custom action") {
                $inCustomAction = $true
                $logCustomAction = $false
            }
            if ($_ -match "MSI \(s\)") {
                $inCustomAction = $false 
            }
            if ($_ -match "returned actual error") {
                $logCustomAction = $true
            }
            if ($inCustomAction) {
                $null = $caOutput.Add($_)
            }
            else
            {
                if($logCustomAction) {
                    $caOutput # output saved lines to pipeline
                }
                $caOutput.Clear()
            }
        }
    } catch {
        # This code is optional so if something goes wrong we'll just swallow the error and have no details
        Write-Verbose "$env:COMPUTERNAME : Error while parsing MSI log: $_"
    }
}

<# Throw a structured exception#>
function Invoke-Failure{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Message,
        [Parameter(Mandatory=$true)]
        $ErrorCode,
        [Parameter(Mandatory=$false)]
        $Details
    )

    $ex = new-object -TypeName System.Exception -ArgumentList @($Message)
    $ex.Data["Details"] = $details
    $ex.Data["ErrorCode"] = $errorcode
    throw $ex
}

function Send-Failure{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Exception] $Error,

        [Parameter(Mandatory = $true)]
        [string] $ErrorCode
    )

    $hisEndpoint = "https://gbl.his.arc.azure.com"
    if ($env:CLOUD -eq "AzureUSGovernment") {
        $hisEndpoint = "https://gbl.his.arc.azure.us"
    } elseif ($env:CLOUD -eq "AzureChinaCloud") {
        $hisEndpoint = "https://gbl.his.arc.azure.cn"
    }

    $message = "$Error"
    if ($Error.Data["Details"]) {
        $message = $Error.Data["Details"]
    }
    $message = $message.Substring(0, [Math]::Min($message.Length, 600))

    if ( $env:PROVIDER_NAMESPACE ) {
        $provider = $env:PROVIDER_NAMESPACE
    }
    $logBody = @{subscriptionId="$env:SUBSCRIPTION_ID";resourceGroup="$env:RESOURCE_GROUP";tenantId="$env:TENANT_ID";location="$env:LOCATION";correlationId="$env:CORRELATION_ID";authType="$env:AUTH_TYPE";operation="onboarding";namespace="$provider";osType="windows";messageType="$ErrorCode";message="$message";}
    
    Invoke-WebRequest -UseBasicParsing -Uri "$hisEndpoint/log" -Method "PUT" -Body ($logBody | ConvertTo-Json) -ErrorAction SilentlyContinue | out-null
}

# Based on the MSI error code, we may have some hint to provide as to the issue
# See https://learn.microsoft.com/en-us/windows/win32/msi/error-codes
function Get-MsiErrorDetails() {
    [CmdletBinding()]
    param(
        $exitCode
    )

    $message = (net helpmsg $exitCode) -join ""
    $hint = ""
    $errorCode = "AZCM0149" # exitCode is the return value from msiexec. errorCode is the error code of the script
    switch($exitCode) {
        1633 {
            # ERROR_INSTALL_PLATFORM_UNSUPPORTED 
            $hint = "Unsupported: Azure Connected Machine Agent is only compatible with X64 operating systems"
            $errorCode = "AZCM0153"
        }
    }
    return [PSCustomObject]@{
        Message = $message
        Hint = $hint
        ErrorCode = $errorCode
    }
}

function Check-Physical-Memory() {
    [CmdletBinding()]
    param (
    )

    $memory = systeminfo | Select-String '^Total Physical Memory'
    Write-Verbose -Message "$memory" -Verbose
}

function Prepare-AzureVMforArc {
    Write-Verbose -Message "Disabling Azure Guest Agent" -Verbose
    Set-Service WindowsAzureGuestAgent -StartupType Disabled -Verbose
    Stop-Service WindowsAzureGuestAgent -Force -Verbose

    Write-Verbose -Message "Adding firewall rule to block access to Azure IMDS"
    New-NetFirewallRule -Name BlockAzureIMDS -DisplayName "Block access to Azure IMDS" -Enabled True -Profile Any -Direction Outbound -Action Block -RemoteAddress 169.254.169.254
}

function Install-Azcmagent {
    # Ensure TLS 1.2 is accepted. Older PowerShell builds (sometimes) complain about the enum "Tls12" so we use the underlying value
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    # Ensure TLS 1.3 is accepted, if this .NET supports it (older versions don't)
    try { 
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 12288 
    } catch {}

    try {
        Write-Verbose -Message "Installing Azure Connected Machine Agent" -Verbose
        $msiFile = "C:\temp\AzureConnectedMachineAgent.msi"
  
        # Install the package
        $logFile = "C:\temp\installationlog.txt"
        Write-Verbose -Message "Installing agent package" -Verbose
        $exitCode = (Start-Process -FilePath msiexec.exe -ArgumentList @("/i", $msiFile , "/l*v", $logFile, "/qn") -Wait -Passthru).ExitCode
        #if ($exitCode -ne 0) {
        #    $details = (Get-MsiErrorDetails $exitCode)
        #    $logInfo = ((Get-MsiLogSummary $logFile) -join "`n")
            #Invoke-Failure -Message "Installation failed: [$exitCode]: $($details.Message) $($details.Hint)`: See $logFile for additional details." -ErrorCode $details.ErrorCode -Details $logInfo
        #}

        # Check if we need to set proxy environment variable
        if ($Proxy) {
            Write-Verbose -Message "Setting proxy configuration: $Proxy" -Verbose
            & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent" config set proxy.url ${Proxy}
        }
        
    } catch {
        $code = $_.Exception.Data.ErrorCode
        $details = $_.Exception.Data.Details
        if(!$code) { $code = "AZCM0150" } # default if we do not have some more specific error 
        if ($OutFile) {
            [ordered]@{
                status  = "failed"
                error = [ordered]@{
                    message = $_.Exception.Message
                    code = $code
                    details = $details
                }
            } | ConvertTo-Json | Out-File $OutFile
        }
        Write-Error $_ -ErrorAction Continue
        if ($details) {
            Write-Output "Details: $details"
        }
        #Send-Failure $_.Exception $code
        exit 1
    }

    # Installation was successful if we got this far
    if ($OutFile) {
        [ordered]@{
            status  = "success"
            message = "Installation of azcmagent completed successfully"
        } | ConvertTo-Json | Out-File $OutFile
    }
}

function Connect-Azcmagent {
    param (
        [Parameter(Mandatory = $true)]
        [string] $ExistingClientId,
        [Parameter(Mandatory = $true)]
        [string] $ExistingClientSecret,
        [Parameter(Mandatory = $true)]
        [string] $TenantId,
        [Parameter(Mandatory = $true)]
        [string] $SubscriptionId,
        [Parameter(Mandatory = $true)]
        [string] $AzureArcResourceGroupName,
        [Parameter(Mandatory = $true)]
        [string] $AzureArcLocation,
        [Parameter(Mandatory = $false)]
        [string] $Tag
    )

    $env:CLOUD = "AzureCloud"

    try {
        Write-Host "Running azcmagent.exe connect command..."
        $azcmagentArgs = [System.Collections.Generic.List[string]]@(
        'connect'
        '--service-principal-id'
        $ExistingClientId
        '--service-principal-secret'
        $ExistingClientSecret
        '--tenant-id'
        $TenantId
        '--subscription-id'
        $SubscriptionId
        '--cloud'
        $env:CLOUD
        '--resource-group'
        $AzureArcResourceGroupName
        '--location'
        $AzureArcLocation
    )

    if ($Tag) {
        $azcmagentArgs.Add('--tags')

        # Build tag string
        $tagStrings = foreach ($key in $Tag.Keys) {
            $t = $key
            if ($Tag[$key] -and $Tag[$key].GetType() -eq [string]) {
                $t += "=$($Tag[$key])"
            }
            $t
        }

        $azcmagentArgs.Add([string]::Join(',', $tagStrings))
    }

        & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" $azcmagentArgs
        Write-Host "Successfully connected machine $env:COMPUTERNAME to Azure Arc"
    }
    catch {
        # Fix this later with correct parameters
        #$logBody = @{subscriptionId="$env:SUBSCRIPTION_ID";resourceGroup="$env:RESOURCE_GROUP";tenantId="$env:TENANT_ID";location="$env:LOCATION";correlationId="$env:CORRELATION_ID";authType="$env:AUTH_TYPE";operation="onboarding";messageType=$_.FullyQualifiedErrorId;message="$_";};
        #Invoke-WebRequest -UseBasicParsing -Uri "https://gbl.his.arc.azure.com/log" -Method "PUT" -Body ($logBody | ConvertTo-Json) | out-null;
        Write-Host  -ForegroundColor red $_.Exception;
    }
}

function Remove-AzADServicePrincipal {
    # Ask if user wants to remove the client secret from Azure AD App
    Read-Host "Do you want to remove the Azure Arc Onboarding Service Principal, $($servicePrincipalClientId), from Azure AD? (y/n)" | ForEach-Object {
        if ($_ -eq "y") {
            try {
                Write-Host "Removing Azure Arc Onboarding Service Principal, $($servicePrincipalClientId), from Azure AD..."
                $sp = Get-AzADServicePrincipal -ServicePrincipalName $servicePrincipalClientId
                Remove-AzADServicePrincipal -ServicePrincipal $sp
                Write-Host "Successfully removed Azure Arc Onboarding Service Principal, $($servicePrincipalClientId), from Azure AD"
            }
            catch {
                Write-Host "Failed to remove Azure Arc Onboarding Service Principal, $($servicePrincipalClientId), from Azure AD"
                Write-Host $_.Exception -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "Please remove the Azure Arc Onboarding Service Principal, $($servicePrincipalClientId), from Azure AD when you no longer need it" -ForegroundColor Yellow
        }
    }
}

# Now running the main script

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072;
    
    if($ServersToOnboard){
        $Session = New-PSSession -ComputerName $ServersToOnboard
        Invoke-Command -Session $Session -ScriptBlock {[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072}
    }
    
    Write-Verbose -Message "Checkling Prerequisites..." -Verbose
    
    if($AzureVMLab -eq "True"){
        Invoke-Command -Session $Session -ScriptBlock ${function:Prepare-AzureVMforArc}
    }
    
    #Check-AzureArcPublicEndpoint
    Invoke-Command -Session $Session -ScriptBlock ${function:Check-AzureArcPublicEndpoint} -ArgumentList $AzureArcLocation

    #Check-Physical-Memory
    Invoke-Command -Session $Session -ScriptBlock ${function:Check-Physical-Memory}

    #Check-IsAzureStackHCI
    Invoke-Command -Session $Session -ScriptBlock ${function:Test-AzureStackHCI}

    #Check-PowerShellVersion
    Invoke-Command -Session $Session -ScriptBlock ${function:Test-PowerShellVersion}

    #Check-DotNetFramework
    Invoke-Command -Session $Session -ScriptBlock ${function:Test-DotNetFramework}

    #Check-IsAzure
    Invoke-Command -Session $Session -ScriptBlock ${function:Test-IsAzure}

    #Download-AzArcAgent
    if ($DownloadAzureArcAgent -eq $true) {
        Download-AzArcAgent
        # Transfer file to remote machine
        Write-Host "Transferring Azure Connected Machine Agent to remote machine"
        if($session.count -gt 1){
            foreach($s in $session){
                Copy-Item -Path "$env:TEMP\AzureConnectedMachineAgent.msi" -Destination "C:\temp\AzureConnectedMachineAgent.msi" -ToSession $s
            }
        } else {
            Copy-Item -Path "$env:TEMP\AzureConnectedMachineAgent.msi" -Destination "C:\temp\AzureConnectedMachineAgent.msi" -ToSession $session
        }
    }

    # Install the agent
    Write-Verbose -Message "Installing Azure Connected Machine Agent" -Verbose
    if($session.count -gt 1){
        foreach($s in $session){
            Invoke-Command -Session $s -ScriptBlock ${function:Install-Azcmagent}
         
        }
    } else {
        Invoke-Command -Session $session -ScriptBlock ${function:Install-Azcmagent}
    }

    # Check MSI installation log
    Write-Verbose -Message "Checking MSI installation log" -Verbose
    if($session.count -gt 1){
        foreach($s in $session){
            Invoke-Command -Session $s -ScriptBlock ${function:Get-MsiLogSummary}
         
        }
    } else {
        Invoke-Command -Session $session -ScriptBlock ${function:Get-MsiLogSummary}
    }

    # Connect the agent to Azure
    Write-Verbose -Message "Connecting Azure Connected Machine Agent" -Verbose
    if($session.count -gt 1){
        foreach($s in $session){
            Invoke-Command -Session $s -ScriptBlock ${function:Connect-Azcmagent} -ArgumentList $ExistingClientId, $ExistingClientSecret, $TenantId, $SubscriptionId, $AzureArcResourceGroupName, $AzureArcLocation
         
        }
    } else {
        Invoke-Command -Session $session -ScriptBlock ${function:Connect-Azcmagent} -ArgumentList $ExistingClientId, $ExistingClientSecret, $TenantId, $SubscriptionId, $AzureArcResourceGroupName, $AzureArcLocation
    }

    #Warn user to remove the service principal
    Write-Host "Please remove the Azure Arc Onboarding Service Principal, $($ExistingClientId), from Azure AD when you no longer need it" -ForegroundColor Yellow

}
