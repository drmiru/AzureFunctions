# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format.
$currentUTCtime = (Get-Date).ToUniversalTime()

#region functions
Function Get-GraphAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$clientId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [securestring]$clientSecret,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$tenantId,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$scope='https://graph.microsoft.com/.default'
    )
    
    #form oauth Url
    $Url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    # Add System.Web for urlencode
    Add-Type -AssemblyName System.Web

    # Create request body
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientSecret) 
    $client_Secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    $Body = @{
        client_id = $clientId
        client_secret = $client_Secret
        scope = $Scope
        grant_type = 'client_credentials'
    }

    # construct request parameter
    $postParams = @{
        ContentType = 'application/x-www-form-urlencoded'
        Method = 'POST'
        Body = $Body
        Uri = $Url
    }

    # Request the token 
    $token = (Invoke-RestMethod @postParams)
    return $token
}
#endregion functions

#Get app configuration values
$graphClientId = $ENV:ClientId
$graphTenantId = $ENV:TenantId
$graphClientSecret = $ENV:ClientSecret | ConvertTo-SecureString -AsPlainText -Force

#get access token for graph API and build authentication header
$graphToken = Get-GraphAccessToken -clientId $graphClientId -tenantId $graphTenantId -clientSecret $graphClientSecret
$authHeader = @{
    'Content-Type'='application/json'
    'Authorization'='Bearer ' +  $graphToken.access_token
}


#See if we have a valid subscription or if we need to renew it
$subscriptions = (Invoke-RestMethod -Method Get -Uri 'https://graph.microsoft.com/v1.0/subscriptions' -Headers $authHeader).value
If ($subscriptions) {
    $exSub = $subscriptions | where-object {$_.applicationId -eq $graphClientId -and $_.resource -match '/communications/callRecords'}
}
If ($exSub) {
    [datetime]$expirationDateTime = $exSub.expirationDateTime
    If ($expirationDateTime -lt (get-date).AddHours(12)) {
        #renew current subscription
        Write-Host "Renewing subscription with id: $($exSub.id)"
        $newExpirationDateTime = ((get-date).AddHours(24)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") 
        $exSub.expirationDateTime = $newExpirationDateTime
        $body = $exSub | convertto-json
        $null = Invoke-RestMethod -Method Patch -uri "https://graph.microsoft.com/v1.0/subscriptions/$($exSub.id)" -body $body -Headers $authHeader
    }
}
else {
    #create new subscription
    Write-Host "Creating subscription"
    $expirationDateTime = ((get-date).AddHours(24)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") 
    write-host "Expiration Time: $expirationDateTime"   
$body = @"
{
    "changeType":"created",
    "notificationUrl":"https://d-fap-teamsanalytics.azurewebsites.net/api/LogCallRecord?code=IuzmNEyJbX2U2S15hta14KEW0fpF7XqJ3Vetqf5Wnf3QkUmLi8VCuA==",
    "resource":"/communications/callRecords",
    "expirationDateTime":"$expirationDateTime",
    "clientState":"secretClientValue",
    "latestSupportedTlsVersion":"v1_2"
}
"@
    $null = Invoke-RestMethod -Method Post -uri "https://graph.microsoft.com/v1.0/subscriptions/" -body $body -Headers $authHeader
}

# Write an information log with the current time.
Write-Host "Function ran successfully: $currentUTCtime"
