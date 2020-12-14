using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "function: LogCallRecord has been triggered"
$ErrorActionPreference = 'stop'

#region functions
Function Build-Signature {
    param(
        $customerId,
        $sharedKey,
        $date,
        $contentLength,
        $method,
        $contentType,
        $resource
    )
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource    
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)    
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash

    return $authorization
}

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

function Get-NewAccessToken {
    param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$tenantId,
    
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$clientId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [securestring]$clientSecret,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$scope='https://graph.microsoft.com/.default',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$refreshToken
    )

    
    #construct the requets parameter
    $BaseURL = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $Resource = 'https://graph.microsoft.com'
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientSecret) 
    $client_Secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    $Body = @(
    'grant_type=refresh_token'
    '&client_id={0}' -f $clientId
    '&refresh_token={0}' -f $refreshToken
    '&client_secret={0}' -f $client_Secret
    '&scope={0}' -f ([System.Web.HTTPUtility]::UrlEncode("offline_access $scope"))
    ) -join ''

    $Params = @{
        Uri = $BaseURL
        Method = 'POST'
        ContentType = "application/x-www-form-urlencoded"
        Body = $Body
        ErrorAction = 'Stop'
        SessionVariable = 'Session'
    }

    $response = Invoke-WebRequest @Params
    $accessToken = ($response.Content | ConvertFrom-Json)
    return $accessToken    
}

Function Set-LogAnalyticsData {
    param(
        $customerId,
        $sharedKey,
        $body,
        $logType
    )

    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature  -customerId $customerId -sharedKey $sharedKey -date $rfc1123date -contentLength $contentLength `
    -fileName $fileName `
    -method $method `
    -contentType $contentType `
    -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }
    
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode 
}

function Send-EventhubMessage {
    param(
        $eventHubName,
        $eventHubNameSpace,
        $keyname,
        $key,
        $message
    )
    
    #Generate SAS Token
    # Load the System.Web assembly to enable UrlEncode
    [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    
    $URI = "{0}.servicebus.windows.net/{1}" -f @($eventHubNameSpace,$eventHubName)
    $encodedURI = [System.Web.HttpUtility]::UrlEncode($URI)
    
    # Calculate expiry value one hour ahead
    $expiry = [string](([DateTimeOffset]::Now.ToUnixTimeSeconds())+3600)
    
    # Create the signature
    $stringToSign = [System.Web.HttpUtility]::UrlEncode($URI) + "`n" + $expiry    
    $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha.key = [Text.Encoding]::ASCII.GetBytes($key)    
    $signature = $hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($stringToSign))
    $signature = [System.Web.HttpUtility]::UrlEncode([Convert]::ToBase64String($signature))
    
    # create Request Body
    $body =  $message
    
    # API headers
    $headers = @{
        "Authorization"="SharedAccessSignature sr=" + $encodedURI + "&sig=" + $signature + "&se=" + $expiry + "&skn=" + $keyname;
    }
    
    # execute the Azure REST API
    $method = "POST"
    $dest = 'https://' +$URI  +'/messages?timeout=60&api-version=' + $eventHubApiVersion
    write-verbose "sending message $body"
    Invoke-RestMethod -Uri $dest -Method $method -Headers $headers -Body $body -SkipHeaderValidation -Verbose
}
#endregion functions

## MAIN ##
# Get the call id information from the request body
If ($VerbosePreference -eq 'continue') {
    write-host "Request:"
    $request

    write-host "body:"
    $request.RawBody
}

try {
    $callId = (($request.RawBody | ConvertFrom-Json).value.resource -split '/')[2]
}
catch {
    write-host "[!] - No Call ID received"
}

#Get app configuration values
$graphClientId = $ENV:ClientId
$graphTenantId = $ENV:TenantId
$graphClientSecret = $ENV:ClientSecret | ConvertTo-SecureString -AsPlainText -Force
$logAnalyticsId = $ENV:WorkSpaceId
$logAnalyticsKey = $ENV:WorkSpaceKey
$EventHubNameSpaceName = $ENV:EventHubNameSpaceName
$EventHubName = $ENV:EventHubName
$EventHubKeyName = $ENV:EventHubKeyName
$EventHubKeySecret = $ENV:EventHubKeySecret
$refreshToken = $ENV:RefreshToken
$internalDomainName = $ENV:InternalDomainName

#If we have a call id, get the details via graph API
if ($callId) {
    write-Host "Received new call record: $callId"

    #get access token for graph API and build authentication header
    write-Host "Getting Graph Access token"
    $graphToken = Get-GraphAccessToken -clientId $graphClientId -tenantId $graphTenantId -clientSecret $graphClientSecret
    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'='Bearer ' +  $graphToken.access_token
    }

    #Get the call details
    write-Host "Getting call info for call: $callId"
    $callEntry = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/communications/callRecords/$callId" -Headers $authHeader
    
    #Get a new access token using the saved refresh token from Key Vault
    write-Host "Getting new access token for Teams Admin API using resfreshtoken from Key Vault"
    $newTeamsApiToken = Get-NewAccessToken  -scope 'https://api.interfaces.records.teams.microsoft.com/user_impersonation' -clientId $graphClientId -tenantId $graphTenantId -clientSecret $graphClientSecret -refreshToken $refreshToken
    $authHeaderCallHistory = @{
        'Content-Type'='application/json'
        'Authorization'='Bearer ' + $newTeamsApiToken.access_token
    }
    #Get Call Participant Details using Teams Admin API
    $containsAnonymous = "False"
    $containsExternal = "False"
    $externalParticipants = @()
    $anonymousParticipants = @()
    $participants = @()
    $externals = @()
    $anonymous = @()
    
    write-Host "Getting participant details from Teams Admin API"
    $callParticipants = (Invoke-RestMethod -Method GET -Uri "https://api.interfaces.records.teams.microsoft.com/Skype.Analytics/Communications('$callId')/Participants" -Headers $authHeaderCallHistory).value

    If ($callParticipants.userIdType -match 'Anonymous') {
        $containsAnonymous = "True"
    }
    If (!($_.userPrincipalName -match $internalDomainName) -and (!($_.userIdType -match 'Anonymous'))) {
        $containsExternal = "True"
    }

    #mark anonymous participants
    $knownParticipants = $callParticipants | where-object  {!($_.userIdType -match 'Anonymous')}
    $externals = $callParticipants | where-object  {!($_.userPrincipalName -match $internalDomainName) -and (!($_.userIdType -match 'Anonymous'))}
    $anonymous = $callParticipants | where-object  {$_.userIdType -match 'Anonymous'}
    #$anonymous | ForEach-Object {$_.userPrincipalName = "Anonymous"}
    Foreach ($e in $externals) {
        $externalParticipants += $e
    }
    Foreach ($a in $anonymous) {
        $anonymousParticipants += $a
    }

    #Add participants to array
    $participants += $knownParticipants       
    $participants +=  $anonymous

    #create a custom object for the call object
    write-Host "Creating call info object"
    $callInfoObj = [PSCUSTOMOBJECT]@{
        Id=$calLId
        Type=$callEntry.Type
        Modalities=$callEntry.modalities
        Organizer=($callParticipants | Where-Object {$_.IsOrganizer}).UserPrincipalName
        ParticipantCount=$callEntry.participants.count
        StartTime=$callEntry.startDateTime
        EndTime=$callEntry.endDateTime
        Participants=$participants.sipId -join ','
        AnonymousParticipants=$containsAnonymous
        NumberOfAnonymousParticipants=$anonymousParticipants.count
        NumberOfExternalParticipants=$externalParticipants.count
        ExternalParticipants=$externalParticipants.sipId -join ','
        JoinWebUrl=$callEntry.joinWebUrl
    }

    #Send the call details to EventHub
    write-Host "Send data to log eventhub"
    Send-EventhubMessage -message ($callInfoObj | ConvertTo-Json) -eventHubName $eventHubName -eventHubNameSpace $eventHubNameSpaceName -keyname $EventHubKeyName -key $EventHubKeySecret

    #Log the call details to Log Analytics
    write-Host "Send data to log analytics"
    $TimeStampField = (get-date $callEntry.startDateTime).GetDateTimeFormats(115)
    $null = Set-LogAnalyticsData -customerId $logAnalyticsId -sharedKey $logAnalyticsKey -logType "TeamsCallRecords_CL" -body ($callInfoObj | ConvertTo-Json)

}
else {
    write-Host "Call Id unknknown or invalid request body reveived"
}


# Interact with query parameters or the body of the request.
try {
    $token = $Request.Query.validationToken
}
catch {
    $token = 'no validation token received'
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $token
})