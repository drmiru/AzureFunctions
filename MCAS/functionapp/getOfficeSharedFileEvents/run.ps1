# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' porperty is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"

#Get App Settings / Variables
$keyVaultName = $ENV:KeyVaultName
$mcasApiKeySecretName = $ENV:mcasApiKeySecretName
$searchTimeFrameHours = 3
$workSpaceName = $ENV:workSpaceName
$workSpaceKeySecret = $ENV:workSpaceKeySecret


#Secret for workspace key from KeyVault
Write-Host "Getting secret: $mcasApiKeySecretName from key vault: $keyVaultName"
$mcasApiKey = (Get-AzKeyVaultSecret -VaultName $keyVaultName -SecretName $mcasApiKeySecretName).SecretValueText
if (!$mcasApiKey) {
    throw "[!]ERROR: Unable to get Secret from KeyVault"
}

#Secret for Workspace key
Write-Host "Getting secret: $workSpaceKeySecret from key vault: $keyVaultName"
$workSpaceKey = (Get-AzKeyVaultSecret -VaultName $keyVaultName -SecretName $workSpaceKeySecret).SecretValueText
if (!$workSpaceKey) {
    throw "[!]ERROR: Unable to get Secret from KeyVault"
}


#region functions
Function Convert-ToUnixDate ($PSdate) {
    $epoch = [timezone]::CurrentTimeZone.ToLocalTime([datetime]'1/1/1970')
    [math]::round((New-TimeSpan -Start $epoch -End $PSdate).TotalSeconds)
 }

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
 
# Create the function to create and post the request
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

#endregion

#Get TenantId
$tenantId = (get-azcontext).Tenant.Id

#Get Log Analytics Workspace
$workSpace = (Get-AzOperationalInsightsWorkspace -Name $WorkspaceName -ResourceGroupName $workspaceResourceGroup)
$workspaceId = $workSpace.ResourceId
$customerId = ($workSpace.CustomerId).ToString()
if (!$workspaceId) {
    throw "[!] Workspace cannot be found. Please try again"
} else {
    Write-Host -ForegroundColor Green "[-] Workspace $WorkspaceName connected"
}


#Create auth header params for Sentinel API Access
$authHeader = @{
    'Content-Type'='application/x-www-form-urlencoded'
    'Authorization'='Token ' + $mcasApiKey
}


$dateStart = (Convert-ToUnixDate (((get-date).addhours(-$searchTimeFrameHours)).ToUniversalTime())) * 1000
$filter = @"
{
    "filters": {
        "activity.eventType": {
            "eq": ["EVENT_CATEGORY_ACCEPT_SHARE_FILE"]
        },
        "created" : {
            "gte" : "$dateStart"
        }
    }
}
"@

$result = Invoke-WebRequest -Method Post -Uri "https://makeitnoblelabs.eu2.portal.cloudappsecurity.com/api/v1/activities/" -Headers $authHeader -body $filter
$sharings = ($result.Content -creplace 'Level','Level_2' -creplace 'EventName','EventName_2' | ConvertFrom-Json -depth 50).data
$shareReport = @()
Foreach ($sharedObj in $sharings) {
    $shareInfo = [PSCUSTOMOBJECT]@{
        Description = $sharedObj.description
        Operation = $sharedObj.eventTypeName
        Severity = $sharedObj.severity
        Collaborator=($sharedObj | select -ExpandProperty user).userName
        CreatedDateTime =  ([datetimeoffset]::FromUnixTimeMilliseconds(1000 * ((($sharedObj.created).toString()).substring(0,10) + "." + (($sharedObj.created).toString()).substring(10,3)))).DateTime
        UserId = $sharedObj.rawDataJson | select -ExpandProperty UserId
        ResolvedUser = $sharedObj.resolvedActor.name
        UserKey = $sharedObj.rawDataJson | select -ExpandProperty UserKey
        SiteUrl = $sharedObj.rawDataJson | select -ExpandProperty SiteUrl
        SourceFileName = $sharedObj.rawDataJson | select -ExpandProperty SourceFileName
        SourceRelativeUrl = $sharedObj.rawDataJson | select -ExpandProperty SourceRelativeUrl
        FileUrl = $sharedObj.description_metadata | select -ExpandProperty target_object
        ObjectId = $sharedObj.rawDataJson | select -ExpandProperty ObjectId
        AccessLocation = $sharedObj.location
        AppName = $sharedObj.appName        
    }
    $shareReport += $shareInfo
}

#Send data to log analytics data collector API
$body = $shareReport | convertto-json
Set-LogAnalyticsData -customerId $customerId -sharedKey $workspaceKey -body $body -logType "MCAS_CL"




