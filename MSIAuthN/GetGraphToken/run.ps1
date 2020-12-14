using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

# Interact with query parameters or the body of the request.
$Scope = $Request.Query.Scope
if (-not $Scope) {
    $Scope = $Request.Body.Scope
}
#If parameter "Scope" has not been provided, we assume that graph.microsoft.com is the target resource
If (!$Scope) {
    $Scope = "https://graph.microsoft.com/"
}

#Add .net core library
$authNdllPath = '.\bin\Debug\netcoreapp3.1\publish\Microsoft.Azure.Services.AppAuthentication.dll'
add-type -Path $authNdllPath
$tokenProvider = New-Object Microsoft.Azure.Services.AppAuthentication.AzureServiceTokenProvider('')
$accessToken = ($tokenProvider.GetAccessTokenAsync("$Scope")).Result

#Invoke REST call to Graph API
$uri = 'https://graph.microsoft.com/v1.0/groups'
$authHeader = @{
    'Content-Type'='application/json'
    'Authorization'='Bearer ' +  $accessToken
}
$result = (Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get -ResponseHeadersVariable RES).value
If ($result) {
    $body = $result
    $StatusCode = '200'
}
Else {
    $body = $RES
    $StatusCode = '400'
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $body
})
