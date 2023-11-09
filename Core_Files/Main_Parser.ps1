function Get-AuthToken {
    param ($TenantId, $appId, $appSecret, $resourceAppIdUri)

    $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $authBody = [Ordered] @{
        resource = "$resourceAppIdUri"
        client_id = "$appId"
        client_secret = "$appSecret"
        grant_type = 'client_credentials'
    }

    $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    return $authResponse.access_token
}

function Invoke-SecurityCenterApi {
    param ($Uri, $Headers)

    try {
        $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get
        return $response.value
    } catch {
        Write-Warning "Error calling API: $_"
        return $null
    }
}

$TenantId = ""
$appId = ""
$appSecret = ""


$token = Get-AuthToken -TenantId $TenantId -appId $appId -appSecret $appSecret -resourceAppIdUri 'https://api.securitycenter.microsoft.com'

$headers = @{
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token"
}

$ListMachinesVulnerabilityUri = "https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities"
$listMachinesUri = "https://api.securitycenter.microsoft.com/api/machines/"

$vulnerabilities = Invoke-SecurityCenterApi -Uri $ListMachinesVulnerabilityUri -Headers $headers
$machines = Invoke-SecurityCenterApi -Uri $listMachinesUri -Headers $headers

$vulObjectData = New-Object System.Collections.Generic.List[Object]
$machineObjectData = New-Object System.Collections.Generic.List[Object]

foreach ($vul in $vulnerabilities) {
    $vulObject = [PSCustomObject]@{
        "cve id" = $vul.cveid
        "machineid" = $vul.machineid
        "product name" = $vul.productname
        "product vendor" = $vul.productvendor
        "product version" = $vul.productversion
    }
    $vulObjectData.Add($vulObject)
}

foreach ($machine in $machines) {
    $machineObject = [PSCustomObject]@{
        "Computer Name" = $machine.computerDnsName
        "Device ID" = $machine.id
        "Last IP Address" = $machine.lastipaddress 
        "Last External IP Address" = $machine.lastexternalipaddress
        "Health Status" = $machine.healthstatus
        "Onboarding Status" = $machine.onboardingstatus
        "OS Platform" = $machine.osplatform
        "OS Version" = $machine.version
    }
    
    $machineObjectData.Add($machineObject)
}

# Filter machine objects based on vulnerability data
$vulnerableDeviceIds = $vulObjectData | ForEach-Object { $_."machineid" } | Sort-Object -Unique
$filteredMachineObjects = $machineObjectData | Where-Object { $vulnerableDeviceIds -contains $_."Device ID" }

write-host "Vulnerable machines: $filteredMachineObjects"


Advanced hunting API - /api/advancedqueries/run
Alert resource type - /api/alerts/[alerts]
Export assessment methods and properties per device -