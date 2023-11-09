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

# Alert resource type - /api/alerts/[alerts]
# Export assessment methods and properties per device -
#     - Export secure configuration assessment per device
#         - GET /api/machines/SecureConfigurationsAssessmentByMachine
#         - GET https://api.securitycenter.microsoft.com/api/machines/SecureConfigurationsAssessmentExport <-- Link to Files
#     - Export software inventory assessment per device
#         - GET /api/machines/SoftwareInventoryByMachine 
#         - GET /api/machines/SoftwareInventoryExport    <-- Link to Files
#     - Export non product code software inventory assessment per device
#         - GET /api/machines/SoftwareInventoryNoProductCodeByMachine
#         - GET /api/machines/SoftwareInventoryNonCpeExport <-- Link to Files
#     - Export software vulnerabilities assessment per device
#         - GET /api/machines/SoftwareVulnerabilitiesByMachine
#         - GET /api/machines/SoftwareVulnerabilitiesExport <-- Link to Files
#         - GET /api/machines/SoftwareVulnerabilityChangesByMachine
#     - Investigations on a machine
#         - List Investigations API
#             - GET https://api.securitycenter.microsoft.com/api/investigations
#         - Get Investigation API
#             - GET https://api.securitycenter.microsoft.com/api/investigations/{id}
#         - Start Investigation API
#             - POST https://api.security.microsoft.com/api/machines/{id}/startInvestigation
#     - Export device antivirus health report
#         - GET https://api.securitycenter.microsoft.com/api/deviceavinfo
#         - GET /api/machines/InfoGatheringExport (May have to convert this to CSV)
#     - Get domain-related alerts API
#         - GET /api/domains/{domain}/alerts
#     - File information APIs
#         - Get file information API
#             - GET /api/files/{id}
#         - Get file-related alerts API
#             - GET /api/files/{id}/alerts
#         - Get file-related machines API
#             - GET /api/files/{id}/machines
#         - Get file statistics API    
#             - GET /api/files/{id}/stats
#     - Indicator APIs
#         - List Indicators API
#             - GET https://api.securitycenter.microsoft.com/api/indicators
#         - Submit or Update Indicator API
#             - POST https://api.securitycenter.microsoft.com/api/indicators
#                 - Will have to fill this in with data https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/post-ti-indicator?view=o365-worldwide
#         - Import Indicators API
#             - POST https://api.securitycenter.microsoft.com/api/indicators/import
#         - Delete Indicator API
#             - Delete https://api.securitycenter.microsoft.com/api/indicators/{id}
#     - Get IP related alerts API
#         - GET /api/ips/{ip}/alerts
#     - Machine Related APIs
#         - List machines API
#             - GET https://api.securitycenter.microsoft.com/api/machines
#         - Get machine by ID API
#             - GET /api/machines/{id}
#         - Get machine logon users API
#             - GET /api/machines/{id}/logonusers
#         - Get machine related alerts API
#             - GET /api/machines/{id}/alerts
#         - Get installed software
#             - GET /api/machines/{machineId}/software
#         - Get discovered vulnerabilities
#             - GET /api/machines/{machineId}/vulnerabilities
#         - Get security recommendations
#             - GET /api/machines/{machineId}/recommendations
#         - Add or remove a tag for a machine
#             - POST https://api.securitycenter.microsoft.com/api/machines/{id}/tags
#         - Find devices by internal IP API
#             - GET /api/machines/findbyip(ip='{IP}',timestamp={TimeStamp})
#         - Find devices by tag API
#             - GET /api/machines/findbytag?tag={tag}&useStartsWithFilter={true/false}
#         - Get missing KBs by device ID
#             - GET /api/machines/{machineId}/getmissingkbs
#         - Set device value API
#             - POST https://api.securitycenter.microsoft.com/api/machines/{machineId}/setDeviceValue
#         - Update machine
#                   - PATCH /api/machines/{machineId}
#     - Machine Action APIs
#         - List MachineActions API
#             - GET https://api.securitycenter.microsoft.com/api/machineactions
#         - Get machineAction API
#             - GET https://api.securitycenter.microsoft.com/api/machineactions/{id}
#         - Collect investigation package API
#             - POST https://api.securitycenter.microsoft.com/api/machines/{id}/collectInvestigationPackage
#         - Get package SAS URI API
#             - GET https://api.securitycenter.microsoft.com/api/machineactions/{machine action id}/getPackageUri
#                   - Parse out this URL.
#         - Isolate machine API
#             - POST https://api.securitycenter.microsoft.com/api/machines/{id}/isolate
#         - Release device from isolation API
#             - POST https://api.securitycenter.microsoft.com/api/machines/{id}/unisolate
#         - Restrict app execution API
#             - POST https://api.securitycenter.microsoft.com/api/machines/{id}/restrictCodeExecution
#         - Remove app restriction API
#             - POST https://api.securitycenter.microsoft.com/api/machines/{id}/unrestrictCodeExecution
#         - Run antivirus scan API
#             - POST https://api.securitycenter.microsoft.com/api/machines/{id}/runAntiVirusScan
#         - Offboard machine API
#             - POST https://api.securitycenter.microsoft.com/api/machines/{id}/offboard
#         - Stop and quarantine file API
#             - POST https://api.securitycenter.microsoft.com/api/machines/{id}/StopAndQuarantineFile
#         - Get live response results
#             - GET https://api.securitycenter.microsoft.com/api/machineactions/{machine action
#                 id}/GetLiveResponseResultDownloadLink(index={command-index})
#         - Cancel machine action API
#             - POST https://api.securitycenter.microsoft.com/api/machineactions/<machineactionid>/cancel
#     - TVM Security Recomendations
#         - List all recommendations
#             - GET /api/recommendations
#         - Get recommendation by ID
#             - GET /api/recommendations/{id}
#         - List software by recommendation
#             - GET /api/recommendations/{id}/software
#         - List devices by recommendation
#             - GET /api/recommendations/{id}/machineReferences
#         - List vulnerabilities by recommendation
#             - GET /api/recommendations/{id}/vulnerabilities
#     - Remediation APIs
#         - List all remediation activities
#             - GET https://api.securitycenter.windows.com/api/remediationtasks/
#         - List exposed devices of one remediation activity
#             - GET /api/remediationTasks/{id}/machineReferences
#         - Get one remediation activity by ID
#             - GET /api/remediationTasks/{id}
#         - Get exposure score
#             - GET /api/exposureScore
#         - Get device secure score
#             - GET /api/configurationScore
#         - List exposure score by device group
#             - GET /api/exposureScore/ByMachineGroups
#     - List Software APIs
#         - List software inventory API
#             - GET /api/Software
#         - Get software by ID
#             - GET /api/Software/{Id}
#         - List software version distribution
#             - GET /api/Software/{Id}/distributions
#         -  List devices by software
#             - GET /api/Software/{Id}/machineReferences
#         - List vulnerabilities by software
#             - GET /api/Software/{Id}/vulnerabilities
#         - Get missing KBs by software ID
#             - GET /api/Software/{Id}/getmissingkbs
#     - User APIs
#         - Get user-related alerts API
#             - GET /api/users/{id}/alerts
#         - Get user-related machines API
#             - GET /api/users/{id}/machines
#     - TVM vulnerabilities API
#         - List vulnerabilities
#             - GET /api/vulnerabilities
#         - Get vulnerability by ID
#             - GET /api/vulnerabilities/{cveId}
#         - List devices by vulnerability
#             - GET /api/vulnerabilities/{cveId}/machineReferences
#         - List vulnerabilities by machine and software
#             - GET /api/vulnerabilities/machinesVulnerabilities

#             - Run live response commands on a device -> TBD
#             - Advanced hunting API -> TBD