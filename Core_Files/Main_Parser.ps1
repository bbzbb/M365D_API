$appIdUri = 'https://api.securitycenter.microsoft.com'
$apiEndpoints = @(
    #@{ Key = "GetAlert"; Endpoint = "/security/alerts/{alert_id}"; Method = "GET" },
    #@{ Key = "SecureConfigAssessmentByMachine"; Endpoint = "/api/machines/SecureConfigurationsAssessmentByMachine"; Method = "GET" },
    #@{ Key = "SecureConfigAssessmentExport"; Endpoint = "/api/machines/SecureConfigurationsAssessmentExport"; Method = "GET" },
    @{ Key = "SoftwareInventoryByMachine"; Endpoint = "/api/machines/SoftwareInventoryByMachine"; Method = "GET" },
    #@{ Key = "SoftwareInventoryExport"; Endpoint = "/api/machines/SoftwareInventoryExport"; Method = "GET" },
    @{ Key = "SoftwareInventoryNoProductCodeByMachine"; Endpoint = "/api/machines/SoftwareInventoryNoProductCodeByMachine"; Method = "GET" },
    #@{ Key = "SoftwareInventoryNonCpeExport"; Endpoint = "/api/machines/SoftwareInventoryNonCpeExport"; Method = "GET" },
    @{ Key = "SoftwareVulnerabilitiesByMachine"; Endpoint = "/api/machines/SoftwareVulnerabilitiesByMachine"; Method = "GET" },
    #@{ Key = "SoftwareVulnerabilitiesExport"; Endpoint = "/api/machines/SoftwareVulnerabilitiesExport"; Method = "GET" },
    #@{ Key = "SoftwareVulnerabilityChangesByMachine"; Endpoint = "/api/machines/SoftwareVulnerabilityChangesByMachine"; Method = "GET" },
    #@{ Key = "ListInvestigationsAPI"; Endpoint = "/api/investigations"; Method = "GET" },
    #@{ Key = "GetInvestigationAPI"; Endpoint = "/api/investigations/{id}"; Method = "GET" },
    #@{ Key = "StartInvestigationAPI"; Endpoint = "/api/machines/{id}/startInvestigation"; Method = "POST" },
    @{ Key = "DeviceAntivirusHealthReport"; Endpoint = "/api/deviceavinfo"; Method = "GET" },
    #@{ Key = "InfoGatheringExport"; Endpoint = "/api/machines/InfoGatheringExport"; Method = "GET" },
    #@{ Key = "GetDomainRelatedAlertsAPI"; Endpoint = "/api/domains/{domain}/alerts"; Method = "GET" },
    #@{ Key = "GetFileInfoAPI"; Endpoint = "/api/files/{id}"; Method = "GET" },
    #@{ Key = "GetFileRelatedAlertsAPI"; Endpoint = "/api/files/{id}/alerts"; Method = "GET" },
    #@{ Key = "GetFileRelatedMachinesAPI"; Endpoint = "/api/files/{id}/machines"; Method = "GET" },
    #@{ Key = "GetFileStatisticsAPI"; Endpoint = "/api/files/{id}/stats"; Method = "GET" },
    #@{ Key = "ListIndicatorsAPI"; Endpoint = "/api/indicators"; Method = "GET" },
    #@{ Key = "SubmitOrUpdateIndicatorAPI"; Endpoint = "/api/indicators"; Method = "POST" },
    #@{ Key = "ImportIndicatorsAPI"; Endpoint = "/api/indicators/import"; Method = "POST" },
    #@{ Key = "DeleteIndicatorAPI"; Endpoint = "/api/indicators/{id}"; Method = "DELETE" },
    #@{ Key = "GetIPRelatedAlertsAPI"; Endpoint = "/api/ips/{ip}/alerts"; Method = "GET" },
    @{ Key = "ListMachinesAPI"; Endpoint = "/api/machines"; Method = "GET" },
    #@{ Key = "GetMachineByIDAPI"; Endpoint = "/api/machines/{id}"; Method = "GET" },
    #@{ Key = "GetMachineLogonUsersAPI"; Endpoint = "/api/machines/{id}/logonusers"; Method = "GET" },
    #@{ Key = "GetMachineRelatedAlertsAPI"; Endpoint = "/api/machines/{id}/alerts"; Method = "GET" },
    #@{ Key = "GetInstalledSoftwareAPI"; Endpoint = "/api/machines/{machineId}/software"; Method = "GET" },
    @{ Key = "GetDiscoveredVulnerabilitiesAPI"; Endpoint = "/api/machines/{machineId}/vulnerabilities"; Method = "GET" },
    @{ Key = "GetSecurityRecommendationsAPI"; Endpoint = "/api/machines/{machineId}/recommendations"; Method = "GET" },
    #@{ Key = "AddOrRemoveTagForMachineAPI"; Endpoint = "/api/machines/{id}/tags"; Method = "POST" },
    #@{ Key = "FindDevicesByInternalIPAPI"; Endpoint = "/api/machines/findbyip(ip='{IP}',timestamp={TimeStamp})"; Method = "GET" },
    #@{ Key = "FindDevicesByTagAPI"; Endpoint = "/api/machines/findbytag?tag={tag}&useStartsWithFilter={true/false}"; Method = "GET" },
    @{ Key = "GetMissingKBsByDeviceID"; Endpoint = "/api/machines/{machineId}/getmissingkbs"; Method = "GET" },
    #@{ Key = "SetDeviceValueAPI"; Endpoint = "/api/machines/{machineId}/setDeviceValue"; Method = "POST" },
    #@{ Key = "UpdateMachineAPI"; Endpoint = "/api/machines/{machineId}"; Method = "PATCH" },
    #@{ Key = "ListMachineActionsAPI"; Endpoint = "/api/machineactions"; Method = "GET" },
    #@{ Key = "GetMachineActionAPI"; Endpoint = "/api/machineactions/{id}"; Method = "GET" },
    #@{ Key = "CollectInvestigationPackageAPI"; Endpoint = "/api/machines/{id}/collectInvestigationPackage"; Method = "POST" },
    #@{ Key = "GetPackageSASURIAPI"; Endpoint = "/api/machineactions/{machine action id}/getPackageUri"; Method = "GET" },
    #@{ Key = "IsolateMachineAPI"; Endpoint = "/api/machines/{id}/isolate"; Method = "POST" },
    #@{ Key = "ReleaseDeviceFromIsolationAPI"; Endpoint = "/api/machines/{id}/unisolate"; Method = "POST" },
    #@{ Key = "RestrictAppExecutionAPI"; Endpoint = "/api/machines/{id}/restrictCodeExecution"; Method = "POST" },
    #@{ Key = "RemoveAppRestrictionAPI"; Endpoint = "/api/machines/{id}/unrestrictCodeExecution"; Method = "POST" },
    #@{ Key = "RunAntivirusScanAPI"; Endpoint = "/api/machines/{id}/runAntiVirusScan"; Method = "POST" },
    #@{ Key = "OffboardMachineAPI"; Endpoint = "/api/machines/{id}/offboard"; Method = "POST" },
    #@{ Key = "StopAndQuarantineFileAPI"; Endpoint = "/api/machines/{id}/StopAndQuarantineFile"; Method = "POST" },
    #@{ Key = "GetLiveResponseResultsAPI"; Endpoint = "/api/machineactions/{machine action id}/GetLiveResponseResultDownloadLink(index={command-index})"; Method = "GET" },
    #@{ Key = "CancelMachineActionAPI"; Endpoint = "/api/machineactions/<machineactionid>/cancel"; Method = "POST" },
    #@{ Key = "ListRecommendationsAPI"; Endpoint = "/api/recommendations"; Method = "GET" },
    #@{ Key = "GetRecommendationByIDAPI"; Endpoint = "/api/recommendations/{id}"; Method = "GET" },
    #@{ Key = "ListSoftwareByRecommendationAPI"; Endpoint = "/api/recommendations/{id}/software"; Method = "GET" },
    #@{ Key = "ListDevicesByRecommendationAPI"; Endpoint = "/api/recommendations/{id}/machineReferences"; Method = "GET" },
    #@{ Key = "ListVulnerabilitiesByRecommendationAPI"; Endpoint = "/api/recommendations/{id}/vulnerabilities"; Method = "GET" },
    #@{ Key = "ListRemediationActivitiesAPI"; Endpoint = "/api/remediationtasks"; Method = "GET" },
    #@{ Key = "ListExposedDevicesOfRemediationActivityAPI"; Endpoint = "/api/remediationTasks/{id}/machineReferences"; Method = "GET" },
    #@{ Key = "GetOneRemediationActivityByIDAPI"; Endpoint = "/api/remediationTasks/{id}"; Method = "GET" },
    #@{ Key = "GetExposureScoreAPI"; Endpoint = "/api/exposureScore"; Method = "GET" },
    #@{ Key = "GetDeviceSecureScoreAPI"; Endpoint = "/api/configurationScore"; Method = "GET" },
    #@{ Key = "ListExposureScoreByDeviceGroupAPI"; Endpoint = "/api/exposureScore/ByMachineGroups"; Method = "GET" },
    #@{ Key = "ListSoftwareInventoryAPI"; Endpoint = "/api/Software"; Method = "GET" },
    #@{ Key = "GetSoftwareByIDAPI"; Endpoint = "/api/Software/{Id}"; Method = "GET" },
    #@{ Key = "ListSoftwareVersionDistributionAPI"; Endpoint = "/api/Software/{Id}/distributions"; Method = "GET" },
    #@{ Key = "ListDevicesBySoftwareAPI"; Endpoint = "/api/Software/{Id}/machineReferences"; Method = "GET" },
    #@{ Key = "ListVulnerabilitiesBySoftwareAPI"; Endpoint = "/api/Software/{Id}/vulnerabilities"; Method = "GET" },
    #@{ Key = "GetMissingKBsBySoftwareIDAPI"; Endpoint = "/api/Software/{Id}/getmissingkbs"; Method = "GET" },
    #@{ Key = "GetUserRelatedAlertsAPI"; Endpoint = "/api/users/{id}/alerts"; Method = "GET" },
    #@{ Key = "GetUserRelatedMachinesAPI"; Endpoint = "/api/users/{id}/machines"; Method = "GET" },
    #@{ Key = "ListVulnerabilitiesAPI"; Endpoint = ""; Method = "GET"/api/vulnerabilities },
    #@{ Key = "GetVulnerabilityByIDAPI"; Endpoint = "/api/vulnerabilities/{cveId}"; Method = "GET" },
    #@{ Key = "ListDevicesByVulnerabilityAPI"; Endpoint = "/api/vulnerabilities/{cveId}/machineReferences"; Method = "GET" },
    @{ Key = "ListVulnerabilitiesByMachineAndSoftwareAPI"; Endpoint = "/api/vulnerabilities/machinesVulnerabilities"; Method = "GET" }
)


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
    param ($Endpoint, $Headers, $Method)

    try {
        $response = Invoke-RestMethod -Uri $appIdUri$Endpoint -Headers $Headers -Method $Method
        return $response.value
    }
    
    catch {
        Write-Warning "Error calling API: $_ - Key: $Endpoint"
        return $null
    }
}

$TenantId = ""
$appId = ""
$appSecret = ""
#Give option to log in as global admin.

$token = Get-AuthToken -TenantId $TenantId -appId $appId -appSecret $appSecret -resourceAppIdUri $appIdUri

$headers = @{
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token"
}

$apiData = @()
foreach ($apiEndpoint in $apiEndpoints) {
    $data = Invoke-SecurityCenterApi -Endpoint $apiEndpoint.Endpoint -Headers $headers -Method $apiEndpoint.Method
    if ($null -ne $data) {
        $apiData += [PSCustomObject]@{
            Endpoint = $apiEndpoint.Endpoint
            Data = $data
        }
    }
}

#option to merge via deviceId property
#$apiData[0].Data | Group-Object -property deviceId
#$apiData[1].Data | Group-Object -property deviceId
#$apiData[2].Data | Group-Object -property deviceId
$apiData[5].Data | Select-Object *, @{Name='deviceId'; Expression={$_.machineId}} -ExcludeProperty machineId | Group-Object -property deviceId


#$apiData[3].Data | Group-Object -property machineId #or computerDNS name contains.
#$apiData[4].Data | Group-Object -property computerDnsName


#Change property name from machineId to deviceId.
#match computerDnsName to 


#-----------------------
#Start correlating the objects.

# ToDo:
# - Make all values a custom powershell object: [PSCustomObject]@
# - Add option to call GOV API: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/gov?view=o365-worldwide#api
#Enders Game
# shadow byte
# data gate
# CMDLET - flood portal with fake eicar test file alerts




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