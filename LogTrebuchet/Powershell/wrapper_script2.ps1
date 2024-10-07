#Updated version to send data in chunks

#Creating a new folder for the data
if (-Not (Test-Path "DC01_Windows_Security")) {
    New-Item -Name "DC01_Windows_Security" -ItemType "directory"
    Write-Host "[*] New folder created to download data"
}

$uri = "https://github.com/OTRF/Security-Datasets/raw/SecurityDatasets2.0/datasets/atomic/windows/190301-CredsAccess-ADReplication/DC01_Windows_Security.zip"
$wc = New-Object System.Net.WebClient

# Get file name
$request = [System.Net.WebRequest]::Create($uri)
$response = $request.GetResponse()
$fileName = [System.IO.Path]::GetFileName($response.ResponseUri)
$response.Close()
$outputDirectory = Get-ChildItem -Filter "DC01_Windows_Security"
$outputFilePath = Join-Path $outputDirectory $filename

# Download the file
$wc.DownloadFile($uri, $outputFilePath) 
Write-Host "[*] .zip file downloaded at: $outputDirectory"

# Unzip file
$UnpackName = (Get-Item $outputFilePath).Basename
$eventsFolder = Join-Path $outputDirectory $UnpackName
Write-host "[*] Allocating new folder path: $eventsFolder"

# Decompressing file
expand-archive -path $outputFilePath -DestinationPath $eventsFolder -Force
if (!(Test-Path $eventsFolder)) { Write-Error "$outputFilePath was not decompressed successfully" -ErrorAction Stop }
Remove-Item $outputFilePath
$outputFilePath = (Get-ChildItem -Path $eventsFolder | Sort-Object | Select-Object -First 1).FullName

$DceURI = "https://dctest-hxnt.westus-1.ingest.monitor.azure.com"
$DcrImmutableId = "dcr-10565b4a76ce4484a0a32028759206bc"
$resource = "https://dctest-hxnt.westus-1.ingest.monitor.azure.com" 
$clientId = "324c470f-1438-4ba9-a011-630cf2eda559"
$tenantId = "3cd87a41-1f61-4aef-a212-cefdecd9a2d1"
$client_secret = Read-Host "What's the client secret?"

$scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
$body = "client_id=$clientId&scope=$scope&client_secret=$client_Secret&grant_type=client_credentials";
$uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
$bearerToken = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers).access_token

$securityEventProperties=@("AccessMask","Account","AccountDomain","AccountExpires","AccountName","AccountSessionIdentifier","AccountType","Activity","AdditionalInfo","AdditionalInfo2","AllowedToDelegateTo","Attributes","AuditPolicyChanges","AuditsDiscarded","AuthenticationLevel","AuthenticationPackageName","AuthenticationProvider","AuthenticationServer","AuthenticationService","AuthenticationType","AzureDeploymentID","CACertificateHash","CalledStationID","CallerProcessId","CallerProcessName","CallingStationID","CAPublicKeyHash","CategoryId","CertificateDatabaseHash","Channel","ClassId","ClassName","ClientAddress","ClientIPAddress","ClientName","CommandLine","CompatibleIds","Computer","DCDNSName","DeviceDescription","DeviceId","DisplayName","Disposition","DomainBehaviorVersion","DomainName","DomainPolicyChanged","DomainSid","EAPType","ElevatedToken","ErrorCode","EventData","EventID","EventSourceName","ExtendedQuarantineState","FailureReason","FileHash","FilePath","FilePathNoUser","Filter","ForceLogoff","Fqbn","FullyQualifiedSubjectMachineName","FullyQualifiedSubjectUserName","GroupMembership","HandleId","HardwareIds","HomeDirectory","HomePath","InterfaceUuid","IpAddress","IpPort","KeyLength","Level","LmPackageName","LocationInformation","LockoutDuration","LockoutObservationWindow","LockoutThreshold","LoggingResult","LogonGuid","LogonHours","LogonID","LogonProcessName","LogonType","LogonTypeName","MachineAccountQuota","MachineInventory","MachineLogon","ManagementGroupName","MandatoryLabel","MaxPasswordAge","MemberName","MemberSid","MinPasswordAge","MinPasswordLength","MixedDomainMode","NASIdentifier","NASIPv4Address","NASIPv6Address","NASPort","NASPortType","NetworkPolicyName","NewDate","NewMaxUsers","NewProcessId","NewProcessName","NewRemark","NewShareFlags","NewTime","NewUacValue","NewValue","NewValueType","ObjectName","ObjectServer","ObjectType","ObjectValueName","OemInformation","OldMaxUsers","OldRemark","OldShareFlags","OldUacValue","OldValue","OldValueType","OperationType","PackageName","ParentProcessName","PasswordHistoryLength","PasswordLastSet","PasswordProperties","PreviousDate","PreviousTime","PrimaryGroupId","PrivateKeyUsageCount","PrivilegeList","Process","ProcessId","ProcessName","ProfilePath","Properties","ProtocolSequence","ProxyPolicyName","QuarantineHelpURL","QuarantineSessionID","QuarantineSessionIdentifier","QuarantineState","QuarantineSystemHealthResult","RelativeTargetName","RemoteIpAddress","RemotePort","Requester","RequestId","RestrictedAdminMode","RowsDeleted","SamAccountName","ScriptPath","SecurityDescriptor","ServiceAccount","ServiceFileName","ServiceName","ServiceStartType","ServiceType","SessionName","ShareLocalPath","ShareName","SidHistory","SourceComputerId","SourceSystem","Status","StorageAccount","SubcategoryGuid","SubcategoryId","Subject","SubjectAccount","SubjectDomainName","SubjectKeyIdentifier","SubjectLogonId","SubjectMachineName","SubjectMachineSID","SubjectUserName","SubjectUserSid","SubStatus","TableId","TargetAccount","TargetDomainName","TargetInfo","TargetLinkedLogonId","TargetLogonGuid","TargetLogonId","TargetOutboundDomainName","TargetOutboundUserName","TargetServerName","TargetSid","TargetUser","TargetUserName","TargetUserSid","TemplateContent","TemplateDSObjectFQDN","TemplateInternalName","TemplateOID","TemplateSchemaVersion","TemplateVersion","TimeGenerated","TokenElevationType","TransmittedServices","Type","UserAccountControl","UserParameters","UserPrincipalName","UserWorkstations","VendorIds","VirtualAccount","Workstation","WorkstationName")

$jsonObjects = Get-Content $outputFilePath -Raw | Convertfrom-json

# Initialize batched data array
$batchedData = @()

foreach ($line in $jsonObjects) {
    $TimeGenerated = Get-Date ([datetime]::UtcNow) -Format O
    $pscustomobject = $line
    $pscustomobject | Add-Member -MemberType NoteProperty -Name 'TimeGenerated' -Value $TimeGenerated -Force

    $currentEventProperties = Get-Member -InputObject $pscustomobject -MemberType NoteProperty
    $allowedProperties = Compare-Object -ReferenceObject $securityEventProperties -DifferenceObject $currentEventProperties.name -PassThru -ExcludeDifferent -IncludeEqual
    
    $batchedData += $pscustomobject  # Add to batched data

    $message = $pscustomobject | Select-Object -Property @($allowedProperties) | ConvertTo-Json -Compress -AsArray
}

    #   Convert batched data to JSON
    $batchedMessage = $batchedData | ConvertTo-Json -Compress -AsArray

    $headers2 = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" };
    Write-Output $bearerToken
    $uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/Custom-SecurityEvent"+"?api-version=2023-01-01";
    $uploadResponse = Invoke-RestMethod -Uri $uri -Method "Post" -Body $batchedMessage -Headers $headers2;

    # Let's see how the response looks
    Write-Output $uploadResponse
    Write-Output $message
    Write-Output "---------------------"
