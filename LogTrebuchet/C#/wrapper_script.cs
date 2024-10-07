using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Linq;
using Azure.Identity;


class Program
{
    static async Task Main()
    {
        // Creating a new folder for the data
        string folderPath = "DC01_Windows_Security";
        if (!Directory.Exists(folderPath))
        {
            Directory.CreateDirectory(folderPath);
            Console.WriteLine("[*] New folder created to download data");
        }

        string downloadURI = "https://github.com/OTRF/Security-Datasets/raw/SecurityDatasets2.0/datasets/atomic/windows/190301-CredsAccess-ADReplication/DC01_Windows_Security.zip";

        // Get file name
        string fileName;
        using (HttpClient client = new HttpClient())
        using (HttpResponseMessage response = await client.GetAsync(downloadURI))
        {
            response.EnsureSuccessStatusCode();
            Uri responseUri = response.RequestMessage.RequestUri;
            fileName = Path.GetFileName(responseUri.AbsolutePath);
        }

        string outputDirectory = Path.Combine(Directory.GetCurrentDirectory(), folderPath);
        string outputFilePath = Path.Combine(outputDirectory, fileName);

        // Download the file
        using (HttpClient client = new HttpClient())
        using (HttpResponseMessage response = await client.GetAsync(downloadURI))
        using (Stream contentStream = await response.Content.ReadAsStreamAsync())
        using (Stream fileStream = File.Create(outputFilePath))
        {
            await contentStream.CopyToAsync(fileStream);
        }

        Console.WriteLine($"[*] .zip file downloaded at: {outputDirectory}");

        // Unzip file
        string unpackName = Path.GetFileNameWithoutExtension(outputFilePath);
        string eventsFolder = Path.Combine(outputDirectory, unpackName);
        Console.WriteLine($"[*] Allocating new folder path: {eventsFolder}");

        // Decompressing file
        ZipFile.ExtractToDirectory(outputFilePath, eventsFolder);
        if (!Directory.Exists(eventsFolder))
        {
            Console.WriteLine($"{outputFilePath} was not decompressed successfully");
            return;
        }
        File.Delete(outputFilePath);
        outputFilePath = new DirectoryInfo(eventsFolder).GetFiles()[0].FullName;

        string jsonContent = File.ReadAllText(outputFilePath);
        List<dynamic> jsonObjects = JsonConvert.DeserializeObject<List<dynamic>>(jsonContent);
        Console.WriteLine(jsonObjects[0]);
        
        // Azure credentials
        var credential = new DefaultAzureCredential();
        string dceUri = "https://dctest-hxnt.westus-1.ingest.monitor.azure.com";
        string dcrImmutableId = "dcr-10565b4a76ce4484a0a32028759206bc";
        string resource = "https://dctest-hxnt.westus-1.ingest.monitor.azure.com";
        string clientId = "324c470f-1438-4ba9-a011-630cf2eda559";
        string tenantId = "3cd87a41-1f61-4aef-a212-cefdecd9a2d1";
        string subscriptionId = "9b00bc5e-9abc-45de-9958-02a9d9277b16";
        string resourceGroupName = "Wrapper-Script-Test";
        string workspaceName = "MSSen2GoCLug22vxas67urs";
        Console.Write("What's the client secret?\n");
        string clientSecret = Console.ReadLine();

        string scope = System.Web.HttpUtility.UrlEncode("https://monitor.azure.com/.default");
        string body = $"client_id={clientId}&scope={scope}&client_secret={clientSecret}&grant_type=client_credentials";
        string uri = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";

        using (HttpClient client = new HttpClient())
        {
            // Authentication
            var authContent = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");
            var authResponse = await client.PostAsync(uri, authContent);
            authResponse.EnsureSuccessStatusCode();
            var authResult = JsonConvert.DeserializeAnonymousType(await authResponse.Content.ReadAsStringAsync(), new { access_token = "" });
            string bearerToken = authResult.access_token;

            Console.WriteLine(bearerToken);

            //Console.WriteLine(bearerToken);

            // Security event properties
            var securityEventProperties = new List<string> {"AccessMask","Account","AccountDomain","AccountExpires","AccountName",
                "AccountSessionIdentifier","AccountType","Activity","AdditionalInfo","AdditionalInfo2","AllowedToDelegateTo",
                "Attributes","AuditPolicyChanges","AuditsDiscarded","AuthenticationLevel","AuthenticationPackageName",
                "AuthenticationProvider","AuthenticationServer","AuthenticationService","AuthenticationType","AzureDeploymentID",
                "CACertificateHash","CalledStationID","CallerProcessId","CallerProcessName", "CallingStationID","CAPublicKeyHash",
                "CategoryId","CertificateDatabaseHash","Channel","ClassId","ClassName","ClientAddress","ClientIPAddress","ClientName",
                "CommandLine","CompatibleIds","Computer","DCDNSName","DeviceDescription","DeviceId","DisplayName","Disposition",
                "DomainBehaviorVersion","DomainName","DomainPolicyChanged","DomainSid","EAPType","ElevatedToken","ErrorCode","EventData",
                "EventID","EventSourceName","ExtendedQuarantineState","FailureReason","FileHash","FilePath","FilePathNoUser","Filter",
                "ForceLogoff","Fqbn","FullyQualifiedSubjectMachineName","FullyQualifiedSubjectUserName","GroupMembership","HandleId",
                "HardwareIds","HomeDirectory","HomePath","InterfaceUuid","IpAddress","IpPort","KeyLength","Level","LmPackageName",
                "LocationInformation","LockoutDuration","LockoutObservationWindow","LockoutThreshold","LoggingResult","LogonGuid",
                "LogonHours","LogonID","LogonProcessName","LogonType","LogonTypeName","MachineAccountQuota","MachineInventory",
                "MachineLogon","ManagementGroupName","MandatoryLabel","MaxPasswordAge","MemberName","MemberSid","MinPasswordAge",
                "MinPasswordLength","MixedDomainMode","NASIdentifier","NASIPv4Address","NASIPv6Address","NASPort","NASPortType",
                "NetworkPolicyName","NewDate","NewMaxUsers","NewProcessId","NewProcessName","NewRemark","NewShareFlags","NewTime",
                "NewUacValue","NewValue","NewValueType","ObjectName","ObjectServer","ObjectType","ObjectValueName","OemInformation",
                "OldMaxUsers","OldRemark","OldShareFlags","OldUacValue","OldValue","OldValueType","OperationType","PackageName",
                "ParentProcessName","PasswordHistoryLength","PasswordLastSet","PasswordProperties","PreviousDate","PreviousTime",
                "PrimaryGroupId","PrivateKeyUsageCount","PrivilegeList","Process","ProcessId","ProcessName","ProfilePath","Properties",
                "ProtocolSequence","ProxyPolicyName","QuarantineHelpURL","QuarantineSessionID","QuarantineSessionIdentifier",
                "QuarantineState","QuarantineSystemHealthResult","RelativeTargetName","RemoteIpAddress","RemotePort","Requester",
                "RequestId","RestrictedAdminMode","RowsDeleted","SamAccountName","ScriptPath","SecurityDescriptor","ServiceAccount",
                "ServiceFileName","ServiceName","ServiceStartType","ServiceType","SessionName","ShareLocalPath","ShareName","SidHistory",
                "SourceComputerId","SourceSystem","Status","StorageAccount","SubcategoryGuid","SubcategoryId","Subject","SubjectAccount",
                "SubjectDomainName","SubjectKeyIdentifier","SubjectLogonId","SubjectMachineName","SubjectMachineSID","SubjectUserName",
                "SubjectUserSid","SubStatus","TableId","TargetAccount","TargetDomainName","TargetInfo","TargetLinkedLogonId",
                "TargetLogonGuid","TargetLogonId","TargetOutboundDomainName","TargetOutboundUserName","TargetServerName","TargetSid",
                "TargetUser","TargetUserName","TargetUserSid","TemplateContent","TemplateDSObjectFQDN","TemplateInternalName","TemplateOID",
                "TemplateSchemaVersion","TemplateVersion","TimeGenerated","TokenElevationType","TransmittedServices","Type",
                "UserAccountControl","UserParameters","UserPrincipalName","UserWorkstations","VendorIds","VirtualAccount","Workstation","WorkstationName"
            };

            // Set the maximum allowed size for each chunk (adjust as needed)
            const long maxChunkSize = 1024 * 1024; // 1 MB

            // Initialize variables for chunked data
            List<dynamic> chunkedData = new List<dynamic>();
            long chunkSize = 0;

            foreach (var line in jsonObjects)
            {
                //Updating TimeGenerated to the current time
                line["TimeGenerated"] = DateTime.UtcNow.ToString("O");
                var jObjectPropertyNames = new List<string>();
                
                foreach (var prop in line.Properties()){
                    jObjectPropertyNames.Add(prop.Name);
                }

                // Getting the properties that are not in Security Events
                var propertiesToRemove = jObjectPropertyNames.Except(securityEventProperties);

                // Removing properties that are not in Security Events from the current line we will be sending
                foreach (var property in propertiesToRemove)
                {
                    line.Remove(property);
                }

                // Prepare request headers
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
               
                // Prepare request content
                StringContent content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");

                // Send request to get bearer token
                HttpResponseMessage response = await client.PostAsync(uri, content);

                // Process response
                if (response.IsSuccessStatusCode)
                {
                    // Construct URI for uploading data
                    string uploadURI = $"{dceUri}/dataCollectionRules/{dcrImmutableId}/streams/Custom-SecurityEvent?api-version=2023-01-01";
                    string jsonMessage = JsonConvert.SerializeObject(line);
                    Console.WriteLine("Message being sent:");
                    Console.WriteLine(jsonMessage);

                    // Upload data to Azure Log Analytics workspace
                    await UploadDataAsync(uploadURI, bearerToken, jsonMessage);
                }
                else
                {
                    Console.WriteLine($"Failed to obtain bearer token. Status code: {response.StatusCode}");
                }

                return;
                // // $currentEventProperties = Get-Member -InputObject $pscustomobject -MemberType NoteProperty
                // var currentEventProperties = pscustomobject.GetType().GetProperties();

                // // $allowedProperties = Compare-Object -ReferenceObject $securityEventProperties -DifferenceObject $currentEventProperties.name -PassThru -ExcludeDifferent -IncludeEqual
                // var securityEventProperties = new string[] { /* Add your properties here */ };
                // var allowedProperties = securityEventProperties.Intersect(currentEventProperties.Select(prop => prop.Name));

                // // Calculate the size of the current message
                // string message = JsonConvert.SerializeObject(line, Formatting.None);
                // long messageSize = Encoding.UTF8.GetByteCount(message);

                // // Calculate the size of the array plus the current message
                // long arraySize = Encoding.UTF8.GetByteCount(JsonConvert.SerializeObject(chunkedData));
                // long arrayProposedSize = Encoding.UTF8.GetByteCount(JsonConvert.SerializeObject(chunkedData.Concat(new[] { line })));

        //         // Check if adding the current message exceeds the maximum chunk size
        //         if (arrayProposedSize >= maxChunkSize || line.Equals(jsonObjects.Last()))
        //         {
        //             // Send the current chunk
        //             string endpoint = $"{dceUri}/dataCollectionRules/{dcrImmutableId}/streams/Custom-SecurityEvent?api-version=2023-01-01";
        //             var uploadResponse = await client.PostAsync(endpoint, new StringContent(JsonConvert.SerializeObject(chunkedData), Encoding.UTF8, "application/json"));
        //             uploadResponse.EnsureSuccessStatusCode();

        //             // Clear variables for the next chunk
        //             chunkedData.Clear();
        //             chunkSize = 0;

        //             // Let's see how the response looks
        //             Console.WriteLine(await uploadResponse.Content.ReadAsStringAsync());
        //             Console.WriteLine(message);
        //             Console.WriteLine($"Content Length: {arraySize}");
        //             Console.WriteLine("---------------------");

        //             // Pausing for 1 second before processing the next entry
        //             await Task.Delay(1000);
        //         }

        //         // Add the current message to the chunked data
        //         chunkedData.Add(line);
        //         chunkSize += messageSize;
            }
        }
        Console.WriteLine("Done!");
    }

    static async Task UploadDataAsync(string uri, string bearerToken, string message)
    {
        // Create HttpClient
        using (HttpClient client = new HttpClient())
        {
            // Set bearer token in request headers
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

            // Prepare request content
            StringContent content = new StringContent(message, Encoding.UTF8, "application/json");

            // Send request to upload data
            HttpResponseMessage response = await client.PostAsync(uri, content);

            // Process response
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("Data uploaded successfully.");
            }
            else
            {
                Console.WriteLine($"Failed to upload data. Status code: {response.StatusCode}");
            }
        }
    }
}


