####################################################
##                                                ##
##               CHECK CONNECTION                 ##
##                                                ##
####################################################

$connection = Test-NetConnection

#check internet connection
if($connection.PingSucceeded -eq $false){
    $dateToday = Get-Date
    $path = "C:\Path\To\BackupLogs"
    $dateToday = $dateToday.ToString("MM-dd-yyyy_HHmmss")
    $logPath = "$path\BackupLog_$dateToday.log"

    Start-Transcript -Path $logPath

    Write-Output $dateToday
    
    $connection

    Write-Output "No internet Connection"

    Stop-Transcript
    
    Send_Email_If_Uploaded -LogFile $logPath
} else {
    ####################################################
    ##                                                ##
    ##                  CREDENTIALS                   ##
    ##                                                ##
    ####################################################
    $config = Get-Content ".\config.json" | ConvertFrom-Json

	$clientId        = $config.Google.ClientId
	$clientSecret    = $config.Google.ClientSecret
	$tokenUri        = $config.Google.TokenUri
	$redirectUri     = $config.Google.RedirectUri
	$scope           = $config.Google.Scope
	$localFolderPath = $config.Paths.LocalData
	$logFolderPath   = $config.Paths.LogFolder

	# (Optional) Google Drive root folder ID
	$driveRootId     = $config.Google.DriveRootId

	# These should not be hardcoded – keep them in config
	$refresh_Token   = $null
	$access_Token    = $null

    #For checking Access Token and Refresh Token
    $checkFile = Get-ChildItem -File -Path $localFolderPath
    $checkRefresh = $localFolderPath + "\refreshToken.txt"
    $checkAccess = $localFolderPath + "\accessToken.txt"

    #Initialize variables for progress tracking
    $totalFilesToUpload = 0
    $totalFilesUploaded = 0
    $totalFoldersToCreate = 0
    $totalFoldersCreated = 0

    ###################################################
    ##                                               ##
    ##          Get-FileAndFolderCount               ##
    ##      Function to get file & folder count      ##
    ###################################################
    function Get-FileAndFolderCount {
        param (
            [string]$folderId,
            [int]$fileCount,
            [int]$folderCount,
            [string]$pageToken = $null
        )

	$headers = @{ Authorization = "Bearer $access_Token" }
        $query = "'$folderId' in parents and trashed=false"
        if ($pageToken) { $query += "&pageToken=$pageToken" }

        $fields = "files(id,name,mimeType), nextPageToken"

        # Make the API request
        $response = Invoke-RestMethod -Uri "https://www.googleapis.com/drive/v3/files?q=$query&fields=$fields" -Headers $headers -Method Get 

        foreach($item in $response.files){
            #check if folder or file
            if($item.mimeType -ne "application/vnd.google-apps.folder"){
                $Global:fileCount++
            } else {
                #increment folder count, go to that folder
                $Global:folderCount++
            }

            if($item.mimeType -eq "application/vnd.google-apps.folder"){
                Get-FileAndFolderCount -folderId $item.id -fileCount $Global:fileCount -folderCount $Global:folderCount
            }
        }

        # Check if there are more pages
        if ($response.nextPageToken) {
            Get-FileAndFolderCount -folderId $folderId -fileCount $Global:fileCount -folderCount $Global:folderCount -pageToken $response.nextPageToken
        }
    }

    ###################################################
    ##                                               ##
    ##          Get-FilesAndFoldersCount             ##
    ##     Function to Get Files and Folder count    ##
    ###################################################
    function Get-FilesAndFoldersCount {
        param(
            [string]$localPath
        )

        $global:totalFilesToUpload += (Get-ChildItem -File -Path $localPath).Count
        $global:totalFoldersToCreate += (Get-ChildItem -Directory -Path $localPath).Count

        # Recursively iterate through subfolders
        foreach ($folder in (Get-ChildItem -Directory -Path $localPath)) {
            Get-FilesAndFoldersCount -localPath $folder.FullName
        }
    }

    ###################################################
    ##                                               ##
    ##          Count-FilesAndFoldersInDrive         ##
    ##  Function to count files and folder in Drive  ##
    ###################################################
    function Count-FilesAndFoldersInDrive {
        param (
            [string]$folderId,
            [int]$driveFileCount,
            [int]$driveFolderCount,
            [string]$pageToken = $null
        )

	$headers = @{ Authorization = "Bearer $access_Token" }
        $query = "'$folderId' in parents and trashed=false"
        if ($pageToken) { $query += "&pageToken=$pageToken" }

        $fields = "files(id,name,mimeType), nextPageToken"

        # Make the API request
        $response = Invoke-RestMethod -Uri "https://www.googleapis.com/drive/v3/files?q=$query&fields=$fields" -Headers $headers -Method Get 

        foreach($item in $response.files){
            #check if folder or file
            if($item.mimeType -ne "application/vnd.google-apps.folder"){
                $driveFileCount++
            } else {
                #increment folder count, go to that folder
                $driveFolderCount++
            
                if($item.mimeType -eq "application/vnd.google-apps.folder"){
                    $counts = Count-FilesAndFoldersInDrive -folderId $item.id -driveFileCount $driveFileCount -driveFolderCount $driveFolderCount
                    $driveFileCount = $counts.driveFileCount
                    $driveFolderCount = $counts.driveFolderCount
                }
            }
        }

        # Check if there are more pages
        if ($response.nextPageToken) {
            $counts = Count-FilesAndFoldersInDrive -folderId $folderId -driveFileCount $driveFileCount -driveFolderCount $driveFolderCount -pageToken $response.nextPageToken
            $driveFileCount = $counts.driveFileCount
            $driveFolderCount = $counts.driveFolderCount
        }

        return @{
            driveFileCount = $driveFileCount
            driveFolderCount = $driveFolderCount
        }
    }

    ###################################################
    ##                                               ##
    ##              Count-FilesAndFolders            ##
    ##    Function to Count Local Files and Folder   ##
    ###################################################
    function Count-FilesAndFolders {
        param(
            [string]$folderPath
        )

        $filesCount = (Get-ChildItem -Path $folderPath -File | Measure-Object).Count
        $foldersCount = (Get-ChildItem -Path $folderPath -Directory | Measure-Object).Count

        foreach ($subfolder in Get-ChildItem -Path $folderPath -Directory) {
            $filesCount += (Count-FilesAndFolders -folderPath $subfolder.FullName).filesCount
            $foldersCount += (Count-FilesAndFolders -folderPath $subfolder.FullName).foldersCount
        }

        return @{
            filesCount = $filesCount
            foldersCount = $foldersCount
        }
    }

    ####################################################
    ##                                                ##
    ##                   Get-AuthCode                 ##
    ## Function to Get Authorization Code from Google ##
    ####################################################
    Function Get-AuthCode{
        Start-Process -Wait -FilePath $authURL Wait-Process

        $Redirect_Uri = Read-Host "URL"
        $uri = [System.Uri] $Redirect_Uri

        Add-Type -AssemblyName System.Web
        $authorizationCode = [System.Web.HttpUtility]::ParseQueryString($uri.Query).Get("code")

        $body = @{
            code = $authorizationCode;
            client_id  = $clientId;
            client_secret = $clientSecret;
            redirect_uri = $RedirectUri;
            grant_type="authorization_code"; # Fixed value
        };

        $authResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -Body $body

        $Global:refresh_Token = $authResponse.refresh_token
        $Global:access_Token = $authResponse.access_token

        $checkFile = Get-ChildItem -File -Path $localFolderPath

        $savePath = $localFolderPath + '\refreshToken.txt'


        if($refresh_Token -ne $null){
            if($checkFile.Name -eq "refreshToken.txt") {
                Set-Content $savePath $authResponse.refresh_token
            } else {
                New-Item -path $localFolderPath -name "refreshToken.txt" -type "file"
            
                Set-Content $savePath $authResponse.refresh_token
            }
        }

        if($access_Token -ne $null){
            if($checkFile.Name -eq "accessToken.txt"){
                Set-Content $checkAccess $authResponse.access_token
            } else {
                New-Item -path $localFolderPath -name "accessToken.txt" -type "file"

                Set-Content $checkAccess $authResponse.access_token
            }
        }
    }

    ###################################################
    ##                                               ##
    ##          Check-AccessTokenExpiration          ##
    ##         Function to check access token        ##
    ###################################################
    function Check-AccessTokenExpiration {
        param(
            [string]$accessToken
        )

        $introspectionEndpoint = "https://www.googleapis.com/oauth2/v1/tokeninfo"
        $url = "${introspectionEndpoint}?access_token=${accessToken}"
        $response = Invoke-RestMethod -Uri $url -Method Get

        if ($response.expires_in -gt 100) {
            return $true
        } else {
            if (Test-Path (Join-Path $localFolderPath "accessToken.txt")) {
                # Clear the content of accessToken.txt
                Clear-Content (Join-Path $localFolderPath "accessToken.txt")
            }
            return $false
        }
    }

    ###################################################
    ##                                               ##
    ##               Generate_base64Key              ##
    ##        Function to generate base64 Key        ##
    ###################################################
    function Generate_base64Key{
        $date = (Get-Date).ToString("MMyyyydd")
        $base64date = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($date))

        $string = "GAPI-RENTAL-" + $base64date
        $base64String = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($string))


        #$returnstring = $base64String + $base64date 
        
        return $base64String
    }

    ###################################################
    ##                                               ##
    ##                GetNewRefreshToken             ##
    ##    Function to get new RefreshToken via API   ##
    ###################################################
    function GetNewRefreshToken{
        # Set the URL of your PHP script
        $url = "<API URL FOR REFRESH TOKEN>"

        # Set the Base64 encoded string (replace with your actual encoded string)
        $base64String = Generate_base64Key

        # Build the URL with the Base64 encoded string
        $urlWithToken = $url -replace "{token}", $base64String

        # Call the PHP script and get the response
        $response = Invoke-RestMethod -Uri $urlWithToken

        # Display the response
        $global:refresh_Token = $response.refresh_token
    }

    ###################################################
    ##                                               ##
    ##                  RefreshToken                 ##
    ##         Function to get refresh token         ##
    ###################################################
    function RefreshToken {
    
        GetNewRefreshToken

        #exchange refresh token to access token
        $refreshParams = @{
            client_id = $clientId;
            client_secret = $clientSecret;
            refresh_token = $refresh_Token;
            grant_type = "refresh_token"; #Fixed value
        }

        try{
            $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -Body $refreshParams
        

            $Global:access_Token = $tokenResponse.access_token
        } catch {
            # If there's an error, call Get-AuthCode
            Write-Warning -Message $_
        }
    }

    ###################################################
    ##                                               ##
    ##          ReplaceToSpecialCharacter            ##
    ##     Function to replace special character     ##
    ###################################################
    function ReplaceToSpecialCharacter{
        param(
            [string]$Name
        )

        #replace special character
            if($Name.Contains("\")){
                $Name = $Name.Replace("\","X01X")
            } elseif($Name.Contains("/")){
                $Name = $Name.Replace("/","X02X")
            } elseif($Name.Contains("'")){
                $Name = $Name.Replace("'","X03X")
            } elseif($Name.Contains("?")){
                $Name = $Name.Replace("?"."X04X")
            } elseif($Name.Contains("*")){
                $Name = $Name.Replace("*","X05X")
            } elseif($Name.Contains("<")){
                $Name = $Name.Replace("<","X06X")
            } elseif($Name.Contains(">")){
                $Name = $Name.Replace(">","X07X")
            } elseif($Name.Contains("|")){
                $Name = $Name.Replace("|","X08X")
            } elseif($Name.Contains("+")){
                $Name = $Name.Replace("+","X09X")
            } elseif($Name.Contains('"')){
                $Name = $Name.Replace('"',"X10X")
            } elseif($Name.Contains("&")){
                $Name = $Name.Replace("&","X11X")
            } elseif($Name.Contains("#")){
                $Name = $Name.Replace("#","X12X")
            } elseif($Name.Contains(":")){
                $Name = $Name.Replace(":","X13X")
            } elseif($Name.Contains("ñ")){
                $Name = $Name.Replace("ñ","X14X")
            } elseif($Name.Contains("Ñ")){
                $Name = $Name.Replace("Ñ","X15X")
            } elseif($Name.Contains("’")){
                $Name = $Name.Replace("’","X16X")
            }

        return $Name
    }

    ###################################################
    ##                                               ##
    ##        ReplaceFromSpecialCharacter            ##
    ##     Function to replace special character     ##
    ###################################################
    function ReplaceFromSpecialCharacter{
        param(
            [string]$Name
        )

        #replace special character
            if($Name.Contains("X01X")){
                $Name = $Name.Replace("X01X","\")
            } elseif($Name.Contains("X02X")){
                $Name = $Name.Replace("X02X","/")
            } elseif($Name.Contains("X03X")){
                $Name = $Name.Replace("X03X","'")
            } elseif($Name.Contains("X04X")){
                $Name = $Name.Replace("X04X"."?")
            } elseif($Name.Contains("X05X")){
                $Name = $Name.Replace("X05X","*")
            } elseif($Name.Contains("X06X")){
                $Name = $Name.Replace("X06X","<")
            } elseif($Name.Contains("X07X")){
                $Name = $Name.Replace("X07X",">")
            } elseif($Name.Contains("X08X")){
                $Name = $Name.Replace("X08X","|")
            } elseif($Name.Contains("X09X")){
                $Name = $Name.Replace("X09X","+")
            } elseif($Name.Contains('X10X')){
                $Name = $Name.Replace('X10X','"')
            } elseif($Name.Contains("X11X")){
                $Name = $Name.Replace("X11X","&")
            } elseif($Name.Contains("X12X")){
                $Name = $Name.Replace("X12X","#")
            } elseif($Name.Contains("X13X")){
                $Name = $Name.Replace("X13X",":")
            } elseif($Name.Contains("X14X")){
                $Name = $Name.Replace("X14X","ñ")
            } elseif($Name.Contains("X15X")){
                $Name = $Name.Replace("X15X","Ñ")
            } elseif($Name.Contains("X16X")){
                $Name = $Name.Replace("X16X","’")
            }

        return $Name
    }

####################################################
##                                                ##
##               Upload-FileToDrive               ##
## function to Upload file to Drive with metadata ##
####################################################
function Upload-FileToDrive {
    param (
        [string]$localFilePath,
        [string]$driveParentId,
        [string]$modifiedDate
    )


    $localFileName = [System.IO.Path]::GetFileName($localFilePath)
    $fileName = ReplaceToSpecialCharacter -Name $localFileName

    $sourceBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($localFilePath))
    $sourceMime = [System.Web.MimeMapping]::GetMimeMapping($localFilePath)

    $fileContent = Get-Content -Path $localFilePath -Raw
    $fileMetadata = @{
        name     = $fileName
        description = $modifiedDate
        parents  = @($driveParentId)
    }

    $fileUploadResponse = Invoke-RestMethod -Uri $uploadUrl -Method POST -Headers @{ Authorization = "Bearer $access_Token"} -ContentType "multipart/related; boundary=foo_bar_baz" -Body @"
--foo_bar_baz
Content-Type: application/json; charset=UTF-8

$($fileMetadata | ConvertTo-Json)

--foo_bar_baz
Content-Transfer-Encoding: base64
Content-Type: $sourceMime

$sourceBase64
--foo_bar_baz--
"@

    $global:totalFilesUploaded++
    
    if($fileUploadResponse){
        $Global:totalFileUpload ++
    }
}

    ###################################################
    ##                                               ##
    ##          Create-GoogleDriveFolder             ##
    ##  Function to create a folder in Google Drive  ##
    ###################################################
    function Create-GoogleDriveFolder {
        param (
            [string]$folderName,
            [string]$driveParentId,
            [string]$modifiedDate
        )

        $GBody = @{
            name = $folderName
            mimeType = "application/vnd.google-apps.folder"
            description = $modifiedDate
            parents = @($driveParentId)
        }

        $GBody = $GBody | ConvertTo-Json

        $folderCreateResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/drive/v3/files" -Method POST -Headers @{
            Authorization = "Bearer $access_Token"
        } -ContentType "application/json" -Body $GBody

        $global:totalFoldersCreated++

        return $folderCreateResponse.id
    }

    ###################################################
    ##                                               ##
    ##              Check-DeletedFiles               ##
    ##         Function to check deleted files       ##
    ###################################################
    function Check-DeletedFiles {
        param(
            [string]$localPath,
            [string]$driveId
        )

        $CheckFileHeaders = @{
            Authorization = "Bearer $access_Token"
        }

        #check drive File exists in local
        $query1 = "'$driveId' in parents and trashed=false"
        $fields = "files(id, name, description, mimeType)"
        $checkDriveFiles = Invoke-RestMethod -Uri "https://www.googleapis.com/drive/v3/files?q=$query1&fields=$fields" -Headers $CheckFileHeaders -Method Get 

        $localFiles = Get-ChildItem -File -Path $localPath | Select-Object Name, FullName

        # Initialize an array to store unmatched drive file names
        $unmatchedDriveFiles = @()

        foreach($driveFile in $checkDriveFiles.files){
            if($drivefile.mimeType -ne "application/vnd.google-apps.folder"){
                $driveFileName = ReplaceFromSpecialCharacter -Name $driveFile.name
                # Check if the drive file name exists in the list of local files
                if ($driveFileName -notin $localFiles.Name) {
                    # If not found, add the drive file name to the array
                    $unmatchedDriveFiles += [PSCustomObject]@{
                        Name = $driveFile.name
                        Id = $driveFile.id
                        Desc = $driveFile.description + " $localPath\" + $driveFile.name
                        }
                    }
                }
            }
        

        foreach($unmatchDriveFile in $unmatchedDriveFiles){
            $Id = $unmatchDriveFile.Id

            # Prepare the new parent folder ID where you want to move the file
            $newParentFolderId = "<PARENT FOLDER ID>"
            # Copy the file to the new folder
            
            $copyFileParams = @{
                parents = @($newParentFolderId)
                name = $unmatchDriveFile.Name
                description = $unmatchDriveFile.Desc
            }

            $copyFileHeaders = @{
                Authorization = "Bearer $access_Token"
                "Content-Type" = "application/json"
            }
  
            $copyFileUri = "https://www.googleapis.com/drive/v3/files/$Id/copy"
            $copyFileResponse = Invoke-RestMethod -Uri $copyFileUri -Method Post -Headers $copyFileHeaders -Body ($copyFileParams | ConvertTo-Json)

            if($copyFileResponse){
                $deleteUri = "https://www.googleapis.com/drive/v3/files/$Id"

                $deleteResponse = Invoke-RestMethod -Method DELETE -Uri $deleteUri -Headers @{ Authorization = "Bearer $access_Token" }
            }

            $LogDate = $null
            $LogDate = Get-Date
            
            $deletedFileName = $unmatchDriveFile.Name
            Write-Output "$LogDate : Move files to the deleted items = $deletedFileName"
        }
    }


    ###################################################
    ##                                               ##
    ##          Get-ModifiedFileInLocal              ##
    ##        Function to Get Files from local       ##
    ###################################################
    function Get-ModifiedFileInLocal{
        param(
            [string]$localPath,
            [string]$driveId
        )

        # Check access token expiration
        $accessTokenExpired = Check-AccessTokenExpiration -accessToken $access_Token

        if ($accessTokenExpired) {
            # Token expired or about to expire, renew token using refresh token
            RefreshToken
        }

        if($access_Token -ne $null){

            $LogDate = $null
            $LogDate = Get-Date

            $files = Get-ChildItem -File -Path $localPath
            $folders = Get-ChildItem -Directory -Path $localPath

            
            Check-DeletedFiles -localPath $localPath -driveId $driveId

            #checking for folders
            foreach($folder in $folders){

                # Check access token expiration
                $accessTokenExpired = Check-AccessTokenExpiration -accessToken $access_Token

                if ($accessTokenExpired) {
                    # Token expired or about to expire, renew token using refresh token
                    RefreshToken
                }

                $folderName = $folder.Name
                $folderPath = $folder.FullName
                $modifiedDate = $folder.LastWriteTime.ToString("MM/dd/yyyy HH:mm:ss")

                $counts = Count-FilesAndFolders -folderPath $folderPath
                $contentCount = $counts.filesCount + $counts.foldersCount

                #replace special character
                $folderName = ReplaceToSpecialCharacter -Name $folderName

                #Check if folder exists
                $query = "name='$folderName' and '$driveId' in parents and trashed=false"

                $checkFolderHeaders = @{
                    Authorization = "Bearer $access_Token"
                }

                try{
                    $results = Invoke-RestMethod -Uri "https://www.googleapis.com/drive/v3/files?q=$query" -Method GET -Headers $checkFolderHeaders
            
                    $folderId = $results.files[0].id
                    $driveFolderName = $results.files[0].name

                    if($folderId -ne $null){
                        $folderDescriptionUri = "https://www.googleapis.com/drive/v3/files/$folderId" + "?fields=description"

                        $folderDescriptionHeaders = @{
                            Authorization = "Bearer $access_Token"
                        }

                         try {
                            $folderDescriptionResponse = Invoke-RestMethod -Uri $folderDescriptionUri -Method GET -Headers $folderDescriptionHeaders
                            $folderDescription = $folderDescriptionResponse.description
                        } catch {
                            Write-Warning -Message $_
                        }

                        $driveFileCount = 0
                        $driveFoldercount = 0
                        
                        $driveCounts = Count-FilesAndFoldersInDrive -folderId $folderId -driveFileCount $driveFileCount -driveFolderCount $driveFoldercount

                        $driveContentCount = $driveCounts.driveFolderCount + $driveCounts.driveFileCount
                    }

                    if($results.files.Count -gt 0){
                       if($contentCount -ne $driveContentCount){
                            Get-ModifiedFileInLocal -localPath $folderPath -driveId $folderId       
                       } 
                    } else {
                        if(-not($driveFolderName -eq $folderName)){
                            $LogDate = $null
                            $LogDate = Get-Date

                            #If not existing, create new folder
                            Write-Output "$LogDate : New Folder Upload = $folderName"
                            $Global:totalFolderCreated ++
                            $driveSubFolderId = Create-GoogleDriveFolder -folderName $folderName -driveParentId $driveId -modifiedDate $modifiedDate
                            Get-ModifiedFileInLocal -localPath $folderPath -driveId $driveSubFolderId 
                        }
                    }
                } catch {
                    Write-Warning -Message $_   
                }
            }

            #checking for files
            foreach($file in $files){
                $fileName = $file.Name
                $filePath = $file.FullName
                $fileCreationDate = $file.CreationTime
                $fileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                $fileExtension = [System.IO.Path]::GetExtension($file.Name)

                $accessTokenExpired = Check-AccessTokenExpiration -accessToken $access_Token

                if ($accessTokenExpired) {
                    # Token expired or about to expire, renew token using refresh token
                    RefreshToken
                }
                
                $CheckFileHeaders = @{
                    Authorization = "Bearer $access_Token"
                }

                $query1 = "'$driveId' in parents and trashed=false"
                $fields = "files(id, name, description, mimeType)"

                $response = Invoke-RestMethod -Uri "https://www.googleapis.com/drive/v3/files?q=$query1&fields=$fields" -Headers $CheckFileHeaders -Method Get 

                #Renaming pdf to bak
                if($fileExtension -eq ".bak"){
                    #if localFileName is like driveFileName
                    foreach($driveFile in $response.files){
                        $driveFileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($driveFile.Name)
                        $driveFileExtension = [System.IO.Path]::GetExtension($driveFile.Name)
                        $driveFileDate = $driveFile.description

                        if($driveFileExtension -eq ".pdf"){
                            if($fileNameWithoutExtension -like "*$driveFileNameWithoutExtension*"){
                                #check if driveFileDesc is equal to localFile.CreationTime
                                if(($driveFileDate -eq $fileCreationDate)){
                                    #if equal Rename
                                    $newFileName = $fileNameWithoutExtension + [System.IO.Path]::GetExtension($file.Name)
                                    $driveFileId = $driveFile.id

                                    $uri = "https://www.googleapis.com/drive/v3/files/$driveFileId"
                                    $body = @{
                                        "name" = $newFileName
                                    } | ConvertTo-Json

                                    $renameHeaders = @{
                                        Authorization = "Bearer $access_Token"
                                    }

                                    $rename = Invoke-RestMethod -Uri $uri -Headers $renameHeaders -Method Patch -Body $body

                            
                                    if($rename){
                                        $LogDate = $null
                                        $LogDate = Get-Date
                                        Write-Output "$LogDate : Renamed $($driveFile.Name) to $newFileName"
                                    }
                                }
                        }
                        }
                    }
                }

                #Upload remaning

                #replace special character
                $newFileName = ReplaceToSpecialCharacter -Name $fileName

                #Check if file exists
                $query = "name='$newFileName' and '$driveId' in parents and trashed=false"

                $CheckFileHeaders = @{
                    Authorization = "Bearer $access_Token"
                }

                try{
                    $results = Invoke-RestMethod -Uri "https://www.googleapis.com/drive/v3/files?q=$query" -Method GET -Headers $CheckFileHeaders
            
                    $fileId = $results.files[0].id
                    $driveFileName = $results.files[0].name

                    #check if existing in drive
                    if(-not($results.files.Count -gt 0)){
                        if(-not($fileName -eq $driveFileName)){
                            #Upload if not existing
                            $LogDate = $null
                            $LogDate = Get-Date

                            Write-Output "$LogDate : New  File Upload = $fileName"
                            Upload-FileToDrive -localFilePath $filePath -driveParentId $driveId -modifiedDate $fileCreationDate
                        }
                    }
                } catch {
                    Write-Warning -Message $_
                }
            }
        }
    }

    function Send_EmailNotif{
        param(
            [string]$LogFile,
            [string]$InitialDate,
            [string]$FinalDate
        )

        $api_id = '<API_ID>'
        $api_secret = '<API_SECRET>'

        $string = $api_id +':'+ $api_secret
        $base64String = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($string))

        $headers = @{
            "Content-Type" = "applicaiton/json"
            "Authorization" = "Basic " + $base64String
        }

        $response = Invoke-RestMethod -Method POST -Uri "<API URL FOR GETTING AUTH>" -Headers $headers

        $accessToken = $response.data.access_token

        if($accessToken){
            $sendnotif_headers = @{
                'Content-Type' = 'application/json'
                'Authorization' = $accessToken
            }

            $emailBody = @{
                'attachment' = $LogFile
                'email' = "<REDACTED_EMAIL>"
                'template' = 'script_notification'
                'project' = '<PROJECT>'
                'transaction' = '<TRANSACTION>'
                'initial_date' = $initialDate
                'final_date' = $finalDate
                'initial_folder_count' = $folderCount
                'initial_file_count' = $totalFilesToUpload
                'final_folder_count' = $folderCount
                'final_file_count' = $fileCount
            } 

            $req_body = $emailBody | ConvertTo-Json

            $emailNotif_response = Invoke-RestMethod -Method POST -Uri "<API URL FOR SENDING EMAIL NOTIF>" -Headers $sendnotif_headers -Body $req_body
        }
    }

    ###################################################
    ##                                               ##
    ##             PROGRAM STARTS HERE               ##
    ##                                               ##
    ###################################################

    #Check File refreshToken.txt is existing
    RefreshToken   

    #check if access token is not null
    if($access_Token -ne $null){

        $LogDate = Get-Date
        $initialDate = Get-Date

        $date = $initialDate.ToString("MM-dd-yyyy_HHmmss")
    

        $logPath = $path + "\file.log"

        Start-Transcript -Path $logPath

        $rootLocalFolderPath = "<root folder path"
        $parentFolderId = "<parent folder ID>"

        $totalFileUpload = 0
        $totalFolderCreated = 0

        $fileCount = 0
        $folderCount = 0

        Get-FileAndFolderCount -folderId $parentFolderId -fileCount $fileCount -folderCount $folderCount

        # Output the results
        Write-Output ""
        Write-Output "========================================="
        Write-Output "Before Upload: Total Number of Folders and Files in GDrive"
        Write-Output "Number of folders: $folderCount"
        Write-Output "Number of files: $fileCount"

        $year = (Get-Date).ToString("yyyy")

        # Get the total number of files and folders to upload
        Get-FilesAndFoldersCount -localPath $rootLocalFolderPath
        Write-Output ""
        Write-Output "========================================="
        Write-Output "Total Number of Folders and Files in SAP Server"
        Write-Output "Number of folders: $totalFoldersToCreate"
        Write-Output "Number of files: $totalFilesToUpload"
        Write-Output ""
        Write-Output "========================================="

        # Define the Google Drive API URL
        $uploadUrl = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"

        Get-ModifiedFileInLocal -localPath $rootLocalFolderPath -driveId $parentFolderId

        $finalDate = $null
        $finalDate = Get-Date

        Write-Output ""
        Write-Output "========================================="
        Write-Output "Total Folders Created: $totalFolderCreated"
        Write-Output "Total Files Upload: $totalFileUpload"
        Write-Output "$finalDate : Upload Complete!"
        Write-Output "========================================="

        #re-initialized variable
        $fileCount = 0
        $folderCount = 0

        Get-FileAndFolderCount -folderId $parentFolderId -fileCount $fileCount -folderCount $folderCount

        # Output the results
        Write-Output ""
        Write-Output "========================================="
        Write-Output "After Upload: Total Number of Folders and Files in GDrive"
        Write-Output "Number of folders: $folderCount"
        Write-Output "Number of files: $fileCount"
        Write-Output "========================================="
        Write-Output ""

        Stop-Transcript

        Send_EmailNotif -LogFile $logPath -InitialDate $initialDate -FinalDate $finalDate
    }
}