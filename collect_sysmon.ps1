param(
    [string]$LogPath,
    [int]$HoursBack = 24
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$TempFile = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.json'
Write-Host " Temporary file: $TempFile"

$xmlFilter = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=1 or EventID=3 or EventID=11 or EventID=13) and TimeCreated[timediff(@SystemTime) &lt;= $($HoursBack * 3600000)]]]
    </Select>
  </Query>
</QueryList>
"@

try {
    $events = if ($LogPath) {
        if (-not (Test-Path $LogPath)) {
            Write-Error "Log file not found: $LogPath"
            exit 1
        }
        Get-WinEvent -Path $LogPath -FilterXPath $xmlFilter -ErrorAction SilentlyContinue
    } else {
        Get-WinEvent -FilterXml ([xml]$xmlFilter) -ErrorAction SilentlyContinue
    }

    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()

        switch ($event.Id) {
            1 {
                $image = $null; $cmd = $null; $parent = $null; $logonId = $null; $processId = $null; $parentProcessId = $null
                foreach ($d in $xml.Event.EventData.Data) {
                    switch ($d.Name) {
                        'Image'          { $image = $d.'#text' }
                        'CommandLine'    { $cmd = $d.'#text' }
                        'ParentImage'    { $parent = $d.'#text' }
                        'LogonId'        { $logonId = $d.'#text' }
                        'ProcessId'      { $processId = $d.'#text' }
                        'ParentProcessId'{ $parentProcessId = $d.'#text' }
                    }
                }
                $obj = [PSCustomObject]@{
                    Id = 1; Time = $event.TimeCreated.ToString('o')
                    Image = $image; CommandLine = $cmd; ParentImage = $parent
                    LogonId = $logonId; ProcessId = $processId; ParentProcessId = $parentProcessId
                }
            }
            3 {
                $ip = $null; $port = $null; $logonId = $null; $hostname = $null
                foreach ($d in $xml.Event.EventData.Data) {
                    switch ($d.Name) {
                        'DestinationIp'       { $ip = $d.'#text' }
                        'DestinationPort'     { $port = $d.'#text' }
                        'LogonId'             { $logonId = $d.'#text' }
                        'DestinationHostname' { $hostname = $d.'#text' }
                    }
                }
                $obj = [PSCustomObject]@{
                    Id = 3; Time = $event.TimeCreated.ToString('o')
                    DestinationIp = $ip; DestinationPort = $port; LogonId = $logonId
                    DestinationHostname = $hostname
                }
            }
            11 {
                $target = $null; $image = $null
                foreach ($d in $xml.Event.EventData.Data) {
                    if ($d.Name -eq 'TargetFilename') { $target = $d.'#text' }
                    if ($d.Name -eq 'Image') { $image = $d.'#text' }
                }
                $obj = [PSCustomObject]@{
                    Id = 11; Time = $event.TimeCreated.ToString('o')
                    TargetFilename = $target; Image = $image
                }
            }
            13 {
                $target = $null; $details = $null; $image = $null
                foreach ($d in $xml.Event.EventData.Data) {
                    switch ($d.Name) {
                        'TargetObject' { $target = $d.'#text' }
                        'Details'      { $details = $d.'#text' }
                        'Image'        { $image = $d.'#text' }
                    }
                }
                $obj = [PSCustomObject]@{
                    Id = 13; Time = $event.TimeCreated.ToString('o')
                    TargetObject = $target; Details = $details; Image = $image
                }
            }
            default { continue }
        }

        $jsonLine = $obj | ConvertTo-Json -Compress
        Add-Content -Path $TempFile -Value $jsonLine -Encoding UTF8
    }

    Write-Output "OUTPUT_FILE:$TempFile"
}
catch {
    Write-Error "Error: $($_.Exception.Message)"
    if (Test-Path $TempFile) { Remove-Item $TempFile -Force }
    exit 1
}
