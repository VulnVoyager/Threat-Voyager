param(
    [string]$LogPath,
    [int]$HoursBack = 24
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$TempFile = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.json'
Write-Host " Temporary Security log file: $TempFile"

$milliseconds = $HoursBack * 3600000
$xmlFilter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4724 or EventID=4732 or EventID=4697 or EventID=4698) and TimeCreated[timediff(@SystemTime) &lt;= $milliseconds]]]
    </Select>
  </Query>
</QueryList>
"@

try {
    if ($LogPath) {
        if (-not (Test-Path $LogPath)) {
            Write-Error "Security log file not found: $LogPath"
            exit 1
        }
        $events = Get-WinEvent -Path $LogPath -FilterXPath $xmlFilter -ErrorAction SilentlyContinue
    } else {
        $events = Get-WinEvent -FilterXml ([xml]$xmlFilter) -ErrorAction SilentlyContinue
    }

    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $props = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $props[$d.Name] = $d.'#text'
        }

        $output = $null
        switch ($event.Id) {
            4624 {
                $logonType = $props['LogonType']
                if ($logonType -eq '3' -or $logonType -eq '10') {
                    $logonIdInt = $props['LogonId']
                    $logonIdHex = if ($logonIdInt -match '^\d+$') { '0x{0:x}' -f [uint64]$logonIdInt } else { $logonIdInt }
                    $output = [PSCustomObject]@{
                        Id = 4624; Time = $event.TimeCreated.ToString('o')
                        TargetUser = $props['TargetUserName']
                        LogonType = [int]$logonType
                        SourceIp = $props['IpAddress']
                        LogonId = $logonIdHex
                    }
                }
            }
            4625 {
                $logonType = $props['LogonType']
                if ($logonType -eq '3' -or $logonType -eq '10') {
                    $output = [PSCustomObject]@{
                        Id = 4625; Time = $event.TimeCreated.ToString('o')
                        TargetUser = $props['TargetUserName']
                        LogonType = [int]$logonType
                        SourceIp = $props['IpAddress']
                    }
                }
            }
            4720 {
                $output = [PSCustomObject]@{
                    Id = 4720; Time = $event.TimeCreated.ToString('o')
                    TargetUserName = $props['TargetUserName']
                    SubjectUserName = $props['SubjectUserName']
                    SubjectDomainName = $props['SubjectDomainName']
                    IpAddress = $props['IpAddress']
                }
            }
            4724 {
                $output = [PSCustomObject]@{
                    Id = 4724; Time = $event.TimeCreated.ToString('o')
                    TargetUserName = $props['TargetUserName']
                    SubjectUserName = $props['SubjectUserName']
                    IpAddress = $props['IpAddress']
                }
            }
            4732 {
                $output = [PSCustomObject]@{
                    Id = 4732; Time = $event.TimeCreated.ToString('o')
                    TargetUserName = $props['TargetUserName']
                    MemberName = $props['MemberName']
                    SubjectUserName = $props['SubjectUserName']
                }
            }
            4697 {
                $output = [PSCustomObject]@{
                    Id = 4697; Time = $event.TimeCreated.ToString('o')
                    ServiceName = $props['ServiceName']
                    ImagePath = $props['ImagePath']
                    SubjectUserName = $props['SubjectUserName']
                }
            }
            4698 {
                $output = [PSCustomObject]@{
                    Id = 4698; Time = $event.TimeCreated.ToString('o')
                    TaskName = $props['TaskName']
                    SubjectUserName = $props['SubjectUserName']
                }
            }
        }

        if ($output) {
            $jsonLine = $output | ConvertTo-Json -Compress
            Add-Content -Path $TempFile -Value $jsonLine -Encoding UTF8
        }
    }

    Write-Output "OUTPUT_FILE:$TempFile"
}
catch {
    Write-Error "Error: $($_.Exception.Message)"
    if (Test-Path $TempFile) { Remove-Item $TempFile -Force }
    exit 1
}
