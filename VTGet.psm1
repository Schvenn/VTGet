function vtget($indicator, $mode, [switch]$save) {# Query VT for file or URL reputations, if available.

$powershell = Split-Path $profile
$script:baseModulePath = "$powershell\Modules\VTGet"; $script:configPath = Join-Path $baseModulePath "VTGet.psd1"
if (-not (Test-Path $configPath)) {Write-Host -f red "`nConfig file not found at $configPath`n"; return}
$script:config = Import-PowerShellDataFile -Path $configPath
$script:apikey = $config.privatedata.apikey
[string]$global:OutputBuffer = ''
$global:stringBuilder = New-Object System.Text.StringBuilder

# Function to split output to screen and file.
function Append-Output {param([string]$text, [System.Consolecolor]$colour = $null)
$global:stringBuilder.AppendLine($text) | Out-Null
if ($null -ne $colour) {Write-Host $text -Foregroundcolor $colour} else {Write-Host $text}}

# Error checking.
if ($mode -notmatch "(?i)^(file|url)$") {Write-Host -f cyan "`nUsage: vtget "resource" (file/url) -save`n"; return}

# File handling.
if ($mode -match "(?i)^file$") {if (-not (Test-Path $indicator)) {Write-Host "File not found: $indicator" -f Yellow; return}
$hash = Get-FileHash -Path $indicator -Algorithm SHA256 | Select-Object -ExpandProperty Hash; $headers = @{"x-apikey" = $apikey}; $apiUrl = "https://www.virustotal.com/api/v3/files/$hash"; Append-Output "`nhttps://www.virustotal.com/gui/search/$hash" Cyan
try {$response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get -ErrorAction Stop; $results = $response.data.attributes.last_analysis_results; $positives = $response.data.attributes.last_analysis_stats.malicious; Append-Output "Detected by $positives engine(s)." Red
if (-not $results) {Append-Output "No detailed engine results available." Yellow; return}
$malicious = foreach ($engine in $results.PSObject.Properties.Name) {$entry = $results.$engine
if ($entry.category -eq 'malicious' -and $entry.result) {[PSCustomObject]@{Engine = $entry.engine_name; Result = $entry.result}}}
if (-not $malicious) {Append-Output "No malicious results with descriptions found." Yellow; return}
$malicious = $malicious | Sort-Object Engine -Unique; $tableString = $malicious | Format-Table -AutoSize | Out-String; Append-Output $tableString White
$basefile = [IO.Path]::GetFileNameWithoutExtension($indicator); $outfile = "Indicator report - $basefile.vt"
if ($save) {$global:stringBuilder.ToString() | Out-File -FilePath $outfile -Encoding UTF8; Append-Output "Report saved to $outfile" Cyan}}
catch {Write-Host "Error querying VirusTotal:`n$_" -f Yellow}; ""; return}

# URL handling.
if ($mode -match "(?i)^url$")  {$headers = @{"x-apikey" = $apikey}; $apiUrl = "https://www.virustotal.com/api/v3/urls"
if ($indicator -match '(?i)^https?://(?:www\.)?([^/]+)') {$domain = $Matches[1] -replace '[^\w.-]', '_'; $outfile = "Indicator report - $domain.vt"} else {$outfile = "Indicator report - url.vt"}
try {$body = "url=$indicator"; $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $body -ContentType 'application/x-www-form-urlencoded'; $rawBytes = [System.Text.Encoding]::UTF8.GetBytes($indicator); $base64 = [Convert]::ToBase64String($rawBytes); $url_id = $base64 -replace '\+', '-' -replace '/', '_' -replace '='; Start-Sleep -Seconds 3; $report = Invoke-RestMethod -Uri "$apiUrl/$url_id" -Headers $headers -Method Get; $malicious = $report.data.attributes.last_analysis_stats.malicious; $permalink = "https://www.virustotal.com/gui/url/$($url_id -replace '-', '')/detection"
Append-Output "`n$permalink" Cyan; Append-Output "Detected by $malicious engine(s)." Red
$results = foreach ($engine in $report.data.attributes.last_analysis_results.PSObject.Properties) {if ($engine.Value.result -and $engine.Value.result -notin @('clean', 'unrated')) {[PSCustomObject]@{Engine = $engine.Value.engine_name; Result = $engine.Value.result}}}
$results = $results | Sort-Object Engine -Unique; $tablestring = $results | Format-Table -Autosize | Out-String; Append-Output $tableString White
if ($save) {$global:stringBuilder.ToString() | Out-File -FilePath $outfile -Encoding UTF8; Append-Output "Report saved to $outfile" Cyan}} catch {Write-Host "`nError querying VirusTotal:`n$_" Yellow}}; ""; return}

if (Get-Command vtget -ErrorAction SilentlyContinue) {Write-Host -f green "VTGet loaded successfully."} else {Write-Host -f red "VTGet function not loaded."}