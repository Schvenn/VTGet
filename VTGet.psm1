function vtget($indicator, $mode, [switch]$save, [switch]$help) {# Query VT for file or URL reputations, if available.

# Modify fields sent to it with proper word wrapping.
function wordwrap ($field, $maximumlinelength) {if ($null -eq $field) {return $null}
$breakchars = ',.;?!\/ '; $wrapped = @()
if (-not $maximumlinelength) {[int]$maximumlinelength = (100, $Host.UI.RawUI.WindowSize.Width | Measure-Object -Maximum).Maximum}
if ($maximumlinelength -lt 60) {[int]$maximumlinelength = 60}
if ($maximumlinelength -gt $Host.UI.RawUI.BufferSize.Width) {[int]$maximumlinelength = $Host.UI.RawUI.BufferSize.Width}
foreach ($line in $field -split "`n", [System.StringSplitOptions]::None) {if ($line -eq "") {$wrapped += ""; continue}
$remaining = $line
while ($remaining.Length -gt $maximumlinelength) {$segment = $remaining.Substring(0, $maximumlinelength); $breakIndex = -1
foreach ($char in $breakchars.ToCharArray()) {$index = $segment.LastIndexOf($char)
if ($index -gt $breakIndex) {$breakIndex = $index}}
if ($breakIndex -lt 0) {$breakIndex = $maximumlinelength - 1}
$chunk = $segment.Substring(0, $breakIndex + 1); $wrapped += $chunk; $remaining = $remaining.Substring($breakIndex + 1)}
if ($remaining.Length -gt 0 -or $line -eq "") {$wrapped += $remaining}}
return ($wrapped -join "`n")}

# Display a horizontal line.
function line ($colour, $length, [switch]$pre, [switch]$post, [switch]$double) {if (-not $length) {[int]$length = (100, $Host.UI.RawUI.WindowSize.Width | Measure-Object -Maximum).Maximum}
if ($length) {if ($length -lt 60) {[int]$length = 60}
if ($length -gt $Host.UI.RawUI.BufferSize.Width) {[int]$length = $Host.UI.RawUI.BufferSize.Width}}
if ($pre) {Write-Host ""}
$character = if ($double) {"="} else {"-"}
Write-Host -f $colour ($character * $length)
if ($post) {Write-Host ""}}

function help {# Inline help.
function scripthelp ($section) {# (Internal) Generate the help sections from the comments section of the script.
line yellow 100 -pre; $pattern = "(?ims)^## ($section.*?)(##|\z)"; $match = [regex]::Match($scripthelp, $pattern); $lines = $match.Groups[1].Value.TrimEnd() -split "`r?`n", 2; Write-Host $lines[0] -f yellow; line yellow 100
if ($lines.Count -gt 1) {wordwrap $lines[1] 100 | Write-Host -f white | Out-Host -Paging}; line yellow 100}
$scripthelp = Get-Content -Raw -Path $PSCommandPath; $sections = [regex]::Matches($scripthelp, "(?im)^## (.+?)(?=\r?\n)")
if ($sections.Count -eq 1) {cls; Write-Host "$([System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)) Help:" -f cyan; scripthelp $sections[0].Groups[1].Value; ""; return}

$selection = $null
do {cls; Write-Host -f cyan "$(Get-ChildItem (Split-Path $PSCommandPath) | Where-Object { $_.FullName -ieq $PSCommandPath } | Select-Object -ExpandProperty BaseName) Help Sections:`n"; for ($i = 0; $i -lt $sections.Count; $i++) {Write-Host "$($i + 1). " -f cyan -n; Write-Host $sections[$i].Groups[1].Value -f white}
if ($selection) {scripthelp $sections[$selection - 1].Groups[1].Value}
Write-Host -f yellow "`nEnter a section number to view " -n; $input = Read-Host
if ($input -match '^\d+$') {$index = [int]$input
if ($index -ge 1 -and $index -le $sections.Count) {$selection = $index}
else {$selection = $null}} else {""; return}}
while ($true); return}

# External call to help.
if ($help) {help; return}

$powershell = Split-Path $profile
$script:baseModulePath = "$powershell\Modules\VTGet"; $script:configPath = Join-Path $baseModulePath "VTGet.psd1"
if (-not (Test-Path $configPath)) {Write-Host -f red "`nConfig file not found at $configPath`n"; return}
$script:config = Import-PowerShellDataFile -Path $configPath
$script:apikey = $config.privatedata.apikey
[string]$global:OutputBuffer = ''
$global:stringBuilder = New-Object System.Text.StringBuilder

# Function to split output to screen and file.
function appendoutput {param([string]$text, [System.Consolecolor]$colour = $null)
$global:stringBuilder.AppendLine($text) | Out-Null
if ($null -ne $colour) {Write-Host $text -Foregroundcolor $colour} else {Write-Host $text}}

# Error checking.
if ($mode -notmatch "(?i)^(file|url)$") {Write-Host -f cyan "`nUsage: vtget "resource" (file/url) -save`n"; return}

# File handling.
if ($mode -match "(?i)^file$") {if (-not (Test-Path $indicator)) {Write-Host "File not found: $indicator" -f Yellow; return}
$hash = Get-FileHash -Path $indicator -Algorithm SHA256 | Select-Object -ExpandProperty Hash; $headers = @{"x-apikey" = $apikey}; $apiUrl = "https://www.virustotal.com/api/v3/files/$hash"; appendoutput "`nhttps://www.virustotal.com/gui/search/$hash" Cyan
try {$response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get -ErrorAction Stop; $results = $response.data.attributes.last_analysis_results; $positives = $response.data.attributes.last_analysis_stats.malicious; appendoutput "Detected by $positives engine(s)." Red
if (-not $results) {appendoutput "No detailed engine results available." Yellow; return}
$malicious = foreach ($engine in $results.PSObject.Properties.Name) {$entry = $results.$engine
if ($entry.category -eq 'malicious' -and $entry.result) {[PSCustomObject]@{Engine = $entry.engine_name; Result = $entry.result}}}
if (-not $malicious) {appendoutput "No malicious results with descriptions found." Yellow; return}
$malicious = $malicious | Sort-Object Engine -Unique; $tableString = $malicious | Format-Table -AutoSize | Out-String; appendoutput $tableString White
$basefile = [IO.Path]::GetFileNameWithoutExtension($indicator); $outfile = "Indicator report - $basefile.vt"
if ($save) {$global:stringBuilder.ToString() | Out-File -FilePath $outfile -Encoding UTF8; appendoutput "Report saved to $outfile" Cyan}}
catch {Write-Host "Error querying VirusTotal:`n$_" -f Yellow}; ""; return}

# URL handling.
if ($mode -match "(?i)^url$")  {$headers = @{"x-apikey" = $apikey}; $apiUrl = "https://www.virustotal.com/api/v3/urls"
if ($indicator -match '(?i)^https?://(?:www\.)?([^/]+)') {$domain = $Matches[1] -replace '[^\w.-]', '_'; $outfile = "Indicator report - $domain.vt"} else {$outfile = "Indicator report - url.vt"}
try {$body = "url=$indicator"; $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $body -ContentType 'application/x-www-form-urlencoded'; $rawBytes = [System.Text.Encoding]::UTF8.GetBytes($indicator); $base64 = [Convert]::ToBase64String($rawBytes); $url_id = $base64 -replace '\+', '-' -replace '/', '_' -replace '='; Start-Sleep -Seconds 3; $report = Invoke-RestMethod -Uri "$apiUrl/$url_id" -Headers $headers -Method Get; $malicious = $report.data.attributes.last_analysis_stats.malicious; $permalink = "https://www.virustotal.com/gui/url/$($url_id -replace '-', '')/detection"
appendoutput "`n$permalink" Cyan; appendoutput "Detected by $malicious engine(s)." Red
$results = foreach ($engine in $report.data.attributes.last_analysis_results.PSObject.Properties) {if ($engine.Value.result -and $engine.Value.result -notin @('clean', 'unrated')) {[PSCustomObject]@{Engine = $engine.Value.engine_name; Result = $engine.Value.result}}}
$results = $results | Sort-Object Engine -Unique; $tablestring = $results | Format-Table -Autosize | Out-String; appendoutput $tableString White
if ($save) {$global:stringBuilder.ToString() | Out-File -FilePath $outfile -Encoding UTF8; appendoutput "Report saved to $outfile" Cyan}} catch {Write-Host "`nError querying VirusTotal:`n$_" Yellow}}; ""; return}

Export-ModuleMember -Function vtget

<#
## VTGet
	Usage: vtget  resource (file/url) -save

VTGet will use an API key to contact VirusTotal.com in order to obtain reputation results for the file/URL passed to it.

If the file option is used, VTGet will calculate the SHA256 for the file and only pass that value to VirusTotal.com, in order to maintain privacy.
## License
MIT License

Copyright © 2025 Craig Plath

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
copies of the Software, and to permit persons to whom the Software is 
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in 
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
THE SOFTWARE.
##>
