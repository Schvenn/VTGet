@{RootModule = 'VTGet.psm1'
ModuleVersion = '1.0'
GUID = 'd43ea607-49c9-4f1b-9397-3982895af19c'
Author = 'Craig Plath'
CompanyName = 'Plath Consulting Incorporated'
Copyright = '© Craig Plath. All rights reserved.'
Description = 'PowerShell module to check VirusTotal for file and URL reputations and optionally save the results to disk.'
PowerShellVersion = '5.1'
FunctionsToExport = @('VTGet')
CmdletsToExport = @()
VariablesToExport = @()
AliasesToExport = @()
FileList = @('VTGet.psm1')

PrivateData = @{PSData = @{Tags = @('virustotal', 'sha256', 'url', 'powershell', 'api')
LicenseUri = 'https://github.com/Schvenn/TCX2CSV/VTGet/blob/main/LICENSE'
ProjectUri = 'https://github.com/Schvenn/TCX2CSV/VTGet'
ReleaseNotes = 'Initial release.'}

apikey = 'REPLACE THIS STRING WITH YOUR PERSONAL OR BUSINESS APIKEY'}}
