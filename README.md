# VTGet
PowerShell module to check VirusTotal for file and URL reputations and optionally save the results to disk.

    Usage: vtget "resource" (file/url) -save

Check a file on a local system without having to navigate to VirusTotal.com or upload a file, which may expose sensitive data.
Instead, this module will create the SHA256 hash and test it against VirusTotal.com first.
If malicious matches are found, a report is generated on screen and optionally, saved to disk that includes the VirusTotal results URL as well as a table of the engines that identified it as malicious.

More useful for SOC personnel, this module can also check URLs the same way and having a simple text report with a link to the report and a table of the results, is useful for attaching to incident tickets.
