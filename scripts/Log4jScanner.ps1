<#
.SYNOPSIS
    Log4j Shield - Enterprise PowerShell Vulnerability Scanner & Report Generator
.DESCRIPTION
    Standalone PowerShell application with Windows Forms GUI. Scans directories, pom.xml,
    build.gradle, and .jar archives for Apache Log4j vulnerabilities (Log4Shell, CVE-2021-44228,
    CVE-2021-45046, CVE-2021-45105, CVE-2021-44832, Log4j 1.x EOL).
    Can be converted directly into a standalone .EXE using PS2EXE.
.NOTES
    Compile to EXE command:
    Invoke-ps2exe -InputFile .\Log4jScanner.ps1 -OutputFile .\Log4jScanner.exe -noConsole -title "Log4j Shield Scanner"
#>

[CmdletBinding()]
param()

# Ensure Windows Forms & Compression are loaded
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem

[System.Windows.Forms.Application]::EnableVisualStyles()

# --- CVE DATABASE DEFINITION ---
$global:CveDatabase = @(
    @{
        Id = "CVE-2021-44228"
        Name = "Log4Shell RCE"
        Severity = "CRITICAL"
        Cvss = 10.0
        Min = "2.0-beta9"
        Max = "2.14.1"
        Recommended = "2.17.1"
        Desc = "JNDI message lookup RCE vulnerability allowing full unauthenticated remote compromise."
    },
    @{
        Id = "CVE-2021-45046"
        Name = "ThreadContext Pattern RCE"
        Severity = "CRITICAL"
        Cvss = 9.0
        Min = "2.0-beta9"
        Max = "2.15.0"
        Recommended = "2.17.1"
        Desc = "Incomplete patch for CVE-2021-44228 in non-default ThreadContext pattern layout."
    },
    @{
        Id = "CVE-2021-45105"
        Name = "Context Lookup Recursion DoS"
        Severity = "MEDIUM"
        Cvss = 5.9
        Min = "2.0-alpha1"
        Max = "2.16.0"
        Recommended = "2.17.1"
        Desc = "Infinite recursion in self-referential context lookups causing StackOverflowError."
    },
    @{
        Id = "CVE-2021-44832"
        Name = "JDBCAppender JNDI RCE"
        Severity = "MEDIUM"
        Cvss = 6.6
        Min = "2.0-beta7"
        Max = "2.17.0"
        Recommended = "2.17.1"
        Desc = "JDBCAppender DataSource JNDI reference RCE for configuration write access."
    },
    @{
        Id = "CVE-2019-17571"
        Name = "Log4j 1.x SocketServer RCE"
        Severity = "CRITICAL"
        Cvss = 9.8
        Min = "1.0.0"
        Max = "1.2.17"
        Recommended = "ch.qos.reload4j:1.2.25"
        Desc = "Log4j 1.x End-of-Life untrusted object deserialization in SocketServer."
    }
)

# --- HELPER FUNCTIONS ---
function Compare-Log4jVersion {
    param([string]$v1, [string]$v2)

    $clean1 = $v1 -replace '^[vV]', ''
    $clean2 = $v2 -replace '^[vV]', ''

    $regex = '^(\d+)(?:\.(\d+))?(?:\.(\d+))?'
    $m1 = [regex]::Match($clean1, $regex)
    $m2 = [regex]::Match($clean2, $regex)

    $maj1 = if ($m1.Groups[1].Success) { [int]$m1.Groups[1].Value } else { 0 }
    $min1 = if ($m1.Groups[2].Success) { [int]$m1.Groups[2].Value } else { 0 }
    $pat1 = if ($m1.Groups[3].Success) { [int]$m1.Groups[3].Value } else { 0 }

    $maj2 = if ($m2.Groups[1].Success) { [int]$m2.Groups[1].Value } else { 0 }
    $min2 = if ($m2.Groups[2].Success) { [int]$m2.Groups[2].Value } else { 0 }
    $pat2 = if ($m2.Groups[3].Success) { [int]$m2.Groups[3].Value } else { 0 }

    if ($maj1 -ne $maj2) { return ($maj1 - $maj2) }
    if ($min1 -ne $min2) { return ($min1 - $min2) }
    if ($pat1 -ne $pat2) { return ($pat1 - $pat2) }
    return 0
}

function Test-IsVulnerable {
    param([string]$version, [string]$targetJdk = "Java 8+")

    $matched = @()
    foreach ($cve in $global:CveDatabase) {
        $cmpMin = Compare-Log4jVersion $version $cve.Min
        $cmpMax = Compare-Log4jVersion $version $cve.Max
        if ($cmpMin -ge 0 -and $cmpMax -le 0) {
            $matched += $cve
        }
    }

    $isVuln = ($matched.Count -gt 0)
    $maxCvss = 0.0
    $highestSev = "SAFE"
    $rec = "2.17.1"

    if ($isVuln) {
        foreach ($m in $matched) {
            if ($m.Cvss -gt $maxCvss) { $maxCvss = $m.Cvss }
        }
        if ($matched | Where-Object { $_.Severity -eq "CRITICAL" }) {
            $highestSev = "CRITICAL"
        } elseif ($matched | Where-Object { $_.Severity -eq "HIGH" }) {
            $highestSev = "HIGH"
        } else {
            $highestSev = "MEDIUM"
        }
    }

    if ($version.StartsWith("1.")) {
        $rec = "reload4j-1.2.25"
    } elseif ($targetJdk -eq "Java 7") {
        $rec = "2.12.4"
    } elseif ($targetJdk -eq "Java 6") {
        $rec = "2.3.2"
    } else {
        $rec = "2.24.3 (or 2.17.1)"
    }

    return @{
        IsVulnerable = $isVuln
        MatchedCves = $matched
        HighestCvss = $maxCvss
        HighestSeverity = $highestSev
        RecommendedVersion = $rec
    }
}

# --- SCAN ENGINE ---
$global:ScanResults = [System.Collections.ArrayList]::new()

function Scan-File {
    param([string]$filePath, [string]$targetJdk)

    $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
    $fileName = [System.IO.Path]::GetFileName($filePath)

    # 1. Inspect JAR archives
    if ($ext -in @('.jar', '.war', '.ear', '.zip')) {
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($filePath)
            $jndiFound = $false
            $foundVersion = $null
            $foundArtifact = "log4j-core"

            foreach ($entry in $zip.Entries) {
                if ($entry.FullName.EndsWith("JndiLookup.class")) {
                    $jndiFound = $true
                }
                if ($entry.FullName.Contains("META-INF/maven/") -and $entry.FullName.EndsWith("pom.properties")) {
                    $stream = $entry.Open()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $content = $reader.ReadToEnd()
                    $reader.Close()
                    $stream.Close()

                    if ($content -match 'version\s*=\s*(.+)') {
                        $foundVersion = $matches[1].Trim()
                    }
                    if ($content -match 'artifactId\s*=\s*(.+)') {
                        $foundArtifact = $matches[1].Trim()
                    }
                }
            }
            $zip.Dispose()

            # If version was not in pom.properties, check filename (e.g. log4j-core-2.14.1.jar)
            if (-not $foundVersion -and $fileName -match 'log4j(?:-[a-zA-Z0-9]+)?-([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9]+)?)\.jar') {
                $foundVersion = $matches[1]
            }

            if ($foundVersion -or $jndiFound) {
                $ver = if ($foundVersion) { $foundVersion } else { "2.14.1" }
                $eval = Test-IsVulnerable -version $ver -targetJdk $targetJdk
                $cveList = ($eval.MatchedCves | ForEach-Object { $_.Id }) -join ", "

                $res = [PSCustomObject]@{
                    File = $fileName
                    Path = $filePath
                    Type = "JAR Archive"
                    DetectedVersion = $ver
                    Status = if ($eval.IsVulnerable) { $eval.HighestSeverity } else { "SAFE" }
                    Cvss = $eval.HighestCvss
                    JndiClass = if ($jndiFound) { "PRESENT" } else { "STRIPPED" }
                    MatchedCVEs = if ($cveList) { $cveList } else { "None" }
                    RecommendedFix = $eval.RecommendedVersion
                }
                [void]$global:ScanResults.Add($res)
            }
        } catch {
            Write-Verbose "Could not read archive $filePath : $_"
        }
    }

    # 2. Inspect Maven pom.xml
    elseif ($fileName -eq "pom.xml" -or $ext -eq ".xml") {
        try {
            $content = Get-Content -Path $filePath -Raw -ErrorAction SilentlyContinue
            if ($content -match 'log4j') {
                $versionMatches = [regex]::Matches($content, '<artifactId>(log4j[a-zA-Z0-9_-]*|spring-boot-starter-log4j2)<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>')
                foreach ($vm in $versionMatches) {
                    $art = $vm.Groups[1].Value
                    $ver = $vm.Groups[2].Value.Trim()
                    $eval = Test-IsVulnerable -version $ver -targetJdk $targetJdk
                    $cveList = ($eval.MatchedCves | ForEach-Object { $_.Id }) -join ", "

                    $res = [PSCustomObject]@{
                        File = $fileName
                        Path = $filePath
                        Type = "pom.xml"
                        DetectedVersion = $ver
                        Status = if ($eval.IsVulnerable) { $eval.HighestSeverity } else { "SAFE" }
                        Cvss = $eval.HighestCvss
                        JndiClass = "N/A"
                        MatchedCVEs = if ($cveList) { $cveList } else { "None" }
                        RecommendedFix = $eval.RecommendedVersion
                    }
                    [void]$global:ScanResults.Add($res)
                }
            }
        } catch {}
    }

    # 3. Inspect Gradle build.gradle
    elseif ($fileName -like "*gradle*" -or $ext -in @('.gradle', '.kts')) {
        try {
            $content = Get-Content -Path $filePath -Raw -ErrorAction SilentlyContinue
            $matchesGradle = [regex]::Matches($content, 'org\.apache\.logging\.log4j:([a-zA-Z0-9_-]+):([a-zA-Z0-9._-]+)')
            foreach ($gm in $matchesGradle) {
                $art = $gm.Groups[1].Value
                $ver = $gm.Groups[2].Value.Trim()
                $eval = Test-IsVulnerable -version $ver -targetJdk $targetJdk
                $cveList = ($eval.MatchedCves | ForEach-Object { $_.Id }) -join ", "

                $res = [PSCustomObject]@{
                    File = $fileName
                    Path = $filePath
                    Type = "build.gradle"
                    DetectedVersion = $ver
                    Status = if ($eval.IsVulnerable) { $eval.HighestSeverity } else { "SAFE" }
                    Cvss = $eval.HighestCvss
                    JndiClass = "N/A"
                    MatchedCVEs = if ($cveList) { $cveList } else { "None" }
                    RecommendedFix = $eval.RecommendedVersion
                }
                [void]$global:ScanResults.Add($res)
            }
        } catch {}
    }
}

# --- GUI WINDOW DEFINITION ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Log4j Shield - Vulnerability Scanner & Report Generator"
$form.Size = New-Object System.Drawing.Size(1020, 680)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(15, 23, 42) # Slate-900
$form.ForeColor = [System.Drawing.Color]::White
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)

# --- Top Header Panel ---
$topPanel = New-Object System.Windows.Forms.Panel
$topPanel.Dock = "Top"
$topPanel.Height = 80
$topPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59) # Slate-800
$form.Controls.Add($topPanel)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "Log4j Shield - Security Compliance Scanner"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(244, 63, 94) # Rose-500
$lblTitle.Location = New-Object System.Drawing.Point(20, 15)
$lblTitle.AutoSize = $true
$topPanel.Controls.Add($lblTitle)

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = "Scans files, manifests (pom.xml, build.gradle) & JAR archives for Log4Shell (CVE-2021-44228 / 45046 / 45105 / 44832)"
$lblSub.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
$lblSub.ForeColor = [System.Drawing.Color]::FromArgb(148, 163, 184)
$lblSub.Location = New-Object System.Drawing.Point(22, 45)
$lblSub.AutoSize = $true
$topPanel.Controls.Add($lblSub)

# --- Control Panel ---
$ctlPanel = New-Object System.Windows.Forms.Panel
$ctlPanel.Dock = "Top"
$ctlPanel.Height = 110
$ctlPanel.BackColor = [System.Drawing.Color]::FromArgb(15, 23, 42)
$ctlPanel.Padding = New-Object System.Windows.Forms.Padding(20, 10, 20, 10)
$form.Controls.Add($ctlPanel)

$lblTarget = New-Object System.Windows.Forms.Label
$lblTarget.Text = "Target Scan Directory / Workspace:"
$lblTarget.Location = New-Object System.Drawing.Point(20, 15)
$lblTarget.AutoSize = $true
$lblTarget.ForeColor = [System.Drawing.Color]::FromArgb(203, 213, 225)
$ctlPanel.Controls.Add($lblTarget)

$txtPath = New-Object System.Windows.Forms.TextBox
$txtPath.Location = New-Object System.Drawing.Point(20, 38)
$txtPath.Size = New-Object System.Drawing.Size(560, 26)
$txtPath.Text = (Get-Location).Path
$txtPath.BackColor = [System.Drawing.Color]::FromArgb(2, 6, 23)
$txtPath.ForeColor = [System.Drawing.Color]::White
$ctlPanel.Controls.Add($txtPath)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = "Browse..."
$btnBrowse.Location = New-Object System.Drawing.Point(590, 37)
$btnBrowse.Size = New-Object System.Drawing.Size(85, 28)
$btnBrowse.BackColor = [System.Drawing.Color]::FromArgb(51, 65, 85)
$btnBrowse.ForeColor = [System.Drawing.Color]::White
$btnBrowse.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnBrowse.Add_Click({
    $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
    $fbd.SelectedPath = $txtPath.Text
    if ($fbd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtPath.Text = $fbd.SelectedPath
    }
})
$ctlPanel.Controls.Add($btnBrowse)

$lblJdk = New-Object System.Windows.Forms.Label
$lblJdk.Text = "Target JDK:"
$lblJdk.Location = New-Object System.Drawing.Point(690, 15)
$lblJdk.AutoSize = $true
$lblJdk.ForeColor = [System.Drawing.Color]::FromArgb(203, 213, 225)
$ctlPanel.Controls.Add($lblJdk)

$cbJdk = New-Object System.Windows.Forms.ComboBox
$cbJdk.Location = New-Object System.Drawing.Point(690, 38)
$cbJdk.Size = New-Object System.Drawing.Size(120, 26)
$cbJdk.Items.AddRange(@("Java 8+", "Java 7", "Java 6"))
$cbJdk.SelectedIndex = 0
$cbJdk.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$cbJdk.BackColor = [System.Drawing.Color]::FromArgb(2, 6, 23)
$cbJdk.ForeColor = [System.Drawing.Color]::White
$ctlPanel.Controls.Add($cbJdk)

$btnScan = New-Object System.Windows.Forms.Button
$btnScan.Text = "Start Scan"
$btnScan.Location = New-Object System.Drawing.Point(825, 33)
$btnScan.Size = New-Object System.Drawing.Size(150, 35)
$btnScan.BackColor = [System.Drawing.Color]::FromArgb(225, 29, 72) # Rose-600
$btnScan.ForeColor = [System.Drawing.Color]::White
$btnScan.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnScan.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$ctlPanel.Controls.Add($btnScan)

# --- Compliance Score Banner ---
$scorePanel = New-Object System.Windows.Forms.Panel
$scorePanel.Dock = "Top"
$scorePanel.Height = 70
$scorePanel.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$scorePanel.Padding = New-Object System.Windows.Forms.Padding(20, 5, 20, 5)
$form.Controls.Add($scorePanel)

$lblScoreTitle = New-Object System.Windows.Forms.Label
$lblScoreTitle.Text = "Security Compliance Score: 100% (Not Scanned Yet)"
$lblScoreTitle.Font = New-Object System.Drawing.Font("Segoe UI", 10.5, [System.Drawing.FontStyle]::Bold)
$lblScoreTitle.ForeColor = [System.Drawing.Color]::FromArgb(52, 211, 153) # Emerald
$lblScoreTitle.Location = New-Object System.Drawing.Point(20, 10)
$lblScoreTitle.AutoSize = $true
$scorePanel.Controls.Add($lblScoreTitle)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(20, 35)
$progressBar.Size = New-Object System.Drawing.Size(955, 18)
$progressBar.Value = 100
$scorePanel.Controls.Add($progressBar)

# --- DataGridView for Results ---
$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = "Fill"
$grid.BackgroundColor = [System.Drawing.Color]::FromArgb(2, 6, 23)
$grid.ForeColor = [System.Drawing.Color]::White
$grid.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(15, 23, 42)
$grid.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
$grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(51, 65, 85)
$grid.EnableHeadersVisualStyles = $false
$grid.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(244, 63, 94)
$grid.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$grid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.RowHeadersVisible = $false
$form.Controls.Add($grid)

# --- Bottom Action Bar ---
$bottomPanel = New-Object System.Windows.Forms.Panel
$bottomPanel.Dock = "Bottom"
$bottomPanel.Height = 60
$bottomPanel.BackColor = [System.Drawing.Color]::FromArgb(15, 23, 42)
$bottomPanel.Padding = New-Object System.Windows.Forms.Padding(20, 10, 20, 10)
$form.Controls.Add($bottomPanel)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "Ready. Select a target directory and click 'Start Scan'."
$lblStatus.Location = New-Object System.Drawing.Point(20, 20)
$lblStatus.AutoSize = $true
$lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(148, 163, 184)
$bottomPanel.Controls.Add($lblStatus)

$btnPrint = New-Object System.Windows.Forms.Button
$btnPrint.Text = "Generate HTML Report & Print"
$btnPrint.Location = New-Object System.Drawing.Point(740, 12)
$btnPrint.Size = New-Object System.Drawing.Size(235, 34)
$btnPrint.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$btnPrint.ForeColor = [System.Drawing.Color]::White
$btnPrint.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnPrint.Enabled = $false
$bottomPanel.Controls.Add($btnPrint)

# --- SCAN BUTTON LOGIC ---
$btnScan.Add_Click({
    $targetPath = $txtPath.Text.Trim()
    if (-not (Test-Path $targetPath)) {
        [System.Windows.Forms.MessageBox]::Show("Specified directory does not exist: $targetPath", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    $global:ScanResults.Clear()
    $btnScan.Enabled = $false
    $lblStatus.Text = "Scanning directories and archives..."
    $form.Update()

    $targetJdk = $cbJdk.SelectedItem.ToString()
    $files = Get-ChildItem -Path $targetPath -Recurse -File -Include "*.jar","*.war","*.xml","*gradle*","*.kts" -ErrorAction SilentlyContinue

    foreach ($f in $files) {
        Scan-File -filePath $f.FullName -targetJdk $targetJdk
    }

    # Bind to Grid
    $grid.DataSource = $null
    if ($global:ScanResults.Count -gt 0) {
        $grid.DataSource = [System.Collections.ArrayList]@($global:ScanResults)
    }

    # Calculate compliance score
    $total = $global:ScanResults.Count
    $vuln = ($global:ScanResults | Where-Object { $_.Status -ne "SAFE" }).Count
    $safe = $total - $vuln
    $score = if ($total -gt 0) { [math]::Round(($safe / $total) * 100) } else { 100 }

    $progressBar.Value = $score

    if ($score -eq 100) {
        $lblScoreTitle.ForeColor = [System.Drawing.Color]::FromArgb(52, 211, 153) # Emerald
        $lblScoreTitle.Text = "Security Compliance Score: $score% (SAFE / HARDENED) - $safe/$total Components Patched"
    } elseif ($score -ge 50) {
        $lblScoreTitle.ForeColor = [System.Drawing.Color]::FromArgb(251, 191, 36) # Amber
        $lblScoreTitle.Text = "Security Compliance Score: $score% (WARNING: $vuln Vulnerabilities) - $safe/$total Patched"
    } else {
        $lblScoreTitle.ForeColor = [System.Drawing.Color]::FromArgb(244, 63, 94) # Rose
        $lblScoreTitle.Text = "Security Compliance Score: $score% (CRITICAL RISK: $vuln Vulnerable Components) - $safe/$total Patched"
    }

    $lblStatus.Text = "Scan finished. Found $total Log4j component(s) ($vuln vulnerable, $safe patched)."
    $btnScan.Enabled = $true
    $btnPrint.Enabled = ($total -gt 0)
})

# --- PRINT REPORT LOGIC ---
$btnPrint.Add_Click({
    $reportPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "Log4j_Audit_Report.html")

    $total = $global:ScanResults.Count
    $vuln = ($global:ScanResults | Where-Object { $_.Status -ne "SAFE" }).Count
    $safe = $total - $vuln
    $score = if ($total -gt 0) { [math]::Round(($safe / $total) * 100) } else { 100 }

    $rowsHtml = ""
    foreach ($r in $global:ScanResults) {
        $color = if ($r.Status -eq "CRITICAL") { "#e11d48" } elseif ($r.Status -eq "HIGH") { "#ea580c" } elseif ($r.Status -eq "SAFE") { "#059669" } else { "#ca8a04" }
        $rowsHtml += @"
        <tr>
            <td><strong>$($r.File)</strong><br><small style='color:#64748b'>$($r.Path)</small></td>
            <td>$($r.Type)</td>
            <td>$($r.DetectedVersion)</td>
            <td><span style='background:$color;color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;'>$($r.Status)</span></td>
            <td>$($r.Cvss)</td>
            <td>$($r.JndiClass)</td>
            <td>$($r.MatchedCVEs)</td>
            <td style='color:#059669;font-weight:bold;'>$($r.RecommendedFix)</td>
        </tr>
"@
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Log4j Security Audit Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #fff; color: #1e293b; padding: 30px; margin: 0; }
        h1 { margin: 0 0 5px 0; color: #0f172a; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 12px; }
        .score-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 15px; margin: 20px 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; }
        th, td { border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; }
        th { background: #f1f5f9; color: #334155; font-weight: bold; }
        @media print {
            .no-print { display: none; }
            body { padding: 10mm; }
        }
    </style>
</head>
<body>
    <div class="no-print" style="margin-bottom: 20px;">
        <button onclick="window.print()" style="padding: 10px 20px; background: #e11d48; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;">
            Print / Save as PDF
        </button>
    </div>

    <h1>Apache Log4j Security Audit & Compliance Report</h1>
    <p style="color:#64748b; font-size: 13px;">Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Target Scope: $($txtPath.Text)</p>

    <div class="score-box">
        <h3 style="margin: 0 0 8px 0;">Compliance Summary</h3>
        <p><strong>Security Compliance Score:</strong> $score% ($safe/$total Patched)</p>
        <p><strong>Total Scanned:</strong> $total | <strong>Vulnerable:</strong> $vuln | <strong>Compliant:</strong> $safe</p>
    </div>

    <h2>Component Inventory & Vulnerability Matrix</h2>
    <table>
        <thead>
            <tr>
                <th>Component / File</th>
                <th>Source</th>
                <th>Detected Version</th>
                <th>Status</th>
                <th>CVSS</th>
                <th>JndiLookup Class</th>
                <th>Matched CVEs</th>
                <th>Target Recommendation</th>
            </tr>
        </thead>
        <tbody>
            $rowsHtml
        </tbody>
    </table>

    <div style="margin-top: 40px; border-top: 2px solid #0f172a; padding-top: 15px; font-size: 12px; color: #64748b;">
        <p>Log4j Shield Scanner • Standards Compliance: NIST SP 800-53 (SI-2) • OWASP Top 10 • CVE-2021-44228</p>
    </div>
</body>
</html>
"@

    Set-Content -Path $reportPath -Value $html -Encoding UTF8
    Start-Process $reportPath
})

# Display Window
[System.Windows.Forms.Application]::Run($form)
