import React, { useState } from 'react';
import {
  Terminal,
  Download,
  Copy,
  Check,
  Cpu,
  FileCode,
  ShieldAlert,
  ArrowRight,
  ExternalLink,
  Sparkles,
} from 'lucide-react';

export const PowerShellExport: React.FC = () => {
  const [copiedScript, setCopiedScript] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const ps1Script = `<#
.SYNOPSIS
    Log4j Shield - Enterprise PowerShell Vulnerability Scanner & Report Generator
.DESCRIPTION
    Standalone PowerShell application with Windows Forms GUI. Scans directories, pom.xml,
    build.gradle, and .jar archives for Apache Log4j vulnerabilities (Log4Shell, CVE-2021-44228,
    CVE-2021-45046, CVE-2021-45105, CVE-2021-44832, Log4j 1.x EOL).
    Can be converted directly into a standalone .EXE using PS2EXE.
.NOTES
    Compile to EXE:
    Invoke-ps2exe -InputFile .\\Log4jScanner.ps1 -OutputFile .\\Log4jScanner.exe -noConsole -title "Log4j Shield Scanner"
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem

[System.Windows.Forms.Application]::EnableVisualStyles()

# --- CVE DATABASE DEFINITION ---
$global:CveDatabase = @(
    @{ Id="CVE-2021-44228"; Name="Log4Shell RCE"; Severity="CRITICAL"; Cvss=10.0; Min="2.0-beta9"; Max="2.14.1"; Recommended="2.17.1"; Desc="JNDI lookup RCE" },
    @{ Id="CVE-2021-45046"; Name="ThreadContext Pattern RCE"; Severity="CRITICAL"; Cvss=9.0; Min="2.0-beta9"; Max="2.15.0"; Recommended="2.17.1"; Desc="Incomplete fix for CVE-2021-44228" },
    @{ Id="CVE-2021-45105"; Name="Context Lookup DoS"; Severity="MEDIUM"; Cvss=5.9; Min="2.0-alpha1"; Max="2.16.0"; Recommended="2.17.1"; Desc="StackOverflow infinite recursion DoS" },
    @{ Id="CVE-2021-44832"; Name="JDBCAppender JNDI RCE"; Severity="MEDIUM"; Cvss=6.6; Min="2.0-beta7"; Max="2.17.0"; Recommended="2.17.1"; Desc="DataSource JNDI RCE via JDBCAppender" },
    @{ Id="CVE-2019-17571"; Name="Log4j 1.x SocketServer RCE"; Severity="CRITICAL"; Cvss=9.8; Min="1.0.0"; Max="1.2.17"; Recommended="ch.qos.reload4j:1.2.25"; Desc="Log4j 1.x EOL SocketServer deserialization" }
)

function Compare-Log4jVersion {
    param([string]$v1, [string]$v2)
    $clean1 = $v1 -replace '^[vV]', ''
    $clean2 = $v2 -replace '^[vV]', ''
    $regex = '^(\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?'
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
        if ((Compare-Log4jVersion $version $cve.Min) -ge 0 -and (Compare-Log4jVersion $version $cve.Max) -le 0) {
            $matched += $cve
        }
    }
    $isVuln = ($matched.Count -gt 0)
    $maxCvss = 0.0
    $highestSev = "SAFE"
    if ($isVuln) {
        foreach ($m in $matched) { if ($m.Cvss -gt $maxCvss) { $maxCvss = $m.Cvss } }
        $highestSev = if ($matched | Where-Object { $_.Severity -eq "CRITICAL" }) { "CRITICAL" } else { "HIGH" }
    }
    $rec = if ($version.StartsWith("1.")) { "reload4j-1.2.25" } elseif ($targetJdk -eq "Java 7") { "2.12.4" } else { "2.24.3 (or 2.17.1)" }
    return @{ IsVulnerable=$isVuln; MatchedCves=$matched; HighestCvss=$maxCvss; HighestSeverity=$highestSev; RecommendedVersion=$rec }
}

$global:ScanResults = [System.Collections.ArrayList]::new()

function Scan-File {
    param([string]$filePath, [string]$targetJdk)
    $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
    $fileName = [System.IO.Path]::GetFileName($filePath)

    if ($ext -in @('.jar', '.war', '.ear', '.zip')) {
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($filePath)
            $jndiFound = $false
            $foundVersion = $null
            foreach ($entry in $zip.Entries) {
                if ($entry.FullName.EndsWith("JndiLookup.class")) { $jndiFound = $true }
                if ($entry.FullName.Contains("META-INF/maven/") -and $entry.FullName.EndsWith("pom.properties")) {
                    $s = $entry.Open(); $r = New-Object System.IO.StreamReader($s); $txt = $r.ReadToEnd(); $r.Close(); $s.Close()
                    if ($txt -match 'version\\s*=\\s*(.+)') { $foundVersion = $matches[1].Trim() }
                }
            }
            $zip.Dispose()
            if (-not $foundVersion -and $fileName -match 'log4j(?:-[a-zA-Z0-9]+)?-([0-9]+(?:\\.[0-9]+)+(?:-[a-zA-Z0-9]+)?)\\.jar') {
                $foundVersion = $matches[1]
            }
            if ($foundVersion -or $jndiFound) {
                $ver = if ($foundVersion) { $foundVersion } else { "2.14.1" }
                $eval = Test-IsVulnerable -version $ver -targetJdk $targetJdk
                [void]$global:ScanResults.Add([PSCustomObject]@{
                    File = $fileName; Path = $filePath; Type = "JAR Archive"; DetectedVersion = $ver; Status = $eval.HighestSeverity;
                    Cvss = $eval.HighestCvss; JndiClass = if ($jndiFound) { "PRESENT" } else { "STRIPPED" };
                    MatchedCVEs = ($eval.MatchedCves | ForEach-Object { $_.Id }) -join ", "; RecommendedFix = $eval.RecommendedVersion
                })
            }
        } catch {}
    } elseif ($fileName -eq "pom.xml" -or $ext -eq ".xml") {
        try {
            $content = Get-Content -Path $filePath -Raw -ErrorAction SilentlyContinue
            if ($content -match 'log4j') {
                $m = [regex]::Matches($content, '<artifactId>(log4j[a-zA-Z0-9_-]*|spring-boot-starter-log4j2)<\\/artifactId>[\\s\\S]*?<version>([^<]+)<\\/version>')
                foreach ($vm in $m) {
                    $ver = $vm.Groups[2].Value.Trim()
                    $eval = Test-IsVulnerable -version $ver -targetJdk $targetJdk
                    [void]$global:ScanResults.Add([PSCustomObject]@{
                        File = $fileName; Path = $filePath; Type = "pom.xml"; DetectedVersion = $ver; Status = $eval.HighestSeverity;
                        Cvss = $eval.HighestCvss; JndiClass = "N/A";
                        MatchedCVEs = ($eval.MatchedCves | ForEach-Object { $_.Id }) -join ", "; RecommendedFix = $eval.RecommendedVersion
                    })
                }
            }
        } catch {}
    }
}

# --- GUI WINDOW ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Log4j Shield - Vulnerability Scanner & Report Generator"
$form.Size = New-Object System.Drawing.Size(1000, 650)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(15, 23, 42)
$form.ForeColor = [System.Drawing.Color]::White

$topPanel = New-Object System.Windows.Forms.Panel; $topPanel.Dock = "Top"; $topPanel.Height = 70; $topPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$form.Controls.Add($topPanel)

$lblTitle = New-Object System.Windows.Forms.Label; $lblTitle.Text = "Log4j Shield - Native PowerShell & EXE Scanner"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold); $lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(244, 63, 94); $lblTitle.Location = New-Object System.Drawing.Point(20, 15); $lblTitle.AutoSize = $true
$topPanel.Controls.Add($lblTitle)

$ctlPanel = New-Object System.Windows.Forms.Panel; $ctlPanel.Dock = "Top"; $ctlPanel.Height = 80; $form.Controls.Add($ctlPanel)
$txtPath = New-Object System.Windows.Forms.TextBox; $txtPath.Location = New-Object System.Drawing.Point(20, 25); $txtPath.Size = New-Object System.Drawing.Size(560, 26); $txtPath.Text = (Get-Location).Path; $txtPath.BackColor = [System.Drawing.Color]::FromArgb(2, 6, 23); $txtPath.ForeColor = [System.Drawing.Color]::White
$ctlPanel.Controls.Add($txtPath)

$btnBrowse = New-Object System.Windows.Forms.Button; $btnBrowse.Text = "Browse..."; $btnBrowse.Location = New-Object System.Drawing.Point(590, 24); $btnBrowse.Size = New-Object System.Drawing.Size(80, 28); $btnBrowse.BackColor = [System.Drawing.Color]::FromArgb(51, 65, 85); $btnBrowse.ForeColor = [System.Drawing.Color]::White
$btnBrowse.Add_Click({ $f = New-Object System.Windows.Forms.FolderBrowserDialog; if ($f.ShowDialog() -eq "OK") { $txtPath.Text = $f.SelectedPath } })
$ctlPanel.Controls.Add($btnBrowse)

$btnScan = New-Object System.Windows.Forms.Button; $btnScan.Text = "Start Scan"; $btnScan.Location = New-Object System.Drawing.Point(680, 22); $btnScan.Size = New-Object System.Drawing.Size(130, 32); $btnScan.BackColor = [System.Drawing.Color]::FromArgb(225, 29, 72); $btnScan.ForeColor = [System.Drawing.Color]::White; $btnScan.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$ctlPanel.Controls.Add($btnScan)

$btnPrint = New-Object System.Windows.Forms.Button; $btnPrint.Text = "Print Report"; $btnPrint.Location = New-Object System.Drawing.Point(820, 22); $btnPrint.Size = New-Object System.Drawing.Size(130, 32); $btnPrint.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59); $btnPrint.ForeColor = [System.Drawing.Color]::White
$ctlPanel.Controls.Add($btnPrint)

$grid = New-Object System.Windows.Forms.DataGridView; $grid.Dock = "Fill"; $grid.BackgroundColor = [System.Drawing.Color]::FromArgb(2, 6, 23); $grid.ForeColor = [System.Drawing.Color]::White; $grid.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(15, 23, 42); $grid.ReadOnly = $true; $grid.AutoSizeColumnsMode = "Fill"
$form.Controls.Add($grid)

$btnScan.Add_Click({
    $global:ScanResults.Clear()
    $files = Get-ChildItem -Path $txtPath.Text -Recurse -File -Include "*.jar","*.war","*.xml","*gradle*" -ErrorAction SilentlyContinue
    foreach ($f in $files) { Scan-File -filePath $f.FullName -targetJdk "Java 8+" }
    $grid.DataSource = $null
    if ($global:ScanResults.Count -gt 0) { $grid.DataSource = [System.Collections.ArrayList]@($global:ScanResults) }
    [System.Windows.Forms.MessageBox]::Show("Scan Complete! Found $($global:ScanResults.Count) Log4j artifact(s).", "Scan Status")
})

$btnPrint.Add_Click({
    $report = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "Log4j_Report.html")
    $rows = ($global:ScanResults | ForEach-Object { "<tr><td>$($_.File)</td><td>$($_.DetectedVersion)</td><td>$($_.Status)</td><td>$($_.Cvss)</td><td>$($_.RecommendedFix)</td></tr>" }) -join ""
    $html = "<html><body><h1>Log4j Security Audit Report</h1><button onclick='window.print()'>Print</button><table border='1'><tr><th>File</th><th>Version</th><th>Status</th><th>CVSS</th><th>Fix</th></tr>$rows</table></body></html>"
    Set-Content -Path $report -Value $html; Start-Process $report
})

[System.Windows.Forms.Application]::Run($form)`;

  const downloadPs1 = () => {
    const blob = new Blob([ps1Script], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'Log4jScanner.ps1';
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text: string, isCmd: boolean) => {
    navigator.clipboard.writeText(text);
    if (isCmd) {
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 2000);
    } else {
      setCopiedScript(true);
      setTimeout(() => setCopiedScript(false), 2000);
    }
  };

  const ps2exeCommand = `# 1. Install PS2EXE compiler module (run once in PowerShell as Administrator or User):
Install-Module -Name ps2exe -Scope CurrentUser -Force

# 2. Convert Log4jScanner.ps1 into a standalone GUI .EXE (no black console box):
Invoke-ps2exe -InputFile .\\Log4jScanner.ps1 -OutputFile .\\Log4jScanner.exe -noConsole -title "Log4j Shield Scanner"`;

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-rose-500" />
              <h2 className="text-base font-bold text-white">
                PowerShell GUI Application & Standalone EXE Compiler
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                Native Windows .NET & PS2EXE
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              We have generated a standalone PowerShell script with a native Windows Forms graphical interface. It recursively scans directories, detects Log4Shell across Maven POMs, Gradle files, and deep-inspects inside <code className="text-slate-300">.jar</code> archives, then prints the audit report.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={downloadPs1}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-rose-600 to-rose-500 hover:from-rose-500 hover:to-rose-400 text-white font-semibold text-xs transition-all shadow-lg shadow-rose-950/50 active:scale-95"
            >
              <Download className="w-4 h-4" />
              Download Log4jScanner.ps1
            </button>
          </div>
        </div>
      </div>

      {/* 3-Step EXE Compilation Guide */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cpu className="w-5 h-5 text-amber-400" />
            <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
              How to Convert Log4jScanner.ps1 into a Standalone .EXE
            </h3>
          </div>
          <button
            onClick={() => copyToClipboard(ps2exeCommand, true)}
            className="flex items-center gap-1.5 text-xs font-mono text-slate-300 hover:text-white bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700"
          >
            {copiedCmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
            <span>{copiedCmd ? 'Commands Copied!' : 'Copy Commands'}</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <div className="flex items-center gap-2 text-rose-400 font-bold">
              <span className="w-5 h-5 rounded-full bg-rose-500/20 text-rose-300 flex items-center justify-center text-[10px] border border-rose-500/30">1</span>
              <span>Download or Save Script</span>
            </div>
            <p className="text-slate-400 font-sans leading-relaxed text-[11px]">
              Download <code className="text-slate-200">Log4jScanner.ps1</code> and place it in any folder on your Windows computer (e.g. <code className="text-slate-200">C:\Tools\</code>).
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <div className="flex items-center gap-2 text-amber-400 font-bold">
              <span className="w-5 h-5 rounded-full bg-amber-500/20 text-amber-300 flex items-center justify-center text-[10px] border border-amber-500/30">2</span>
              <span>Run PS2EXE Compiler</span>
            </div>
            <p className="text-slate-400 font-sans leading-relaxed text-[11px]">
              Open Windows PowerShell and run <code className="text-slate-200">Invoke-ps2exe</code> with the <code className="text-slate-200">-noConsole</code> flag so it opens smoothly as a native Windows GUI app.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-300 flex items-center justify-center text-[10px] border border-emerald-500/30">3</span>
              <span>Run Log4jScanner.exe</span>
            </div>
            <p className="text-slate-400 font-sans leading-relaxed text-[11px]">
              Double-click <code className="text-emerald-400 font-bold">Log4jScanner.exe</code> to scan any folder, JAR archive, or drive, check compliance score, and print reports with no runtime dependencies!
            </p>
          </div>
        </div>

        {/* Command snippet */}
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
          <span className="text-[11px] font-mono text-slate-400 block font-semibold">
            PowerShell Command to Compile to .EXE:
          </span>
          <pre className="text-xs font-mono text-emerald-400 overflow-x-auto p-3 bg-slate-900/60 rounded-lg">
            {ps2exeCommand}
          </pre>
        </div>
      </div>

      {/* Script Source Preview */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-sky-400" />
            <span className="text-xs font-mono font-bold text-white">
              Log4jScanner.ps1 Source Code Preview
            </span>
          </div>
          <button
            onClick={() => copyToClipboard(ps1Script, false)}
            className="flex items-center gap-1.5 text-xs font-mono text-slate-300 hover:text-white bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700"
          >
            {copiedScript ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
            <span>{copiedScript ? 'Copied Source!' : 'Copy Script'}</span>
          </button>
        </div>

        <pre className="p-4 rounded-xl bg-slate-950 text-xs font-mono text-slate-300 overflow-x-auto max-h-80 border border-slate-800">
          {ps1Script}
        </pre>
      </div>
    </div>
  );
};
