<#
.SYNOPSIS
    Установка AntiZapret VPN для Windows 11.

.DESCRIPTION
    Ставит клиентскую часть AntiZapret на Windows 11:
      * готовит каталоги (C:\ProgramData\AntiZapret);
      * обновляет списки доменов и IP;
      * отключает IPv6 (иначе трафик уходит в обход туннеля);
      * выключает Secure DNS (DoH), NRDOT и WPAD — иначе DNS AntiZapret
        игнорируется и появляется утечка;
      * регистрирует локальный DNS-резолвер как задачу планировщика;
      * создаёт клиентские профили (OpenVPN / WireGuard / AmneziaWG).

.EXAMPLE
    .\setup.ps1 -ServerHost 203.0.113.10

.EXAMPLE
    .\setup.ps1 -ServerHost 203.0.113.10 -ClientName home -NoProfiles

.NOTES
    Нужны права администратора. Порты клиентов: OpenVPN 50443 (UDP),
    WireGuard 51443, AmneziaWG 2 — 53443, AmneziaWG 3 — 51821.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ServerHost = "",

    [Parameter(Mandatory = $false)]
    [string]$ClientName = "antizapret-client",

    [Parameter(Mandatory = $false)]
    [string]$Root = "C:\ProgramData\AntiZapret",

    [Parameter(Mandatory = $false)]
    [string]$TunnelInterface = "",

    [Parameter(Mandatory = $false)]
    [switch]$NoProfiles,

    [Parameter(Mandatory = $false)]
    [switch]$NoDisableIpv6,

    [Parameter(Mandatory = $false)]
    [switch]$SkipUpdate
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Red
}

# --- проверка прав ---------------------------------------------------------

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Нужны права администратора. Запустите PowerShell от имени администратора." -ForegroundColor Red
    exit 1
}

# --- поиск Python -----------------------------------------------------------

$python = $null
foreach ($candidate in @("python", "py -3", "python3")) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) {
        try {
            $ver = & $candidate --version 2>&1
            if ($ver -match "Python 3") { $python = $candidate; break }
        } catch { }
    }
}
if (-not $python) {
    Write-Host "Python 3 не найден. Установите Python 3.11+ с python.org и повторите." -ForegroundColor Red
    exit 1
}
Write-Ok "Python: $python"

$repoRoot = Split-Path -Parent $PSScriptRoot
$pkgDir = Join-Path $repoRoot "windows"
if (-not (Test-Path (Join-Path $pkgDir "azwin"))) {
    $pkgDir = $PSScriptRoot
}

Write-Step "Каталоги"
foreach ($dir in @($Root, "$Root\download", "$Root\config", "$Root\result", "$Root\client", "$Root\logs")) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-Ok "Корень: $Root"

# --- настройки --------------------------------------------------------------

$setupFile = Join-Path $Root "setup"
$settings = @{}
if (Test-Path $setupFile) {
    Get-Content $setupFile | ForEach-Object {
        if ($_ -match "^\s*([^#=]+?)\s*=\s*(.*)$") { $settings[$Matches[1].Trim()] = $Matches[2].Trim() }
    }
}
if (-not $settings.ContainsKey("FAKE_IP_CIDR")) { $settings["FAKE_IP_CIDR"] = "198.18.0.0/15" }
if (-not $settings.ContainsKey("MODE")) { $settings["MODE"] = "split" }
if (-not $settings.ContainsKey("IPV6_MODE")) { $settings["IPV6_MODE"] = "a" }
if (-not $settings.ContainsKey("ADBLOCK")) { $settings["ADBLOCK"] = "n" }
if (-not $settings.ContainsKey("DNS_IPS")) { $settings["DNS_IPS"] = "10.29.0.1,10.29.4.1,10.29.8.1" }
if (-not $settings.ContainsKey("TUNNEL_GATEWAY")) { $settings["TUNNEL_GATEWAY"] = "10.29.8.1" }
if ($ServerHost) { $settings["SERVER_HOST"] = $ServerHost }
if ($TunnelInterface) { $settings["TUNNEL_INTERFACE"] = $TunnelInterface }

$settings | ForEach-Object { "$($_.Key)=$($_.Value)" } | Set-Content -Path $setupFile -Encoding UTF8
Write-Ok "Настройки: $setupFile"

# --- списки -----------------------------------------------------------------

if (-not $SkipUpdate) {
    Write-Step "Обновляю списки доменов и адблока"
    & $python -m azwin.cli --root $Root update
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Часть списков не обновилась — используются прежние версии"
    }
}

Write-Step "Пересобираю маршруты и списки"
& $python -m azwin.cli --root $Root parse

# --- IPv6 -------------------------------------------------------------------

if (-not $NoDisableIpv6) {
    Write-Step "Отключаю IPv6"
    & $python -m azwin.cli --root $Root doctor | Out-Null
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    try {
        New-ItemProperty -Path $key -Name "DisabledComponents" -Value 0xFFFFFFFF `
            -PropertyType DWord -Force | Out-Null
        Write-Ok "IPv6 отключён системно. Для полного эффекта нужна перезагрузка."
    } catch {
        Write-Err "Не удалось отключить IPv6: $($_.Exception.Message)"
    }
} else {
    Write-Step "IPv6 оставлен как есть (по запросу)"
}

# --- утечки DNS ------------------------------------------------------------

Write-Step "Выключаю Secure DNS (DoH), NRDOT и WPAD"
$dnsPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSCache"
try {
    New-Item -Path $dnsPolicy -Force | Out-Null
    New-ItemProperty -Path $dnsPolicy -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $dnsPolicy -Name "DisableNrDomainParam" -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Ok "Secure DNS выключен, NRDOT отключён"
} catch {
    Write-Err "Не удалось применить политику DNS: $($_.Exception.Message)"
}

# --- локальный резолвер как задача -----------------------------------------

Write-Step "Регистрирую локальный DNS-резолвер"
$taskName = "AntiZapret DNS"
$exe = (Get-Command $candidate -ErrorAction SilentlyContinue)
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) { $pythonExe = (Get-Command py -ErrorAction SilentlyContinue).Source }
$taskAction = New-ScheduledTaskAction -Execute $pythonExe `
    -Argument "-m azwin.dnsd --root `"$Root`" --mode $($settings['MODE']) --listen 127.0.0.1 --port 5353" `
    -WorkingDirectory $pkgDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $trigger `
        -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)) | Out-Null
    Write-Ok "Задача «$taskName» создана (запуск при старте, от SYSTEM)"
    Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Write-Ok "Резолвер запущен"
} catch {
    Write-Err "Не удалось создать задачу: $($_.Exception.Message)"
}

# --- профили ----------------------------------------------------------------

if (-not $NoProfiles) {
    if (-not $ServerHost) {
        Write-Warn "Не задан -ServerHost — профили не созданы"
        Write-Warn "Укажите адрес зарубежного сервера AntiZapret и повторите."
    } else {
        Write-Step "Создаю клиентские профили для «$ClientName»"
        & $python -m azwin.cli --root $Root client create $ClientName
    }
}

# --- итог -------------------------------------------------------------------

Write-Step "Готово"
& $python -m azwin.cli --root $Root doctor
Write-Host ""
Write-Host "Дальше:" -ForegroundColor Cyan
Write-Host "  1. Подключите туннель (AmneziaWG / WireGuard / OpenVPN)."
Write-Host "  2. Включите маршрутизацию:  azwin up"
Write-Host "  3. Проверьте состояние:      azwin status"
Write-Host ""
Write-Host "Важно: после отключения IPv6 нужна перезагрузка Windows."
Write-Host "Файлы профилей: $Root\client"
