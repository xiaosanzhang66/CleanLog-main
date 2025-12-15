function CleanLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]$EventLogName,
        [String]$IpAddress,
        [Int]$Mins,
        [Int]$Hours
    )

    $LogNames = if ($EventLogName.Contains(',')) {
        $EventLogName.Split(',').Trim()
    } else {
        @($EventLogName)
    }

    # 如果用户只指定了Security，我们需要处理4个日志
    if ($LogNames.Count -eq 1 -and $LogNames[0] -eq "Security") {
        $LogNames = @(
            "Security",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
        )
    }

    $EventLogPath = "C:\Windows\System32\Winevt\Logs\"
    Write-Host "开始清理以下日志: $($LogNames -join ', ')"

    $TempFiles = @{}
    
    # 第一阶段：为Security日志创建临时文件
    foreach ($CurrentLogName in $LogNames) {
        try {
            # 跳过TerminalServices日志，它们直接删除
            if ($CurrentLogName -like "*TerminalServices*") {
                Write-Host "跳过TerminalServices日志: $CurrentLogName (将在服务停止后直接删除)" -ForegroundColor Yellow
                continue
            }
            
            Write-Host "处理非TerminalServices日志: $CurrentLogName"
            
            # 构建查询条件
            $Query = ""
            if ($IpAddress) {
                $Query = "*[EventData[(Data[@Name='IpAddress']!='$IpAddress')]]"
            }
            if ($Mins) {
                $TimeCondition = "*[System[TimeCreated[timediff(@SystemTime) >= $($Mins * 60000)]]]"
                $Query = if ($Query) { "($Query) and $TimeCondition" } else { $TimeCondition }
            }
            if ($Hours) {
                $TimeCondition = "*[System[TimeCreated[timediff(@SystemTime) >= $($Hours * 3600000)]]]"
                $Query = if ($Query) { "($Query) and $TimeCondition" } else { $TimeCondition }
            }
            if ([String]::IsNullOrEmpty($Query)) { 
                $Query = "*" 
            }

            $SafeLogName = $CurrentLogName.Replace("/", "%4")
            $TempFile = Join-Path $EventLogPath "${SafeLogName}_.evtx"
            $OriginalFile = Join-Path $EventLogPath "${SafeLogName}.evtx"

            # 使用 wevtutil 导出符合条件的日志
            Write-Host "导出条件: $Query"
            $Result = wevtutil epl "$CurrentLogName" "$TempFile" /q:"$Query" /ow:true 2>&1

            if ($LASTEXITCODE -eq 0) {
                Write-Host "导出成功: $TempFile" -ForegroundColor Green
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

    # 第二阶段：停止服务并处理所有文件
    if ($true) {  # 总是尝试处理
        Write-Host "停止事件日志服务..."
        Stop-Service -Name eventlog -Force
        Start-Sleep -Seconds 2

        # 1. 先删除所有TerminalServices日志文件
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
                    Remove-Item $FullPath -Force
                    Write-Host "删除成功" -ForegroundColor Green
                } else {
                    Write-Host "文件不存在: $TSFile" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "删除文件 $TSFile 时出错: $_" -ForegroundColor Red
            }
        }

        # 2. 处理Security日志（替换文件）
        if ($TempFiles.Count -gt 0) {
            Write-Host "`n正在处理Security日志..." -ForegroundColor Cyan
            foreach ($LogEntry in $TempFiles.GetEnumerator()) {
                $CurrentLogName = $LogEntry.Key
                $TempFile = $LogEntry.Value.TempFile
                $OriginalFile = $LogEntry.Value.OriginalFile

                try {
                    Write-Host "处理日志: $CurrentLogName"
                    if (Test-Path $OriginalFile) {
                        Remove-Item $OriginalFile -Force
                    }
                    if (Test-Path $TempFile) {
                        Rename-Item $TempFile $OriginalFile -Force
                        Write-Host "日志 $CurrentLogName 替换完成" -ForegroundColor Green
                    } else {
                        Write-Host "警告: 临时文件不存在: $TempFile" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host "替换日志 $CurrentLogName 时出错: $_" -ForegroundColor Red
                }
            }
        }

        Write-Host "`n启动事件日志服务..."
        Start-Service -Name eventlog

        Write-Host "`n所有日志处理完成!" -ForegroundColor Green
    }
}

# 使用示例：
# CleanLog -EventLogName Security -IpAddress "123.123.123.1" -Hours 1
# CleanLog -EventLogName Security -Mins 30
# CleanLog -EventLogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
# CleanLog -EventLogName Security  # 会自动处理Security和3个TerminalServices日志