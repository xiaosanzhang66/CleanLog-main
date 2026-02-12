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
            # 跳过TerminalServices日志，它们直接删除
            if ($CurrentLogName -like "*TerminalServices*") {
                Write-Host "跳过TerminalServices日志: $CurrentLogName (将在服务停止后直接删除)" -ForegroundColor Yellow
                continue
            }
            
            Write-Host "处理非TerminalServices日志: $CurrentLogName"
            
            # 修正时间条件逻辑！
            # 用户意图：删除X小时内的记录，保留X小时外的记录
            # 所以应该查询：时间差 > X小时的记录（保留这些）
            $Query = ""
            if ($IpAddress) {
                $Query = "*[EventData[(Data[@Name='IpAddress']!='$IpAddress')]]"
            }
            if ($Mins) {
                # 删除$Mins分钟内的记录，保留$Mins分钟前的记录
                $TimeCondition = "*[System[TimeCreated[timediff(@SystemTime) > $($Mins * 60000)]]]"
                $Query = if ($Query) { "($Query) and $TimeCondition" } else { $TimeCondition }
            }
            if ($Hours) {
                # 删除$Hours小时内的记录，保留$Hours小时前的记录
                $TimeCondition = "*[System[TimeCreated[timediff(@SystemTime) > $($Hours * 3600000)]]]"
                $Query = if ($Query) { "($Query) and $TimeCondition" } else { $TimeCondition }
            }
            if ([String]::IsNullOrEmpty($Query)) { 
                # 如果没有指定条件，保留所有记录（实际上不删除任何记录）
                Write-Host "警告：没有指定任何过滤条件，将保留所有记录" -ForegroundColor Yellow
                $Query = "*" 
            }

            Write-Host "时间条件说明：将保留符合条件的记录（删除不符合条件的）" -ForegroundColor Magenta
            Write-Host "查询条件: $Query" -ForegroundColor Magenta
            
            $SafeLogName = $CurrentLogName.Replace("/", "%4")
            $TempFile = Join-Path $EventLogPath "${SafeLogName}_.evtx"
            $OriginalFile = Join-Path $EventLogPath "${SafeLogName}.evtx"

            # 使用 wevtutil 导出符合条件的日志
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

    # 第二阶段：强制停止服务并处理文件
    Write-Host "`n强制停止事件日志服务..." -ForegroundColor Red
    
    # 方法1：先尝试正常停止
    try {
        Write-Host "尝试正常停止事件日志服务..."
        Stop-Service -Name eventlog -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "正常停止失败: $_" -ForegroundColor Yellow
    }
    
    # 方法2：使用sc命令停止
    Write-Host "使用sc命令停止服务..."
    $null = sc.exe stop eventlog 2>&1
    Start-Sleep -Seconds 2
    
    # 方法3：找到并强制终止eventlog服务的进程
    Write-Host "查找eventlog服务进程..." -ForegroundColor Cyan
    
    # 获取eventlog服务的进程ID
    $serviceInfo = Get-WmiObject -Class Win32_Service -Filter "Name='eventlog'"
    if ($serviceInfo -and $serviceInfo.ProcessId -gt 0) {
        Write-Host "找到eventlog服务进程PID: $($serviceInfo.ProcessId)" -ForegroundColor Yellow
        Write-Host "强制终止进程..."
        $null = taskkill /F /PID $serviceInfo.ProcessId 2>&1
        Write-Host "进程已终止" -ForegroundColor Green
    } else {
        Write-Host "未找到eventlog服务进程，查找svchost进程..." -ForegroundColor Yellow
        
        # 查找所有svchost进程，找到运行eventlog的
        $svchostProcesses = Get-Process svchost -ErrorAction SilentlyContinue
        
        foreach ($process in $svchostProcesses) {
            try {
                # 检查进程命令行是否包含eventlog
                $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId=$($process.Id)").CommandLine
                if ($cmdLine -like "*EventLog*" -or $cmdLine -like "*eventlog*") {
                    Write-Host "找到eventlog相关进程 PID: $($process.Id)" -ForegroundColor Yellow
                    Write-Host "强制终止进程 $($process.Id)..."
                    $null = taskkill /F /PID $process.Id 2>&1
                    Write-Host "进程 $($process.Id) 已终止" -ForegroundColor Green
                }
            } catch {
                # 忽略错误继续查找
            }
        }
    }
    
    # 方法4：使用taskkill按服务名终止
    Write-Host "使用taskkill按服务名终止进程..."
    $null = taskkill /F /IM svchost.exe /FI "SERVICES eq eventlog" 2>&1
    
    # 方法5：使用net stop /y
    Write-Host "使用net stop强制停止..."
    $null = net stop eventlog /y 2>&1
    
    # 等待确保进程已终止
    Start-Sleep -Seconds 3
    
    # 检查服务状态
    $serviceStatus = Get-Service -Name eventlog -ErrorAction SilentlyContinue
    if ($serviceStatus.Status -eq "Stopped") {
        Write-Host "事件日志服务已成功停止" -ForegroundColor Green
    } else {
        Write-Host "警告：事件日志服务可能仍在运行，尝试继续操作..." -ForegroundColor Red
    }

    # 等待文件锁释放
    Write-Host "等待文件锁释放..."
    Start-Sleep -Seconds 2

    # 1. 删除所有TerminalServices日志文件
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
                
                # 先尝试正常删除
                Remove-Item $FullPath -Force -ErrorAction SilentlyContinue
                
                # 如果失败，使用cmd强制删除
                if (Test-Path $FullPath) {
                    Write-Host "使用cmd强制删除..." -ForegroundColor Yellow
                    $null = cmd.exe /c "del /F `"$FullPath`"" 2>&1
                }
                
                # 检查结果
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

    # 2. 处理Security日志（替换文件）
    if ($TempFiles.Count -gt 0) {
        Write-Host "`n正在处理Security日志..." -ForegroundColor Cyan
        foreach ($LogEntry in $TempFiles.GetEnumerator()) {
            $CurrentLogName = $LogEntry.Key
            $TempFile = $LogEntry.Value.TempFile
            $OriginalFile = $LogEntry.Value.OriginalFile

            try {
                Write-Host "处理日志: $CurrentLogName"
                
                # 检查临时文件是否存在
                if (-not (Test-Path $TempFile)) {
                    Write-Host "警告: 临时文件不存在: $TempFile" -ForegroundColor Yellow
                    continue
                }
                
                # 获取文件大小信息
                $tempSize = if (Test-Path $TempFile) { (Get-Item $TempFile).Length } else { 0 }
                $originalSize = if (Test-Path $OriginalFile) { (Get-Item $OriginalFile).Length } else { 0 }
                
                Write-Host "临时文件: $([Math]::Round($tempSize/1MB, 2)) MB"
                Write-Host "原始文件: $([Math]::Round($originalSize/1MB, 2)) MB"
                
                # 如果原始文件存在，尝试删除
                if (Test-Path $OriginalFile) {
                    Write-Host "删除原始文件..."
                    
                    # 尝试多种删除方法
                    Remove-Item $OriginalFile -Force -ErrorAction SilentlyContinue
                    
                    if (Test-Path $OriginalFile) {
                        # 使用cmd删除
                        $null = cmd.exe /c "del /F `"$OriginalFile`"" 2>&1
                    }
                    
                    if (Test-Path $OriginalFile) {
                        # 使用takeown获取所有权
                        Write-Host "获取文件所有权..." -ForegroundColor Yellow
                        $null = takeown.exe /F `"$OriginalFile`" 2>&1
                        $null = icacls.exe `"$OriginalFile`" /grant Administrators:F 2>&1
                        Remove-Item $OriginalFile -Force -ErrorAction SilentlyContinue
                    }
                    
                    # 等待文件系统更新
                    Start-Sleep -Milliseconds 500
                }
                
                # 重命名临时文件
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
        
        # 再次检查
        Start-Sleep -Seconds 2
        $serviceStatus = Get-Service -Name eventlog -ErrorAction SilentlyContinue
        if ($serviceStatus.Status -eq "Running") {
            Write-Host "事件日志服务已成功启动" -ForegroundColor Green
        } else {
            Write-Host "警告：事件日志服务可能未启动，可能需要重启系统" -ForegroundColor Red
        }
    }

    Write-Host "`n所有日志处理完成!" -ForegroundColor Green
    
    # 显示清理结果
    Write-Host "`n清理摘要:" -ForegroundColor Cyan
    foreach ($LogEntry in $TempFiles.GetEnumerator()) {
        $OriginalFile = $LogEntry.Value.OriginalFile
        if (Test-Path $OriginalFile) {
            $size = (Get-Item $OriginalFile).Length / 1MB
            Write-Host "  $($LogEntry.Key): $([Math]::Round($size, 2)) MB" -ForegroundColor Gray
        }
    }
    
    # 解释清理结果
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
# CleanLog -EventLogName Security -Hours 2  # 删除2小时内的记录，保留2小时前的记录
# CleanLog -EventLogName Security -Mins 30  # 删除30分钟内的记录，保留30分钟前的记录
# CleanLog -EventLogName Security           # 完全清除Security日志（不指定时间条件）