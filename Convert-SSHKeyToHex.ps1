# 配置参数
$Script:Config = @{
    SshDir = Join-Path $env:USERPROFILE ".ssh"
    AlgorithmMap = @{
        "1" = @{ 
            Name = "rsa"; 
            KeySizes = @(1024, 2048, 3072, 4096); 
            DefaultSize = 3072;
            Tag = "rsa-public-key" 
        }
        "2" = @{ 
            Name = "ecdsa"; 
            KeySizes = @(256, 384, 521); 
            DefaultSize = 256;
            Tag = "ecc-public-key" 
        }
        "3" = @{ 
            Name = "dsa"; 
            KeySizes = @(1024); 
            DefaultSize = 1024;
            Tag = "dsa-public-key" 
        }
        "4" = @{ 
            Name = "ed25519"; 
            KeySizes = @(256); 
            DefaultSize = 256;
            Tag = "ed25519-public-key" 
        }
    }
    DefaultAlgorithm = "1"
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$ForegroundColor = "White",
        [switch]$IsTitle
    )
    
    if ($IsTitle) {
        Write-Host "`n$Message" -ForegroundColor $ForegroundColor
    } else {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
}

function Test-OpenSSHInstallation {
    try {
        $null = Get-Command ssh-keygen -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Install-OpenSSHClient {
    Write-ColorOutput "检测到系统未安装OpenSSH客户端" -ForegroundColor Yellow
    
    $installChoice = Read-Host "是否立即安装OpenSSH客户端? (输入 y 确认安装，其他键退出)"
    if ($installChoice -ne 'y') {
        Write-ColorOutput "安装已取消，请手动安装OpenSSH客户端后重新运行脚本" -ForegroundColor Red
        exit 1
    }
    
    try {
        Write-ColorOutput "正在安装OpenSSH客户端组件..." -ForegroundColor Green
        $result = Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
        
        if ($result.RebootNeeded) {
            Write-ColorOutput "安装完成，系统需要重启后才能使用" -ForegroundColor Yellow
            Write-ColorOutput "请重启后重新运行此脚本" -ForegroundColor Cyan
        } else {
            Start-Service ssh-agent -ErrorAction SilentlyContinue
            Set-Service -Name ssh-agent -StartupType Automatic -ErrorAction SilentlyContinue
            Write-ColorOutput "OpenSSH客户端安装成功" -ForegroundColor Green
        }
        return $true
    } catch {
        Write-ColorOutput "自动安装失败: $($_.Exception.Message)" -ForegroundColor Red
        Write-ColorOutput "请通过Windows功能手动启用OpenSSH客户端" -ForegroundColor Yellow
        exit 1
    }
}

function Get-UserAlgorithmChoice {
    Write-ColorOutput "请选择密钥算法类型：" -ForegroundColor Yellow -IsTitle
    Write-Host "1. RSA算法 (推荐选择，兼容性最佳)" -ForegroundColor Cyan
    Write-Host "2. ECDSA算法 (安全性更高，使用P-256曲线)" -ForegroundColor Cyan
    Write-Host "3. DSA算法 (旧设备兼容，安全性较低)" -ForegroundColor Cyan
    Write-Host "4. ED25519算法 (最新算法，性能最优)" -ForegroundColor Cyan
    
    do {
        $choice = Read-Host "`n请输入选项编号 [1-4] (默认选择1)"
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = $Script:Config.DefaultAlgorithm }
        
        if ($Script:Config.AlgorithmMap.ContainsKey($choice)) {
            $algorithm = $Script:Config.AlgorithmMap[$choice]
            
            if ($algorithm.Name -eq "ed25519") {
                Write-ColorOutput "已选择ED25519算法，使用固定256位密钥长度" -ForegroundColor Yellow
                $algorithm.SelectedSize = 256
                return $algorithm
            }
            
            Write-ColorOutput "`n请选择密钥长度：" -ForegroundColor Yellow
            for ($i = 0; $i -lt $algorithm.KeySizes.Length; $i++) {
                Write-Host "$($i+1). $($algorithm.KeySizes[$i]) 位" -ForegroundColor Cyan
            }
            
            do {
                $sizeChoice = Read-Host "`n请输入长度选项编号 [1-$($algorithm.KeySizes.Length)] (默认1)"
                if ([string]::IsNullOrWhiteSpace($sizeChoice)) { $sizeChoice = "1" }
                
                $sizeIndex = [int]$sizeChoice - 1
                if ($sizeIndex -ge 0 -and $sizeIndex -lt $algorithm.KeySizes.Length) {
                    $algorithm.SelectedSize = $algorithm.KeySizes[$sizeIndex]
                    Write-ColorOutput "已选择 $($algorithm.Name) 算法，密钥长度: $($algorithm.SelectedSize) 位" -ForegroundColor Green
                    return $algorithm
                } else {
                    Write-ColorOutput "输入无效，请输入1到$($algorithm.KeySizes.Length)之间的数字" -ForegroundColor Red
                }
            } while ($true)
            
        } else {
            Write-ColorOutput "输入无效，请输入1、2、3或4" -ForegroundColor Red
        }
    } while ($true)
}

function New-SSHKeyPair {
    param(
        [hashtable]$Algorithm,
        [string]$KeyPath
    )
    
    Write-ColorOutput "`n开始生成 $($Algorithm.Name.ToUpper()) 密钥对..." -ForegroundColor Green -IsTitle
    Write-ColorOutput "密钥长度: $($Algorithm.SelectedSize) 位" -ForegroundColor White
    
    $privateKey = Join-Path $KeyPath "id_$($Algorithm.Name)_$($Algorithm.SelectedSize)"
    $pubKeyFile = "$privateKey.pub"
    
    if (Test-Path $privateKey) {
        Write-ColorOutput "检测到已存在同名密钥文件: $privateKey" -ForegroundColor Yellow
        $overwrite = Read-Host "是否覆盖现有文件? (输入 y 覆盖，其他键保留原文件)"
        if ($overwrite -ne 'y') {
            Write-ColorOutput "将使用现有密钥文件继续处理" -ForegroundColor Yellow
            return @{ PrivateKey = $privateKey; PublicKey = $pubKeyFile }
        } else {
            Remove-Item $privateKey -Force -ErrorAction SilentlyContinue
            Remove-Item $pubKeyFile -Force -ErrorAction SilentlyContinue
            Write-ColorOutput "已删除旧密钥文件，准备生成新密钥" -ForegroundColor Green
        }
        
        # 确保SSH目录权限正确
        try {
            $acl = Get-Acl $Script:Config.SshDir
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "InheritOnly",
                "Allow"
            )
            $acl.SetAccessRule($accessRule)
            Set-Acl $Script:Config.SshDir $acl
        } catch {
            Write-ColorOutput "警告: 无法设置SSH目录权限: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    try {
        if ($Algorithm.Name -eq "ed25519") {
            $keygenArgs = @(
                "-t", $Algorithm.Name,
                "-f", $privateKey,
                "-N", '""',
                "-q"
            )
        } else {
            $keygenArgs = @(
                "-t", $Algorithm.Name,
                "-b", $Algorithm.SelectedSize,
                "-f", $privateKey,
                "-N", '""',
                "-q"
            )
        }
        
        Write-ColorOutput "正在调用ssh-keygen生成密钥..." -ForegroundColor Yellow
        $process = Start-Process -FilePath "ssh-keygen" -ArgumentList $keygenArgs -NoNewWindow -PassThru -Wait
        
        if ($process.ExitCode -eq 0) {
            Write-ColorOutput "密钥对生成成功完成" -ForegroundColor Green
            return @{ PrivateKey = $privateKey; PublicKey = $pubKeyFile }
        } else {
            Write-ColorOutput "标准生成方法失败，尝试备用方案..." -ForegroundColor Yellow
            try {
                if ($Algorithm.Name -eq "ed25519") {
                    $altArgs = @("-t", $Algorithm.Name, "-f", $privateKey, "-N", '""', "-q")
                } else {
                    $altArgs = @("-t", $Algorithm.Name, "-b", $Algorithm.SelectedSize, "-f", $privateKey, "-N", '""', "-q")
                }
                
                $process = Start-Process -FilePath "ssh-keygen" -ArgumentList $altArgs -NoNewWindow -PassThru -Wait -ErrorAction Stop
                
                if ($process.ExitCode -eq 0) {
                    Write-ColorOutput "备用方法密钥生成成功" -ForegroundColor Green
                    return @{ PrivateKey = $privateKey; PublicKey = $pubKeyFile }
                } else {
                    throw "密钥生成过程失败，退出代码: $($process.ExitCode)"
                }
            } catch {
                throw "备用方案执行失败: $($_.Exception.Message)"
            }
        
        # 设置新生成的私钥文件权限
        try {
            if (Test-Path $privateKey) {
                $acl = Get-Acl $privateKey
                $acl.SetAccessRuleProtection($true, $false)
                $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $userSid,
                    "FullControl",
                    "None",
                    "InheritOnly",
                    "Allow"
                )
                $acl.SetAccessRule($accessRule)
                Set-Acl $privateKey $acl
                Write-ColorOutput "私钥文件权限设置完成" -ForegroundColor Green
            }
        } catch {
            Write-ColorOutput "警告: 无法设置私钥文件权限: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        }
    } catch {
        Write-ColorOutput "密钥生成失败: $($_.Exception.Message)" -ForegroundColor Red
        Write-ColorOutput "`n您可以尝试手动生成密钥：" -ForegroundColor Yellow
        if ($Algorithm.Name -eq "ed25519") {
            Write-Host "1. 打开命令提示符或PowerShell"
            Write-Host "2. 执行命令: ssh-keygen -t $($Algorithm.Name) -f `"$privateKey`" -N `"`""
        } else {
            Write-Host "1. 打开命令提示符或PowerShell"
            Write-Host "2. 执行命令: ssh-keygen -t $($Algorithm.Name) -b $($Algorithm.SelectedSize) -f `"$privateKey`" -N `"`""
        }
        Write-Host "3. 按Enter键两次跳过密码设置"
        Write-Host "4. 完成后重新运行此脚本进行转换"
        exit 1
    }
}

function Convert-ToHexFormat {
    param(
        [string]$PublicKeyFile,
        [string]$Tag
    )
    
    try {
        Write-ColorOutput "`n开始16进制格式转换" -ForegroundColor Cyan -IsTitle
        
        # 读取公钥文件
        Write-ColorOutput "正在读取公钥文件内容..." -ForegroundColor Yellow
        Write-ColorOutput "文件位置: $PublicKeyFile" -ForegroundColor White
        $pubContent = Get-Content $PublicKeyFile -Raw
        Write-ColorOutput "公钥文件读取成功" -ForegroundColor Green
        
        # 解析公钥格式 - 增强错误处理和验证
        Write-ColorOutput "正在解析公钥数据结构..." -ForegroundColor Yellow
        $base64Key = $null
        $patterns = @(
            "(?:ssh-(?:rsa|dss)|ecdsa-sha2-nistp\d+|ssh-ed25519)\s+([A-Za-z0-9+/=]+)",
            "([A-Za-z0-9+/=]{20,})"
        )
        
        foreach ($pattern in $patterns) {
            if ($pubContent -match $pattern) {
                $base64Key = $matches[1].Trim()
                if (-not [string]::IsNullOrWhiteSpace($base64Key)) {
                    Write-ColorOutput "成功提取Base64编码的密钥数据" -ForegroundColor Green
                    break
                }
            }
        }
        
        # 验证Base64格式有效性
        if ($base64Key -and $base64Key -match '[^A-Za-z0-9+/=]') {
            throw "检测到无效的Base64字符，公钥文件可能已损坏"
        }
        
        if ([string]::IsNullOrWhiteSpace($base64Key)) {
            throw "无法识别公钥文件格式，请检查文件完整性"
        }
        
        # 处理Base64填充
        Write-ColorOutput "正在校验Base64编码格式..." -ForegroundColor Yellow
        if ($base64Key.Length % 4 -ne 0) {
            $padding = 4 - ($base64Key.Length % 4)
            $base64Key = $base64Key.PadRight($base64Key.Length + $padding, '=')
            Write-ColorOutput "自动补充格式字符: $padding 个 '=' 填充" -ForegroundColor Green
        } else {
            Write-ColorOutput "Base64编码格式验证通过" -ForegroundColor Green
        }
        
        # 解码Base64
        Write-ColorOutput "正在进行Base64解码..." -ForegroundColor Yellow
        $bytes = [System.Convert]::FromBase64String($base64Key)
        Write-ColorOutput "Base64解码完成，数据大小: $($bytes.Length) 字节" -ForegroundColor Green
        
        # 转换为16进制
        Write-ColorOutput "正在生成16进制表示形式..." -ForegroundColor Yellow
        $hexString = [System.BitConverter]::ToString($bytes).Replace("-", "").ToUpper()
        Write-ColorOutput "16进制转换完成，字符总数: $($hexString.Length)" -ForegroundColor Green
        
        # 格式化输出 - 使用StringBuilder优化性能
        Write-ColorOutput "正在进行格式化排版..." -ForegroundColor Yellow
        $hexOutput = [System.Collections.Generic.List[string]]::new()
        for ($i = 0; $i -lt $hexString.Length; $i += 20) {
            $remaining = $hexString.Length - $i
            $chunkSize = [Math]::Min(20, $remaining)
            $line = $hexString.Substring($i, $chunkSize)
            $formattedLine = $line -replace '(.{4})', '$1 ' -replace '\s+$'
            $hexOutput.Add($formattedLine)
        }
        
        Write-ColorOutput "格式化排版完成，共生成 $($hexOutput.Count) 行" -ForegroundColor Green
        Write-ColorOutput "16进制转换处理完成" -ForegroundColor Green -IsTitle
        
        return $hexOutput
        
    } catch {
        Write-ColorOutput "转换过程中出现错误: $($_.Exception.Message)" -ForegroundColor Red -IsTitle
        Write-ColorOutput "请确认公钥文件格式正确且未被损坏" -ForegroundColor Yellow
        exit 1
    }
}

function Save-HexToFile {
    param(
        [string[]]$HexContent,
        [string]$PublicKeyFile
    )
    
    $saveChoice = Read-Host "`n是否将16进制结果保存为文本文件? (输入 y 保存，其他键跳过)"
    if ($saveChoice -ne 'y') {
        Write-ColorOutput "已跳过文件保存，结果将仅显示在屏幕上" -ForegroundColor Yellow
        return
    }
    
    $defaultFileName = [System.IO.Path]::GetFileNameWithoutExtension($PublicKeyFile) + "_hex.txt"
    $outputFile = Read-Host "请输入保存文件名 (直接回车使用默认名称: $defaultFileName)"
    if ([string]::IsNullOrWhiteSpace($outputFile)) {
        $outputFile = $defaultFileName
    }
    
    if (-not [System.IO.Path]::IsPathRooted($outputFile)) {
        $outputFile = Join-Path (Split-Path $PublicKeyFile) $outputFile
    }
    
    try {
        Write-ColorOutput "正在写入文件..." -ForegroundColor Yellow
        $HexContent | Out-File $outputFile -Encoding UTF8
        Write-ColorOutput "文件保存成功: $outputFile" -ForegroundColor Green
        return $outputFile
    } catch {
        Write-ColorOutput "文件保存失败: $($_.Exception.Message)" -ForegroundColor Red
        Write-ColorOutput "请检查文件路径权限或磁盘空间" -ForegroundColor Yellow
    }
}

function Main {
    Write-ColorOutput "=== SSH公钥转16进制格式工具 ===" -ForegroundColor Cyan -IsTitle
    Write-ColorOutput "版本: 优化提示语句版" -ForegroundColor White
    
    if (-not (Test-OpenSSHInstallation)) {
        Install-OpenSSHClient
    }
    Write-Host ""
    
    if (-not (Test-Path $Script:Config.SshDir)) {
        New-Item -ItemType Directory -Path $Script:Config.SshDir -Force | Out-Null
        Write-ColorOutput "已创建SSH目录: $($Script:Config.SshDir)" -ForegroundColor Green
    }
    
    $algorithm = Get-UserAlgorithmChoice
    Write-Host ""
    
    $keyFiles = New-SSHKeyPair -Algorithm $algorithm -KeyPath $Script:Config.SshDir
    Write-Host ""
    
    $hexConfig = Convert-ToHexFormat -PublicKeyFile $keyFiles.PublicKey -Tag $algorithm.Tag
    Write-Host ""
    
    $hexFile = Save-HexToFile -HexContent $hexConfig -PublicKeyFile $keyFiles.PublicKey
    Write-Host ""
    
    Write-ColorOutput "=== 生成结果汇总 ===" -ForegroundColor Cyan -IsTitle
    Write-Host "私钥文件位置: $($keyFiles.PrivateKey)" -ForegroundColor Yellow
    Write-Host "公钥文件位置: $($keyFiles.PublicKey)" -ForegroundColor Yellow
    if ($hexFile) { Write-Host "16进制文本文件: $hexFile" -ForegroundColor Yellow }
    
    Write-ColorOutput "=== 转换后的16进制结果 ===" -ForegroundColor Green -IsTitle
    $hexConfig
    
    Write-ColorOutput "=== 所有操作已完成 ===" -ForegroundColor Green -IsTitle
    Write-ColorOutput "感谢使用SSH公钥转换工具！" -ForegroundColor Cyan
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Main
    } catch {
        Write-ColorOutput "脚本执行过程中出现错误: $($_.Exception.Message)" -ForegroundColor Red
        Write-ColorOutput "请检查错误信息并重试" -ForegroundColor Yellow
        exit 1
    }
}
