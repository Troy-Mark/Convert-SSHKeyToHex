# Convert-SSHKeyToHex
windows系统上的SSH公钥转16进制工具，自动生成OpenSSH密钥对并转换为16进制格式，支持RSA/ECDSA/DSA/ED25519算法。
先安装powershell，将脚本放置到C:\Users\<username>\.ssh目录下，然后执行脚本
```
Set-ExecutionPolicy RemoteSigned -Scope Process
./Convert-SSHKeyToHex.ps1
```

运行环境：PowerShell 7.5.4
