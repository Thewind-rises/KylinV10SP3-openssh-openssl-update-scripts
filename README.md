# KylinV10SP3-openssh-openssl-update-scripts
手动编译后将所有操作交给DeepSeek生成的脚本，考虑到了升级过程中可能出现的各种GSSAPI，动态链接库等问题。

此脚本仅在麒麟V10SP3-2303上进行过测试，结果符合预期。如在其他系统使用请先打快照或者使用测试环境。

升级后版本：openssh-10.2p1，openssl-3.0.18

使用方式，在/opt目录下创建/opt/openssh-update目录，将下载好的openssh-10.2p1，openssl-3.0.18安装包上传到/opt/openssh-update目录后将脚本上传到此目录下。

执行sh update-openssh-openssl.sh

冲个豆浆啃个包子等着结束就行。

【回滚方案】（SOP）
若升级后 SSH 无法连接或系统异常，通过 IPMI/Console 登录控制台执行：

# 1. 停止当前损坏的 sshd
systemctl stop sshd

# 2. 还原二进制文件（脚本执行成功前会保留 .bak）
cd /usr/sbin && [[ -f sshd.bak ]] && mv -f sshd.bak sshd
cd /usr/bin && for b in ssh scp sftp; do [[ -f ${b}.bak ]] && mv -f ${b}.bak $b; done

# 3. 还原配置文件
cp -f /opt/openssh-update/backup_*/sshd_config.bak /etc/ssh/sshd_config

# 4. 清理局部 ldconfig（移除新 OpenSSL 的全局搜索路径）
rm -f /etc/ld.so.conf.d/custom-openssl.conf
ldconfig

# 5. 重启服务并验证
systemctl start sshd
ss -tlnp | grep 22
