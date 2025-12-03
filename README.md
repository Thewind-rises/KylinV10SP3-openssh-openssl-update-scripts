# KylinV10SP3-openssh-openssl-update-scripts
手动编译后将所有操作交给DeepSeek生成的脚本，考虑到了升级过程中可能出现的各种GSSAPI，动态链接库等问题。

此脚本仅在麒麟V10SP3-2303上进行过测试，结果符合预期。如在其他系统使用请先打快照或者使用测试环境。

升级后版本：openssh-10.2p1，openssl-3.0.18

使用方式，在/opt目录下创建/opt/openssh-update目录，将下载好的openssh-10.2p1，openssl-3.0.18安装包上传到/opt/openssh-update目录后将脚本上传到此目录下。

执行sh update-openssh-openssl.sh

冲个豆浆啃个包子等着结束就行。
